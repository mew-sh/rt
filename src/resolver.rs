//! DNS resolver, ported from gost's `resolver.go`.
//!
//! # Why a hand-rolled wire codec
//!
//! gost uses `github.com/miekg/dns` for message packing and its own transports
//! so that every exchange can be dialled through the proxy chain
//! (resolver.go:709, 759, 814, 885). The Rust port keeps the same split --
//! transports live here so they can go through [`crate::chain::Chain`] -- but
//! the message codec below is hand written instead of pulling in
//! `hickory-proto`. The codec only has to understand the header, the question
//! section and opaque RRs (plus A/AAAA/OPT rdata), which is about 200 lines,
//! whereas `hickory-proto` would add a sizeable dependency tree to a build that
//! is already memory constrained. See [`Message`] for the one caveat this
//! implies (rdata name compression is not rewritten on re-encode) and how the
//! resolver avoids it.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::debug;

use crate::auth::{parse_go_duration, split_line_ref};
use crate::chain::Chain;
use crate::reload::{Reloader, Stoppable};

/// gost: `DefaultResolverTimeout` (resolver.go:24).
pub const DEFAULT_RESOLVER_TIMEOUT: Duration = Duration::from_secs(5);

/// Default EDNS0 UDP payload size advertised by queries this resolver builds,
/// and the read buffer used by the UDP exchanger. gost hardcodes 1024
/// (resolver.go:721); 1232 is the modern "safe across the internet" value and
/// is what we advertise, so replies up to that size are not truncated.
pub const DEFAULT_UDP_SIZE: u16 = 1232;

// ---------------------------------------------------------------------------
// DNS wire format
// ---------------------------------------------------------------------------

pub const CLASS_IN: u16 = 1;
pub const CLASS_CH: u16 = 3;
pub const CLASS_HS: u16 = 4;
pub const CLASS_ANY: u16 = 255;

pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_MX: u16 = 15;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;
pub const TYPE_OPT: u16 = 41;
pub const TYPE_ANY: u16 = 255;

/// EDNS0 option code for client subnet (RFC 7871).
pub const EDNS0_SUBNET: u16 = 8;

/// Recursion Desired flag.
pub const FLAG_RD: u16 = 0x0100;
/// Query Response flag.
pub const FLAG_QR: u16 = 0x8000;

fn wire_err<T: Into<String>>(msg: T) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Renders a DNS class the way `dns.Class.String()` does, for cache keys.
pub fn class_name(class: u16) -> String {
    match class {
        CLASS_IN => "IN".to_string(),
        CLASS_CH => "CH".to_string(),
        CLASS_HS => "HS".to_string(),
        CLASS_ANY => "ANY".to_string(),
        other => format!("CLASS{}", other),
    }
}

/// Renders a DNS type the way `dns.Type.String()` does, for cache keys.
pub fn type_name(t: u16) -> String {
    match t {
        TYPE_A => "A".to_string(),
        TYPE_NS => "NS".to_string(),
        TYPE_CNAME => "CNAME".to_string(),
        TYPE_SOA => "SOA".to_string(),
        TYPE_PTR => "PTR".to_string(),
        TYPE_MX => "MX".to_string(),
        TYPE_TXT => "TXT".to_string(),
        TYPE_AAAA => "AAAA".to_string(),
        TYPE_SRV => "SRV".to_string(),
        TYPE_OPT => "OPT".to_string(),
        TYPE_ANY => "ANY".to_string(),
        other => format!("TYPE{}", other),
    }
}

/// gost/miekg: `dns.Fqdn` -- appends the root label if missing.
pub fn fqdn(name: &str) -> String {
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{}.", name)
    }
}

fn be16(buf: &[u8], pos: usize) -> io::Result<u16> {
    if pos + 2 > buf.len() {
        return Err(wire_err("short read (u16)"));
    }
    Ok(u16::from_be_bytes([buf[pos], buf[pos + 1]]))
}

fn be32(buf: &[u8], pos: usize) -> io::Result<u32> {
    if pos + 4 > buf.len() {
        return Err(wire_err("short read (u32)"));
    }
    Ok(u32::from_be_bytes([
        buf[pos],
        buf[pos + 1],
        buf[pos + 2],
        buf[pos + 3],
    ]))
}

/// Encodes a domain name in label form. No compression pointers are emitted,
/// which is always valid on the wire.
pub fn encode_name(name: &str, out: &mut Vec<u8>) -> io::Result<()> {
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        if label.len() > 63 {
            return Err(wire_err(format!("label too long: {}", label)));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

/// Decodes a possibly compressed domain name.
///
/// Returns the fully qualified name and the offset just past the name *in the
/// original stream* (i.e. past the pointer, not past the pointed-to labels).
pub fn decode_name(buf: &[u8], start: usize) -> io::Result<(String, usize)> {
    let mut name = String::new();
    let mut pos = start;
    let mut end_pos = start;
    let mut jumped = false;
    // Guard against pointer loops: every step consumes at least one byte of the
    // budget, and a valid name can never need more steps than there are bytes.
    let mut budget = buf.len() + 1;

    loop {
        if budget == 0 {
            return Err(wire_err("compression pointer loop"));
        }
        budget -= 1;

        if pos >= buf.len() {
            return Err(wire_err("truncated name"));
        }
        let len = buf[pos] as usize;
        if len == 0 {
            pos += 1;
            if !jumped {
                end_pos = pos;
            }
            if name.is_empty() {
                name.push('.');
            }
            return Ok((name, end_pos));
        }
        match len & 0xC0 {
            0x00 => {
                if pos + 1 + len > buf.len() {
                    return Err(wire_err("truncated label"));
                }
                let label = &buf[pos + 1..pos + 1 + len];
                name.push_str(&String::from_utf8_lossy(label));
                name.push('.');
                pos += 1 + len;
            }
            0xC0 => {
                if pos + 2 > buf.len() {
                    return Err(wire_err("truncated compression pointer"));
                }
                let ptr = (((len & 0x3F) as usize) << 8) | buf[pos + 1] as usize;
                if !jumped {
                    end_pos = pos + 2;
                    jumped = true;
                }
                if ptr >= buf.len() {
                    return Err(wire_err("compression pointer out of range"));
                }
                pos = ptr;
            }
            _ => return Err(wire_err("reserved label type")),
        }
    }
}

/// A question section entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

impl Question {
    pub fn new(name: &str, qtype: u16) -> Self {
        Self {
            name: fqdn(name),
            qtype,
            qclass: CLASS_IN,
        }
    }
}

/// A resource record. `rdata` is kept opaque.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rr {
    pub name: String,
    pub rtype: u16,
    /// For OPT records this field carries the advertised UDP payload size.
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

impl Rr {
    /// If this record is an A record, returns the address.
    pub fn as_a(&self) -> Option<IpAddr> {
        if self.rtype != TYPE_A || self.rdata.len() != 4 {
            return None;
        }
        Some(IpAddr::V4(Ipv4Addr::new(
            self.rdata[0],
            self.rdata[1],
            self.rdata[2],
            self.rdata[3],
        )))
    }

    /// If this record is an AAAA record, returns the address.
    pub fn as_aaaa(&self) -> Option<IpAddr> {
        if self.rtype != TYPE_AAAA || self.rdata.len() != 16 {
            return None;
        }
        let mut o = [0u8; 16];
        o.copy_from_slice(&self.rdata);
        Some(IpAddr::V6(Ipv6Addr::from(o)))
    }
}

/// A DNS message.
///
/// # Caveat
///
/// [`Message::encode`] writes `rdata` verbatim. A record whose rdata embeds a
/// compressed domain name (CNAME, NS, SOA, MX, ...) therefore does **not**
/// survive a decode/encode round trip byte-for-byte, because the pointer
/// offsets would move. The resolver never relies on that: replies are cached
/// and returned as the *original* bytes with only the 2-byte ID patched
/// ([`set_msg_id`]), and re-encoding is limited to messages this crate builds
/// itself plus client queries (whose sections do not use compression).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Message {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<Question>,
    pub answers: Vec<Rr>,
    pub authorities: Vec<Rr>,
    pub additionals: Vec<Rr>,
}

impl Message {
    /// gost/miekg: `mq.SetQuestion(dns.Fqdn(host), qtype)`.
    pub fn query(id: u16, name: &str, qtype: u16) -> Self {
        Self {
            id,
            flags: FLAG_RD,
            questions: vec![Question::new(name, qtype)],
            ..Default::default()
        }
    }

    pub fn is_response(&self) -> bool {
        self.flags & FLAG_QR != 0
    }

    pub fn rcode(&self) -> u16 {
        self.flags & 0x000F
    }

    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&(self.questions.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.answers.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.authorities.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.additionals.len() as u16).to_be_bytes());

        for q in &self.questions {
            encode_name(&q.name, &mut out)?;
            out.extend_from_slice(&q.qtype.to_be_bytes());
            out.extend_from_slice(&q.qclass.to_be_bytes());
        }
        for section in [&self.answers, &self.authorities, &self.additionals] {
            for rr in section {
                encode_name(&rr.name, &mut out)?;
                out.extend_from_slice(&rr.rtype.to_be_bytes());
                out.extend_from_slice(&rr.rclass.to_be_bytes());
                out.extend_from_slice(&rr.ttl.to_be_bytes());
                if rr.rdata.len() > u16::MAX as usize {
                    return Err(wire_err("rdata too long"));
                }
                out.extend_from_slice(&(rr.rdata.len() as u16).to_be_bytes());
                out.extend_from_slice(&rr.rdata);
            }
        }
        Ok(out)
    }

    pub fn decode(buf: &[u8]) -> io::Result<Message> {
        if buf.len() < 12 {
            return Err(wire_err("message shorter than DNS header"));
        }
        let id = be16(buf, 0)?;
        let flags = be16(buf, 2)?;
        let qdcount = be16(buf, 4)? as usize;
        let ancount = be16(buf, 6)? as usize;
        let nscount = be16(buf, 8)? as usize;
        let arcount = be16(buf, 10)? as usize;

        let mut pos = 12usize;
        let mut questions = Vec::with_capacity(qdcount.min(16));
        for _ in 0..qdcount {
            let (name, next) = decode_name(buf, pos)?;
            pos = next;
            let qtype = be16(buf, pos)?;
            let qclass = be16(buf, pos + 2)?;
            pos += 4;
            questions.push(Question {
                name,
                qtype,
                qclass,
            });
        }

        let mut decode_section = |count: usize, pos: &mut usize| -> io::Result<Vec<Rr>> {
            let mut rrs = Vec::with_capacity(count.min(16));
            for _ in 0..count {
                let (name, next) = decode_name(buf, *pos)?;
                *pos = next;
                let rtype = be16(buf, *pos)?;
                let rclass = be16(buf, *pos + 2)?;
                let ttl = be32(buf, *pos + 4)?;
                let rdlen = be16(buf, *pos + 8)? as usize;
                *pos += 10;
                if *pos + rdlen > buf.len() {
                    return Err(wire_err("truncated rdata"));
                }
                let rdata = buf[*pos..*pos + rdlen].to_vec();
                *pos += rdlen;
                rrs.push(Rr {
                    name,
                    rtype,
                    rclass,
                    ttl,
                    rdata,
                });
            }
            Ok(rrs)
        };

        let answers = decode_section(ancount, &mut pos)?;
        let authorities = decode_section(nscount, &mut pos)?;
        let additionals = decode_section(arcount, &mut pos)?;

        Ok(Message {
            id,
            flags,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    /// The EDNS0 UDP payload size advertised by this message, if any.
    /// gost/miekg: `msg.IsEdns0().UDPSize()`.
    pub fn edns0_udp_size(&self) -> Option<u16> {
        self.additionals
            .iter()
            .find(|rr| rr.rtype == TYPE_OPT)
            .map(|rr| rr.rclass)
    }

    /// Removes any OPT record from the additional section.
    pub fn remove_opt(&mut self) {
        self.additionals.retain(|rr| rr.rtype != TYPE_OPT);
    }

    /// All A/AAAA addresses in the answer section, in wire order.
    /// gost: `resolveIPs` (resolver.go:348-355).
    pub fn answer_ips(&self) -> Vec<IpAddr> {
        let mut ips = Vec::new();
        for ans in &self.answers {
            if let Some(ip) = ans.as_aaaa() {
                ips.push(ip);
            }
            if let Some(ip) = ans.as_a() {
                ips.push(ip);
            }
        }
        ips
    }

    /// The smallest TTL across the answer section, or `None` when there are no
    /// answers. gost checks every answer RR individually
    /// (resolver.go:629-634), which is the same as checking the minimum.
    pub fn min_answer_ttl(&self) -> Option<u32> {
        self.answers.iter().map(|rr| rr.ttl).min()
    }
}

/// Overwrites the 2-byte ID of an encoded message in place.
///
/// This is how cached replies are handed back to a different client without
/// re-encoding (and thus without the rdata compression caveat on [`Message`]).
/// gost does `mr.Id = mq.Id; return mr.Pack()` (resolver.go:399-400).
pub fn set_msg_id(buf: &mut [u8], id: u16) {
    if buf.len() >= 2 {
        buf[0..2].copy_from_slice(&id.to_be_bytes());
    }
}

/// Builds an OPT record carrying an EDNS0 client-subnet option.
/// gost: `addSubnetOpt` (resolver.go:360-380).
pub fn edns0_subnet_opt(src: IpAddr, udp_size: u16) -> Rr {
    let (family, netmask, addr): (u16, u8, Vec<u8>) = match src {
        IpAddr::V4(v4) => (1, 32, v4.octets().to_vec()),
        IpAddr::V6(v6) => (2, 128, v6.octets().to_vec()),
    };

    let mut option = Vec::with_capacity(4 + addr.len());
    option.extend_from_slice(&family.to_be_bytes());
    option.push(netmask);
    option.push(0); // scope netmask, always 0 in a query
    option.extend_from_slice(&addr);

    let mut rdata = Vec::with_capacity(4 + option.len());
    rdata.extend_from_slice(&EDNS0_SUBNET.to_be_bytes());
    rdata.extend_from_slice(&(option.len() as u16).to_be_bytes());
    rdata.extend_from_slice(&option);

    Rr {
        name: ".".to_string(),
        rtype: TYPE_OPT,
        rclass: udp_size,
        ttl: 0,
        rdata,
    }
}

/// Parses the client-subnet option out of an OPT record, if present.
/// Used by tests and by anything wanting to inspect what we sent.
pub fn parse_edns0_subnet(rr: &Rr) -> Option<(u16, u8, Vec<u8>)> {
    if rr.rtype != TYPE_OPT {
        return None;
    }
    let mut pos = 0usize;
    while pos + 4 <= rr.rdata.len() {
        let code = u16::from_be_bytes([rr.rdata[pos], rr.rdata[pos + 1]]);
        let len = u16::from_be_bytes([rr.rdata[pos + 2], rr.rdata[pos + 3]]) as usize;
        pos += 4;
        if pos + len > rr.rdata.len() {
            return None;
        }
        if code == EDNS0_SUBNET && len >= 4 {
            let family = u16::from_be_bytes([rr.rdata[pos], rr.rdata[pos + 1]]);
            let netmask = rr.rdata[pos + 2];
            let addr = rr.rdata[pos + 4..pos + len].to_vec();
            return Some((family, netmask, addr));
        }
        pos += len;
    }
    None
}

// ---------------------------------------------------------------------------
// Name servers and transports
// ---------------------------------------------------------------------------

/// Transport protocol of a name server. gost: `NameServer.Init`
/// (resolver.go:68-107).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NsProtocol {
    Udp,
    Tcp,
    Tls,
    Https,
}

impl NsProtocol {
    /// Splits gost's `"<proto>"` / `"<proto>-chain"` spelling. The `-chain`
    /// suffix means "dial this exchanger through the proxy chain".
    pub fn parse(s: &str) -> (NsProtocol, bool) {
        let lower = s.to_ascii_lowercase();
        let (base, chained) = match lower.strip_suffix("-chain") {
            Some(b) => (b.to_string(), true),
            None => (lower, false),
        };
        let proto = match base.as_str() {
            "tcp" => NsProtocol::Tcp,
            "tls" => NsProtocol::Tls,
            "https" => NsProtocol::Https,
            // gost: `case "udp": fallthrough; default:` -- anything unknown is UDP.
            _ => NsProtocol::Udp,
        };
        (proto, chained)
    }
}

/// A single name server. gost: `NameServer` (resolver.go:51-57).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NameServer {
    pub addr: String,
    pub protocol: String,
    /// SNI / certificate verification hostname for `tls` and `https`.
    /// gost: resolver.go:54, 79-84, 95-98.
    pub hostname: String,
}

impl NameServer {
    pub fn new(addr: &str) -> Self {
        Self {
            addr: addr.to_string(),
            protocol: String::new(),
            hostname: String::new(),
        }
    }

    pub fn with_protocol(mut self, protocol: &str) -> Self {
        self.protocol = protocol.to_string();
        self
    }

    pub fn with_hostname(mut self, hostname: &str) -> Self {
        self.hostname = hostname.to_string();
        self
    }

    pub fn protocol_kind(&self) -> (NsProtocol, bool) {
        NsProtocol::parse(&self.protocol)
    }

    /// The address with `:53` appended when no port is present, matching
    /// gost's `net.SplitHostPort` check in every exchanger constructor.
    /// Not applied to `https`, whose address is a URL.
    pub fn dial_addr(&self) -> String {
        ensure_port(&self.addr, "53")
    }
}

impl fmt::Display for NameServer {
    /// gost: `NameServer.String()` (resolver.go:112-119).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prot = if self.protocol.is_empty() {
            "udp"
        } else {
            &self.protocol
        };
        write!(f, "{}/{}", self.addr, prot)
    }
}

/// Appends `:<default_port>` when `addr` has no port, handling bare and
/// bracketed IPv6 literals. Mirrors `net.JoinHostPort(addr, "53")` guarded by
/// `net.SplitHostPort`.
pub fn ensure_port(addr: &str, default_port: &str) -> String {
    if addr.is_empty() {
        return addr.to_string();
    }
    if addr.starts_with('[') {
        // "[::1]:53" already has a port; "[::1]" does not.
        return match addr.rfind("]:") {
            Some(_) => addr.to_string(),
            None => format!("{}:{}", addr, default_port),
        };
    }
    match addr.matches(':').count() {
        0 => format!("{}:{}", addr, default_port),
        1 => addr.to_string(),
        // Bare IPv6 literal, needs brackets.
        _ => format!("[{}]:{}", addr, default_port),
    }
}

fn io_other<E: fmt::Display>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e.to_string())
}

/// Dials TCP, going through the proxy chain when one is supplied.
///
/// The `ChainOptions` deliberately carry `resolver: None`: dialling the name
/// server must never re-enter the resolver that is doing the dialling.
async fn dial_tcp_via(
    addr: &str,
    timeout: Duration,
    chain: Option<&Chain>,
) -> io::Result<crate::conn::ProxyConn> {
    match chain {
        Some(c) if !c.is_empty() => {
            let opts = crate::chain::ChainOptions {
                retries: 0,
                timeout,
                hosts: c.hosts.clone(),
                resolver: None,
            };
            c.dial_with_options(addr, &opts).await.map_err(io_other)
        }
        _ => tokio::time::timeout(timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dns dial timeout"))?
            .map(crate::conn::ProxyConn::from_tcp),
    }
}

/// Writes a 2-byte length prefixed query and reads the length prefixed reply.
/// This is the framing shared by DNS-over-TCP and DNS-over-TLS (RFC 1035 4.2.2).
async fn exchange_stream<S>(stream: &mut S, query: &[u8]) -> io::Result<Vec<u8>>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    if query.len() > u16::MAX as usize {
        return Err(wire_err("query too long for TCP framing"));
    }
    let mut framed = Vec::with_capacity(query.len() + 2);
    framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
    framed.extend_from_slice(query);
    stream.write_all(&framed).await?;
    stream.flush().await?;

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let n = u16::from_be_bytes(len_buf) as usize;
    let mut reply = vec![0u8; n];
    stream.read_exact(&mut reply).await?;
    Ok(reply)
}

/// DNS over UDP. gost: `dnsExchanger` (resolver.go:707-733).
///
/// The chain is not consulted here: `Chain::dial` only speaks TCP, so a
/// `udp-chain` name server degrades to a direct UDP exchange rather than
/// silently sending nothing.
async fn exchange_udp(addr: &str, query: &[u8], timeout: Duration) -> io::Result<Vec<u8>> {
    let bind = if addr.starts_with('[') || addr.matches(':').count() > 1 {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(addr).await?;
    sock.send(query).await?;

    // Honour the size we advertised so large replies are not clipped.
    let size = Message::decode(query)
        .ok()
        .and_then(|m| m.edns0_udp_size())
        .unwrap_or(DEFAULT_UDP_SIZE)
        .max(512) as usize;
    let mut buf = vec![0u8; size];
    let n = tokio::time::timeout(timeout, sock.recv(&mut buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dns udp timeout"))??;
    buf.truncate(n);
    Ok(buf)
}

/// DNS over TCP. gost: `dnsTCPExchanger` (resolver.go:757-782).
async fn exchange_tcp(
    addr: &str,
    query: &[u8],
    timeout: Duration,
    chain: Option<&Chain>,
) -> io::Result<Vec<u8>> {
    let mut stream = dial_tcp_via(addr, timeout, chain).await?;
    tokio::time::timeout(timeout, exchange_stream(&mut stream, query))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dns tcp timeout"))?
}

/// DNS over TLS. gost: `dotExchanger` (resolver.go:813-848).
///
/// gost sets `ServerName: ns.Hostname` and falls back to
/// `InsecureSkipVerify` when the hostname is empty (resolver.go:79-84).
async fn exchange_tls(
    addr: &str,
    hostname: &str,
    query: &[u8],
    timeout: Duration,
    chain: Option<&Chain>,
) -> io::Result<Vec<u8>> {
    let stream = dial_tcp_via(addr, timeout, chain).await?;

    let insecure = hostname.is_empty();
    let sni = if insecure {
        host_of(addr).to_string()
    } else {
        hostname.to_string()
    };

    let connector = if insecure {
        crate::tls_transport::insecure_tls_connector().map_err(io_other)?
    } else {
        crate::tls_transport::default_tls_connector().map_err(io_other)?
    };
    let mut tls = tokio::time::timeout(timeout, connector.connect(&sni, stream))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dns tls handshake timeout"))?
        .map_err(io_other)?;

    tokio::time::timeout(timeout, exchange_stream(&mut tls, query))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dns tls timeout"))?
}

/// The host portion of `host:port`, keeping bare IPv6 literals intact.
fn host_of(addr: &str) -> &str {
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return &rest[..end];
        }
    }
    match addr.rfind(':') {
        Some(i) if addr[..i].find(':').is_none() => &addr[..i],
        _ => addr,
    }
}

/// DNS over HTTPS. gost: `dohExchanger` (resolver.go:891-923).
///
/// A minimal HTTP/1.1 POST is written by hand rather than pulling in an HTTP
/// client, because the connection has to be dialled through
/// [`dial_tcp_via`] so `https-chain` name servers can traverse the proxy chain
/// (gost does the same via `Transport.DialContext`, resolver.go:884-889).
async fn exchange_doh(
    url_str: &str,
    hostname: &str,
    query: &[u8],
    timeout: Duration,
    chain: Option<&Chain>,
) -> io::Result<Vec<u8>> {
    let url = url::Url::parse(url_str).map_err(|e| wire_err(format!("bad DoH url: {}", e)))?;
    let host = url
        .host_str()
        .ok_or_else(|| wire_err("DoH url has no host"))?
        .to_string();
    // gost rewrites the scheme to https, so the port default is always 443.
    let plaintext = url.scheme() == "http";
    let port = url.port().unwrap_or(if plaintext { 80 } else { 443 });
    let mut path = url.path().to_string();
    if path.is_empty() {
        path = "/".to_string();
    }
    if let Some(q) = url.query() {
        path.push('?');
        path.push_str(q);
    }

    let addr = if host.contains(':') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    };

    let host_header = if (plaintext && port == 80) || (!plaintext && port == 443) {
        host.clone()
    } else {
        format!("{}:{}", host, port)
    };

    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/dns-message\r\n\
         Accept: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        path,
        host_header,
        query.len()
    );

    let stream = dial_tcp_via(&addr, timeout, chain).await?;

    let run = async move {
        if plaintext {
            let mut s = stream;
            s.write_all(request.as_bytes()).await?;
            s.write_all(query).await?;
            s.flush().await?;
            read_http_body(&mut s).await
        } else {
            let insecure = hostname.is_empty();
            let sni = if insecure {
                host.clone()
            } else {
                hostname.to_string()
            };
            let connector = if insecure {
                crate::tls_transport::insecure_tls_connector().map_err(io_other)?
            } else {
                crate::tls_transport::default_tls_connector().map_err(io_other)?
            };
            let mut s = connector.connect(&sni, stream).await.map_err(io_other)?;
            s.write_all(request.as_bytes()).await?;
            s.write_all(query).await?;
            s.flush().await?;
            read_http_body(&mut s).await
        }
    };

    tokio::time::timeout(timeout, run)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "doh timeout"))?
}

/// Reads an HTTP/1.1 response and returns the body, requiring a 200.
async fn read_http_body<S>(stream: &mut S) -> io::Result<Vec<u8>>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    let mut header_end = None;

    // Read at least the whole header block.
    while header_end.is_none() {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        header_end = find_header_end(&buf);
        if buf.len() > 64 * 1024 {
            return Err(wire_err("DoH response header too large"));
        }
    }
    let header_end = header_end.ok_or_else(|| wire_err("truncated DoH response"))?;

    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut headers);
    resp.parse(&buf[..header_end])
        .map_err(|e| wire_err(format!("bad DoH response: {}", e)))?;
    let code = resp.code.unwrap_or(0);
    if code != 200 {
        return Err(io_other(format!("returned status code {}", code)));
    }
    let content_length = resp
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-length"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .and_then(|v| v.trim().parse::<usize>().ok());

    let mut body = buf[header_end..].to_vec();
    match content_length {
        Some(len) => {
            while body.len() < len {
                let n = stream.read(&mut chunk).await?;
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&chunk[..n]);
            }
            body.truncate(len);
        }
        None => loop {
            // Connection: close -- read to EOF.
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        },
    }
    Ok(body)
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// Performs one exchange against a single name server.
pub async fn ns_exchange(
    ns: &NameServer,
    query: &[u8],
    timeout: Duration,
    chain: Option<&Chain>,
) -> io::Result<Vec<u8>> {
    let (proto, chained) = ns.protocol_kind();
    let chain = if chained { chain } else { None };
    match proto {
        NsProtocol::Udp => exchange_udp(&ns.dial_addr(), query, timeout).await,
        NsProtocol::Tcp => exchange_tcp(&ns.dial_addr(), query, timeout, chain).await,
        NsProtocol::Tls => exchange_tls(&ns.dial_addr(), &ns.hostname, query, timeout, chain).await,
        NsProtocol::Https => exchange_doh(&ns.addr, &ns.hostname, query, timeout, chain).await,
    }
}

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

/// gost: `newResolverCacheKey` -- `"<name><class>.<type>"` (resolver.go:591-597).
pub fn cache_key(name: &str, qclass: u16, qtype: u16) -> String {
    format!("{}{}.{}", name, class_name(qclass), type_name(qtype))
}

#[derive(Clone, Debug)]
struct CacheItem {
    bytes: Vec<u8>,
    ts: Instant,
    /// The configured TTL; `Duration::ZERO` means "no configured limit".
    ttl: Duration,
    /// Smallest TTL over the answer RRs, `None` when there were no answers.
    min_rr_ttl: Option<u32>,
}

#[derive(Debug, Default)]
struct ResolverCache {
    map: Mutex<HashMap<String, CacheItem>>,
}

impl ResolverCache {
    /// gost: `loadCache` (resolver.go:613-641). Honours BOTH the configured TTL
    /// and each answer RR's own TTL.
    fn load(&self, key: &str) -> Option<Vec<u8>> {
        let mut map = self.map.lock().unwrap();
        let item = map.get(key)?;
        let elapsed = item.ts.elapsed();

        if item.ttl > Duration::ZERO && elapsed > item.ttl {
            map.remove(key);
            return None;
        }
        if let Some(rr_ttl) = item.min_rr_ttl {
            if elapsed > Duration::from_secs(rr_ttl as u64) {
                map.remove(key);
                return None;
            }
        }
        Some(item.bytes.clone())
    }

    /// gost: `storeCache` (resolver.go:643-656). A negative configured TTL
    /// disables caching entirely.
    fn store(&self, key: &str, bytes: &[u8], msg: &Message, ttl: Duration, ttl_negative: bool) {
        if key.is_empty() || ttl_negative {
            return;
        }
        self.map.lock().unwrap().insert(
            key.to_string(),
            CacheItem {
                bytes: bytes.to_vec(),
                ts: Instant::now(),
                ttl,
                min_rr_ttl: msg.min_answer_ttl(),
            },
        );
    }

    fn clear(&self) {
        self.map.lock().unwrap().clear();
    }

    fn len(&self) -> usize {
        self.map.lock().unwrap().len()
    }
}

// ---------------------------------------------------------------------------
// Resolver
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
struct State {
    // Values parsed from the config file / inline spec.
    servers: Vec<NameServer>,
    domain: String,
    period: Duration,
    // Effective values: config file first, then overridden by `init` options.
    ttl: Duration,
    ttl_negative: bool,
    timeout: Duration,
    prefer: String,
    src_ip: Option<IpAddr>,
    // The `init` overrides themselves, re-applied after every reload exactly
    // like gost's `Reload` -> `Init` sequence (resolver.go:535).
    opt_ttl: Duration,
    opt_ttl_negative: bool,
    opt_timeout: Duration,
    opt_prefer: String,
    opt_src_ip: Option<IpAddr>,
}

impl State {
    /// gost: `resolver.Init` (resolver.go:214-258) -- options override the file.
    fn apply_options(&mut self) {
        if self.opt_timeout != Duration::ZERO {
            self.timeout = self.opt_timeout;
        }
        if self.opt_ttl != Duration::ZERO || self.opt_ttl_negative {
            self.ttl = self.opt_ttl;
            self.ttl_negative = self.opt_ttl_negative;
        }
        if !self.opt_prefer.is_empty() {
            self.prefer = self.opt_prefer.clone();
        }
        if self.opt_src_ip.is_some() {
            self.src_ip = self.opt_src_ip;
        }
    }

    /// gost: `timeout <= 0 -> DefaultResolverTimeout` (resolver.go:230-232).
    fn effective_timeout(&self) -> Duration {
        if self.timeout == Duration::ZERO {
            DEFAULT_RESOLVER_TIMEOUT
        } else {
            self.timeout
        }
    }
}

struct Inner {
    state: RwLock<State>,
    cache: ResolverCache,
    /// gost signals "stopped" by closing a channel and returning a negative
    /// `Period()`. `reload::period_reload` cannot express a negative
    /// `Duration`, so the stopped state lives in this flag and `period()`
    /// reports `Duration::ZERO` once stopped, which makes `period_reload`
    /// return. Same convention as `Bypass` and `LocalAuthenticator`.
    stopped: AtomicBool,
    /// Set when `init`/`set_chain` wired a proxy chain, so `*-chain` name
    /// servers can be dialled through it (gost: `ChainResolverOption`).
    chain: RwLock<Option<Arc<Chain>>>,
}

/// A name resolver holding a list of name servers.
///
/// Cheap to clone: all state is shared behind an `Arc`, so a `Resolver` stored
/// in `ChainOptions` and in `Chain` refers to the same cache and the same live
/// reloaded configuration.
#[derive(Clone)]
pub struct Resolver {
    inner: Arc<Inner>,
}

impl fmt::Debug for Resolver {
    /// Hand written so that `Chain`'s derived `Debug` cannot recurse through
    /// `Resolver -> Chain -> Resolver -> ...`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let st = self.inner.state.read().unwrap();
        f.debug_struct("Resolver")
            .field("servers", &st.servers)
            .field("ttl", &st.ttl)
            .field("timeout", &st.timeout)
            .field("period", &st.period)
            .field("domain", &st.domain)
            .field("prefer", &st.prefer)
            .field("src_ip", &st.src_ip)
            .field("chained", &self.inner.chain.read().unwrap().is_some())
            .field("stopped", &self.stopped())
            .finish()
    }
}

impl Default for Resolver {
    fn default() -> Self {
        Self::with_servers(Vec::new())
    }
}

impl Resolver {
    /// Backwards compatible constructor: each string is a name server spec in
    /// gost's inline form (`8.8.8.8`, `1.1.1.1/tcp`, `https://dns.google/dns-query`).
    pub fn new(servers: Vec<String>) -> Self {
        let servers = servers
            .iter()
            .filter_map(|s| parse_ns_spec(s.trim()))
            .collect();
        let r = Self::with_servers(servers);
        r.inner.state.write().unwrap().prefer = "ipv4".to_string();
        r
    }

    pub fn with_servers(servers: Vec<NameServer>) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: RwLock::new(State {
                    servers,
                    ..Default::default()
                }),
                cache: ResolverCache::default(),
                stopped: AtomicBool::new(false),
                chain: RwLock::new(None),
            }),
        }
    }

    /// gost's `parseResolver` (cmd/gost/cfg.go:226-281): if `cfg` names a
    /// readable file, load it as a resolver config; otherwise treat it as a
    /// comma separated inline list. Returns `None` for an empty spec.
    ///
    /// The caller is responsible for spawning [`crate::reload::period_reload`]
    /// when the spec was a file.
    pub fn parse(cfg: &str) -> Option<Resolver> {
        if cfg.is_empty() {
            return None;
        }
        match std::fs::File::open(cfg) {
            Ok(f) => {
                let r = Resolver::with_servers(Vec::new());
                if let Err(e) = r.reload(f) {
                    debug!("[resolver] {}: {}", cfg, e);
                }
                Some(r)
            }
            Err(_) => Some(Resolver::from_inline(cfg)),
        }
    }

    /// The inline, comma separated form accepted by gost's `parseResolver`.
    pub fn from_inline(cfg: &str) -> Resolver {
        let servers = cfg
            .split(',')
            .filter_map(|s| parse_ns_spec(s.trim()))
            .collect();
        Resolver::with_servers(servers)
    }

    /// gost: `resolver.Init(ChainResolverOption, TimeoutResolverOption,
    /// TTLResolverOption, PreferResolverOption, SrcIPResolverOption)`
    /// as called from cmd/gost/route.go:641-647. Zero/empty arguments mean
    /// "leave the config file value alone".
    pub fn init(
        &self,
        chain: Option<Arc<Chain>>,
        timeout: Duration,
        ttl: Duration,
        prefer: &str,
        src_ip: Option<IpAddr>,
    ) {
        if chain.is_some() {
            *self.inner.chain.write().unwrap() = chain;
        }
        let mut st = self.inner.state.write().unwrap();
        if timeout != Duration::ZERO {
            st.opt_timeout = timeout;
        }
        if ttl != Duration::ZERO {
            st.opt_ttl = ttl;
        }
        if !prefer.is_empty() {
            st.opt_prefer = prefer.to_ascii_lowercase();
        }
        if src_ip.is_some() {
            st.opt_src_ip = src_ip;
        }
        st.apply_options();
    }

    /// Disables caching, the way a negative `ttl` in the config file does.
    pub fn set_ttl_disabled(&self) {
        let mut st = self.inner.state.write().unwrap();
        st.opt_ttl_negative = true;
        st.opt_ttl = Duration::ZERO;
        st.apply_options();
    }

    pub fn set_chain(&self, chain: Arc<Chain>) {
        *self.inner.chain.write().unwrap() = Some(chain);
    }

    pub fn set_prefer(&self, prefer: &str) {
        let mut st = self.inner.state.write().unwrap();
        st.opt_prefer = prefer.to_ascii_lowercase();
        st.apply_options();
    }

    pub fn set_src_ip(&self, ip: Option<IpAddr>) {
        let mut st = self.inner.state.write().unwrap();
        st.opt_src_ip = ip;
        st.apply_options();
    }

    pub fn set_timeout(&self, timeout: Duration) {
        let mut st = self.inner.state.write().unwrap();
        st.opt_timeout = timeout;
        st.apply_options();
    }

    pub fn servers(&self) -> Vec<NameServer> {
        self.inner.state.read().unwrap().servers.clone()
    }

    pub fn add_server(&self, ns: NameServer) {
        self.inner.state.write().unwrap().servers.push(ns);
    }

    pub fn is_empty(&self) -> bool {
        self.inner.state.read().unwrap().servers.is_empty()
    }

    pub fn prefer(&self) -> String {
        self.inner.state.read().unwrap().prefer.clone()
    }

    pub fn domain(&self) -> String {
        self.inner.state.read().unwrap().domain.clone()
    }

    /// The configured TTL (gost: `resolver.TTL()`).
    pub fn ttl(&self) -> Duration {
        self.inner.state.read().unwrap().ttl
    }

    pub fn timeout(&self) -> Duration {
        self.inner.state.read().unwrap().effective_timeout()
    }

    pub fn src_ip(&self) -> Option<IpAddr> {
        self.inner.state.read().unwrap().src_ip
    }

    pub fn cache_len(&self) -> usize {
        self.inner.cache.len()
    }

    pub fn clear_cache(&self) {
        self.inner.cache.clear();
    }

    fn chain(&self) -> Option<Arc<Chain>> {
        self.inner.chain.read().unwrap().clone()
    }

    // -- resolution ------------------------------------------------------

    /// Returns the host's IPv4 and IPv6 addresses.
    /// gost: `resolver.Resolve` (resolver.go:270-300).
    pub async fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        if host.is_empty() {
            return Ok(Vec::new());
        }

        // IP literal short circuit (resolver.go:275-277).
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        let st = self.inner.state.read().unwrap().clone();

        // `domain` search suffix (resolver.go:279-281).
        let host = if !host.contains('.') && !st.domain.is_empty() {
            format!("{}.{}", host, st.domain)
        } else {
            host.to_string()
        };

        // No name servers configured: fall back to the system resolver so a
        // resolver-less deployment still works (gost simply has no resolver at
        // all in that case and lets the OS dial).
        if st.servers.is_empty() {
            return system_lookup(&host, &st.prefer).await;
        }

        // Multi-server failover (resolver.go:284-297).
        let chain = self.chain();
        let mut ips: Vec<IpAddr> = Vec::new();
        let mut last_err: Option<io::Error> = None;
        for ns in &st.servers {
            match self.resolve_via(ns, &host, &st, chain.as_deref()).await {
                Ok(v) => {
                    debug!("[resolver] {} via {} {:?}", host, ns, v);
                    ips = v;
                    last_err = None;
                    if !ips.is_empty() {
                        break;
                    }
                }
                Err(e) => {
                    debug!("[resolver] {} via {} : {}", host, ns, e);
                    last_err = Some(e);
                }
            }
        }

        if ips.is_empty() {
            if let Some(e) = last_err {
                return Err(e);
            }
        }
        Ok(ips)
    }

    /// gost: `resolver.resolve` -- prefer ipv4/ipv6 with fallback
    /// (resolver.go:302-322). Two SEPARATE queries, not one sorted lookup.
    async fn resolve_via(
        &self,
        ns: &NameServer,
        host: &str,
        st: &State,
        chain: Option<&Chain>,
    ) -> io::Result<Vec<IpAddr>> {
        if st.prefer == "ipv6" {
            if let Ok(ips) = self.query(ns, host, TYPE_AAAA, st, chain).await {
                if !ips.is_empty() {
                    return Ok(ips);
                }
            }
            return self.query(ns, host, TYPE_A, st, chain).await;
        }

        if let Ok(ips) = self.query(ns, host, TYPE_A, st, chain).await {
            if !ips.is_empty() {
                return Ok(ips);
            }
        }
        self.query(ns, host, TYPE_AAAA, st, chain).await
    }

    /// gost: `resolveIPs` (resolver.go:336-358).
    async fn query(
        &self,
        ns: &NameServer,
        host: &str,
        qtype: u16,
        st: &State,
        chain: Option<&Chain>,
    ) -> io::Result<Vec<IpAddr>> {
        let name = fqdn(host);
        let key = cache_key(&name, CLASS_IN, qtype);

        if let Some(bytes) = self.inner.cache.load(&key) {
            debug!("[resolver] cache hit {}", key);
            let mr = Message::decode(&bytes)?;
            return Ok(mr.answer_ips());
        }

        let mut mq = Message::query(rand::random::<u16>(), &name, qtype);
        if let Some(ip) = st.src_ip {
            mq.additionals.push(edns0_subnet_opt(ip, DEFAULT_UDP_SIZE));
        }
        let query = mq.encode()?;

        let reply = ns_exchange(ns, &query, st.effective_timeout(), chain).await?;
        let mr = Message::decode(&reply)?;
        self.inner
            .cache
            .store(&key, &reply, &mr, st.ttl, st.ttl_negative);
        Ok(mr.answer_ips())
    }

    /// Raw wire-format passthrough used by the DNS server.
    /// gost: `resolver.Exchange` (resolver.go:382-424).
    pub async fn exchange(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let mq = Message::decode(query)?;
        if mq.questions.is_empty() {
            return Err(io_other("empty question"));
        }

        let st = self.inner.state.read().unwrap().clone();

        // Only cache single-question messages (resolver.go:394).
        let key = if mq.questions.len() == 1 {
            let q = &mq.questions[0];
            let key = cache_key(&q.name, q.qclass, q.qtype);
            if let Some(mut bytes) = self.inner.cache.load(&key) {
                debug!("[dns] exchange message {} (cached)", mq.id);
                set_msg_id(&mut bytes, mq.id);
                return Ok(bytes);
            }
            key
        } else {
            String::new()
        };

        // EDNS0 client subnet (resolver.go:410).
        let outbound: Vec<u8> = match st.src_ip {
            Some(ip) => {
                let size = mq.edns0_udp_size().unwrap_or(DEFAULT_UDP_SIZE);
                let mut m = mq.clone();
                m.remove_opt();
                m.additionals.push(edns0_subnet_opt(ip, size));
                m.encode()?
            }
            None => query.to_vec(),
        };

        if st.servers.is_empty() {
            return Err(io_other("no name server configured"));
        }

        let chain = self.chain();
        let mut last_err: Option<io::Error> = None;
        for ns in &st.servers {
            debug!("[dns] exchange message {} via {}", mq.id, ns);
            match ns_exchange(ns, &outbound, st.effective_timeout(), chain.as_deref()).await {
                Ok(mut reply) => {
                    if let Ok(mr) = Message::decode(&reply) {
                        self.inner
                            .cache
                            .store(&key, &reply, &mr, st.ttl, st.ttl_negative);
                    }
                    set_msg_id(&mut reply, mq.id);
                    return Ok(reply);
                }
                Err(e) => {
                    debug!("[dns] exchange message {} via {}: {}", mq.id, ns, e);
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| io_other("no name server answered")))
    }

    // -- live reload -----------------------------------------------------

    /// Parses a resolver config file. gost: `resolver.Reload`
    /// (resolver.go:448-538).
    pub fn reload(&self, reader: impl io::Read) -> io::Result<()> {
        self.reload_impl(reader)
    }

    fn reload_impl(&self, reader: impl io::Read) -> io::Result<()> {
        use io::BufRead;

        if self.stopped() {
            return Ok(());
        }

        let buf = io::BufReader::new(reader);
        let mut ttl = Duration::ZERO;
        let mut ttl_negative = false;
        let mut timeout = Duration::ZERO;
        let mut period = Duration::ZERO;
        let mut domain = String::new();
        let mut prefer = String::new();
        let mut src_ip: Option<IpAddr> = None;
        let mut servers: Vec<NameServer> = Vec::new();

        for line in buf.lines() {
            let line = line?;
            let mut ss: Vec<&str> = split_line_ref(&line);
            if ss.is_empty() {
                continue;
            }

            // Copy the keyword out so the `nameserver` arm may mutate `ss`.
            let head: &str = ss[0];
            match head {
                "timeout" => {
                    if ss.len() > 1 {
                        timeout = parse_go_duration(ss[1]).unwrap_or(Duration::ZERO);
                    }
                    continue;
                }
                "ttl" => {
                    if ss.len() > 1 {
                        let (neg, d) = parse_signed_go_duration(ss[1]);
                        ttl = d;
                        ttl_negative = neg;
                    }
                    continue;
                }
                "reload" => {
                    if ss.len() > 1 {
                        period = parse_go_duration(ss[1]).unwrap_or(Duration::ZERO);
                    }
                    continue;
                }
                "domain" => {
                    if ss.len() > 1 {
                        domain = ss[1].to_string();
                    }
                    continue;
                }
                // Not supported in /etc/resolv.conf terms (resolver.go:483).
                "search" | "sortlist" | "options" => continue,
                "prefer" => {
                    if ss.len() > 1 {
                        prefer = ss[1].to_ascii_lowercase();
                    }
                    continue;
                }
                "ip" => {
                    if ss.len() > 1 {
                        src_ip = ss[1].parse::<IpAddr>().ok();
                    }
                    continue;
                }
                "nameserver" => {
                    // gost: strip the keyword then fall through to `default`.
                    if ss.len() <= 1 {
                        continue;
                    }
                    ss.remove(0);
                }
                _ => {}
            }

            let mut ns = NameServer::default();
            match ss.len() {
                0 => continue,
                1 => ns.addr = ss[0].to_string(),
                2 => {
                    ns.addr = ss[0].to_string();
                    ns.protocol = ss[1].to_string();
                }
                _ => {
                    ns.addr = ss[0].to_string();
                    ns.protocol = ss[1].to_string();
                    ns.hostname = ss[2].to_string();
                }
            }
            // resolver.go:514-516
            if ns.addr.starts_with("https") && ns.protocol.is_empty() {
                ns.protocol = "https".to_string();
            }
            servers.push(ns);
        }

        {
            let mut st = self.inner.state.write().unwrap();
            st.ttl = ttl;
            st.ttl_negative = ttl_negative;
            st.timeout = timeout;
            st.domain = domain;
            st.period = period;
            st.prefer = prefer;
            st.src_ip = src_ip;
            st.servers = servers;
            // gost's Reload ends with r.Init(), which re-applies the options
            // set from the command line over the file values.
            st.apply_options();
        }

        // The server set changed, so previously cached answers may have come
        // from a name server that is no longer configured.
        self.inner.cache.clear();
        Ok(())
    }

    /// gost: `Period()`. Reports `Duration::ZERO` once stopped, which makes
    /// `reload::period_reload` return.
    pub fn period(&self) -> Duration {
        self.period_impl()
    }

    fn period_impl(&self) -> Duration {
        if self.stopped() {
            return Duration::ZERO;
        }
        self.inner.state.read().unwrap().period
    }

    /// gost: `Stop()`.
    pub fn stop(&self) {
        self.inner.stopped.store(true, Ordering::SeqCst);
    }

    /// gost: `Stopped()`.
    pub fn stopped(&self) -> bool {
        self.inner.stopped.load(Ordering::SeqCst)
    }
}

impl fmt::Display for Resolver {
    /// gost: `resolver.String()` (resolver.go:570-586).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let st = self.inner.state.read().unwrap();
        writeln!(f, "TTL {:?}", st.ttl)?;
        writeln!(f, "Reload {:?}", st.period)?;
        writeln!(f, "Domain {}", st.domain)?;
        for ns in &st.servers {
            writeln!(f, "{}", ns)?;
        }
        Ok(())
    }
}

impl Reloader for Resolver {
    fn reload(&self, reader: Box<dyn io::Read + Send>) -> io::Result<()> {
        self.reload_impl(reader)
    }

    fn period(&self) -> Duration {
        self.period_impl()
    }
}

impl Stoppable for Resolver {
    fn stop(&self) {
        self.inner.stopped.store(true, Ordering::SeqCst);
    }

    fn stopped(&self) -> bool {
        self.inner.stopped.load(Ordering::SeqCst)
    }
}

/// gost's inline name server spec, one element of the comma separated list
/// accepted by `parseResolver` (cmd/gost/cfg.go:233-267).
pub fn parse_ns_spec(s: &str) -> Option<NameServer> {
    if s.is_empty() {
        return None;
    }
    if s.starts_with("https") {
        // "https://..." or "https-chain://..."
        let url = url::Url::parse(s).ok()?;
        if url.scheme().is_empty() {
            return None;
        }
        let protocol = if url.scheme() == "https-chain" {
            "https-chain"
        } else {
            "https"
        };
        return Some(NameServer::new(s).with_protocol(protocol));
    }

    let parts: Vec<&str> = s.split('/').collect();
    match parts.len() {
        1 => Some(NameServer::new(parts[0])),
        2 => Some(NameServer::new(parts[0]).with_protocol(parts[1])),
        _ => None,
    }
}

/// Like [`parse_go_duration`], but reports whether the value was negative.
///
/// gost stores a negative `ttl` and uses it as "never cache"
/// (resolver.go:644). `std::time::Duration` is unsigned, so the sign is
/// returned separately.
pub fn parse_signed_go_duration(s: &str) -> (bool, Duration) {
    if let Some(rest) = s.strip_prefix('-') {
        let d = parse_go_duration(rest).unwrap_or(Duration::ZERO);
        if d > Duration::ZERO {
            return (true, Duration::ZERO);
        }
        return (false, Duration::ZERO);
    }
    (false, parse_go_duration(s).unwrap_or(Duration::ZERO))
}

/// System resolver fallback, used only when no name server is configured.
/// Keeps the historical ordering behaviour of this module.
async fn system_lookup(host: &str, prefer: &str) -> io::Result<Vec<IpAddr>> {
    let addrs: Vec<IpAddr> = tokio::net::lookup_host(format!("{}:0", host))
        .await?
        .map(|a| a.ip())
        .collect();

    let (first, second): (Vec<IpAddr>, Vec<IpAddr>) = if prefer == "ipv6" {
        addrs.iter().partition(|a| a.is_ipv6())
    } else {
        addrs.iter().partition(|a| a.is_ipv4())
    };
    let mut out = first;
    out.extend(second);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicUsize;

    // -- wire codec ------------------------------------------------------

    #[test]
    fn test_encode_decode_query_roundtrip() {
        let m = Message::query(0x1234, "example.com", TYPE_A);
        let bytes = m.encode().unwrap();
        let back = Message::decode(&bytes).unwrap();
        assert_eq!(back, m);
        assert_eq!(back.id, 0x1234);
        assert_eq!(back.questions[0].name, "example.com.");
        assert_eq!(back.questions[0].qtype, TYPE_A);
        assert_eq!(back.questions[0].qclass, CLASS_IN);
        assert_eq!(back.flags, FLAG_RD);
    }

    #[test]
    fn test_encode_decode_answer_roundtrip() {
        let mut m = Message::query(7, "example.com", TYPE_A);
        m.flags |= FLAG_QR;
        m.answers.push(Rr {
            name: "example.com.".into(),
            rtype: TYPE_A,
            rclass: CLASS_IN,
            ttl: 300,
            rdata: vec![93, 184, 216, 34],
        });
        m.answers.push(Rr {
            name: "example.com.".into(),
            rtype: TYPE_AAAA,
            rclass: CLASS_IN,
            ttl: 60,
            rdata: Ipv6Addr::new(0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25c8, 0x1946)
                .octets()
                .to_vec(),
        });
        let bytes = m.encode().unwrap();
        let back = Message::decode(&bytes).unwrap();
        assert_eq!(back, m);
        assert!(back.is_response());
        assert_eq!(back.min_answer_ttl(), Some(60));
        // gost walks the answer section in wire order and appends whichever of
        // AAAA/A the record happens to be (resolver.go:348-355), so the output
        // order is the answer order, not "AAAA first".
        assert_eq!(
            back.answer_ips(),
            vec![
                "93.184.216.34".parse::<IpAddr>().unwrap(),
                "2606:2800:220:1:248:1893:25c8:1946"
                    .parse::<IpAddr>()
                    .unwrap(),
            ]
        );
    }

    #[test]
    fn test_decode_handles_compression_pointer() {
        // Hand built reply: question "a.example.com" A, answer name is a
        // pointer back to offset 12.
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&0x00ABu16.to_be_bytes());
        buf.extend_from_slice(&(FLAG_QR | FLAG_RD).to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes()); // qd
        buf.extend_from_slice(&1u16.to_be_bytes()); // an
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        encode_name("a.example.com.", &mut buf).unwrap();
        buf.extend_from_slice(&TYPE_A.to_be_bytes());
        buf.extend_from_slice(&CLASS_IN.to_be_bytes());
        // answer: pointer to 12
        buf.extend_from_slice(&[0xC0, 0x0C]);
        buf.extend_from_slice(&TYPE_A.to_be_bytes());
        buf.extend_from_slice(&CLASS_IN.to_be_bytes());
        buf.extend_from_slice(&42u32.to_be_bytes());
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(&[10, 1, 2, 3]);

        let m = Message::decode(&buf).unwrap();
        assert_eq!(m.questions[0].name, "a.example.com.");
        assert_eq!(m.answers[0].name, "a.example.com.");
        assert_eq!(m.answers[0].ttl, 42);
        assert_eq!(m.answer_ips(), vec!["10.1.2.3".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn test_decode_rejects_pointer_loop() {
        let mut buf = vec![0u8; 12];
        buf[4] = 0;
        buf[5] = 1; // qdcount = 1
        buf.extend_from_slice(&[0xC0, 0x0C]); // points at itself
        buf.extend_from_slice(&TYPE_A.to_be_bytes());
        buf.extend_from_slice(&CLASS_IN.to_be_bytes());
        assert!(Message::decode(&buf).is_err());
    }

    #[test]
    fn test_decode_rejects_short_message() {
        assert!(Message::decode(&[0u8; 4]).is_err());
        assert!(Message::decode(&[]).is_err());
    }

    #[test]
    fn test_set_msg_id_in_place() {
        let m = Message::query(1, "example.com", TYPE_A);
        let mut bytes = m.encode().unwrap();
        set_msg_id(&mut bytes, 0xBEEF);
        assert_eq!(Message::decode(&bytes).unwrap().id, 0xBEEF);
    }

    #[test]
    fn test_edns0_subnet_v4_and_v6() {
        let rr = edns0_subnet_opt("1.2.3.4".parse().unwrap(), 1232);
        assert_eq!(rr.rtype, TYPE_OPT);
        assert_eq!(rr.rclass, 1232);
        let (family, mask, addr) = parse_edns0_subnet(&rr).unwrap();
        assert_eq!(family, 1);
        assert_eq!(mask, 32);
        assert_eq!(addr, vec![1, 2, 3, 4]);

        let rr6 = edns0_subnet_opt("2001:db8::1".parse().unwrap(), 512);
        let (family, mask, addr) = parse_edns0_subnet(&rr6).unwrap();
        assert_eq!(family, 2);
        assert_eq!(mask, 128);
        assert_eq!(addr.len(), 16);

        // Survives a round trip through the wire codec.
        let mut m = Message::query(3, "x.test", TYPE_A);
        m.additionals.push(rr.clone());
        let back = Message::decode(&m.encode().unwrap()).unwrap();
        assert_eq!(back.additionals[0], rr);
        assert_eq!(back.edns0_udp_size(), Some(1232));
    }

    #[test]
    fn test_cache_key_matches_gost_format() {
        assert_eq!(
            cache_key("example.com.", CLASS_IN, TYPE_A),
            "example.com.IN.A"
        );
        assert_eq!(
            cache_key("example.com.", CLASS_IN, TYPE_AAAA),
            "example.com.IN.AAAA"
        );
    }

    #[test]
    fn test_ensure_port() {
        assert_eq!(ensure_port("8.8.8.8", "53"), "8.8.8.8:53");
        assert_eq!(ensure_port("8.8.8.8:5353", "53"), "8.8.8.8:5353");
        assert_eq!(ensure_port("::1", "53"), "[::1]:53");
        assert_eq!(ensure_port("[::1]", "53"), "[::1]:53");
        assert_eq!(ensure_port("[::1]:5353", "53"), "[::1]:5353");
        assert_eq!(ensure_port("dns.example", "53"), "dns.example:53");
    }

    #[test]
    fn test_host_of() {
        assert_eq!(host_of("1.2.3.4:53"), "1.2.3.4");
        assert_eq!(host_of("[::1]:53"), "::1");
        assert_eq!(host_of("dns.example:853"), "dns.example");
    }

    // -- config parsing --------------------------------------------------

    #[test]
    fn test_reload_every_directive() {
        let cfg = "\
# comment line
timeout 10s
ttl 60s
reload 30s
domain example.org
prefer IPv6
ip 1.2.3.4
search foo bar
sortlist 10.0.0.0/8
options ndots:2
nameserver 8.8.8.8
nameserver 1.1.1.1 tcp
nameserver 1.0.0.1 tls one.one.one.one
nameserver https://dns.google/dns-query
9.9.9.9 udp
https://cloudflare-dns.com/dns-query
";
        let r = Resolver::default();
        r.reload(cfg.as_bytes()).unwrap();

        assert_eq!(r.timeout(), Duration::from_secs(10));
        assert_eq!(r.ttl(), Duration::from_secs(60));
        assert_eq!(r.period(), Duration::from_secs(30));
        assert_eq!(r.domain(), "example.org");
        assert_eq!(r.prefer(), "ipv6");
        assert_eq!(r.src_ip(), Some("1.2.3.4".parse().unwrap()));

        let ns = r.servers();
        assert_eq!(ns.len(), 6, "got {:?}", ns);

        assert_eq!(ns[0], NameServer::new("8.8.8.8"));
        assert_eq!(ns[0].protocol_kind(), (NsProtocol::Udp, false));
        assert_eq!(ns[0].dial_addr(), "8.8.8.8:53");

        assert_eq!(ns[1], NameServer::new("1.1.1.1").with_protocol("tcp"));
        assert_eq!(ns[1].protocol_kind(), (NsProtocol::Tcp, false));

        assert_eq!(
            ns[2],
            NameServer::new("1.0.0.1")
                .with_protocol("tls")
                .with_hostname("one.one.one.one")
        );
        assert_eq!(ns[2].protocol_kind(), (NsProtocol::Tls, false));
        assert_eq!(ns[2].hostname, "one.one.one.one");

        // `https` addr with no explicit protocol gets protocol "https".
        assert_eq!(ns[3].addr, "https://dns.google/dns-query");
        assert_eq!(ns[3].protocol, "https");

        assert_eq!(ns[4], NameServer::new("9.9.9.9").with_protocol("udp"));
        assert_eq!(ns[5].protocol, "https");

        // search / sortlist / options must not become name servers.
        assert!(!ns.iter().any(|n| n.addr == "foo" || n.addr == "ndots:2"));
    }

    #[test]
    fn test_reload_negative_ttl_disables_cache() {
        let r = Resolver::default();
        r.reload(&b"ttl -1s\nnameserver 8.8.8.8\n"[..]).unwrap();
        assert_eq!(r.ttl(), Duration::ZERO);
        let st = r.inner.state.read().unwrap();
        assert!(st.ttl_negative);
    }

    #[test]
    fn test_reload_bare_nameserver_keyword_ignored() {
        let r = Resolver::default();
        r.reload(&b"nameserver\n8.8.4.4\n"[..]).unwrap();
        assert_eq!(r.servers().len(), 1);
        assert_eq!(r.servers()[0].addr, "8.8.4.4");
    }

    #[test]
    fn test_reload_replaces_previous_config() {
        let r = Resolver::default();
        r.reload(&b"reload 5s\nnameserver 8.8.8.8\n"[..]).unwrap();
        assert_eq!(r.servers().len(), 1);
        r.reload(&b"nameserver 1.1.1.1\nnameserver 1.0.0.1\n"[..])
            .unwrap();
        assert_eq!(r.servers().len(), 2);
        assert_eq!(r.period(), Duration::ZERO);
    }

    #[test]
    fn test_init_options_override_file_and_survive_reload() {
        let r = Resolver::default();
        r.reload(&b"ttl 60s\ntimeout 1s\nprefer ipv4\nip 9.9.9.9\nnameserver 8.8.8.8\n"[..])
            .unwrap();
        assert_eq!(r.prefer(), "ipv4");

        r.init(
            None,
            Duration::from_secs(3),
            Duration::from_secs(120),
            "ipv6",
            Some("5.6.7.8".parse().unwrap()),
        );
        assert_eq!(r.timeout(), Duration::from_secs(3));
        assert_eq!(r.ttl(), Duration::from_secs(120));
        assert_eq!(r.prefer(), "ipv6");
        assert_eq!(r.src_ip(), Some("5.6.7.8".parse().unwrap()));

        // gost's Reload calls Init() again, so options keep winning.
        r.reload(&b"ttl 60s\ntimeout 1s\nprefer ipv4\nip 9.9.9.9\nnameserver 8.8.8.8\n"[..])
            .unwrap();
        assert_eq!(r.timeout(), Duration::from_secs(3));
        assert_eq!(r.ttl(), Duration::from_secs(120));
        assert_eq!(r.prefer(), "ipv6");
        assert_eq!(r.src_ip(), Some("5.6.7.8".parse().unwrap()));
    }

    #[test]
    fn test_default_timeout() {
        let r = Resolver::default();
        assert_eq!(r.timeout(), DEFAULT_RESOLVER_TIMEOUT);
    }

    #[test]
    fn test_inline_spec_parsing() {
        let r = Resolver::from_inline(
            "8.8.8.8, 1.1.1.1/tcp ,1.0.0.1/tls, https://dns.google/dns-query, https-chain://x.y/dns-query",
        );
        let ns = r.servers();
        assert_eq!(ns.len(), 5);
        assert_eq!(ns[0].addr, "8.8.8.8");
        assert_eq!(ns[0].protocol, "");
        assert_eq!(ns[1].protocol, "tcp");
        assert_eq!(ns[2].protocol, "tls");
        assert_eq!(ns[3].protocol, "https");
        assert_eq!(ns[4].protocol, "https-chain");
        assert_eq!(ns[4].protocol_kind(), (NsProtocol::Https, true));
    }

    #[test]
    fn test_protocol_parse_chain_suffix() {
        assert_eq!(NsProtocol::parse("udp"), (NsProtocol::Udp, false));
        assert_eq!(NsProtocol::parse("udp-chain"), (NsProtocol::Udp, true));
        assert_eq!(NsProtocol::parse("TCP-Chain"), (NsProtocol::Tcp, true));
        assert_eq!(NsProtocol::parse("tls-chain"), (NsProtocol::Tls, true));
        assert_eq!(NsProtocol::parse("https-chain"), (NsProtocol::Https, true));
        assert_eq!(NsProtocol::parse(""), (NsProtocol::Udp, false));
        assert_eq!(NsProtocol::parse("bogus"), (NsProtocol::Udp, false));
    }

    #[test]
    fn test_stop_makes_period_zero_and_reload_noop() {
        let r = Resolver::default();
        r.reload(&b"reload 30s\nnameserver 8.8.8.8\n"[..]).unwrap();
        assert_eq!(r.period(), Duration::from_secs(30));
        assert!(!r.stopped());

        Stoppable::stop(&r);
        assert!(r.stopped());
        assert_eq!(r.period(), Duration::ZERO);

        r.reload(&b"nameserver 1.1.1.1\n"[..]).unwrap();
        assert_eq!(r.servers()[0].addr, "8.8.8.8", "reload must be a no-op");
    }

    #[test]
    fn test_reloader_trait_impl() {
        let r = Resolver::default();
        Reloader::reload(&r, Box::new(&b"reload 15s\nnameserver 8.8.8.8\n"[..])).unwrap();
        let rl: &dyn Reloader = &r;
        assert_eq!(rl.period(), Duration::from_secs(15));
    }

    #[test]
    fn test_resolver_is_clone_and_shares_state() {
        let a = Resolver::default();
        let b = a.clone();
        a.reload(&b"nameserver 8.8.8.8\n"[..]).unwrap();
        assert_eq!(b.servers().len(), 1);
        assert!(format!("{:?}", b).contains("8.8.8.8"));
        assert!(format!("{}", a).contains("8.8.8.8"));
    }

    #[test]
    fn test_parse_signed_go_duration() {
        assert_eq!(
            parse_signed_go_duration("30s"),
            (false, Duration::from_secs(30))
        );
        assert_eq!(parse_signed_go_duration("-1s"), (true, Duration::ZERO));
        assert_eq!(parse_signed_go_duration("0"), (false, Duration::ZERO));
        assert_eq!(parse_signed_go_duration("junk"), (false, Duration::ZERO));
    }

    // -- fake name server ------------------------------------------------

    /// Description of what the fake name server should answer with.
    #[derive(Clone)]
    struct FakeAnswer {
        a: Vec<Ipv4Addr>,
        aaaa: Vec<Ipv6Addr>,
        ttl: u32,
    }

    impl Default for FakeAnswer {
        fn default() -> Self {
            Self {
                a: Vec::new(),
                aaaa: Vec::new(),
                ttl: 300,
            }
        }
    }

    fn build_reply(query: &Message, ans: &FakeAnswer) -> Message {
        let q = &query.questions[0];
        let mut m = Message {
            id: query.id,
            flags: FLAG_QR | FLAG_RD,
            questions: query.questions.clone(),
            ..Default::default()
        };
        if q.qtype == TYPE_A {
            for ip in &ans.a {
                m.answers.push(Rr {
                    name: q.name.clone(),
                    rtype: TYPE_A,
                    rclass: CLASS_IN,
                    ttl: ans.ttl,
                    rdata: ip.octets().to_vec(),
                });
            }
        } else if q.qtype == TYPE_AAAA {
            for ip in &ans.aaaa {
                m.answers.push(Rr {
                    name: q.name.clone(),
                    rtype: TYPE_AAAA,
                    rclass: CLASS_IN,
                    ttl: ans.ttl,
                    rdata: ip.octets().to_vec(),
                });
            }
        }
        m
    }

    /// Spawns a UDP name server on 127.0.0.1:0 and returns its address plus a
    /// counter of the queries it served and the last query it saw.
    async fn spawn_fake_ns(
        ans: FakeAnswer,
    ) -> (SocketAddr, Arc<AtomicUsize>, Arc<Mutex<Option<Message>>>) {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let last = Arc::new(Mutex::new(None));
        let c = count.clone();
        let l = last.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let (n, peer) = match sock.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let mq = match Message::decode(&buf[..n]) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                c.fetch_add(1, Ordering::SeqCst);
                *l.lock().unwrap() = Some(mq.clone());
                let mr = build_reply(&mq, &ans);
                let _ = sock.send_to(&mr.encode().unwrap(), peer).await;
            }
        });
        (addr, count, last)
    }

    // -- resolution ------------------------------------------------------

    #[tokio::test]
    async fn test_resolve_uses_configured_nameserver() {
        let (addr, count, _) = spawn_fake_ns(FakeAnswer {
            a: vec![Ipv4Addr::new(10, 0, 0, 7)],
            ..Default::default()
        })
        .await;

        let r = Resolver::default();
        r.reload(format!("nameserver {}\n", addr).as_bytes())
            .unwrap();

        let ips = r.resolve("example.com").await.unwrap();
        assert_eq!(ips, vec!["10.0.0.7".parse::<IpAddr>().unwrap()]);
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_resolve_ip_literal_short_circuit() {
        let r = Resolver::default();
        r.reload(&b"nameserver 127.0.0.1:1\n"[..]).unwrap();
        // No query is issued at all, so the unreachable server does not matter.
        assert_eq!(
            r.resolve("192.168.1.1").await.unwrap(),
            vec!["192.168.1.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            r.resolve("::1").await.unwrap(),
            vec!["::1".parse::<IpAddr>().unwrap()]
        );
    }

    #[tokio::test]
    async fn test_resolve_appends_domain_suffix() {
        let (addr, _, last) = spawn_fake_ns(FakeAnswer {
            a: vec![Ipv4Addr::new(10, 0, 0, 1)],
            ..Default::default()
        })
        .await;

        let r = Resolver::default();
        r.reload(format!("domain example.org\nnameserver {}\n", addr).as_bytes())
            .unwrap();

        r.resolve("web").await.unwrap();
        let q = last.lock().unwrap().clone().unwrap();
        assert_eq!(q.questions[0].name, "web.example.org.");

        // A name that already contains a dot is left alone.
        r.clear_cache();
        r.resolve("a.b").await.unwrap();
        let q = last.lock().unwrap().clone().unwrap();
        assert_eq!(q.questions[0].name, "a.b.");
    }

    #[tokio::test]
    async fn test_prefer_ipv4_falls_back_to_aaaa() {
        // Server only answers AAAA; prefer ipv4 must still find the address.
        let (addr, count, last) = spawn_fake_ns(FakeAnswer {
            aaaa: vec!["2001:db8::5".parse().unwrap()],
            ..Default::default()
        })
        .await;

        let r = Resolver::default();
        r.reload(format!("prefer ipv4\nnameserver {}\n", addr).as_bytes())
            .unwrap();

        let ips = r.resolve("v6only.test").await.unwrap();
        assert_eq!(ips, vec!["2001:db8::5".parse::<IpAddr>().unwrap()]);
        // Two SEPARATE queries: A first, then AAAA.
        assert_eq!(count.load(Ordering::SeqCst), 2);
        assert_eq!(
            last.lock().unwrap().clone().unwrap().questions[0].qtype,
            TYPE_AAAA
        );
    }

    #[tokio::test]
    async fn test_prefer_ipv6_queries_aaaa_first() {
        let (addr, count, last) = spawn_fake_ns(FakeAnswer {
            a: vec![Ipv4Addr::new(10, 0, 0, 3)],
            aaaa: vec!["2001:db8::9".parse().unwrap()],
            ..Default::default()
        })
        .await;

        let r = Resolver::default();
        r.reload(format!("prefer ipv6\nnameserver {}\n", addr).as_bytes())
            .unwrap();

        let ips = r.resolve("dual.test").await.unwrap();
        assert_eq!(ips, vec!["2001:db8::9".parse::<IpAddr>().unwrap()]);
        // Only the AAAA query was needed.
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(
            last.lock().unwrap().clone().unwrap().questions[0].qtype,
            TYPE_AAAA
        );
    }

    #[tokio::test]
    async fn test_prefer_ipv6_falls_back_to_a() {
        let (addr, count, _) = spawn_fake_ns(FakeAnswer {
            a: vec![Ipv4Addr::new(10, 0, 0, 4)],
            ..Default::default()
        })
        .await;

        let r = Resolver::default();
        r.reload(format!("prefer ipv6\nnameserver {}\n", addr).as_bytes())
            .unwrap();

        let ips = r.resolve("v4only.test").await.unwrap();
        assert_eq!(ips, vec!["10.0.0.4".parse::<IpAddr>().unwrap()]);
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_prefer_ipv4_default_stops_after_a() {
        let (addr, count, _) = spawn_fake_ns(FakeAnswer {
            a: vec![Ipv4Addr::new(10, 0, 0, 5)],
            aaaa: vec!["2001:db8::1".parse().unwrap()],
            ..Default::default()
        })
        .await;

        let r = Resolver::default();
        r.reload(format!("nameserver {}\n", addr).as_bytes())
            .unwrap();

        let ips = r.resolve("dual.test").await.unwrap();
        assert_eq!(ips, vec!["10.0.0.5".parse::<IpAddr>().unwrap()]);
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_multi_server_failover() {
        // First server is a closed port on localhost; second one answers.
        let (good, count, _) = spawn_fake_ns(FakeAnswer {
            a: vec![Ipv4Addr::new(10, 0, 0, 8)],
            ..Default::default()
        })
        .await;
        // Bind then drop to obtain a port nothing listens on.
        let dead = {
            let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            s.local_addr().unwrap()
        };

        let r = Resolver::default();
        r.reload(
            format!(
                "timeout 300ms\nnameserver {} tcp\nnameserver {}\n",
                dead, good
            )
            .as_bytes(),
        )
        .unwrap();

        let ips = r.resolve("failover.test").await.unwrap();
        assert_eq!(ips, vec!["10.0.0.8".parse::<IpAddr>().unwrap()]);
        assert!(count.load(Ordering::SeqCst) >= 1);
    }

    #[tokio::test]
    async fn test_resolve_error_when_all_servers_fail() {
        let dead = {
            let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            s.local_addr().unwrap()
        };
        let r = Resolver::default();
        r.reload(format!("timeout 200ms\nnameserver {} tcp\n", dead).as_bytes())
            .unwrap();
        assert!(r.resolve("nope.test").await.is_err());
    }

    #[tokio::test]
    async fn test_timeout_is_honoured() {
        // A socket that never answers.
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let r = Resolver::default();
        r.reload(format!("timeout 150ms\nnameserver {}\n", addr).as_bytes())
            .unwrap();

        let start = Instant::now();
        let res = r.resolve("slow.test").await;
        assert!(res.is_err());
        // Two queries (A then AAAA), each capped at 150ms.
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "{:?}",
            start.elapsed()
        );
        drop(sock);
    }

    // -- cache -----------------------------------------------------------

    #[tokio::test]
    async fn test_cache_hit_avoids_second_query() {
        let (addr, count, _) = spawn_fake_ns(FakeAnswer {
            a: vec![Ipv4Addr::new(10, 0, 0, 9)],
            ttl: 300,
            ..Default::default()
        })
        .await;

        let r = Resolver::default();
        r.reload(format!("ttl 60s\nnameserver {}\n", addr).as_bytes())
            .unwrap();

        let a = r.resolve("cached.test").await.unwrap();
        let b = r.resolve("cached.test").await.unwrap();
        assert_eq!(a, b);
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "second lookup must be cached"
        );
        assert_eq!(r.cache_len(), 1);
    }

    #[tokio::test]
    async fn test_cache_expires_on_configured_ttl() {
        // Long RR TTL, very short configured TTL: the configured TTL must win.
        let (addr, count, _) = spawn_fake_ns(FakeAnswer {
            a: vec![Ipv4Addr::new(10, 0, 0, 10)],
            ttl: 86400,
            ..Default::default()
        })
        .await;

        let r = Resolver::default();
        r.reload(format!("ttl 100ms\nnameserver {}\n", addr).as_bytes())
            .unwrap();

        r.resolve("ttl.test").await.unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);
        tokio::time::sleep(Duration::from_millis(250)).await;
        r.resolve("ttl.test").await.unwrap();
        assert_eq!(
            count.load(Ordering::SeqCst),
            2,
            "configured TTL must expire"
        );
    }

    #[tokio::test]
    async fn test_cache_expires_on_record_ttl() {
        // No configured TTL at all, but the RR TTL is 0 -> never reusable.
        let (addr, count, _) = spawn_fake_ns(FakeAnswer {
            a: vec![Ipv4Addr::new(10, 0, 0, 11)],
            ttl: 0,
            ..Default::default()
        })
        .await;

        let r = Resolver::default();
        r.reload(format!("nameserver {}\n", addr).as_bytes())
            .unwrap();

        r.resolve("rr.test").await.unwrap();
        tokio::time::sleep(Duration::from_millis(1100)).await;
        r.resolve("rr.test").await.unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 2, "RR TTL must expire");
    }

    #[tokio::test]
    async fn test_negative_ttl_disables_caching() {
        let (addr, count, _) = spawn_fake_ns(FakeAnswer {
            a: vec![Ipv4Addr::new(10, 0, 0, 12)],
            ttl: 3600,
            ..Default::default()
        })
        .await;

        let r = Resolver::default();
        r.reload(format!("ttl -1s\nnameserver {}\n", addr).as_bytes())
            .unwrap();

        r.resolve("nocache.test").await.unwrap();
        r.resolve("nocache.test").await.unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 2);
        assert_eq!(r.cache_len(), 0);
    }

    // -- exchange --------------------------------------------------------

    #[tokio::test]
    async fn test_exchange_wire_passthrough_and_cache() {
        let (addr, count, _) = spawn_fake_ns(FakeAnswer {
            a: vec![Ipv4Addr::new(10, 0, 0, 13)],
            ttl: 600,
            ..Default::default()
        })
        .await;

        let r = Resolver::default();
        r.reload(format!("ttl 60s\nnameserver {}\n", addr).as_bytes())
            .unwrap();

        let q1 = Message::query(0x1111, "wire.test", TYPE_A)
            .encode()
            .unwrap();
        let reply = r.exchange(&q1).await.unwrap();
        let mr = Message::decode(&reply).unwrap();
        assert_eq!(mr.id, 0x1111);
        assert_eq!(
            mr.answer_ips(),
            vec!["10.0.0.13".parse::<IpAddr>().unwrap()]
        );

        // A second query for the same question with a DIFFERENT id must be
        // served from cache but carry the new id.
        let q2 = Message::query(0x2222, "wire.test", TYPE_A)
            .encode()
            .unwrap();
        let reply2 = r.exchange(&q2).await.unwrap();
        let mr2 = Message::decode(&reply2).unwrap();
        assert_eq!(mr2.id, 0x2222);
        assert_eq!(mr2.answers, mr.answers);
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_exchange_rejects_malformed_and_empty_question() {
        let r = Resolver::default();
        r.reload(&b"nameserver 127.0.0.1:1\n"[..]).unwrap();
        assert!(r.exchange(&[0u8; 3]).await.is_err());

        let empty = Message {
            id: 1,
            flags: FLAG_RD,
            ..Default::default()
        }
        .encode()
        .unwrap();
        assert!(r.exchange(&empty).await.is_err());
    }

    #[tokio::test]
    async fn test_exchange_adds_edns0_subnet_from_ip_directive() {
        let (addr, _, last) = spawn_fake_ns(FakeAnswer {
            a: vec![Ipv4Addr::new(10, 0, 0, 14)],
            ..Default::default()
        })
        .await;

        let r = Resolver::default();
        r.reload(format!("ip 203.0.113.9\nnameserver {}\n", addr).as_bytes())
            .unwrap();

        let q = Message::query(5, "subnet.test", TYPE_A).encode().unwrap();
        r.exchange(&q).await.unwrap();

        let seen = last.lock().unwrap().clone().unwrap();
        let opt = seen
            .additionals
            .iter()
            .find(|rr| rr.rtype == TYPE_OPT)
            .expect("OPT record must be present");
        let (family, mask, ip) = parse_edns0_subnet(opt).unwrap();
        assert_eq!((family, mask), (1, 32));
        assert_eq!(ip, vec![203, 0, 113, 9]);
    }

    #[tokio::test]
    async fn test_resolve_adds_edns0_subnet_from_ip_directive() {
        let (addr, _, last) = spawn_fake_ns(FakeAnswer {
            a: vec![Ipv4Addr::new(10, 0, 0, 15)],
            ..Default::default()
        })
        .await;

        let r = Resolver::default();
        r.reload(format!("ip 2001:db8::1\nnameserver {}\n", addr).as_bytes())
            .unwrap();

        r.resolve("subnet6.test").await.unwrap();
        let seen = last.lock().unwrap().clone().unwrap();
        let opt = seen
            .additionals
            .iter()
            .find(|rr| rr.rtype == TYPE_OPT)
            .expect("OPT record must be present");
        let (family, mask, ip) = parse_edns0_subnet(opt).unwrap();
        assert_eq!((family, mask), (2, 128));
        assert_eq!(ip.len(), 16);
    }

    #[tokio::test]
    async fn test_tcp_nameserver() {
        // Minimal DNS-over-TCP name server on 127.0.0.1:0.
        let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match ln.accept().await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                tokio::spawn(async move {
                    let mut len = [0u8; 2];
                    if s.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let n = u16::from_be_bytes(len) as usize;
                    let mut q = vec![0u8; n];
                    if s.read_exact(&mut q).await.is_err() {
                        return;
                    }
                    let mq = Message::decode(&q).unwrap();
                    let mr = build_reply(
                        &mq,
                        &FakeAnswer {
                            a: vec![Ipv4Addr::new(10, 0, 0, 20)],
                            ..Default::default()
                        },
                    );
                    let body = mr.encode().unwrap();
                    let _ = s.write_all(&(body.len() as u16).to_be_bytes()).await;
                    let _ = s.write_all(&body).await;
                });
            }
        });

        let r = Resolver::default();
        r.reload(format!("nameserver {} tcp\n", addr).as_bytes())
            .unwrap();
        let ips = r.resolve("tcp.test").await.unwrap();
        assert_eq!(ips, vec!["10.0.0.20".parse::<IpAddr>().unwrap()]);
    }

    // -- legacy API ------------------------------------------------------

    #[tokio::test]
    async fn test_resolver_localhost() {
        // No name servers -> system resolver fallback, same as before.
        let r = Resolver::new(vec![]);
        let ips = r.resolve("localhost").await.unwrap();
        assert!(!ips.is_empty());
        assert!(ips.iter().any(|ip| {
            ip == &IpAddr::from([127, 0, 0, 1]) || ip == &IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1])
        }));
    }

    #[tokio::test]
    async fn test_resolver_invalid() {
        let r = Resolver::new(vec![]);
        let result = r.resolve("this.host.does.not.exist.invalid").await;
        assert!(result.is_err() || result.unwrap().is_empty());
    }

    #[test]
    fn test_resolver_new_parses_specs() {
        let r = Resolver::new(vec!["8.8.8.8".into(), "1.1.1.1/tcp".into()]);
        assert_eq!(r.servers().len(), 2);
        assert_eq!(r.servers()[1].protocol, "tcp");
        assert_eq!(r.prefer(), "ipv4");
    }

    #[test]
    fn test_parse_returns_none_for_empty() {
        assert!(Resolver::parse("").is_none());
        // Not a file -> treated as an inline list.
        let r = Resolver::parse("8.8.8.8,1.1.1.1/tcp").unwrap();
        assert_eq!(r.servers().len(), 2);
    }
}
