use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::{debug, info};

use crate::conn::ProxyConn;
use crate::handler::{Handler, HandlerError, HandlerOptions};
use crate::node::{Node, NodeGroup};
use crate::permissions::Can;
use crate::transport::transport;

// Relay protocol constants, per github.com/go-gost/relay (the module gost
// pins in go.mod). The header is:
//
//   VER(1) | FLAGS(1) | FEALEN(2, big-endian) | FEATURES(var)
//
// and each feature is TYPE(1) | LEN(2, big-endian) | DATA(var).
const RELAY_VERSION1: u8 = 0x01;
const RELAY_STATUS_OK: u8 = 0x00;
const RELAY_STATUS_BAD_REQUEST: u8 = 0x01;
const RELAY_STATUS_UNAUTHORIZED: u8 = 0x02;
const RELAY_STATUS_FORBIDDEN: u8 = 0x03;
const RELAY_STATUS_TIMEOUT: u8 = 0x04;
const RELAY_STATUS_SERVICE_UNAVAILABLE: u8 = 0x05;
const RELAY_STATUS_HOST_UNREACHABLE: u8 = 0x06;
const RELAY_STATUS_NETWORK_UNREACHABLE: u8 = 0x07;

const RELAY_FLAG_UDP: u8 = 0x80;

const FEATURE_USER_AUTH: u8 = 0x01;
const FEATURE_ADDR: u8 = 0x02;

const ADDR_IPV4: u8 = 0x01;
const ADDR_IPV6: u8 = 0x04;
const ADDR_DOMAIN: u8 = 0x03;

/// Size of the fixed relay header: version, flags, and a 16-bit feature length.
const RELAY_HEADER_LEN: usize = 4;

/// Size of the length prefix that precedes every datagram in UDP mode.
const RELAY_DGRAM_LEN_SIZE: usize = 2;

/// The datagram length is a 16-bit field, so anything larger cannot be framed.
/// gost rejects such a write outright (relay.go:324-327) rather than silently
/// splitting it, because splitting would invent a datagram boundary that the
/// peer would then deliver as two separate packets.
const RELAY_MAX_DATAGRAM: usize = 0xFFFF;

// --- Relay stream framing -----------------------------------------------
//
// In TCP mode (`FUDP` clear) the relay is a transparent byte pipe: whatever
// follows the handshake header is the payload, unframed.
//
// In UDP mode (`FUDP` set) every datagram is preceded by its length as a
// 16-bit big-endian integer:
//
//   +--------+--------+----------------+
//   | LEN_HI | LEN_LO |    DATAGRAM    |
//   +--------+--------+----------------+
//   |   1    |   1    |  LEN (0..FFFF) |
//   +--------+--------+----------------+
//
// gost reads that prefix in relayConn.Read (relay.go:302-314) and writes it in
// relayConn.Write (relay.go:330-334 for the first datagram, which rides along
// with the buffered handshake header, and relay.go:353-363 for every later
// one).
//
// Both peers also defer their half of the handshake:
//   * the server buffers its response and lets the first payload write flush
//     it (relay.go:252-258 buffers into `wbuf`, relay.go:329-340 flushes it),
//   * the client does not read that response until its first read
//     (relay.go:274-292, guarded by `once`).
// A client that instead blocks on the response right after sending its request
// therefore hangs forever against a real gost server, which is why the read is
// deferred here too.

/// Read-side state machine for [`RelayConn`].
enum ReadState {
    /// Client only: the server's 4-byte response header is still on the wire.
    Response,
    /// Client only: draining the response's feature block.
    ResponseFeatures(usize),
    /// TCP mode: everything from here on is raw payload.
    Raw,
    /// UDP mode: waiting for a datagram's 2-byte length prefix.
    Length,
    /// UDP mode: waiting for the datagram body of the given length.
    Payload(usize),
    /// The peer closed the stream on a frame boundary.
    Eof,
}

/// Wraps a relay stream in the relay protocol's data framing.
///
/// The wrapper is a transparent byte pipe in TCP mode and applies the 2-byte
/// big-endian datagram framing in UDP mode. It also owns the lazy half of the
/// handshake: the client's response read and the server's response write.
pub struct RelayConn<S> {
    inner: S,
    udp: bool,

    read_state: ReadState,
    read_buf: Vec<u8>,
    read_need: usize,
    /// One fully-received datagram, waiting to be handed to the caller. Held
    /// across `poll_read` calls so that a datagram larger than the caller's
    /// buffer is delivered in full rather than truncated, and so that two
    /// datagrams are never coalesced into a single read.
    plain: Vec<u8>,
    plain_pos: usize,

    /// Server only: the response header, held back until the first write.
    pending_header: Vec<u8>,
    out: Vec<u8>,
    out_pos: usize,
}

impl<S> RelayConn<S> {
    /// Client side. The server's response is read lazily, on the first read,
    /// so that a server which withholds it until it has payload to send does
    /// not deadlock the connection.
    pub fn client(inner: S, udp: bool) -> Self {
        Self {
            inner,
            udp,
            read_state: ReadState::Response,
            read_buf: Vec::with_capacity(RELAY_HEADER_LEN),
            read_need: RELAY_HEADER_LEN,
            plain: Vec::new(),
            plain_pos: 0,
            pending_header: Vec::new(),
            out: Vec::new(),
            out_pos: 0,
        }
    }

    /// Server side. `status` is buffered and written together with the first
    /// payload, mirroring gost's `resp.WriteTo(&sc.wbuf)`.
    pub fn server(inner: S, udp: bool, status: u8) -> Self {
        let (read_state, read_need) = if udp {
            (ReadState::Length, RELAY_DGRAM_LEN_SIZE)
        } else {
            (ReadState::Raw, 0)
        };
        Self {
            inner,
            udp,
            read_state,
            read_buf: Vec::with_capacity(RELAY_DGRAM_LEN_SIZE),
            read_need,
            plain: Vec::new(),
            plain_pos: 0,
            // VER | STATUS | FEALEN(2, big-endian), with no features.
            pending_header: vec![RELAY_VERSION1, status, 0x00, 0x00],
            out: Vec::new(),
            out_pos: 0,
        }
    }

    /// Moves past the handshake into whichever data framing this mode uses.
    fn enter_data_phase(&mut self) {
        if self.udp {
            self.read_state = ReadState::Length;
            self.read_need = RELAY_DGRAM_LEN_SIZE;
        } else {
            self.read_state = ReadState::Raw;
            self.read_need = 0;
        }
    }

    /// Queues the deferred response header, if it has not gone out already.
    /// Safe to append: the header is only ever queued before the first payload
    /// byte, so `out` is empty whenever `pending_header` is not.
    fn queue_pending_header(&mut self) {
        if !self.pending_header.is_empty() {
            let header = std::mem::take(&mut self.pending_header);
            self.out.extend_from_slice(&header);
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> RelayConn<S> {
    /// Reads until `read_buf` holds `read_need` bytes. `Ok(false)` means the
    /// peer closed the stream before that many arrived.
    fn poll_fill(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        while self.read_buf.len() < self.read_need {
            let start = self.read_buf.len();
            self.read_buf.resize(self.read_need, 0);
            let mut rb = ReadBuf::new(&mut self.read_buf[start..]);
            match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                Poll::Pending => {
                    self.read_buf.truncate(start);
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => {
                    self.read_buf.truncate(start);
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    self.read_buf.truncate(start + n);
                    if n == 0 {
                        return Poll::Ready(Ok(false));
                    }
                }
            }
        }
        Poll::Ready(Ok(true))
    }

    fn poll_flush_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.out.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.out[self.out_pos..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(n)) => self.out_pos += n,
            }
        }
        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for RelayConn<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();

        loop {
            // Hand back the datagram already in hand before pulling another,
            // so a single read never spans two datagrams.
            if me.plain_pos < me.plain.len() {
                let n = buf.remaining().min(me.plain.len() - me.plain_pos);
                buf.put_slice(&me.plain[me.plain_pos..me.plain_pos + n]);
                me.plain_pos += n;
                if me.plain_pos == me.plain.len() {
                    me.plain.clear();
                    me.plain_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            match me.read_state {
                ReadState::Eof => return Poll::Ready(Ok(())),
                ReadState::Raw => return Pin::new(&mut me.inner).poll_read(cx, buf),
                _ => {}
            }

            let complete = match me.poll_fill(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(c)) => c,
            };
            if !complete {
                return match me.read_state {
                    // A close before the handshake completes is never orderly.
                    ReadState::Response | ReadState::ResponseFeatures(_) => {
                        Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "relay: connection closed before the server response",
                        )))
                    }
                    _ if me.read_buf.is_empty() => {
                        // A close on a frame boundary is a normal end of stream.
                        me.read_state = ReadState::Eof;
                        Poll::Ready(Ok(()))
                    }
                    _ => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "relay: truncated datagram",
                    ))),
                };
            }

            match me.read_state {
                ReadState::Response => {
                    let header = std::mem::take(&mut me.read_buf);
                    if header[0] != RELAY_VERSION1 {
                        return Poll::Ready(Err(io::Error::other("relay: bad version")));
                    }
                    if header[1] != RELAY_STATUS_OK {
                        return Poll::Ready(Err(io::Error::other(format!(
                            "relay: {}",
                            relay_status_text(header[1])
                        ))));
                    }
                    let fea_len = u16::from_be_bytes([header[2], header[3]]) as usize;
                    if fea_len > 0 {
                        // Drain the reply's features so they are not mistaken
                        // for payload.
                        me.read_state = ReadState::ResponseFeatures(fea_len);
                        me.read_need = fea_len;
                    } else {
                        me.enter_data_phase();
                    }
                }
                ReadState::ResponseFeatures(_) => {
                    me.read_buf.clear();
                    me.enter_data_phase();
                }
                ReadState::Length => {
                    let block = std::mem::take(&mut me.read_buf);
                    let dlen = u16::from_be_bytes([block[0], block[1]]) as usize;
                    if dlen == 0 {
                        // An empty datagram carries nothing, and reporting it
                        // as a zero-byte read would look like end of stream.
                        me.read_need = RELAY_DGRAM_LEN_SIZE;
                        continue;
                    }
                    me.read_state = ReadState::Payload(dlen);
                    me.read_need = dlen;
                }
                ReadState::Payload(_) => {
                    me.plain = std::mem::take(&mut me.read_buf);
                    me.plain_pos = 0;
                    me.read_state = ReadState::Length;
                    me.read_need = RELAY_DGRAM_LEN_SIZE;
                }
                ReadState::Raw | ReadState::Eof => unreachable!("handled above"),
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for RelayConn<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if me.udp && buf.len() > RELAY_MAX_DATAGRAM {
            return Poll::Ready(Err(io::Error::other(format!(
                "relay: datagram of {} bytes exceeds the {}-byte maximum",
                buf.len(),
                RELAY_MAX_DATAGRAM
            ))));
        }

        // Bound memory by draining the previous frame before queueing another.
        match me.poll_flush_out(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }

        // Once the handshake is out of the way, TCP mode has nothing to add,
        // so pass the caller's buffer straight through without a copy.
        if !me.udp && me.pending_header.is_empty() {
            return Pin::new(&mut me.inner).poll_write(cx, buf);
        }

        me.queue_pending_header();
        if me.udp {
            me.out
                .extend_from_slice(&(buf.len() as u16).to_be_bytes());
        }
        me.out.extend_from_slice(buf);

        // Best-effort flush; whatever remains goes out on the next call.
        let _ = me.poll_flush_out(cx);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        // A flush means "get everything you are holding to the peer", and the
        // deferred response header is exactly that.
        me.queue_pending_header();
        match me.poll_flush_out(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => Pin::new(&mut me.inner).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        me.queue_pending_header();
        match me.poll_flush_out(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}

/// Relay connector (client side).
pub struct RelayConnector {
    pub user: Option<(String, Option<String>)>,
}

impl RelayConnector {
    pub fn new(user: Option<(String, Option<String>)>) -> Self {
        Self { user }
    }

    /// Connect via relay protocol.
    ///
    /// Returns the connection wrapped in [`RelayConn`], which applies the UDP
    /// datagram framing and reads the server's response lazily. The response
    /// is deliberately *not* read here: gost's server holds it back until it
    /// has payload to send (relay.go:252-258), so reading it eagerly would
    /// deadlock against a real gost server.
    pub async fn connect<S>(
        &self,
        mut conn: S,
        network: &str,
        address: &str,
    ) -> Result<RelayConn<S>, HandlerError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    {
        let udp = matches!(network, "udp" | "udp4" | "udp6");

        let mut req = Vec::new();
        req.push(RELAY_VERSION1);
        let flags = if udp { RELAY_FLAG_UDP } else { 0 };
        req.push(flags);

        // Add features length placeholder - we'll fill the features inline
        let mut features = Vec::new();

        // User auth feature
        if let Some((ref user, ref pass)) = self.user {
            let p = pass.as_deref().unwrap_or("");
            features.push(FEATURE_USER_AUTH);
            let user_bytes = user.as_bytes();
            let pass_bytes = p.as_bytes();
            let flen = 1 + user_bytes.len() + 1 + pass_bytes.len();
            features.extend_from_slice(&(flen as u16).to_be_bytes());
            features.push(user_bytes.len() as u8);
            features.extend_from_slice(user_bytes);
            features.push(pass_bytes.len() as u8);
            features.extend_from_slice(pass_bytes);
        }

        // Address feature
        if !address.is_empty() {
            if let Some((host, port_str)) = split_host_port(address) {
                if let Ok(port) = port_str.parse::<u16>() {
                    features.push(FEATURE_ADDR);
                    let mut addr_data = Vec::new();
                    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
                        addr_data.push(ADDR_IPV4);
                        addr_data.extend_from_slice(&ip.octets());
                    } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
                        addr_data.push(ADDR_IPV6);
                        addr_data.extend_from_slice(&ip.octets());
                    } else {
                        addr_data.push(ADDR_DOMAIN);
                        addr_data.push(host.len() as u8);
                        addr_data.extend_from_slice(host.as_bytes());
                    }
                    addr_data.extend_from_slice(&port.to_be_bytes());

                    features.extend_from_slice(&(addr_data.len() as u16).to_be_bytes());
                    features.extend_from_slice(&addr_data);
                }
            }
        }

        // Feature block length is a 16-bit big-endian field, not a byte.
        if features.len() > u16::MAX as usize {
            return Err(HandlerError::Proxy("relay: feature block too large".into()));
        }
        req.extend_from_slice(&(features.len() as u16).to_be_bytes());
        req.extend_from_slice(&features);

        conn.write_all(&req).await?;

        // The response header (and any features it carries) is validated and
        // drained by the wrapper on the first read, so both an eager server
        // and a lazy one work.
        Ok(RelayConn::client(conn, udp))
    }
}

/// Relay handler (server side).
pub struct RelayHandler {
    raddr: String,
    group: NodeGroup,
    options: HandlerOptions,
}

impl RelayHandler {
    pub fn new(raddr: &str, options: HandlerOptions) -> Self {
        let group = NodeGroup::new(Vec::new());
        let addrs: Vec<&str> = raddr.split(',').filter(|a| !a.is_empty()).collect();
        for (i, addr) in addrs.iter().enumerate() {
            let mut node = Node::default();
            node.id = i + 1;
            node.addr = addr.to_string();
            group.add_node(node);
        }

        Self {
            raddr: raddr.to_string(),
            group,
            options,
        }
    }
}

#[async_trait]
impl Handler for RelayHandler {
    async fn handle(&self, mut conn: ProxyConn) -> Result<(), HandlerError> {
        let peer_addr = conn.peer_addr_str();

        // Read request header
        let mut header = [0u8; RELAY_HEADER_LEN];
        conn.read_exact(&mut header).await?;

        if header[0] != RELAY_VERSION1 {
            return Err(HandlerError::Proxy("relay: bad version".into()));
        }

        let udp = (header[1] & RELAY_FLAG_UDP) != 0;
        let features_len = u16::from_be_bytes([header[2], header[3]]) as usize;

        // Read features
        let mut features_buf = vec![0u8; features_len];
        if features_len > 0 {
            conn.read_exact(&mut features_buf).await?;
        }

        // Parse features
        let mut user = String::new();
        let mut pass = String::new();
        let mut raddr = String::new();
        let mut pos = 0;

        while pos < features_buf.len() {
            let ftype = features_buf[pos];
            pos += 1;
            if pos + 2 > features_buf.len() {
                break;
            }
            let flen = u16::from_be_bytes([features_buf[pos], features_buf[pos + 1]]) as usize;
            pos += 2;
            if pos + flen > features_buf.len() {
                break;
            }
            let fdata = &features_buf[pos..pos + flen];
            pos += flen;

            match ftype {
                FEATURE_USER_AUTH => {
                    if !fdata.is_empty() {
                        let ulen = fdata[0] as usize;
                        if 1 + ulen < fdata.len() {
                            user = String::from_utf8_lossy(&fdata[1..1 + ulen]).to_string();
                            let plen = fdata[1 + ulen] as usize;
                            if 2 + ulen + plen <= fdata.len() {
                                pass = String::from_utf8_lossy(&fdata[2 + ulen..2 + ulen + plen])
                                    .to_string();
                            }
                        }
                    }
                }
                FEATURE_ADDR => {
                    if !fdata.is_empty() {
                        let (host, port) = parse_relay_addr(fdata);
                        raddr = format!("{}:{}", host, port);
                    }
                }
                _ => {}
            }
        }

        // Authenticate
        if let Some(ref auth) = self.options.authenticator {
            if !auth.authenticate(&user, &pass) {
                send_relay_reply(&mut conn, RELAY_STATUS_UNAUTHORIZED).await?;
                info!(
                    "[relay] {} -> {} : {} unauthorized",
                    peer_addr,
                    conn.local_addr().map(|a| a.to_string()).unwrap_or_default(),
                    user
                );
                return Err(HandlerError::AuthFailed);
            }
        }

        // Determine target
        if raddr.is_empty() {
            if self.group.nodes().is_empty() {
                send_relay_reply(&mut conn, RELAY_STATUS_BAD_REQUEST).await?;
                return Err(HandlerError::Proxy("relay: no target address".into()));
            }
        }

        let network = if udp { "udp" } else { "tcp" };
        if !Can(
            network,
            &raddr,
            self.options.whitelist.as_ref(),
            self.options.blacklist.as_ref(),
        ) {
            send_relay_reply(&mut conn, RELAY_STATUS_FORBIDDEN).await?;
            return Err(HandlerError::Forbidden);
        }

        let chain = self.options.chain.as_ref().cloned().unwrap_or_default();

        let mut node = Node::default();
        let target = if !self.group.nodes().is_empty() {
            if let Ok(n) = self.group.next() {
                node = n;
                node.addr.clone()
            } else {
                raddr.clone()
            }
        } else {
            raddr.clone()
        };

        info!("[relay] {} -> {}", peer_addr, target);

        match chain.dial(&target).await {
            Ok(cc) => {
                node.reset_dead();

                // The OK response is handed to the wrapper rather than written
                // here: gost buffers it and flushes it with the first payload
                // write (relay.go:252-258). The wrapper also owns the UDP
                // datagram framing, which a raw byte pipe would destroy.
                let sc = RelayConn::server(conn, udp, RELAY_STATUS_OK);

                info!("[relay] {} <-> {}", peer_addr, target);
                transport(sc, cc).await.ok();
                info!("[relay] {} >-< {}", peer_addr, target);
            }
            Err(e) => {
                node.mark_dead();
                send_relay_reply(&mut conn, RELAY_STATUS_SERVICE_UNAVAILABLE).await?;
                return Err(HandlerError::Chain(e));
            }
        }

        Ok(())
    }
}

/// Splits `host:port`, stripping the brackets from an IPv6 literal so the
/// host half parses as an `Ipv6Addr` rather than falling through to the
/// domain-name encoding.
fn split_host_port(addr: &str) -> Option<(&str, &str)> {
    if let Some(rest) = addr.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        return Some((host, rest.strip_prefix(':')?));
    }
    addr.rsplit_once(':')
}

fn parse_relay_addr(data: &[u8]) -> (String, u16) {
    if data.is_empty() {
        return (String::new(), 0);
    }
    let atype = data[0];
    match atype {
        ADDR_IPV4 if data.len() >= 7 => {
            let ip = std::net::Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            (ip.to_string(), port)
        }
        ADDR_IPV6 if data.len() >= 19 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[1..17]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([data[17], data[18]]);
            (ip.to_string(), port)
        }
        ADDR_DOMAIN if data.len() >= 2 => {
            let dlen = data[1] as usize;
            if data.len() >= 2 + dlen + 2 {
                let domain = String::from_utf8_lossy(&data[2..2 + dlen]).to_string();
                let port = u16::from_be_bytes([data[2 + dlen], data[3 + dlen]]);
                (domain, port)
            } else {
                (String::new(), 0)
            }
        }
        _ => (String::new(), 0),
    }
}

async fn send_relay_reply<W: AsyncWrite + Unpin + ?Sized>(
    conn: &mut W,
    status: u8,
) -> Result<(), HandlerError> {
    // version, status, then a 16-bit feature length of zero.
    let reply = [RELAY_VERSION1, status, 0x00, 0x00];
    conn.write_all(&reply).await?;
    Ok(())
}

fn relay_status_text(status: u8) -> &'static str {
    match status {
        RELAY_STATUS_OK => "ok",
        RELAY_STATUS_BAD_REQUEST => "bad request",
        RELAY_STATUS_UNAUTHORIZED => "unauthorized",
        RELAY_STATUS_FORBIDDEN => "forbidden",
        RELAY_STATUS_TIMEOUT => "timeout",
        RELAY_STATUS_SERVICE_UNAVAILABLE => "service unavailable",
        RELAY_STATUS_HOST_UNREACHABLE => "host unreachable",
        RELAY_STATUS_NETWORK_UNREACHABLE => "network unreachable",
        _ => "unknown status",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_relay_handler_connect() {
        // Start a mock target server
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            conn.write_all(b"relay ok").await.unwrap();
        });

        // Start relay handler with target
        let handler = RelayHandler::new(&target_addr.to_string(), HandlerOptions::default());
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(ProxyConn::from_tcp(conn)).await.ok();
        });

        // Use RelayConnector
        let connector = RelayConnector::new(None);
        let stream = TcpStream::connect(proxy_addr).await.unwrap();
        // Connect without specifying address (handler has fixed target)
        let mut conn = connector.connect(stream, "tcp", "").await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"relay ok");
    }

    #[test]
    fn test_parse_relay_addr_ipv4() {
        let data = [ADDR_IPV4, 127, 0, 0, 1, 0, 80];
        let (host, port) = parse_relay_addr(&data);
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_parse_relay_addr_domain() {
        let mut data = vec![ADDR_DOMAIN, 11]; // domain length
        data.extend_from_slice(b"example.com");
        data.extend_from_slice(&443u16.to_be_bytes());
        let (host, port) = parse_relay_addr(&data);
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_relay_addr_ipv6() {
        let mut data = vec![ADDR_IPV6];
        data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // ::1
        data.extend_from_slice(&8080u16.to_be_bytes());
        let (host, port) = parse_relay_addr(&data);
        assert_eq!(host, "::1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_relay_addr_empty() {
        let (host, port) = parse_relay_addr(&[]);
        assert!(host.is_empty());
        assert_eq!(port, 0);
    }

    #[tokio::test]
    async fn test_relay_handler_auth_failure() {
        use std::collections::HashMap;
        use std::sync::Arc;

        let mut kvs = HashMap::new();
        kvs.insert("admin".into(), "secret".into());
        let auth = Arc::new(crate::auth::LocalAuthenticator::new(kvs));

        let handler = RelayHandler::new(
            "",
            HandlerOptions {
                authenticator: Some(auth),
                ..Default::default()
            },
        );

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(ProxyConn::from_tcp(conn)).await.ok();
        });

        // Send relay request with no auth
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        // version, no flags, 16-bit feature length of zero
        let req = [RELAY_VERSION1, 0x00, 0x00, 0x00];
        client.write_all(&req).await.unwrap();

        let mut resp = [0u8; RELAY_HEADER_LEN];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[0], RELAY_VERSION1);
        assert_eq!(resp[1], RELAY_STATUS_UNAUTHORIZED);
    }

    #[test]
    fn test_protocol_constants_match_go_gost_relay() {
        // Guards against silently regressing to the old, incompatible values
        // (3-byte header, FUDP=0x01, IPv6=0x02, ServiceUnavailable=0x04).
        assert_eq!(RELAY_HEADER_LEN, 4);
        assert_eq!(RELAY_FLAG_UDP, 0x80);
        assert_eq!(ADDR_IPV4, 1);
        assert_eq!(ADDR_DOMAIN, 3);
        assert_eq!(ADDR_IPV6, 4);
        assert_eq!(RELAY_STATUS_TIMEOUT, 0x04);
        assert_eq!(RELAY_STATUS_SERVICE_UNAVAILABLE, 0x05);
        assert_eq!(RELAY_STATUS_HOST_UNREACHABLE, 0x06);
        assert_eq!(RELAY_STATUS_NETWORK_UNREACHABLE, 0x07);
    }

    /// Asserts the exact bytes a request puts on the wire, rather than
    /// round-tripping our own encoder against our own decoder.
    #[tokio::test]
    async fn test_request_wire_layout_is_byte_exact() {
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let reader = tokio::spawn(async move {
            let (mut conn, _) = server.accept().await.unwrap();
            let mut head = [0u8; RELAY_HEADER_LEN];
            conn.read_exact(&mut head).await.unwrap();
            let fea_len = u16::from_be_bytes([head[2], head[3]]) as usize;
            let mut features = vec![0u8; fea_len];
            conn.read_exact(&mut features).await.unwrap();
            // Unblock the connector.
            conn.write_all(&[RELAY_VERSION1, RELAY_STATUS_OK, 0x00, 0x00])
                .await
                .unwrap();
            (head, features)
        });

        let connector = RelayConnector::new(None);
        let stream = TcpStream::connect(server_addr).await.unwrap();
        let _ = connector.connect(stream, "udp", "1.2.3.4:80").await.unwrap();

        let (head, features) = reader.await.unwrap();

        assert_eq!(head[0], RELAY_VERSION1);
        assert_eq!(head[1], RELAY_FLAG_UDP, "udp network must set FUDP=0x80");

        // One Addr feature: TYPE(1) LEN(2 BE) then ATYP + 4-byte IPv4 + port.
        let expected_data = [ADDR_IPV4, 1, 2, 3, 4, 0x00, 0x50];
        let mut expected = vec![FEATURE_ADDR];
        expected.extend_from_slice(&(expected_data.len() as u16).to_be_bytes());
        expected.extend_from_slice(&expected_data);

        assert_eq!(features, expected);
        assert_eq!(u16::from_be_bytes([head[2], head[3]]) as usize, expected.len());
    }

    #[tokio::test]
    async fn test_ipv6_address_feature_uses_atyp_4() {
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let reader = tokio::spawn(async move {
            let (mut conn, _) = server.accept().await.unwrap();
            let mut head = [0u8; RELAY_HEADER_LEN];
            conn.read_exact(&mut head).await.unwrap();
            let fea_len = u16::from_be_bytes([head[2], head[3]]) as usize;
            let mut features = vec![0u8; fea_len];
            conn.read_exact(&mut features).await.unwrap();
            conn.write_all(&[RELAY_VERSION1, RELAY_STATUS_OK, 0x00, 0x00])
                .await
                .unwrap();
            features
        });

        let connector = RelayConnector::new(None);
        let stream = TcpStream::connect(server_addr).await.unwrap();
        let _ = connector.connect(stream, "tcp", "[::1]:443").await.unwrap();

        let features = reader.await.unwrap();
        assert_eq!(features[0], FEATURE_ADDR);
        assert_eq!(features[3], ADDR_IPV6, "IPv6 ATYP must be 4, not 2");

        // The decoder must agree with what we just encoded.
        let (host, port) = parse_relay_addr(&features[3..]);
        assert_eq!(host, "::1");
        assert_eq!(port, 443);
    }

    #[tokio::test]
    async fn test_relay_connector_with_auth() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            conn.write_all(b"relay-auth-ok").await.unwrap();
        });

        let handler = RelayHandler::new(&target_addr.to_string(), HandlerOptions::default());
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(ProxyConn::from_tcp(conn)).await.ok();
        });

        let connector = RelayConnector::new(Some(("user".into(), Some("pass".into()))));
        let stream = TcpStream::connect(proxy_addr).await.unwrap();
        let mut conn = connector.connect(stream, "tcp", "").await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"relay-auth-ok");
    }

    // --- UDP datagram framing --------------------------------------------

    /// The bytes a UDP-mode write puts on the wire, checked against a
    /// hardcoded expectation rather than against our own decoder.
    #[tokio::test]
    async fn test_udp_write_is_length_prefixed_on_the_wire() {
        let (conn, mut wire) = tokio::io::duplex(1 << 16);
        // Client side: nothing is buffered ahead of the payload, so the first
        // bytes on the wire are the frame itself.
        let mut client = RelayConn::client(conn, true);

        client.write_all(b"ABC").await.unwrap();
        client.flush().await.unwrap();

        let mut raw = [0u8; 5];
        wire.read_exact(&mut raw).await.unwrap();
        assert_eq!(raw, [0x00, 0x03, b'A', b'B', b'C']);

        // 258 = 0x0102 exercises both halves of the 16-bit length.
        let payload = vec![0x5Au8; 258];
        client.write_all(&payload).await.unwrap();
        client.flush().await.unwrap();

        let mut raw = vec![0u8; RELAY_DGRAM_LEN_SIZE + payload.len()];
        wire.read_exact(&mut raw).await.unwrap();
        assert_eq!(
            &raw[..2],
            &[0x01, 0x02],
            "the datagram length must be 16-bit big-endian"
        );
        assert_eq!(&raw[2..], &payload[..]);
    }

    /// The server holds its response back and lets the first payload write
    /// carry it, exactly as gost does (relay.go:252-258, 329-340).
    #[tokio::test]
    async fn test_server_defers_response_header_until_first_write() {
        let (conn, mut wire) = tokio::io::duplex(1 << 16);
        let mut server = RelayConn::server(conn, true, RELAY_STATUS_OK);

        // Nothing at all until there is payload to send.
        let mut peek = [0u8; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(100), wire.read(&mut peek))
                .await
                .is_err(),
            "the response header must not be written before the first payload"
        );

        server.write_all(b"hi").await.unwrap();
        server.flush().await.unwrap();

        let mut raw = [0u8; 8];
        wire.read_exact(&mut raw).await.unwrap();
        assert_eq!(
            raw,
            [
                RELAY_VERSION1,
                RELAY_STATUS_OK,
                0x00,
                0x00, // response header, no features
                0x00,
                0x02, // datagram length
                b'h',
                b'i',
            ]
        );
    }

    #[tokio::test]
    async fn test_udp_framing_preserves_datagram_boundaries() {
        let (client_raw, server_raw) = tokio::io::duplex(1 << 20);
        let mut server = RelayConn::server(server_raw, true, RELAY_STATUS_OK);
        let mut client = RelayConn::client(client_raw, true);

        let big: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let to_send = big.clone();
        let writer = tokio::spawn(async move {
            server.write_all(b"one").await.unwrap();
            server.write_all(b"two").await.unwrap();
            server.write_all(&to_send).await.unwrap();
            server.write_all(b"tail").await.unwrap();
            server.flush().await.unwrap();
            server
        });

        // A read buffer far larger than the datagram must still come back with
        // exactly one datagram, not with several run together.
        let mut buf = vec![0u8; 4096];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"one", "datagrams must not be coalesced");
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"two", "datagrams must not be coalesced");

        // A datagram larger than the read buffer spans several reads without
        // losing bytes and without spilling into the next datagram.
        let mut got = Vec::new();
        let mut small = [0u8; 1000];
        while got.len() < big.len() {
            let n = client.read(&mut small).await.unwrap();
            assert!(n > 0, "unexpected end of stream mid-datagram");
            assert!(
                got.len() + n <= big.len(),
                "a read crossed a datagram boundary"
            );
            got.extend_from_slice(&small[..n]);
        }
        assert_eq!(got, big);

        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"tail", "the next datagram must be intact");

        let _ = writer.await.unwrap();
    }

    #[tokio::test]
    async fn test_udp_read_reassembles_a_datagram_split_across_polls() {
        let (conn, mut wire) = tokio::io::duplex(1 << 16);
        let mut client = RelayConn::client(conn, true);

        // 600 = 0x0258.
        let payload: Vec<u8> = (0..600u32).map(|i| (i % 253) as u8).collect();
        let expected = payload.clone();

        let writer = tokio::spawn(async move {
            wire.write_all(&[RELAY_VERSION1, RELAY_STATUS_OK, 0x00, 0x00])
                .await
                .unwrap();
            // Split even the length prefix, so poll_fill has to resume.
            for chunk in [&[0x02u8][..], &[0x58u8][..], &expected[..100], &expected[100..]] {
                wire.write_all(chunk).await.unwrap();
                wire.flush().await.unwrap();
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            wire
        });

        let mut got = vec![0u8; 600];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload);
        let _ = writer.await.unwrap();
    }

    #[tokio::test]
    async fn test_datagram_larger_than_u16_is_rejected() {
        let (conn, _wire) = tokio::io::duplex(1 << 20);
        let mut client = RelayConn::client(conn, true);

        let too_big = vec![0u8; RELAY_MAX_DATAGRAM + 1];
        let err = client.write_all(&too_big).await.unwrap_err();
        assert!(
            err.to_string().contains("65535"),
            "expected a maximum-size error, got: {}",
            err
        );

        // The boundary case is still legal.
        let at_limit = vec![7u8; RELAY_MAX_DATAGRAM];
        client.write_all(&at_limit).await.unwrap();
        client.flush().await.unwrap();
    }

    // --- TCP mode ---------------------------------------------------------

    #[tokio::test]
    async fn test_tcp_mode_is_byte_transparent() {
        let (conn, mut wire) = tokio::io::duplex(1 << 16);
        let mut client = RelayConn::client(conn, false);

        client.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        client.write_all(b"Host: x\r\n\r\n").await.unwrap();
        client.flush().await.unwrap();

        let mut raw = vec![0u8; 27];
        wire.read_exact(&mut raw).await.unwrap();
        assert_eq!(
            &raw[..],
            b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
            "TCP mode must not add length prefixes"
        );

        // And the read direction: the response header, then raw bytes.
        wire.write_all(&[RELAY_VERSION1, RELAY_STATUS_OK, 0x00, 0x00])
            .await
            .unwrap();
        wire.write_all(b"HTTP/1.1 200 OK").await.unwrap();

        let mut got = vec![0u8; 15];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got[..], b"HTTP/1.1 200 OK");
    }

    // --- Lazy handshake ---------------------------------------------------

    /// gost withholds its response until it has data to send, so a connector
    /// that blocks on the response before writing any payload never returns.
    #[tokio::test]
    async fn test_connector_does_not_deadlock_against_a_lazy_server() {
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let lazy = tokio::spawn(async move {
            let (mut conn, _) = server.accept().await.unwrap();

            let mut head = [0u8; RELAY_HEADER_LEN];
            conn.read_exact(&mut head).await.unwrap();
            let fea_len = u16::from_be_bytes([head[2], head[3]]) as usize;
            let mut features = vec![0u8; fea_len];
            conn.read_exact(&mut features).await.unwrap();

            // Deliberately no response yet: wait for payload first.
            let mut payload = [0u8; 5];
            conn.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ping!");

            let mut out = vec![RELAY_VERSION1, RELAY_STATUS_OK, 0x00, 0x00];
            out.extend_from_slice(b"pong!");
            conn.write_all(&out).await.unwrap();
            conn
        });

        let connector = RelayConnector::new(None);
        let stream = TcpStream::connect(server_addr).await.unwrap();

        let exchange = async move {
            let mut conn = connector
                .connect(stream, "tcp", "example.com:80")
                .await
                .unwrap();
            conn.write_all(b"ping!").await.unwrap();
            let mut buf = [0u8; 5];
            conn.read_exact(&mut buf).await.unwrap();
            buf
        };

        let buf = tokio::time::timeout(Duration::from_secs(5), exchange)
            .await
            .expect("the connector deadlocked waiting for a lazy server's response");
        assert_eq!(&buf, b"pong!");
        let _ = lazy.await.unwrap();
    }

    #[tokio::test]
    async fn test_client_surfaces_non_ok_status_on_first_read() {
        let (conn, mut wire) = tokio::io::duplex(1 << 16);
        let mut client = RelayConn::client(conn, false);

        wire.write_all(&[RELAY_VERSION1, RELAY_STATUS_FORBIDDEN, 0x00, 0x00])
            .await
            .unwrap();

        let mut buf = [0u8; 8];
        let err = client.read(&mut buf).await.unwrap_err();
        assert!(
            err.to_string().contains("forbidden"),
            "expected the status text, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_client_drains_response_features_before_payload() {
        let (conn, mut wire) = tokio::io::duplex(1 << 16);
        let mut client = RelayConn::client(conn, false);

        // One Addr feature: TYPE(1) | LEN(2) | ATYP + IPv4 + port.
        let feature = [FEATURE_ADDR, 0x00, 0x07, ADDR_IPV4, 10, 0, 0, 1, 0x1F, 0x90];
        let mut out = vec![RELAY_VERSION1, RELAY_STATUS_OK];
        out.extend_from_slice(&(feature.len() as u16).to_be_bytes());
        out.extend_from_slice(&feature);
        out.extend_from_slice(b"payload");
        wire.write_all(&out).await.unwrap();

        let mut got = vec![0u8; 7];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(
            &got[..],
            b"payload",
            "the reply's features must be drained, not returned as payload"
        );
    }

    /// End-to-end through the real handler with FUDP set. Driven with a raw
    /// socket so the bytes on the wire are asserted directly: the handler has
    /// to put the framing wrapper on the data path, not a raw byte pipe.
    #[tokio::test]
    async fn test_handler_frames_udp_datagrams_end_to_end() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        let echo = tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            // The target sees the payload unframed; the relay strips the
            // length prefix on the way in and re-adds it on the way out.
            let mut buf = [0u8; 3];
            conn.read_exact(&mut buf).await.unwrap();
            conn.write_all(b"pong").await.unwrap();
            conn.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await;
            buf
        });

        let handler = RelayHandler::new(&target_addr.to_string(), HandlerOptions::default());
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(ProxyConn::from_tcp(conn)).await.ok();
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(&[RELAY_VERSION1, RELAY_FLAG_UDP, 0x00, 0x00])
            .await
            .unwrap();
        client
            .write_all(&[0x00, 0x03, b'r', b'e', b'q'])
            .await
            .unwrap();

        let mut resp = [0u8; RELAY_HEADER_LEN + RELAY_DGRAM_LEN_SIZE + 4];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(
            resp,
            [
                RELAY_VERSION1,
                RELAY_STATUS_OK,
                0x00,
                0x00, // deferred response header
                0x00,
                0x04, // datagram length
                b'p',
                b'o',
                b'n',
                b'g',
            ]
        );

        assert_eq!(&echo.await.unwrap(), b"req");
    }
}
