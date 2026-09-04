//! DNS server, ported from gost's `dns.go`.
//!
//! gost splits this into a `dnsListener` (which speaks udp / tcp / tcp-tls /
//! DoH and turns every message into a fake `net.Conn`) and a `dnsHandler`
//! (which unpacks the message and calls `Resolver.Exchange`). This crate's
//! `Handler` trait serves a single stream connection, so the split here is:
//!
//! * [`DnsHandler`] -- the `Handler` for stream transports (`mode=tcp`, and
//!   `mode=tls` once the stream has been wrapped). Length prefixed framing
//!   per RFC 1035 4.2.2. `serve_stream` stays generic over the stream type so
//!   the DoT path can reuse it on a `TlsStream`.
//! * [`DnsServer`] -- owns the listener for all four `?mode=` values and calls
//!   [`Resolver::exchange`] directly, which is what gost's handler does.
//! * [`DnsUdpProxy`] -- the standalone UDP server (kept for API compatibility).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use native_tls::Identity;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_native_tls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::conn::ProxyConn;
use crate::handler::{Handler, HandlerError, HandlerOptions};
use crate::resolver::{Message, Resolver, DEFAULT_UDP_SIZE};

/// gost's default name server for the DNS handler (dns.go:25-31).
/// NOT 8.8.8.8: forwarding to a public resolver by default would silently
/// exfiltrate every query of a user who forgot to configure `?dns=`.
pub const DEFAULT_DNS_UPSTREAM: &str = "127.0.0.1:53";

/// gost's `dnsListener` read buffer is the miekg default (512) unless
/// `DNSOptions.UDPSize` raises it. We start from the EDNS0 safe size and let
/// the client's own OPT record raise it further, which is what
/// "honour the EDNS0 UDP size" means in practice.
pub const MIN_UDP_SIZE: usize = 512;
pub const MAX_UDP_SIZE: usize = 65535;

/// Builds the resolver a DNS listener should forward through.
///
/// `spec` is gost's `-L dns://...` remote address: it accepts the same inline
/// comma separated name server list `?dns=` does. An empty spec falls back to
/// [`DEFAULT_DNS_UPSTREAM`].
pub fn resolver_from_spec(spec: &str) -> Resolver {
    let spec = spec.trim();
    if spec.is_empty() {
        return Resolver::from_inline(DEFAULT_DNS_UPSTREAM);
    }
    let r = Resolver::from_inline(spec);
    if r.is_empty() {
        return Resolver::from_inline(DEFAULT_DNS_UPSTREAM);
    }
    r
}

/// The `?mode=` values gost's DNS listener supports (dns.go:153-192).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum DnsMode {
    #[default]
    Udp,
    Tcp,
    Tls,
    Https,
}

impl DnsMode {
    /// gost: `strings.ToLower(options.Mode)` with `default:` = udp.
    pub fn parse(s: &str) -> DnsMode {
        match s.to_ascii_lowercase().as_str() {
            "tcp" => DnsMode::Tcp,
            "tls" | "dot" => DnsMode::Tls,
            "https" | "doh" => DnsMode::Https,
            _ => DnsMode::Udp,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            DnsMode::Udp => "udp",
            DnsMode::Tcp => "tcp",
            DnsMode::Tls => "tls",
            DnsMode::Https => "https",
        }
    }
}

/// DNS proxy handler: forwards a DNS query to the configured [`Resolver`],
/// which does its own multi-upstream failover and caching.
/// gost: `dnsHandler.Handle` (dns.go:58-107).
pub struct DnsHandler {
    resolver: Resolver,
    options: HandlerOptions,
}

impl DnsHandler {
    /// Backwards compatible constructor. `upstream` is the listener's remote
    /// address; it accepts a single `host[:port]` or gost's inline
    /// comma separated name server list.
    pub fn new(upstream: &str, options: HandlerOptions) -> Self {
        Self {
            resolver: resolver_from_spec(upstream),
            options,
        }
    }

    /// Preferred constructor: forward through an already configured resolver
    /// (multiple upstreams, cache, `?prefer=`, `?ip=`, live reload).
    pub fn with_resolver(resolver: Resolver, options: HandlerOptions) -> Self {
        Self { resolver, options }
    }

    pub fn resolver(&self) -> &Resolver {
        &self.resolver
    }

    pub fn options(&self) -> &HandlerOptions {
        &self.options
    }

    /// Serves one length prefixed DNS message on an arbitrary stream. Shared by
    /// the plain TCP path and the DoT path.
    async fn serve_stream<S>(&self, conn: &mut S, peer: &str) -> Result<(), HandlerError>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        let mut len_buf = [0u8; 2];
        conn.read_exact(&mut len_buf).await?;
        let msg_len = u16::from_be_bytes(len_buf) as usize;

        let mut query = vec![0u8; msg_len];
        conn.read_exact(&mut query).await?;

        let reply = exchange_logged(&self.resolver, &query, peer).await?;
        if reply.len() > u16::MAX as usize {
            return Err(HandlerError::Proxy("DNS reply too long for TCP".into()));
        }

        conn.write_all(&(reply.len() as u16).to_be_bytes()).await?;
        conn.write_all(&reply).await?;
        conn.flush().await?;
        Ok(())
    }
}

#[async_trait]
impl Handler for DnsHandler {
    async fn handle(&self, mut conn: ProxyConn) -> Result<(), HandlerError> {
        let peer_addr = conn.peer_addr_str();
        self.serve_stream(&mut conn, &peer_addr).await
    }
}

/// Runs one exchange and logs it the way gost's handler does.
async fn exchange_logged(
    resolver: &Resolver,
    query: &[u8],
    peer: &str,
) -> Result<Vec<u8>, HandlerError> {
    let mq = Message::decode(query)
        .map_err(|e| HandlerError::Proxy(format!("request unpack: {}", e)))?;
    debug!(
        "[dns] {} -> : id {} QUERY: {}",
        peer,
        mq.id,
        mq.questions.len()
    );

    let start = std::time::Instant::now();
    let reply = resolver
        .exchange(query)
        .await
        .map_err(|e| HandlerError::Proxy(format!("exchange: {}", e)))?;

    match Message::decode(&reply) {
        Ok(mr) => debug!(
            "[dns] {} <- : id {} ANSWER: {} [{:?}]",
            peer,
            mr.id,
            mr.answers.len(),
            start.elapsed()
        ),
        Err(e) => {
            return Err(HandlerError::Proxy(format!("reply unpack: {}", e)));
        }
    }
    Ok(reply)
}

/// The UDP read buffer to use for a listener, honouring the client's EDNS0
/// advertised payload size instead of a fixed 4096 bytes.
fn udp_buffer_size(configured: usize) -> usize {
    configured.clamp(MIN_UDP_SIZE, MAX_UDP_SIZE)
}

// ---------------------------------------------------------------------------
// DoH request handling
// ---------------------------------------------------------------------------

/// What a DoH request maps to. gost: `dnsListener.ServeHTTP`
/// (dns.go:253-293).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DohRequest {
    /// A wire-format query to forward.
    Query(Vec<u8>),
    /// An HTTP status code to return instead.
    Status(u16),
}

/// Parses a DoH request into either a query or an HTTP error status.
///
/// * `GET` requires `?dns=<base64url>` (RawURLEncoding, i.e. unpadded) --
///   empty or undecodable means 400.
/// * `POST` requires `Content-Type: application/dns-message` -- otherwise 415.
/// * Any other method is 405.
/// * A body that is not a decodable DNS message is 400.
pub fn parse_doh_request(
    method: &str,
    target: &str,
    content_type: Option<&str>,
    body: &[u8],
) -> DohRequest {
    let buf: Vec<u8> = match method {
        "GET" => {
            let dns_param = query_param(target, "dns").unwrap_or_default();
            if dns_param.is_empty() {
                return DohRequest::Status(400);
            }
            match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(dns_param.as_bytes()) {
                Ok(b) if !b.is_empty() => b,
                _ => return DohRequest::Status(400),
            }
        }
        "POST" => {
            // gost compares the header verbatim (dns.go:264).
            let ct = content_type.unwrap_or("");
            if !ct
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("application/dns-message")
            {
                return DohRequest::Status(415);
            }
            body.to_vec()
        }
        _ => return DohRequest::Status(405),
    };

    // gost unpacks before forwarding and answers 400 on a malformed message.
    if Message::decode(&buf).is_err() {
        return DohRequest::Status(400);
    }
    DohRequest::Query(buf)
}

/// Extracts a percent-decoded query parameter from a request target.
fn query_param(target: &str, key: &str) -> Option<String> {
    let query = target.split_once('?')?.1;
    for pair in query.split('&') {
        let (k, v) = match pair.split_once('=') {
            Some(kv) => kv,
            None => (pair, ""),
        };
        if k == key {
            return Some(percent_decode(v));
        }
    }
    None
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn http_status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        400 => "Bad Request",
        405 => "Method Not Allowed",
        415 => "Unsupported Media Type",
        500 => "Internal Server Error",
        _ => "Error",
    }
}

fn http_error_response(code: u16) -> Vec<u8> {
    let text = http_status_text(code);
    format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{}\n",
        code,
        text,
        text.len() + 1,
        text
    )
    .into_bytes()
}

fn http_dns_response(body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 200 OK\r\nServer: SDNS\r\nContent-Type: application/dns-message\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

/// Reads one HTTP/1.1 request and answers it as a DoH endpoint.
async fn serve_doh_conn<S>(resolver: &Resolver, conn: &mut S, peer: &str) -> std::io::Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    let mut header_end = None;

    while header_end.is_none() {
        let n = conn.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        header_end = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4);
        if buf.len() > 64 * 1024 {
            let _ = conn.write_all(&http_error_response(400)).await;
            return Ok(());
        }
    }
    let header_end = header_end.unwrap();

    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);
    if req.parse(&buf[..header_end]).is_err() {
        let _ = conn.write_all(&http_error_response(400)).await;
        return Ok(());
    }
    let method = req.method.unwrap_or("").to_string();
    let target = req.path.unwrap_or("/").to_string();
    let content_type = req
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-type"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .map(|s| s.to_string());
    let content_length = req
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-length"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);

    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        let n = conn.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length.min(body.len()));

    let response = match parse_doh_request(&method, &target, content_type.as_deref(), &body) {
        DohRequest::Status(code) => http_error_response(code),
        DohRequest::Query(query) => match resolver.exchange(&query).await {
            Ok(reply) => http_dns_response(&reply),
            Err(e) => {
                warn!("[dns] {} doh exchange: {}", peer, e);
                http_error_response(500)
            }
        },
    };
    conn.write_all(&response).await?;
    conn.flush().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// The DNS server
// ---------------------------------------------------------------------------

/// A DNS server covering gost's four `?mode=` values.
pub struct DnsServer {
    addr: String,
    mode: DnsMode,
    resolver: Resolver,
    udp_size: usize,
    identity: Option<Identity>,
    read_timeout: Duration,
}

impl DnsServer {
    pub fn new(addr: &str, resolver: Resolver) -> Self {
        Self {
            addr: addr.to_string(),
            mode: DnsMode::Udp,
            resolver,
            udp_size: DEFAULT_UDP_SIZE as usize,
            identity: None,
            read_timeout: Duration::ZERO,
        }
    }

    pub fn with_mode(mut self, mode: DnsMode) -> Self {
        self.mode = mode;
        self
    }

    /// gost: `DNSOptions.UDPSize`.
    pub fn with_udp_size(mut self, size: usize) -> Self {
        if size > 0 {
            self.udp_size = size;
        }
        self
    }

    /// Certificate for `mode=tls` (DoT) and `mode=https` (DoH).
    /// gost: `DNSOptions.TLSConfig`.
    pub fn with_identity(mut self, identity: Identity) -> Self {
        self.identity = Some(identity);
        self
    }

    pub fn with_read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout;
        self
    }

    pub fn mode(&self) -> DnsMode {
        self.mode
    }

    pub fn resolver(&self) -> &Resolver {
        &self.resolver
    }

    /// Runs the server until it fails.
    pub async fn serve(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match self.mode {
            DnsMode::Udp => {
                let socket = UdpSocket::bind(&self.addr).await?;
                info!("[dns] udp listening on {}", socket.local_addr()?);
                serve_udp(socket, self.resolver, self.udp_size).await
            }
            DnsMode::Tcp => {
                let ln = TcpListener::bind(&self.addr).await?;
                info!("[dns] tcp listening on {}", ln.local_addr()?);
                serve_tcp(ln, self.resolver, self.read_timeout).await
            }
            DnsMode::Tls => {
                let identity = self
                    .identity
                    .ok_or("dns mode=tls requires a TLS certificate")?;
                let acceptor = TlsAcceptor::from(native_tls::TlsAcceptor::new(identity)?);
                let ln = TcpListener::bind(&self.addr).await?;
                info!("[dns] tls listening on {}", ln.local_addr()?);
                serve_dot(ln, acceptor, self.resolver, self.read_timeout).await
            }
            DnsMode::Https => {
                let ln = TcpListener::bind(&self.addr).await?;
                info!("[dns] https listening on {}", ln.local_addr()?);
                let acceptor = match self.identity {
                    Some(id) => Some(TlsAcceptor::from(native_tls::TlsAcceptor::new(id)?)),
                    None => {
                        // gost always wraps DoH in TLS. Allowing plaintext is a
                        // deliberate extension for running behind a terminator
                        // (and for the tests), but it must be visible.
                        warn!("[dns] mode=https without a certificate: serving PLAINTEXT HTTP");
                        None
                    }
                };
                serve_doh(ln, acceptor, self.resolver, self.read_timeout).await
            }
        }
    }
}

/// UDP DNS server loop.
///
/// The historical bug this replaces: the reply was received from the upstream
/// and only logged, never `send_to`'d back, so every UDP client timed out.
pub async fn serve_udp(
    socket: UdpSocket,
    resolver: Resolver,
    udp_size: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let socket = Arc::new(socket);
    let mut buf = vec![0u8; udp_buffer_size(udp_size)];

    loop {
        let (n, peer) = socket.recv_from(&mut buf).await?;
        let query = buf[..n].to_vec();
        let resolver = resolver.clone();
        let sock = socket.clone();

        tokio::spawn(async move {
            let peer_str = peer.to_string();
            match exchange_logged(&resolver, &query, &peer_str).await {
                Ok(mut reply) => {
                    // Respect the client's advertised EDNS0 buffer: if the
                    // answer does not fit, set TC so the client retries on TCP.
                    let limit = Message::decode(&query)
                        .ok()
                        .and_then(|m| m.edns0_udp_size())
                        .map(|s| udp_buffer_size(s as usize))
                        .unwrap_or(MIN_UDP_SIZE);
                    if reply.len() > limit {
                        reply = truncated_response(&query).unwrap_or(reply);
                    }
                    if let Err(e) = sock.send_to(&reply, peer).await {
                        debug!("[dns] {} : reply write: {}", peer_str, e);
                    }
                }
                Err(e) => debug!("[dns] {} : {}", peer_str, e),
            }
        });
    }
}

/// Builds an empty answer with the TC (truncated) bit set, so an oversized
/// reply makes the client retry over TCP instead of being silently dropped.
fn truncated_response(query: &[u8]) -> Option<Vec<u8>> {
    let mq = Message::decode(query).ok()?;
    let mut mr = Message {
        id: mq.id,
        // QR | TC, keeping the request's RD bit.
        flags: 0x8000 | 0x0200 | (mq.flags & 0x0100),
        questions: mq.questions,
        ..Default::default()
    };
    mr.additionals.clear();
    mr.encode().ok()
}

/// TCP DNS server loop (RFC 1035 length prefixed framing).
pub async fn serve_tcp(
    listener: TcpListener,
    resolver: Resolver,
    read_timeout: Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let resolver = resolver.clone();
        tokio::spawn(async move {
            let handler = DnsHandler::with_resolver(resolver, HandlerOptions::default());
            let fut = handler.handle(ProxyConn::from_tcp(stream));
            let res = if read_timeout > Duration::ZERO {
                match tokio::time::timeout(read_timeout, fut).await {
                    Ok(r) => r,
                    Err(_) => Err(HandlerError::Proxy("dns read timeout".into())),
                }
            } else {
                fut.await
            };
            if let Err(e) = res {
                debug!("[dns] {} : {}", peer, e);
            }
        });
    }
}

/// DNS-over-TLS server loop (gost: `Net: "tcp-tls"`, dns.go:162-170).
pub async fn serve_dot(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    resolver: Resolver,
    read_timeout: Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let resolver = resolver.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let mut tls = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    debug!("[dns] {} tls handshake: {}", peer, e);
                    return;
                }
            };
            let handler = DnsHandler::with_resolver(resolver, HandlerOptions::default());
            let peer_str = peer.to_string();
            let fut = handler.serve_stream(&mut tls, &peer_str);
            let res = if read_timeout > Duration::ZERO {
                match tokio::time::timeout(read_timeout, fut).await {
                    Ok(r) => r,
                    Err(_) => Err(HandlerError::Proxy("dns read timeout".into())),
                }
            } else {
                fut.await
            };
            if let Err(e) = res {
                debug!("[dns] {} : {}", peer_str, e);
            }
        });
    }
}

/// DNS-over-HTTPS server loop (gost: `dohServer`, dns.go:316-333).
pub async fn serve_doh(
    listener: TcpListener,
    acceptor: Option<TlsAcceptor>,
    resolver: Resolver,
    read_timeout: Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let resolver = resolver.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let peer_str = peer.to_string();
            let run = async {
                match acceptor {
                    Some(a) => {
                        let mut tls = match a.accept(stream).await {
                            Ok(s) => s,
                            Err(e) => {
                                debug!("[dns] {} tls handshake: {}", peer_str, e);
                                return Ok(());
                            }
                        };
                        serve_doh_conn(&resolver, &mut tls, &peer_str).await
                    }
                    None => {
                        let mut s = stream;
                        serve_doh_conn(&resolver, &mut s, &peer_str).await
                    }
                }
            };
            let res = if read_timeout > Duration::ZERO {
                tokio::time::timeout(read_timeout, run)
                    .await
                    .unwrap_or_else(|_| {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "doh read timeout",
                        ))
                    })
            } else {
                run.await
            };
            if let Err(e) = res {
                debug!("[dns] {} doh: {}", peer, e);
            }
        });
    }
}

/// Standalone UDP DNS proxy. Kept for API compatibility with the previous
/// version; new code should prefer [`DnsServer`].
pub struct DnsUdpProxy {
    bind_addr: String,
    resolver: Resolver,
    udp_size: usize,
}

impl DnsUdpProxy {
    /// `upstream` accepts a single `host[:port]` or gost's inline comma
    /// separated name server list. Empty means [`DEFAULT_DNS_UPSTREAM`].
    pub fn new(bind_addr: &str, upstream: &str) -> Self {
        Self {
            bind_addr: bind_addr.to_string(),
            resolver: resolver_from_spec(upstream),
            udp_size: DEFAULT_UDP_SIZE as usize,
        }
    }

    pub fn with_resolver(bind_addr: &str, resolver: Resolver) -> Self {
        Self {
            bind_addr: bind_addr.to_string(),
            resolver,
            udp_size: DEFAULT_UDP_SIZE as usize,
        }
    }

    pub fn with_udp_size(mut self, size: usize) -> Self {
        if size > 0 {
            self.udp_size = size;
        }
        self
    }

    pub fn resolver(&self) -> &Resolver {
        &self.resolver
    }

    /// Run the UDP DNS proxy.
    pub async fn serve(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let socket = UdpSocket::bind(&self.bind_addr).await?;
        info!("[dns] UDP listening on {}", socket.local_addr()?);
        serve_udp(socket, self.resolver.clone(), self.udp_size).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolver::{Rr, CLASS_IN, FLAG_QR, FLAG_RD, TYPE_A};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A fake upstream name server on 127.0.0.1:0 that answers every A query
    /// with the given address.
    async fn spawn_upstream(ip: Ipv4Addr, ttl: u32) -> (SocketAddr, Arc<AtomicUsize>) {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
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
                let mut mr = Message {
                    id: mq.id,
                    flags: FLAG_QR | FLAG_RD,
                    questions: mq.questions.clone(),
                    ..Default::default()
                };
                if mq.questions[0].qtype == TYPE_A {
                    mr.answers.push(Rr {
                        name: mq.questions[0].name.clone(),
                        rtype: TYPE_A,
                        rclass: CLASS_IN,
                        ttl,
                        rdata: ip.octets().to_vec(),
                    });
                }
                let _ = sock.send_to(&mr.encode().unwrap(), peer).await;
            }
        });
        (addr, count)
    }

    #[test]
    fn test_default_upstream_is_localhost_not_google() {
        // gost's default is 127.0.0.1:53 (dns.go:25-31).
        let r = resolver_from_spec("");
        assert_eq!(r.servers().len(), 1);
        assert_eq!(r.servers()[0].addr, "127.0.0.1:53");

        let p = DnsUdpProxy::new("127.0.0.1:0", "");
        assert_eq!(p.resolver().servers()[0].addr, "127.0.0.1:53");

        let h = DnsHandler::new("", HandlerOptions::default());
        assert_eq!(h.resolver().servers()[0].addr, "127.0.0.1:53");
    }

    #[test]
    fn test_resolver_from_spec_multi_upstream() {
        let r = resolver_from_spec("1.1.1.1,8.8.8.8/tcp,1.0.0.1/tls");
        let ns = r.servers();
        assert_eq!(ns.len(), 3);
        assert_eq!(ns[0].dial_addr(), "1.1.1.1:53");
        assert_eq!(ns[1].protocol, "tcp");
        assert_eq!(ns[2].protocol, "tls");
    }

    #[test]
    fn test_mode_parse() {
        assert_eq!(DnsMode::parse(""), DnsMode::Udp);
        assert_eq!(DnsMode::parse("udp"), DnsMode::Udp);
        assert_eq!(DnsMode::parse("TCP"), DnsMode::Tcp);
        assert_eq!(DnsMode::parse("tls"), DnsMode::Tls);
        assert_eq!(DnsMode::parse("https"), DnsMode::Https);
        assert_eq!(DnsMode::parse("bogus"), DnsMode::Udp);
        assert_eq!(DnsMode::Tls.as_str(), "tls");
    }

    #[test]
    fn test_udp_buffer_size_clamps() {
        assert_eq!(udp_buffer_size(0), MIN_UDP_SIZE);
        assert_eq!(udp_buffer_size(128), MIN_UDP_SIZE);
        assert_eq!(udp_buffer_size(4096), 4096);
        assert_eq!(udp_buffer_size(1 << 20), MAX_UDP_SIZE);
    }

    // -- the UDP reply bug -----------------------------------------------

    #[tokio::test]
    async fn test_udp_server_actually_replies() {
        let (upstream, count) = spawn_upstream(Ipv4Addr::new(10, 1, 2, 3), 300).await;

        let resolver = Resolver::from_inline(&upstream.to_string());
        let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = serve_udp(server_sock, resolver, DEFAULT_UDP_SIZE as usize).await;
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(server_addr).await.unwrap();
        let query = Message::query(0x4242, "udp.test", TYPE_A).encode().unwrap();
        client.send(&query).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buf))
            .await
            .expect("UDP server must send a reply back to the client")
            .unwrap();

        let mr = Message::decode(&buf[..n]).unwrap();
        assert_eq!(mr.id, 0x4242);
        assert_eq!(
            mr.answer_ips(),
            vec!["10.1.2.3".parse::<std::net::IpAddr>().unwrap()]
        );
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_udp_server_uses_resolver_cache_and_failover() {
        let (upstream, count) = spawn_upstream(Ipv4Addr::new(10, 4, 5, 6), 600).await;
        // First upstream is a dead TCP port -> must fail over to the good one.
        let dead = {
            let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            s.local_addr().unwrap()
        };
        let resolver = Resolver::default();
        resolver
            .reload(
                format!(
                    "timeout 300ms\nttl 60s\nnameserver {} tcp\nnameserver {}\n",
                    dead, upstream
                )
                .as_bytes(),
            )
            .unwrap();

        let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = serve_udp(server_sock, resolver, DEFAULT_UDP_SIZE as usize).await;
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(server_addr).await.unwrap();
        let mut buf = vec![0u8; 4096];

        for id in [1u16, 2u16] {
            let q = Message::query(id, "cache.test", TYPE_A).encode().unwrap();
            client.send(&q).await.unwrap();
            let n = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buf))
                .await
                .unwrap()
                .unwrap();
            let mr = Message::decode(&buf[..n]).unwrap();
            assert_eq!(mr.id, id);
            assert_eq!(
                mr.answer_ips(),
                vec!["10.4.5.6".parse::<std::net::IpAddr>().unwrap()]
            );
        }
        // Second request served from cache.
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_tcp_handler_roundtrip() {
        let (upstream, _) = spawn_upstream(Ipv4Addr::new(10, 7, 8, 9), 300).await;
        let resolver = Resolver::from_inline(&upstream.to_string());

        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = serve_tcp(ln, resolver, Duration::ZERO).await;
        });

        let mut s = TcpStream::connect(addr).await.unwrap();
        let query = Message::query(0x0101, "tcp.test", TYPE_A).encode().unwrap();
        s.write_all(&(query.len() as u16).to_be_bytes())
            .await
            .unwrap();
        s.write_all(&query).await.unwrap();

        let mut len = [0u8; 2];
        s.read_exact(&mut len).await.unwrap();
        let mut reply = vec![0u8; u16::from_be_bytes(len) as usize];
        s.read_exact(&mut reply).await.unwrap();

        let mr = Message::decode(&reply).unwrap();
        assert_eq!(mr.id, 0x0101);
        assert_eq!(
            mr.answer_ips(),
            vec!["10.7.8.9".parse::<std::net::IpAddr>().unwrap()]
        );
    }

    // -- DoH request handling --------------------------------------------

    #[test]
    fn test_doh_get_requires_dns_param() {
        assert_eq!(
            parse_doh_request("GET", "/dns-query", None, b""),
            DohRequest::Status(400)
        );
        assert_eq!(
            parse_doh_request("GET", "/dns-query?dns=", None, b""),
            DohRequest::Status(400)
        );
        assert_eq!(
            parse_doh_request("GET", "/dns-query?dns=!!!not-base64!!!", None, b""),
            DohRequest::Status(400)
        );
    }

    #[test]
    fn test_doh_get_accepts_base64url_no_pad() {
        let query = Message::query(9, "doh.test", TYPE_A).encode().unwrap();
        let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&query);
        // The unpadded form is what RFC 8484 and gost's RawURLEncoding require.
        assert!(!enc.contains('='));
        let target = format!("/dns-query?dns={}", enc);
        assert_eq!(
            parse_doh_request("GET", &target, None, b""),
            DohRequest::Query(query.clone())
        );
        // Extra parameters must not confuse the lookup.
        let target2 = format!("/dns-query?ct=application/dns-message&dns={}", enc);
        assert_eq!(
            parse_doh_request("GET", &target2, None, b""),
            DohRequest::Query(query)
        );
    }

    #[test]
    fn test_doh_post_requires_content_type() {
        let query = Message::query(9, "doh.test", TYPE_A).encode().unwrap();
        assert_eq!(
            parse_doh_request("POST", "/dns-query", None, &query),
            DohRequest::Status(415)
        );
        assert_eq!(
            parse_doh_request("POST", "/dns-query", Some("application/json"), &query),
            DohRequest::Status(415)
        );
        assert_eq!(
            parse_doh_request(
                "POST",
                "/dns-query",
                Some("application/dns-message"),
                &query
            ),
            DohRequest::Query(query.clone())
        );
        // Charset parameters are tolerated.
        assert_eq!(
            parse_doh_request(
                "POST",
                "/dns-query",
                Some("application/dns-message; charset=utf-8"),
                &query
            ),
            DohRequest::Query(query)
        );
    }

    #[test]
    fn test_doh_method_not_allowed_and_bad_message() {
        let query = Message::query(9, "doh.test", TYPE_A).encode().unwrap();
        assert_eq!(
            parse_doh_request("PUT", "/dns-query", None, &query),
            DohRequest::Status(405)
        );
        assert_eq!(
            parse_doh_request("DELETE", "/dns-query", None, &query),
            DohRequest::Status(405)
        );
        // Well-formed HTTP, malformed DNS -> 400.
        assert_eq!(
            parse_doh_request(
                "POST",
                "/dns-query",
                Some("application/dns-message"),
                b"\x00\x01"
            ),
            DohRequest::Status(400)
        );
    }

    #[tokio::test]
    async fn test_doh_server_end_to_end_post_and_get() {
        let (upstream, _) = spawn_upstream(Ipv4Addr::new(10, 9, 9, 9), 300).await;
        let resolver = Resolver::from_inline(&upstream.to_string());

        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = serve_doh(ln, None, resolver, Duration::ZERO).await;
        });

        // POST
        let query = Message::query(0x7777, "doh.test", TYPE_A).encode().unwrap();
        let mut s = TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "POST /dns-query HTTP/1.1\r\nHost: x\r\nContent-Type: application/dns-message\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            query.len()
        );
        s.write_all(req.as_bytes()).await.unwrap();
        s.write_all(&query).await.unwrap();
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).await.unwrap();
        let head_end = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let head = String::from_utf8_lossy(&resp[..head_end]).to_string();
        assert!(head.starts_with("HTTP/1.1 200 OK"), "{}", head);
        assert!(head.contains("application/dns-message"));
        let mr = Message::decode(&resp[head_end..]).unwrap();
        assert_eq!(mr.id, 0x7777);
        assert_eq!(
            mr.answer_ips(),
            vec!["10.9.9.9".parse::<std::net::IpAddr>().unwrap()]
        );

        // GET
        let query = Message::query(0x8888, "doh2.test", TYPE_A)
            .encode()
            .unwrap();
        let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&query);
        let mut s = TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "GET /dns-query?dns={} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            enc
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).await.unwrap();
        let head_end = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert!(String::from_utf8_lossy(&resp[..head_end]).starts_with("HTTP/1.1 200 OK"));
        let mr = Message::decode(&resp[head_end..]).unwrap();
        assert_eq!(mr.id, 0x8888);
    }

    #[tokio::test]
    async fn test_doh_server_returns_405_and_415() {
        let resolver = Resolver::from_inline("127.0.0.1:1");
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = serve_doh(ln, None, resolver, Duration::ZERO).await;
        });

        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"PUT /dns-query HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).await.unwrap();
        assert!(String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 405"));

        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(
            b"POST /dns-query HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\
              Content-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).await.unwrap();
        assert!(String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 415"));
    }

    /// Exercises the DoH *client* exchanger in `resolver.rs` against this
    /// module's DoH server. TLS is skipped by using the `http://` scheme, so
    /// the test needs no certificate and no network; everything except the
    /// TLS wrap is covered (request construction, response parsing,
    /// Content-Length handling, wire-format body).
    #[tokio::test]
    async fn test_doh_client_exchanger_against_doh_server() {
        use crate::resolver::NameServer;

        let (upstream, _) = spawn_upstream(Ipv4Addr::new(10, 11, 12, 13), 300).await;
        let server_resolver = Resolver::from_inline(&upstream.to_string());

        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = serve_doh(ln, None, server_resolver, Duration::ZERO).await;
        });

        let client =
            Resolver::with_servers(vec![
                NameServer::new(&format!("http://{}/dns-query", addr)).with_protocol("https")
            ]);

        let ips = client.resolve("doh-client.test").await.unwrap();
        assert_eq!(
            ips,
            vec!["10.11.12.13".parse::<std::net::IpAddr>().unwrap()]
        );
    }

    #[test]
    fn test_truncated_response_sets_tc() {
        let q = Message::query(0x1234, "big.test", TYPE_A).encode().unwrap();
        let tc = truncated_response(&q).unwrap();
        let m = Message::decode(&tc).unwrap();
        assert_eq!(m.id, 0x1234);
        assert!(m.is_response());
        assert_ne!(m.flags & 0x0200, 0, "TC bit must be set");
        assert!(m.answers.is_empty());
        assert_eq!(m.questions.len(), 1);
    }

    #[test]
    fn test_query_param_and_percent_decode() {
        assert_eq!(query_param("/p?a=1&b=2", "b").as_deref(), Some("2"));
        assert_eq!(query_param("/p?a=1", "z"), None);
        assert_eq!(query_param("/p", "a"), None);
        assert_eq!(query_param("/p?a=x%2Dy", "a").as_deref(), Some("x-y"));
        assert_eq!(percent_decode("a%2Fb"), "a/b");
        assert_eq!(percent_decode("plain"), "plain");
    }
}
