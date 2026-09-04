use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{debug, info, warn};

use crate::chain::{Chain, ChainError, ChainOptions};
use crate::conn::ProxyConn;
use crate::handler::{Handler, HandlerError, HandlerOptions};
use crate::permissions::Can;
use crate::transport::transport;

// SOCKS5 constants
const SOCKS5_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USER_PASS: u8 = 0x02;
const METHOD_NO_ACCEPTABLE: u8 = 0xFF;

const CMD_CONNECT: u8 = 0x01;
const CMD_BIND: u8 = 0x02;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
/// gost's private SOCKS5 command for tunnelling UDP datagrams over the TCP
/// control connection (`CmdUDPTun`, socks.go:37).
const CMD_UDP_TUN: u8 = 0xF3;

/// Maximum size of a single UDP datagram we are willing to relay.
const UDP_BUFFER_SIZE: usize = 64 * 1024;

/// The largest payload one tunnelled datagram can carry: its length travels in
/// the 2-byte RSV field, so it cannot exceed a `u16`.
const UDP_TUN_MAX_PAYLOAD: usize = u16::MAX as usize;

/// How many bytes of a tunnel frame can be read before its total length is
/// known: RSV(2) | FRAG(1) | ATYP(1) plus one more byte, which is either the
/// first address byte or, for a domain, the name's length. gost reads exactly
/// these five first (gosocks5 v0.3.0 socks5.go:676).
const UDP_TUN_HEAD_LEN: usize = 5;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_NOT_ALLOWED: u8 = 0x02;
const REP_NETWORK_UNREACHABLE: u8 = 0x03;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_CONNECTION_REFUSED: u8 = 0x05;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ADDR_NOT_SUPPORTED: u8 = 0x08;

// ---------------------------------------------------------------------------
// SOCKS5 UDP-over-TCP tunnel framing (gost's CmdUDPTun, socks.go:37)
// ---------------------------------------------------------------------------
//
// The tunnel carries ordinary SOCKS5 UDP datagrams over a byte stream:
//
//     +-----+------+------+----------+----------+----------+
//     | RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//     +-----+------+------+----------+----------+----------+
//     |  2  |  1   |  1   | Variable |    2     | Variable |
//     +-----+------+------+----------+----------+----------+
//
// There is no separate length prefix. TCP's missing message boundaries are
// recovered by *repurposing the 2-byte RSV field as the length of DATA*,
// big-endian, covering the payload only and not the header. gosocks5 v0.3.0
// calls this out in so many words:
//
//     dlen := int(header.Rsv)
//     if dlen == 0 { // standard SOCKS5 UDP datagram
//         ...
//     } else { // extended feature, for UDP over TCP, using reserved field as data length
//         if _, err := io.ReadFull(r, b[n:hlen+dlen]); err != nil { ... }
//     }
//                                             -- gosocks5 socks5.go:693-706
//
// and both ends of gost's tunnel stamp it on every write:
//
//     dgram := gosocks5.NewUDPDatagram(
//         gosocks5.NewUDPHeader(uint16(n), 0, toSocksAddr(addr)), b[:n])
//                                             -- gost socks.go:1478-1479 (server)
//     dgram := gosocks5.NewUDPDatagram(
//         gosocks5.NewUDPHeader(uint16(len(b)), 0, toSocksAddr(addr)), b)
//                                             -- gost socks.go:1968 (client)
//
// The reader therefore takes the frame length from the header alone:
// `hlen` is 10 for IPv4, 22 for IPv6 and `7 + len(domain)` for a name
// (gosocks5 socks5.go:686-694), and the whole frame is `hlen + dlen` bytes.
//
// One deliberate deviation: gost's reader treats `RSV == 0` as "this is a
// plain packet-conn datagram" and calls `ioutil.ReadAll`, which on a stream
// swallows every following frame. gost's writers only ever produce `RSV == 0`
// for a zero-length payload, so this port reads such a frame as an empty
// datagram and drops it, exactly as `RelayConn` drops empty relay datagrams
// (relay.rs:314-319). That keeps the stream in sync where gost would desync,
// and produces identical bytes on the wire.

/// Read-side state machine for [`Socks5UdpTunnelConn`].
enum TunnelReadState {
    /// Waiting for the fixed five-byte prefix that reveals the frame length.
    Head,
    /// Waiting for the rest of the frame: `(header length, data length)`.
    Body(usize, usize),
    /// The peer closed the stream on a frame boundary.
    Eof,
}

/// Wraps a byte stream in gost's SOCKS5 UDP-over-TCP datagram framing.
///
/// gost's `socks5UDPTunnelConn` (socks.go:1905-1974) is both a `net.Conn` and
/// a `net.PacketConn`; this type offers the same two views. [`recv_from`] and
/// [`send_to`] carry the per-datagram address, while the `AsyncRead` /
/// `AsyncWrite` impls hide it: reads yield payloads only, and writes are
/// stamped with the fixed destination `taddr` the connection was built with,
/// mirroring gost's `Read`/`Write` (socks.go:1948-1968).
///
/// [`recv_from`]: Socks5UdpTunnelConn::recv_from
/// [`send_to`]: Socks5UdpTunnelConn::send_to
pub struct Socks5UdpTunnelConn<S> {
    inner: S,
    /// Destination stamped on datagrams written through `AsyncWrite`. gost's
    /// `toSocksAddr(nil)` is `0.0.0.0:0` (socks.go:1634-1651), which is what a
    /// tunnel opened without one uses.
    taddr: (String, u16),
    /// Address the server reported in its reply; client side only.
    bound_addr: Option<String>,

    read_state: TunnelReadState,
    read_buf: Vec<u8>,
    read_need: usize,
    /// One fully received datagram, held across `poll_read` calls so that a
    /// datagram larger than the caller's buffer is delivered in full rather
    /// than truncated, and so that two datagrams are never coalesced.
    plain: Vec<u8>,
    plain_pos: usize,
    /// Source address of `plain`.
    plain_host: String,
    plain_port: u16,

    out: Vec<u8>,
    out_pos: usize,
}

impl<S> Socks5UdpTunnelConn<S> {
    /// Server side: every datagram carries its own address, so there is no
    /// default destination.
    pub fn server(inner: S) -> Self {
        Self::with_taddr(inner, ("0.0.0.0".to_string(), 0), None)
    }

    /// Client side. `taddr` is stamped on datagrams written through
    /// `AsyncWrite`; `bound_addr` is the address the server reported.
    pub fn client(inner: S, taddr: (String, u16), bound_addr: String) -> Self {
        Self::with_taddr(inner, taddr, Some(bound_addr))
    }

    fn with_taddr(inner: S, taddr: (String, u16), bound_addr: Option<String>) -> Self {
        Self {
            inner,
            taddr,
            bound_addr,
            read_state: TunnelReadState::Head,
            read_buf: Vec::with_capacity(UDP_TUN_HEAD_LEN),
            read_need: UDP_TUN_HEAD_LEN,
            plain: Vec::new(),
            plain_pos: 0,
            plain_host: String::new(),
            plain_port: 0,
            out: Vec::new(),
            out_pos: 0,
        }
    }

    /// The address the server bound for this tunnel, as reported in its reply.
    pub fn bound_addr(&self) -> Option<&str> {
        self.bound_addr.as_deref()
    }

    /// Queues one datagram for transmission.
    fn queue_datagram(&mut self, host: &str, port: u16, data: &[u8]) -> io::Result<()> {
        if data.len() > UDP_TUN_MAX_PAYLOAD {
            return Err(io::Error::other(format!(
                "socks5: datagram of {} bytes exceeds the {}-byte tunnel maximum",
                data.len(),
                UDP_TUN_MAX_PAYLOAD
            )));
        }
        encode_udp_tunnel_datagram_into(host, port, data, &mut self.out);
        Ok(())
    }
}

/// One received datagram with its source address, or `None` at end of
/// stream. Named because the nested type is otherwise unreadable.
type PollDatagram = Poll<io::Result<Option<(Vec<u8>, String, u16)>>>;

impl<S: AsyncRead + Unpin> Socks5UdpTunnelConn<S> {
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

    /// Advances the read state machine until `plain` holds one whole datagram.
    /// `Ok(false)` means the stream ended cleanly on a frame boundary.
    fn poll_datagram(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        loop {
            if self.plain_pos < self.plain.len() {
                return Poll::Ready(Ok(true));
            }
            self.plain.clear();
            self.plain_pos = 0;

            if matches!(self.read_state, TunnelReadState::Eof) {
                return Poll::Ready(Ok(false));
            }

            let complete = match self.poll_fill(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(c)) => c,
            };
            if !complete {
                // A close on a frame boundary is a normal end of stream;
                // part-way through a frame it is a truncated one.
                if self.read_buf.is_empty() && matches!(self.read_state, TunnelReadState::Head) {
                    self.read_state = TunnelReadState::Eof;
                    return Poll::Ready(Ok(false));
                }
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "socks5: truncated UDP tunnel datagram",
                )));
            }

            match self.read_state {
                TunnelReadState::Head => {
                    let b = &self.read_buf;
                    // RSV doubles as the payload length (gosocks5 socks5.go:693).
                    let dlen = u16::from_be_bytes([b[0], b[1]]) as usize;
                    // gosocks5 socks5.go:686-694.
                    let hlen = match b[3] {
                        ATYP_IPV4 => 10,
                        ATYP_IPV6 => 22,
                        ATYP_DOMAIN => 7 + b[4] as usize,
                        other => {
                            return Poll::Ready(Err(io::Error::other(format!(
                                "socks5: bad address type in UDP tunnel frame: {}",
                                other
                            ))))
                        }
                    };
                    self.read_state = TunnelReadState::Body(hlen, dlen);
                    self.read_need = hlen + dlen;
                }
                TunnelReadState::Body(hlen, dlen) => {
                    let frame = std::mem::take(&mut self.read_buf);
                    self.read_state = TunnelReadState::Head;
                    self.read_need = UDP_TUN_HEAD_LEN;

                    // The header is a plain SOCKS5 UDP header, so the datagram
                    // parser the ASSOCIATE relay uses decodes it verbatim.
                    let (frag, host, port, off) = match parse_udp_datagram(&frame[..hlen]) {
                        Some(v) => v,
                        None => {
                            return Poll::Ready(Err(io::Error::other(
                                "socks5: malformed address in UDP tunnel frame",
                            )))
                        }
                    };
                    debug_assert_eq!(off, hlen);

                    // Neither gost nor this port reassembles fragments.
                    if frag != 0 {
                        debug!("[socks5-udp-tun] dropping fragment (frag={})", frag);
                        continue;
                    }

                    self.plain_host = host;
                    self.plain_port = port;
                    self.plain = frame[hlen..hlen + dlen].to_vec();
                    self.plain_pos = 0;
                }
                TunnelReadState::Eof => unreachable!("handled above"),
            }
        }
    }

    fn poll_recv_from(&mut self, cx: &mut Context<'_>) -> PollDatagram {
        match self.poll_datagram(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(false)) => Poll::Ready(Ok(None)),
            Poll::Ready(Ok(true)) => {
                let data = self.plain[self.plain_pos..].to_vec();
                self.plain.clear();
                self.plain_pos = 0;
                Poll::Ready(Ok(Some((data, self.plain_host.clone(), self.plain_port))))
            }
        }
    }

    /// Receives the next datagram as `(payload, host, port)`. `Ok(None)` is a
    /// clean end of stream. Cancel-safe: every byte of a partially received
    /// frame stays in the connection, so dropping the future loses nothing.
    pub async fn recv_from(&mut self) -> io::Result<Option<(Vec<u8>, String, u16)>> {
        std::future::poll_fn(|cx| self.poll_recv_from(cx)).await
    }
}

impl<S: AsyncWrite + Unpin> Socks5UdpTunnelConn<S> {
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

    /// Sends one datagram addressed to `host:port`.
    pub async fn send_to(&mut self, data: &[u8], host: &str, port: u16) -> io::Result<()> {
        // Drain what is already queued before adding more, so a slow peer
        // cannot make the outbound buffer grow without bound.
        std::future::poll_fn(|cx| self.poll_flush_out(cx)).await?;
        self.queue_datagram(host, port, data)?;
        std::future::poll_fn(|cx| self.poll_flush_out(cx)).await
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Socks5UdpTunnelConn<S> {
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

            match me.poll_datagram(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(false)) => return Poll::Ready(Ok(())),
                Poll::Ready(Ok(true)) => {}
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Socks5UdpTunnelConn<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Bound memory by draining the previous frame before queueing another.
        match me.poll_flush_out(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }

        let (host, port) = me.taddr.clone();
        me.queue_datagram(&host, port, buf)?;

        // Best-effort flush; whatever remains goes out on the next call.
        let _ = me.poll_flush_out(cx);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        match me.poll_flush_out(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => Pin::new(&mut me.inner).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        match me.poll_flush_out(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}

/// Appends one UDP-over-TCP tunnel frame to `buf`.
///
/// `RSV` is the payload length, big-endian, covering `DATA` only; `FRAG` is
/// always 0. gost: `UDPHeader.Write` + `UDPDatagram.Write`
/// (gosocks5 v0.3.0 socks5.go:633-647 and 726-741).
fn encode_udp_tunnel_datagram_into(host: &str, port: u16, data: &[u8], buf: &mut Vec<u8>) {
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes()); // RSV = len(DATA)
    buf.push(0x00); // FRAG
    encode_address(host, port, buf); // ATYP | DST.ADDR | DST.PORT
    buf.extend_from_slice(data);
}

/// Convenience wrapper around [`encode_udp_tunnel_datagram_into`].
fn encode_udp_tunnel_datagram(host: &str, port: u16, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(data.len() + 3 + 1 + host.len().max(16) + 2);
    encode_udp_tunnel_datagram_into(host, port, data, &mut buf);
    buf
}

/// SOCKS5 connector (client side).
pub struct Socks5Connector {
    pub user: Option<(String, Option<String>)>,
}

impl Socks5Connector {
    pub fn new(user: Option<(String, Option<String>)>) -> Self {
        Self { user }
    }

    /// Perform SOCKS5 handshake and CONNECT through proxy.
    pub async fn connect(
        &self,
        mut conn: TcpStream,
        address: &str,
    ) -> Result<TcpStream, HandlerError> {
        // Determine methods
        let methods = if self.user.is_some() {
            vec![METHOD_NO_AUTH, METHOD_USER_PASS]
        } else {
            vec![METHOD_NO_AUTH]
        };

        // Send greeting
        let mut greeting = vec![SOCKS5_VERSION, methods.len() as u8];
        greeting.extend_from_slice(&methods);
        conn.write_all(&greeting).await?;

        // Read server choice
        let mut resp = [0u8; 2];
        conn.read_exact(&mut resp).await?;
        if resp[0] != SOCKS5_VERSION {
            return Err(HandlerError::Proxy("invalid SOCKS5 version".into()));
        }

        // Handle auth if required
        if resp[1] == METHOD_USER_PASS {
            if let Some((ref user, ref pass)) = self.user {
                let p = pass.as_deref().unwrap_or("");
                let mut auth = vec![0x01, user.len() as u8];
                auth.extend_from_slice(user.as_bytes());
                auth.push(p.len() as u8);
                auth.extend_from_slice(p.as_bytes());
                conn.write_all(&auth).await?;

                let mut auth_resp = [0u8; 2];
                conn.read_exact(&mut auth_resp).await?;
                if auth_resp[1] != 0x00 {
                    return Err(HandlerError::AuthFailed);
                }
            } else {
                return Err(HandlerError::AuthFailed);
            }
        } else if resp[1] == METHOD_NO_ACCEPTABLE {
            return Err(HandlerError::Proxy("no acceptable method".into()));
        }

        // Send CONNECT request
        let (host, port) = parse_address(address)?;
        let mut req = vec![SOCKS5_VERSION, CMD_CONNECT, 0x00];
        encode_address(&host, port, &mut req);
        conn.write_all(&req).await?;

        // Read reply
        let mut reply = [0u8; 4];
        conn.read_exact(&mut reply).await?;
        if reply[1] != REP_SUCCESS {
            return Err(HandlerError::Proxy(format!(
                "SOCKS5 connect failed: code {}",
                reply[1]
            )));
        }

        // Skip bound address
        skip_address(&mut conn, reply[3]).await?;

        Ok(conn)
    }

    /// Opens a UDP-over-TCP tunnel over `conn` and returns the datagram view
    /// of it.
    ///
    /// gost: `newSocks5UDPTunnelConn` (socks.go:1910-1946), reached through
    /// `getSocks5UDPTunnel` (socks.go:1887-1903). `bind_addr` is the address
    /// the server should bind its UDP socket on, which travels in the request;
    /// `target` is the fixed destination for the `AsyncWrite` view and may be
    /// omitted when every datagram carries its own (gost passes `nil`).
    ///
    /// Generic over the stream so a chain hop can hand in whatever it dialled:
    /// `Chain::dial` is TCP-only today, but a `ProxyConn` works just as well.
    pub async fn udp_tunnel<S>(
        &self,
        mut conn: S,
        bind_addr: &str,
        target: Option<&str>,
    ) -> Result<Socks5UdpTunnelConn<S>, HandlerError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        socks5_method_handshake(&mut conn, self.user.as_ref()).await?;

        // VER | CMD=0xF3 | RSV | ATYP | ADDR | PORT (gosocks5 socks5.go:487-506)
        let (host, port) = parse_address(bind_addr)?;
        let mut req = vec![SOCKS5_VERSION, CMD_UDP_TUN, 0x00];
        encode_address(&host, port, &mut req);
        conn.write_all(&req).await?;

        let mut head = [0u8; 4];
        conn.read_exact(&mut head).await?;
        if head[0] != SOCKS5_VERSION {
            return Err(HandlerError::Proxy("invalid SOCKS5 version".into()));
        }
        if head[1] != REP_SUCCESS {
            return Err(HandlerError::Proxy(format!(
                "socks5 UDP tunnel failure: code {}",
                head[1]
            )));
        }
        let (bhost, bport) = read_address(&mut conn, head[3]).await?;

        // gost's `toSocksAddr(nil)` is 0.0.0.0:0 (socks.go:1634-1651).
        let taddr = match target {
            Some(t) => parse_address(t)?,
            None => ("0.0.0.0".to_string(), 0),
        };

        Ok(Socks5UdpTunnelConn::client(
            conn,
            taddr,
            join_host_port(&bhost, bport),
        ))
    }
}

/// SOCKS5 handler (server side).
pub struct Socks5Handler {
    options: HandlerOptions,
}

impl Socks5Handler {
    pub fn new(options: HandlerOptions) -> Self {
        Self { options }
    }

    async fn authenticate(&self, user: &str, password: &str) -> bool {
        if let Some(ref auth) = self.options.authenticator {
            auth.authenticate(user, password)
        } else {
            true
        }
    }

    /// Mirrors gost's retry precedence (socks.go:915-921): the handler's own
    /// `Retries` wins, otherwise the chain's `Retries`, otherwise a single try.
    ///
    /// The returned chain has its internal retry counter pinned to 1 so the
    /// loop here is the only place retries happen.
    fn dial_setup(&self) -> (Chain, usize, ChainOptions) {
        let mut chain = self.options.chain.clone().unwrap_or_default();
        let chain_retries = chain.retries;
        chain.retries = 1;

        let retries = if self.options.retries > 0 {
            self.options.retries
        } else if chain_retries > 0 {
            chain_retries
        } else {
            1
        };

        // Start from the chain's own options so `?hosts=` and `?dns=` keep
        // working (main.rs pushes them onto the chain); only the retry count
        // and the timeout are overridden, mirroring gost's
        // TimeoutChainOption/HostsChainOption/ResolverChainOption trio.
        let mut opts = chain.default_options();
        opts.retries = 1;
        if self.options.timeout > Duration::ZERO {
            opts.timeout = self.options.timeout;
        }

        (chain, retries, opts)
    }

    async fn dial_target(&self, target: &str) -> Result<crate::conn::ProxyConn, ChainError> {
        let (chain, retries, opts) = self.dial_setup();
        let mut last_err = ChainError::EmptyChain;
        for i in 0..retries {
            match chain.dial_with_options(target, &opts).await {
                Ok(cc) => return Ok(cc),
                Err(e) => {
                    debug!(
                        "[socks5] dial {} attempt {}/{}: {}",
                        target,
                        i + 1,
                        retries,
                        e
                    );
                    last_err = e;
                }
            }
        }
        Err(last_err)
    }

    fn dial_timeout(&self) -> Duration {
        if self.options.timeout > Duration::ZERO {
            self.options.timeout
        } else {
            Duration::from_secs(crate::DIAL_TIMEOUT)
        }
    }

    /// gost: socks5Handler.handleConnect (socks.go:880-978)
    async fn handle_connect(
        &self,
        mut conn: ProxyConn,
        target: &str,
        peer_addr: &str,
    ) -> Result<(), HandlerError> {
        if !Can(
            "tcp",
            target,
            self.options.whitelist.as_ref(),
            self.options.blacklist.as_ref(),
        ) {
            warn!(
                "[socks5] {} - unauthorized to tcp connect to {}",
                peer_addr, target
            );
            send_reply(&mut conn, REP_NOT_ALLOWED, "0.0.0.0", 0).await?;
            return Err(HandlerError::Forbidden);
        }

        if let Some(ref bypass) = self.options.bypass {
            if bypass.contains(target) {
                debug!("[socks5] {} - bypass {}", peer_addr, target);
                send_reply(&mut conn, REP_NOT_ALLOWED, "0.0.0.0", 0).await?;
                return Ok(());
            }
        }

        match self.dial_target(target).await {
            Ok(cc) => {
                // gost replies `NewReply(Succeeded, nil)` (socks.go:966), i.e. an
                // all-zero bound address. Echoing the real outbound socket here
                // would disclose the proxy's egress IP and ephemeral port.
                send_reply(&mut conn, REP_SUCCESS, "0.0.0.0", 0).await?;

                info!("[socks5] {} <-> {}", peer_addr, target);
                transport(conn, cc).await.ok();
                info!("[socks5] {} >-< {}", peer_addr, target);
                Ok(())
            }
            Err(e) => {
                debug!("[socks5] {} -> {} : {}", peer_addr, target, e);
                send_reply(&mut conn, REP_HOST_UNREACHABLE, "0.0.0.0", 0).await?;
                Err(HandlerError::Chain(e))
            }
        }
    }

    /// gost: socks5Handler.handleBind (socks.go:981-1018)
    async fn handle_bind(
        &self,
        mut conn: ProxyConn,
        target: &str,
        peer_addr: &str,
    ) -> Result<(), HandlerError> {
        let chain = self.options.chain.clone().unwrap_or_default();

        if chain.is_empty() {
            if !Can(
                "rtcp",
                target,
                self.options.whitelist.as_ref(),
                self.options.blacklist.as_ref(),
            ) {
                warn!(
                    "[socks5-bind] {} - unauthorized to tcp bind to {}",
                    peer_addr, target
                );
                send_reply(&mut conn, REP_NOT_ALLOWED, "0.0.0.0", 0).await?;
                return Err(HandlerError::Forbidden);
            }
            return bind_on(conn, target, peer_addr).await;
        }

        // Chain forward (socks.go:997-1017): open a connection to the last node
        // of the chain and replay the BIND request onto it verbatim, then splice.
        let node = chain.last_node();
        let cc = tokio::time::timeout(self.dial_timeout(), TcpStream::connect(&node.addr)).await;
        let mut cc = match cc {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                send_reply(&mut conn, REP_GENERAL_FAILURE, "0.0.0.0", 0).await?;
                return Err(HandlerError::Io(e));
            }
            Err(_) => {
                send_reply(&mut conn, REP_GENERAL_FAILURE, "0.0.0.0", 0).await?;
                return Err(HandlerError::Proxy("bind: chain dial timeout".into()));
            }
        };

        // A socks5 node needs its method negotiation done before the request is
        // replayed; a plain forward node takes the request as-is.
        if node.protocol == "socks5" {
            if let Err(e) = socks5_method_handshake(&mut cc, node.user.as_ref()).await {
                send_reply(&mut conn, REP_GENERAL_FAILURE, "0.0.0.0", 0).await?;
                return Err(e);
            }
        }

        let (host, port) = parse_address(target)?;
        let mut req = vec![SOCKS5_VERSION, CMD_BIND, 0x00];
        encode_address(&host, port, &mut req);
        cc.write_all(&req).await?;

        info!("[socks5-bind] {} <-> {}", peer_addr, target);
        transport(conn, cc).await.ok();
        info!("[socks5-bind] {} >-< {}", peer_addr, target);
        Ok(())
    }

    /// gost: socks5Handler.handleUDPRelay (socks.go:1116-1217)
    async fn handle_udp_relay(
        &self,
        mut conn: ProxyConn,
        target: &str,
        peer_addr: &str,
    ) -> Result<(), HandlerError> {
        if !Can(
            "udp",
            target,
            self.options.whitelist.as_ref(),
            self.options.blacklist.as_ref(),
        ) {
            warn!(
                "[socks5-udp] {} - unauthorized to udp connect to {}",
                peer_addr, target
            );
            send_reply(&mut conn, REP_NOT_ALLOWED, "0.0.0.0", 0).await?;
            return Err(HandlerError::Forbidden);
        }

        // Bind the relay socket on the out-going interface's IP, exactly as
        // gost does (socks.go:1128) so the address we advertise is reachable.
        // `ProxyConn` carries the accepted socket's local address through every
        // transport layer, so this stays the listener's real interface IP even
        // when the control connection is TLS/WebSocket rather than raw TCP.
        let local_ip = conn
            .local_addr()
            .map(|a| a.ip())
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));

        let relay = match UdpSocket::bind(SocketAddr::new(local_ip, 0)).await {
            Ok(s) => s,
            Err(e) => {
                debug!("[socks5-udp] {} - bind relay: {}", peer_addr, e);
                send_reply(&mut conn, REP_GENERAL_FAILURE, "0.0.0.0", 0).await?;
                return Err(HandlerError::Io(e));
            }
        };
        let relay_addr = relay.local_addr()?;

        // Reply with the address of the socket we actually bound.
        send_reply(
            &mut conn,
            REP_SUCCESS,
            &relay_addr.ip().to_string(),
            relay_addr.port(),
        )
        .await?;

        let peer_bind = if local_ip.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        };
        let peer = match UdpSocket::bind(peer_bind).await {
            Ok(s) => s,
            Err(e) => {
                debug!("[socks5-udp] {} - bind peer: {}", peer_addr, e);
                return Err(HandlerError::Io(e));
            }
        };

        info!(
            "[socks5-udp] {} <-> {} : associated on {}",
            peer_addr, target, relay_addr
        );

        // The association lives exactly as long as the TCP control connection.
        // When the control connection goes away, both sockets are dropped and
        // the association is torn down (RFC 1928 / gost socks.go:1206-1211).
        tokio::select! {
            r = discard_client_data(&mut conn) => {
                if let Err(e) = r {
                    debug!("[socks5-udp] {} - control conn: {}", peer_addr, e);
                }
            }
            r = self.transport_udp(&relay, &peer) => {
                if let Err(e) = r {
                    debug!("[socks5-udp] {} - relay: {}", peer_addr, e);
                }
            }
        }

        info!(
            "[socks5-udp] {} >-< {} : association on {} closed",
            peer_addr, target, relay_addr
        );
        Ok(())
    }

    /// gost: socks5Handler.handleUDPTunnel (socks.go:1397-1455).
    ///
    /// The datagrams ride the TCP control connection itself instead of a
    /// side-channel UDP socket, which is what lets UDP cross a proxy chain at
    /// all: `Chain::dial` only ever produces a stream.
    async fn handle_udp_tunnel(
        &self,
        mut conn: ProxyConn,
        target: &str,
        peer_addr: &str,
    ) -> Result<(), HandlerError> {
        let chain = self.options.chain.clone().unwrap_or_default();

        if !chain.is_empty() {
            // Chain forward (socks.go:1431-1454): replay the request onto the
            // last node and splice, so a tunnel can be relayed hop by hop.
            // gost deliberately does not re-authorize a forwarded tunnel: the
            // forwarding is configured server-side, which is as explicit as
            // whitelisting (socks.go:1445-1447).
            let node = chain.last_node();
            let cc =
                tokio::time::timeout(self.dial_timeout(), TcpStream::connect(&node.addr)).await;
            let mut cc = match cc {
                Ok(Ok(c)) => c,
                Ok(Err(e)) => {
                    send_reply(&mut conn, REP_GENERAL_FAILURE, "0.0.0.0", 0).await?;
                    return Err(HandlerError::Io(e));
                }
                Err(_) => {
                    send_reply(&mut conn, REP_GENERAL_FAILURE, "0.0.0.0", 0).await?;
                    return Err(HandlerError::Proxy("udp-tun: chain dial timeout".into()));
                }
            };

            if let Err(e) = socks5_method_handshake(&mut cc, node.user.as_ref()).await {
                send_reply(&mut conn, REP_GENERAL_FAILURE, "0.0.0.0", 0).await?;
                return Err(e);
            }

            let (host, port) = parse_address(target)?;
            let mut req = vec![SOCKS5_VERSION, CMD_UDP_TUN, 0x00];
            encode_address(&host, port, &mut req);
            cc.write_all(&req).await?;

            info!("[socks5-udp-tun] {} <-> {}", peer_addr, node.addr);
            transport(conn, cc).await.ok();
            info!("[socks5-udp-tun] {} >-< {}", peer_addr, node.addr);
            return Ok(());
        }

        // gost gates the bind address with the "rudp" action (socks.go:1402)
        // and then simply drops the connection. Replying NOT_ALLOWED first is
        // strictly more informative and is what every other refusal in this
        // handler does.
        if !Can(
            "rudp",
            target,
            self.options.whitelist.as_ref(),
            self.options.blacklist.as_ref(),
        ) {
            warn!(
                "[socks5-udp-tun] {} - unauthorized to udp bind to {}",
                peer_addr, target
            );
            send_reply(&mut conn, REP_NOT_ALLOWED, "0.0.0.0", 0).await?;
            return Err(HandlerError::Forbidden);
        }

        // gost resolves the requested bind address and hands it to ListenUDP;
        // an address it cannot resolve becomes nil, i.e. a wildcard bind on an
        // ephemeral port (socks.go:1406-1407).
        let (bind_host, bind_port) = parse_address(target)?;
        let bind_sa = resolve_udp_addr(&bind_host, bind_port)
            .await
            .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));

        let uc = match UdpSocket::bind(bind_sa).await {
            Ok(s) => s,
            Err(e) => {
                debug!("[socks5-udp-tun] {} -> {} : {}", peer_addr, target, e);
                send_reply(&mut conn, REP_GENERAL_FAILURE, "0.0.0.0", 0).await?;
                return Err(HandlerError::Io(e));
            }
        };
        let bound = uc.local_addr()?;

        // gost advertises the UDP socket's port under the control connection's
        // local IP (socks.go:1414-1415), so a wildcard bind still reports an
        // address the client can actually reach.
        let advertised_ip = conn.local_addr().map(|a| a.ip()).unwrap_or(bound.ip());
        send_reply(
            &mut conn,
            REP_SUCCESS,
            &advertised_ip.to_string(),
            bound.port(),
        )
        .await?;

        info!(
            "[socks5-udp-tun] {} <-> {} : tunnel bound on {}",
            peer_addr,
            target,
            join_host_port(&advertised_ip.to_string(), bound.port())
        );

        let mut tunnel = Socks5UdpTunnelConn::server(conn);
        if let Err(e) = self.tunnel_server_udp(&mut tunnel, &uc).await {
            debug!("[socks5-udp-tun] {} - relay: {}", peer_addr, e);
        }

        info!(
            "[socks5-udp-tun] {} >-< {} : tunnel closed",
            peer_addr, target
        );
        Ok(())
    }

    /// gost: socks5Handler.tunnelServerUDP (socks.go:1457-1524).
    ///
    /// `tunnel` speaks the UDP-over-TCP framing towards the client; `pc` faces
    /// the world and speaks plain UDP. The association lives exactly as long
    /// as the tunnel stream: the loop ends when it closes.
    async fn tunnel_server_udp<S>(
        &self,
        tunnel: &mut Socks5UdpTunnelConn<S>,
        pc: &UdpSocket,
    ) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut pbuf = vec![0u8; UDP_BUFFER_SIZE];

        enum Ev {
            FromTunnel(Option<(Vec<u8>, String, u16)>),
            FromPeer(usize, SocketAddr),
        }

        loop {
            // The branch results are hoisted out of `select!` so the borrows
            // on `tunnel` and `pbuf` end before we act on their contents.
            let ev = tokio::select! {
                r = tunnel.recv_from() => Ev::FromTunnel(r?),
                r = pc.recv_from(&mut pbuf) => {
                    let (n, a) = r?;
                    Ev::FromPeer(n, a)
                }
            };

            match ev {
                // The client hung up; the association goes with it.
                Ev::FromTunnel(None) => return Ok(()),
                Ev::FromTunnel(Some((data, host, port))) => {
                    // Filtered exactly like the ASSOCIATE relay: once as
                    // written in the datagram, so domain rules apply, and once
                    // after resolution, so IP/CIDR rules apply.
                    let dst = join_host_port(&host, port);
                    if !self.udp_dst_allowed(&dst) {
                        continue;
                    }
                    let raddr = match resolve_udp_addr(&host, port).await {
                        Some(a) => a,
                        None => continue, // unresolvable, drop silently
                    };
                    let resolved = raddr.to_string();
                    if resolved != dst && !self.udp_dst_allowed(&resolved) {
                        continue;
                    }
                    pc.send_to(&data, raddr).await?;
                }
                Ev::FromPeer(n, raddr) => {
                    // gost only applies the bypass on the way back
                    // (socks.go:1476-1479), as does the ASSOCIATE relay.
                    if let Some(ref bypass) = self.options.bypass {
                        if bypass.contains(&raddr.to_string()) {
                            debug!("[socks5-udp-tun] [bypass] read from {}", raddr);
                            continue;
                        }
                    }
                    tunnel
                        .send_to(&pbuf[..n], &raddr.ip().to_string(), raddr.port())
                        .await?;
                }
            }
        }
    }

    /// Whether a UDP datagram may be forwarded to `dst` ("host:port").
    ///
    /// Applies the same whitelist/blacklist and bypass rules the TCP path uses,
    /// per datagram (gost socks.go:1263, 1290).
    fn udp_dst_allowed(&self, dst: &str) -> bool {
        if !Can(
            "udp",
            dst,
            self.options.whitelist.as_ref(),
            self.options.blacklist.as_ref(),
        ) {
            debug!("[socks5-udp] unauthorized to send to {}", dst);
            return false;
        }
        if let Some(ref bypass) = self.options.bypass {
            if bypass.contains(dst) {
                debug!("[socks5-udp] [bypass] write to {}", dst);
                return false;
            }
        }
        true
    }

    /// gost: socks5Handler.transportUDP (socks.go:1235-1313).
    ///
    /// `relay` faces the SOCKS client and speaks the SOCKS5 UDP datagram
    /// framing; `peer` faces the world and speaks plain UDP.
    async fn transport_udp(&self, relay: &UdpSocket, peer: &UdpSocket) -> std::io::Result<()> {
        let mut rbuf = vec![0u8; UDP_BUFFER_SIZE];
        let mut pbuf = vec![0u8; UDP_BUFFER_SIZE];
        let mut client_addr: Option<SocketAddr> = None;

        enum Ev {
            FromClient(usize, SocketAddr),
            FromPeer(usize, SocketAddr),
        }

        loop {
            // The branch results are hoisted out of `select!` so the mutable
            // borrows on the buffers end before we inspect their contents.
            let ev = tokio::select! {
                r = relay.recv_from(&mut rbuf) => {
                    let (n, a) = r?;
                    Ev::FromClient(n, a)
                }
                r = peer.recv_from(&mut pbuf) => {
                    let (n, a) = r?;
                    Ev::FromPeer(n, a)
                }
            };

            match ev {
                Ev::FromClient(n, laddr) => {
                    if client_addr.is_none() {
                        client_addr = Some(laddr);
                    }
                    // Only serve the client that owns the association.
                    if client_addr != Some(laddr) {
                        continue;
                    }

                    let (frag, host, port, off) = match parse_udp_datagram(&rbuf[..n]) {
                        Some(v) => v,
                        None => continue, // malformed, drop silently
                    };
                    // gost does not reassemble fragments either.
                    if frag != 0 {
                        debug!("[socks5-udp] dropping fragmented datagram (frag={})", frag);
                        continue;
                    }

                    // The destination is filtered twice: once as written in the
                    // datagram (so domain rules apply) and once after
                    // resolution (so IP/CIDR rules apply). gost only performs
                    // the second one (socks.go:1263); checking a domain name
                    // against an IP rule alone would let `evil.example`
                    // reach a blacklisted address.
                    let dst = join_host_port(&host, port);
                    if !self.udp_dst_allowed(&dst) {
                        continue;
                    }

                    let raddr = match resolve_udp_addr(&host, port).await {
                        Some(a) => a,
                        None => continue, // unresolvable, drop silently
                    };
                    let resolved = raddr.to_string();
                    if resolved != dst && !self.udp_dst_allowed(&resolved) {
                        continue;
                    }

                    let sent = peer.send_to(&rbuf[off..n], raddr).await;
                    sent?;
                }
                Ev::FromPeer(n, raddr) => {
                    let caddr = match client_addr {
                        Some(a) => a,
                        None => continue, // nothing to send back to yet
                    };
                    if let Some(ref bypass) = self.options.bypass {
                        if bypass.contains(&raddr.to_string()) {
                            debug!("[socks5-udp] [bypass] read from {}", raddr);
                            continue;
                        }
                    }
                    let out = encode_udp_datagram(&raddr, &pbuf[..n]);
                    let r = relay.send_to(&out, caddr).await;
                    r?;
                }
            }
        }
    }
}

#[async_trait]
impl Handler for Socks5Handler {
    async fn handle(&self, mut conn: ProxyConn) -> Result<(), HandlerError> {
        let peer_addr = conn.peer_addr_str();

        // Read greeting
        let mut ver = [0u8; 1];
        conn.read_exact(&mut ver).await?;
        if ver[0] != SOCKS5_VERSION {
            return Err(HandlerError::Proxy(format!(
                "unsupported SOCKS version: {}",
                ver[0]
            )));
        }

        let mut nmethods = [0u8; 1];
        conn.read_exact(&mut nmethods).await?;
        let mut methods = vec![0u8; nmethods[0] as usize];
        conn.read_exact(&mut methods).await?;

        let requires_auth = self.options.authenticator.is_some();

        if requires_auth {
            if methods.contains(&METHOD_USER_PASS) {
                conn.write_all(&[SOCKS5_VERSION, METHOD_USER_PASS]).await?;

                // Read auth request
                let mut auth_ver = [0u8; 1];
                conn.read_exact(&mut auth_ver).await?;

                let mut ulen = [0u8; 1];
                conn.read_exact(&mut ulen).await?;
                let mut uname = vec![0u8; ulen[0] as usize];
                conn.read_exact(&mut uname).await?;

                let mut plen = [0u8; 1];
                conn.read_exact(&mut plen).await?;
                let mut passwd = vec![0u8; plen[0] as usize];
                conn.read_exact(&mut passwd).await?;

                let user = String::from_utf8_lossy(&uname).to_string();
                let pass = String::from_utf8_lossy(&passwd).to_string();

                if self.authenticate(&user, &pass).await {
                    conn.write_all(&[0x01, 0x00]).await?;
                    debug!("[socks5] {} authenticated as {}", peer_addr, user);
                } else {
                    conn.write_all(&[0x01, 0x01]).await?;
                    warn!("[socks5] {} authentication failed for {}", peer_addr, user);
                    return Err(HandlerError::AuthFailed);
                }
            } else {
                conn.write_all(&[SOCKS5_VERSION, METHOD_NO_ACCEPTABLE])
                    .await?;
                return Err(HandlerError::AuthFailed);
            }
        } else {
            conn.write_all(&[SOCKS5_VERSION, METHOD_NO_AUTH]).await?;
        }

        // Read request
        let mut req_header = [0u8; 4];
        conn.read_exact(&mut req_header).await?;

        if req_header[0] != SOCKS5_VERSION {
            return Err(HandlerError::Proxy("invalid version in request".into()));
        }

        let (host, port) = read_address(&mut conn, req_header[3]).await?;
        let target = join_host_port(&host, port);

        info!("[socks5] {} -> {}", peer_addr, target);

        match req_header[1] {
            CMD_CONNECT => self.handle_connect(conn, &target, &peer_addr).await,
            CMD_BIND => self.handle_bind(conn, &target, &peer_addr).await,
            CMD_UDP_ASSOCIATE => self.handle_udp_relay(conn, &target, &peer_addr).await,
            CMD_UDP_TUN => self.handle_udp_tunnel(conn, &target, &peer_addr).await,
            _ => {
                send_reply(&mut conn, REP_CMD_NOT_SUPPORTED, "0.0.0.0", 0).await?;
                Err(HandlerError::Proxy(format!(
                    "unsupported command: {}",
                    req_header[1]
                )))
            }
        }
    }
}

/// gost: socks5Handler.bindOn (socks.go:1020-1114).
///
/// Binds a real TCP listener, sends a first reply carrying the bound address,
/// and on the first inbound peer connection sends a second reply carrying the
/// peer's address before splicing the two connections together.
async fn bind_on(mut conn: ProxyConn, addr: &str, peer_addr: &str) -> Result<(), HandlerError> {
    // Strict mode, like gost: if the port is already in use, fail.
    let ln = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            debug!("[socks5-bind] {} -> {} : {}", peer_addr, addr, e);
            send_reply(&mut conn, REP_GENERAL_FAILURE, "0.0.0.0", 0).await?;
            return Err(HandlerError::Io(e));
        }
    };

    let bound = ln.local_addr()?;
    // The listener may be bound to a wildcard address; advertise the local IP
    // of the control connection instead, which is reachable by definition.
    let host = conn.local_addr().map(|a| a.ip()).unwrap_or(bound.ip());
    let socks_addr = SocketAddr::new(host, bound.port());

    send_reply(
        &mut conn,
        REP_SUCCESS,
        &socks_addr.ip().to_string(),
        socks_addr.port(),
    )
    .await?;
    info!("[socks5-bind] {} - BIND ON {} OK", peer_addr, socks_addr);

    enum Ev {
        Peer(TcpStream, SocketAddr),
        AcceptFailed(std::io::Error),
        Closed,
    }

    // Race the peer accept against the control connection going away. gost
    // does the same via a net.Pipe (socks.go:1076-1105).
    let ev = {
        let mut probe = [0u8; 1];
        tokio::select! {
            res = ln.accept() => match res {
                Ok((c, a)) => Ev::Peer(c, a),
                Err(e) => Ev::AcceptFailed(e),
            },
            _ = conn.read(&mut probe) => Ev::Closed,
        }
    };
    drop(ln);

    match ev {
        Ev::Peer(pconn, praddr) => {
            send_reply(
                &mut conn,
                REP_SUCCESS,
                &praddr.ip().to_string(),
                praddr.port(),
            )
            .await?;
            info!(
                "[socks5-bind] {} <- {} PEER {} ACCEPTED",
                peer_addr, socks_addr, praddr
            );
            transport(conn, pconn).await.ok();
            info!("[socks5-bind] {} >-< {}", peer_addr, praddr);
            Ok(())
        }
        Ev::AcceptFailed(e) => {
            debug!("[socks5-bind] {} <- {} : {}", peer_addr, addr, e);
            Err(HandlerError::Io(e))
        }
        Ev::Closed => {
            debug!(
                "[socks5-bind] {} - control connection closed while binding",
                peer_addr
            );
            Ok(())
        }
    }
}

/// gost: socks5Handler.discardClientData (socks.go:1219-1233).
/// Resolves when the control connection is closed by the client.
///
/// Generic over the stream: a `ProxyConn` read returns 0 on EOF exactly like a
/// `TcpStream`, so the association still dies with the control connection.
async fn discard_client_data<S>(conn: &mut S) -> std::io::Result<()>
where
    S: AsyncRead + Unpin + Send + ?Sized,
{
    let mut buf = vec![0u8; crate::SMALL_BUFFER_SIZE];
    loop {
        let n = conn.read(&mut buf).await?;
        if n == 0 {
            return Ok(()); // client disconnected
        }
        debug!("[socks5-udp] read {} UNEXPECTED TCP data from client", n);
    }
}

/// Client-side SOCKS5 method negotiation, used when forwarding a BIND request
/// through a chain node.
async fn socks5_method_handshake<S>(
    conn: &mut S,
    user: Option<&(String, Option<String>)>,
) -> Result<(), HandlerError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + ?Sized,
{
    let methods: Vec<u8> = if user.is_some() {
        vec![METHOD_NO_AUTH, METHOD_USER_PASS]
    } else {
        vec![METHOD_NO_AUTH]
    };
    let mut greeting = vec![SOCKS5_VERSION, methods.len() as u8];
    greeting.extend_from_slice(&methods);
    conn.write_all(&greeting).await?;

    let mut resp = [0u8; 2];
    conn.read_exact(&mut resp).await?;
    if resp[0] != SOCKS5_VERSION {
        return Err(HandlerError::Proxy("invalid SOCKS5 version".into()));
    }

    match resp[1] {
        METHOD_NO_AUTH => Ok(()),
        METHOD_USER_PASS => {
            let (u, p) = match user {
                Some((u, p)) => (u.as_str(), p.as_deref().unwrap_or("")),
                None => return Err(HandlerError::AuthFailed),
            };
            let mut auth = vec![0x01, u.len() as u8];
            auth.extend_from_slice(u.as_bytes());
            auth.push(p.len() as u8);
            auth.extend_from_slice(p.as_bytes());
            conn.write_all(&auth).await?;

            let mut ar = [0u8; 2];
            conn.read_exact(&mut ar).await?;
            if ar[1] != 0x00 {
                return Err(HandlerError::AuthFailed);
            }
            Ok(())
        }
        _ => Err(HandlerError::Proxy("no acceptable method".into())),
    }
}

/// Parses a SOCKS5 UDP request header:
/// `RSV(2) | FRAG(1) | ATYP(1) | DST.ADDR | DST.PORT(2) | DATA`.
///
/// Returns `(frag, host, port, data_offset)`.
fn parse_udp_datagram(b: &[u8]) -> Option<(u8, String, u16, usize)> {
    if b.len() < 5 {
        return None;
    }
    let frag = b[2];
    let atyp = b[3];
    let mut i = 4usize;

    let host = match atyp {
        ATYP_IPV4 => {
            if b.len() < i + 4 {
                return None;
            }
            let h = Ipv4Addr::new(b[i], b[i + 1], b[i + 2], b[i + 3]).to_string();
            i += 4;
            h
        }
        ATYP_DOMAIN => {
            let len = b[i] as usize;
            i += 1;
            if len == 0 || b.len() < i + len {
                return None;
            }
            let h = String::from_utf8_lossy(&b[i..i + len]).to_string();
            i += len;
            h
        }
        ATYP_IPV6 => {
            if b.len() < i + 16 {
                return None;
            }
            let mut a = [0u8; 16];
            a.copy_from_slice(&b[i..i + 16]);
            i += 16;
            Ipv6Addr::from(a).to_string()
        }
        _ => return None,
    };

    if b.len() < i + 2 {
        return None;
    }
    let port = u16::from_be_bytes([b[i], b[i + 1]]);
    i += 2;

    Some((frag, host, port, i))
}

/// Builds a SOCKS5 UDP reply datagram (FRAG is always 0).
fn encode_udp_datagram(addr: &SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(data.len() + 22);
    buf.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV, RSV, FRAG
    encode_address(&addr.ip().to_string(), addr.port(), &mut buf);
    buf.extend_from_slice(data);
    buf
}

async fn resolve_udp_addr(host: &str, port: u16) -> Option<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, port));
    }
    tokio::net::lookup_host((host, port)).await.ok()?.next()
}

/// Generic over the stream so the same reply writer serves a `ProxyConn`
/// control connection and a plain `TcpStream`.
async fn send_reply<S>(conn: &mut S, rep: u8, addr: &str, port: u16) -> Result<(), HandlerError>
where
    S: AsyncWrite + Unpin + Send + ?Sized,
{
    let mut reply = vec![SOCKS5_VERSION, rep, 0x00];
    if let Ok(ip) = addr.parse::<Ipv4Addr>() {
        reply.push(ATYP_IPV4);
        reply.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = addr.parse::<Ipv6Addr>() {
        reply.push(ATYP_IPV6);
        reply.extend_from_slice(&ip.octets());
    } else {
        reply.push(ATYP_IPV4);
        reply.extend_from_slice(&[0, 0, 0, 0]);
    }
    reply.extend_from_slice(&port.to_be_bytes());
    conn.write_all(&reply).await?;
    Ok(())
}

/// Joins a host and a port the way Go's `net.JoinHostPort` does: a host that
/// contains a colon (i.e. an IPv6 literal) is wrapped in brackets.
///
/// gost builds every address through `gosocks5.Addr.String()`, which is
/// `net.JoinHostPort`. A bare `format!("{}:{}")` produced `"::1:443"`, which is
/// not a valid address: `Can()` fails to split it and therefore DENIES, and
/// `TcpStream::connect`/`TcpListener::bind` reject it too. The net effect was
/// that every IPv6 destination was silently refused.
fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

/// Splits an address with Go's `net.SplitHostPort` semantics, so a bracketed
/// IPv6 literal yields the bare address (`"[::1]:443"` -> `("::1", 443)`).
fn parse_address(addr: &str) -> Result<(String, u16), HandlerError> {
    let (host, port_str) = crate::permissions::split_host_port(addr)
        .map_err(|_| HandlerError::Proxy(format!("invalid address: {}", addr)))?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| HandlerError::Proxy(format!("invalid port: {}", port_str)))?;
    Ok((host.to_string(), port))
}

fn encode_address(host: &str, port: u16, buf: &mut Vec<u8>) {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        buf.push(ATYP_IPV4);
        buf.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = host.parse::<Ipv6Addr>() {
        buf.push(ATYP_IPV6);
        buf.extend_from_slice(&ip.octets());
    } else {
        buf.push(ATYP_DOMAIN);
        buf.push(host.len() as u8);
        buf.extend_from_slice(host.as_bytes());
    }
    buf.extend_from_slice(&port.to_be_bytes());
}

async fn read_address<S>(conn: &mut S, atyp: u8) -> Result<(String, u16), HandlerError>
where
    S: AsyncRead + Unpin + Send + ?Sized,
{
    let host = match atyp {
        ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            conn.read_exact(&mut addr).await?;
            Ipv4Addr::from(addr).to_string()
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            conn.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            conn.read_exact(&mut domain).await?;
            String::from_utf8_lossy(&domain).to_string()
        }
        ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            conn.read_exact(&mut addr).await?;
            Ipv6Addr::from(addr).to_string()
        }
        _ => return Err(HandlerError::Proxy(format!("unsupported atyp: {}", atyp))),
    };

    let mut port_buf = [0u8; 2];
    conn.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    Ok((host, port))
}

async fn skip_address<S>(conn: &mut S, atyp: u8) -> Result<(), HandlerError>
where
    S: AsyncRead + Unpin + Send + ?Sized,
{
    match atyp {
        ATYP_IPV4 => {
            let mut buf = [0u8; 6]; // 4 + 2
            conn.read_exact(&mut buf).await?;
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            conn.read_exact(&mut len).await?;
            let mut buf = vec![0u8; len[0] as usize + 2];
            conn.read_exact(&mut buf).await?;
        }
        ATYP_IPV6 => {
            let mut buf = [0u8; 18]; // 16 + 2
            conn.read_exact(&mut buf).await?;
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_socks5_handler_connect() {
        // Start a mock target server
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            conn.write_all(b"hello from socks5 target").await.unwrap();
        });

        // Start SOCKS5 proxy
        let handler = Socks5Handler::new(HandlerOptions::default());
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(ProxyConn::from_tcp(conn)).await.ok();
        });

        // Connect as SOCKS5 client
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();

        // Greeting
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00]);

        // CONNECT request
        let ip = target_addr.ip();
        let port = target_addr.port();
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        if let std::net::IpAddr::V4(ip4) = ip {
            req.extend_from_slice(&ip4.octets());
        }
        req.extend_from_slice(&port.to_be_bytes());
        client.write_all(&req).await.unwrap();

        // Read reply
        let mut reply = [0u8; 4];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0], 0x05); // version
        assert_eq!(reply[1], 0x00); // success

        // Skip bound address
        skip_address(&mut client, reply[3]).await.unwrap();

        // Read data from target
        let mut buf = vec![0u8; 4096];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello from socks5 target");
    }

    #[tokio::test]
    async fn test_socks5_handler_with_auth() {
        use std::collections::HashMap;
        use std::sync::Arc;

        let mut kvs = HashMap::new();
        kvs.insert("user".into(), "pass".into());
        let auth = Arc::new(crate::auth::LocalAuthenticator::new(kvs));

        let handler = Socks5Handler::new(HandlerOptions {
            authenticator: Some(auth),
            ..Default::default()
        });

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(ProxyConn::from_tcp(conn)).await.ok();
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();

        // Greeting with user/pass method
        client.write_all(&[0x05, 0x02, 0x00, 0x02]).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[0], 0x05);
        assert_eq!(resp[1], 0x02); // user/pass required

        // Send auth - wrong password
        let auth_req = [
            0x01, 4, b'u', b's', b'e', b'r', 5, b'w', b'r', b'o', b'n', b'g',
        ];
        client.write_all(&auth_req).await.unwrap();
        let mut auth_resp = [0u8; 2];
        client.read_exact(&mut auth_resp).await.unwrap();
        assert_ne!(auth_resp[1], 0x00); // auth failed
    }

    #[test]
    fn test_parse_address() {
        let (host, port) = parse_address("example.com:443").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_encode_address_ipv4() {
        let mut buf = Vec::new();
        encode_address("127.0.0.1", 80, &mut buf);
        assert_eq!(buf[0], ATYP_IPV4);
        assert_eq!(&buf[1..5], &[127, 0, 0, 1]);
        assert_eq!(&buf[5..7], &[0, 80]);
    }

    #[test]
    fn test_encode_address_domain() {
        let mut buf = Vec::new();
        encode_address("example.com", 443, &mut buf);
        assert_eq!(buf[0], ATYP_DOMAIN);
        assert_eq!(buf[1], 11); // "example.com" length
        assert_eq!(&buf[2..13], b"example.com");
    }

    #[test]
    fn test_encode_address_ipv6() {
        let mut buf = Vec::new();
        encode_address("::1", 8080, &mut buf);
        assert_eq!(buf[0], ATYP_IPV6);
        assert_eq!(buf.len(), 1 + 16 + 2); // type + 16 bytes IPv6 + port
    }

    #[test]
    fn test_parse_address_valid() {
        let (h, p) = parse_address("example.com:443").unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 443);
    }

    #[test]
    fn test_parse_address_invalid_no_port() {
        assert!(parse_address("example.com").is_err());
    }

    #[test]
    fn test_parse_address_invalid_port() {
        assert!(parse_address("example.com:notaport").is_err());
    }

    #[tokio::test]
    async fn test_socks5_handler_domain_connect() {
        // Test connecting via domain name (not IP)
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            conn.write_all(b"domain-connect").await.unwrap();
        });

        let handler = Socks5Handler::new(HandlerOptions::default());
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(ProxyConn::from_tcp(conn)).await.ok();
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();

        // Greeting
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00]);

        // CONNECT with domain address type
        let host = "127.0.0.1".to_string();
        let port = target_addr.port();
        let mut req = vec![0x05, 0x01, 0x00, 0x03]; // ver, connect, rsv, domain
        req.push(host.len() as u8);
        req.extend_from_slice(host.as_bytes());
        req.extend_from_slice(&port.to_be_bytes());
        client.write_all(&req).await.unwrap();

        // Read reply
        let mut reply = [0u8; 4];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x00); // success

        skip_address(&mut client, reply[3]).await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"domain-connect");
    }

    #[tokio::test]
    async fn test_socks5_handler_unsupported_command() {
        let handler = Socks5Handler::new(HandlerOptions::default());
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(ProxyConn::from_tcp(conn)).await.ok();
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();

        // Greeting
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();

        // Send a command that genuinely has no implementation (0x09).
        let req = [0x05, 0x09, 0x00, 0x01, 127, 0, 0, 1, 0, 80];
        client.write_all(&req).await.unwrap();

        let mut reply = [0u8; 4];
        let result = client.read_exact(&mut reply).await;
        if result.is_ok() {
            assert_eq!(reply[1], REP_CMD_NOT_SUPPORTED);
        }
    }

    #[tokio::test]
    async fn test_socks5_handler_with_bypass() {
        use std::sync::Arc;

        let bypass = Arc::new(crate::bypass::Bypass::from_patterns(
            false,
            &["blocked.com"],
        ));
        let handler = Socks5Handler::new(HandlerOptions {
            bypass: Some(bypass),
            ..Default::default()
        });

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(ProxyConn::from_tcp(conn)).await.ok();
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();

        // Greeting
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();

        // CONNECT to bypassed domain
        let host = b"blocked.com";
        let mut req = vec![0x05, 0x01, 0x00, 0x03];
        req.push(host.len() as u8);
        req.extend_from_slice(host);
        req.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&req).await.unwrap();

        let mut reply = [0u8; 4];
        let result = client.read_exact(&mut reply).await;
        if result.is_ok() {
            assert_eq!(reply[1], REP_NOT_ALLOWED);
        }
    }

    /// Helper: spawn a one-shot SOCKS5 proxy and return its address.
    async fn spawn_proxy(options: HandlerOptions) -> SocketAddr {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = proxy.local_addr().unwrap();
        tokio::spawn(async move {
            let handler = Socks5Handler::new(options);
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(ProxyConn::from_tcp(conn)).await.ok();
        });
        addr
    }

    async fn greet(client: &mut TcpStream) {
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00]);
    }

    /// Reads a full SOCKS5 reply and returns (rep, host, port).
    async fn read_reply(client: &mut TcpStream) -> (u8, String, u16) {
        let mut head = [0u8; 4];
        client.read_exact(&mut head).await.unwrap();
        assert_eq!(head[0], SOCKS5_VERSION);
        let (host, port) = read_address(client, head[3]).await.unwrap();
        (head[1], host, port)
    }

    // ---- Defect 3: the CONNECT reply must not leak the outbound address ----

    #[tokio::test]
    async fn test_socks5_connect_reply_has_zero_address() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        tokio::spawn(async move {
            let (_c, _) = target.accept().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        let proxy_addr = spawn_proxy(HandlerOptions::default()).await;
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        greet(&mut client).await;

        let mut req = vec![0x05, CMD_CONNECT, 0x00, ATYP_IPV4];
        match target_addr.ip() {
            std::net::IpAddr::V4(v) => req.extend_from_slice(&v.octets()),
            _ => panic!("expected v4"),
        }
        req.extend_from_slice(&target_addr.port().to_be_bytes());
        client.write_all(&req).await.unwrap();

        // Whole reply must be VER,SUCCESS,RSV,ATYP=IPv4,0.0.0.0,0
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(
            reply,
            [0x05, REP_SUCCESS, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0],
            "CONNECT reply must carry an all-zero bound address (gost parity)"
        );
    }

    // ---- Defect 1: UDP ASSOCIATE must bind a real relay socket ----

    #[tokio::test]
    async fn test_socks5_udp_associate_roundtrip() {
        // Local UDP echo server.
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let (n, from) = match echo.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let mut out = b"echo:".to_vec();
                out.extend_from_slice(&buf[..n]);
                echo.send_to(&out, from).await.ok();
            }
        });

        let proxy_addr = spawn_proxy(HandlerOptions::default()).await;
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        greet(&mut client).await;

        // UDP ASSOCIATE with the conventional 0.0.0.0:0 client address.
        let req = [0x05, CMD_UDP_ASSOCIATE, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
        client.write_all(&req).await.unwrap();

        let (rep, host, port) = read_reply(&mut client).await;
        assert_eq!(rep, REP_SUCCESS);
        assert_ne!(port, 0, "the relay endpoint must be a real bound UDP port");
        let relay_addr: SocketAddr = format!("{}:{}", host, port).parse().unwrap();
        assert_ne!(
            relay_addr.port(),
            proxy_addr.port(),
            "the relay must not advertise the TCP listener's port"
        );

        // Send a SOCKS5-framed datagram destined for the echo server.
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut dgram = vec![0x00, 0x00, 0x00, ATYP_IPV4];
        match echo_addr.ip() {
            std::net::IpAddr::V4(v) => dgram.extend_from_slice(&v.octets()),
            _ => panic!("expected v4"),
        }
        dgram.extend_from_slice(&echo_addr.port().to_be_bytes());
        dgram.extend_from_slice(b"ping");
        udp.send_to(&dgram, relay_addr).await.unwrap();

        let mut buf = vec![0u8; 2048];
        let (n, from) =
            tokio::time::timeout(std::time::Duration::from_secs(5), udp.recv_from(&mut buf))
                .await
                .expect("timed out waiting for the relayed UDP reply")
                .unwrap();
        assert_eq!(from, relay_addr);

        let (frag, rhost, rport, off) = parse_udp_datagram(&buf[..n]).unwrap();
        assert_eq!(frag, 0);
        assert_eq!(rhost, echo_addr.ip().to_string());
        assert_eq!(rport, echo_addr.port());
        assert_eq!(&buf[off..n], b"echo:ping");
    }

    #[tokio::test]
    async fn test_socks5_udp_associate_drops_fragments() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let (n, from) = match echo.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                echo.send_to(&buf[..n], from).await.ok();
            }
        });

        let proxy_addr = spawn_proxy(HandlerOptions::default()).await;
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        greet(&mut client).await;
        client
            .write_all(&[0x05, CMD_UDP_ASSOCIATE, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let (rep, host, port) = read_reply(&mut client).await;
        assert_eq!(rep, REP_SUCCESS);
        let relay_addr: SocketAddr = format!("{}:{}", host, port).parse().unwrap();

        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut dgram = vec![0x00, 0x00, 0x01, ATYP_IPV4]; // FRAG = 1
        match echo_addr.ip() {
            std::net::IpAddr::V4(v) => dgram.extend_from_slice(&v.octets()),
            _ => panic!("expected v4"),
        }
        dgram.extend_from_slice(&echo_addr.port().to_be_bytes());
        dgram.extend_from_slice(b"frag");
        udp.send_to(&dgram, relay_addr).await.unwrap();

        let mut buf = vec![0u8; 2048];
        let r = tokio::time::timeout(
            std::time::Duration::from_millis(400),
            udp.recv_from(&mut buf),
        )
        .await;
        assert!(
            r.is_err(),
            "fragmented datagrams must be dropped, not relayed"
        );
    }

    #[tokio::test]
    async fn test_socks5_udp_associate_dies_with_control_conn() {
        let proxy_addr = spawn_proxy(HandlerOptions::default()).await;
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        greet(&mut client).await;
        client
            .write_all(&[0x05, CMD_UDP_ASSOCIATE, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let (rep, host, port) = read_reply(&mut client).await;
        assert_eq!(rep, REP_SUCCESS);
        let relay_addr: SocketAddr = format!("{}:{}", host, port).parse().unwrap();

        // Tear down the control connection: the association must go with it.
        drop(client);
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        // The relay port should now be free again; if the socket had leaked
        // this bind would fail with AddrInUse.
        let rebound = UdpSocket::bind(relay_addr).await;
        assert!(
            rebound.is_ok(),
            "the UDP relay socket must be closed when the TCP control connection closes"
        );
    }

    #[tokio::test]
    async fn test_socks5_udp_associate_blocked_by_blacklist() {
        let bl = crate::permissions::Permissions::parse("udp:*:*").unwrap();
        let proxy_addr = spawn_proxy(HandlerOptions {
            blacklist: Some(bl),
            ..Default::default()
        })
        .await;

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        greet(&mut client).await;
        client
            .write_all(&[0x05, CMD_UDP_ASSOCIATE, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let (rep, _, _) = read_reply(&mut client).await;
        assert_eq!(rep, REP_NOT_ALLOWED);
    }

    // ---- Defect 2: SOCKS5 BIND ----

    #[tokio::test]
    async fn test_socks5_bind_roundtrip() {
        let proxy_addr = spawn_proxy(HandlerOptions::default()).await;
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        greet(&mut client).await;

        // BIND on an ephemeral loopback port.
        let req = [0x05, CMD_BIND, 0x00, ATYP_IPV4, 127, 0, 0, 1, 0, 0];
        client.write_all(&req).await.unwrap();

        // First reply: the bound address.
        let (rep, host, port) = read_reply(&mut client).await;
        assert_eq!(rep, REP_SUCCESS);
        assert_ne!(
            port, 0,
            "the first BIND reply must carry the real bound port"
        );
        let bound: SocketAddr = format!("{}:{}", host, port).parse().unwrap();

        // A peer connects to the bound address.
        let mut peer = TcpStream::connect(bound).await.unwrap();
        let peer_local = peer.local_addr().unwrap();

        // Second reply: the peer's address.
        let (rep2, phost, pport) = read_reply(&mut client).await;
        assert_eq!(rep2, REP_SUCCESS);
        assert_eq!(phost, peer_local.ip().to_string());
        assert_eq!(pport, peer_local.port());

        // Now the two are spliced, both directions.
        peer.write_all(b"peer->client").await.unwrap();
        let mut buf = vec![0u8; 64];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"peer->client");

        client.write_all(b"client->peer").await.unwrap();
        let n = peer.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"client->peer");
    }

    #[tokio::test]
    async fn test_socks5_bind_denied_by_blacklist() {
        let bl = crate::permissions::Permissions::parse("rtcp:*:*").unwrap();
        let proxy_addr = spawn_proxy(HandlerOptions {
            blacklist: Some(bl),
            ..Default::default()
        })
        .await;

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        greet(&mut client).await;
        client
            .write_all(&[0x05, CMD_BIND, 0x00, ATYP_IPV4, 127, 0, 0, 1, 0, 0])
            .await
            .unwrap();
        let (rep, _, _) = read_reply(&mut client).await;
        assert_eq!(rep, REP_NOT_ALLOWED);
    }

    // ---- per-datagram access control on the UDP relay ----

    /// Spawns a UDP echo server that prefixes replies with "echo:".
    fn spawn_udp_echo(sock: UdpSocket) {
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let (n, from) = match sock.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let mut out = b"echo:".to_vec();
                out.extend_from_slice(&buf[..n]);
                sock.send_to(&out, from).await.ok();
            }
        });
    }

    /// Opens a UDP association and returns (control conn, relay address).
    async fn associate(proxy_addr: SocketAddr) -> (TcpStream, SocketAddr) {
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        greet(&mut client).await;
        client
            .write_all(&[0x05, CMD_UDP_ASSOCIATE, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let (rep, host, port) = read_reply(&mut client).await;
        assert_eq!(rep, REP_SUCCESS);
        (client, format!("{}:{}", host, port).parse().unwrap())
    }

    /// Builds a SOCKS5 UDP datagram for an IPv4 destination.
    fn v4_datagram(dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
        let mut d = vec![0x00, 0x00, 0x00, ATYP_IPV4];
        match dst.ip() {
            std::net::IpAddr::V4(v) => d.extend_from_slice(&v.octets()),
            _ => panic!("expected v4"),
        }
        d.extend_from_slice(&dst.port().to_be_bytes());
        d.extend_from_slice(payload);
        d
    }

    #[tokio::test]
    async fn test_socks5_udp_datagram_blocked_by_bypass() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        spawn_udp_echo(echo);

        // The ASSOCIATE request itself (0.0.0.0:0) is not covered by the rule,
        // so the association is granted and only the datagram is filtered.
        let bypass =
            std::sync::Arc::new(crate::bypass::Bypass::from_patterns(false, &["127.0.0.1"]));
        let proxy_addr = spawn_proxy(HandlerOptions {
            bypass: Some(bypass),
            ..Default::default()
        })
        .await;

        let (_ctl, relay_addr) = associate(proxy_addr).await;
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp.send_to(&v4_datagram(echo_addr, b"ping"), relay_addr)
            .await
            .unwrap();

        let mut buf = vec![0u8; 2048];
        let r = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            udp.recv_from(&mut buf),
        )
        .await;
        assert!(
            r.is_err(),
            "the bypass must be applied per datagram, not just at ASSOCIATE time"
        );
    }

    #[tokio::test]
    async fn test_socks5_udp_datagram_blocked_by_blacklist() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        spawn_udp_echo(echo);

        // "udp:127.0.0.1:*" does not cover the 0.0.0.0:0 ASSOCIATE address, so
        // the association succeeds and only the datagram is denied.
        let bl = crate::permissions::Permissions::parse("udp:127.0.0.1:*").unwrap();
        let proxy_addr = spawn_proxy(HandlerOptions {
            blacklist: Some(bl),
            ..Default::default()
        })
        .await;

        let (_ctl, relay_addr) = associate(proxy_addr).await;
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp.send_to(&v4_datagram(echo_addr, b"ping"), relay_addr)
            .await
            .unwrap();

        let mut buf = vec![0u8; 2048];
        let r = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            udp.recv_from(&mut buf),
        )
        .await;
        assert!(r.is_err(), "Can(\"udp\", ...) must be applied per datagram");
    }

    #[tokio::test]
    async fn test_socks5_udp_domain_is_filtered_after_resolution() {
        // A datagram may name a DOMAIN while the rule names an IP; gost checks
        // the resolved address (socks.go:1263). Resolve first so the test works
        // whichever family "localhost" maps to on this host.
        let resolved = match resolve_udp_addr("localhost", 0).await {
            Some(a) => a,
            None => return, // no name resolution available; nothing to assert
        };
        // The relay's outbound `peer` socket follows the control connection's
        // family, so an IPv6-only "localhost" cannot be reached from an IPv4
        // control connection. Skip rather than fail spuriously.
        if !resolved.ip().is_ipv4() {
            return;
        }
        let echo = UdpSocket::bind(SocketAddr::new(resolved.ip(), 0))
            .await
            .unwrap();
        let echo_addr = echo.local_addr().unwrap();
        spawn_udp_echo(echo);

        let mut dgram = vec![0x00, 0x00, 0x00, ATYP_DOMAIN, 9];
        dgram.extend_from_slice(b"localhost");
        dgram.extend_from_slice(&echo_addr.port().to_be_bytes());
        dgram.extend_from_slice(b"ping");

        // Positive control: without any rule the datagram is relayed, which
        // proves the domain really resolves to the echo server.
        let open_proxy = spawn_proxy(HandlerOptions::default()).await;
        let (_ctl, relay_addr) = associate(open_proxy).await;
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp.send_to(&dgram, relay_addr).await.unwrap();
        let mut buf = vec![0u8; 2048];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), udp.recv_from(&mut buf))
            .await
            .expect("control: the datagram addressed by domain must be relayed")
            .unwrap()
            .0;
        let (_, _, _, off) = parse_udp_datagram(&buf[..n]).unwrap();
        assert_eq!(&buf[off..n], b"echo:ping");

        // Now the same datagram against a bypass naming only the resolved IP.
        // Checking the literal "localhost:port" would never match it.
        let bypass = std::sync::Arc::new(crate::bypass::Bypass::from_patterns(
            false,
            &[resolved.ip().to_string().as_str()],
        ));
        let proxy_addr = spawn_proxy(HandlerOptions {
            bypass: Some(bypass),
            ..Default::default()
        })
        .await;
        let (_ctl2, relay2) = associate(proxy_addr).await;
        let udp2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp2.send_to(&dgram, relay2).await.unwrap();
        let r = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            udp2.recv_from(&mut buf),
        )
        .await;
        assert!(
            r.is_err(),
            "a domain destination must be re-checked against its resolved address"
        );
    }

    // ---- IPv6 destinations must survive the fail-closed Can() ----

    #[test]
    fn test_join_host_port_brackets_ipv6() {
        assert_eq!(join_host_port("1.2.3.4", 80), "1.2.3.4:80");
        assert_eq!(join_host_port("example.com", 80), "example.com:80");
        assert_eq!(join_host_port("::1", 443), "[::1]:443");
        assert_eq!(join_host_port("2001:db8::1", 53), "[2001:db8::1]:53");

        // Can() fails closed on a malformed address, so an unbracketed IPv6
        // target would deny every v6 destination even with no lists set.
        assert!(!Can("tcp", "::1:443", None, None));
        assert!(Can("tcp", &join_host_port("::1", 443), None, None));
    }

    #[test]
    fn test_parse_address_strips_ipv6_brackets() {
        let (h, p) = parse_address("[::1]:443").unwrap();
        assert_eq!(h, "::1");
        assert_eq!(p, 443);
        // ...and the bare form round-trips through encode_address as IPv6.
        let mut buf = Vec::new();
        encode_address(&h, p, &mut buf);
        assert_eq!(buf[0], ATYP_IPV6);
    }

    #[tokio::test]
    async fn test_socks5_connect_to_ipv6_literal() {
        // Skip on hosts without IPv6 loopback.
        let target = match TcpListener::bind("[::1]:0").await {
            Ok(l) => l,
            Err(_) => return,
        };
        let target_addr = target.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            conn.write_all(b"v6-ok").await.unwrap();
        });

        let proxy_addr = spawn_proxy(HandlerOptions::default()).await;
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        greet(&mut client).await;

        let mut req = vec![0x05, CMD_CONNECT, 0x00, ATYP_IPV6];
        match target_addr.ip() {
            std::net::IpAddr::V6(v) => req.extend_from_slice(&v.octets()),
            _ => panic!("expected v6"),
        }
        req.extend_from_slice(&target_addr.port().to_be_bytes());
        client.write_all(&req).await.unwrap();

        let (rep, _, _) = read_reply(&mut client).await;
        assert_eq!(
            rep, REP_SUCCESS,
            "an IPv6 literal target must not be denied by Can()"
        );

        let mut buf = vec![0u8; 64];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"v6-ok");
    }

    // ---- Defect 5: retries ----

    #[tokio::test]
    async fn test_socks5_connect_retries_then_fails() {
        // Port 1 on loopback is not listening; with retries=3 we should still
        // get a clean HostUnreachable reply rather than hanging.
        let proxy_addr = spawn_proxy(HandlerOptions {
            retries: 3,
            timeout: std::time::Duration::from_millis(100),
            ..Default::default()
        })
        .await;

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        greet(&mut client).await;
        client
            .write_all(&[0x05, CMD_CONNECT, 0x00, ATYP_IPV4, 127, 0, 0, 1, 0, 1])
            .await
            .unwrap();
        let (rep, _, _) = read_reply(&mut client).await;
        assert_eq!(rep, REP_HOST_UNREACHABLE);
    }

    #[test]
    fn test_socks5_dial_setup_retry_precedence() {
        use crate::chain::Chain;
        use crate::node::Node;

        let node = || Node {
            addr: "127.0.0.1:1".into(),
            protocol: "socks5".into(),
            ..Default::default()
        };

        // Neither set -> a single attempt.
        let (_, r, _) = Socks5Handler::new(HandlerOptions {
            chain: Some(Chain::new(vec![node()])),
            ..Default::default()
        })
        .dial_setup();
        assert_eq!(r, 1);

        // Chain only.
        let mut chain = Chain::new(vec![node()]);
        chain.retries = 5;
        let (c, r, _) = Socks5Handler::new(HandlerOptions {
            chain: Some(chain),
            ..Default::default()
        })
        .dial_setup();
        assert_eq!(
            r, 5,
            "the chain's Retries must be used when the handler's is 0"
        );
        assert_eq!(c.retries, 1, "the inner chain loop must not retry as well");

        // Handler wins over chain (gost socks.go:915-921).
        let mut chain = Chain::new(vec![node()]);
        chain.retries = 5;
        let (_, r, o) = Socks5Handler::new(HandlerOptions {
            chain: Some(chain),
            retries: 3,
            timeout: Duration::from_millis(250),
            ..Default::default()
        })
        .dial_setup();
        assert_eq!(r, 3);
        assert_eq!(o.retries, 1);
        assert_eq!(o.timeout, Duration::from_millis(250));
    }

    #[tokio::test]
    async fn test_socks5_dial_target_actually_retries() {
        use crate::chain::Chain;
        use crate::node::Node;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        // A chain node that accepts and immediately hangs up, so every dial
        // attempt fails during the handshake and opens a fresh connection.
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let node_addr = ln.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        tokio::spawn(async move {
            while let Ok((conn, _)) = ln.accept().await {
                h.fetch_add(1, Ordering::SeqCst);
                drop(conn);
            }
        });

        let chain = Chain::new(vec![Node {
            addr: node_addr.to_string(),
            protocol: "socks5".into(),
            ..Default::default()
        }]);
        let handler = Socks5Handler::new(HandlerOptions {
            chain: Some(chain),
            retries: 3,
            timeout: Duration::from_millis(300),
            ..Default::default()
        });

        assert!(handler.dial_target("example.com:80").await.is_err());
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            hits.load(Ordering::SeqCst),
            3,
            "options.retries must drive the dial loop on the live path"
        );
    }

    #[test]
    fn test_socks5_dial_setup_keeps_chain_hosts() {
        use crate::chain::Chain;
        use crate::hosts::Hosts;

        // gost passes HostsChainOption/ResolverChainOption alongside the
        // timeout; building ChainOptions from scratch silently dropped `?hosts=`
        // and `?dns=` for the SOCKS handlers.
        let mut chain = Chain::empty();
        chain.hosts = Some(Hosts::new(vec![]));
        let (_, _, opts) = Socks5Handler::new(HandlerOptions {
            chain: Some(chain),
            ..Default::default()
        })
        .dial_setup();
        assert!(
            opts.hosts.is_some(),
            "the chain's hosts table must reach the dial options"
        );
    }

    // ---- UDP datagram codec ----

    #[test]
    fn test_udp_datagram_codec_roundtrip() {
        let addr: SocketAddr = "1.2.3.4:5678".parse().unwrap();
        let enc = encode_udp_datagram(&addr, b"payload");
        let (frag, host, port, off) = parse_udp_datagram(&enc).unwrap();
        assert_eq!(frag, 0);
        assert_eq!(host, "1.2.3.4");
        assert_eq!(port, 5678);
        assert_eq!(&enc[off..], b"payload");
    }

    #[test]
    fn test_udp_datagram_codec_ipv6() {
        let addr: SocketAddr = "[::1]:9".parse().unwrap();
        let enc = encode_udp_datagram(&addr, b"x");
        assert_eq!(enc[3], ATYP_IPV6);
        let (_, host, port, off) = parse_udp_datagram(&enc).unwrap();
        assert_eq!(host, "::1");
        assert_eq!(port, 9);
        assert_eq!(&enc[off..], b"x");
    }

    #[test]
    fn test_parse_udp_datagram_domain() {
        let mut b = vec![0x00, 0x00, 0x00, ATYP_DOMAIN, 11];
        b.extend_from_slice(b"example.com");
        b.extend_from_slice(&443u16.to_be_bytes());
        b.extend_from_slice(b"data");
        let (frag, host, port, off) = parse_udp_datagram(&b).unwrap();
        assert_eq!(frag, 0);
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(&b[off..], b"data");
    }

    #[test]
    fn test_parse_udp_datagram_truncated() {
        assert!(parse_udp_datagram(&[]).is_none());
        assert!(parse_udp_datagram(&[0, 0, 0, ATYP_IPV4, 1]).is_none());
        assert!(parse_udp_datagram(&[0, 0, 0, 0x77, 1, 2, 3, 4, 0, 80]).is_none());
        // Domain with a zero length is malformed.
        assert!(parse_udp_datagram(&[0, 0, 0, ATYP_DOMAIN, 0, 0, 80]).is_none());
    }

    // ---- UDP over TCP tunnel (gost CmdUDPTun, 0xF3) ----
    //
    // The framing assertions below are written against hardcoded bytes taken
    // from the gost/gosocks5 sources rather than round-tripped through this
    // module's own encoder, because a codec that is wrong in every field still
    // round-trips against itself perfectly.

    #[test]
    fn test_udp_tunnel_frame_bytes_ipv4() {
        // RSV(2, big-endian) = len(DATA) | FRAG | ATYP | ADDR | PORT | DATA.
        // gosocks5 v0.3.0 socks5.go:633-647 (UDPHeader.Write) and 726-741
        // (UDPDatagram.Write); gost socks.go:1478-1479 and 1968 set
        // Rsv = uint16(len(data)).
        assert_eq!(
            encode_udp_tunnel_datagram("1.2.3.4", 5678, b"hello"),
            vec![
                0x00, 0x05, // RSV = 5 = len("hello"), big-endian
                0x00, // FRAG
                0x01, // ATYP = IPv4
                1, 2, 3, 4, // DST.ADDR
                0x16, 0x2E, // DST.PORT = 5678
                b'h', b'e', b'l', b'l', b'o',
            ]
        );
    }

    #[test]
    fn test_udp_tunnel_frame_length_is_big_endian_and_covers_data_only() {
        let frame = encode_udp_tunnel_datagram("example.com", 53, &[0xAB; 300]);
        // 300 = 0x012C. Big-endian puts 0x01 first; little-endian would emit
        // 0x2C 0x01 and desync a real gost peer on the very first datagram.
        assert_eq!(&frame[..2], &[0x01, 0x2C]);
        // The length counts DATA only. The 18-byte header (2+1+1+1+11+2) is
        // not included, so the frame is header + 300.
        assert_eq!(frame.len(), 18 + 300);
        assert_eq!(&frame[2..5], &[0x00, ATYP_DOMAIN, 11]);
        assert_eq!(&frame[5..16], b"example.com");
        assert_eq!(&frame[16..18], &[0x00, 0x35]);
        assert!(frame[18..].iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn test_udp_tunnel_frame_bytes_ipv6() {
        let mut want = vec![0x00, 0x01, 0x00, 0x04];
        want.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        want.extend_from_slice(&[0x00, 0x09, b'x']);
        assert_eq!(encode_udp_tunnel_datagram("::1", 9, b"x"), want);
    }

    /// Bounds a read so that a framing regression shows up as a failure
    /// rather than a hung test: a decoder that misreads the length simply
    /// waits forever for bytes that will never come.
    async fn soon<F: std::future::Future>(f: F) -> F::Output {
        tokio::time::timeout(Duration::from_secs(5), f)
            .await
            .expect("timed out: the UDP tunnel framing stalled the stream")
    }

    #[tokio::test]
    async fn test_udp_tunnel_decodes_hardcoded_gost_frames() {
        // Three frames written by hand in gost's wire format, back to back.
        let mut wire: Vec<u8> = vec![
            0x00, 0x04, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x35, b'p', b'i', b'n', b'g',
        ];
        wire.extend_from_slice(&[0x00, 0x02, 0x00, 0x03, 11]);
        wire.extend_from_slice(b"example.com");
        wire.extend_from_slice(&[0x01, 0xBB, b'o', b'k']);
        wire.extend_from_slice(&[0x00, 0x01, 0x00, 0x04]);
        wire.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        wire.extend_from_slice(&[0x1F, 0x90, b'z']);

        let (mut a, b) = tokio::io::duplex(4096);
        a.write_all(&wire).await.unwrap();
        let mut conn = Socks5UdpTunnelConn::server(b);

        let (d, h, p) = soon(conn.recv_from()).await.unwrap().unwrap();
        assert_eq!(
            (d.as_slice(), h.as_str(), p),
            (&b"ping"[..], "127.0.0.1", 53)
        );
        let (d, h, p) = soon(conn.recv_from()).await.unwrap().unwrap();
        assert_eq!(
            (d.as_slice(), h.as_str(), p),
            (&b"ok"[..], "example.com", 443)
        );
        let (d, h, p) = soon(conn.recv_from()).await.unwrap().unwrap();
        assert_eq!((d.as_slice(), h.as_str(), p), (&b"z"[..], "::1", 8080));
    }

    #[tokio::test]
    async fn test_udp_tunnel_length_is_big_endian_on_read() {
        // RSV = 0x0102. Read big-endian that is 258 bytes; read little-endian
        // it would be 513, and the trailing frame would never parse.
        let mut wire: Vec<u8> = vec![0x01, 0x02, 0x00, ATYP_IPV4, 127, 0, 0, 1, 0x00, 0x35];
        wire.extend_from_slice(&[0xAA; 258]);
        wire.extend_from_slice(&[
            0x00, 0x02, 0x00, ATYP_IPV4, 8, 8, 8, 8, 0x00, 0x35, b'o', b'k',
        ]);

        let (mut a, b) = tokio::io::duplex(4096);
        a.write_all(&wire).await.unwrap();
        let mut conn = Socks5UdpTunnelConn::server(b);

        let (d, _, _) = soon(conn.recv_from()).await.unwrap().unwrap();
        assert_eq!(d.len(), 258);
        assert!(d.iter().all(|&x| x == 0xAA));
        let (d, h, _) = soon(conn.recv_from()).await.unwrap().unwrap();
        assert_eq!(d, b"ok");
        assert_eq!(h, "8.8.8.8");
    }

    #[tokio::test]
    async fn test_udp_tunnel_preserves_boundaries_across_tcp_reads() {
        // Two hand-built frames, dribbled out seven bytes at a time so that
        // every header and every payload straddles several reads.
        let payload: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let mut wire: Vec<u8> = vec![0x03, 0xE8, 0x00, ATYP_IPV4, 1, 2, 3, 4, 0x27, 0x0F];
        wire.extend_from_slice(&payload);
        wire.extend_from_slice(&[0x00, 0x04, 0x00, ATYP_DOMAIN, 11]);
        wire.extend_from_slice(b"example.com");
        wire.extend_from_slice(&[0x00, 0x35, b't', b'a', b'i', b'l']);

        let (mut a, b) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            for chunk in wire.chunks(7) {
                a.write_all(chunk).await.unwrap();
                a.flush().await.unwrap();
                tokio::task::yield_now().await;
            }
        });

        let mut conn = Socks5UdpTunnelConn::server(b);
        let (d, h, p) = soon(conn.recv_from()).await.unwrap().unwrap();
        assert_eq!(
            d, payload,
            "a datagram split over many reads must arrive whole"
        );
        assert_eq!((h.as_str(), p), ("1.2.3.4", 9999));

        let (d, h, p) = soon(conn.recv_from()).await.unwrap().unwrap();
        assert_eq!(
            d, b"tail",
            "the next datagram must not absorb the previous one"
        );
        assert_eq!((h.as_str(), p), ("example.com", 53));
    }

    #[tokio::test]
    async fn test_udp_tunnel_async_read_never_coalesces_datagrams() {
        // The byte-stream view still delivers one datagram per read.
        let mut wire: Vec<u8> = vec![0x00, 0x03, 0x00, ATYP_IPV4, 1, 2, 3, 4, 0x00, 0x35];
        wire.extend_from_slice(b"aaa");
        wire.extend_from_slice(&[0x00, 0x03, 0x00, ATYP_IPV4, 1, 2, 3, 4, 0x00, 0x35]);
        wire.extend_from_slice(b"bbb");

        let (mut a, b) = tokio::io::duplex(4096);
        a.write_all(&wire).await.unwrap();
        let mut conn = Socks5UdpTunnelConn::server(b);

        let mut buf = [0u8; 64];
        let n = soon(conn.read(&mut buf)).await.unwrap();
        assert_eq!(&buf[..n], b"aaa");
        let n = soon(conn.read(&mut buf)).await.unwrap();
        assert_eq!(&buf[..n], b"bbb");
    }

    #[tokio::test]
    async fn test_udp_tunnel_async_write_stamps_the_fixed_destination() {
        // gost's socks5UDPTunnelConn.Write forwards to WriteTo(b, c.taddr)
        // (socks.go:1963-1965).
        let (mut a, b) = tokio::io::duplex(256);
        let mut conn =
            Socks5UdpTunnelConn::client(b, ("1.2.3.4".to_string(), 53), "0.0.0.0:0".to_string());
        conn.write_all(b"hi").await.unwrap();
        conn.flush().await.unwrap();

        let mut got = [0u8; 12];
        soon(a.read_exact(&mut got)).await.unwrap();
        assert_eq!(
            got,
            [0x00, 0x02, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x35, b'h', b'i']
        );
    }

    // ---- malformed / truncated frames must be rejected, not mis-parsed ----

    #[tokio::test]
    async fn test_udp_tunnel_rejects_bad_address_type() {
        let (mut a, b) = tokio::io::duplex(64);
        a.write_all(&[0x00, 0x04, 0x00, 0x77, 1, 2, 3, 4, 0x00, 0x50])
            .await
            .unwrap();
        let mut conn = Socks5UdpTunnelConn::server(b);
        let err = soon(conn.recv_from()).await.unwrap_err();
        assert!(
            err.to_string().contains("bad address type"),
            "unexpected error: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_udp_tunnel_rejects_truncated_frame() {
        // RSV promises 8 payload bytes; only 3 arrive before the close.
        let (mut a, b) = tokio::io::duplex(64);
        a.write_all(&[
            0x00, 0x08, 0x00, ATYP_IPV4, 127, 0, 0, 1, 0x00, 0x35, b'a', b'b', b'c',
        ])
        .await
        .unwrap();
        drop(a);

        let mut conn = Socks5UdpTunnelConn::server(b);
        let err = soon(conn.recv_from()).await.unwrap_err();
        assert_eq!(
            err.kind(),
            io::ErrorKind::UnexpectedEof,
            "a short frame must be an error, not a short datagram: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_udp_tunnel_rejects_truncated_header() {
        // Two bytes of a five-byte prefix, then the peer goes away.
        let (mut a, b) = tokio::io::duplex(64);
        a.write_all(&[0x00, 0x04]).await.unwrap();
        drop(a);

        let mut conn = Socks5UdpTunnelConn::server(b);
        let err = soon(conn.recv_from()).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn test_udp_tunnel_rejects_empty_domain_name() {
        let (mut a, b) = tokio::io::duplex(64);
        a.write_all(&[0x00, 0x01, 0x00, ATYP_DOMAIN, 0x00, 0x00, 0x35, b'x'])
            .await
            .unwrap();
        let mut conn = Socks5UdpTunnelConn::server(b);
        let err = soon(conn.recv_from()).await.unwrap_err();
        assert!(
            err.to_string().contains("malformed address"),
            "unexpected error: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_udp_tunnel_clean_eof_on_a_frame_boundary() {
        let (a, b) = tokio::io::duplex(64);
        drop(a);
        let mut conn = Socks5UdpTunnelConn::server(b);
        assert!(soon(conn.recv_from()).await.unwrap().is_none());
    }

    // ---- the client half speaks gost's request on the wire ----

    #[tokio::test]
    async fn test_socks5_udp_tunnel_client_sends_gost_request_bytes() {
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut s, _) = ln.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            s.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            s.write_all(&[0x05, 0x00]).await.unwrap();

            let mut req = [0u8; 10];
            s.read_exact(&mut req).await.unwrap();
            // VER | CmdUDPTun(0xF3) | RSV | ATYP | 127.0.0.1 | 8080
            assert_eq!(req, [0x05, 0xF3, 0x00, 0x01, 127, 0, 0, 1, 0x1F, 0x90]);

            s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x22, 0xB8])
                .await
                .unwrap();
            s
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let conn = Socks5Connector::new(None)
            .udp_tunnel(stream, "127.0.0.1:8080", Some("1.2.3.4:53"))
            .await
            .unwrap();
        assert_eq!(conn.bound_addr(), Some("127.0.0.1:8888"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_socks5_udp_tunnel_client_surfaces_a_refusal() {
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = ln.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            s.read_exact(&mut greeting).await.unwrap();
            s.write_all(&[0x05, 0x00]).await.unwrap();
            let mut req = [0u8; 10];
            s.read_exact(&mut req).await.unwrap();
            s.write_all(&[0x05, REP_NOT_ALLOWED, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        assert!(Socks5Connector::new(None)
            .udp_tunnel(stream, "0.0.0.0:0", None)
            .await
            .is_err());
    }

    // ---- end to end through the handler ----

    /// Reads one tunnel frame straight off the socket, deliberately without
    /// using this module's decoder, so the assertion cannot pass by agreeing
    /// with the encoder under test.
    async fn read_tunnel_frame(s: &mut TcpStream) -> (Vec<u8>, String, u16) {
        let mut head = [0u8; 4];
        s.read_exact(&mut head).await.unwrap();
        let dlen = u16::from_be_bytes([head[0], head[1]]) as usize;
        assert_eq!(head[2], 0x00, "FRAG must be 0");

        let host = match head[3] {
            ATYP_IPV4 => {
                let mut a = [0u8; 4];
                s.read_exact(&mut a).await.unwrap();
                Ipv4Addr::from(a).to_string()
            }
            ATYP_IPV6 => {
                let mut a = [0u8; 16];
                s.read_exact(&mut a).await.unwrap();
                Ipv6Addr::from(a).to_string()
            }
            ATYP_DOMAIN => {
                let mut l = [0u8; 1];
                s.read_exact(&mut l).await.unwrap();
                let mut d = vec![0u8; l[0] as usize];
                s.read_exact(&mut d).await.unwrap();
                String::from_utf8(d).unwrap()
            }
            other => panic!("bad ATYP on the wire: {}", other),
        };

        let mut port = [0u8; 2];
        s.read_exact(&mut port).await.unwrap();
        // Exactly `dlen` bytes: if RSV covered the header too, or were
        // little-endian, this would block or over-read.
        let mut data = vec![0u8; dlen];
        s.read_exact(&mut data).await.unwrap();
        (data, host, u16::from_be_bytes(port))
    }

    /// Opens a UDP tunnel with hand-written bytes and returns (conn, reply).
    async fn open_raw_tunnel(proxy_addr: SocketAddr) -> (TcpStream, String, u16) {
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        greet(&mut client).await;
        client
            .write_all(&[0x05, CMD_UDP_TUN, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let (rep, host, port) = read_reply(&mut client).await;
        assert_eq!(rep, REP_SUCCESS);
        (client, host, port)
    }

    #[tokio::test]
    async fn test_socks5_udp_tunnel_end_to_end() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        spawn_udp_echo(echo);

        let proxy_addr = spawn_proxy(HandlerOptions::default()).await;
        let (mut client, host, port) = open_raw_tunnel(proxy_addr).await;

        // gost advertises the UDP socket's port under the control connection's
        // local IP (socks.go:1414-1415).
        assert_eq!(host, "127.0.0.1");
        assert_ne!(port, 0, "the tunnel must bind a real UDP port");
        assert_ne!(port, proxy_addr.port());

        let mut frame: Vec<u8> = vec![0x00, 0x04, 0x00, ATYP_IPV4];
        match echo_addr.ip() {
            IpAddr::V4(v) => frame.extend_from_slice(&v.octets()),
            _ => panic!("expected v4"),
        }
        frame.extend_from_slice(&echo_addr.port().to_be_bytes());
        frame.extend_from_slice(b"ping");
        client.write_all(&frame).await.unwrap();

        let (data, rhost, rport) =
            tokio::time::timeout(Duration::from_secs(5), read_tunnel_frame(&mut client))
                .await
                .expect("timed out waiting for the tunnelled reply");
        assert_eq!(data, b"echo:ping");
        assert_eq!(rhost, echo_addr.ip().to_string());
        assert_eq!(rport, echo_addr.port());
    }

    #[tokio::test]
    async fn test_socks5_udp_tunnel_end_to_end_via_connector() {
        // Same exchange, but with this crate's own client half driving it, so
        // the connector's handshake is exercised against the real handler.
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        spawn_udp_echo(echo);

        let proxy_addr = spawn_proxy(HandlerOptions::default()).await;
        let stream = TcpStream::connect(proxy_addr).await.unwrap();
        let mut tunnel = Socks5Connector::new(None)
            .udp_tunnel(stream, "0.0.0.0:0", None)
            .await
            .unwrap();

        tunnel
            .send_to(b"ping", &echo_addr.ip().to_string(), echo_addr.port())
            .await
            .unwrap();

        let (data, host, port) = tokio::time::timeout(Duration::from_secs(5), tunnel.recv_from())
            .await
            .expect("timed out waiting for the tunnelled reply")
            .unwrap()
            .unwrap();
        assert_eq!(data, b"echo:ping");
        assert_eq!(host, echo_addr.ip().to_string());
        assert_eq!(port, echo_addr.port());
    }

    #[tokio::test]
    async fn test_socks5_udp_tunnel_two_datagrams_in_one_write() {
        // Both frames land in a single TCP segment; the server must split them.
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        spawn_udp_echo(echo);

        let proxy_addr = spawn_proxy(HandlerOptions::default()).await;
        let (mut client, _, _) = open_raw_tunnel(proxy_addr).await;

        let ip = match echo_addr.ip() {
            IpAddr::V4(v) => v.octets(),
            _ => panic!("expected v4"),
        };
        let mut wire = Vec::new();
        for payload in [&b"one"[..], &b"two"[..]] {
            wire.extend_from_slice(&[0x00, payload.len() as u8, 0x00, ATYP_IPV4]);
            wire.extend_from_slice(&ip);
            wire.extend_from_slice(&echo_addr.port().to_be_bytes());
            wire.extend_from_slice(payload);
        }
        client.write_all(&wire).await.unwrap();

        let mut seen = Vec::new();
        for _ in 0..2 {
            let (data, _, _) =
                tokio::time::timeout(Duration::from_secs(5), read_tunnel_frame(&mut client))
                    .await
                    .expect("timed out waiting for a tunnelled reply");
            seen.push(String::from_utf8(data).unwrap());
        }
        seen.sort();
        assert_eq!(seen, vec!["echo:one".to_string(), "echo:two".to_string()]);
    }

    // ---- per-datagram access control on the tunnel ----

    /// Sends one datagram through a fresh tunnel and reports whether a reply
    /// came back within `wait`.
    async fn tunnel_datagram_relayed(
        options: HandlerOptions,
        dst: SocketAddr,
        wait: Duration,
    ) -> bool {
        let proxy_addr = spawn_proxy(options).await;
        let (mut client, _, _) = open_raw_tunnel(proxy_addr).await;

        let mut frame: Vec<u8> = vec![0x00, 0x04, 0x00, ATYP_IPV4];
        match dst.ip() {
            IpAddr::V4(v) => frame.extend_from_slice(&v.octets()),
            _ => panic!("expected v4"),
        }
        frame.extend_from_slice(&dst.port().to_be_bytes());
        frame.extend_from_slice(b"ping");
        client.write_all(&frame).await.unwrap();

        tokio::time::timeout(wait, read_tunnel_frame(&mut client))
            .await
            .is_ok()
    }

    #[tokio::test]
    async fn test_socks5_udp_tunnel_datagram_blocked_by_blacklist() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        spawn_udp_echo(echo);

        // Positive control: with no rules the datagram is relayed, so a later
        // absence of a reply can only be the rule doing its job.
        assert!(
            tunnel_datagram_relayed(HandlerOptions::default(), echo_addr, Duration::from_secs(5))
                .await,
            "control: an unfiltered datagram must be relayed through the tunnel"
        );

        // "udp:127.0.0.1:*" does not cover the 0.0.0.0:0 bind address in the
        // request, so the tunnel is still granted and only the datagram is
        // denied.
        let bl = crate::permissions::Permissions::parse("udp:127.0.0.1:*").unwrap();
        assert!(
            !tunnel_datagram_relayed(
                HandlerOptions {
                    blacklist: Some(bl),
                    ..Default::default()
                },
                echo_addr,
                Duration::from_millis(600),
            )
            .await,
            "Can(\"udp\", ...) must be applied to every tunnelled datagram"
        );
    }

    #[tokio::test]
    async fn test_socks5_udp_tunnel_datagram_blocked_by_bypass() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        spawn_udp_echo(echo);

        assert!(
            tunnel_datagram_relayed(HandlerOptions::default(), echo_addr, Duration::from_secs(5))
                .await,
            "control: an unfiltered datagram must be relayed through the tunnel"
        );

        let bypass =
            std::sync::Arc::new(crate::bypass::Bypass::from_patterns(false, &["127.0.0.1"]));
        assert!(
            !tunnel_datagram_relayed(
                HandlerOptions {
                    bypass: Some(bypass),
                    ..Default::default()
                },
                echo_addr,
                Duration::from_millis(600),
            )
            .await,
            "the bypass must be applied per tunnelled datagram"
        );
    }

    #[tokio::test]
    async fn test_socks5_udp_tunnel_bind_denied_by_blacklist() {
        // gost gates the requested bind address with the "rudp" action
        // (socks.go:1402).
        let bl = crate::permissions::Permissions::parse("rudp:*:*").unwrap();
        let proxy_addr = spawn_proxy(HandlerOptions {
            blacklist: Some(bl),
            ..Default::default()
        })
        .await;

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        greet(&mut client).await;
        client
            .write_all(&[0x05, CMD_UDP_TUN, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let (rep, _, _) = read_reply(&mut client).await;
        assert_eq!(rep, REP_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn test_socks5_udp_tunnel_socket_dies_with_the_stream() {
        let proxy_addr = spawn_proxy(HandlerOptions::default()).await;
        let (client, host, port) = open_raw_tunnel(proxy_addr).await;
        let bound: SocketAddr = format!("{}:{}", host, port).parse().unwrap();

        drop(client);
        tokio::time::sleep(Duration::from_millis(300)).await;

        assert!(
            UdpSocket::bind(bound).await.is_ok(),
            "the tunnel's UDP socket must be closed when the stream closes"
        );
    }

    #[tokio::test]
    async fn test_socks5_connector_basic() {
        // Start a real SOCKS5 proxy
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            conn.write_all(b"connector-test").await.unwrap();
        });

        let handler = Socks5Handler::new(HandlerOptions::default());
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(ProxyConn::from_tcp(conn)).await.ok();
        });

        let connector = Socks5Connector::new(None);
        let stream = TcpStream::connect(proxy_addr).await.unwrap();
        let mut conn = connector
            .connect(stream, &target_addr.to_string())
            .await
            .unwrap();

        let mut buf = vec![0u8; 1024];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"connector-test");
    }
}
