//! The QUIC transport: `-L quic://` and `-F quic://` (gost's quic.go).
//!
//! One QUIC connection carries many bidirectional streams, so this has the
//! shape of the multiplexed transports rather than the plain ones: the
//! listener turns each accepted connection into an accept loop and dispatches
//! every stream on it to the handler as its own [`ProxyConn`] (gost's
//! `quicListener.sessionLoop`, quic.go:211-231), and the dialer keeps one
//! connection per node and opens a stream per dial (`quicTransporter.Dial`,
//! quic.go:56-97). [`MuxServer`](crate::mux_transport::MuxServer) and
//! [`MuxDialer`](crate::mux_transport::MuxDialer) solve the same two problems
//! over smux and this module deliberately follows their structure.
//!
//! # Wire compatibility with gost
//!
//! * **ALPN.** gost overwrites `NextProtos` with `[]string{"http/3", "quic/v1"}`
//!   on both ends (`tlsConfigQUICALPN`, quic.go:340-346, applied to the dialer
//!   at quic.go:121 and to the listener at quic.go:183). RFC 9001 makes ALPN
//!   mandatory for QUIC and rustls enforces it, so a peer that offers nothing
//!   is refused with `no_application_protocol`. [`QUIC_ALPN`] is that list, in
//!   that order, and both [`QuicServer`] and [`QuicDialer`] overwrite whatever
//!   the caller configured, exactly as gost's clone-and-overwrite does.
//!
//! * **The `?cipher=` datagram layer.** gost derives `Key = sha256(cipher)`
//!   (route.go:223-226 for the dialer, 476-479 for the listener) and wraps the
//!   UDP socket in a `quicCipherConn` (quic.go:267-338) that AES-GCM-seals
//!   *every* datagram. The framing is `nonce || ciphertext || tag`: `encrypt`
//!   is `gcm.Seal(nonce, nonce, data, nil)` (quic.go:317), and Go's `Seal`
//!   appends to its first argument, so the 12-byte random nonce is a *prefix*;
//!   the 16-byte tag is the suffix GCM appends; the additional data is `nil`,
//!   so nothing outside the datagram body is authenticated. `decrypt` splits
//!   the same way (`data[:nonceSize]`, `data[nonceSize:]`, quic.go:336).
//!   [`CipherSocket`] reproduces that byte for byte, as a
//!   [`quinn::AsyncUdpSocket`] wrapper so it sits in the same place in the
//!   stack as gost's `net.PacketConn` wrapper.
//!
//!   One deliberate deviation: gost's `ReadFrom` returns the decrypt error to
//!   quic-go (quic.go:277-280), which lets one stray datagram tear down the
//!   listener. Here an undecryptable datagram is dropped and the receive loop
//!   continues, which is what a UDP listener has to do to survive a scanner.
//!
//! # The pieces
//!
//! * [`QuicServer`] (aliased [`QuicListener`]) — the listener, with
//!   [`TlsServer`](crate::tls_listener::TlsServer)'s lifecycle:
//!   [`cancel_token`](QuicServer::cancel_token), [`local_addr`](QuicServer::local_addr),
//!   a [`TaskTracker`] and the same graceful drain.
//! * [`QuicDialer`] — one connection per node address, a stream per dial, with
//!   [`MuxDialer`](crate::mux_transport::MuxDialer)'s double-checked cache and
//!   rebuild-on-dead-connection.
//! * [`QuicTransporter`] — gost's `sessions map[string]*quicSession`
//!   (quic.go:42): one [`QuicDialer`] per address, shared process-wide.
//! * [`QuicStream`] — a `SendStream`/`RecvStream` pair as one
//!   `AsyncRead + AsyncWrite` stream, so it drops into a [`ProxyConn`].

use std::collections::HashMap;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};
use std::time::Duration;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{
    AsyncUdpSocket, Connection, Endpoint, EndpointConfig, IdleTimeout, RecvStream, SendStream,
    TransportConfig, UdpPoller, VarInt,
};
use rand::RngCore;
use rustls::crypto::hash::Hash as _;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, info};

use crate::conn::ProxyConn;
use crate::handler::Handler;
use crate::node::Node;

/// The error type the rest of the crate's constructors use.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

// ---------------------------------------------------------------------------
// ALPN
// ---------------------------------------------------------------------------

/// The application protocols gost offers on both ends of a QUIC connection,
/// in gost's order (`tlsConfigQUICALPN`, quic.go:340-346).
///
/// The order matters: rustls' server picks the first of *its own* protocols
/// that the client also offered, so two gost-compatible peers always settle on
/// `http/3`. Nothing here speaks HTTP/3 — gost tunnels its own protocols
/// inside QUIC streams — but the name has to match or the handshake fails.
pub const QUIC_ALPN: [&[u8]; 2] = [b"http/3", b"quic/v1"];

/// [`QUIC_ALPN`] in the shape rustls' `alpn_protocols` wants.
pub fn alpn_protocols() -> Vec<Vec<u8>> {
    QUIC_ALPN.iter().map(|p| p.to_vec()).collect()
}

/// The protocol a live connection settled on, or `None` when the handshake has
/// not finished. Compare against [`QUIC_ALPN`] to check gost compatibility.
pub fn negotiated_alpn(connection: &Connection) -> Option<Vec<u8>> {
    let data = connection
        .handshake_data()?
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .ok()?;
    data.protocol
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// QUIC configuration, gost's `QUICConfig` (quic.go:133-141) minus the TLS
/// config, which both ends take separately so certificate handling stays with
/// the caller.
///
/// Every field is read. Zero means "not set" for the three durations, in which
/// case quinn's own default applies, matching gost — `node.GetDuration` yields
/// zero for an absent parameter and quic-go treats zero as "use the default".
#[derive(Clone, Debug)]
pub struct QuicConfig {
    /// `?keepalive=`. gost only sets a keep-alive period when this is true
    /// (route.go:215-221), so a period without this flag is ignored here too.
    pub keep_alive: bool,
    /// `?ttl=`, gost's `KeepAlivePeriod` → quinn's keep-alive interval.
    pub keep_alive_period: Duration,
    /// `?timeout=`. gost maps this to quic-go's `HandshakeIdleTimeout`; quinn
    /// has no equivalent knob, so it is applied as the dial deadline.
    pub timeout: Duration,
    /// `?idle=`, gost's `IdleTimeout` → quinn's max idle timeout.
    pub idle_timeout: Duration,
    /// `sha256(?cipher=)`. Turns on the [`CipherSocket`] datagram layer.
    /// 16 or 32 bytes; anything else is refused by [`QuicConfig::validate`].
    pub key: Option<Vec<u8>>,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            keep_alive: false,
            keep_alive_period: Duration::from_secs(10),
            timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(30),
            key: None,
        }
    }
}

impl QuicConfig {
    /// Rejects a key length no AES-GCM variant here can take, so a mistyped
    /// `?cipher=` fails at construction rather than silently disabling the
    /// encryption it asked for.
    pub fn validate(&self) -> Result<(), BoxError> {
        if let Some(key) = &self.key {
            if !matches!(key.len(), 16 | 32) {
                return Err(format!(
                    "quic: a datagram key must be 16 or 32 bytes, got {}",
                    key.len()
                )
                .into());
            }
        }
        Ok(())
    }

    /// True when the `?cipher=` datagram layer is on.
    pub fn is_encrypted(&self) -> bool {
        self.key.is_some()
    }
}

/// gost's `Key = sha256(cipher)` (route.go:223-226, 476-479).
///
/// The digest comes from the ring provider rustls already links, rather than a
/// new dependency: `TLS13_AES_128_GCM_SHA256`'s hash *is* SHA-256, and
/// `CipherSuiteCommon::hash_provider` is public API.
pub fn key_from_cipher(cipher: &str) -> Vec<u8> {
    rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .expect("TLS13_AES_128_GCM_SHA256 is a TLS 1.3 suite")
        .common
        .hash_provider
        .hash(cipher.as_bytes())
        .as_ref()
        .to_vec()
}

/// Builds a [`QuicConfig`] from a node's query parameters, following
/// route.go:209-227 (dialer) and route.go:463-479 (listener) exactly:
/// `?keepalive=`, `?ttl=`, `?timeout=`, `?idle=` and `?cipher=`.
///
/// `?ttl=` is read only when `?keepalive=true`, and defaults to 10s then, as
/// gost does at route.go:215-221.
pub fn quic_config_from_node(node: &Node) -> Result<QuicConfig, BoxError> {
    let keep_alive = node.get_bool("keepalive");
    let keep_alive_period = if keep_alive {
        let ttl = node.get_duration("ttl");
        if ttl.is_zero() {
            Duration::from_secs(10)
        } else {
            ttl
        }
    } else {
        Duration::ZERO
    };

    let key = match node.get("cipher") {
        Some(cipher) if !cipher.is_empty() => Some(key_from_cipher(cipher)),
        _ => None,
    };

    let config = QuicConfig {
        keep_alive,
        keep_alive_period,
        timeout: node.get_duration("timeout"),
        idle_timeout: node.get_duration("idle"),
        key,
    };
    config.validate()?;
    Ok(config)
}

/// Maps [`QuicConfig`]'s durations onto quinn's transport parameters, the way
/// gost fills `quic.Config` (quic.go:112-120 and 154-162).
///
/// `timeout` is absent on purpose: gost gives it to `HandshakeIdleTimeout`,
/// which quinn does not expose, so [`QuicDialer`] applies it as a deadline
/// around the connect instead.
pub fn quic_transport_config(config: &QuicConfig) -> Result<TransportConfig, BoxError> {
    let mut transport = TransportConfig::default();

    if !config.idle_timeout.is_zero() {
        transport.max_idle_timeout(Some(IdleTimeout::try_from(config.idle_timeout)?));
    }
    // gost reads KeepAlivePeriod only when KeepAlive is set, so an interval
    // left over from a previous configuration cannot switch keep-alives on.
    if config.keep_alive && !config.keep_alive_period.is_zero() {
        transport.keep_alive_interval(Some(config.keep_alive_period));
    }

    Ok(transport)
}

// ---------------------------------------------------------------------------
// The `?cipher=` datagram layer
// ---------------------------------------------------------------------------

/// Go's `gcm.NonceSize()` for AES-GCM.
const NONCE_LEN: usize = 12;
/// Go's `gcm.Overhead()`; the tag GCM appends.
const TAG_LEN: usize = 16;
/// Room for the largest datagram a peer can send us plus the framing.
const MAX_DATAGRAM: usize = 64 * 1024;

/// The AEAD behind [`CipherSocket`], gost's `aes.NewCipher(key)` +
/// `cipher.NewGCM` (quic.go:302-310).
enum PacketCipher {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
}

impl PacketCipher {
    fn new(key: &[u8]) -> io::Result<Self> {
        match key.len() {
            16 => Ok(Self::Aes128(Box::new(
                Aes128Gcm::new_from_slice(key).map_err(io::Error::other)?,
            ))),
            32 => Ok(Self::Aes256(Box::new(
                Aes256Gcm::new_from_slice(key).map_err(io::Error::other)?,
            ))),
            n => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("quic: a datagram key must be 16 or 32 bytes, got {}", n),
            )),
        }
    }

    /// `nonce || ciphertext || tag`, gost's `gcm.Seal(nonce, nonce, data, nil)`
    /// (quic.go:317). The nonce is fresh per datagram, as it must be: the key
    /// is fixed for the life of the listener.
    fn seal(&self, plain: &[u8]) -> io::Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);

        let mut out = Vec::with_capacity(NONCE_LEN + plain.len() + TAG_LEN);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(plain);

        let n = (&nonce).into();
        let tag = match self {
            // The additional data is empty, matching gost's trailing `nil`:
            // only the datagram body is authenticated.
            Self::Aes128(c) => c.encrypt_in_place_detached(n, b"", &mut out[NONCE_LEN..]),
            Self::Aes256(c) => c.encrypt_in_place_detached(n, b"", &mut out[NONCE_LEN..]),
        }
        .map_err(|_| io::Error::other("quic: datagram encryption failed"))?;

        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// The inverse, gost's `decrypt` (quic.go:320-338).
    fn open(&self, datagram: &[u8]) -> io::Result<Vec<u8>> {
        if datagram.len() < NONCE_LEN + TAG_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "quic: datagram too short to carry a nonce and tag",
            ));
        }

        let (nonce, rest) = datagram.split_at(NONCE_LEN);
        let (body, tag) = rest.split_at(rest.len() - TAG_LEN);

        let nonce: &[u8; NONCE_LEN] = nonce
            .try_into()
            .map_err(|_| io::Error::other("quic: malformed datagram nonce"))?;
        let tag: &[u8; TAG_LEN] = tag
            .try_into()
            .map_err(|_| io::Error::other("quic: malformed datagram tag"))?;

        let mut out = body.to_vec();
        let n = nonce.into();
        let t = tag.into();
        match self {
            Self::Aes128(c) => c.decrypt_in_place_detached(n, b"", &mut out, t),
            Self::Aes256(c) => c.decrypt_in_place_detached(n, b"", &mut out, t),
        }
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "quic: datagram authentication tag mismatch",
            )
        })?;

        Ok(out)
    }
}

/// gost's `quicCipherConn` (quic.go:267-299): a UDP socket that AES-GCM-seals
/// every datagram leaving it and opens every datagram arriving.
///
/// Expressed as a [`quinn::AsyncUdpSocket`] rather than a socket wrapper,
/// because that is where quinn lets a `net.PacketConn` substitute go —
/// [`quinn::Endpoint::new_with_abstract_socket`] takes exactly this.
///
/// GSO and GRO are switched off ([`max_transmit_segments`](Self::max_transmit_segments),
/// [`max_receive_segments`](Self::max_receive_segments) return 1) so a buffer
/// is always exactly one datagram: the framing is per-datagram and a coalesced
/// batch would seal several as one and change the bytes on the wire.
///
/// The 28 bytes of framing sit outside quinn's MTU accounting, as they do in
/// gost. quinn's own ceiling is 1452, so an encrypted datagram tops out at
/// 1480 and still fits a 1500-byte path.
struct CipherSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    cipher: PacketCipher,
    /// Raw datagrams land here before being opened: the encrypted form is
    /// longer than the plaintext, so quinn's buffers cannot receive into
    /// directly without risking a truncated read.
    scratch: Mutex<Vec<u8>>,
}

impl CipherSocket {
    fn new(inner: Arc<dyn AsyncUdpSocket>, key: &[u8]) -> io::Result<Self> {
        Ok(Self {
            inner,
            cipher: PacketCipher::new(key)?,
            scratch: Mutex::new(vec![0u8; MAX_DATAGRAM]),
        })
    }
}

impl std::fmt::Debug for CipherSocket {
    // `AsyncUdpSocket` requires Debug and an AEAD key is not something to
    // print, so only the socket underneath is shown.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CipherSocket")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for CipherSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        // Write readiness is the inner socket's; the cipher adds no buffering.
        Arc::clone(&self.inner).create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // `max_transmit_segments` is 1, so `segment_size` is always None in
        // practice; the split is here so a future quinn that ignores that hint
        // still produces one sealed datagram per segment rather than one
        // sealed blob. A repeated datagram after a partial WouldBlock is
        // harmless — QUIC deduplicates.
        let segment = transmit.segment_size.unwrap_or(transmit.contents.len());
        let segment = segment.max(1);

        for chunk in transmit.contents.chunks(segment) {
            let sealed = self.cipher.seal(chunk)?;
            self.inner.try_send(&Transmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: &sealed,
                segment_size: None,
                src_ip: transmit.src_ip,
            })?;
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }

        loop {
            let mut scratch = self.scratch.lock().unwrap();
            let mut raw_bufs = [IoSliceMut::new(&mut scratch[..])];
            let mut raw_meta = [RecvMeta::default()];

            let n = ready!(self.inner.poll_recv(cx, &mut raw_bufs, &mut raw_meta))?;
            if n == 0 {
                return Poll::Ready(Ok(0));
            }
            // `raw_bufs` borrowed `scratch` mutably; that borrow ends at
            // the poll_recv above, so `scratch` can be read from here.
            let received = raw_meta[0];
            let plain = match self.cipher.open(&scratch[..received.len]) {
                Ok(plain) => plain,
                Err(e) => {
                    // Unlike gost (quic.go:277-280), a datagram we cannot open
                    // is dropped rather than reported: a scanner or a peer
                    // with the wrong `?cipher=` would otherwise end the
                    // listener's receive loop.
                    debug!("[quic] dropping a datagram from {}: {}", received.addr, e);
                    continue;
                }
            };
            drop(scratch);

            if plain.len() > bufs[0].len() {
                debug!(
                    "[quic] dropping a {}-byte datagram from {}: larger than the receive buffer",
                    plain.len(),
                    received.addr
                );
                continue;
            }

            bufs[0][..plain.len()].copy_from_slice(&plain);
            meta[0] = RecvMeta {
                addr: received.addr,
                len: plain.len(),
                // One datagram per buffer: GRO is off.
                stride: plain.len(),
                ecn: received.ecn,
                dst_ip: received.dst_ip,
            };
            return Poll::Ready(Ok(1));
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

/// Binds a UDP socket and builds the quinn endpoint on it, inserting the
/// [`CipherSocket`] when a key is configured — the same place gost inserts its
/// `quicCipherConn`, between the socket and QUIC (quic.go:78-80, 179-181).
fn build_endpoint(
    bind: SocketAddr,
    server_config: Option<quinn::ServerConfig>,
    key: Option<&[u8]>,
) -> io::Result<Endpoint> {
    let runtime =
        quinn::default_runtime().ok_or_else(|| io::Error::other("quic: no async runtime found"))?;

    let socket = std::net::UdpSocket::bind(bind)?;
    socket.set_nonblocking(true)?;
    let socket = runtime.wrap_udp_socket(socket)?;

    let socket: Arc<dyn AsyncUdpSocket> = match key {
        Some(key) => Arc::new(CipherSocket::new(socket, key)?),
        None => socket,
    };

    Endpoint::new_with_abstract_socket(EndpointConfig::default(), server_config, socket, runtime)
}

/// gost resolves listener and dialer addresses with `net.ResolveUDPAddr`
/// (quic.go:62, 170), so `localhost:8443` has to work as well as a literal.
async fn resolve(addr: &str) -> io::Result<SocketAddr> {
    tokio::net::lookup_host(addr).await?.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("quic: {} resolved to no address", addr),
        )
    })
}

// ---------------------------------------------------------------------------
// Stream
// ---------------------------------------------------------------------------

/// One bidirectional QUIC stream as a single byte stream, gost's `quicConn`
/// (quic.go:253-265).
///
/// Partial reads and writes are quinn's `RecvStream`/`SendStream` impls,
/// which already resume correctly across poll calls; what this adds is joining
/// the two halves and keeping the connection — and, on the client, the
/// endpoint that owns its socket — alive for as long as the stream, the same
/// reason [`MuxStreamConn`](crate::mux_transport::MuxStreamConn) holds its
/// session.
pub struct QuicStream {
    send: SendStream,
    recv: RecvStream,
    connection: Connection,
    /// The client's cached connection, if this stream came from a
    /// [`QuicDialer`]. Server-side streams are kept alive by the listener.
    session: Option<Arc<QuicSession>>,
}

impl QuicStream {
    fn new(
        send: SendStream,
        recv: RecvStream,
        connection: Connection,
        session: Option<Arc<QuicSession>>,
    ) -> Self {
        Self {
            send,
            recv,
            connection,
            session,
        }
    }

    /// The QUIC stream id, unique within its connection.
    pub fn id(&self) -> quinn::StreamId {
        self.send.id()
    }

    /// The connection this stream rides on, kept alive as long as the stream.
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    /// The ALPN protocol the connection settled on. Expected to be
    /// `QUIC_ALPN[0]` against a gost peer.
    pub fn negotiated_alpn(&self) -> Option<Vec<u8>> {
        negotiated_alpn(&self.connection)
    }

    /// True while the connection is still usable.
    pub fn is_live(&self) -> bool {
        self.connection.close_reason().is_none()
    }
}

// The calls below are fully qualified on purpose: `SendStream` and
// `RecvStream` both have inherent `poll_write`/`poll_read` methods with
// quinn's own error types, which would shadow the trait ones.
impl AsyncRead for QuicStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.get_mut().recv), cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.get_mut().send), cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().send), cx)
    }

    /// Finishes the sending half, which is QUIC's half-close: the peer sees
    /// EOF while this side can still read.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.get_mut().send), cx)
    }
}

impl std::fmt::Debug for QuicStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicStream")
            .field("id", &self.id())
            .field("peer", &self.connection.remote_address())
            .field("pooled", &self.session.is_some())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// A live handle to a listener's accepted-connection count.
///
/// [`QuicServer::serve`] consumes the listener, so anything to be read while
/// it runs has to be taken beforehand — the same shape as
/// [`QuicServer::cancel_token`].
#[derive(Clone, Debug, Default)]
pub struct ConnectionCount(Arc<AtomicU64>);

impl ConnectionCount {
    /// Connections that completed the QUIC handshake. One that failed it never
    /// gets this far and is not counted.
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    fn incr(&self) -> u64 {
        self.0.fetch_add(1, Ordering::Relaxed) + 1
    }
}

fn addr_str(addr: Option<SocketAddr>) -> String {
    addr.map(|a| a.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// The QUIC listener, gost's `quicListener` (quic.go:143-251).
///
/// One accepted connection becomes one accept loop and every stream on it is
/// dispatched to the handler as its own [`ProxyConn`], so a single client can
/// carry any number of concurrent proxy requests over one UDP flow.
///
/// The lifecycle mirrors [`TlsServer`](crate::tls_listener::TlsServer):
/// [`cancel_token`](Self::cancel_token), a [`TaskTracker`] that carries both
/// the per-connection loops and the per-stream handlers, and a `serve` that
/// returns only once they have all finished.
///
/// There is no accept-error backoff ladder, unlike `TlsServer`: quinn's
/// `accept` cannot fail — it yields `None` only when the endpoint is gone — so
/// there is no transient error to back off from. A failed handshake surfaces
/// inside the per-connection task and is logged there, which is where
/// `TlsServer` handles its own failed handshakes too.
pub struct QuicServer {
    endpoint: Endpoint,
    handler: Arc<dyn Handler>,
    connections: ConnectionCount,
    cancel: CancellationToken,
    tracker: TaskTracker,
}

/// gost's name for [`QuicServer`] (`QUICListener`, quic.go:150).
pub type QuicListener = QuicServer;

impl QuicServer {
    /// Builds a listener from a prepared rustls configuration.
    ///
    /// Certificate handling stays with the caller:
    /// [`server_config_from_files`](crate::tls_listener::server_config_from_files)
    /// for `?cert=`/`?key=` and
    /// [`self_signed_config`](crate::tls_listener::self_signed_config) for
    /// gost's fallback when a listener has no key pair. `alpn_protocols` is
    /// overwritten with [`QUIC_ALPN`] whatever the caller set, exactly as
    /// gost's `tlsConfigQUICALPN` clone-and-overwrite does (quic.go:183).
    pub async fn new(
        addr: &str,
        tls_config: rustls::ServerConfig,
        config: QuicConfig,
        handler: impl Handler + 'static,
    ) -> Result<Self, BoxError> {
        // Fail here rather than on the first datagram, where a bad key would
        // look like a peer that never connects.
        config.validate()?;

        let mut crypto = tls_config;
        crypto.alpn_protocols = alpn_protocols();

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?,
        ));
        server_config.transport_config(Arc::new(quic_transport_config(&config)?));

        let bind = resolve(addr).await?;
        let endpoint = build_endpoint(bind, Some(server_config), config.key.as_deref())?;

        info!(
            "QUIC listening on {}{}",
            endpoint.local_addr()?,
            if config.is_encrypted() {
                " (encrypted datagrams)"
            } else {
                ""
            }
        );

        Ok(Self {
            endpoint,
            handler: Arc::new(handler),
            connections: ConnectionCount::default(),
            cancel: CancellationToken::new(),
            tracker: TaskTracker::new(),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// A handle to the number of connections accepted so far. Taken before
    /// [`serve`](Self::serve), which consumes the listener.
    pub fn connection_count(&self) -> ConnectionCount {
        self.connections.clone()
    }

    /// The endpoint, for callers that need to share the UDP socket.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Accepts connections, turns each into a stream accept loop and
    /// dispatches every stream on it to the handler.
    pub async fn serve(self) -> Result<(), BoxError> {
        let local_addr = self.endpoint.local_addr().ok();

        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => {
                    info!("[quic] shutdown signal received, draining connections...");
                    break;
                }
                incoming = self.endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        // Only happens once the endpoint is closed or its
                        // driver died; there is nothing left to accept.
                        debug!("[quic] endpoint closed, accept loop ending");
                        break;
                    };

                    let peer_addr = incoming.remote_address();
                    let handler = self.handler.clone();
                    let connections = self.connections.clone();
                    let cancel = self.cancel.clone();
                    let tracker = self.tracker.clone();

                    // The stream accept loop is this task; the streams it
                    // dispatches are spawned on the same tracker, so shutdown
                    // drains both.
                    self.tracker.spawn(async move {
                        let connection = match incoming.await {
                            Ok(connection) => connection,
                            Err(e) => {
                                // Routine: port scanners, a peer without ALPN
                                // and a peer with the wrong `?cipher=` all
                                // land here.
                                debug!("[quic] handshake failed from {}: {}", peer_addr, e);
                                return;
                            }
                        };

                        let peer = connection.remote_address();
                        let local = addr_str(local_addr);
                        let n = connections.incr();
                        debug!("[quic] {} <-> {} : connection up ({} total)", peer, local, n);

                        loop {
                            let (send, recv) = tokio::select! {
                                accepted = connection.accept_bi() => match accepted {
                                    Ok(pair) => pair,
                                    // The connection ended. That closes this
                                    // loop and nothing else: the listener
                                    // keeps accepting.
                                    Err(e) => {
                                        debug!("[quic] {} : {}", peer, e);
                                        break;
                                    }
                                },
                                _ = cancel.cancelled() => break,
                            };

                            let stream = QuicStream::new(send, recv, connection.clone(), None);
                            let sid = stream.id();
                            let conn = ProxyConn::layered(
                                Box::new(stream),
                                Some(peer),
                                local_addr,
                            );

                            let handler = handler.clone();
                            let cancel = cancel.clone();

                            // Each stream is its own task, so one handler's
                            // error cannot stop the connection from accepting
                            // the next.
                            tracker.spawn(async move {
                                tokio::select! {
                                    result = handler.handle(conn) => {
                                        if let Err(e) = result {
                                            debug!("[quic] {} stream {} : {}", peer, sid, e);
                                        }
                                    }
                                    _ = cancel.cancelled() => {
                                        debug!("[quic] {} stream {} : cancelled", peer, sid);
                                    }
                                }
                            });
                        }

                        // gost's session.CloseWithError(0, "closed"),
                        // quic.go:219.
                        connection.close(VarInt::from_u32(0), b"closed");
                        debug!("[quic] {} >-< {} : connection down", peer, local);
                    });
                }
            }
        }

        self.tracker.close();
        self.tracker.wait().await;
        // Only after the drain: closing the endpoint tears down every live
        // connection, which would cut short the handlers still running.
        self.endpoint.close(VarInt::from_u32(0), b"closed");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// A live connection and the endpoint that owns its UDP socket.
///
/// gost builds a fresh `net.PacketConn` per session (quic.go:72-76) and this
/// keeps the equivalent alive alongside the connection, so a
/// [`QuicStream`] handed out on its own cannot outlive its socket.
struct QuicSession {
    endpoint: Endpoint,
    connection: Connection,
}

impl QuicSession {
    fn is_live(&self) -> bool {
        self.connection.close_reason().is_none()
    }
}

impl Drop for QuicSession {
    fn drop(&mut self) {
        // gost's quicSession.Close (quic.go:35-37).
        self.connection.close(VarInt::from_u32(0), b"closed");
        self.endpoint.close(VarInt::from_u32(0), b"closed");
    }
}

/// The client half: one QUIC connection per node address, a stream per dial.
///
/// gost keeps a connection per address and calls `OpenStreamSync` for every
/// dial (quic.go:70-96) — a dialer that built a connection per dial would pay
/// for a full QUIC handshake on every request. This caches the connection and
/// rebuilds it only when it dies, following
/// [`MuxDialer`](crate::mux_transport::MuxDialer): the same double-checked
/// cache, the same build lock so concurrent cold dials produce one connection.
///
/// Safe to share across tasks.
pub struct QuicDialer {
    addr: String,
    server_name: String,
    crypto: Arc<quinn::crypto::rustls::QuicClientConfig>,
    config: QuicConfig,
    transport: Arc<TransportConfig>,
    /// The live connection. A plain mutex, held only long enough to clone the
    /// `Arc` out, so warm dials never serialise behind each other.
    cached: Mutex<Option<Arc<QuicSession>>>,
    /// Held across the connect, so only one task builds a connection at a
    /// time. This is gost's `sessionMutex` (quic.go:41, 67).
    build_lock: tokio::sync::Mutex<()>,
    built: AtomicU64,
}

impl QuicDialer {
    /// A dialer that does not verify the server certificate, which is gost's
    /// default for QUIC (`&tls.Config{InsecureSkipVerify: true}`,
    /// quic.go:108-110).
    pub fn new(addr: &str, config: QuicConfig) -> Result<Self, BoxError> {
        Self::with_client_config(addr, config, insecure_client_config()?)
    }

    /// A dialer over a prepared rustls configuration, for callers that do want
    /// to verify the peer. `alpn_protocols` is overwritten with [`QUIC_ALPN`]
    /// regardless, as gost's `tlsConfigQUICALPN` does (quic.go:121).
    pub fn with_client_config(
        addr: &str,
        config: QuicConfig,
        crypto: rustls::ClientConfig,
    ) -> Result<Self, BoxError> {
        config.validate()?;

        let mut crypto = crypto;
        crypto.alpn_protocols = alpn_protocols();

        // The name defaults to the address's host, which is what a caller
        // verifying certificates would expect; `with_server_name` overrides it
        // for gost's `?secure=`-style host pinning.
        let server_name = host_of(addr).to_string();

        Ok(Self {
            addr: addr.to_string(),
            server_name,
            crypto: Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?),
            transport: Arc::new(quic_transport_config(&config)?),
            config,
            cached: Mutex::new(None),
            build_lock: tokio::sync::Mutex::new(()),
            built: AtomicU64::new(0),
        })
    }

    /// The name presented in SNI and checked against the certificate.
    pub fn with_server_name(mut self, name: &str) -> Self {
        self.server_name = name.to_string();
        self
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// Opens a stream on the cached connection, building one first if there is
    /// none or the cached one is dead.
    ///
    /// The rebuild is transparent and happens at most once per call: if the
    /// connection that was just built cannot open a stream either, that error
    /// is returned rather than looping.
    pub async fn dial(&self) -> Result<QuicStream, BoxError> {
        // Warm path. No build lock: an established connection opens a stream
        // without a round trip, so serialising here would be pure contention.
        if let Some(session) = self.live_session() {
            match session.connection.open_bi().await {
                Ok((send, recv)) => {
                    let connection = session.connection.clone();
                    return Ok(QuicStream::new(send, recv, connection, Some(session)));
                }
                Err(e) => debug!(
                    "[quic] {}: the cached connection refused a stream ({}), rebuilding",
                    self.addr, e
                ),
            }
        }

        // Cold or dead. One builder at a time, so two concurrent first dials
        // produce one connection rather than racing to replace each other's.
        let _guard = self.build_lock.lock().await;

        // Re-check under the lock: the task that held it may have built the
        // connection we were about to build.
        if let Some(session) = self.live_session() {
            if let Ok((send, recv)) = session.connection.open_bi().await {
                let connection = session.connection.clone();
                return Ok(QuicStream::new(send, recv, connection, Some(session)));
            }
        }

        let session = Arc::new(self.connect().await?);
        self.built.fetch_add(1, Ordering::Relaxed);

        // Only publish a connection that works. Otherwise one that died during
        // the handshake would be handed to the next caller as live.
        let (send, recv) = session.connection.open_bi().await?;
        *self.cached.lock().unwrap() = Some(session.clone());
        debug!(
            "[quic] {}: connection {} up (alpn {:?})",
            self.addr,
            self.built.load(Ordering::Relaxed),
            negotiated_alpn(&session.connection).map(|p| String::from_utf8_lossy(&p).into_owned())
        );

        let connection = session.connection.clone();
        Ok(QuicStream::new(send, recv, connection, Some(session)))
    }

    /// gost's `initSession` (quic.go:103-127): a fresh UDP socket, the cipher
    /// layer if configured, then the handshake.
    async fn connect(&self) -> Result<QuicSession, BoxError> {
        let remote = resolve(&self.addr).await?;

        // Bound to the remote's family: gost hardcodes IPv4 (quic.go:73), which
        // cannot reach an IPv6 peer at all.
        let bind: SocketAddr = if remote.is_ipv6() {
            (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
        } else {
            (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
        };

        let endpoint = build_endpoint(bind, None, self.config.key.as_deref())?;

        let mut client_config = quinn::ClientConfig::new(self.crypto.clone());
        client_config.transport_config(self.transport.clone());

        let connecting = endpoint.connect_with(client_config, remote, &self.server_name)?;

        // gost gives `Timeout` to quic-go's HandshakeIdleTimeout; quinn has no
        // such knob, so it becomes the deadline on the handshake itself.
        let connection = if self.config.timeout.is_zero() {
            connecting.await?
        } else {
            tokio::time::timeout(self.config.timeout, connecting)
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "quic: the handshake with {} did not finish within {:?}",
                            self.addr, self.config.timeout
                        ),
                    )
                })??
        };

        Ok(QuicSession {
            endpoint,
            connection,
        })
    }

    /// The cached connection if it is still usable. A dead one is evicted on
    /// the way past, as gost does with `delete(tr.sessions, addr)`
    /// (quic.go:93).
    fn live_session(&self) -> Option<Arc<QuicSession>> {
        let mut cached = self.cached.lock().unwrap();
        match cached.as_ref() {
            Some(session) if session.is_live() => Some(session.clone()),
            Some(_) => {
                *cached = None;
                None
            }
            None => None,
        }
    }

    /// Connections built since this dialer was created. One, however many
    /// dials have been made, unless a connection died in between.
    pub fn connections_built(&self) -> u64 {
        self.built.load(Ordering::Relaxed)
    }

    pub fn has_live_connection(&self) -> bool {
        self.live_session().is_some()
    }

    /// The ALPN protocol the cached connection settled on, if there is one.
    pub fn negotiated_alpn(&self) -> Option<Vec<u8>> {
        self.live_session()
            .and_then(|s| negotiated_alpn(&s.connection))
    }

    /// Closes the cached connection, ending every stream on it.
    ///
    /// The dead connection is deliberately dropped from the cache; the next
    /// dial rebuilds, which is the same path a connection dying because the
    /// peer went away takes.
    pub fn close(&self) {
        if let Some(session) = self.cached.lock().unwrap().take() {
            session.connection.close(VarInt::from_u32(0), b"closed");
        }
    }
}

impl std::fmt::Debug for QuicDialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicDialer")
            .field("addr", &self.addr)
            .field("connections_built", &self.connections_built())
            .field("encrypted", &self.config.is_encrypted())
            .finish()
    }
}

/// gost's default QUIC client TLS configuration: no verification at all
/// (quic.go:108-110).
fn insecure_client_config() -> Result<rustls::ClientConfig, BoxError> {
    // The provider is named explicitly: several crates in this dependency
    // graph pull in both ring and aws-lc-rs, which leaves no unambiguous
    // default. Same reasoning as `tls_listener::server_config_from_pem`.
    Ok(rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
    .with_no_client_auth())
}

/// The host part of `host:port`, for the default SNI name.
fn host_of(addr: &str) -> &str {
    // `[::1]:443` has to keep its brackets off and its colons intact.
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some((host, _)) = rest.split_once(']') {
            return host;
        }
    }
    match addr.rsplit_once(':') {
        Some((host, _)) if !host.is_empty() => host,
        _ => "localhost",
    }
}

/// One [`QuicDialer`] per address, which is gost's
/// `sessions map[string]*quicSession` (quic.go:42) with the key being the node
/// address.
///
/// A chain or connector holds one of these for the whole process and asks it
/// for the dialer belonging to the hop it is about to use, so the QUIC
/// connection for that hop is shared by every request that crosses it.
///
/// gost builds one transporter per node (route.go:228), which is why the TLS
/// settings below belong to the transporter rather than to a single address:
/// every address a node resolves to is the same peer.
pub struct QuicTransporter {
    config: QuicConfig,
    /// `None` is gost's default of no certificate verification (quic.go:109).
    crypto: Option<rustls::ClientConfig>,
    /// `None` derives the SNI name from each address.
    server_name: Option<String>,
    dialers: Mutex<HashMap<String, Arc<QuicDialer>>>,
}

impl std::fmt::Debug for QuicTransporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let keys: Vec<String> = match self.dialers.lock() {
            Ok(map) => map.keys().cloned().collect(),
            Err(poisoned) => poisoned.into_inner().keys().cloned().collect(),
        };
        f.debug_struct("QuicTransporter")
            .field("nodes", &keys)
            .finish()
    }
}

impl QuicTransporter {
    /// The configuration is checked here, so a mistyped `?cipher=` fails at
    /// startup rather than on the first request.
    pub fn new(config: QuicConfig) -> Result<Self, BoxError> {
        config.validate()?;
        Ok(Self {
            config,
            crypto: None,
            server_name: None,
            dialers: Mutex::new(HashMap::new()),
        })
    }

    /// A prepared rustls client configuration for every dialer, replacing
    /// gost's default of no verification at all. The mirror of the
    /// `rustls::ServerConfig` [`QuicServer::new`] takes: certificate handling
    /// stays with the caller on both ends.
    pub fn with_client_config(mut self, crypto: rustls::ClientConfig) -> Self {
        self.crypto = Some(crypto);
        self
    }

    /// The name presented in SNI and checked against the certificate, gost's
    /// `?secure=` host. Without it each dialer uses its address's host.
    pub fn with_server_name(mut self, name: impl Into<String>) -> Self {
        self.server_name = Some(name.into());
        self
    }

    /// The dialer for `addr`, creating it the first time.
    pub fn dialer(&self, addr: &str) -> Result<Arc<QuicDialer>, BoxError> {
        let mut dialers = self.dialers.lock().unwrap();
        if let Some(dialer) = dialers.get(addr) {
            return Ok(dialer.clone());
        }

        let mut dialer = match &self.crypto {
            Some(crypto) => {
                QuicDialer::with_client_config(addr, self.config.clone(), crypto.clone())?
            }
            None => QuicDialer::new(addr, self.config.clone())?,
        };
        if let Some(name) = &self.server_name {
            dialer = dialer.with_server_name(name);
        }

        let dialer = Arc::new(dialer);
        dialers.insert(addr.to_string(), dialer.clone());
        Ok(dialer)
    }

    /// gost's `quicTransporter.Dial` (quic.go:56-97): a stream on the
    /// connection for `addr`, opening that connection on the first call.
    pub async fn dial(&self, addr: &str) -> Result<QuicStream, BoxError> {
        self.dialer(addr)?.dial().await
    }

    /// Drops the dialer for `addr`, closing its connection.
    pub fn remove(&self, addr: &str) -> Option<Arc<QuicDialer>> {
        let removed = self.dialers.lock().unwrap().remove(addr);
        if let Some(dialer) = &removed {
            dialer.close();
        }
        removed
    }

    pub fn len(&self) -> usize {
        self.dialers.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn config(&self) -> &QuicConfig {
        &self.config
    }
}

/// Skip server certificate verification, gost's `InsecureSkipVerify: true`
/// (quic.go:109).
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        // Taken from the provider rather than hardcoded, so a certificate
        // signed with anything ring supports still reaches the (accepting)
        // verifier above.
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::handler::HandlerError;

    /// Anything that hangs would block the whole (single-threaded) run, so
    /// reads are bounded and fail loudly instead.
    const READ_TIMEOUT: Duration = Duration::from_secs(10);

    /// Echoes what it reads, so the transport is shown to carry an arbitrary
    /// inner protocol.
    struct EchoHandler;

    #[async_trait]
    impl Handler for EchoHandler {
        async fn handle(&self, mut conn: ProxyConn) -> Result<(), HandlerError> {
            let mut buf = vec![0u8; 4096];
            loop {
                let n = match conn.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                if conn.write_all(&buf[..n]).await.is_err() {
                    break;
                }
                conn.flush().await.ok();
            }
            Ok(())
        }
    }

    /// A running listener: its address, its shutdown switch and a live view of
    /// how many connections it has accepted.
    struct RunningServer {
        addr: SocketAddr,
        cancel: CancellationToken,
        connections: ConnectionCount,
    }

    fn spawn(server: QuicServer) -> RunningServer {
        let addr = server.local_addr().unwrap();
        let cancel = server.cancel_token();
        let connections = server.connection_count();
        tokio::spawn(async move {
            server.serve().await.ok();
        });
        RunningServer {
            addr,
            cancel,
            connections,
        }
    }

    async fn start_server(config: QuicConfig) -> RunningServer {
        let (tls, _cert) = crate::tls_listener::self_signed_config("localhost").unwrap();
        spawn(
            QuicServer::new("127.0.0.1:0", tls, config, EchoHandler)
                .await
                .unwrap(),
        )
    }

    fn dialer(addr: SocketAddr, config: QuicConfig) -> QuicDialer {
        QuicDialer::new(&addr.to_string(), config)
            .unwrap()
            .with_server_name("localhost")
    }

    async fn read_exactly(stream: &mut QuicStream, n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        tokio::time::timeout(READ_TIMEOUT, stream.read_exact(&mut buf))
            .await
            .expect("timed out waiting for the echo")
            .unwrap();
        buf
    }

    async fn echo(stream: &mut QuicStream, payload: &[u8]) -> Vec<u8> {
        stream.write_all(payload).await.unwrap();
        stream.flush().await.unwrap();
        read_exactly(stream, payload.len()).await
    }

    // -----------------------------------------------------------------------
    // Connection reuse
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_two_streams_over_one_quic_connection() {
        let server = start_server(QuicConfig::default()).await;
        let dialer = dialer(server.addr, QuicConfig::default());

        let mut first = dialer.dial().await.unwrap();
        let mut second = dialer.dial().await.unwrap();
        assert_ne!(first.id(), second.id(), "each dial must be its own stream");

        // Interleaved on purpose: a connection that crossed its streams' data
        // would pass a strictly sequential test.
        first.write_all(b"alpha").await.unwrap();
        second.write_all(b"bravo").await.unwrap();
        first.flush().await.unwrap();
        second.flush().await.unwrap();

        assert_eq!(read_exactly(&mut first, 5).await, b"alpha");
        assert_eq!(read_exactly(&mut second, 5).await, b"bravo");

        // The whole point of the QUIC transport. Without this the two round
        // trips above would have paid for two handshakes.
        assert_eq!(
            dialer.connections_built(),
            1,
            "two dials must share one QUIC connection"
        );
        assert_eq!(
            server.connections.get(),
            1,
            "the listener must have accepted exactly one connection"
        );

        // And more data still flows on both afterwards.
        assert_eq!(echo(&mut first, b"one more").await, b"one more");
        assert_eq!(echo(&mut second, b"and here").await, b"and here");

        server.cancel.cancel();
    }

    // Genuinely parallel, not just interleaved: the double-checked cache and
    // the build lock have to hold with the dials running on several threads.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_cold_dials_build_one_connection() {
        let server = start_server(QuicConfig::default()).await;
        let dialer = Arc::new(dialer(server.addr, QuicConfig::default()));

        let mut tasks = Vec::new();
        for i in 0..8u8 {
            let dialer = dialer.clone();
            tasks.push(tokio::spawn(async move {
                let mut stream = dialer.dial().await.unwrap();
                let payload = [b'a' + i; 6];
                assert_eq!(echo(&mut stream, &payload).await, payload);
                stream.id()
            }));
        }

        let mut ids = Vec::new();
        for task in tasks {
            ids.push(task.await.unwrap());
        }
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 8, "every dial must get a stream of its own");

        assert_eq!(dialer.connections_built(), 1);
        assert_eq!(server.connections.get(), 1);
        server.cancel.cancel();
    }

    #[tokio::test]
    async fn test_a_dead_connection_is_rebuilt_on_the_next_dial() {
        let server = start_server(QuicConfig::default()).await;
        let dialer = dialer(server.addr, QuicConfig::default());

        let mut first = dialer.dial().await.unwrap();
        assert_eq!(echo(&mut first, b"one").await, b"one");

        dialer.close();
        assert!(!first.is_live());
        assert!(!dialer.has_live_connection());

        let mut second = dialer.dial().await.unwrap();
        assert_eq!(echo(&mut second, b"two").await, b"two");

        assert_eq!(
            dialer.connections_built(),
            2,
            "the dead connection must be replaced"
        );
        // Proof the rebuild reached the network rather than being papered over
        // locally: the listener saw a second handshake.
        assert_eq!(server.connections.get(), 2);
        server.cancel.cancel();
    }

    #[tokio::test]
    async fn test_a_transporter_keeps_one_dialer_per_address() {
        let server = start_server(QuicConfig::default()).await;
        let transporter = QuicTransporter::new(QuicConfig::default()).unwrap();
        let key = server.addr.to_string();

        for _ in 0..3 {
            let mut stream = transporter.dial(&key).await.unwrap();
            assert_eq!(echo(&mut stream, b"pooled").await, b"pooled");
        }

        assert_eq!(transporter.len(), 1);
        assert_eq!(
            server.connections.get(),
            1,
            "one connection for the whole address"
        );

        transporter.remove(&key);
        assert!(transporter.is_empty());
        server.cancel.cancel();
    }

    #[tokio::test]
    async fn test_a_supplied_client_config_replaces_the_default_verifier() {
        let server = start_server(QuicConfig::default()).await;

        // gost's default accepts the listener's self-signed certificate...
        let permissive = dialer(server.addr, QuicConfig::default());
        let mut stream = permissive.dial().await.unwrap();
        assert_eq!(echo(&mut stream, b"insecure").await, b"insecure");

        // ...and a caller-supplied configuration with an empty root store does
        // not, which is how we know the verifier really is the caller's rather
        // than the accept-anything one underneath.
        let crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();

        let strict = QuicTransporter::new(QuicConfig {
            timeout: Duration::from_secs(5),
            ..Default::default()
        })
        .unwrap()
        .with_client_config(crypto)
        .with_server_name("localhost");

        let err = strict
            .dial(&server.addr.to_string())
            .await
            .expect_err("an untrusted certificate must not be accepted");
        assert!(
            err.to_string().to_lowercase().contains("certificate"),
            "expected a certificate failure, got: {}",
            err
        );

        server.cancel.cancel();
    }

    // -----------------------------------------------------------------------
    // ALPN
    // -----------------------------------------------------------------------

    #[test]
    fn test_alpn_is_gosts_list_in_gosts_order() {
        // tlsConfigQUICALPN, quic.go:345.
        assert_eq!(QUIC_ALPN, [b"http/3".as_slice(), b"quic/v1".as_slice()]);
        assert_eq!(
            alpn_protocols(),
            vec![b"http/3".to_vec(), b"quic/v1".to_vec()]
        );
    }

    #[tokio::test]
    async fn test_the_negotiated_protocol_is_what_gost_expects() {
        let server = start_server(QuicConfig::default()).await;
        let dialer = dialer(server.addr, QuicConfig::default());
        let mut stream = dialer.dial().await.unwrap();

        // Not "the handshake succeeded": the actual protocol both ends agreed
        // on. rustls picks the server's first offer that the client also sent,
        // so with gost's list on both sides this is `http/3`.
        assert_eq!(
            stream.negotiated_alpn().as_deref(),
            Some(QUIC_ALPN[0]),
            "a gost peer expects http/3 to win"
        );
        assert_eq!(echo(&mut stream, b"alpn").await, b"alpn");
        server.cancel.cancel();
    }

    #[tokio::test]
    async fn test_a_client_without_alpn_is_refused() {
        // The failure this transport used to have in reverse: RFC 9001 makes
        // ALPN mandatory, and rustls rejects a QUIC peer that offers none with
        // no_application_protocol. Proves the listener really requires it.
        let server = start_server(QuicConfig::default()).await;

        let mut crypto = insecure_client_config().unwrap();
        crypto.alpn_protocols = Vec::new();
        let client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap(),
        ));

        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let err = endpoint
            .connect_with(client_config, server.addr, "localhost")
            .unwrap()
            .await
            .expect_err("a client offering no ALPN must not be accepted");

        let text = err.to_string();
        assert!(
            text.contains("no_application_protocol") || text.contains("120"),
            "expected an ALPN failure, got: {}",
            text
        );
        assert_eq!(
            server.connections.get(),
            0,
            "a refused handshake is not a connection"
        );
        server.cancel.cancel();
    }

    // -----------------------------------------------------------------------
    // Payloads
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_a_payload_larger_than_one_read_buffer_survives() {
        // 300 KiB is far past the handler's 4 KiB buffer, quinn's stream
        // receive window and the 1200-byte datagrams underneath, so the
        // reassembly on both sides is exercised.
        let server = start_server(QuicConfig::default()).await;
        let dialer = dialer(server.addr, QuicConfig::default());

        let payload: Vec<u8> = (0..300_000usize).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();

        let stream = dialer.dial().await.unwrap();
        let (mut reader, mut writer) = tokio::io::split(stream);
        tokio::spawn(async move {
            writer.write_all(&payload).await.ok();
            writer.flush().await.ok();
        });

        let mut got = vec![0u8; expected.len()];
        tokio::time::timeout(Duration::from_secs(60), reader.read_exact(&mut got))
            .await
            .expect("timed out on the large payload")
            .unwrap();
        assert_eq!(got, expected);
        server.cancel.cancel();
    }

    #[tokio::test]
    async fn test_cancelling_the_listener_drains_and_returns() {
        let (tls, _cert) = crate::tls_listener::self_signed_config("localhost").unwrap();
        let server = QuicServer::new("127.0.0.1:0", tls, QuicConfig::default(), EchoHandler)
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let cancel = server.cancel_token();
        let served = tokio::spawn(async move { server.serve().await });

        let dialer = dialer(addr, QuicConfig::default());
        let mut stream = dialer.dial().await.unwrap();
        assert_eq!(echo(&mut stream, b"up").await, b"up");

        cancel.cancel();
        tokio::time::timeout(READ_TIMEOUT, served)
            .await
            .expect("serve did not return after cancellation")
            .unwrap()
            .unwrap();
    }

    // -----------------------------------------------------------------------
    // Configuration
    // -----------------------------------------------------------------------

    #[test]
    fn test_the_durations_reach_quinns_transport_config() {
        // TransportConfig exposes no getters, but its Debug prints both fields
        // this maps onto, so the assertion is on the config quinn will use
        // rather than on a timer expiring.
        let config = QuicConfig {
            keep_alive: true,
            keep_alive_period: Duration::from_secs(7),
            idle_timeout: Duration::from_secs(23),
            ..Default::default()
        };
        let shown = format!("{:?}", quic_transport_config(&config).unwrap());
        assert!(
            shown.contains("keep_alive_interval: Some(7s)"),
            "keep-alive did not reach quinn: {}",
            shown
        );
        // IdleTimeout's Debug is the varint's, i.e. the timeout in milliseconds.
        assert!(
            shown.contains("max_idle_timeout: Some(23000)"),
            "idle timeout did not reach quinn: {}",
            shown
        );

        // gost only reads KeepAlivePeriod when KeepAlive is set
        // (route.go:215-221), so a period alone must stay off.
        let off = QuicConfig {
            keep_alive: false,
            keep_alive_period: Duration::from_secs(7),
            ..Default::default()
        };
        let shown = format!("{:?}", quic_transport_config(&off).unwrap());
        assert!(shown.contains("keep_alive_interval: None"), "{}", shown);

        // Zero means "unset": quinn's own default applies, as quic-go's does
        // for gost.
        let unset = QuicConfig {
            idle_timeout: Duration::ZERO,
            ..Default::default()
        };
        let shown = format!("{:?}", quic_transport_config(&unset).unwrap());
        assert!(!shown.contains("max_idle_timeout: Some(0"), "{}", shown);
    }

    #[tokio::test]
    async fn test_keep_alive_holds_a_connection_past_its_idle_timeout() {
        // The observable half of the same claim: with a 1s idle timeout and
        // nothing to send, a connection dies; with keep-alives every 200ms it
        // does not. Bounded by the configured timeout, not a real-world one.
        let idle = Duration::from_secs(1);
        let server = start_server(QuicConfig {
            idle_timeout: idle,
            ..Default::default()
        })
        .await;

        let silent = dialer(
            server.addr,
            QuicConfig {
                idle_timeout: idle,
                keep_alive: false,
                ..Default::default()
            },
        );
        let chatty = dialer(
            server.addr,
            QuicConfig {
                idle_timeout: idle,
                keep_alive: true,
                keep_alive_period: Duration::from_millis(200),
                ..Default::default()
            },
        );

        let quiet = silent.dial().await.unwrap();
        let kept = chatty.dial().await.unwrap();
        assert!(quiet.is_live() && kept.is_live());

        tokio::time::sleep(idle + Duration::from_millis(1200)).await;

        assert!(
            !quiet.is_live(),
            "a silent connection must hit the idle timeout"
        );
        assert!(
            kept.is_live(),
            "keep-alives must hold the connection open past the idle timeout"
        );
        server.cancel.cancel();
    }

    #[test]
    fn test_a_key_that_no_aes_gcm_variant_accepts_is_refused() {
        let bad = QuicConfig {
            key: Some(vec![0u8; 24]),
            ..Default::default()
        };
        assert!(bad.validate().is_err());
        assert!(QuicTransporter::new(bad.clone()).is_err());
        assert!(QuicDialer::new("127.0.0.1:1", bad).is_err());
    }

    #[test]
    fn test_the_key_is_sha256_of_the_cipher_string() {
        // route.go:223-226: sum := sha256.Sum256([]byte(cipher)).
        let empty = key_from_cipher("");
        assert_eq!(
            hex(&empty),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&key_from_cipher("abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(empty.len(), 32, "gost always ends up with an AES-256 key");
    }

    #[test]
    fn test_the_node_parameters_reach_the_config() {
        let node =
            Node::parse("quic://127.0.0.1:1080?keepalive=true&ttl=15&timeout=3&idle=45").unwrap();
        let config = quic_config_from_node(&node).unwrap();
        assert!(config.keep_alive);
        assert_eq!(config.keep_alive_period, Duration::from_secs(15));
        assert_eq!(config.timeout, Duration::from_secs(3));
        assert_eq!(config.idle_timeout, Duration::from_secs(45));
        assert!(config.key.is_none());

        // route.go:216-220: keepalive with no ttl means 10s.
        let node = Node::parse("quic://127.0.0.1:1080?keepalive=true").unwrap();
        assert_eq!(
            quic_config_from_node(&node).unwrap().keep_alive_period,
            Duration::from_secs(10)
        );

        // ...and a ttl without keepalive is ignored, as gost ignores it.
        let node = Node::parse("quic://127.0.0.1:1080?ttl=15").unwrap();
        let config = quic_config_from_node(&node).unwrap();
        assert!(!config.keep_alive);
        assert_eq!(config.keep_alive_period, Duration::ZERO);

        let node = Node::parse("quic://127.0.0.1:1080?cipher=secret").unwrap();
        assert_eq!(
            quic_config_from_node(&node).unwrap().key,
            Some(key_from_cipher("secret"))
        );
    }

    #[test]
    fn test_the_default_sni_name_comes_from_the_address() {
        assert_eq!(host_of("example.com:443"), "example.com");
        assert_eq!(host_of("127.0.0.1:4433"), "127.0.0.1");
        assert_eq!(host_of("[::1]:4433"), "::1");
        assert_eq!(host_of(":4433"), "localhost");
    }

    // -----------------------------------------------------------------------
    // The `?cipher=` datagram layer
    // -----------------------------------------------------------------------

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn test_the_datagram_framing_matches_gost() {
        let key = key_from_cipher("hunter2");
        let cipher = PacketCipher::new(&key).unwrap();
        let plain = b"the quick brown fox jumps over the lazy dog";

        let sealed = cipher.seal(plain).unwrap();

        // gcm.Seal(nonce, nonce, data, nil): a 12-byte nonce prefix, then the
        // ciphertext, then GCM's 16-byte tag (quic.go:312-317).
        assert_eq!(sealed.len(), NONCE_LEN + plain.len() + TAG_LEN);

        // The plaintext must not be visible anywhere in the datagram.
        assert!(
            !sealed.windows(plain.len()).any(|w| w == plain),
            "the plaintext is on the wire: {}",
            hex(&sealed)
        );
        // Not even a recognisable run of it: the whole body is ciphertext.
        assert!(!sealed.windows(8).any(|w| w == &plain[..8]));

        // A fresh nonce per datagram, so two seals of the same bytes differ.
        let again = cipher.seal(plain).unwrap();
        assert_ne!(sealed[..NONCE_LEN], again[..NONCE_LEN]);
        assert_ne!(sealed, again);

        // And it round-trips, splitting exactly where gost splits
        // (quic.go:336).
        assert_eq!(cipher.open(&sealed).unwrap(), plain);
        assert_eq!(cipher.open(&again).unwrap(), plain);
    }

    #[test]
    fn test_a_datagram_sealed_under_another_key_does_not_open() {
        let ours = PacketCipher::new(&key_from_cipher("ours")).unwrap();
        let theirs = PacketCipher::new(&key_from_cipher("theirs")).unwrap();

        let sealed = theirs.seal(b"secret payload").unwrap();
        let err = ours.open(&sealed).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        // A truncated datagram is rejected rather than panicking on the split.
        assert!(ours.open(&sealed[..NONCE_LEN + TAG_LEN - 1]).is_err());
        assert!(ours.open(b"").is_err());

        // A flipped bit anywhere fails the tag.
        let mut tampered = theirs.seal(b"secret payload").unwrap();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(theirs.open(&tampered).is_err());
    }

    #[tokio::test]
    async fn test_the_socket_wrapper_seals_and_opens_real_datagrams() {
        // The framing assertion above is on the AEAD; this one is on the wire.
        // A plain UDP socket stands in for the peer, so what it receives is
        // exactly the bytes `CipherSocket` put on the network.
        let key = key_from_cipher("wire");
        let cipher = PacketCipher::new(&key).unwrap();

        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let runtime = quinn::default_runtime().unwrap();
        let raw = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        raw.set_nonblocking(true).unwrap();
        let local_addr = raw.local_addr().unwrap();
        let sock =
            Arc::new(CipherSocket::new(runtime.wrap_udp_socket(raw).unwrap(), &key).unwrap());

        // GSO and GRO must be off, or one buffer would not be one datagram.
        assert_eq!(sock.max_transmit_segments(), 1);
        assert_eq!(sock.max_receive_segments(), 1);

        let plain = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

        // The contract quinn's endpoint driver follows, and the reason
        // `create_io_poller` has to reach the socket underneath: a fresh
        // socket answers the first `try_send` with WouldBlock until write
        // readiness has been registered.
        let mut poller = Arc::clone(&sock).create_io_poller();
        loop {
            match sock.try_send(&Transmit {
                destination: peer_addr,
                ecn: None,
                contents: plain,
                segment_size: None,
                src_ip: None,
            }) {
                Ok(()) => break,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx))
                        .await
                        .unwrap();
                }
                Err(e) => panic!("the sealed datagram could not be sent: {}", e),
            }
        }

        let mut got = vec![0u8; 2048];
        let (n, from) = tokio::time::timeout(READ_TIMEOUT, peer.recv_from(&mut got))
            .await
            .expect("the sealed datagram never arrived")
            .unwrap();
        assert_eq!(from, local_addr);

        let on_the_wire = &got[..n];
        assert_eq!(on_the_wire.len(), plain.len() + NONCE_LEN + TAG_LEN);
        assert!(
            !on_the_wire.windows(plain.len()).any(|w| w == plain),
            "the plaintext went out unencrypted: {}",
            hex(on_the_wire)
        );
        assert!(!on_the_wire.windows(8).any(|w| w == &plain[..8]));
        assert_eq!(cipher.open(on_the_wire).unwrap(), plain);

        // And the receiving half opens what a peer seals, handing quinn the
        // plaintext and the real source address.
        peer.send_to(&cipher.seal(b"pong").unwrap(), local_addr)
            .await
            .unwrap();

        let mut backing = vec![0u8; 2048];
        let mut meta = [RecvMeta::default()];
        let msgs = tokio::time::timeout(
            READ_TIMEOUT,
            std::future::poll_fn(|cx| {
                let mut bufs = [IoSliceMut::new(&mut backing)];
                sock.poll_recv(cx, &mut bufs, &mut meta)
            }),
        )
        .await
        .expect("the reply was never received")
        .unwrap();

        assert_eq!(msgs, 1);
        assert_eq!(meta[0].addr, peer_addr);
        assert_eq!(&backing[..meta[0].len], b"pong");
        assert_eq!(meta[0].stride, meta[0].len);
    }

    #[tokio::test]
    async fn test_the_cipher_layer_carries_a_real_connection() {
        let config = QuicConfig {
            key: Some(key_from_cipher("shared")),
            ..Default::default()
        };
        let server = start_server(config.clone()).await;
        let dialer = dialer(server.addr, config);

        let mut first = dialer.dial().await.unwrap();
        let mut second = dialer.dial().await.unwrap();
        assert_eq!(echo(&mut first, b"encrypted").await, b"encrypted");
        assert_eq!(echo(&mut second, b"as well").await, b"as well");

        // Still one connection: the datagram layer is transparent to reuse.
        assert_eq!(server.connections.get(), 1);
        assert_eq!(
            first.negotiated_alpn().as_deref(),
            Some(QUIC_ALPN[0]),
            "ALPN still has to be negotiated under the cipher"
        );

        // A payload well past one datagram, so the framing is exercised on
        // every packet of a multi-packet transfer rather than just the
        // handshake.
        let payload: Vec<u8> = (0..80_000usize).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();
        let stream = dialer.dial().await.unwrap();
        let (mut reader, mut writer) = tokio::io::split(stream);
        tokio::spawn(async move {
            writer.write_all(&payload).await.ok();
            writer.flush().await.ok();
        });
        let mut got = vec![0u8; expected.len()];
        tokio::time::timeout(Duration::from_secs(60), reader.read_exact(&mut got))
            .await
            .expect("timed out under the cipher layer")
            .unwrap();
        assert_eq!(got, expected);

        server.cancel.cancel();
    }

    #[tokio::test]
    async fn test_the_wrong_cipher_cannot_reach_the_listener() {
        // Proof the layer is really on the wire and not a no-op: with the
        // wrong key every datagram fails its tag and is dropped, so the
        // handshake never completes.
        let server = start_server(QuicConfig {
            key: Some(key_from_cipher("right")),
            ..Default::default()
        })
        .await;

        // A short dial timeout keeps the test quick; the point is that the
        // handshake cannot finish, not how long it takes to give up.
        let short = Duration::from_millis(600);
        let wrong = dialer(
            server.addr,
            QuicConfig {
                key: Some(key_from_cipher("wrong")),
                timeout: short,
                ..Default::default()
            },
        );
        assert!(
            wrong.dial().await.is_err(),
            "a peer with the wrong ?cipher= must not connect"
        );

        // And a peer with no cipher at all is equally shut out: its plaintext
        // datagrams do not open.
        let plain = dialer(
            server.addr,
            QuicConfig {
                timeout: short,
                ..Default::default()
            },
        );
        assert!(
            plain.dial().await.is_err(),
            "a plaintext peer must not connect to an encrypted listener"
        );

        assert_eq!(server.connections.get(), 0);
        server.cancel.cancel();
    }

    #[tokio::test]
    async fn test_an_encrypted_peer_cannot_reach_a_plain_listener() {
        let server = start_server(QuicConfig::default()).await;
        let encrypted = dialer(
            server.addr,
            QuicConfig {
                key: Some(key_from_cipher("secret")),
                timeout: Duration::from_millis(600),
                ..Default::default()
            },
        );
        assert!(encrypted.dial().await.is_err());
        assert_eq!(server.connections.get(), 0);
        server.cancel.cancel();
    }

    #[tokio::test]
    async fn test_a_dial_to_nowhere_fails_and_leaves_no_connection() {
        // Nothing is bound on this port: reserve one, read it back, drop it.
        let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);

        let dialer = dialer(
            addr,
            QuicConfig {
                timeout: Duration::from_millis(400),
                ..Default::default()
            },
        );
        assert!(dialer.dial().await.is_err());
        assert!(!dialer.has_live_connection());
        // Only a connection that handshook counts; a failed attempt leaves
        // nothing behind for the next dial to trip over.
        assert_eq!(dialer.connections_built(), 0);
    }
}
