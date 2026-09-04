//! UDP listener abstraction.
//!
//! gost models a UDP socket as a listener that yields one virtual connection
//! per source address, so the same handlers can serve `udp://`, `ssu://`,
//! `rudp://` and `redu://`. This module is the Rust equivalent of gost's
//! `udp.go`.
//!
//! [`Server`](crate::server::Server) binds a `TcpListener` unconditionally, so
//! every UDP-shaped scheme had nowhere to be served from. [`UdpListener`] fills
//! that hole: one real socket, a demultiplex loop that fans datagrams out by
//! source address, and a [`UdpServerConn`] per peer that implements
//! `AsyncRead`/`AsyncWrite` and therefore drops straight into a
//! [`ProxyConn`](crate::conn::ProxyConn).
//!
//! # Datagram semantics
//!
//! `AsyncRead` is a byte-stream interface and UDP is not a byte stream, so the
//! mapping needs stating:
//!
//! * One read yields at most one datagram. Two datagrams are never merged into
//!   a single read, so a handler that reads with a large buffer sees exactly
//!   the frames the peer sent.
//! * One write sends exactly one datagram. Nothing is buffered, so `flush` is
//!   a no-op.
//! * If the caller's buffer is too small for the datagram, the remainder is
//!   **kept and returned by the following read** rather than discarded (gost
//!   truncates and loses it, see `udp.go:244`). Losing a payload silently is
//!   the worst of the options; failing the connection would be almost as bad,
//!   because a handler is entitled to read with whatever buffer size it likes
//!   and would then die mid-handshake. Boundaries are therefore preserved
//!   whenever the buffer is large enough, and no byte is ever dropped when it
//!   is not.
//! * Empty datagrams are skipped by the reader: returning zero bytes from
//!   `poll_read` means EOF to every `AsyncRead` caller, which would tear the
//!   virtual connection down.
//! * Once the connection is closed - explicitly, by TTL expiry, or because the
//!   listener stopped - reads report EOF.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info};

use crate::conn::ProxyConn;
use crate::handler::Handler;

/// Idle timeout of a virtual connection (gost `defaultTTL`, gost.go:71).
pub const DEFAULT_TTL: Duration = Duration::from_secs(60);
/// Pending-connection queue depth (gost `defaultBacklog`, gost.go:72).
pub const DEFAULT_BACKLOG: usize = 128;
/// Per-connection receive queue depth (gost `defaultQueueSize`, gost.go:73).
pub const DEFAULT_QUEUE_SIZE: usize = 128;

/// Receive buffer for the demux loop. A UDP payload cannot exceed 65507 bytes,
/// so nothing is ever truncated at the socket (which on Windows would surface
/// as `WSAEMSGSIZE` rather than a short read).
const MAX_DATAGRAM: usize = 64 * 1024;

/// Configuration for a [`UdpListener`], gost's `UDPListenConfig` (udp.go:44).
#[derive(Clone, Debug)]
pub struct UdpListenConfig {
    /// How long a virtual connection may sit without traffic before it is
    /// closed and removed. This is what keeps the peer map bounded.
    pub ttl: Duration,
    /// Depth of the accept queue. Datagrams from a new peer are dropped when
    /// it is full.
    pub backlog: usize,
    /// Depth of each virtual connection's receive queue. Datagrams are dropped
    /// when it is full.
    pub queue_size: usize,
}

impl Default for UdpListenConfig {
    fn default() -> Self {
        Self {
            ttl: DEFAULT_TTL,
            backlog: DEFAULT_BACKLOG,
            queue_size: DEFAULT_QUEUE_SIZE,
        }
    }
}

impl UdpListenConfig {
    /// Substitutes the default for any field left at zero, as gost does when a
    /// command line omits `?ttl=`, `?backlog=` or `?queue=` (udp.go:74-77,
    /// udp.go:220-223). A zero-capacity queue would otherwise drop every
    /// datagram.
    fn normalized(&self) -> Self {
        Self {
            ttl: if self.ttl.is_zero() {
                DEFAULT_TTL
            } else {
                self.ttl
            },
            backlog: if self.backlog == 0 {
                DEFAULT_BACKLOG
            } else {
                self.backlog
            },
            queue_size: if self.queue_size == 0 {
                DEFAULT_QUEUE_SIZE
            } else {
                self.queue_size
            },
        }
    }
}

/// Routing table from source address to virtual connection, gost's
/// `udpConnMap` (udp.go:162).
type PeerMap = Arc<Mutex<HashMap<SocketAddr, PeerHandle>>>;

/// Last time a virtual connection carried traffic, read by its TTL watcher.
type Activity = Arc<Mutex<Instant>>;

/// The listener's half of a virtual connection.
struct PeerHandle {
    /// Distinguishes this connection from a later one for the same peer, so a
    /// late `Drop` cannot evict its own replacement.
    id: u64,
    tx: mpsc::Sender<Vec<u8>>,
    closed: CancellationToken,
}

fn lock_peers(peers: &PeerMap) -> MutexGuard<'_, HashMap<SocketAddr, PeerHandle>> {
    // A panic in a task never happens while this lock is held (nothing is
    // awaited under it), but recovering beats propagating a poison panic into
    // the demux loop and killing the whole listener.
    peers.lock().unwrap_or_else(|e| e.into_inner())
}

fn touch(activity: &Activity) {
    *activity.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
}

fn last_activity(activity: &Activity) -> Instant {
    *activity.lock().unwrap_or_else(|e| e.into_inner())
}

/// Removes a peer's entry, but only if it is still the entry for `id`.
/// Dropping the stored `Sender` is what makes the connection's reader see EOF.
fn remove_peer(peers: &PeerMap, peer: &SocketAddr, id: u64) -> bool {
    let mut map = lock_peers(peers);
    match map.get(peer) {
        Some(handle) if handle.id == id => {
            map.remove(peer);
            true
        }
        _ => false,
    }
}

/// A UDP socket presented as a listener of per-peer virtual connections.
///
/// gost's `udpListener` (udp.go:51). A background task owns the receive half
/// of the socket and demultiplexes by source address; the socket itself is
/// shared with every virtual connection through an `Arc` so replies go out
/// without a lock on the send path (tokio's `UdpSocket` sends through `&self`).
pub struct UdpListener {
    socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
    accept_rx: mpsc::Receiver<UdpServerConn>,
    peers: PeerMap,
    cancel: CancellationToken,
    config: UdpListenConfig,
}

impl UdpListener {
    /// Binds a UDP socket and starts demultiplexing.
    pub async fn bind(addr: &str, config: UdpListenConfig) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        Self::from_socket(socket, config)
    }

    /// Wraps an already-bound socket. Must be called from within a tokio
    /// runtime: it spawns the demultiplex loop.
    pub fn from_socket(socket: UdpSocket, config: UdpListenConfig) -> io::Result<Self> {
        let config = config.normalized();
        let local_addr = socket.local_addr()?;
        let socket = Arc::new(socket);
        let (accept_tx, accept_rx) = mpsc::channel(config.backlog);
        let peers: PeerMap = Arc::new(Mutex::new(HashMap::new()));
        let cancel = CancellationToken::new();

        tokio::spawn(demux_loop(
            socket.clone(),
            local_addr,
            config.clone(),
            peers.clone(),
            accept_tx,
            cancel.clone(),
        ));

        Ok(Self {
            socket,
            local_addr,
            accept_rx,
            peers,
            cancel,
            config,
        })
    }

    /// Returns the next virtual connection, or `None` once the listener has
    /// stopped. gost's `Accept` (udp.go:136).
    pub async fn accept(&mut self) -> Option<UdpServerConn> {
        self.accept_rx.recv().await
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The effective configuration, with defaults filled in.
    pub fn config(&self) -> &UdpListenConfig {
        &self.config
    }

    /// Number of live virtual connections. Bounded by the TTL sweep; useful
    /// for logging and for asserting that expiry actually reclaims entries.
    pub fn peer_count(&self) -> usize {
        lock_peers(&self.peers).len()
    }

    /// The shared socket, for callers that need to send outside a virtual
    /// connection.
    pub fn socket(&self) -> &Arc<UdpSocket> {
        &self.socket
    }

    /// Stops the demultiplex loop and closes every virtual connection, so
    /// their readers see EOF. gost's `Close` (udp.go:152).
    pub fn close(&self) {
        self.cancel.cancel();
    }
}

impl Drop for UdpListener {
    fn drop(&mut self) {
        // Without this the demux task would outlive its listener, holding the
        // socket open and the bound port with it.
        self.cancel.cancel();
    }
}

/// Reads every datagram off the socket and routes it by source address.
///
/// gost's `listenLoop` (udp.go:90). Both overflow paths drop rather than
/// block: this loop is the only reader of the socket, so waiting for one slow
/// peer would stall every other peer as well.
async fn demux_loop(
    socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
    config: UdpListenConfig,
    peers: PeerMap,
    accept_tx: mpsc::Sender<UdpServerConn>,
    cancel: CancellationToken,
) {
    let next_id = AtomicU64::new(1);
    let mut buf = vec![0u8; MAX_DATAGRAM];
    let mut backoff = Duration::ZERO;

    loop {
        let (n, src) = tokio::select! {
            _ = cancel.cancelled() => break,
            result = socket.recv_from(&mut buf) => match result {
                Ok(v) => {
                    backoff = Duration::ZERO;
                    v
                }
                Err(e) => {
                    // A UDP socket reports errors for *earlier* sends here: on
                    // Windows an ICMP port-unreachable from a dead peer comes
                    // back as ConnectionReset on the next recv. gost closes
                    // the listener on any error (udp.go:96-102), which would
                    // take the whole service down because one peer went away,
                    // so back off and carry on the way the TCP accept loop
                    // does instead.
                    backoff = next_backoff(backoff);
                    error!("[udp] {} recv error: {}; retrying in {:?}", local_addr, e, backoff);
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = tokio::time::sleep(backoff) => {}
                    }
                    continue;
                }
            }
        };

        let mut datagram = buf[..n].to_vec();

        // Known peer: hand the datagram to its receive queue. The lookup and
        // the send both happen under the peer-map lock, which is safe because
        // `try_send` never blocks.
        {
            let mut map = lock_peers(&peers);
            // Cloning the sender releases the borrow on the map so the stale
            // entry can be evicted below; it is only an Arc bump.
            let tx = map.get(&src).map(|handle| handle.tx.clone());
            if let Some(tx) = tx {
                match tx.try_send(datagram) {
                    Ok(()) => continue,
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        debug!(
                            "[udp] {} -> {} : recv queue is full ({}), datagram dropped",
                            src, local_addr, config.queue_size
                        );
                        continue;
                    }
                    Err(mpsc::error::TrySendError::Closed(returned)) => {
                        // The virtual connection is gone (TTL expiry raced us,
                        // or the handler finished) but its entry lingers.
                        // Evict it and start a fresh connection below.
                        map.remove(&src);
                        datagram = returned;
                    }
                }
            }
        }

        // New peer: build a virtual connection and offer it to `accept`.
        let id = next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(config.queue_size);
        let closed = CancellationToken::new();
        let activity: Activity = Arc::new(Mutex::new(Instant::now()));
        let conn = UdpServerConn {
            socket: socket.clone(),
            peer: src,
            local: local_addr,
            rx,
            pending: None,
            activity: activity.clone(),
            closed: closed.clone(),
            peers: peers.clone(),
            id,
        };

        match accept_tx.try_send(conn) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                // gost drops the connection outright here (udp.go:119-122).
                // Nothing has been registered yet, so dropping the value is
                // the whole cleanup: no map entry, no TTL task, no leak.
                debug!(
                    "[udp] {} - {} : connection backlog is full ({}), connection dropped",
                    src, local_addr, config.backlog
                );
                continue;
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                debug!(
                    "[udp] {} : listener closed, stopping demux loop",
                    local_addr
                );
                break;
            }
        }

        // The queue is fresh and its capacity is at least one, so the first
        // datagram cannot be rejected.
        if tx.try_send(datagram).is_err() {
            debug!("[udp] {} -> {} : first datagram dropped", src, local_addr);
        }
        lock_peers(&peers).insert(
            src,
            PeerHandle {
                id,
                tx,
                closed: closed.clone(),
            },
        );
        tokio::spawn(ttl_watch(
            peers.clone(),
            src,
            id,
            activity,
            closed,
            config.ttl,
        ));

        debug!(
            "[udp] {} -> {} ({})",
            src,
            local_addr,
            lock_peers(&peers).len()
        );
    }

    // Closing every peer drops its sender, so in-flight handlers see EOF
    // instead of hanging on a socket that no longer has a reader.
    let handles: Vec<PeerHandle> = lock_peers(&peers).drain().map(|(_, h)| h).collect();
    for handle in &handles {
        handle.closed.cancel();
    }
    debug!("[udp] {} : demux loop stopped", local_addr);
}

fn next_backoff(current: Duration) -> Duration {
    let next = if current.is_zero() {
        Duration::from_millis(5)
    } else {
        current * 2
    };
    next.min(Duration::from_secs(1))
}

/// Closes a virtual connection once it has been idle for `ttl`.
///
/// gost's `ttlWait` (udp.go:300). Rather than resetting a timer on every
/// datagram, this re-reads the last-activity stamp after each sleep: a
/// connection that keeps working simply pushes its deadline out, and there is
/// no wakeup to miss.
async fn ttl_watch(
    peers: PeerMap,
    peer: SocketAddr,
    id: u64,
    activity: Activity,
    closed: CancellationToken,
    ttl: Duration,
) {
    loop {
        let deadline = last_activity(&activity) + ttl;
        let wait = deadline.saturating_duration_since(Instant::now());
        if wait.is_zero() {
            break;
        }
        tokio::select! {
            _ = closed.cancelled() => return,
            _ = tokio::time::sleep(wait) => {}
        }
    }

    if remove_peer(&peers, &peer, id) {
        debug!("[udp] {} : idle for {:?}, closed", peer, ttl);
    }
    closed.cancel();
}

/// One peer's virtual connection, gost's `udpServerConn` (udp.go:196).
///
/// Reads come from the demux loop's queue; writes go straight out of the
/// shared socket to this peer's address.
pub struct UdpServerConn {
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    local: SocketAddr,
    rx: mpsc::Receiver<Vec<u8>>,
    /// Tail of a datagram the caller's buffer could not hold, plus how much of
    /// it has already been handed over.
    pending: Option<(Vec<u8>, usize)>,
    activity: Activity,
    closed: CancellationToken,
    peers: PeerMap,
    id: u64,
}

impl UdpServerConn {
    /// The source address every datagram on this connection came from.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// The address the shared socket is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Bytes of the current datagram not yet handed to the caller.
    pub fn pending_len(&self) -> usize {
        self.pending
            .as_ref()
            .map(|(d, pos)| d.len() - pos)
            .unwrap_or(0)
    }

    /// Closes the connection and unregisters it, so later datagrams from this
    /// peer start a new one. gost's `Close` (udp.go:284).
    pub fn close(&self) {
        self.closed.cancel();
        remove_peer(&self.peers, &self.peer, self.id);
    }
}

impl Drop for UdpServerConn {
    fn drop(&mut self) {
        // A handler that returns must not leave its routing entry behind; the
        // TTL sweep would eventually get it, but not for another `ttl`.
        self.close();
    }
}

impl AsyncRead for UdpServerConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        loop {
            if me.pending.is_none() {
                match me.rx.poll_recv(cx) {
                    Poll::Pending => return Poll::Pending,
                    // Every sender is gone: closed, expired, or the listener
                    // stopped. Report EOF so copy loops terminate.
                    Poll::Ready(None) => return Poll::Ready(Ok(())),
                    Poll::Ready(Some(datagram)) => {
                        touch(&me.activity);
                        if datagram.is_empty() {
                            // Zero bytes would be read as EOF; skip instead.
                            continue;
                        }
                        me.pending = Some((datagram, 0));
                    }
                }
            }

            let (datagram, pos) = me.pending.as_mut().expect("pending was just set");
            let n = buf.remaining().min(datagram.len() - *pos);
            buf.put_slice(&datagram[*pos..*pos + n]);
            *pos += n;
            if *pos >= datagram.len() {
                me.pending = None;
            }
            return Poll::Ready(Ok(()));
        }
    }
}

impl AsyncWrite for UdpServerConn {
    /// Sends `buf` as exactly one datagram to this connection's peer.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        match me.socket.poll_send_to(cx, buf, me.peer) {
            Poll::Ready(Ok(n)) => {
                touch(&me.activity);
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Nothing is buffered, so there is nothing to flush.
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.close();
        Poll::Ready(Ok(()))
    }
}

/// A UDP proxy server, the counterpart of [`Server`](crate::server::Server).
///
/// Each virtual connection is wrapped in a
/// [`ProxyConn`](crate::conn::ProxyConn) and dispatched to the handler on a
/// `TaskTracker`, with the same cancellation and drain behaviour as the TCP
/// server.
pub struct UdpServer {
    listener: UdpListener,
    handler: Arc<dyn Handler>,
    cancel: CancellationToken,
    tracker: TaskTracker,
}

impl UdpServer {
    /// Binds `addr` and prepares to serve it with `handler`.
    pub async fn new(
        addr: &str,
        config: UdpListenConfig,
        handler: impl Handler + 'static,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let listener = UdpListener::bind(addr, config).await?;
        info!("Listening on {} (udp)", listener.local_addr());
        Ok(Self::from_listener(listener, handler))
    }

    pub fn from_listener(listener: UdpListener, handler: impl Handler + 'static) -> Self {
        Self {
            listener,
            handler: Arc::new(handler),
            cancel: CancellationToken::new(),
            tracker: TaskTracker::new(),
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.listener.local_addr()
    }

    /// Triggers graceful shutdown when cancelled.
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// Accepts virtual connections and hands them to the handler.
    pub async fn serve(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Destructured because `accept` needs the listener mutably while the
        // handler and tracker are used in the same `select!`.
        let UdpServer {
            mut listener,
            handler,
            cancel,
            tracker,
        } = self;
        let local_addr = listener.local_addr();

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("[udp] shutdown signal received, draining connections...");
                    break;
                }
                accepted = listener.accept() => {
                    let Some(conn) = accepted else {
                        // Only reachable if the demux loop stopped on its own.
                        info!("[udp] {} : listener stopped", local_addr);
                        break;
                    };
                    let peer_addr = conn.peer_addr();
                    let handler = handler.clone();
                    let conn_cancel = cancel.clone();

                    tracker.spawn(async move {
                        let proxy_conn =
                            ProxyConn::new(Box::new(conn), Some(peer_addr), Some(local_addr));
                        tokio::select! {
                            result = handler.handle(proxy_conn) => {
                                if let Err(e) = result {
                                    debug!("[udp] {} : {}", peer_addr, e);
                                }
                            }
                            _ = conn_cancel.cancelled() => {
                                debug!("[udp] {} : cancelled", peer_addr);
                            }
                        }
                    });
                }
            }
        }

        // Stop demultiplexing before draining: in-flight handlers then see EOF
        // rather than waiting for datagrams that will never be read.
        listener.close();
        tracker.close();

        let drain_timeout = Duration::from_secs(10);
        if tokio::time::timeout(drain_timeout, tracker.wait())
            .await
            .is_err()
        {
            tracing::warn!(
                "[udp] drain timeout after {:?}, {} tasks still running",
                drain_timeout,
                tracker.len()
            );
        } else {
            info!("[udp] all connections drained");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::HandlerError;
    use async_trait::async_trait;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn config(ttl_ms: u64, backlog: usize, queue_size: usize) -> UdpListenConfig {
        UdpListenConfig {
            ttl: Duration::from_millis(ttl_ms),
            backlog,
            queue_size,
        }
    }

    async fn listener(cfg: UdpListenConfig) -> UdpListener {
        UdpListener::bind("127.0.0.1:0", cfg).await.unwrap()
    }

    async fn client() -> UdpSocket {
        UdpSocket::bind("127.0.0.1:0").await.unwrap()
    }

    /// Accepts within `ms`, or gives up. Used so a broken demux loop fails the
    /// test instead of hanging it.
    async fn accept_within(l: &mut UdpListener, ms: u64) -> Option<UdpServerConn> {
        tokio::time::timeout(Duration::from_millis(ms), l.accept())
            .await
            .ok()
            .flatten()
    }

    async fn read_within(conn: &mut UdpServerConn, ms: u64, buf: &mut [u8]) -> Option<usize> {
        tokio::time::timeout(Duration::from_millis(ms), conn.read(buf))
            .await
            .ok()
            .map(|r| r.unwrap())
    }

    async fn recv_within(sock: &UdpSocket, ms: u64, buf: &mut [u8]) -> Option<usize> {
        tokio::time::timeout(Duration::from_millis(ms), sock.recv_from(buf))
            .await
            .ok()
            .map(|r| r.unwrap().0)
    }

    #[test]
    fn test_config_defaults_match_gost() {
        let cfg = UdpListenConfig::default();
        assert_eq!(cfg.ttl, Duration::from_secs(60));
        assert_eq!(cfg.backlog, 128);
        assert_eq!(cfg.queue_size, 128);
    }

    #[tokio::test]
    async fn test_zero_config_fields_fall_back_to_defaults() {
        let l = listener(UdpListenConfig {
            ttl: Duration::ZERO,
            backlog: 0,
            queue_size: 0,
        })
        .await;
        assert_eq!(l.config().ttl, DEFAULT_TTL);
        assert_eq!(l.config().backlog, DEFAULT_BACKLOG);
        assert_eq!(l.config().queue_size, DEFAULT_QUEUE_SIZE);
    }

    #[tokio::test]
    async fn test_listener_reports_its_bound_address() {
        let l = listener(UdpListenConfig::default()).await;
        assert_ne!(l.local_addr().port(), 0);
        assert_eq!(l.peer_count(), 0);
        assert_eq!(l.socket().local_addr().unwrap(), l.local_addr());
    }

    /// Two source addresses must produce two independent virtual connections.
    #[tokio::test]
    async fn test_two_sources_produce_two_connections() {
        let mut l = listener(config(5_000, 16, 16)).await;
        let addr = l.local_addr();

        let a = client().await;
        let b = client().await;
        a.send_to(b"from-a", addr).await.unwrap();
        b.send_to(b"from-b", addr).await.unwrap();

        let mut first = accept_within(&mut l, 500).await.expect("first accept");
        let mut second = accept_within(&mut l, 500).await.expect("second accept");
        assert_ne!(first.peer_addr(), second.peer_addr());
        assert_eq!(l.peer_count(), 2);

        // Each connection carries only its own peer's datagram.
        let (mut from_a, mut from_b) = if first.peer_addr() == a.local_addr().unwrap() {
            (first, second)
        } else {
            (second, first)
        };
        assert_eq!(from_a.peer_addr(), a.local_addr().unwrap());
        assert_eq!(from_b.peer_addr(), b.local_addr().unwrap());
        assert_eq!(from_a.local_addr(), addr);

        let mut buf = [0u8; 64];
        let n = read_within(&mut from_a, 500, &mut buf)
            .await
            .expect("read a");
        assert_eq!(&buf[..n], b"from-a");
        let n = read_within(&mut from_b, 500, &mut buf)
            .await
            .expect("read b");
        assert_eq!(&buf[..n], b"from-b");
    }

    /// One read yields one datagram: three sends are never coalesced into a
    /// single read, even though the buffer could hold all of them.
    #[tokio::test]
    async fn test_datagram_boundaries_are_preserved() {
        let mut l = listener(config(5_000, 16, 16)).await;
        let addr = l.local_addr();

        let c = client().await;
        c.send_to(b"one", addr).await.unwrap();
        c.send_to(b"twotwo", addr).await.unwrap();
        c.send_to(b"threethree", addr).await.unwrap();

        let mut conn = accept_within(&mut l, 500).await.expect("accept");
        let mut buf = [0u8; 1024];

        for expected in [&b"one"[..], &b"twotwo"[..], &b"threethree"[..]] {
            let n = read_within(&mut conn, 500, &mut buf).await.expect("read");
            assert_eq!(&buf[..n], expected, "datagrams must not be merged");
        }
    }

    /// A buffer too small for the datagram keeps the tail for the next read
    /// instead of discarding it, and the next datagram still starts cleanly.
    #[tokio::test]
    async fn test_short_buffer_keeps_the_remainder() {
        let mut l = listener(config(5_000, 16, 16)).await;
        let addr = l.local_addr();

        let c = client().await;
        c.send_to(b"abcdef", addr).await.unwrap();
        c.send_to(b"xyz", addr).await.unwrap();

        let mut conn = accept_within(&mut l, 500).await.expect("accept");
        let mut small = [0u8; 3];

        let n = read_within(&mut conn, 500, &mut small).await.expect("read");
        assert_eq!(&small[..n], b"abc");
        assert_eq!(conn.pending_len(), 3, "the tail must be kept, not dropped");

        let n = read_within(&mut conn, 500, &mut small).await.expect("read");
        assert_eq!(&small[..n], b"def");
        assert_eq!(conn.pending_len(), 0);

        // The following datagram is not merged with the tail.
        let n = read_within(&mut conn, 500, &mut small).await.expect("read");
        assert_eq!(&small[..n], b"xyz");
    }

    /// Overflowing the accept queue drops the excess connections, and crucially
    /// leaves the demux loop running for everyone else.
    #[tokio::test]
    async fn test_backlog_overflow_drops_without_blocking_the_demux_loop() {
        let mut l = listener(config(5_000, 1, 8)).await;
        let addr = l.local_addr();

        let a = client().await;
        a.send_to(b"a", addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // The queue now holds A, so these two have nowhere to go.
        let b = client().await;
        let c = client().await;
        b.send_to(b"b", addr).await.unwrap();
        c.send_to(b"c", addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let first = accept_within(&mut l, 300).await.expect("A is accepted");
        assert_eq!(first.peer_addr(), a.local_addr().unwrap());
        assert!(
            accept_within(&mut l, 150).await.is_none(),
            "B and C must have been dropped, not queued"
        );

        // The dropped connections left no routing entries behind.
        assert_eq!(l.peer_count(), 1);

        // The loop is still alive: a brand new peer is served normally.
        let d = client().await;
        d.send_to(b"d", addr).await.unwrap();
        let last = accept_within(&mut l, 500)
            .await
            .expect("demux loop must still be running");
        assert_eq!(last.peer_addr(), d.local_addr().unwrap());
    }

    /// Overflowing a connection's receive queue drops datagrams rather than
    /// blocking, and the connection keeps working afterwards.
    #[tokio::test]
    async fn test_receive_queue_overflow_drops_datagrams() {
        let mut l = listener(config(5_000, 8, 1)).await;
        let addr = l.local_addr();

        let c = client().await;
        c.send_to(b"first", addr).await.unwrap();
        let mut conn = accept_within(&mut l, 500).await.expect("accept");

        // "first" already fills the one-slot queue.
        c.send_to(b"second", addr).await.unwrap();
        c.send_to(b"third", addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut buf = [0u8; 64];
        let n = read_within(&mut conn, 500, &mut buf).await.expect("read");
        assert_eq!(&buf[..n], b"first");
        assert!(
            read_within(&mut conn, 150, &mut buf).await.is_none(),
            "the overflowing datagrams must have been dropped"
        );

        // The queue has room again, so the connection recovers.
        c.send_to(b"fourth", addr).await.unwrap();
        let n = read_within(&mut conn, 500, &mut buf).await.expect("read");
        assert_eq!(&buf[..n], b"fourth");
    }

    /// An idle connection is closed and removed once its TTL elapses.
    #[tokio::test]
    async fn test_idle_connection_expires_and_is_removed() {
        let mut l = listener(config(100, 8, 8)).await;
        let addr = l.local_addr();

        let c = client().await;
        c.send_to(b"hi", addr).await.unwrap();
        let mut conn = accept_within(&mut l, 500).await.expect("accept");

        let mut buf = [0u8; 64];
        let n = read_within(&mut conn, 500, &mut buf).await.expect("read");
        assert_eq!(&buf[..n], b"hi");
        assert_eq!(l.peer_count(), 1);

        tokio::time::sleep(Duration::from_millis(300)).await;

        assert_eq!(l.peer_count(), 0, "the expired peer must be unregistered");
        let n = read_within(&mut conn, 300, &mut buf)
            .await
            .expect("read must return, not hang");
        assert_eq!(n, 0, "an expired connection reads as EOF");
    }

    /// Traffic keeps a connection alive past its TTL.
    #[tokio::test]
    async fn test_activity_postpones_expiry() {
        let mut l = listener(config(150, 8, 8)).await;
        let addr = l.local_addr();

        let c = client().await;
        c.send_to(b"1", addr).await.unwrap();
        let mut conn = accept_within(&mut l, 500).await.expect("accept");
        let mut buf = [0u8; 64];
        read_within(&mut conn, 500, &mut buf).await.expect("read");

        // Three reads spaced inside the TTL: total elapsed exceeds it.
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_millis(80)).await;
            c.send_to(b"ping", addr).await.unwrap();
            let n = read_within(&mut conn, 300, &mut buf).await.expect("read");
            assert_eq!(&buf[..n], b"ping");
        }

        assert_eq!(l.peer_count(), 1, "an active connection must not expire");
    }

    /// A reply written to a virtual connection reaches that peer and no other.
    #[tokio::test]
    async fn test_reply_reaches_the_originating_peer() {
        let mut l = listener(config(5_000, 8, 8)).await;
        let addr = l.local_addr();

        let a = client().await;
        let b = client().await;
        a.send_to(b"hello-a", addr).await.unwrap();
        b.send_to(b"hello-b", addr).await.unwrap();

        let first = accept_within(&mut l, 500).await.expect("accept");
        let second = accept_within(&mut l, 500).await.expect("accept");
        let (mut conn_a, mut conn_b) = if first.peer_addr() == a.local_addr().unwrap() {
            (first, second)
        } else {
            (second, first)
        };

        conn_a.write_all(b"reply-to-a").await.unwrap();
        conn_a.flush().await.unwrap();
        conn_b.write_all(b"reply-to-b").await.unwrap();

        let mut buf = [0u8; 64];
        let n = recv_within(&a, 500, &mut buf).await.expect("a receives");
        assert_eq!(&buf[..n], b"reply-to-a");
        let n = recv_within(&b, 500, &mut buf).await.expect("b receives");
        assert_eq!(&buf[..n], b"reply-to-b");

        // Replies come from the listener's own address, so the peer accepts them.
        let mut probe = [0u8; 64];
        conn_a.write_all(b"again").await.unwrap();
        let (n, from) = tokio::time::timeout(Duration::from_millis(500), a.recv_from(&mut probe))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&probe[..n], b"again");
        assert_eq!(from, addr);
    }

    /// Dropping a connection unregisters it immediately, well before its TTL.
    #[tokio::test]
    async fn test_dropping_a_connection_unregisters_it() {
        let mut l = listener(config(5_000, 8, 8)).await;
        let addr = l.local_addr();

        let c = client().await;
        c.send_to(b"x", addr).await.unwrap();
        let conn = accept_within(&mut l, 500).await.expect("accept");
        assert_eq!(l.peer_count(), 1);
        drop(conn);
        assert_eq!(l.peer_count(), 0);

        // The same peer is then served by a fresh connection.
        c.send_to(b"y", addr).await.unwrap();
        let mut again = accept_within(&mut l, 500).await.expect("second accept");
        let mut buf = [0u8; 64];
        let n = read_within(&mut again, 500, &mut buf).await.expect("read");
        assert_eq!(&buf[..n], b"y");
    }

    /// Closing the listener ends `accept` and gives live connections EOF.
    #[tokio::test]
    async fn test_close_ends_accept_and_eofs_connections() {
        let mut l = listener(config(5_000, 8, 8)).await;
        let addr = l.local_addr();

        let c = client().await;
        c.send_to(b"z", addr).await.unwrap();
        let mut conn = accept_within(&mut l, 500).await.expect("accept");
        let mut buf = [0u8; 64];
        read_within(&mut conn, 500, &mut buf).await.expect("read");

        l.close();

        let accepted = tokio::time::timeout(Duration::from_millis(500), l.accept())
            .await
            .expect("accept must return after close");
        assert!(accepted.is_none(), "a closed listener accepts nothing");

        let n = read_within(&mut conn, 500, &mut buf)
            .await
            .expect("read must return after close");
        assert_eq!(n, 0);
    }

    struct EchoHandler;

    #[async_trait]
    impl Handler for EchoHandler {
        async fn handle(&self, mut conn: ProxyConn) -> Result<(), HandlerError> {
            let mut buf = vec![0u8; 2048];
            loop {
                let n = conn.read(&mut buf).await?;
                if n == 0 {
                    return Ok(());
                }
                conn.write_all(&buf[..n]).await?;
            }
        }
    }

    /// Reports the addresses the listener attached to the `ProxyConn`.
    struct AddrHandler;

    #[async_trait]
    impl Handler for AddrHandler {
        async fn handle(&self, mut conn: ProxyConn) -> Result<(), HandlerError> {
            let mut buf = vec![0u8; 64];
            conn.read(&mut buf).await?;
            let reply = format!("{}|{}", conn.peer_addr_str(), conn.local_addr_str());
            conn.write_all(reply.as_bytes()).await?;
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_server_dispatches_each_peer_to_the_handler() {
        let l = listener(config(5_000, 8, 8)).await;
        let addr = l.local_addr();
        let server = UdpServer::from_listener(l, EchoHandler);
        assert_eq!(server.local_addr(), addr);
        let cancel = server.cancel_token();
        let handle = tokio::spawn(async move { server.serve().await.ok() });

        let a = client().await;
        let b = client().await;
        a.send_to(b"ping-a", addr).await.unwrap();
        b.send_to(b"ping-b", addr).await.unwrap();

        let mut buf = [0u8; 64];
        let n = recv_within(&a, 500, &mut buf).await.expect("a echo");
        assert_eq!(&buf[..n], b"ping-a");
        let n = recv_within(&b, 500, &mut buf).await.expect("b echo");
        assert_eq!(&buf[..n], b"ping-b");

        // The same connection keeps serving further datagrams.
        a.send_to(b"ping-a-2", addr).await.unwrap();
        let n = recv_within(&a, 500, &mut buf).await.expect("a echo 2");
        assert_eq!(&buf[..n], b"ping-a-2");

        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("server must shut down promptly")
            .unwrap();
    }

    #[tokio::test]
    async fn test_server_gives_the_handler_the_peer_and_local_addresses() {
        let l = listener(config(5_000, 8, 8)).await;
        let addr = l.local_addr();
        let server = UdpServer::from_listener(l, AddrHandler);
        let cancel = server.cancel_token();
        let handle = tokio::spawn(async move { server.serve().await.ok() });

        let c = client().await;
        c.send_to(b"who", addr).await.unwrap();

        let mut buf = [0u8; 128];
        let n = recv_within(&c, 500, &mut buf).await.expect("reply");
        let expected = format!("{}|{}", c.local_addr().unwrap(), addr);
        assert_eq!(String::from_utf8_lossy(&buf[..n]), expected);

        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("server must shut down promptly")
            .unwrap();
    }

    #[tokio::test]
    async fn test_server_new_binds_and_shuts_down() {
        let server = UdpServer::new("127.0.0.1:0", UdpListenConfig::default(), EchoHandler)
            .await
            .unwrap();
        assert_ne!(server.local_addr().port(), 0);
        let cancel = server.cancel_token();
        let handle = tokio::spawn(async move { server.serve().await.ok() });

        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("server must exit promptly on cancel")
            .unwrap();
    }

    /// Protocol selection produces a `Box<dyn Handler>`; the blanket impl in
    /// `handler.rs` has to carry it through `UdpServer` for the CLI to wire
    /// `udp://` up at all.
    #[tokio::test]
    async fn test_server_accepts_a_boxed_handler() {
        let handler: Box<dyn Handler> = Box::new(EchoHandler);
        let l = listener(config(5_000, 8, 8)).await;
        let addr = l.local_addr();
        let server = UdpServer::from_listener(l, handler);
        let cancel = server.cancel_token();
        let handle = tokio::spawn(async move { server.serve().await.ok() });

        let c = client().await;
        c.send_to(b"boxed", addr).await.unwrap();
        let mut buf = [0u8; 64];
        let n = recv_within(&c, 500, &mut buf).await.expect("echo");
        assert_eq!(&buf[..n], b"boxed");

        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("server must shut down promptly")
            .unwrap();
    }

    #[test]
    fn test_backoff_grows_and_is_capped() {
        let mut d = Duration::ZERO;
        d = next_backoff(d);
        assert_eq!(d, Duration::from_millis(5));
        for _ in 0..20 {
            d = next_backoff(d);
        }
        assert_eq!(d, Duration::from_secs(1));
    }
}
