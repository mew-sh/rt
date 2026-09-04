//! Multiplexed transports: `mtls`, `mws` and `mwss`.
//!
//! gost runs smux over TLS and WebSocket so one connection carries many
//! streams. This module composes [`MuxSession`](crate::mux::MuxSession) with
//! the TLS and WebSocket layers.
//!
//! # What changes compared with the plain transports
//!
//! For `tls`, `ws` and `wss` one accepted socket is one [`Handler`]
//! invocation. Here one accepted socket is one smux *session*, and every
//! stream the peer opens on it is a separate [`ProxyConn`] dispatched to the
//! handler (gost's `mtlsListener.mux`, tls.go:196-224, and `mwsListener.mux`,
//! ws.go:524-556). The client side is the mirror image: gost keeps one session
//! per node and opens a stream per dial (tls.go:52-118), which is the entire
//! point of the multiplexed variants — a dialer that built a session per dial
//! would be strictly more expensive than plain `tls`.
//!
//! # The pieces
//!
//! * [`MuxHandler`] — the session half, expressed as a [`Handler`] that wraps
//!   another handler: it turns the connection it is given into an smux server
//!   session and feeds every accepted stream to the inner handler. This is
//!   what makes the three layerings a composition rather than three listeners:
//!   `mtls` is TLS + [`MuxHandler`], `mws` is
//!   [`WsHandler`](crate::ws::WsHandler) + [`MuxHandler`], and `mwss` is TLS +
//!   both.
//! * [`MuxServer`] — the listener that terminates TLS (when configured) and
//!   drives that pipeline, with the same lifecycle as
//!   [`TlsServer`](crate::tls_listener::TlsServer): accept backoff,
//!   [`CancellationToken`], [`TaskTracker`] and the same graceful drain.
//! * [`MuxDialer`] — the client half, holding one session per instance and
//!   handing out a stream per [`dial`](MuxDialer::dial). It takes a closure
//!   that produces a fresh inner transport, so the caller supplies the
//!   TCP+TLS / TCP+WS stack and this module never needs to know how to dial.
//! * [`MuxStreamConn`] — a stream plus a reference to the session it belongs
//!   to, gost's `muxStreamConn` (mux.go:9-26). Dropping the last reference to
//!   a [`MuxSession`] closes it and aborts its tasks, so a stream handed out
//!   on its own would die the moment the session went out of scope.
//! * [`mux_config_from_node`] / [`mux_config_from_values`] — `?smuxver=` and
//!   the smux buffer sizes (kcp.go:248-256, 356-361) mapped onto a
//!   [`MuxConfig`].

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info};

use crate::conn::{AsyncStream, ProxyConn};
use crate::handler::{Handler, HandlerError};
use crate::mux::{MuxConfig, MuxSession, MuxStream, VERSION_1};
use crate::node::Node;
use crate::ws::{WsHandler, WsOptions};

/// The error type the rest of the crate's constructors use.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

// ---------------------------------------------------------------------------
// Stream + session
// ---------------------------------------------------------------------------

/// One multiplexed stream, plus the session that carries it.
///
/// gost's `muxStreamConn` (mux.go:9-26) keeps the underlying `net.Conn`
/// alongside the stream. The reason is sharper here: dropping the last
/// [`MuxSession`] reference closes the session and aborts its reader, writer
/// and keepalive tasks, so a bare [`MuxStream`] would stop working as soon as
/// the accept loop that produced it moved on.
pub struct MuxStreamConn {
    stream: MuxStream,
    session: Arc<MuxSession>,
}

impl MuxStreamConn {
    fn new(stream: MuxStream, session: Arc<MuxSession>) -> Self {
        Self { stream, session }
    }

    /// The smux stream id: odd for streams a client opened, even for a server.
    pub fn id(&self) -> u32 {
        self.stream.id()
    }

    /// The session this stream rides on, kept alive for as long as the stream.
    pub fn session(&self) -> &MuxSession {
        &self.session
    }
}

impl AsyncRead for MuxStreamConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for MuxStreamConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

impl std::fmt::Debug for MuxStreamConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MuxStreamConn")
            .field("id", &self.id())
            .finish()
    }
}

/// A live handle to a listener's accepted-session count.
///
/// [`MuxServer::serve`] takes the listener by value, so anything to be read
/// after the listener is running has to be taken beforehand — the same shape
/// as [`MuxServer::cancel_token`].
#[derive(Clone, Debug, Default)]
pub struct SessionCount(Arc<AtomicU64>);

impl SessionCount {
    /// Connections that became smux sessions. A connection that failed the TLS
    /// or WebSocket handshake never gets that far and is not counted.
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

// ---------------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------------

/// The smux server session as a [`Handler`] wrapping another handler.
///
/// Given a connection, it builds an smux server session on it and dispatches
/// every stream the peer opens to `inner` as its own [`ProxyConn`], carrying
/// the connection's peer and local addresses so handlers still see the real
/// client (gost's `mtlsListener.mux`, tls.go:196-224).
///
/// [`MuxServer`] is the usual way in; this exists on its own because it is
/// what makes the three layerings compose — put it under
/// [`WsHandler`](crate::ws::WsHandler) and `mws` falls out with no new accept
/// loop.
///
/// Failures are contained in both directions: a stream handler that returns an
/// error only ends that stream, and a session that ends only ends its own
/// accept loop.
pub struct MuxHandler {
    inner: Arc<dyn Handler>,
    config: MuxConfig,
    tag: &'static str,
    sessions: SessionCount,
    tracker: TaskTracker,
    cancel: CancellationToken,
}

impl MuxHandler {
    /// A standalone handler: streams are spawned on a task tracker of its own.
    /// Use [`MuxHandler::with_lifecycle`] to put them on a listener's instead,
    /// which is what [`MuxServer`] does so its shutdown drains them.
    pub fn new(inner: impl Handler + 'static, config: MuxConfig) -> Self {
        Self {
            inner: Arc::new(inner),
            config,
            tag: "mux",
            sessions: SessionCount::default(),
            tracker: TaskTracker::new(),
            cancel: CancellationToken::new(),
        }
    }

    /// Adopts a listener's log tag, session counter, task tracker and
    /// cancellation token, so stream tasks are drained by the listener's
    /// shutdown rather than outliving it.
    pub fn with_lifecycle(
        mut self,
        tag: &'static str,
        sessions: SessionCount,
        tracker: TaskTracker,
        cancel: CancellationToken,
    ) -> Self {
        self.tag = tag;
        self.sessions = sessions;
        self.tracker = tracker;
        self.cancel = cancel;
        self
    }

    pub fn session_count(&self) -> SessionCount {
        self.sessions.clone()
    }
}

#[async_trait]
impl Handler for MuxHandler {
    async fn handle(&self, conn: ProxyConn) -> Result<(), HandlerError> {
        // Captured before the connection is consumed by the session, so every
        // stream's ProxyConn still reports the real client and listener.
        let peer_addr = conn.peer_addr();
        let local_addr = conn.local_addr();
        let peer = addr_str(peer_addr);
        let local = addr_str(local_addr);

        let session = Arc::new(MuxSession::server(conn, self.config.clone())?);
        let n = self.sessions.incr();
        debug!("[{}] {} <-> {} : session up ({} total)", self.tag, peer, local, n);

        loop {
            let stream = tokio::select! {
                accepted = session.accept_stream() => match accepted {
                    Some(stream) => stream,
                    // The session ended. That closes this loop and nothing
                    // else: the listener keeps accepting.
                    None => break,
                },
                _ = self.cancel.cancelled() => break,
            };

            let sid = stream.id();
            let conn = ProxyConn::layered(
                Box::new(MuxStreamConn::new(stream, session.clone())),
                peer_addr,
                local_addr,
            );

            let inner = self.inner.clone();
            let cancel = self.cancel.clone();
            let tag = self.tag;
            let peer = peer.clone();

            // Each stream is its own task, so one handler's error — or one
            // slow stream — cannot stop the session from accepting the next.
            self.tracker.spawn(async move {
                tokio::select! {
                    result = inner.handle(conn) => {
                        if let Err(e) = result {
                            debug!("[{}] {} stream {} : {}", tag, peer, sid, e);
                        }
                    }
                    _ = cancel.cancelled() => {
                        debug!("[{}] {} stream {} : cancelled", tag, peer, sid);
                    }
                }
            });
        }

        debug!("[{}] {} >-< {} : session down", self.tag, peer, local);
        Ok(())
    }
}

/// Listener for the multiplexed transports `mtls`, `mws` and `mwss`.
///
/// One accepted socket becomes one smux session and every stream on it is
/// dispatched to the handler separately, so a single client connection can
/// carry any number of concurrent proxy requests.
///
/// The lifecycle mirrors [`TlsServer`](crate::tls_listener::TlsServer)
/// exactly: the same accept backoff, the same [`cancel_token`](Self::cancel_token),
/// the same [`TaskTracker`] drain on shutdown. Session accept loops and stream
/// handlers both run on that tracker, so `serve` returns only once every
/// stream in flight has finished.
///
/// The layerings are stacked the way [`WsServer::new_tls`](crate::ws::WsServer::new_tls)
/// stacks `wss`: TLS is terminated first and the WebSocket handshake runs
/// inside it, rather than either layer owning a socket of its own.
pub struct MuxServer {
    listener: TcpListener,
    /// `Some` for `mtls` and `mwss`.
    tls: Option<TlsAcceptor>,
    /// [`MuxHandler`] for `mtls`, `WsHandler(MuxHandler)` for `mws`/`mwss`.
    pipeline: Arc<dyn Handler>,
    sessions: SessionCount,
    tag: &'static str,
    cancel: CancellationToken,
    tracker: TaskTracker,
}

impl MuxServer {
    /// `mtls`: TLS, then smux (gost's `MTLSListener`, tls.go:169-190).
    ///
    /// The rustls configuration is built exactly as for
    /// [`TlsServer`](crate::tls_listener::TlsServer) — see
    /// [`server_config_from_pem`](crate::tls_listener::server_config_from_pem).
    pub async fn new_mtls(
        addr: &str,
        tls_config: ServerConfig,
        mux_config: MuxConfig,
        handler: impl Handler + 'static,
    ) -> Result<Self, BoxError> {
        // Fail here rather than on the first connection, where an unsupported
        // smux version would look like a hang.
        mux_config.verify()?;

        let listener = TcpListener::bind(addr).await?;
        let cancel = CancellationToken::new();
        let tracker = TaskTracker::new();
        let sessions = SessionCount::default();

        let pipeline: Arc<dyn Handler> = Arc::new(MuxHandler::new(handler, mux_config).with_lifecycle(
            "mtls",
            sessions.clone(),
            tracker.clone(),
            cancel.clone(),
        ));

        info!("MTLS listening on {}", listener.local_addr()?);

        Ok(Self {
            listener,
            tls: Some(TlsAcceptor::from(Arc::new(tls_config))),
            pipeline,
            sessions,
            tag: "mtls",
            cancel,
            tracker,
        })
    }

    /// `mws`: WebSocket, then smux (gost's `MWSListener`, ws.go:447-506).
    pub async fn new_mws(
        addr: &str,
        options: WsOptions,
        mux_config: MuxConfig,
        handler: impl Handler + 'static,
    ) -> Result<Self, BoxError> {
        Self::build_ws(addr, options, None, mux_config, "mws", handler).await
    }

    /// `mwss`: TLS, then WebSocket, then smux (gost's `MWSSListener`,
    /// ws.go:636-700).
    pub async fn new_mwss(
        addr: &str,
        options: WsOptions,
        tls_config: ServerConfig,
        mux_config: MuxConfig,
        handler: impl Handler + 'static,
    ) -> Result<Self, BoxError> {
        Self::build_ws(
            addr,
            options,
            Some(TlsAcceptor::from(Arc::new(tls_config))),
            mux_config,
            "mwss",
            handler,
        )
        .await
    }

    async fn build_ws(
        addr: &str,
        options: WsOptions,
        tls: Option<TlsAcceptor>,
        mux_config: MuxConfig,
        tag: &'static str,
        handler: impl Handler + 'static,
    ) -> Result<Self, BoxError> {
        mux_config.verify()?;

        let listener = TcpListener::bind(addr).await?;
        let cancel = CancellationToken::new();
        let tracker = TaskTracker::new();
        let sessions = SessionCount::default();
        let path = options.resolved_path();

        // The WebSocket upgrade is reused from the `ws` transport rather than
        // reimplemented: it already serves exactly the configured path and 404s
        // everything else, and it passes the client's addresses through.
        let muxer = MuxHandler::new(handler, mux_config).with_lifecycle(
            tag,
            sessions.clone(),
            tracker.clone(),
            cancel.clone(),
        );
        let pipeline: Arc<dyn Handler> = Arc::new(WsHandler::new(muxer, options));

        info!(
            "{} listening on {} (path {})",
            tag.to_uppercase(),
            listener.local_addr()?,
            path
        );

        Ok(Self {
            listener,
            tls,
            pipeline,
            sessions,
            tag,
            cancel,
            tracker,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// A handle to the number of sessions accepted so far. Taken before
    /// [`serve`](Self::serve), which consumes the listener.
    pub fn session_count(&self) -> SessionCount {
        self.sessions.clone()
    }

    /// Accepts connections, turns each into an smux session and dispatches
    /// every stream on it to the handler.
    pub async fn serve(self) -> Result<(), BoxError> {
        let tag = self.tag;
        let mut temp_delay = Duration::ZERO;

        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => {
                    info!("[{}] shutdown signal received, draining connections...", tag);
                    break;
                }
                result = self.listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            temp_delay = Duration::ZERO;
                            let tls = self.tls.clone();
                            let pipeline = self.pipeline.clone();
                            let cancel = self.cancel.clone();
                            // Captured before the socket is consumed by the
                            // TLS session, so the handler still sees the real
                            // client and listener addresses.
                            let local_addr = stream.local_addr().ok();

                            // The session accept loop is this task; the streams
                            // it dispatches are spawned on the same tracker, so
                            // shutdown drains both.
                            self.tracker.spawn(async move {
                                let inner: Box<dyn AsyncStream> = match tls {
                                    Some(acceptor) => match acceptor.accept(stream).await {
                                        Ok(s) => Box::new(s),
                                        Err(e) => {
                                            // A failed handshake is routine:
                                            // port scanners and plaintext
                                            // clients cause it.
                                            debug!("[{}] handshake failed from {}: {}", tag, peer_addr, e);
                                            return;
                                        }
                                    },
                                    None => Box::new(stream),
                                };

                                let conn = ProxyConn::layered(inner, Some(peer_addr), local_addr);

                                tokio::select! {
                                    result = pipeline.handle(conn) => {
                                        if let Err(e) = result {
                                            debug!("[{}] {} : {}", tag, peer_addr, e);
                                        }
                                    }
                                    _ = cancel.cancelled() => {
                                        debug!("[{}] {} : cancelled", tag, peer_addr);
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            if temp_delay.is_zero() {
                                temp_delay = Duration::from_millis(5);
                            } else {
                                temp_delay *= 2;
                            }
                            if temp_delay > Duration::from_secs(1) {
                                temp_delay = Duration::from_secs(1);
                            }
                            error!("[{}] accept error: {}; retrying in {:?}", tag, e, temp_delay);
                            tokio::time::sleep(temp_delay).await;
                        }
                    }
                }
            }
        }

        self.tracker.close();
        self.tracker.wait().await;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

/// A boxed future producing a fresh inner transport.
type TransportFuture = Pin<Box<dyn Future<Output = Result<Box<dyn AsyncStream>, BoxError>> + Send>>;

/// The closure a [`MuxDialer`] calls when it needs a new transport to run a
/// session over.
type TransportFactory = Arc<dyn Fn() -> TransportFuture + Send + Sync>;

/// The client half of the multiplexed transports: one session, a stream per
/// dial.
///
/// gost keeps a session per node and opens a stream on it for every dial
/// (tls.go:52-118, ws.go:83-149). That is the whole point of `mtls`/`mws`/`mwss`
/// — a dialer that built a session per dial would pay for smux and get nothing
/// back — so this caches the session and rebuilds it only when it dies.
///
/// The transport is supplied by a closure, so a caller can hand over any stack
/// (TCP, TCP+TLS, TCP+TLS+WebSocket, or a stream a previous chain hop
/// produced) without this module knowing how to dial.
///
/// Safe to share across tasks: concurrent dials on a cold cache produce one
/// session, not one per caller.
pub struct MuxDialer {
    config: MuxConfig,
    factory: TransportFactory,
    /// The live session. A plain mutex, held only long enough to clone the
    /// `Arc` out, so warm dials never serialise behind each other.
    cached: Mutex<Option<Arc<MuxSession>>>,
    /// Held across the transport dial and handshake, so only one task builds a
    /// session at a time. This is gost's `sessionMutex` (tls.go:59, 97).
    build_lock: tokio::sync::Mutex<()>,
    built: AtomicU64,
    label: String,
}

impl MuxDialer {
    /// `config` is verified up front, so an unsupported `?smuxver=` is an error
    /// here rather than a stalled dial later.
    ///
    /// `factory` must produce a *fresh* transport on every call: it is invoked
    /// once per session, not once per dial.
    pub fn new<F, Fut, S>(config: MuxConfig, factory: F) -> Result<Self, BoxError>
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<S, BoxError>> + Send + 'static,
        S: AsyncStream + 'static,
    {
        config.verify()?;

        let factory: TransportFactory = Arc::new(move || {
            let fut = factory();
            Box::pin(async move { fut.await.map(|s| Box::new(s) as Box<dyn AsyncStream>) })
        });

        Ok(Self {
            config,
            factory,
            cached: Mutex::new(None),
            build_lock: tokio::sync::Mutex::new(()),
            built: AtomicU64::new(0),
            label: String::new(),
        })
    }

    /// A name for the logs, usually the node address.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }

    /// Opens a stream on the cached session, building one first if there is
    /// none or the cached one is dead.
    ///
    /// The rebuild is transparent and happens at most once per call: if the
    /// session that was just built cannot open a stream either, that error is
    /// returned rather than looping.
    pub async fn dial(&self) -> Result<MuxStreamConn, BoxError> {
        // Warm path. No build lock: an established session opens a stream with
        // no round trip, so serialising here would be pure contention.
        if let Some(session) = self.live_session() {
            match session.open_stream().await {
                Ok(stream) => return Ok(MuxStreamConn::new(stream, session)),
                Err(e) => debug!(
                    "[mux] {}: the cached session refused a stream ({}), rebuilding",
                    self.label, e
                ),
            }
        }

        // Cold or dead. One builder at a time, so two concurrent first dials
        // produce one session rather than racing to replace each other's.
        let _guard = self.build_lock.lock().await;

        // Re-check under the lock: the task that held it may have built the
        // session we were about to build.
        if let Some(session) = self.live_session() {
            if let Ok(stream) = session.open_stream().await {
                return Ok(MuxStreamConn::new(stream, session));
            }
        }

        let transport = (self.factory)().await?;
        let session = Arc::new(MuxSession::client(transport, self.config.clone())?);
        self.built.fetch_add(1, Ordering::Relaxed);

        // Only publish a session that works. Otherwise a session that died
        // during the handshake would be handed to the next caller as live.
        let stream = session.open_stream().await?;
        *self.cached.lock().unwrap() = Some(session.clone());
        debug!(
            "[mux] {}: session {} up",
            self.label,
            self.built.load(Ordering::Relaxed)
        );

        Ok(MuxStreamConn::new(stream, session))
    }

    /// The cached session if it is still usable. A dead one is evicted on the
    /// way past, as gost does with `delete(tr.sessions, addr)` (tls.go:63).
    fn live_session(&self) -> Option<Arc<MuxSession>> {
        let mut cached = self.cached.lock().unwrap();
        match cached.as_ref() {
            Some(session) if !session.is_closed() => Some(session.clone()),
            Some(_) => {
                *cached = None;
                None
            }
            None => None,
        }
    }

    /// Sessions built since this dialer was created. One, however many dials
    /// have been made, unless a session died in between.
    pub fn sessions_built(&self) -> u64 {
        self.built.load(Ordering::Relaxed)
    }

    pub fn has_live_session(&self) -> bool {
        self.live_session().is_some()
    }

    /// Streams open on the cached session.
    pub fn num_streams(&self) -> usize {
        self.live_session().map(|s| s.num_streams()).unwrap_or(0)
    }

    /// Closes the cached session, ending every stream on it.
    ///
    /// The dead session is deliberately left in the cache: the next dial
    /// notices it is closed and rebuilds, which is the same path a session
    /// dying because the peer went away takes.
    pub fn close(&self) {
        if let Some(session) = self.cached.lock().unwrap().as_ref() {
            session.close();
        }
    }
}

impl std::fmt::Debug for MuxDialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MuxDialer")
            .field("label", &self.label)
            .field("sessions_built", &self.sessions_built())
            .field("live", &self.cached.lock().map(|c| c.is_some()).unwrap_or(false))
            .finish()
    }
}

/// One [`MuxDialer`] per key, which is gost's `sessions map[string]*muxSession`
/// (tls.go:43) with the key being the node address.
///
/// A chain or connector holds one of these for the whole process and asks it
/// for the dialer belonging to the hop it is about to use, so the session for
/// that hop is shared by every request that crosses it.
pub struct MuxDialerPool {
    dialers: Mutex<HashMap<String, Arc<MuxDialer>>>,
}

impl std::fmt::Debug for MuxDialerPool {
    // Hand-written because a dialer holds closures and live sessions, neither
    // of which is Debug. `Chain` derives Debug and holds a pool, so it needs
    // one; the key set is the only useful thing to show.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let keys: Vec<String> = match self.dialers.lock() {
            Ok(map) => map.keys().cloned().collect(),
            Err(poisoned) => poisoned.into_inner().keys().cloned().collect(),
        };
        f.debug_struct("MuxDialerPool").field("nodes", &keys).finish()
    }
}

impl MuxDialerPool {
    pub fn new() -> Self {
        Self {
            dialers: Mutex::new(HashMap::new()),
        }
    }

    /// The dialer for `key`, creating it with `factory` the first time.
    /// `factory` is ignored when one already exists.
    pub fn get_or_create<F, Fut, S>(
        &self,
        key: &str,
        config: MuxConfig,
        factory: F,
    ) -> Result<Arc<MuxDialer>, BoxError>
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<S, BoxError>> + Send + 'static,
        S: AsyncStream + 'static,
    {
        let mut dialers = self.dialers.lock().unwrap();
        if let Some(dialer) = dialers.get(key) {
            return Ok(dialer.clone());
        }
        let dialer = Arc::new(MuxDialer::new(config, factory)?.with_label(key.to_string()));
        dialers.insert(key.to_string(), dialer.clone());
        Ok(dialer)
    }

    /// Drops the dialer for `key`, closing its session.
    pub fn remove(&self, key: &str) -> Option<Arc<MuxDialer>> {
        let removed = self.dialers.lock().unwrap().remove(key);
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
}

impl Default for MuxDialerPool {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Configuration from node parameters
// ---------------------------------------------------------------------------

/// Builds a [`MuxConfig`] from gost's smux node parameters.
///
/// Zero means "not set" for every field, exactly as in gost's `KCPConfig.Init`
/// (kcp.go:137-146), and the smux defaults are used instead — `mtls`, `mws` and
/// `mwss` themselves always use `smux.DefaultConfig()` (tls.go:130-133,
/// ws.go:172-175), so an unparameterised node is byte-for-byte compatible with
/// a stock gost peer.
///
/// The version is checked here: only smux v1 is implemented, and v2 without
/// its `cmdUPD` window updates would stall as soon as the peer's initial
/// window ran out, so it is refused rather than left to hang.
///
/// `keepalive_secs` sets the interval only, as gost does (kcp.go:253). smux's
/// `VerifyConfig` requires the timeout — 30s, untouched by gost — to be at
/// least the interval, so a keepalive above 30 is rejected here just as
/// `smux.VerifyConfig` rejects it there.
pub fn mux_config_from_values(
    smux_ver: u32,
    smux_buf: usize,
    stream_buf: usize,
    keepalive_secs: u64,
) -> io::Result<MuxConfig> {
    let defaults = MuxConfig::default();

    if smux_ver > u8::MAX as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("smux: unsupported protocol version {}", smux_ver),
        ));
    }

    let config = MuxConfig {
        version: if smux_ver == 0 {
            VERSION_1
        } else {
            smux_ver as u8
        },
        max_receive_buffer: if smux_buf == 0 {
            defaults.max_receive_buffer
        } else {
            smux_buf
        },
        max_stream_buffer: if stream_buf == 0 {
            defaults.max_stream_buffer
        } else {
            stream_buf
        },
        keep_alive_interval: if keepalive_secs == 0 {
            defaults.keep_alive_interval
        } else {
            Duration::from_secs(keepalive_secs)
        },
        ..defaults
    };

    config.verify()?;
    Ok(config)
}

/// [`mux_config_from_values`] driven by a node's query parameters:
/// `?smuxver=`, `?smuxbuf=`, `?streambuf=` and `?keepalive=`.
pub fn mux_config_from_node(node: &Node) -> io::Result<MuxConfig> {
    fn non_negative(value: i64) -> u64 {
        value.max(0) as u64
    }

    mux_config_from_values(
        non_negative(node.get_int("smuxver")) as u32,
        non_negative(node.get_int("smuxbuf")) as usize,
        non_negative(node.get_int("streambuf")) as usize,
        non_negative(node.get_int("keepalive")),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// Anything that hangs would block the whole (single-threaded) run, so
    /// reads are bounded and fail loudly instead.
    const READ_TIMEOUT: Duration = Duration::from_secs(10);

    /// Echoes what it reads, so the transport is shown to carry an arbitrary
    /// inner protocol. A payload starting with `FAIL` is refused, which is how
    /// a handler error is provoked on one stream while the rest keep going.
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
                if buf[..n].starts_with(b"FAIL") {
                    return Err(HandlerError::Proxy("refused by the test handler".to_string()));
                }
                if conn.write_all(&buf[..n]).await.is_err() {
                    break;
                }
                conn.flush().await.ok();
            }
            Ok(())
        }
    }

    /// A running listener: its address, its shutdown switch, and a live view of
    /// how many sessions it has accepted.
    struct RunningServer {
        addr: SocketAddr,
        cancel: CancellationToken,
        sessions: SessionCount,
    }

    fn spawn(server: MuxServer) -> RunningServer {
        let addr = server.local_addr().unwrap();
        let cancel = server.cancel_token();
        let sessions = server.session_count();
        tokio::spawn(async move {
            server.serve().await.ok();
        });
        RunningServer {
            addr,
            cancel,
            sessions,
        }
    }

    async fn start_mtls() -> RunningServer {
        let (tls, _cert) = crate::tls_listener::self_signed_config("localhost").unwrap();
        spawn(
            MuxServer::new_mtls("127.0.0.1:0", tls, MuxConfig::default(), EchoHandler)
                .await
                .unwrap(),
        )
    }

    async fn start_mws() -> RunningServer {
        spawn(
            MuxServer::new_mws(
                "127.0.0.1:0",
                WsOptions::default(),
                MuxConfig::default(),
                EchoHandler,
            )
            .await
            .unwrap(),
        )
    }

    async fn start_mwss() -> RunningServer {
        let (tls, _cert) = crate::tls_listener::self_signed_config("localhost").unwrap();
        spawn(
            MuxServer::new_mwss(
                "127.0.0.1:0",
                WsOptions::default(),
                tls,
                MuxConfig::default(),
                EchoHandler,
            )
            .await
            .unwrap(),
        )
    }

    /// Counts the TCP connections a dialer actually opens. Nothing else
    /// connects to these listeners, so this is the number of connections the
    /// listener accepted.
    type DialCount = Arc<AtomicU64>;

    fn mtls_dialer(addr: SocketAddr, dials: DialCount) -> MuxDialer {
        MuxDialer::new(MuxConfig::default(), move || {
            let dials = dials.clone();
            async move {
                let tcp = TcpStream::connect(addr).await?;
                dials.fetch_add(1, Ordering::Relaxed);
                let tls = crate::tls_transport::tls_connect_stream(tcp, "localhost", true).await?;
                Ok::<_, BoxError>(tls)
            }
        })
        .unwrap()
        .with_label("mtls-test")
    }

    fn mws_dialer(addr: SocketAddr, dials: DialCount) -> MuxDialer {
        MuxDialer::new(MuxConfig::default(), move || {
            let dials = dials.clone();
            async move {
                let tcp = TcpStream::connect(addr).await?;
                dials.fetch_add(1, Ordering::Relaxed);
                let ws =
                    crate::ws::ws_connect_stream(tcp, &addr.to_string(), "", &WsOptions::default())
                        .await?;
                Ok::<_, BoxError>(ws)
            }
        })
        .unwrap()
        .with_label("mws-test")
    }

    fn mwss_dialer(addr: SocketAddr, dials: DialCount) -> MuxDialer {
        MuxDialer::new(MuxConfig::default(), move || {
            let dials = dials.clone();
            async move {
                let tcp = TcpStream::connect(addr).await?;
                dials.fetch_add(1, Ordering::Relaxed);
                let tls = crate::tls_transport::tls_connect_stream(tcp, "localhost", true).await?;
                let ws = crate::ws::ws_connect_stream(tls, "localhost", "", &WsOptions::default())
                    .await?;
                Ok::<_, BoxError>(ws)
            }
        })
        .unwrap()
        .with_label("mwss-test")
    }

    async fn echo(stream: &mut MuxStreamConn, payload: &[u8]) -> Vec<u8> {
        stream.write_all(payload).await.unwrap();
        stream.flush().await.unwrap();
        read_exactly(stream, payload.len()).await
    }

    async fn read_exactly(stream: &mut MuxStreamConn, n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        tokio::time::timeout(READ_TIMEOUT, stream.read_exact(&mut buf))
            .await
            .expect("timed out waiting for the echo")
            .unwrap();
        buf
    }

    /// The contract shared by all three layerings: two dials, two independent
    /// streams, one TCP connection.
    async fn assert_two_streams_share_one_session(
        dialer: &MuxDialer,
        dials: &DialCount,
        server: &RunningServer,
    ) {
        let mut first = dialer.dial().await.unwrap();
        let mut second = dialer.dial().await.unwrap();
        assert_ne!(first.id(), second.id(), "each dial must be its own stream");

        // Interleaved on purpose: a session that crossed its streams' data
        // would pass a strictly sequential test.
        first.write_all(b"alpha").await.unwrap();
        second.write_all(b"bravo").await.unwrap();
        first.flush().await.unwrap();
        second.flush().await.unwrap();

        assert_eq!(read_exactly(&mut first, 5).await, b"alpha");
        assert_eq!(read_exactly(&mut second, 5).await, b"bravo");

        // The whole point of the multiplexed transports. Without this, the two
        // round trips above would pass over two ordinary connections.
        assert_eq!(
            dials.load(Ordering::Relaxed),
            1,
            "two dials must share one TCP connection"
        );
        assert_eq!(dialer.sessions_built(), 1);
        assert_eq!(
            server.sessions.get(),
            1,
            "the listener must have accepted exactly one session"
        );

        // And more data still flows on both afterwards.
        assert_eq!(echo(&mut first, b"one more").await, b"one more");
        assert_eq!(echo(&mut second, b"and here").await, b"and here");
    }

    #[tokio::test]
    async fn test_mtls_two_streams_over_one_session() {
        let server = start_mtls().await;
        let dials: DialCount = Arc::new(AtomicU64::new(0));
        let dialer = mtls_dialer(server.addr, dials.clone());

        assert_two_streams_share_one_session(&dialer, &dials, &server).await;
        server.cancel.cancel();
    }

    #[tokio::test]
    async fn test_mws_two_streams_over_one_session() {
        let server = start_mws().await;
        let dials: DialCount = Arc::new(AtomicU64::new(0));
        let dialer = mws_dialer(server.addr, dials.clone());

        assert_two_streams_share_one_session(&dialer, &dials, &server).await;
        server.cancel.cancel();
    }

    #[tokio::test]
    async fn test_mwss_two_streams_over_one_session() {
        let server = start_mwss().await;
        let dials: DialCount = Arc::new(AtomicU64::new(0));
        let dialer = mwss_dialer(server.addr, dials.clone());

        assert_two_streams_share_one_session(&dialer, &dials, &server).await;
        server.cancel.cancel();
    }

    #[tokio::test]
    async fn test_mws_serves_only_its_path() {
        // The WebSocket layer is the `ws` transport's, so `mws` inherits gost's
        // /ws default and its 404 for anything else.
        let server = start_mws().await;
        let tcp = TcpStream::connect(server.addr).await.unwrap();
        let err = match
            crate::ws::ws_connect_stream(tcp, &server.addr.to_string(), "/", &WsOptions::default())
                .await
        {
            Ok(_) => panic!("the wrong path must not be upgraded"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("404"), "expected a 404, got: {}", err);
        assert_eq!(server.sessions.get(), 0, "a failed upgrade is not a session");
        server.cancel.cancel();
    }

    #[tokio::test]
    async fn test_a_dead_session_is_rebuilt_on_the_next_dial() {
        let server = start_mtls().await;
        let dials: DialCount = Arc::new(AtomicU64::new(0));
        let dialer = mtls_dialer(server.addr, dials.clone());

        let mut first = dialer.dial().await.unwrap();
        assert_eq!(echo(&mut first, b"one").await, b"one");

        // Kill the session the way a peer going away would. The dead session
        // stays in the cache, so the next dial has to notice it itself.
        dialer.close();
        assert!(first.session().is_closed());
        assert!(!dialer.has_live_session());

        let mut second = dialer.dial().await.unwrap();
        assert_eq!(echo(&mut second, b"two").await, b"two");

        assert_eq!(dialer.sessions_built(), 2, "the dead session must be replaced");
        assert_eq!(dials.load(Ordering::Relaxed), 2);
        // Proof the rebuild reached the network rather than being papered over
        // locally: the listener saw a second connection and handshake.
        assert_eq!(server.sessions.get(), 2);

        server.cancel.cancel();
    }

    // Genuinely parallel, not just interleaved: the double-checked cache and
    // the build lock have to hold with the dials running on several threads.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_cold_dials_build_one_session() {
        let server = start_mtls().await;
        let dials: DialCount = Arc::new(AtomicU64::new(0));
        let dialer = Arc::new(mtls_dialer(server.addr, dials.clone()));

        // All of these start with an empty cache. Without the build lock they
        // would each dial their own transport and the last one would win.
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

        assert_eq!(dialer.sessions_built(), 1, "concurrent cold dials built more than one session");
        assert_eq!(dials.load(Ordering::Relaxed), 1);
        assert_eq!(server.sessions.get(), 1);

        server.cancel.cancel();
    }

    #[tokio::test]
    async fn test_a_handler_error_leaves_the_session_working() {
        let server = start_mtls().await;
        let dials: DialCount = Arc::new(AtomicU64::new(0));
        let dialer = mtls_dialer(server.addr, dials.clone());

        let mut good = dialer.dial().await.unwrap();
        let mut doomed = dialer.dial().await.unwrap();

        // The handler returns an error, which ends this stream and nothing
        // else: the client sees a clean EOF rather than a dead session.
        doomed.write_all(b"FAIL please").await.unwrap();
        doomed.flush().await.unwrap();
        let mut sink = [0u8; 16];
        let n = tokio::time::timeout(READ_TIMEOUT, doomed.read(&mut sink))
            .await
            .expect("the failing stream never finished")
            .unwrap();
        assert_eq!(n, 0, "a refused stream must end, not deliver data");

        // The stream opened before the failure still works...
        assert_eq!(echo(&mut good, b"still here").await, b"still here");
        // ...and so does one opened after it, on the same session.
        let mut later = dialer.dial().await.unwrap();
        assert_eq!(echo(&mut later, b"and later").await, b"and later");

        assert!(dialer.has_live_session());
        assert_eq!(dialer.sessions_built(), 1);
        assert_eq!(server.sessions.get(), 1, "the session must have survived");

        server.cancel.cancel();
    }

    #[tokio::test]
    async fn test_streams_carry_payloads_larger_than_one_frame() {
        // 300 KiB crosses smux's 32 KiB frame size and the WebSocket layer's
        // 64 KiB frame cap, so both splitters are exercised.
        let server = start_mwss().await;
        let dials: DialCount = Arc::new(AtomicU64::new(0));
        let dialer = mwss_dialer(server.addr, dials.clone());

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

        assert_eq!(dials.load(Ordering::Relaxed), 1);
        server.cancel.cancel();
    }

    #[tokio::test]
    async fn test_cancelling_the_listener_drains_and_returns() {
        let (tls, _cert) = crate::tls_listener::self_signed_config("localhost").unwrap();
        let server = MuxServer::new_mtls("127.0.0.1:0", tls, MuxConfig::default(), EchoHandler)
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let cancel = server.cancel_token();
        let served = tokio::spawn(async move { server.serve().await });

        let dials: DialCount = Arc::new(AtomicU64::new(0));
        let dialer = mtls_dialer(addr, dials);
        let mut stream = dialer.dial().await.unwrap();
        assert_eq!(echo(&mut stream, b"up").await, b"up");

        cancel.cancel();
        tokio::time::timeout(READ_TIMEOUT, served)
            .await
            .expect("serve did not return after cancellation")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn test_a_dialer_pool_keeps_one_dialer_per_key() {
        let server = start_mtls().await;
        let pool = MuxDialerPool::new();
        let dials: DialCount = Arc::new(AtomicU64::new(0));
        let addr = server.addr;
        let key = addr.to_string();

        for _ in 0..3 {
            let dials = dials.clone();
            let dialer = pool
                .get_or_create(&key, MuxConfig::default(), move || {
                    let dials = dials.clone();
                    async move {
                        let tcp = TcpStream::connect(addr).await?;
                        dials.fetch_add(1, Ordering::Relaxed);
                        let tls =
                            crate::tls_transport::tls_connect_stream(tcp, "localhost", true).await?;
                        Ok::<_, BoxError>(tls)
                    }
                })
                .unwrap();
            let mut stream = dialer.dial().await.unwrap();
            assert_eq!(echo(&mut stream, b"pooled").await, b"pooled");
        }

        assert_eq!(pool.len(), 1);
        assert_eq!(dials.load(Ordering::Relaxed), 1, "one session for the whole key");
        assert_eq!(server.sessions.get(), 1);

        pool.remove(&key);
        assert!(pool.is_empty());
        server.cancel.cancel();
    }

    #[test]
    fn test_default_mux_config_is_the_gost_default() {
        // mtls/mws/mwss use smux.DefaultConfig() verbatim, so an
        // unparameterised node must land exactly there.
        let config = mux_config_from_values(0, 0, 0, 0).unwrap();
        let defaults = MuxConfig::default();
        assert_eq!(config.version, 1);
        assert_eq!(config.max_receive_buffer, defaults.max_receive_buffer);
        assert_eq!(config.max_stream_buffer, defaults.max_stream_buffer);
        assert_eq!(config.keep_alive_interval, defaults.keep_alive_interval);
        assert_eq!(config.keep_alive_timeout, defaults.keep_alive_timeout);
    }

    #[test]
    fn test_mux_config_reads_the_node_parameters() {
        let node = Node::parse(
            "mtls://127.0.0.1:1080?smuxver=1&smuxbuf=1048576&streambuf=65536&keepalive=15",
        )
        .unwrap();
        let config = mux_config_from_node(&node).unwrap();
        assert_eq!(config.version, 1);
        assert_eq!(config.max_receive_buffer, 1_048_576);
        assert_eq!(config.max_stream_buffer, 65_536);
        assert_eq!(config.keep_alive_interval, Duration::from_secs(15));
    }

    #[test]
    fn test_an_unsupported_smux_version_is_an_error_not_a_stall() {
        // smux v2 needs cmdUPD window updates; advertising it without them
        // would hang the moment the peer's initial window ran out.
        let node = Node::parse("mtls://127.0.0.1:1080?smuxver=2").unwrap();
        let err = mux_config_from_node(&node).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);

        let err = mux_config_from_values(3, 0, 0, 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let err = mux_config_from_values(300, 0, 0, 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        // And the same error reaches the constructors rather than a later dial.
        let bad = MuxConfig::default().with_version(2);
        assert!(MuxDialer::new(bad.clone(), || async {
            Ok::<_, BoxError>(tokio::io::duplex(64).0)
        })
        .is_err());
    }

    #[tokio::test]
    async fn test_an_unsupported_smux_version_is_refused_by_the_listener() {
        let (tls, _cert) = crate::tls_listener::self_signed_config("localhost").unwrap();
        assert!(MuxServer::new_mtls(
            "127.0.0.1:0",
            tls,
            MuxConfig::default().with_version(2),
            EchoHandler
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn test_an_erased_transport_factory_dials_like_a_chain_hop() {
        // The shape a chain hop needs: one factory that branches on the hop's
        // transport and hands back an erased stream, and a stream that drops
        // straight into a ProxyConn for the hop's protocol connector.
        let server = start_mwss().await;
        let addr = server.addr;
        let transport = "mwss".to_string();

        let dialer = MuxDialer::new(MuxConfig::default(), move || {
            let transport = transport.clone();
            async move {
                let tcp = TcpStream::connect(addr).await?;
                let inner: Box<dyn AsyncStream> = match transport.as_str() {
                    "mtls" => Box::new(
                        crate::tls_transport::tls_connect_stream(tcp, "localhost", true).await?,
                    ),
                    "mws" => Box::new(
                        crate::ws::ws_connect_stream(
                            tcp,
                            &addr.to_string(),
                            "",
                            &WsOptions::default(),
                        )
                        .await?,
                    ),
                    _ => {
                        let tls =
                            crate::tls_transport::tls_connect_stream(tcp, "localhost", true).await?;
                        Box::new(
                            crate::ws::ws_connect_stream(tls, "localhost", "", &WsOptions::default())
                                .await?,
                        )
                    }
                };
                Ok::<_, BoxError>(inner)
            }
        })
        .unwrap();

        let mut stream = dialer.dial().await.unwrap();
        assert_eq!(echo(&mut stream, b"erased").await, b"erased");

        let mut conn = ProxyConn::layered(Box::new(dialer.dial().await.unwrap()), None, None);
        conn.write_all(b"hop").await.unwrap();
        conn.flush().await.unwrap();
        let mut got = [0u8; 3];
        tokio::time::timeout(READ_TIMEOUT, conn.read_exact(&mut got))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&got, b"hop");

        assert_eq!(server.sessions.get(), 1);
        server.cancel.cancel();
    }

    #[tokio::test]
    async fn test_a_dial_error_is_reported_and_leaves_no_session() {
        // Nothing is listening on the address the factory dials.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let dialer = MuxDialer::new(MuxConfig::default(), move || async move {
            let tcp = TcpStream::connect(addr).await?;
            Ok::<_, BoxError>(tcp)
        })
        .unwrap();

        assert!(dialer.dial().await.is_err());
        assert!(!dialer.has_live_session());
        assert_eq!(dialer.sessions_built(), 0);
    }
}
