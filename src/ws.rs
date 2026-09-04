//! WebSocket transport.
//!
//! In gost, `ws` is a *transport*, not a proxy protocol (ws.go:412-429,
//! 760-807): the WebSocket connection carries an inner proxy protocol (http,
//! socks5, ...) transparently as a stream of binary frames. There is no
//! address-in-the-first-message convention, and this module deliberately does
//! not invent one — an earlier revision did, which made it incompatible with
//! every real `ws://` peer.
//!
//! The pieces are:
//!
//! * [`WsStream`] — an `AsyncRead + AsyncWrite` byte stream over binary
//!   frames, so any [`Handler`] can serve a WebSocket connection unmodified.
//! * [`WsServer`] — a listener that performs the server handshake (honouring
//!   the configured path, optionally after terminating TLS for `wss`) and
//!   dispatches a [`ProxyConn`] to a handler, exactly like
//!   [`TlsServer`](crate::tls_listener::TlsServer).
//! * [`ws_connect_stream`] — the client half, layered over an arbitrary
//!   stream so `wss` composes as TLS-then-WebSocket rather than needing a
//!   socket of its own.
//! * [`WsHandler`] — the same upgrade expressed as a [`Handler`] that wraps
//!   another handler, for callers that compose handlers instead of listeners.
//!
//! `mws`/`mwss` (the smux-multiplexed variants) are not implemented.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::{Sink, Stream};
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::error::ProtocolError;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::header::{CONTENT_LENGTH, CONTENT_TYPE, USER_AGENT};
use tokio_tungstenite::tungstenite::http::{HeaderValue, StatusCode};
use tokio_tungstenite::tungstenite::protocol::{Message, WebSocketConfig};
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::{accept_hdr_async_with_config, client_async_with_config, WebSocketStream};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info, warn};

use crate::conn::{AsyncStream, ProxyConn};
use crate::handler::{Handler, HandlerError};

/// gost's `defaultWSPath` (ws.go:23), applied on both sides at ws.go:61-64,
/// 168-171, 218-221, 328-331 and 378-381.
///
/// A stock gost `ws://` server registers exactly this path on its mux and
/// 404s everything else, so defaulting to `/` — as this module once did —
/// means every handshake against a real gost server fails.
pub const DEFAULT_WS_PATH: &str = "/ws";

/// gost's `ReadHeaderTimeout` for the ws listeners (ws.go:387).
const DEFAULT_SERVER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// The most payload bytes put into a single outbound frame.
///
/// gost sends one message per `Write` whatever its size (ws.go:776-780). One
/// frame per `poll_write` is the same thing for every buffer a relay actually
/// uses (this crate's largest is 32 KiB), but an unbounded write would build
/// a message the peer may refuse: tungstenite's default `max_message_size` is
/// 64 MiB. Capping keeps a huge write legal — `poll_write` reports the short
/// count and the caller loops, which is the `AsyncWrite` contract.
const MAX_WRITE_FRAME: usize = 64 * 1024;

/// WebSocket options, mirroring gost's `WSOptions` (ws.go:27-34).
#[derive(Clone, Debug)]
pub struct WsOptions {
    /// The HTTP path the handshake uses. Empty means [`DEFAULT_WS_PATH`].
    pub path: String,
    /// No tungstenite equivalent: its `WebSocketConfig` has no read-buffer
    /// knob (reads go through a fixed internal chunk). Kept for CLI parity so
    /// `?rbuf=` parses, but it does not reach the protocol.
    pub read_buffer_size: usize,
    /// Mapped to `WebSocketConfig::write_buffer_size`. Note the semantics
    /// differ slightly from gorilla's: tungstenite treats it as the fill
    /// level to reach before pushing to the socket, so `0` (the default)
    /// means "write every frame straight through", which is what gorilla's
    /// `WriteMessage` does.
    pub write_buffer_size: usize,
    /// Applied with `tokio::time::timeout` around the handshake; tungstenite
    /// has no timeout of its own. Zero means the default (5s dialling,
    /// 30s accepting, matching gost).
    pub handshake_timeout: Duration,
    /// No tungstenite equivalent: tungstenite 0.24 does not implement
    /// permessage-deflate at all. Setting it logs a warning rather than
    /// silently pretending compression is on.
    pub enable_compression: bool,
    /// Sent on the client handshake. Empty means [`crate::DEFAULT_USER_AGENT`]
    /// (`Chrome/78.0.3904.106`), which is what gost always sends (ws.go:747-751).
    pub user_agent: String,
}

impl Default for WsOptions {
    fn default() -> Self {
        Self {
            path: DEFAULT_WS_PATH.to_string(),
            read_buffer_size: 0,
            write_buffer_size: 0,
            handshake_timeout: Duration::ZERO,
            enable_compression: false,
            user_agent: String::new(),
        }
    }
}

impl WsOptions {
    /// The path to serve or request: gost's `/ws` default for an empty value,
    /// and a leading `/` for a relative one.
    pub fn resolved_path(&self) -> String {
        normalize_path(&self.path)
    }

    /// The configured user agent, or gost's default.
    pub fn resolved_user_agent(&self) -> &str {
        if self.user_agent.is_empty() {
            crate::DEFAULT_USER_AGENT
        } else {
            &self.user_agent
        }
    }

    fn timeout_or(&self, default: Duration) -> Duration {
        if self.handshake_timeout.is_zero() {
            default
        } else {
            self.handshake_timeout
        }
    }
}

fn normalize_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        DEFAULT_WS_PATH.to_string()
    } else if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{}", trimmed)
    }
}

/// Translates [`WsOptions`] into the subset tungstenite can express.
fn ws_config(options: &WsOptions) -> WebSocketConfig {
    let defaults = WebSocketConfig::default();
    let write_buffer_size = options.write_buffer_size;
    WebSocketConfig {
        write_buffer_size,
        // `WebSocketConfig::assert_valid` panics unless max > target.
        max_write_buffer_size: defaults
            .max_write_buffer_size
            .max(write_buffer_size.saturating_add(1)),
        ..defaults
    }
}

/// Says out loud which options this backend cannot honour, so they are not
/// dropped silently.
fn warn_unsupported(options: &WsOptions) {
    if options.enable_compression {
        warn!(
            "[ws] compression requested but ignored: tungstenite has no permessage-deflate support"
        );
    }
    if options.read_buffer_size != 0 {
        warn!("[ws] read_buffer_size requested but ignored: tungstenite has no read buffer size option");
    }
}

fn ws_to_io(e: WsError) -> io::Error {
    match e {
        WsError::Io(e) => e,
        WsError::ConnectionClosed | WsError::AlreadyClosed => {
            io::Error::new(io::ErrorKind::BrokenPipe, "websocket connection closed")
        }
        other => io::Error::other(other.to_string()),
    }
}

// --- WsStream ------------------------------------------------------------

/// A byte stream over WebSocket binary frames.
///
/// tokio-tungstenite hands out a `Stream`/`Sink` of `Message`; handlers need
/// `AsyncRead + AsyncWrite`. This is the adapter, and it is what makes the
/// WebSocket a *transport*: the bytes crossing it are whatever inner protocol
/// the handler speaks, exactly as in gost's `websocketConn` (ws.go:722-780).
///
/// A frame payload is buffered and handed out across as many `poll_read`
/// calls as it takes, and each `poll_write` becomes one binary frame.
pub struct WsStream<S> {
    inner: WebSocketStream<S>,
    /// The payload currently being handed out, and how much of it is gone.
    read_buf: Vec<u8>,
    read_pos: usize,
    /// Set once a Close frame or the end of the message stream is seen.
    eof: bool,
}

impl<S> WsStream<S> {
    pub fn new(inner: WebSocketStream<S>) -> Self {
        Self {
            inner,
            read_buf: Vec::new(),
            read_pos: 0,
            eof: false,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();

        loop {
            // Drain the frame in hand before pulling another one.
            if me.read_pos < me.read_buf.len() {
                let available = &me.read_buf[me.read_pos..];
                let n = buf.remaining().min(available.len());
                buf.put_slice(&available[..n]);
                me.read_pos += n;
                if me.read_pos == me.read_buf.len() {
                    me.read_buf.clear();
                    me.read_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            if me.eof {
                // A zero-length read is EOF.
                return Poll::Ready(Ok(()));
            }

            let message = match Pin::new(&mut me.inner).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    me.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Ok(m))) => m,
                Poll::Ready(Some(Err(WsError::Protocol(
                    ProtocolError::ResetWithoutClosingHandshake,
                )))) => {
                    // The peer dropped the connection without a Close frame.
                    // For a byte-stream transport that is the same event as a
                    // FIN on a socket, so report EOF and let the handler
                    // finish rather than failing the relay.
                    me.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(ws_to_io(e))),
            };

            match message {
                Message::Binary(data) => {
                    if data.is_empty() {
                        // An empty frame carries no bytes; returning here
                        // would look like EOF, so keep pulling.
                        continue;
                    }
                    me.read_buf = data;
                    me.read_pos = 0;
                }
                Message::Text(text) => {
                    // gost reads with gorilla's `ReadMessage`, which ignores
                    // the message type and yields the payload either way
                    // (ws.go:767-774). Doing the same keeps a text-sending
                    // peer working instead of silently dropping its data.
                    if text.is_empty() {
                        continue;
                    }
                    me.read_buf = text.into_bytes();
                    me.read_pos = 0;
                }
                // Tungstenite answers Pings itself and Pongs need no action;
                // neither carries stream data. `Frame` is never produced on
                // the read side.
                Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => continue,
                Message::Close(_) => {
                    me.eof = true;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // `poll_ready` must come before `start_send`. It doubles as the
        // recovery path: if an earlier frame was accepted but could not reach
        // the socket, this drains it first, so frames never reorder.
        match Pin::new(&mut me.inner).poll_ready(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(ws_to_io(e))),
            Poll::Ready(Ok(())) => {}
        }

        let n = buf.len().min(MAX_WRITE_FRAME);
        if let Err(e) = Pin::new(&mut me.inner).start_send(Message::Binary(buf[..n].to_vec())) {
            return Poll::Ready(Err(ws_to_io(e)));
        }

        // With an eager write buffer — the default, and what gorilla's
        // `WriteMessage` does — push the frame at the socket now, so a
        // handler that writes a request and then waits for the reply cannot
        // stall on bytes parked in the sink. `Pending` is not an error here:
        // the sink already owns those bytes and the next `poll_ready` or
        // `poll_flush` drives them out, so `n` is still the accepted count.
        if me.inner.get_config().write_buffer_size == 0 {
            if let Poll::Ready(Err(e)) = Pin::new(&mut me.inner).poll_flush(cx) {
                return Poll::Ready(Err(ws_to_io(e)));
            }
        }

        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        match Pin::new(&mut me.inner).poll_flush(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(ws_to_io(e))),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        // `Sink::poll_close` on a `WebSocketStream` queues a Close frame and
        // then flushes the close handshake to completion, which is exactly
        // "send Close, then close the sink". Sending the Close message
        // separately first would be the same call twice: tungstenite maps
        // `write(Message::Close)` onto `close()`.
        match Pin::new(&mut me.inner).poll_close(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            // Closing an already-closed connection is a no-op, not a failure.
            Poll::Ready(Err(WsError::ConnectionClosed))
            | Poll::Ready(Err(WsError::AlreadyClosed)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(ws_to_io(e))),
        }
    }
}

// --- server --------------------------------------------------------------

/// The 404 a stock gost server returns for any path other than the configured
/// one: its mux only registers `path` (ws.go:383), so everything else falls
/// through to `http.NotFound`.
fn not_found() -> ErrorResponse {
    const BODY: &str = "404 page not found\n";
    let mut response = ErrorResponse::new(Some(BODY.to_string()));
    *response.status_mut() = StatusCode::NOT_FOUND;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    if let Ok(len) = HeaderValue::from_str(&BODY.len().to_string()) {
        response.headers_mut().insert(CONTENT_LENGTH, len);
    }
    response
}

/// Performs the server handshake, serving only `path`.
#[allow(clippy::result_large_err)]
async fn ws_upgrade<S>(
    stream: S,
    path: &str,
    config: WebSocketConfig,
) -> Result<WebSocketStream<S>, WsError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let want = path.to_string();
    accept_hdr_async_with_config(
        stream,
        move |request: &Request, response: Response| {
            let got = request.uri().path();
            if got != want {
                debug!("[ws] 404 for {}: the listener serves {}", got, want);
                return Err(not_found());
            }
            Ok(response)
        },
        Some(config),
    )
    .await
}

/// TLS termination (when configured) followed by the WebSocket handshake.
async fn accept_ws(
    stream: TcpStream,
    tls: Option<TlsAcceptor>,
    path: &str,
    config: WebSocketConfig,
) -> Result<WsStream<Box<dyn AsyncStream>>, Box<dyn std::error::Error + Send + Sync>> {
    let stream: Box<dyn AsyncStream> = match tls {
        Some(acceptor) => Box::new(acceptor.accept(stream).await?),
        None => Box::new(stream),
    };
    Ok(WsStream::new(ws_upgrade(stream, path, config).await?))
}

/// WebSocket server: upgrades each accepted socket and hands the resulting
/// byte stream to a handler.
///
/// This is the `+ws` half of a `-L http+ws://` listener. It mirrors
/// [`TlsServer`](crate::tls_listener::TlsServer) — same accept backoff,
/// cancellation token and task tracker — and, like it, keeps the underlying
/// socket's addresses so handlers still see the real client.
///
/// Use [`WsServer::new_tls`] for `wss`: TLS is terminated first and the
/// WebSocket handshake runs inside it, so the two layers compose instead of
/// each owning a socket.
pub struct WsServer {
    listener: TcpListener,
    path: Arc<str>,
    config: WebSocketConfig,
    handshake_timeout: Duration,
    tls: Option<TlsAcceptor>,
    handler: Arc<dyn Handler>,
    cancel: CancellationToken,
    tracker: TaskTracker,
}

impl WsServer {
    /// Create a plain `ws://` server.
    pub async fn new(
        addr: &str,
        options: WsOptions,
        handler: impl Handler + 'static,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::build(addr, options, None, handler).await
    }

    /// Create a `wss://` server from a prepared rustls configuration, built
    /// the same way as [`TlsServer`](crate::tls_listener::TlsServer)'s — see
    /// [`crate::tls_listener::server_config_from_pem`].
    pub async fn new_tls(
        addr: &str,
        options: WsOptions,
        config: ServerConfig,
        handler: impl Handler + 'static,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let acceptor = TlsAcceptor::from(Arc::new(config));
        Self::build(addr, options, Some(acceptor), handler).await
    }

    async fn build(
        addr: &str,
        options: WsOptions,
        tls: Option<TlsAcceptor>,
        handler: impl Handler + 'static,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        warn_unsupported(&options);

        let listener = TcpListener::bind(addr).await?;
        let path = options.resolved_path();

        info!(
            "{} listening on {} (path {})",
            if tls.is_some() { "WSS" } else { "WS" },
            listener.local_addr()?,
            path
        );

        Ok(Self {
            listener,
            path: Arc::from(path.as_str()),
            config: ws_config(&options),
            handshake_timeout: options.timeout_or(DEFAULT_SERVER_HANDSHAKE_TIMEOUT),
            tls,
            handler: Arc::new(handler),
            cancel: CancellationToken::new(),
            tracker: TaskTracker::new(),
        })
    }

    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// The path this listener upgrades; every other path gets a 404.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Accepts connections, upgrades them and dispatches them to the handler.
    pub async fn serve(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let tag = if self.tls.is_some() { "wss" } else { "ws" };
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
                            let handler = self.handler.clone();
                            let cancel = self.cancel.clone();
                            let tls = self.tls.clone();
                            let path = self.path.clone();
                            let config = self.config;
                            let handshake_timeout = self.handshake_timeout;
                            // Captured before the socket is consumed by the
                            // upgrade, so the handler still sees the real
                            // client and listener addresses.
                            let local_addr = stream.local_addr().ok();

                            self.tracker.spawn(async move {
                                let upgraded = tokio::time::timeout(
                                    handshake_timeout,
                                    accept_ws(stream, tls, &path, config),
                                )
                                .await;

                                let ws = match upgraded {
                                    Err(_) => {
                                        debug!("[{}] handshake from {} timed out", tag, peer_addr);
                                        return;
                                    }
                                    Ok(Err(e)) => {
                                        // A failed handshake is routine: port
                                        // scanners, plain HTTP clients and
                                        // wrong-path clients all cause it.
                                        debug!("[{}] handshake failed from {}: {}", tag, peer_addr, e);
                                        return;
                                    }
                                    Ok(Ok(ws)) => ws,
                                };

                                let conn = ProxyConn::layered(
                                    Box::new(ws),
                                    Some(peer_addr),
                                    local_addr,
                                );

                                tokio::select! {
                                    result = handler.handle(conn) => {
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

/// The WebSocket upgrade as a [`Handler`] wrapping another handler.
///
/// [`WsServer`] is the usual way in; this exists for callers that layer
/// handlers rather than listeners. It carries no protocol of its own: it
/// upgrades, then hands the byte stream to `inner` with the client's
/// addresses intact.
pub struct WsHandler {
    inner: Arc<dyn Handler>,
    path: String,
    config: WebSocketConfig,
    handshake_timeout: Duration,
}

impl WsHandler {
    pub fn new(inner: impl Handler + 'static, options: WsOptions) -> Self {
        warn_unsupported(&options);
        Self {
            inner: Arc::new(inner),
            path: options.resolved_path(),
            config: ws_config(&options),
            handshake_timeout: options.timeout_or(DEFAULT_SERVER_HANDSHAKE_TIMEOUT),
        }
    }
}

#[async_trait]
impl Handler for WsHandler {
    async fn handle(&self, conn: ProxyConn) -> Result<(), HandlerError> {
        let peer_addr = conn.peer_addr();
        let local_addr = conn.local_addr();

        let ws = tokio::time::timeout(
            self.handshake_timeout,
            ws_upgrade(conn, &self.path, self.config),
        )
        .await
        .map_err(|_| HandlerError::Proxy("WebSocket handshake timed out".to_string()))?
        .map_err(|e| HandlerError::Proxy(format!("WebSocket upgrade failed: {}", e)))?;

        self.inner
            .handle(ProxyConn::layered(
                Box::new(WsStream::new(ws)),
                peer_addr,
                local_addr,
            ))
            .await
    }
}

// --- client --------------------------------------------------------------

/// Layer WebSocket over an arbitrary stream.
///
/// Mirrors [`tls_connect_stream`](crate::tls_transport::tls_connect_stream):
/// the stream may already be TLS-wrapped, which is how `wss` is built — TLS
/// first, then this — instead of the transport dialling a socket itself.
///
/// `host` is the authority used for the request URL and the `Host` header.
/// `path` overrides `options.path`; pass `""` to use the configured one,
/// which falls back to gost's [`DEFAULT_WS_PATH`].
pub async fn ws_connect_stream<S>(
    stream: S,
    host: &str,
    path: &str,
    options: &WsOptions,
) -> Result<WsStream<S>, Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    if host.is_empty() {
        return Err("websocket handshake needs a host".into());
    }

    let path = if path.trim().is_empty() {
        options.resolved_path()
    } else {
        normalize_path(path)
    };

    // Always `ws://`: any TLS is already in `stream`, so tungstenite must not
    // try to add its own.
    let mut request = format!("ws://{}{}", host, path).into_client_request()?;
    request.headers_mut().insert(
        USER_AGENT,
        HeaderValue::from_str(options.resolved_user_agent())?,
    );

    let (ws, _response) = tokio::time::timeout(
        options.timeout_or(Duration::from_secs(crate::HANDSHAKE_TIMEOUT)),
        client_async_with_config(request, stream, Some(ws_config(options))),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "websocket handshake timed out"))??;

    Ok(WsStream::new(ws))
}

/// Client-side `ws` transport, gost's `wsTransporter` (ws.go:36-67).
///
/// A holder for [`WsOptions`] over [`ws_connect_stream`]: like gost's
/// `Handshake`, it takes the stream the dial produced rather than dialling
/// itself, so a chain hop can supply it.
pub struct WsTransporter {
    pub options: WsOptions,
}

impl WsTransporter {
    pub fn new(options: WsOptions) -> Self {
        Self { options }
    }

    pub async fn handshake<S>(
        &self,
        stream: S,
        host: &str,
    ) -> Result<WsStream<S>, Box<dyn std::error::Error + Send + Sync>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        ws_connect_stream(stream, host, "", &self.options).await
    }
}

/// Client-side `wss` transport, gost's `wssTransporter` (ws.go:190-224).
///
/// gost folds TLS into the WebSocket dialer; here the two layers are
/// separate, so `stream` must already be TLS-wrapped — see
/// [`tls_connect_stream`](crate::tls_transport::tls_connect_stream). That is
/// what lets `wss` run over a stream a previous chain hop produced.
pub struct WssTransporter {
    pub options: WsOptions,
}

impl WssTransporter {
    pub fn new(options: WsOptions) -> Self {
        Self { options }
    }

    pub async fn handshake<S>(
        &self,
        tls_stream: S,
        host: &str,
    ) -> Result<WsStream<S>, Box<dyn std::error::Error + Send + Sync>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        ws_connect_stream(tls_stream, host, "", &self.options).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::tungstenite::protocol::Role;

    /// Echoes every byte back: enough to prove the transport carries an
    /// arbitrary inner protocol without interpreting it.
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

    /// A connected pair of `WsStream`s with no handshake, so the byte-stream
    /// behaviour can be tested on its own.
    async fn ws_pair() -> (
        WsStream<tokio::io::DuplexStream>,
        WsStream<tokio::io::DuplexStream>,
    ) {
        let config = ws_config(&WsOptions::default());
        let (a, b) = tokio::io::duplex(64 * 1024);
        let client = WebSocketStream::from_raw_socket(a, Role::Client, Some(config)).await;
        let server = WebSocketStream::from_raw_socket(b, Role::Server, Some(config)).await;
        (WsStream::new(client), WsStream::new(server))
    }

    async fn start_echo_server(options: WsOptions) -> (std::net::SocketAddr, CancellationToken) {
        let server = WsServer::new("127.0.0.1:0", options, EchoHandler)
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let cancel = server.cancel_token();
        tokio::spawn(async move {
            server.serve().await.ok();
        });
        (addr, cancel)
    }

    #[test]
    fn test_default_path_is_the_gost_default() {
        // gost's defaultWSPath. `/` would 404 against a stock gost server,
        // which is exactly the incompatibility this guards.
        assert_eq!(DEFAULT_WS_PATH, "/ws");
        assert_eq!(WsOptions::default().path, "/ws");
        assert_eq!(WsOptions::default().resolved_path(), "/ws");

        // An explicitly empty path falls back the same way gost does.
        let empty = WsOptions {
            path: String::new(),
            ..WsOptions::default()
        };
        assert_eq!(empty.resolved_path(), "/ws");

        // A relative path is made absolute rather than silently ignored.
        let relative = WsOptions {
            path: "custom".to_string(),
            ..WsOptions::default()
        };
        assert_eq!(relative.resolved_path(), "/custom");
    }

    #[test]
    fn test_default_user_agent_matches_gost() {
        assert_eq!(
            WsOptions::default().resolved_user_agent(),
            "Chrome/78.0.3904.106"
        );
        let custom = WsOptions {
            user_agent: "curl/8".to_string(),
            ..WsOptions::default()
        };
        assert_eq!(custom.resolved_user_agent(), "curl/8");
    }

    #[test]
    fn test_write_buffer_size_reaches_the_tungstenite_config() {
        let config = ws_config(&WsOptions::default());
        // Eager writes by default, like gorilla's WriteMessage.
        assert_eq!(config.write_buffer_size, 0);

        let tuned = ws_config(&WsOptions {
            write_buffer_size: 8192,
            ..WsOptions::default()
        });
        assert_eq!(tuned.write_buffer_size, 8192);
        assert!(tuned.max_write_buffer_size > tuned.write_buffer_size);
    }

    #[tokio::test]
    async fn test_ws_stream_round_trip_across_buffer_and_frame_boundaries() {
        let (mut client, mut server) = ws_pair().await;

        // Larger than one frame and than the read buffer used below.
        let payload: Vec<u8> = (0..300_000usize).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();

        let writer = tokio::spawn(async move {
            // A single write must never claim more than the sink accepted.
            let first = client.write(&payload).await.unwrap();
            assert_eq!(first, MAX_WRITE_FRAME, "one poll_write is one frame");
            client.write_all(&payload[first..]).await.unwrap();
            client.flush().await.unwrap();
            client
        });

        // Deliberately much smaller than a frame, so payloads must be handed
        // out across many poll_read calls.
        let mut buf = [0u8; 1024];
        let mut got = Vec::with_capacity(expected.len());
        while got.len() < expected.len() {
            let n = server.read(&mut buf).await.unwrap();
            assert!(n > 0, "unexpected EOF after {} bytes", got.len());
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, expected);

        let mut client = writer.await.unwrap();

        // The reverse direction, and Close as EOF rather than an error.
        server.write_all(b"pong").await.unwrap();
        server.flush().await.unwrap();
        let mut back = [0u8; 4];
        client.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"pong");

        server.shutdown().await.unwrap();
        assert_eq!(client.read(&mut back).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_client_to_server_round_trip_carries_arbitrary_binary() {
        let (addr, cancel) = start_echo_server(WsOptions::default()).await;

        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut ws = ws_connect_stream(tcp, &addr.to_string(), "", &WsOptions::default())
            .await
            .unwrap();

        // Neither valid UTF-8 nor free of NULs: a text- or string-based
        // transport would mangle these.
        let payload: Vec<u8> = vec![0x00, 0xff, 0xfe, 0x80, b'\n', 0x7f, 0x01, 0x00, 0xc3, 0x28];
        ws.write_all(&payload).await.unwrap();
        ws.flush().await.unwrap();

        let mut got = vec![0u8; payload.len()];
        ws.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload);

        // And a payload spanning several frames survives the round trip.
        let big: Vec<u8> = (0..200_000usize).map(|i| (i % 199) as u8).collect();
        let expected = big.clone();
        let (mut reader, mut writer) = tokio::io::split(ws);
        tokio::spawn(async move {
            writer.write_all(&big).await.ok();
            writer.flush().await.ok();
        });
        let mut echoed = vec![0u8; expected.len()];
        reader.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, expected);

        cancel.cancel();
    }

    #[tokio::test]
    async fn test_wrong_path_is_rejected() {
        let (addr, cancel) = start_echo_server(WsOptions::default()).await;
        let host = addr.to_string();

        // "/" is what the old `/` default produced. A stock gost server 404s
        // it, and so must this one.
        let tcp = TcpStream::connect(addr).await.unwrap();
        let err = match ws_connect_stream(tcp, &host, "/", &WsOptions::default()).await {
            Ok(_) => panic!("the wrong path must not be upgraded"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("404"),
            "expected a 404, got: {}",
            err
        );

        // The configured path still works on the same listener.
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut ws = ws_connect_stream(tcp, &host, "/ws", &WsOptions::default())
            .await
            .unwrap();
        ws.write_all(b"ok").await.unwrap();
        ws.flush().await.unwrap();
        let mut got = [0u8; 2];
        ws.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ok");

        cancel.cancel();
    }

    #[tokio::test]
    async fn test_a_custom_path_is_honoured_on_both_sides() {
        let options = WsOptions {
            path: "/tunnel".to_string(),
            ..WsOptions::default()
        };
        let (addr, cancel) = start_echo_server(options.clone()).await;
        let host = addr.to_string();

        // The default path is no longer served once one is configured.
        let tcp = TcpStream::connect(addr).await.unwrap();
        assert!(ws_connect_stream(tcp, &host, "/ws", &WsOptions::default())
            .await
            .is_err());

        // The client takes the path from its options when none is passed.
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut ws = ws_connect_stream(tcp, &host, "", &options).await.unwrap();
        ws.write_all(b"tunnelled").await.unwrap();
        ws.flush().await.unwrap();
        let mut got = [0u8; 9];
        ws.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"tunnelled");

        cancel.cancel();
    }

    #[tokio::test]
    async fn test_wss_composes_tls_then_websocket() {
        let (config, _cert) = crate::tls_listener::self_signed_config("localhost").unwrap();
        let server = WsServer::new_tls("127.0.0.1:0", WsOptions::default(), config, EchoHandler)
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let cancel = server.cancel_token();
        tokio::spawn(async move {
            server.serve().await.ok();
        });

        // TLS first, then the WebSocket over it: the client side composes the
        // two layers exactly as the listener does.
        let tcp = TcpStream::connect(addr).await.unwrap();
        let tls = crate::tls_transport::tls_connect_stream(tcp, "localhost", true)
            .await
            .unwrap();
        let mut ws = ws_connect_stream(tls, "localhost", "", &WsOptions::default())
            .await
            .unwrap();

        ws.write_all(b"secure").await.unwrap();
        ws.flush().await.unwrap();
        let mut got = [0u8; 6];
        ws.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"secure");

        cancel.cancel();
    }

    #[tokio::test]
    async fn test_plaintext_client_does_not_reach_a_wss_listener() {
        let (config, _cert) = crate::tls_listener::self_signed_config("localhost").unwrap();
        let server = WsServer::new_tls("127.0.0.1:0", WsOptions::default(), config, EchoHandler)
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let cancel = server.cancel_token();
        tokio::spawn(async move {
            server.serve().await.ok();
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let options = WsOptions {
            handshake_timeout: Duration::from_secs(3),
            ..WsOptions::default()
        };
        assert!(
            ws_connect_stream(tcp, &addr.to_string(), "", &options)
                .await
                .is_err(),
            "a cleartext WebSocket handshake must not be served by a wss listener"
        );

        cancel.cancel();
    }

    #[tokio::test]
    async fn test_client_handshake_sends_the_gost_user_agent_and_path() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let probe = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 2048];
            let n = socket.read(&mut buf).await.unwrap();
            buf.truncate(n);
            String::from_utf8_lossy(&buf).to_string()
        });

        // The probe never replies, so the handshake fails; the request it
        // captured is what matters.
        let tcp = TcpStream::connect(addr).await.unwrap();
        let options = WsOptions {
            handshake_timeout: Duration::from_secs(3),
            ..WsOptions::default()
        };
        let _ = ws_connect_stream(tcp, &addr.to_string(), "", &options).await;

        let request = probe.await.unwrap().to_lowercase();
        assert!(
            request.starts_with("get /ws http/1.1"),
            "expected the gost default path, got: {}",
            request
        );
        assert!(
            request.contains("user-agent: chrome/78.0.3904.106"),
            "expected gost's User-Agent, got: {}",
            request
        );
    }

    #[tokio::test]
    async fn test_ws_handler_upgrades_and_delegates_without_inventing_a_protocol() {
        // The handler form of the same upgrade: the inner handler sees the
        // decoded byte stream, and no address is expected in a first message.
        let handler = WsHandler::new(EchoHandler, WsOptions::default());
        let (a, b) = tokio::io::duplex(64 * 1024);

        let served = tokio::spawn(async move {
            handler
                .handle(ProxyConn::new(Box::new(b), None, None))
                .await
        });

        let mut ws = ws_connect_stream(a, "example.com", "", &WsOptions::default())
            .await
            .unwrap();
        ws.write_all(b"\x05\x01\x00").await.unwrap();
        ws.flush().await.unwrap();
        let mut got = [0u8; 3];
        ws.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"\x05\x01\x00");

        ws.shutdown().await.unwrap();
        served.await.unwrap().unwrap();
    }
}
