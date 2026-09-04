//! HTTP/2 tunnel transports: `h2` and `h2c`.
//!
//! gost carries a connection inside a single HTTP/2 stream: the request body
//! is the client-to-server direction and the response body is the
//! server-to-client direction (http2.go:220-297 for the dialer, 760-816 for
//! the listener). `h2` runs that over TLS, `h2c` in cleartext.
//!
//! # Shape
//!
//! Like the multiplexed transports, one accepted socket is one HTTP/2
//! *connection* and every stream on it is a separate [`ProxyConn`] handed to
//! the handler. So [`H2Handler`] follows [`MuxHandler`](crate::mux_transport)
//! and is a [`Handler`] that wraps another handler rather than a listener of
//! its own: `h2c` is a plain TCP listener plus [`H2Handler`], and `h2` is the
//! ordinary TLS listener plus [`H2Handler`].
//!
//! # Method and path
//!
//! gost keys the two off `path` being empty. With no `?path=`, the client
//! sends `CONNECT` and the server rejects anything else. With a path, the
//! client sends `GET <path>` and the server rejects a request for any other
//! target. Both are honoured here, so a gost peer on either side interoperates
//! without configuration beyond the URL.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use h2::{RecvStream, SendStream};
use http::{Method, Request, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

use crate::conn::ProxyConn;
use crate::handler::{Handler, HandlerError, HandlerOptions};
use crate::node::Node;
use crate::DEFAULT_PROXY_AGENT;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn io_error(e: h2::Error) -> std::io::Error {
    std::io::Error::other(e)
}

/// One HTTP/2 stream presented as a byte stream.
///
/// Reads drain the peer's body and return the flow-control window as they go;
/// without that release the peer stalls once it has sent one window's worth.
/// Writes reserve capacity first, because HTTP/2 will not let a DATA frame
/// exceed the window the peer has advertised.
pub struct H2Stream {
    recv: RecvStream,
    send: SendStream<Bytes>,
    /// The remainder of the DATA frame currently being handed to the reader.
    chunk: Bytes,
}

impl H2Stream {
    pub fn new(recv: RecvStream, send: SendStream<Bytes>) -> Self {
        Self {
            recv,
            send,
            chunk: Bytes::new(),
        }
    }
}

impl std::fmt::Debug for H2Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2Stream")
            .field("buffered", &self.chunk.len())
            .finish()
    }
}

impl AsyncRead for H2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if !self.chunk.is_empty() {
                let n = self.chunk.len().min(buf.remaining());
                buf.put_slice(&self.chunk[..n]);
                self.chunk.advance(n);
                // Tell the peer it may send another n bytes. Skipped, this
                // deadlocks as soon as a transfer exceeds the initial window.
                let _ = self.recv.flow_control().release_capacity(n);
                return Poll::Ready(Ok(()));
            }

            match Pin::new(&mut self.recv).poll_data(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    if chunk.is_empty() {
                        continue;
                    }
                    self.chunk = chunk;
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(io_error(e))),
                // End of the body is end of the connection.
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        self.send.reserve_capacity(buf.len());
        match self.send.poll_capacity(cx) {
            Poll::Ready(Some(Ok(n))) => {
                // A short write is fine; the caller loops.
                let n = n.min(buf.len());
                if n == 0 {
                    return Poll::Pending;
                }
                let data = Bytes::copy_from_slice(&buf[..n]);
                self.send.send_data(data, false).map_err(io_error)?;
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(io_error(e))),
            Poll::Ready(None) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "h2 stream closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // h2 owns its own write buffering; there is nothing held back here.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // A zero-length DATA frame with END_STREAM is the half-close, which is
        // what makes a client that shuts down its write side still receive the
        // rest of the response.
        self.send.send_data(Bytes::new(), true).map_err(io_error)?;
        Poll::Ready(Ok(()))
    }
}

/// `?path=` for the tunnel. Empty means gost's CONNECT form.
#[derive(Clone, Debug, Default)]
pub struct H2Config {
    pub path: String,
}

impl H2Config {
    pub fn from_node(node: &Node) -> Self {
        Self {
            path: node
                .get("path")
                .filter(|p| !p.is_empty())
                .unwrap_or_default()
                .to_string(),
        }
    }
}

/// The server half: an HTTP/2 connection whose every stream becomes a
/// [`ProxyConn`] for the inner handler.
pub struct H2Handler {
    inner: Arc<dyn Handler>,
    config: H2Config,
}

impl H2Handler {
    pub fn new(inner: impl Handler + 'static, config: H2Config) -> Self {
        Self {
            inner: Arc::new(inner),
            config,
        }
    }
}

#[async_trait]
impl Handler for H2Handler {
    async fn handle(&self, conn: ProxyConn) -> Result<(), HandlerError> {
        let peer_addr = conn.peer_addr();
        let local_addr = conn.local_addr();
        let peer_str = conn.peer_addr_str();

        let mut connection = h2::server::handshake(conn)
            .await
            .map_err(|e| HandlerError::Proxy(format!("h2 handshake failed: {e}")))?;

        while let Some(accepted) = connection.accept().await {
            let (request, mut respond) = match accepted {
                Ok(pair) => pair,
                Err(e) => {
                    debug!("[h2] {} accept failed: {}", peer_str, e);
                    break;
                }
            };

            // gost keys both checks off whether a path is configured
            // (http2.go:784-793); mismatches get a status rather than a
            // silently accepted tunnel.
            let status = if self.config.path.is_empty() {
                if request.method() == Method::CONNECT {
                    None
                } else {
                    Some(StatusCode::METHOD_NOT_ALLOWED)
                }
            } else if request.uri().path() == self.config.path {
                None
            } else {
                Some(StatusCode::BAD_REQUEST)
            };

            if let Some(status) = status {
                debug!(
                    "[h2] {} rejected {} {}",
                    peer_str,
                    request.method(),
                    request.uri()
                );
                let response = Response::builder().status(status).body(()).unwrap();
                let _ = respond.send_response(response, true);
                continue;
            }

            let response = Response::builder()
                .status(StatusCode::OK)
                .header("Proxy-Agent", DEFAULT_PROXY_AGENT)
                .body(())
                .unwrap();
            let send = match respond.send_response(response, false) {
                Ok(send) => send,
                Err(e) => {
                    debug!("[h2] {} response failed: {}", peer_str, e);
                    continue;
                }
            };

            let stream = H2Stream::new(request.into_body(), send);
            let inner = self.inner.clone();
            // Each stream is independent, so the accept loop must not wait for
            // this one to finish or the connection would carry one stream at a
            // time.
            tokio::spawn(async move {
                let conn = ProxyConn::layered(Box::new(stream), peer_addr, local_addr);
                if let Err(e) = inner.handle(conn).await {
                    debug!("[h2] stream: {}", e);
                }
            });
        }

        Ok(())
    }
}

/// The client half: opens one HTTP/2 stream per dial.
///
/// gost pools an `http.Client` per address and lets it own connection reuse
/// (http2.go:226-252). The pooling here lives in [`Chain`](crate::chain), so
/// this is only the per-dial half.
pub async fn h2_connect<S>(stream: S, host: &str, config: &H2Config) -> Result<H2Stream, BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut send_request, connection) = h2::client::handshake(stream).await?;

    // The connection future drives the whole HTTP/2 session; without it
    // running nothing is ever written to the socket.
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            debug!("[h2] connection closed: {}", e);
        }
    });

    let request = if config.path.is_empty() {
        Request::builder()
            .method(Method::CONNECT)
            .uri(format!("https://{host}"))
            .body(())?
    } else {
        Request::builder()
            .method(Method::GET)
            .uri(format!("https://{host}{}", config.path))
            .body(())?
    };

    let (response, send) = send_request.send_request(request, false)?;
    let response = response.await?;
    if response.status() != StatusCode::OK {
        return Err(format!("h2 tunnel rejected: {}", response.status()).into());
    }

    Ok(H2Stream::new(response.into_body(), send))
}

/// Build the handler stack for an `h2`/`h2c` listener.
pub fn h2_listener_handler(
    inner: impl Handler + 'static,
    node: &Node,
    _options: &HandlerOptions,
) -> H2Handler {
    H2Handler::new(inner, H2Config::from_node(node))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::HandlerOptions;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// Echoes whatever it is given, so a test can prove the tunnel carries
    /// bytes in both directions.
    struct EchoHandler;

    #[async_trait]
    impl Handler for EchoHandler {
        async fn handle(&self, mut conn: ProxyConn) -> Result<(), HandlerError> {
            let mut buf = vec![0u8; 1024];
            loop {
                let n = conn.read(&mut buf).await?;
                if n == 0 {
                    return Ok(());
                }
                conn.write_all(&buf[..n]).await?;
            }
        }
    }

    #[test]
    fn test_h2_config_from_node() {
        let node = Node::parse("http+h2://example.com:443?path=/tunnel").unwrap();
        assert_eq!(H2Config::from_node(&node).path, "/tunnel");

        let node = Node::parse("http+h2://example.com:443").unwrap();
        assert_eq!(H2Config::from_node(&node).path, "");
    }

    #[test]
    fn test_h2_config_ignores_empty_path() {
        let node = Node::parse("http+h2://example.com:443?path=").unwrap();
        assert_eq!(H2Config::from_node(&node).path, "");
    }

    async fn roundtrip(config: H2Config) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_config = config.clone();
        tokio::spawn(async move {
            let (sock, peer) = listener.accept().await.unwrap();
            let local = sock.local_addr().ok();
            let handler = H2Handler::new(EchoHandler, server_config);
            let conn = ProxyConn::layered(Box::new(sock), Some(peer), local);
            handler.handle(conn).await.ok();
        });

        let sock = TcpStream::connect(addr).await.unwrap();
        let mut stream = h2_connect(sock, &addr.to_string(), &config).await.unwrap();

        stream.write_all(b"through the h2 tunnel").await.unwrap();
        let mut got = vec![0u8; 21];
        stream.read_exact(&mut got).await.unwrap();
        String::from_utf8(got).unwrap()
    }

    #[tokio::test]
    async fn test_h2c_tunnel_connect_form() {
        // No path configured, so this is gost's CONNECT form.
        assert_eq!(
            roundtrip(H2Config::default()).await,
            "through the h2 tunnel"
        );
    }

    #[tokio::test]
    async fn test_h2c_tunnel_path_form() {
        assert_eq!(
            roundtrip(H2Config {
                path: "/tunnel".into()
            })
            .await,
            "through the h2 tunnel"
        );
    }

    #[tokio::test]
    async fn test_h2_server_rejects_wrong_path() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (sock, peer) = listener.accept().await.unwrap();
            let handler = H2Handler::new(
                EchoHandler,
                H2Config {
                    path: "/expected".into(),
                },
            );
            let conn = ProxyConn::layered(Box::new(sock), Some(peer), None);
            handler.handle(conn).await.ok();
        });

        let sock = TcpStream::connect(addr).await.unwrap();
        let err = h2_connect(
            sock,
            &addr.to_string(),
            &H2Config {
                path: "/wrong".into(),
            },
        )
        .await
        .expect_err("a path the server does not serve must not tunnel");
        assert!(err.to_string().contains("400"), "got: {err}");
    }

    #[tokio::test]
    async fn test_h2_server_rejects_non_connect_when_no_path() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (sock, peer) = listener.accept().await.unwrap();
            let handler = H2Handler::new(EchoHandler, H2Config::default());
            let conn = ProxyConn::layered(Box::new(sock), Some(peer), None);
            handler.handle(conn).await.ok();
        });

        // The client asks with a path; the server wants CONNECT.
        let sock = TcpStream::connect(addr).await.unwrap();
        let err = h2_connect(
            sock,
            &addr.to_string(),
            &H2Config {
                path: "/nope".into(),
            },
        )
        .await
        .expect_err("a GET must not be accepted when the server expects CONNECT");
        assert!(err.to_string().contains("405"), "got: {err}");
    }

    #[tokio::test]
    async fn test_h2_tunnel_carries_more_than_one_window() {
        // Proves release_capacity is wired: without it this stalls once the
        // initial flow-control window is exhausted.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (sock, peer) = listener.accept().await.unwrap();
            let handler = H2Handler::new(EchoHandler, H2Config::default());
            let conn = ProxyConn::layered(Box::new(sock), Some(peer), None);
            handler.handle(conn).await.ok();
        });

        let sock = TcpStream::connect(addr).await.unwrap();
        let stream = h2_connect(sock, &addr.to_string(), &H2Config::default())
            .await
            .unwrap();

        let payload = vec![0xABu8; 256 * 1024];
        let (mut rd, mut wr) = tokio::io::split(stream);
        let sent = payload.clone();
        let writer = tokio::spawn(async move {
            wr.write_all(&sent).await.unwrap();
            wr.flush().await.unwrap();
        });

        let mut got = vec![0u8; payload.len()];
        rd.read_exact(&mut got).await.unwrap();
        writer.await.unwrap();
        assert_eq!(got, payload);
    }

    #[test]
    fn test_h2_handler_wraps_inner() {
        let _ = HandlerOptions::default();
        let handler = H2Handler::new(EchoHandler, H2Config::default());
        assert!(handler.config.path.is_empty());
    }
}
