//! The `http2` proxy protocol.
//!
//! This is a *proxy*, not a tunnel: the server resolves and dials the target
//! named in each request, where [`h2`](crate::h2_transport) simply hands the
//! stream to whatever protocol handler is configured. gost keeps the same
//! split — `HTTP2Handler` (http2.go:316-592) versus `H2Listener`.
//!
//! One TLS connection carries many HTTP/2 streams and each is an independent
//! request, so the handler dispatches every stream on its own task rather than
//! serving them one at a time.
//!
//! Both request forms gost supports are handled: `CONNECT` opens a tunnel to
//! the authority, and any other method is forwarded to the origin with the
//! response translated back onto the HTTP/2 stream.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use h2::server::SendResponse;
use http::{Method, Request, Response, StatusCode};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, info};

use crate::conn::ProxyConn;
use crate::h2_transport::{H2Config, H2Stream};
use crate::handler::{basic_proxy_auth, Handler, HandlerError, HandlerOptions};
use crate::transport::transport;
use crate::DEFAULT_PROXY_AGENT;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Connects through an `http2` proxy for a chain hop.
///
/// gost's `HTTP2Connector` sends `CONNECT` for the target over the pooled
/// HTTP/2 connection (http2.go:36-120). The TLS underneath is layered by the
/// chain before this runs, so this is only the stream half.
pub async fn http2_connect<S>(stream: S, target: &str) -> Result<H2Stream, BoxError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // An empty path is the CONNECT form, which is what a proxy hop wants.
    crate::h2_transport::h2_connect(stream, target, &H2Config::default()).await
}

/// HTTP/2 proxy handler.
pub struct Http2Handler {
    options: HandlerOptions,
}

impl Http2Handler {
    pub fn new(options: HandlerOptions) -> Self {
        Self { options }
    }

    fn proxy_agent(&self) -> String {
        if self.options.proxy_agent.is_empty() {
            DEFAULT_PROXY_AGENT.to_string()
        } else {
            self.options.proxy_agent.clone()
        }
    }

    async fn authenticate(&self, user: &str, password: &str) -> bool {
        match self.options.authenticator {
            Some(ref auth) => auth.authenticate(user, password),
            None => true,
        }
    }
}

/// The target a request names, as `host:port`.
///
/// CONNECT carries it in the authority; other methods carry an absolute URI,
/// whose scheme supplies the port when it is not explicit.
fn request_target<T>(request: &Request<T>) -> Option<String> {
    let uri = request.uri();
    let host = uri.host()?;
    let port = uri.port_u16().unwrap_or_else(|| {
        // CONNECT names an authority with no scheme, and gost treats it as
        // TLS-bound; an absolute URI supplies its own default.
        if request.method() == Method::CONNECT || uri.scheme_str() == Some("https") {
            443
        } else {
            80
        }
    });
    if host.contains(':') && !host.starts_with('[') {
        // A bare IPv6 literal needs bracketing before it is reparsed.
        Some(format!("[{host}]:{port}"))
    } else {
        Some(format!("{host}:{port}"))
    }
}

fn header_str<T>(request: &Request<T>, name: &str) -> String {
    request
        .headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

async fn send_status(
    respond: &mut SendResponse<Bytes>,
    status: StatusCode,
    agent: &str,
) -> Result<(), h2::Error> {
    let mut builder = Response::builder()
        .status(status)
        .header("Proxy-Agent", agent);
    if status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
        builder = builder.header("Proxy-Authenticate", "Basic realm=\"gost\"");
    }
    respond
        .send_response(builder.body(()).unwrap(), true)
        .map(|_| ())
}

impl Http2Handler {
    async fn serve_request(
        self: Arc<Self>,
        request: Request<h2::RecvStream>,
        mut respond: SendResponse<Bytes>,
        peer: String,
    ) -> Result<(), HandlerError> {
        let agent = self.proxy_agent();

        let Some(host) = request_target(&request) else {
            let _ = send_status(&mut respond, StatusCode::BAD_REQUEST, &agent).await;
            return Ok(());
        };

        info!("[http2] {} -> {}", peer, host);

        if let Some(ref bypass) = self.options.bypass {
            if bypass.contains(&host) {
                info!("[http2] {} - bypass {}", peer, host);
                let _ = send_status(&mut respond, StatusCode::FORBIDDEN, &agent).await;
                return Ok(());
            }
        }

        let (user, password, _) = basic_proxy_auth(&header_str(&request, "proxy-authorization"));
        if !self.authenticate(&user, &password).await {
            debug!("[http2] {} - authentication failed", peer);
            let _ = send_status(
                &mut respond,
                StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                &agent,
            )
            .await;
            return Ok(());
        }

        let chain = self.options.chain.as_ref().cloned().unwrap_or_default();
        let retries = self.options.retries.max(1);

        let mut target_conn = None;
        for _ in 0..retries {
            match chain.dial(&host).await {
                Ok(c) => {
                    target_conn = Some(c);
                    break;
                }
                Err(e) => debug!("[http2] {} -> {} : {}", peer, host, e),
            }
        }
        let Some(target_conn) = target_conn else {
            let _ = send_status(&mut respond, StatusCode::BAD_GATEWAY, &agent).await;
            return Ok(());
        };

        if request.method() == Method::CONNECT {
            let send = respond
                .send_response(
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("Proxy-Agent", agent)
                        .body(())
                        .unwrap(),
                    false,
                )
                .map_err(|e| HandlerError::Proxy(format!("h2 response failed: {e}")))?;

            info!("[http2] {} <-> {}", peer, host);
            let stream = H2Stream::new(request.into_body(), send);
            transport(stream, target_conn).await?;
            info!("[http2] {} >-< {}", peer, host);
            return Ok(());
        }

        forward_request(request, respond, target_conn, &host, &peer, &agent).await
    }
}

/// Forwards a non-CONNECT request to the origin and maps the reply back.
///
/// The origin speaks HTTP/1.1, so the request is rebuilt in origin form and
/// the status line and headers of the reply are translated onto the HTTP/2
/// stream. gost does the same (http2.go:561-592).
async fn forward_request(
    request: Request<h2::RecvStream>,
    mut respond: SendResponse<Bytes>,
    target_conn: ProxyConn,
    host: &str,
    peer: &str,
    agent: &str,
) -> Result<(), HandlerError> {
    let method = request.method().clone();
    let path = request
        .uri()
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_else(|| "/".to_string());

    let mut head = format!("{method} {path} HTTP/1.1\r\n");
    let authority = request
        .uri()
        .authority()
        .map(|a| a.to_string())
        .unwrap_or_else(|| host.to_string());
    head.push_str(&format!("Host: {authority}\r\n"));
    for (name, value) in request.headers() {
        let n = name.as_str();
        // Hop-by-hop headers, and the pseudo-header equivalents HTTP/2 does
        // not carry, must not be forwarded.
        if n == "host"
            || n == "connection"
            || n == "proxy-connection"
            || n == "proxy-authorization"
            || n == "keep-alive"
            || n == "transfer-encoding"
            || n == "upgrade"
            || n == "te"
        {
            continue;
        }
        if let Ok(v) = value.to_str() {
            head.push_str(&format!("{n}: {v}\r\n"));
        }
    }
    head.push_str("Connection: close\r\n\r\n");

    let mut origin = BufReader::new(target_conn);
    origin.write_all(head.as_bytes()).await?;

    // Relay the request body, if any.
    let mut body = request.into_body();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|e| HandlerError::Proxy(format!("h2 body: {e}")))?;
        origin.write_all(&chunk).await?;
        let _ = body.flow_control().release_capacity(chunk.len());
    }
    origin.flush().await?;

    // Status line.
    let mut line = String::new();
    if origin.read_line(&mut line).await? == 0 {
        let _ = send_status(&mut respond, StatusCode::BAD_GATEWAY, agent).await;
        return Ok(());
    }
    let status = line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .and_then(|c| StatusCode::from_u16(c).ok())
        .unwrap_or(StatusCode::BAD_GATEWAY);

    let mut builder = Response::builder().status(status);
    loop {
        let mut header = String::new();
        if origin.read_line(&mut header).await? == 0 {
            break;
        }
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        let Some((name, value)) = header.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        // Connection-specific headers are meaningless over HTTP/2, and h2
        // rejects the stream if they are sent.
        if name == "connection"
            || name == "transfer-encoding"
            || name == "keep-alive"
            || name == "upgrade"
            || name == "proxy-connection"
        {
            continue;
        }
        builder = builder.header(name, value.trim());
    }

    let mut send = respond
        .send_response(builder.body(()).unwrap(), false)
        .map_err(|e| HandlerError::Proxy(format!("h2 response failed: {e}")))?;

    let mut buf = vec![0u8; 32 * 1024];
    loop {
        let n = origin.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        send.reserve_capacity(n);
        send.send_data(Bytes::copy_from_slice(&buf[..n]), false)
            .map_err(|e| HandlerError::Proxy(format!("h2 send: {e}")))?;
    }
    let _ = send.send_data(Bytes::new(), true);

    info!("[http2] {} >-< {}", peer, host);
    Ok(())
}

#[async_trait]
impl Handler for Http2Handler {
    async fn handle(&self, conn: ProxyConn) -> Result<(), HandlerError> {
        let peer = conn.peer_addr_str();

        let mut connection = h2::server::handshake(conn)
            .await
            .map_err(|e| HandlerError::Proxy(format!("h2 handshake failed: {e}")))?;

        let shared = Arc::new(Http2Handler::new(self.options.clone()));

        while let Some(accepted) = connection.accept().await {
            let (request, respond) = match accepted {
                Ok(pair) => pair,
                Err(e) => {
                    debug!("[http2] {} accept failed: {}", peer, e);
                    break;
                }
            };

            let handler = shared.clone();
            let peer = peer.clone();
            // Streams are independent requests; serving them in turn would
            // make one slow origin stall the whole connection.
            tokio::spawn(async move {
                if let Err(e) = handler.serve_request(request, respond, peer.clone()).await {
                    debug!("[http2] {} : {}", peer, e);
                }
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::LocalAuthenticator;
    use std::collections::HashMap;
    use tokio::net::{TcpListener, TcpStream};

    async fn start_proxy(options: HandlerOptions) -> std::net::SocketAddr {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = proxy.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((conn, peer)) = proxy.accept().await else {
                    return;
                };
                let handler = Http2Handler::new(options.clone());
                tokio::spawn(async move {
                    let local = conn.local_addr().ok();
                    handler
                        .handle(ProxyConn::layered(Box::new(conn), Some(peer), local))
                        .await
                        .ok();
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn test_http2_proxy_connect_tunnels() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            let mut buf = [0u8; 5];
            conn.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping!");
            conn.write_all(b"pong!").await.unwrap();
        });

        let proxy_addr = start_proxy(HandlerOptions::default()).await;
        let sock = TcpStream::connect(proxy_addr).await.unwrap();
        let mut tunnel = http2_connect(sock, &target_addr.to_string()).await.unwrap();

        tunnel.write_all(b"ping!").await.unwrap();
        let mut got = [0u8; 5];
        tunnel.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"pong!");
    }

    #[tokio::test]
    async fn test_http2_proxy_rejects_bad_credentials() {
        let mut users = HashMap::new();
        users.insert("admin".to_string(), "secret".to_string());
        let options = HandlerOptions {
            authenticator: Some(Arc::new(LocalAuthenticator::new(users))),
            ..Default::default()
        };

        let proxy_addr = start_proxy(options).await;
        let sock = TcpStream::connect(proxy_addr).await.unwrap();
        // http2_connect sends no credentials at all.
        let err = http2_connect(sock, "example.com:443")
            .await
            .expect_err("an unauthenticated tunnel must be refused");
        assert!(err.to_string().contains("407"), "got: {err}");
    }

    #[tokio::test]
    async fn test_http2_proxy_honours_bypass() {
        let options = HandlerOptions {
            bypass: Some(Arc::new(crate::bypass::Bypass::from_patterns(
                false,
                &["blocked.example"],
            ))),
            ..Default::default()
        };

        let proxy_addr = start_proxy(options).await;
        let sock = TcpStream::connect(proxy_addr).await.unwrap();
        let err = http2_connect(sock, "blocked.example:443")
            .await
            .expect_err("a bypassed host must be refused");
        assert!(err.to_string().contains("403"), "got: {err}");
    }

    #[tokio::test]
    async fn test_http2_proxy_forwards_plain_requests() {
        // An origin that answers one HTTP/1.1 request.
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut conn, _) = origin.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = conn.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            assert!(req.starts_with("GET /hello HTTP/1.1"), "got: {req}");
            assert!(req.to_lowercase().contains("host: "), "got: {req}");
            conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
                .await
                .unwrap();
        });

        let proxy_addr = start_proxy(HandlerOptions::default()).await;
        let sock = TcpStream::connect(proxy_addr).await.unwrap();
        let (mut send_request, connection) = h2::client::handshake(sock).await.unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });

        let request = Request::builder()
            .method(Method::GET)
            .uri(format!("http://{origin_addr}/hello"))
            .body(())
            .unwrap();
        let (response, _send) = send_request.send_request(request, true).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let mut body = response.into_body();
        let mut got = Vec::new();
        while let Some(chunk) = body.data().await {
            got.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(got, b"hi");
    }

    #[test]
    fn test_request_target_defaults_port_by_scheme() {
        fn target(uri: &str, method: Method) -> Option<String> {
            let req = Request::builder().method(method).uri(uri).body(()).unwrap();
            request_target(&req)
        }

        assert_eq!(
            target("http://example.com/x", Method::GET).as_deref(),
            Some("example.com:80")
        );
        assert_eq!(
            target("https://example.com/x", Method::GET).as_deref(),
            Some("example.com:443")
        );
        assert_eq!(
            target("http://example.com:8080/x", Method::GET).as_deref(),
            Some("example.com:8080")
        );
    }
}
