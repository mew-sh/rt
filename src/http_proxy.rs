use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::handler::{basic_proxy_auth, Handler, HandlerError, HandlerOptions};
use crate::permissions::Can;
use crate::transport::transport;
use crate::{DEFAULT_PROXY_AGENT, DEFAULT_USER_AGENT};

/// HTTP proxy connector (client side).
pub struct HttpConnector {
    pub user: Option<(String, Option<String>)>,
}

impl HttpConnector {
    pub fn new(user: Option<(String, Option<String>)>) -> Self {
        Self { user }
    }

    /// Send HTTP CONNECT to establish tunnel through proxy.
    pub async fn connect(
        &self,
        mut conn: TcpStream,
        address: &str,
    ) -> Result<TcpStream, HandlerError> {
        let mut req = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nProxy-Connection: keep-alive\r\n",
            address, address, DEFAULT_USER_AGENT
        );

        if let Some((ref user, ref pass)) = self.user {
            use base64::Engine;
            let p = pass.as_deref().unwrap_or("");
            let encoded =
                base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", user, p));
            req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", encoded));
        }
        req.push_str("\r\n");

        conn.write_all(req.as_bytes()).await?;

        // Read response
        let mut reader = BufReader::new(&mut conn);
        let mut status_line = String::new();
        reader.read_line(&mut status_line).await?;

        if !status_line.contains("200") {
            return Err(HandlerError::Proxy(format!(
                "HTTP CONNECT failed: {}",
                status_line.trim()
            )));
        }

        // Read headers until empty line
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await?;
            if line.trim().is_empty() {
                break;
            }
        }

        Ok(conn)
    }
}

/// HTTP proxy handler (server side).
pub struct HttpHandler {
    options: HandlerOptions,
}

impl HttpHandler {
    pub fn new(options: HandlerOptions) -> Self {
        Self { options }
    }

    fn proxy_agent(&self) -> &str {
        if self.options.proxy_agent.is_empty() {
            DEFAULT_PROXY_AGENT
        } else {
            &self.options.proxy_agent
        }
    }

    async fn authenticate(&self, user: &str, password: &str) -> bool {
        if let Some(ref auth) = self.options.authenticator {
            auth.authenticate(user, password)
        } else {
            true // No authenticator = allow all
        }
    }
}

#[async_trait]
impl Handler for HttpHandler {
    async fn handle(&self, mut conn: TcpStream) -> Result<(), HandlerError> {
        let peer_addr = conn
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        let local_addr = conn
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        // Read the HTTP request
        let mut buf_reader = BufReader::new(&mut conn);
        let mut request_line = String::new();
        buf_reader.read_line(&mut request_line).await?;

        if request_line.is_empty() {
            return Ok(());
        }

        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(HandlerError::Proxy("malformed request".into()));
        }

        let method = parts[0];
        let target = parts[1];
        let _version = parts[2];

        // Read headers
        let mut headers = Vec::new();
        let mut proxy_auth = String::new();
        let mut host_header = String::new();
        loop {
            let mut line = String::new();
            buf_reader.read_line(&mut line).await?;
            if line.trim().is_empty() {
                break;
            }
            let trimmed = line.trim().to_string();
            if trimmed.to_lowercase().starts_with("proxy-authorization:") {
                proxy_auth = trimmed[20..].trim().to_string();
            } else if trimmed.to_lowercase().starts_with("host:") {
                host_header = trimmed[5..].trim().to_string();
            }
            headers.push(trimmed);
        }

        // The BufReader reads ahead, so bytes the client coalesced after the
        // header terminator are sitting in its buffer. Dropping the reader
        // without recovering them loses the request body of a POST/PUT, or the
        // TLS ClientHello a client sent together with its CONNECT.
        let pipelined = buf_reader.buffer().to_vec();
        drop(buf_reader);

        // Determine target host
        let host = if method == "CONNECT" {
            target.to_string()
        } else if let Ok(url) = url::Url::parse(target) {
            let h = url.host_str().unwrap_or(&host_header);
            let port = url.port().unwrap_or(80);
            format!("{}:{}", h, port)
        } else {
            let h = if host_header.is_empty() {
                target.to_string()
            } else {
                host_header.clone()
            };
            if !h.contains(':') {
                format!("{}:80", h)
            } else {
                h
            }
        };

        let (user, _, _) = basic_proxy_auth(&proxy_auth);
        let user_prefix = if !user.is_empty() {
            format!("{}@", user)
        } else {
            String::new()
        };
        info!(
            "[http] {}{} -> {} -> {}",
            user_prefix, peer_addr, local_addr, host
        );

        // Check permissions
        if !Can(
            "tcp",
            &host,
            self.options.whitelist.as_ref(),
            self.options.blacklist.as_ref(),
        ) {
            warn!(
                "[http] {} - {} : Unauthorized to connect to {}",
                peer_addr, local_addr, host
            );
            let resp = format!(
                "HTTP/1.1 403 Forbidden\r\nProxy-Agent: {}\r\n\r\n",
                self.proxy_agent()
            );
            conn.write_all(resp.as_bytes()).await?;
            return Ok(());
        }

        // Check bypass
        if let Some(ref bypass) = self.options.bypass {
            if bypass.contains(&host) {
                let resp = format!(
                    "HTTP/1.1 403 Forbidden\r\nProxy-Agent: {}\r\n\r\n",
                    self.proxy_agent()
                );
                conn.write_all(resp.as_bytes()).await?;
                info!("[http] {} - {} bypass {}", peer_addr, local_addr, host);
                return Ok(());
            }
        }

        // Authenticate
        let (u, p, _) = basic_proxy_auth(&proxy_auth);
        if !self.authenticate(&u, &p).await {
            let resp = "HTTP/1.1 407 Proxy Authentication Required\r\n\
                        Proxy-Authenticate: Basic realm=\"rustun\"\r\n\
                        Connection: close\r\n\r\n";
            conn.write_all(resp.as_bytes()).await?;
            return Ok(());
        }

        // Connect to target through chain
        let chain = self.options.chain.as_ref().cloned().unwrap_or_default();

        let retries = if self.options.retries > 0 {
            self.options.retries
        } else {
            1
        };

        let mut target_conn = None;
        let mut last_err = None;
        for _ in 0..retries {
            match chain.dial(&host).await {
                Ok(c) => {
                    target_conn = Some(c);
                    break;
                }
                Err(e) => {
                    debug!("[http] {} -> {} : {}", peer_addr, host, e);
                    last_err = Some(e);
                }
            }
        }

        let mut cc = match target_conn {
            Some(c) => c,
            None => {
                let resp = format!(
                    "HTTP/1.1 503 Service Unavailable\r\nProxy-Agent: {}\r\n\r\n",
                    self.proxy_agent()
                );
                conn.write_all(resp.as_bytes()).await?;
                return Err(HandlerError::Proxy(format!(
                    "failed to connect to {}: {:?}",
                    host, last_err
                )));
            }
        };

        if method == "CONNECT" {
            // HTTPS tunnel
            let resp = format!(
                "HTTP/1.1 200 Connection established\r\nProxy-Agent: {}\r\n\r\n",
                self.proxy_agent()
            );
            conn.write_all(resp.as_bytes()).await?;

            // Replay anything the client sent alongside the CONNECT.
            if !pipelined.is_empty() {
                cc.write_all(&pipelined).await?;
            }

            info!("[http] {} <-> {}", peer_addr, host);
            transport(conn, cc).await.ok();
            info!("[http] {} >-< {}", peer_addr, host);
        } else {
            // Forward the request. gost emits origin-form for a direct
            // connection and reserves absolute-form for an upstream proxy
            // (http.go:316 vs :472); some origin servers reject absolute-form.
            let request_target = origin_form(target);
            let mut req = format!("{} {} HTTP/1.1\r\n", method, request_target);
            for header in &headers {
                let lower = header.to_lowercase();
                if !lower.starts_with("proxy-authorization")
                    && !lower.starts_with("proxy-connection")
                {
                    req.push_str(header);
                    req.push_str("\r\n");
                }
            }
            req.push_str("\r\n");

            cc.write_all(req.as_bytes()).await?;
            // The body begins in whatever the header reader buffered.
            if !pipelined.is_empty() {
                cc.write_all(&pipelined).await?;
            }

            info!("[http] {} <-> {}", peer_addr, host);
            transport(conn, cc).await.ok();
            info!("[http] {} >-< {}", peer_addr, host);
        }

        Ok(())
    }
}

/// Converts an absolute-form request target (`http://host/path?q`) into the
/// origin form (`/path?q`) an origin server expects. Anything that is not an
/// absolute URL is passed through unchanged.
fn origin_form(target: &str) -> String {
    match url::Url::parse(target) {
        Ok(url) if url.has_host() => {
            let mut out = url.path().to_string();
            if out.is_empty() {
                out.push('/');
            }
            if let Some(q) = url.query() {
                out.push('?');
                out.push_str(q);
            }
            out
        }
        _ => target.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_http_handler_connect() {
        // Start a mock target server
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            conn.write_all(b"hello from target").await.unwrap();
        });

        // Start HTTP proxy
        let handler = HttpHandler::new(HandlerOptions::default());
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(conn).await.ok();
        });

        // Connect to proxy and issue CONNECT
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let req = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
            target_addr, target_addr
        );
        client.write_all(req.as_bytes()).await.unwrap();

        // Read response
        let mut buf = vec![0u8; 4096];
        let n = client.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("200"));

        // Read data from target
        let mut data_buf = vec![0u8; 4096];
        let n = client.read(&mut data_buf).await.unwrap();
        assert_eq!(&data_buf[..n], b"hello from target");
    }

    #[tokio::test]
    async fn test_http_handler_auth_required() {
        use std::collections::HashMap;
        use std::sync::Arc;

        let mut kvs = HashMap::new();
        kvs.insert("admin".into(), "secret".into());
        let auth = Arc::new(crate::auth::LocalAuthenticator::new(kvs));

        let handler = HttpHandler::new(HandlerOptions {
            authenticator: Some(auth),
            ..Default::default()
        });

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(conn).await.ok();
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        client.write_all(req.as_bytes()).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = client.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("407"));
    }

    #[tokio::test]
    async fn test_http_handler_bypass() {
        use std::sync::Arc;

        let bypass = Arc::new(crate::bypass::Bypass::from_patterns(
            false,
            &["blocked.com"],
        ));
        let handler = HttpHandler::new(HandlerOptions {
            bypass: Some(bypass),
            ..Default::default()
        });

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(conn).await.ok();
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let req = "CONNECT blocked.com:443 HTTP/1.1\r\nHost: blocked.com\r\n\r\n";
        client.write_all(req.as_bytes()).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = client.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("403"));
    }

    #[tokio::test]
    async fn test_http_handler_blacklist() {
        let blacklist = crate::permissions::Permissions::parse("tcp:evil.com:*").unwrap();
        let handler = HttpHandler::new(HandlerOptions {
            blacklist: Some(blacklist),
            ..Default::default()
        });

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(conn).await.ok();
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let req = "CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com\r\n\r\n";
        client.write_all(req.as_bytes()).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = client.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("403"));
    }

    #[tokio::test]
    async fn test_http_handler_auth_success() {
        use std::collections::HashMap;
        use std::sync::Arc;

        let mut kvs = HashMap::new();
        kvs.insert("admin".into(), "secret".into());
        let auth = Arc::new(crate::auth::LocalAuthenticator::new(kvs));

        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            conn.write_all(b"authenticated-ok").await.unwrap();
        });

        let handler = HttpHandler::new(HandlerOptions {
            authenticator: Some(auth),
            ..Default::default()
        });

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(conn).await.ok();
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        use base64::Engine;
        let creds = base64::engine::general_purpose::STANDARD.encode("admin:secret");
        let req = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Authorization: Basic {}\r\n\r\n",
            target_addr, target_addr, creds
        );
        client.write_all(req.as_bytes()).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = client.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("200"));

        let mut data = vec![0u8; 1024];
        let n = client.read(&mut data).await.unwrap();
        assert_eq!(&data[..n], b"authenticated-ok");
    }

    #[tokio::test]
    async fn test_http_handler_malformed_request() {
        let handler = HttpHandler::new(HandlerOptions::default());
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            // Malformed request should not panic
            handler.handle(conn).await.ok();
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(b"GARBAGE\r\n\r\n").await.unwrap();
        // Just verify it doesn't hang or panic
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    #[test]
    fn test_origin_form() {
        assert_eq!(origin_form("http://example.com/a/b?x=1"), "/a/b?x=1");
        assert_eq!(origin_form("http://example.com"), "/");
        // Already origin-form, or not a URL at all: pass through untouched.
        assert_eq!(origin_form("/already/origin"), "/already/origin");
        assert_eq!(origin_form("example.com:443"), "example.com:443");
    }

    /// A POST whose body arrives in the same TCP segment as its headers must
    /// reach the origin server. The header reader buffers ahead, so those
    /// bytes were previously dropped along with the reader.
    #[tokio::test]
    async fn test_forward_mode_preserves_coalesced_request_body() {
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();

        let received = tokio::spawn(async move {
            let (mut conn, _) = origin.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let mut total = Vec::new();
            // Read until we have the terminator plus the body.
            while !total.windows(9).any(|w| w == b"BODY-HERE") {
                let n = conn.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                total.extend_from_slice(&buf[..n]);
            }
            String::from_utf8_lossy(&total).to_string()
        });

        let handler = HttpHandler::new(HandlerOptions::default());
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(conn).await.ok();
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        // Headers and body written together, as a client sending a small body does.
        let req = format!(
            "POST http://{}/submit HTTP/1.1\r\nHost: {}\r\nContent-Length: 9\r\n\r\nBODY-HERE",
            origin_addr, origin_addr
        );
        client.write_all(req.as_bytes()).await.unwrap();

        let got = tokio::time::timeout(std::time::Duration::from_secs(5), received)
            .await
            .expect("origin server did not receive the body")
            .unwrap();

        assert!(got.contains("BODY-HERE"), "request body was dropped: {:?}", got);
        assert!(
            got.starts_with("POST /submit HTTP/1.1"),
            "expected origin-form request line, got: {:?}",
            got.lines().next()
        );
    }
}
