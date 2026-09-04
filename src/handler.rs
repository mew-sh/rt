use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::auth::Authenticator;
use crate::bypass::Bypass;
use crate::chain::Chain;
use crate::conn::ProxyConn;
use crate::node::Node;
use crate::permissions::Permissions;

/// Handler is a proxy server handler.
///
/// Takes a [`ProxyConn`] rather than a `TcpStream` so the same handler can
/// serve a raw socket, a TLS session, or any other transport.
#[async_trait]
pub trait Handler: Send + Sync + 'static {
    async fn handle(&self, conn: ProxyConn) -> Result<(), HandlerError>;
}

/// Lets a listener hold a `Box<dyn Handler>`, so protocol selection and
/// transport selection can be decided independently of each other.
#[async_trait]
impl Handler for Box<dyn Handler> {
    async fn handle(&self, conn: ProxyConn) -> Result<(), HandlerError> {
        (**self).handle(conn).await
    }
}

/// HandlerOptions describes the options for Handler.
#[derive(Clone, Default)]
pub struct HandlerOptions {
    pub addr: String,
    pub chain: Option<Chain>,
    pub users: Vec<(String, Option<String>)>,
    pub authenticator: Option<Arc<dyn Authenticator>>,
    pub whitelist: Option<Permissions>,
    pub blacklist: Option<Permissions>,
    pub bypass: Option<Arc<Bypass>>,
    pub retries: usize,
    pub timeout: Duration,
    pub node: Option<Node>,
    pub host: String,
    pub proxy_agent: String,
    /// Node-selection settings for handlers that load-balance across several
    /// targets (`?strategy=`, `?max_fails=`, `?fail_timeout=`).
    pub strategy: String,
    pub max_fails: u32,
    pub fail_timeout: Duration,
    /// `?fastest_count=`: keep only the N lowest-latency targets. Zero
    /// disables the filter, as in gost.
    pub fastest_count: usize,
    /// `?probe_resist=`: what to answer an unauthenticated client with, so the
    /// listener does not identify itself as a proxy. One of `code:<n>`,
    /// `web:<url>`, `host:<addr>` or `file:<path>`.
    pub probe_resist: String,
    /// `?knock=`: a host that bypasses probe resistance, letting an operator
    /// still reach the real 407.
    pub knocking_host: String,
}

impl HandlerOptions {
    /// Whether this listener has credentials configured, in any of the forms
    /// gost accepts (inline userinfo, a `secrets` file, or both).
    pub fn requires_auth(&self) -> bool {
        !self.users.is_empty() || self.authenticator.is_some()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HandlerError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("proxy error: {0}")]
    Proxy(String),
    #[error("authentication failed")]
    AuthFailed,
    #[error("forbidden")]
    Forbidden,
    #[error("chain error: {0}")]
    Chain(#[from] crate::chain::ChainError),
}

/// AutoHandler detects the protocol from the first byte.
pub struct AutoHandler {
    options: HandlerOptions,
}

impl AutoHandler {
    pub fn new(options: HandlerOptions) -> Self {
        Self { options }
    }
}

#[async_trait]
impl Handler for AutoHandler {
    async fn handle(&self, mut conn: ProxyConn) -> Result<(), HandlerError> {
        let mut peek_buf = [0u8; 1];
        let n = conn.peek(&mut peek_buf).await?;
        if n == 0 {
            return Err(HandlerError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed",
            )));
        }

        match peek_buf[0] {
            0x05 => {
                // SOCKS5
                let handler = crate::socks5::Socks5Handler::new(self.options.clone());
                handler.handle(conn).await
            }
            0x04 => {
                // SOCKS4(a) has no authentication method, so refuse it outright
                // when credentials are configured — otherwise an auto listener
                // with a secrets file would still be an open proxy over SOCKS4.
                if self.options.requires_auth() {
                    return Err(HandlerError::AuthFailed);
                }
                let handler = crate::socks4::Socks4Handler::new(self.options.clone());
                handler.handle(conn).await
            }
            _ => {
                // Assume HTTP
                let handler = crate::http_proxy::HttpHandler::new(self.options.clone());
                handler.handle(conn).await
            }
        }
    }
}

/// Helper: parse Basic Proxy-Authorization header.
pub fn basic_proxy_auth(auth: &str) -> (String, String, bool) {
    if auth.is_empty() || !auth.starts_with("Basic ") {
        return (String::new(), String::new(), false);
    }

    let encoded = &auth[6..];
    match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded) {
        Ok(decoded) => {
            let s = String::from_utf8_lossy(&decoded);
            if let Some(idx) = s.find(':') {
                (s[..idx].to_string(), s[idx + 1..].to_string(), true)
            } else {
                (String::new(), String::new(), false)
            }
        }
        Err(_) => (String::new(), String::new(), false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_proxy_auth() {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:pass");
        let auth = format!("Basic {}", encoded);
        let (u, p, ok) = basic_proxy_auth(&auth);
        assert!(ok);
        assert_eq!(u, "user");
        assert_eq!(p, "pass");
    }

    #[test]
    fn test_basic_proxy_auth_empty() {
        let (u, p, ok) = basic_proxy_auth("");
        assert!(!ok);
        assert!(u.is_empty());
        assert!(p.is_empty());
    }

    #[test]
    fn test_basic_proxy_auth_invalid() {
        let (_, _, ok) = basic_proxy_auth("Bearer token");
        assert!(!ok);
    }

    #[test]
    fn test_basic_proxy_auth_no_colon() {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode("useronly");
        let auth = format!("Basic {}", encoded);
        let (_, _, ok) = basic_proxy_auth(&auth);
        assert!(!ok);
    }

    #[test]
    fn test_basic_proxy_auth_empty_password() {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:");
        let auth = format!("Basic {}", encoded);
        let (u, p, ok) = basic_proxy_auth(&auth);
        assert!(ok);
        assert_eq!(u, "user");
        assert_eq!(p, "");
    }

    #[test]
    fn test_basic_proxy_auth_colon_in_password() {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:pa:ss:word");
        let auth = format!("Basic {}", encoded);
        let (u, p, ok) = basic_proxy_auth(&auth);
        assert!(ok);
        assert_eq!(u, "user");
        assert_eq!(p, "pa:ss:word");
    }

    #[test]
    fn test_basic_proxy_auth_invalid_base64() {
        let (_, _, ok) = basic_proxy_auth("Basic !!!invalid!!!");
        assert!(!ok);
    }

    #[tokio::test]
    async fn test_auto_handler_socks5_detection() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        let handler = AutoHandler::new(HandlerOptions::default());

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(ProxyConn::from_tcp(conn)).await.ok();
        });

        // Send SOCKS5 greeting (version byte 0x05)
        let mut client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();

        // Should get SOCKS5 response
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[0], 0x05); // SOCKS5 version in response
    }

    #[tokio::test]
    async fn test_auto_handler_socks4_detection() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        // Start a target to connect to
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            conn.write_all(b"auto-socks4").await.unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        let handler = AutoHandler::new(HandlerOptions::default());

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(ProxyConn::from_tcp(conn)).await.ok();
        });

        // Send SOCKS4 CONNECT (version byte 0x04)
        let mut client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        let ip = match target_addr.ip() {
            std::net::IpAddr::V4(ip4) => ip4,
            _ => panic!("expected IPv4"),
        };
        let port = target_addr.port();
        let mut req = vec![0x04, 0x01];
        req.extend_from_slice(&port.to_be_bytes());
        req.extend_from_slice(&ip.octets());
        req.push(0x00);
        client.write_all(&req).await.unwrap();

        // Should get SOCKS4 reply (byte 0 = 0x00, byte 1 = 0x5A = granted)
        let mut resp = [0u8; 8];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[1], 0x5A);
    }

    #[tokio::test]
    async fn test_auto_handler_http_detection() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            conn.write_all(b"auto-http-target").await.unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        let handler = AutoHandler::new(HandlerOptions::default());

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(ProxyConn::from_tcp(conn)).await.ok();
        });

        // Send HTTP CONNECT (starts with 'C' = 0x43, not 0x04 or 0x05)
        let mut client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        let req = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
            target_addr, target_addr
        );
        client.write_all(req.as_bytes()).await.unwrap();

        // One read can return a partial status line, so drain to the blank
        // line before asserting on the status.
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            let n = client.read(&mut byte).await.unwrap();
            assert_ne!(n, 0, "peer closed before finishing the response head");
            head.push(byte[0]);
        }
        assert!(String::from_utf8_lossy(&head).contains("200"));
    }

    #[test]
    fn test_handler_options_default() {
        let opts = HandlerOptions::default();
        assert!(opts.chain.is_none());
        assert!(opts.authenticator.is_none());
        assert!(opts.whitelist.is_none());
        assert!(opts.blacklist.is_none());
        assert!(opts.bypass.is_none());
        assert!(opts.node.is_none());
        assert_eq!(opts.retries, 0);
        assert!(opts.proxy_agent.is_empty());
    }
}
