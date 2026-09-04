use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

use crate::conn::ProxyConn;
use crate::handler::{Handler, HandlerError, HandlerOptions};
use crate::transport::transport;

/// HTTP/2 connector - tunnels through an HTTP/2 proxy using CONNECT.
pub struct Http2Connector {
    pub user: Option<(String, Option<String>)>,
}

impl Http2Connector {
    pub fn new(user: Option<(String, Option<String>)>) -> Self {
        Self { user }
    }

    /// Connect through HTTP/2 proxy using CONNECT method.
    /// This is similar to HTTP CONNECT but over HTTP/2.
    pub async fn connect(
        &self,
        mut conn: TcpStream,
        address: &str,
    ) -> Result<TcpStream, HandlerError> {
        // In a full implementation, we'd use the h2 crate to:
        // 1. Establish HTTP/2 connection
        // 2. Send CONNECT pseudo-request
        // 3. Return the h2 stream as a bidirectional channel
        //
        // For now, fall back to HTTP/1.1 CONNECT (works over TLS)
        let connector = crate::http_proxy::HttpConnector::new(self.user.clone());
        connector.connect(conn, address).await
    }
}

/// HTTP/2 transport - wraps TCP in HTTP/2 framing.
pub struct Http2Transporter {
    tls: bool,
    path: String,
}

impl Http2Transporter {
    /// Create HTTP/2 transporter with TLS (h2).
    pub fn new_h2(path: &str) -> Self {
        Self {
            tls: true,
            path: if path.is_empty() {
                "/".to_string()
            } else {
                path.to_string()
            },
        }
    }

    /// Create HTTP/2 transporter without TLS (h2c).
    pub fn new_h2c(path: &str) -> Self {
        Self {
            tls: false,
            path: if path.is_empty() {
                "/".to_string()
            } else {
                path.to_string()
            },
        }
    }
}

/// HTTP/2 handler - accepts HTTP/2 connections and handles CONNECT tunneling.
pub struct Http2Handler {
    options: HandlerOptions,
}

impl Http2Handler {
    pub fn new(options: HandlerOptions) -> Self {
        Self { options }
    }
}

#[async_trait]
impl Handler for Http2Handler {
    async fn handle(&self, conn: ProxyConn) -> Result<(), HandlerError> {
        let peer_addr = conn.peer_addr_str();

        info!("[http2] {} connected", peer_addr);

        // In a full implementation using the h2 crate:
        // 1. Accept HTTP/2 connection
        // 2. Handle CONNECT requests by establishing tunnel
        // 3. Handle regular HTTP/2 requests by proxying
        //
        // For now, delegate to the HTTP handler which handles
        // HTTP/1.1 CONNECT (HTTP/2 CONNECT is very similar)
        let handler = crate::http_proxy::HttpHandler::new(self.options.clone());
        handler.handle(conn).await
    }
}

/// HTTP/2 listener config.
#[derive(Clone, Debug)]
pub struct Http2ListenerConfig {
    pub path: String,
    pub tls: bool,
}

impl Default for Http2ListenerConfig {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            tls: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http2_transporter_h2() {
        let t = Http2Transporter::new_h2("/tunnel");
        assert!(t.tls);
        assert_eq!(t.path, "/tunnel");
    }

    #[test]
    fn test_http2_transporter_h2c() {
        let t = Http2Transporter::new_h2c("");
        assert!(!t.tls);
        assert_eq!(t.path, "/");
    }

    #[test]
    fn test_http2_connector_creation() {
        let c = Http2Connector::new(Some(("user".into(), Some("pass".into()))));
        assert!(c.user.is_some());
    }

    #[test]
    fn test_http2_handler_creation() {
        let h = Http2Handler::new(HandlerOptions::default());
        assert!(h.options.chain.is_none());
    }

    #[tokio::test]
    async fn test_http2_handler_connect() {
        use tokio::net::TcpListener;

        // Start a mock target
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            conn.write_all(b"h2 ok").await.unwrap();
        });

        // HTTP/2 handler (falls back to HTTP/1.1 CONNECT for now)
        let handler = Http2Handler::new(HandlerOptions::default());
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(ProxyConn::from_tcp(conn)).await.ok();
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let req = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
            target_addr, target_addr
        );
        client.write_all(req.as_bytes()).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = client.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("200"));

        let mut data = vec![0u8; 1024];
        let n = client.read(&mut data).await.unwrap();
        assert_eq!(&data[..n], b"h2 ok");
    }
}
