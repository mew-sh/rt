use std::sync::Arc;

use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    connect_async, tungstenite::protocol::Message, MaybeTlsStream, WebSocketStream,
};
use tracing::{debug, info};

use crate::conn::ProxyConn;
use crate::handler::{Handler, HandlerError, HandlerOptions};
use crate::transport::transport;

/// WebSocket options.
#[derive(Clone, Debug, Default)]
pub struct WsOptions {
    pub path: String,
    pub enable_compression: bool,
    pub user_agent: String,
}

/// WebSocket transporter (client side) - wraps connections in WebSocket.
pub struct WsTransporter {
    pub options: WsOptions,
}

impl WsTransporter {
    pub fn new(options: WsOptions) -> Self {
        Self { options }
    }

    /// Dial a WebSocket connection to the given address.
    pub async fn dial(
        &self,
        addr: &str,
    ) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, Box<dyn std::error::Error + Send + Sync>>
    {
        let path = if self.options.path.is_empty() {
            "/"
        } else {
            &self.options.path
        };
        let url = format!("ws://{}{}", addr, path);
        let (ws_stream, _) = connect_async(&url).await?;
        Ok(ws_stream)
    }
}

/// Secure WebSocket transporter (client side).
pub struct WssTransporter {
    pub options: WsOptions,
}

impl WssTransporter {
    pub fn new(options: WsOptions) -> Self {
        Self { options }
    }

    /// Dial a secure WebSocket connection.
    pub async fn dial(
        &self,
        addr: &str,
    ) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, Box<dyn std::error::Error + Send + Sync>>
    {
        let path = if self.options.path.is_empty() {
            "/"
        } else {
            &self.options.path
        };
        let url = format!("wss://{}{}", addr, path);
        let (ws_stream, _) = connect_async(&url).await?;
        Ok(ws_stream)
    }
}

/// WebSocket handler - upgrades HTTP connections to WebSocket and
/// proxies data through the chain.
pub struct WsHandler {
    options: HandlerOptions,
    ws_options: WsOptions,
}

impl WsHandler {
    pub fn new(options: HandlerOptions, ws_options: WsOptions) -> Self {
        Self {
            options,
            ws_options,
        }
    }
}

#[async_trait]
impl Handler for WsHandler {
    async fn handle(&self, conn: ProxyConn) -> Result<(), HandlerError> {
        let peer_addr = conn.peer_addr_str();

        info!("[ws] {} connected", peer_addr);

        // Accept WebSocket upgrade
        let ws_stream = tokio_tungstenite::accept_async(conn)
            .await
            .map_err(|e| HandlerError::Proxy(format!("WebSocket upgrade failed: {}", e)))?;

        let (mut ws_write, mut ws_read) = ws_stream.split();

        // Read the first message to determine the target (if any)
        // In gost, WebSocket is used as a transport layer, so data flows through
        // For this implementation, we relay WebSocket messages bidirectionally

        // The WebSocket acts as a tunnel - just relay binary data
        let chain = self.options.chain.as_ref().cloned().unwrap_or_default();

        // For WebSocket tunneling, we expect the client to send the target address
        // as the first binary message, then relay subsequent data
        if let Some(msg) = ws_read.next().await {
            match msg {
                Ok(Message::Binary(data)) => {
                    // First message could be target address for tunneling
                    let target = String::from_utf8_lossy(&data).to_string();
                    if let Ok(cc) = chain.dial(&target).await {
                        info!("[ws] {} <-> {}", peer_addr, target);

                        // Create a relay between WebSocket and TCP
                        let (mut tcp_read, mut tcp_write) = tokio::io::split(cc);

                        // WebSocket -> TCP
                        let mut ws_to_tcp = tokio::spawn(async move {
                            while let Some(Ok(msg)) = ws_read.next().await {
                                if let Message::Binary(data) = msg {
                                    if tcp_write.write_all(&data).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        });

                        // TCP -> WebSocket
                        let mut tcp_to_ws = tokio::spawn(async move {
                            let mut buf = vec![0u8; 32768];
                            loop {
                                match tcp_read.read(&mut buf).await {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        if ws_write
                                            .send(Message::Binary(buf[..n].to_vec()))
                                            .await
                                            .is_err()
                                        {
                                            break;
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                        });

                        // Wait for either direction to finish, abort the other
                        // to prevent leaked tasks
                        tokio::select! {
                            _ = &mut ws_to_tcp => { tcp_to_ws.abort(); }
                            _ = &mut tcp_to_ws => { ws_to_tcp.abort(); }
                        }

                        info!("[ws] {} >-< {}", peer_addr, target);
                    }
                }
                Ok(Message::Close(_)) => {}
                Err(e) => {
                    debug!("[ws] {} error: {}", peer_addr, e);
                }
                _ => {}
            }
        }

        Ok(())
    }
}

/// WebSocket listener - accepts WebSocket connections on a TCP listener.
pub struct WsListener {
    pub addr: String,
    pub options: WsOptions,
}

impl WsListener {
    pub fn new(addr: &str, options: WsOptions) -> Self {
        Self {
            addr: addr.to_string(),
            options,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ws_options_default() {
        let opts = WsOptions::default();
        assert!(opts.path.is_empty());
        assert!(!opts.enable_compression);
    }

    #[test]
    fn test_ws_transporter_creation() {
        let opts = WsOptions {
            path: "/ws".to_string(),
            enable_compression: true,
            user_agent: "test".to_string(),
        };
        let t = WsTransporter::new(opts.clone());
        assert_eq!(t.options.path, "/ws");
    }

    #[tokio::test]
    async fn test_ws_handler_creation() {
        let handler = WsHandler::new(HandlerOptions::default(), WsOptions::default());
        // Just verify it constructs without error
        assert!(handler.options.chain.is_none());
    }
}
