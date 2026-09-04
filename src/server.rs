use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{error, info};

use crate::handler::Handler;

/// Server is a proxy server with graceful shutdown support.
///
/// Uses a `CancellationToken` so that all spawned connection handlers
/// are notified on shutdown, and a `TaskTracker` so the server can
/// wait for in-flight connections to drain before exiting.
pub struct Server {
    listener: TcpListener,
    handler: Arc<dyn Handler>,
    cancel: CancellationToken,
    tracker: TaskTracker,
    /// Whether to read SO_ORIGINAL_DST from each accepted socket. Only a
    /// transparent-proxy listener needs it, and it has to happen here because
    /// the raw socket is not reachable once the stream is boxed.
    capture_original_dst: bool,
}

impl Server {
    /// Creates a new server bound to the given address.
    pub async fn new(
        addr: &str,
        handler: impl Handler + 'static,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(addr).await?;
        info!("Listening on {}", listener.local_addr()?);

        Ok(Server {
            listener,
            handler: Arc::new(handler),
            cancel: CancellationToken::new(),
            tracker: TaskTracker::new(),
            capture_original_dst: false,
        })
    }

    /// Creates a server from an existing TcpListener.
    pub fn from_listener(listener: TcpListener, handler: impl Handler + 'static) -> Self {
        Server {
            listener,
            handler: Arc::new(handler),
            cancel: CancellationToken::new(),
            tracker: TaskTracker::new(),
            capture_original_dst: false,
        }
    }

    /// Reads the pre-NAT destination from each accepted socket and attaches it
    /// to the connection. Only meaningful for a transparent-proxy listener.
    pub fn with_original_dst(mut self, enabled: bool) -> Self {
        self.capture_original_dst = enabled;
        self
    }

    /// Returns the local address the server is bound to.
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Returns a CancellationToken that can be used to trigger graceful shutdown.
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// Serve accepts connections and handles them.
    ///
    /// When the cancellation token is cancelled, the server stops accepting
    /// new connections and waits for all in-flight handlers to complete.
    pub async fn serve(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut temp_delay = Duration::ZERO;

        loop {
            tokio::select! {
                // Check for cancellation before accepting
                _ = self.cancel.cancelled() => {
                    info!("[server] shutdown signal received, draining connections...");
                    break;
                }
                result = self.listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            temp_delay = Duration::ZERO;
                            let handler = self.handler.clone();
                            let cancel = self.cancel.clone();
                            // Must be read here, while the raw socket still exists.
                            let original_dst = if self.capture_original_dst {
                                crate::redirect::original_dst(&stream)
                            } else {
                                None
                            };

                            // Spawn through TaskTracker so we can wait for completion
                            self.tracker.spawn(async move {
                                let conn = crate::conn::ProxyConn::from_tcp(stream)
                                    .with_original_dst(original_dst);
                                tokio::select! {
                                    result = handler.handle(conn) => {
                                        if let Err(e) = result {
                                            tracing::debug!("[server] {} : {}", peer_addr, e);
                                        }
                                    }
                                    _ = cancel.cancelled() => {
                                        tracing::debug!("[server] {} : cancelled", peer_addr);
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
                            error!("Accept error: {}; retrying in {:?}", e, temp_delay);
                            tokio::time::sleep(temp_delay).await;
                        }
                    }
                }
            }
        }

        // Close the tracker so wait() can complete
        self.tracker.close();

        // Wait for all in-flight connections to finish (with a timeout)
        let drain_timeout = Duration::from_secs(10);
        if tokio::time::timeout(drain_timeout, self.tracker.wait())
            .await
            .is_err()
        {
            tracing::warn!(
                "[server] drain timeout after {:?}, {} tasks still running",
                drain_timeout,
                self.tracker.len()
            );
        } else {
            info!("[server] all connections drained");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::ProxyConn;
    use crate::handler::{Handler, HandlerError};
    use async_trait::async_trait;
    use tokio::net::TcpStream;

    struct EchoHandler;

    #[async_trait]
    impl Handler for EchoHandler {
        async fn handle(&self, mut conn: ProxyConn) -> Result<(), HandlerError> {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = vec![0u8; 1024];
            let n = conn.read(&mut buf).await?;
            conn.write_all(&buf[..n]).await?;
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_server_echo() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = Server::from_listener(listener, EchoHandler);
        let cancel = server.cancel_token();

        let server_handle = tokio::spawn(async move {
            server.serve().await.ok();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(b"hello rustun").await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello rustun");

        // Graceful shutdown instead of abort
        cancel.cancel();
        let result = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
        assert!(result.is_ok(), "server should shut down within 2 seconds");
    }

    #[tokio::test]
    async fn test_server_graceful_shutdown() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = Server::from_listener(listener, EchoHandler);
        let cancel = server.cancel_token();

        let handle = tokio::spawn(async move {
            server.serve().await.ok();
        });

        // Cancel immediately
        cancel.cancel();

        let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(result.is_ok(), "server should exit promptly on cancel");
    }
}
