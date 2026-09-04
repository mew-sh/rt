use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info};

use crate::conn::ProxyConn;
use crate::handler::{Handler, HandlerError, HandlerOptions};
use crate::node::{Node, NodeGroup};
use crate::transport::transport;

/// TCP Remote Forward Handler - accepts connections from remote proxy
/// and forwards to local targets.
pub struct TcpRemoteForwardHandler {
    raddr: String,
    group: NodeGroup,
    options: HandlerOptions,
}

impl TcpRemoteForwardHandler {
    pub fn new(raddr: &str, options: HandlerOptions) -> Self {
        let group = NodeGroup::new(Vec::new());
        let addrs: Vec<&str> = raddr.split(',').filter(|a| !a.is_empty()).collect();

        for (i, addr) in addrs.iter().enumerate() {
            let mut node = Node::default();
            node.id = i + 1;
            node.addr = addr.to_string();
            node.host = addr.to_string();
            group.add_node(node);
        }

        Self {
            raddr: raddr.to_string(),
            group,
            options,
        }
    }
}

#[async_trait]
impl Handler for TcpRemoteForwardHandler {
    async fn handle(&self, conn: ProxyConn) -> Result<(), HandlerError> {
        let retries = if self.options.retries > 0 {
            self.options.retries
        } else {
            1
        };

        let mut cc = None;
        let mut node = Node::default();
        let mut last_err = None;

        for _ in 0..retries {
            if !self.group.nodes().is_empty() {
                match self.group.next() {
                    Ok(n) => node = n,
                    Err(e) => {
                        info!("[rtcp] {} : {}", self.raddr, e);
                        return Err(HandlerError::Proxy(e.to_string()));
                    }
                }
            }

            let target = if node.addr.is_empty() {
                &self.raddr
            } else {
                &node.addr
            };

            let timeout = if self.options.timeout.as_secs() > 0 {
                self.options.timeout
            } else {
                std::time::Duration::from_secs(crate::DIAL_TIMEOUT)
            };

            match tokio::time::timeout(timeout, TcpStream::connect(target)).await {
                Ok(Ok(c)) => {
                    cc = Some(c);
                    break;
                }
                Ok(Err(e)) => {
                    debug!("[rtcp] -> {} : {}", target, e);
                    node.mark_dead();
                    last_err = Some(HandlerError::Io(e));
                }
                Err(_) => {
                    node.mark_dead();
                    last_err = Some(HandlerError::Proxy("connection timeout".into()));
                }
            }
        }

        let cc = match cc {
            Some(c) => c,
            None => {
                return Err(last_err.unwrap_or(HandlerError::Proxy("no target".into())));
            }
        };

        node.reset_dead();

        let peer = conn.local_addr().map(|a| a.to_string()).unwrap_or_default();

        info!("[rtcp] {} <-> {}", peer, node.addr);
        transport(cc, conn).await.ok();
        info!("[rtcp] {} >-< {}", peer, node.addr);

        Ok(())
    }
}

/// TCP Remote Forward Listener - listens on a remote address
/// via a proxy chain, accepting connections to forward locally.
pub struct TcpRemoteForwardListener {
    addr: String,
    local_target: String,
}

impl TcpRemoteForwardListener {
    pub fn new(listen_addr: &str, local_target: &str) -> Self {
        Self {
            addr: listen_addr.to_string(),
            local_target: local_target.to_string(),
        }
    }

    /// Listen on the remote address and forward connections to local target.
    pub async fn serve(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(&self.addr).await?;
        info!(
            "[rtcp] Listening on {}, forwarding to {}",
            self.addr, self.local_target
        );

        loop {
            let (conn, peer_addr) = listener.accept().await?;
            let target = self.local_target.clone();

            tokio::spawn(async move {
                match TcpStream::connect(&target).await {
                    Ok(cc) => {
                        info!("[rtcp] {} <-> {}", peer_addr, target);
                        transport(conn, cc).await.ok();
                        info!("[rtcp] {} >-< {}", peer_addr, target);
                    }
                    Err(e) => {
                        debug!("[rtcp] {} -> {} : {}", peer_addr, target, e);
                    }
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tcp_remote_forward_handler() {
        // Start a mock local target
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = conn.read(&mut buf).await.unwrap();
            conn.write_all(&buf[..n]).await.unwrap(); // echo
        });

        // Create remote forward handler
        let handler =
            TcpRemoteForwardHandler::new(&target_addr.to_string(), HandlerOptions::default());

        // Start proxy that uses the handler
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(ProxyConn::from_tcp(conn)).await.ok();
        });

        // Connect to proxy and send data
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(b"reverse tunnel").await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"reverse tunnel");
    }

    #[tokio::test]
    async fn test_tcp_remote_forward_listener() {
        // Start a mock local target that echoes
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = conn.read(&mut buf).await.unwrap();
            conn.write_all(&buf[..n]).await.unwrap();
        });

        // Create remote forward listener
        let listener_bind = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = listener_bind.local_addr().unwrap();
        drop(listener_bind); // release the port

        let rfwd =
            TcpRemoteForwardListener::new(&listener_addr.to_string(), &target_addr.to_string());

        let handle = tokio::spawn(async move {
            rfwd.serve().await.ok();
        });

        // Wait for listener to be ready
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect and test
        let mut client = TcpStream::connect(listener_addr).await.unwrap();
        client.write_all(b"remote fwd").await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"remote fwd");

        handle.abort();
    }
}
