use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, info};

use crate::conn::ProxyConn;
use crate::handler::{Handler, HandlerError, HandlerOptions};
use crate::node::{Node, NodeGroup};
use crate::transport::transport;

/// TCP Direct Forward Handler - forwards TCP connections to a remote address.
pub struct TcpDirectForwardHandler {
    raddr: String,
    group: NodeGroup,
    options: HandlerOptions,
}

impl TcpDirectForwardHandler {
    pub fn new(raddr: &str, options: HandlerOptions) -> Self {
        let mut group = NodeGroup::new(Vec::new());

        // Parse comma-separated addresses
        let addrs: Vec<&str> = raddr
            .split(',')
            .chain(
                options
                    .node
                    .as_ref()
                    .and_then(|n| n.values.get("ip").map(|s| s.as_str())),
            )
            .filter(|a| !a.is_empty())
            .collect();

        for (i, addr) in addrs.iter().enumerate() {
            let mut node = Node::default();
            node.id = i + 1;
            node.addr = addr.to_string();
            node.host = addr.to_string();
            group.add_node(node);
        }

        // Without this, `mark_dead` records a failure that selection ignores,
        // so a dead target keeps being handed back on every request.
        group.set_selector(std::sync::Arc::new(
            crate::selector::FilterSelector::with_filters(
                &options.strategy,
                options.max_fails,
                options.fail_timeout,
                options.fastest_count,
            ),
        ));

        Self {
            raddr: raddr.to_string(),
            group,
            options,
        }
    }
}

#[async_trait]
impl Handler for TcpDirectForwardHandler {
    async fn handle(&self, conn: ProxyConn) -> Result<(), HandlerError> {
        let peer_addr = conn.peer_addr_str();
        let local_addr = conn.local_addr_str();

        info!("[tcp] {} - {}", peer_addr, local_addr);

        let retries = if self.options.retries > 0 {
            self.options.retries
        } else {
            1
        };

        let chain = self.options.chain.as_ref().cloned().unwrap_or_default();

        let mut cc = None;
        let mut node = Node::default();
        let mut last_err = None;

        for _ in 0..retries {
            if !self.group.nodes().is_empty() {
                match self.group.next() {
                    Ok(n) => node = n,
                    Err(e) => {
                        info!("[tcp] {} - {} : {}", peer_addr, local_addr, e);
                        return Err(HandlerError::Proxy(e.to_string()));
                    }
                }
            }

            let target = if node.addr.is_empty() {
                &self.raddr
            } else {
                &node.addr
            };

            match chain.dial(target).await {
                Ok(c) => {
                    cc = Some(c);
                    break;
                }
                Err(e) => {
                    debug!("[tcp] {} -> {} : {}", peer_addr, local_addr, e);
                    node.mark_dead();
                    last_err = Some(e);
                }
            }
        }

        let cc = match cc {
            Some(c) => c,
            None => {
                return Err(HandlerError::Proxy(format!(
                    "failed to connect to {}: {:?}",
                    self.raddr, last_err
                )));
            }
        };

        node.reset_dead();

        let addr = if node.addr.is_empty() {
            local_addr
        } else {
            node.addr.clone()
        };

        info!("[tcp] {} <-> {}", peer_addr, addr);
        transport(conn, cc).await.ok();
        info!("[tcp] {} >-< {}", peer_addr, addr);

        Ok(())
    }
}

/// UDP Direct Forward Handler.
pub struct UdpDirectForwardHandler {
    raddr: String,
    group: NodeGroup,
    options: HandlerOptions,
}

impl UdpDirectForwardHandler {
    pub fn new(raddr: &str, options: HandlerOptions) -> Self {
        let mut group = NodeGroup::new(Vec::new());
        let addrs: Vec<&str> = raddr.split(',').filter(|a| !a.is_empty()).collect();

        for (i, addr) in addrs.iter().enumerate() {
            let mut node = Node::default();
            node.id = i + 1;
            node.addr = addr.to_string();
            node.host = addr.to_string();
            group.add_node(node);
        }

        // Without this, `mark_dead` records a failure that selection ignores,
        // so a dead target keeps being handed back on every request.
        group.set_selector(std::sync::Arc::new(
            crate::selector::FilterSelector::with_filters(
                &options.strategy,
                options.max_fails,
                options.fail_timeout,
                options.fastest_count,
            ),
        ));

        Self {
            raddr: raddr.to_string(),
            group,
            options,
        }
    }
}

#[async_trait]
impl Handler for UdpDirectForwardHandler {
    async fn handle(&self, mut conn: ProxyConn) -> Result<(), HandlerError> {
        // UDP forwarding over TCP - read from TCP, forward as UDP
        let peer_addr = conn.peer_addr_str();

        info!("[udp] {} - forwarding to {}", peer_addr, self.raddr);

        let mut node = Node::default();
        if !self.group.nodes().is_empty() {
            match self.group.next() {
                Ok(n) => node = n,
                Err(e) => {
                    return Err(HandlerError::Proxy(e.to_string()));
                }
            }
        }

        let target = if node.addr.is_empty() {
            &self.raddr
        } else {
            &node.addr
        };

        let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
        udp_socket.connect(target).await?;

        // Simple UDP relay: read from TCP, send as UDP, and vice versa
        let mut tcp_buf = vec![0u8; 65535];
        let mut udp_buf = vec![0u8; 65535];
        loop {
            tokio::select! {
                result = conn.read(&mut tcp_buf) => {
                    match result {
                        Ok(0) => break,
                        Ok(n) => {
                            udp_socket.send(&tcp_buf[..n]).await?;
                        }
                        Err(e) => {
                            debug!("[udp] read error: {}", e);
                            break;
                        }
                    }
                }
                result = udp_socket.recv(&mut udp_buf) => {
                    match result {
                        Ok(n) => {
                            conn.write_all(&udp_buf[..n]).await?;
                        }
                        Err(e) => {
                            debug!("[udp] recv error: {}", e);
                            break;
                        }
                    }
                }
            }
        }

        info!("[udp] {} >-< {}", peer_addr, target);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_tcp_forward() {
        // Start a mock target server that echoes data
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = conn.read(&mut buf).await.unwrap();
            conn.write_all(&buf[..n]).await.unwrap();
        });

        // Start TCP forward proxy
        let handler =
            TcpDirectForwardHandler::new(&target_addr.to_string(), HandlerOptions::default());
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(ProxyConn::from_tcp(conn)).await.ok();
        });

        // Connect to forward proxy
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(b"hello forward").await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello forward");
    }

    #[tokio::test]
    async fn test_tcp_forward_multiple_targets() {
        let handler = TcpDirectForwardHandler::new(
            "127.0.0.1:8001,127.0.0.1:8002",
            HandlerOptions::default(),
        );
        assert_eq!(handler.group.nodes().len(), 2);
    }
}
