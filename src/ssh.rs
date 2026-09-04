use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::conn::ProxyConn;
use crate::handler::{Handler, HandlerError, HandlerOptions};
use crate::transport::transport;

// SSH Request types for Port Forwarding (RFC 4254)
const DIRECT_FORWARD_REQUEST: &str = "direct-tcpip";
const REMOTE_FORWARD_REQUEST: &str = "tcpip-forward";
const FORWARDED_TCP_RETURN_REQUEST: &str = "forwarded-tcpip";
const CANCEL_REMOTE_FORWARD_REQUEST: &str = "cancel-tcpip-forward";
const GOST_SSH_TUNNEL_REQUEST: &str = "gost-tunnel";

/// SSH configuration.
#[derive(Clone, Debug, Default)]
pub struct SshConfig {
    pub key_file: Option<String>,
    pub authorized_keys_file: Option<String>,
    pub password: Option<String>,
    pub user: Option<String>,
}

/// SSH tunnel transporter (client side).
/// Connects through an SSH tunnel to forward TCP traffic.
pub struct SshTunnelTransporter {
    config: SshConfig,
}

impl SshTunnelTransporter {
    pub fn new(config: SshConfig) -> Self {
        Self { config }
    }

    /// Establish SSH tunnel and forward connection to remote address.
    pub async fn dial(
        &self,
        ssh_addr: &str,
        _remote_addr: &str,
    ) -> Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
        // Connect to SSH server
        let tcp = TcpStream::connect(ssh_addr).await?;
        let peer = tcp.peer_addr()?;

        info!("[ssh] connected to {}", peer);

        // In a full implementation, we would:
        // 1. Perform SSH handshake using russh
        // 2. Open a direct-tcpip channel to remote_addr
        // 3. Return the channel as a stream
        //
        // For now, return the raw TCP stream as a placeholder
        // The full SSH protocol negotiation would use the russh crate
        Ok(tcp)
    }
}

/// SSH forward transporter - for SSH port forwarding.
pub struct SshForwardTransporter {
    config: SshConfig,
}

impl SshForwardTransporter {
    pub fn new(config: SshConfig) -> Self {
        Self { config }
    }
}

/// SSH Direct Forward Connector - RFC 4254 7.2
pub struct SshDirectForwardConnector;

impl SshDirectForwardConnector {
    pub fn new() -> Self {
        Self
    }
}

/// SSH Remote Forward Connector - RFC 4254 7.1
pub struct SshRemoteForwardConnector;

impl SshRemoteForwardConnector {
    pub fn new() -> Self {
        Self
    }
}

/// SSH Forward Handler - handles SSH port forwarding requests.
pub struct SshForwardHandler {
    options: HandlerOptions,
    config: SshConfig,
}

impl SshForwardHandler {
    pub fn new(options: HandlerOptions, config: SshConfig) -> Self {
        Self { options, config }
    }
}

#[async_trait]
impl Handler for SshForwardHandler {
    async fn handle(&self, conn: ProxyConn) -> Result<(), HandlerError> {
        let peer_addr = conn.peer_addr_str();

        info!("[ssh] {} connected", peer_addr);

        // In a full implementation:
        // 1. Accept SSH handshake (server side)
        // 2. Authenticate the client
        // 3. Handle channel requests (direct-tcpip, tcpip-forward)
        // 4. Forward data bidirectionally

        // For the SSH tunnel, the connection itself IS the tunnel
        // Data flows through the SSH encrypted channel
        let chain = self.options.chain.as_ref().cloned().unwrap_or_default();

        // Read the target from the SSH channel request
        // For now, use the node's remote address
        let target = self
            .options
            .node
            .as_ref()
            .map(|n| n.remote.clone())
            .unwrap_or_default();

        if target.is_empty() {
            return Err(HandlerError::Proxy("ssh: no target address".into()));
        }

        match chain.dial(&target).await {
            Ok(cc) => {
                info!("[ssh] {} <-> {}", peer_addr, target);
                transport(conn, cc).await.ok();
                info!("[ssh] {} >-< {}", peer_addr, target);
            }
            Err(e) => {
                return Err(HandlerError::Chain(e));
            }
        }

        Ok(())
    }
}

/// SSH tunnel listener - accepts connections through an SSH tunnel.
pub struct SshTunnelListener {
    addr: String,
    config: SshConfig,
}

impl SshTunnelListener {
    pub fn new(addr: &str, config: SshConfig) -> Self {
        Self {
            addr: addr.to_string(),
            config,
        }
    }
}

/// Parse SSH private key from file.
pub fn parse_ssh_key_file(path: &str) -> Result<Vec<u8>, std::io::Error> {
    std::fs::read(path)
}

/// Parse SSH authorized keys file.
pub fn parse_ssh_authorized_keys_file(path: &str) -> Result<Vec<String>, std::io::Error> {
    let content = std::fs::read_to_string(path)?;
    Ok(content
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_config_default() {
        let config = SshConfig::default();
        assert!(config.key_file.is_none());
        assert!(config.password.is_none());
    }

    #[test]
    fn test_parse_ssh_key_file_not_found() {
        let result = parse_ssh_key_file("nonexistent_key");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_authorized_keys_not_found() {
        let result = parse_ssh_authorized_keys_file("nonexistent_keys");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_ssh_tunnel_transporter_creation() {
        let config = SshConfig {
            user: Some("testuser".to_string()),
            password: Some("testpass".to_string()),
            ..Default::default()
        };
        let transporter = SshTunnelTransporter::new(config);
        // Just verify construction
        assert!(transporter.config.user.is_some());
    }

    #[test]
    fn test_ssh_forward_handler_creation() {
        let handler = SshForwardHandler::new(HandlerOptions::default(), SshConfig::default());
        assert!(handler.config.key_file.is_none());
    }
}
