use tracing::info;

/// VSOCK address: context_id:port
#[derive(Clone, Debug)]
pub struct VsockAddr {
    pub context_id: u32,
    pub port: u32,
}

impl VsockAddr {
    /// Parse a VSOCK address string in format "context_id:port".
    pub fn parse(addr: &str) -> Result<Self, VsockError> {
        let (host_str, port_str) = addr
            .rsplit_once(':')
            .ok_or_else(|| VsockError::InvalidAddress(format!("missing port in '{}'", addr)))?;

        let context_id = if host_str.is_empty() {
            0
        } else {
            host_str
                .parse()
                .map_err(|_| VsockError::InvalidAddress(format!("invalid CID: {}", host_str)))?
        };

        let port = port_str
            .parse()
            .map_err(|_| VsockError::InvalidAddress(format!("invalid port: {}", port_str)))?;

        Ok(VsockAddr { context_id, port })
    }
}

impl std::fmt::Display for VsockAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.context_id, self.port)
    }
}

/// VSOCK transporter.
/// VSOCK (Virtual Socket) enables communication between
/// a virtual machine and its host, or between VMs.
///
/// Full implementation requires the `vsock` crate (Linux only).
pub struct VsockTransporter;

impl VsockTransporter {
    pub fn new() -> Self {
        Self
    }

    /// Dial a VSOCK connection.
    pub async fn dial(&self, addr: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let _vaddr = VsockAddr::parse(addr)?;
        #[cfg(target_os = "linux")]
        {
            info!("[vsock] dialing {}:{}", _vaddr.context_id, _vaddr.port);
            Err("VSOCK support requires the vsock crate".into())
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err("VSOCK is only supported on Linux".into())
        }
    }
}

/// VSOCK listener.
pub struct VsockListener {
    addr: VsockAddr,
}

impl VsockListener {
    pub fn new(addr: &str) -> Result<Self, VsockError> {
        let vaddr = VsockAddr::parse(addr)?;
        Ok(Self { addr: vaddr })
    }

    /// Start listening on the VSOCK address.
    #[cfg(target_os = "linux")]
    pub async fn listen(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("[vsock] listening on {}", self.addr);
        // In a full implementation: vsock::VsockListener::bind(cid, port)
        Err("VSOCK support requires the vsock crate".into())
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn listen(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Err("VSOCK is only supported on Linux".into())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VsockError {
    #[error("invalid VSOCK address: {0}")]
    InvalidAddress(String),
    #[error("VSOCK not supported on this platform")]
    NotSupported,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vsock_addr_parse() {
        let addr = VsockAddr::parse("2:1234").unwrap();
        assert_eq!(addr.context_id, 2);
        assert_eq!(addr.port, 1234);
    }

    #[test]
    fn test_vsock_addr_parse_empty_cid() {
        let addr = VsockAddr::parse(":1234").unwrap();
        assert_eq!(addr.context_id, 0);
        assert_eq!(addr.port, 1234);
    }

    #[test]
    fn test_vsock_addr_parse_invalid() {
        assert!(VsockAddr::parse("no-port").is_err());
        assert!(VsockAddr::parse("abc:xyz").is_err());
    }

    #[test]
    fn test_vsock_addr_display() {
        let addr = VsockAddr {
            context_id: 2,
            port: 1234,
        };
        assert_eq!(format!("{}", addr), "2:1234");
    }

    #[test]
    fn test_vsock_listener_creation() {
        let listener = VsockListener::new("2:1234").unwrap();
        assert_eq!(listener.addr.context_id, 2);
        assert_eq!(listener.addr.port, 1234);
    }

    #[tokio::test]
    async fn test_vsock_transporter_dial() {
        let t = VsockTransporter::new();
        let result = t.dial("2:1234").await;
        assert!(result.is_err()); // Expected on non-Linux / without vsock
    }
}
