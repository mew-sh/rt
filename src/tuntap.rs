use std::net::{IpAddr, Ipv4Addr};

use tracing::info;

/// IP routing entry for TUN device.
#[derive(Clone, Debug)]
pub struct IpRoute {
    pub dest: ipnet::IpNet,
    pub gateway: Option<IpAddr>,
}

/// TUN device configuration.
#[derive(Clone, Debug, Default)]
pub struct TunConfig {
    pub name: String,
    pub addr: String, // network address, e.g., "10.0.0.1/24"
    pub peer: String, // peer address for point-to-point (macOS)
    pub mtu: u32,
    pub routes: Vec<IpRoute>,
    pub gateway: String, // default gateway
}

/// TAP device configuration.
#[derive(Clone, Debug, Default)]
pub struct TapConfig {
    pub name: String,
    pub addr: String,
    pub mtu: u32,
    pub routes: Vec<String>,
    pub gateway: String,
}

/// TUN tunnel handler.
/// In a full implementation, this would:
/// 1. Open a TUN device using the `tun` crate
/// 2. Read IP packets from the device
/// 3. Route them through the proxy chain
/// 4. Write response packets back to the device
pub struct TunHandler {
    config: TunConfig,
}

impl TunHandler {
    pub fn new(config: TunConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &TunConfig {
        &self.config
    }
}

/// TAP tunnel handler.
/// Similar to TUN but operates at Layer 2 (Ethernet frames).
pub struct TapHandler {
    config: TapConfig,
}

impl TapHandler {
    pub fn new(config: TapConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &TapConfig {
        &self.config
    }
}

/// TUN listener placeholder.
/// In a full implementation, this creates a TUN device and
/// wraps it in the Listener interface.
pub struct TunListener {
    config: TunConfig,
}

impl TunListener {
    pub fn new(config: TunConfig) -> Self {
        Self { config }
    }
}

/// TAP listener placeholder.
pub struct TapListener {
    config: TapConfig,
}

impl TapListener {
    pub fn new(config: TapConfig) -> Self {
        Self { config }
    }
}

// ---------------------------------------------------------------------------
// Platform-specific TUN/TAP device creation
// ---------------------------------------------------------------------------

/// Create a TUN device and configure its network address and routes.
///
/// Platform behavior:
/// - Linux: uses `ip link`, `ip address`, `ip route` commands
/// - macOS: uses `ifconfig` and `route` commands; supports point-to-point
/// - Windows: uses `netsh` commands; requires TAP-Windows driver (tap0901)
/// - Other Unix: uses `ifconfig` and `route` commands
pub fn create_tun(cfg: &TunConfig) -> Result<String, std::io::Error> {
    platform_create_tun(cfg)
}

/// Create a TAP device and configure its network address and routes.
///
/// Platform behavior:
/// - Linux: uses `ip link`, `ip address`, `ip route` commands
/// - macOS: TAP is NOT supported (returns error)
/// - Windows: uses `netsh` commands; requires TAP-Windows driver
/// - Other Unix: uses `ifconfig` and `route` commands
pub fn create_tap(cfg: &TapConfig) -> Result<String, std::io::Error> {
    platform_create_tap(cfg)
}

/// Add IP routes for a TUN device.
pub fn add_tun_routes(if_name: &str, routes: &[IpRoute]) -> Result<(), std::io::Error> {
    platform_add_tun_routes(if_name, routes)
}

/// Add routes for a TAP device.
pub fn add_tap_routes(
    if_name: &str,
    gateway: &str,
    routes: &[String],
) -> Result<(), std::io::Error> {
    platform_add_tap_routes(if_name, gateway, routes)
}

// --- Linux ---

#[cfg(target_os = "linux")]
fn platform_create_tun(cfg: &TunConfig) -> Result<String, std::io::Error> {
    use std::process::Command;

    let name = if cfg.name.is_empty() {
        "tun0"
    } else {
        &cfg.name
    };

    // ip link set <name> up
    // ip address add <addr> dev <name>
    if !cfg.addr.is_empty() {
        Command::new("ip")
            .args(["address", "add", &cfg.addr, "dev", name])
            .status()?;
    }
    let mtu = if cfg.mtu > 0 {
        cfg.mtu.to_string()
    } else {
        "1350".to_string()
    };
    Command::new("ip")
        .args(["link", "set", name, "mtu", &mtu, "up"])
        .status()?;

    platform_add_tun_routes(name, &cfg.routes)?;

    Ok(name.to_string())
}

#[cfg(target_os = "linux")]
fn platform_create_tap(cfg: &TapConfig) -> Result<String, std::io::Error> {
    use std::process::Command;

    let name = if cfg.name.is_empty() {
        "tap0"
    } else {
        &cfg.name
    };

    if !cfg.addr.is_empty() {
        Command::new("ip")
            .args(["address", "add", &cfg.addr, "dev", name])
            .status()?;
    }
    let mtu = if cfg.mtu > 0 {
        cfg.mtu.to_string()
    } else {
        "1500".to_string()
    };
    Command::new("ip")
        .args(["link", "set", name, "mtu", &mtu, "up"])
        .status()?;

    platform_add_tap_routes(name, &cfg.gateway, &cfg.routes)?;

    Ok(name.to_string())
}

#[cfg(target_os = "linux")]
fn platform_add_tun_routes(if_name: &str, routes: &[IpRoute]) -> Result<(), std::io::Error> {
    use std::process::Command;
    for route in routes {
        let dest = route.dest.to_string();
        let mut args = vec!["route", "add", &dest, "dev", if_name];
        let gw_str;
        if let Some(gw) = &route.gateway {
            gw_str = gw.to_string();
            args.push("via");
            args.push(&gw_str);
        }
        Command::new("ip").args(&args).status()?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn platform_add_tap_routes(
    if_name: &str,
    gateway: &str,
    routes: &[String],
) -> Result<(), std::io::Error> {
    use std::process::Command;
    for route in routes {
        if route.is_empty() {
            continue;
        }
        let mut args = vec!["route", "add", route, "dev", if_name];
        if !gateway.is_empty() {
            args.push("via");
            args.push(gateway);
        }
        Command::new("ip").args(&args).status()?;
    }
    Ok(())
}

// --- macOS ---

#[cfg(target_os = "macos")]
fn platform_create_tun(cfg: &TunConfig) -> Result<String, std::io::Error> {
    use std::process::Command;

    let name = if cfg.name.is_empty() {
        "utun0"
    } else {
        &cfg.name
    };
    let mtu = if cfg.mtu > 0 {
        cfg.mtu.to_string()
    } else {
        "1350".to_string()
    };

    if !cfg.addr.is_empty() {
        let mut args = vec!["ifconfig", name, "inet", &cfg.addr];
        // macOS supports point-to-point peer address
        if !cfg.peer.is_empty() {
            args.push(&cfg.peer);
        }
        args.push("mtu");
        args.push(&mtu);
        args.push("up");
        Command::new(args[0]).args(&args[1..]).status()?;
    }

    platform_add_tun_routes(name, &cfg.routes)?;

    Ok(name.to_string())
}

#[cfg(target_os = "macos")]
fn platform_create_tap(_cfg: &TapConfig) -> Result<String, std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "TAP is not supported on macOS",
    ))
}

#[cfg(target_os = "macos")]
fn platform_add_tun_routes(if_name: &str, routes: &[IpRoute]) -> Result<(), std::io::Error> {
    use std::process::Command;
    for route in routes {
        let dest = route.dest.to_string();
        let mut args = vec!["-n", "add", "-net", &dest];
        let gw_str;
        if let Some(gw) = &route.gateway {
            gw_str = gw.to_string();
            args.push(&gw_str);
        } else {
            args.push("-interface");
            args.push(if_name);
        }
        Command::new("route").args(&args).status()?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn platform_add_tap_routes(
    _if_name: &str,
    _gateway: &str,
    _routes: &[String],
) -> Result<(), std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "TAP is not supported on macOS",
    ))
}

// --- Windows ---

#[cfg(target_os = "windows")]
fn platform_create_tun(cfg: &TunConfig) -> Result<String, std::io::Error> {
    use std::process::Command;

    let name = if cfg.name.is_empty() {
        "rt-tun"
    } else {
        &cfg.name
    };

    // Parse address and mask from CIDR notation
    if !cfg.addr.is_empty() {
        if let Ok(net) = cfg.addr.parse::<ipnet::IpNet>() {
            let ip = net.addr().to_string();
            let mask = net.netmask().to_string();
            let gateway = if cfg.gateway.is_empty() {
                &ip
            } else {
                &cfg.gateway
            };
            Command::new("netsh")
                .args([
                    "interface",
                    "ip",
                    "set",
                    "address",
                    name,
                    "static",
                    &ip,
                    &mask,
                    gateway,
                ])
                .status()?;
        }
    }

    platform_add_tun_routes(name, &cfg.routes)?;

    Ok(name.to_string())
}

#[cfg(target_os = "windows")]
fn platform_create_tap(cfg: &TapConfig) -> Result<String, std::io::Error> {
    use std::process::Command;

    let name = if cfg.name.is_empty() {
        "rt-tap"
    } else {
        &cfg.name
    };

    if !cfg.addr.is_empty() {
        if let Ok(net) = cfg.addr.parse::<ipnet::IpNet>() {
            let ip = net.addr().to_string();
            let mask = net.netmask().to_string();
            let gateway = if cfg.gateway.is_empty() {
                &ip
            } else {
                &cfg.gateway
            };
            Command::new("netsh")
                .args([
                    "interface",
                    "ip",
                    "set",
                    "address",
                    name,
                    "static",
                    &ip,
                    &mask,
                    gateway,
                ])
                .status()?;
        }
    }

    platform_add_tap_routes(name, &cfg.gateway, &cfg.routes)?;

    Ok(name.to_string())
}

#[cfg(target_os = "windows")]
fn platform_add_tun_routes(if_name: &str, routes: &[IpRoute]) -> Result<(), std::io::Error> {
    use std::process::Command;
    for route in routes {
        let dest = route.dest.to_string();
        // netsh interface ip add route <prefix> <interface> [nexthop]
        let mut args = vec!["interface", "ip", "add", "route", &dest, if_name];
        let gw_str;
        if let Some(gw) = &route.gateway {
            gw_str = gw.to_string();
            args.push(&gw_str);
        }
        Command::new("netsh").args(&args).status()?;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn platform_add_tap_routes(
    if_name: &str,
    gateway: &str,
    routes: &[String],
) -> Result<(), std::io::Error> {
    use std::process::Command;
    for route in routes {
        if route.is_empty() {
            continue;
        }
        let mut args = vec!["interface", "ip", "add", "route", route, if_name];
        if !gateway.is_empty() {
            args.push(gateway);
        }
        Command::new("netsh").args(&args).status()?;
    }
    Ok(())
}

// --- Other Unix (FreeBSD, OpenBSD, etc.) ---

#[cfg(all(unix, not(target_os = "linux"), not(target_os = "macos")))]
fn platform_create_tun(cfg: &TunConfig) -> Result<String, std::io::Error> {
    use std::process::Command;

    let name = if cfg.name.is_empty() {
        "tun0"
    } else {
        &cfg.name
    };
    let mtu = if cfg.mtu > 0 {
        cfg.mtu.to_string()
    } else {
        "1350".to_string()
    };

    if !cfg.addr.is_empty() {
        Command::new("ifconfig")
            .args([name, "inet", &cfg.addr, "mtu", &mtu, "up"])
            .status()?;
    }

    platform_add_tun_routes(name, &cfg.routes)?;

    Ok(name.to_string())
}

#[cfg(all(unix, not(target_os = "linux"), not(target_os = "macos")))]
fn platform_create_tap(cfg: &TapConfig) -> Result<String, std::io::Error> {
    use std::process::Command;

    let name = if cfg.name.is_empty() {
        "tap0"
    } else {
        &cfg.name
    };
    let mtu = if cfg.mtu > 0 {
        cfg.mtu.to_string()
    } else {
        "1500".to_string()
    };

    let mut args = vec![name];
    if !cfg.addr.is_empty() {
        args.extend(["inet", &cfg.addr]);
    }
    args.extend(["mtu", &mtu, "up"]);
    Command::new("ifconfig").args(&args).status()?;

    platform_add_tap_routes(name, &cfg.gateway, &cfg.routes)?;

    Ok(name.to_string())
}

#[cfg(all(unix, not(target_os = "linux"), not(target_os = "macos")))]
fn platform_add_tun_routes(if_name: &str, routes: &[IpRoute]) -> Result<(), std::io::Error> {
    use std::process::Command;
    for route in routes {
        let dest = route.dest.to_string();
        let mut args = vec!["-n", "add", "-net", &dest];
        let gw_str;
        if let Some(gw) = &route.gateway {
            gw_str = gw.to_string();
            args.push(&gw_str);
        } else {
            args.push("-interface");
            args.push(if_name);
        }
        Command::new("route").args(&args).status()?;
    }
    Ok(())
}

#[cfg(all(unix, not(target_os = "linux"), not(target_os = "macos")))]
fn platform_add_tap_routes(
    if_name: &str,
    gateway: &str,
    routes: &[String],
) -> Result<(), std::io::Error> {
    use std::process::Command;
    for route in routes {
        if route.is_empty() {
            continue;
        }
        let mut args = vec!["-n", "add", "-net", route];
        if !gateway.is_empty() {
            args.push(gateway);
        } else {
            args.push("-interface");
            args.push(if_name);
        }
        Command::new("route").args(&args).status()?;
    }
    Ok(())
}

/// Parse IP routes from a comma-separated string or route file.
pub fn parse_ip_routes(s: &str) -> Vec<IpRoute> {
    if s.is_empty() {
        return Vec::new();
    }

    s.split(',')
        .filter_map(|entry| {
            let entry = entry.trim();
            if entry.is_empty() {
                return None;
            }
            let parts: Vec<&str> = entry.split_whitespace().collect();
            let dest = parts.first()?.parse::<ipnet::IpNet>().ok()?;
            let gateway = parts.get(1).and_then(|g| g.parse::<IpAddr>().ok());
            Some(IpRoute { dest, gateway })
        })
        .collect()
}

/// Known IP protocol numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    Icmp,
    Tcp,
    Udp,
    Icmpv6,
    Unknown(u8),
}

impl From<u8> for IpProtocol {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::Icmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            58 => Self::Icmpv6,
            other => Self::Unknown(other),
        }
    }
}

impl std::fmt::Display for IpProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Icmp => write!(f, "ICMP"),
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
            Self::Icmpv6 => write!(f, "ICMPv6"),
            Self::Unknown(n) => write!(f, "unknown({})", n),
        }
    }
}

/// Parse an IPv4 packet header to extract src/dst addresses and protocol.
pub fn parse_ipv4_header(data: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr, IpProtocol)> {
    if data.len() < 20 {
        return None;
    }
    let version = (data[0] >> 4) & 0x0F;
    if version != 4 {
        return None;
    }
    let protocol = IpProtocol::from(data[9]);
    let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
    Some((src, dst, protocol))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tun_config_default() {
        let config = TunConfig::default();
        assert!(config.name.is_empty());
        assert_eq!(config.mtu, 0);
    }

    #[test]
    fn test_tap_config_default() {
        let config = TapConfig::default();
        assert!(config.name.is_empty());
    }

    #[test]
    fn test_parse_ip_routes() {
        let routes = parse_ip_routes("10.0.0.0/8,192.168.0.0/16 10.0.0.1");
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].dest.to_string(), "10.0.0.0/8");
        assert!(routes[0].gateway.is_none());
        assert_eq!(routes[1].dest.to_string(), "192.168.0.0/16");
        assert_eq!(
            routes[1].gateway,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
    }

    #[test]
    fn test_parse_ip_routes_empty() {
        let routes = parse_ip_routes("");
        assert!(routes.is_empty());
    }

    #[test]
    fn test_parse_ipv4_header() {
        // Minimal IPv4 header (20 bytes)
        let mut header = [0u8; 20];
        header[0] = 0x45; // version 4, IHL 5
        header[9] = 6; // TCP
        header[12..16].copy_from_slice(&[192, 168, 1, 1]); // src
        header[16..20].copy_from_slice(&[10, 0, 0, 1]); // dst

        let (src, dst, proto) = parse_ipv4_header(&header).unwrap();
        assert_eq!(src, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(dst, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(proto, IpProtocol::Tcp);
    }

    #[test]
    fn test_parse_ipv4_header_too_short() {
        assert!(parse_ipv4_header(&[0u8; 10]).is_none());
    }

    #[test]
    fn test_ip_protocol_display() {
        assert_eq!(format!("{}", IpProtocol::Tcp), "TCP");
        assert_eq!(format!("{}", IpProtocol::Udp), "UDP");
        assert_eq!(format!("{}", IpProtocol::Icmp), "ICMP");
        assert_eq!(format!("{}", IpProtocol::Unknown(99)), "unknown(99)");
    }

    #[test]
    fn test_tun_handler_creation() {
        let handler = TunHandler::new(TunConfig {
            name: "tun0".to_string(),
            addr: "10.0.0.1/24".to_string(),
            mtu: 1350,
            ..Default::default()
        });
        assert_eq!(handler.config().name, "tun0");
        assert_eq!(handler.config().mtu, 1350);
    }
}
