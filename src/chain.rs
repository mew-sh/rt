use std::time::Duration;

use tokio::net::TcpStream;
use tracing::debug;

use crate::hosts::Hosts;
use crate::node::{Node, NodeGroup};

/// Chain is a proxy chain that holds a list of proxy node groups.
#[derive(Clone, Debug)]
pub struct Chain {
    pub retries: usize,
    pub mark: i32,
    pub interface: String,
    /// Per-listener dial settings, applied by `dial` so every handler picks
    /// them up without threading ChainOptions through each call site.
    pub timeout: Duration,
    pub hosts: Option<Hosts>,
    pub resolver: Option<crate::resolver::Resolver>,
    node_groups: Vec<NodeGroup>,
    is_route: bool,
}

impl Chain {
    pub fn new(nodes: Vec<Node>) -> Self {
        let node_groups = nodes.into_iter().map(|n| NodeGroup::new(vec![n])).collect();
        Chain {
            retries: 0,
            mark: 0,
            interface: String::new(),
            timeout: Duration::ZERO,
            hosts: None,
            resolver: None,
            node_groups,
            is_route: false,
        }
    }

    pub fn empty() -> Self {
        Chain {
            retries: 0,
            mark: 0,
            interface: String::new(),
            timeout: Duration::ZERO,
            hosts: None,
            resolver: None,
            node_groups: Vec::new(),
            is_route: false,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.node_groups.is_empty()
    }

    pub fn nodes(&self) -> Vec<Node> {
        self.node_groups
            .iter()
            .filter_map(|g| g.get_node(0))
            .collect()
    }

    pub fn last_node(&self) -> Node {
        if self.is_empty() {
            return Node::default();
        }
        self.node_groups
            .last()
            .and_then(|g| g.get_node(0))
            .unwrap_or_default()
    }

    pub fn add_node(&mut self, node: Node) {
        self.node_groups.push(NodeGroup::new(vec![node]));
    }

    pub fn add_node_group(&mut self, group: NodeGroup) {
        self.node_groups.push(group);
    }

    /// Dial connects to the target address through the chain.
    pub async fn dial(&self, address: &str) -> Result<TcpStream, ChainError> {
        self.dial_with_options(address, &self.default_options())
            .await
    }

    /// The dial options configured on this chain, so `?timeout=`, `?retry=`,
    /// `?hosts=` and `?dns=` take effect for every handler.
    pub fn default_options(&self) -> ChainOptions {
        ChainOptions {
            retries: self.retries,
            timeout: self.timeout,
            hosts: self.hosts.clone(),
            resolver: self.resolver.clone(),
        }
    }

    pub async fn dial_with_options(
        &self,
        address: &str,
        options: &ChainOptions,
    ) -> Result<TcpStream, ChainError> {
        // gost's precedence: a default of 1, overridden by the chain, then
        // overridden by the per-call option (chain.go:125-131).
        let mut retries = 1;
        if self.retries > 0 {
            retries = self.retries;
        }
        if options.retries > 0 {
            retries = options.retries;
        }

        let mut last_err = ChainError::EmptyChain;
        for _ in 0..retries {
            match self.dial_once(address, options).await {
                Ok(conn) => return Ok(conn),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    async fn dial_once(
        &self,
        address: &str,
        options: &ChainOptions,
    ) -> Result<TcpStream, ChainError> {
        // Resolve address if needed
        let resolved = self
            .resolve(address, options.resolver.as_ref(), options.hosts.as_ref())
            .await;
        let target = if resolved.is_empty() {
            address.to_string()
        } else {
            resolved
        };

        let timeout = if options.timeout > Duration::ZERO {
            options.timeout
        } else {
            Duration::from_secs(crate::DIAL_TIMEOUT)
        };

        if self.is_empty() {
            // Direct connection
            let conn = tokio::time::timeout(timeout, TcpStream::connect(&target))
                .await
                .map_err(|_| ChainError::Timeout)?
                .map_err(ChainError::Io)?;
            return Ok(conn);
        }

        // Connect through proxy chain
        let nodes = self.nodes();
        if nodes.is_empty() {
            return Err(ChainError::EmptyChain);
        }

        // Connect to first node
        let first = &nodes[0];
        debug!("[chain] connecting to first node: {}", first.addr);
        let conn = tokio::time::timeout(timeout, TcpStream::connect(&first.addr))
            .await
            .map_err(|_| ChainError::Timeout)?
            .map_err(ChainError::Io)?;

        // Walk the chain, asking each node to connect to the next one, and the
        // last node to connect to the real target.
        let mut current = conn;
        for (i, node) in nodes.iter().enumerate() {
            let hop_target = if i == nodes.len() - 1 {
                target.as_str()
            } else {
                nodes[i + 1].addr.as_str()
            };
            current = connect_via(current, node, hop_target).await?;
        }

        Ok(current)
    }

    async fn resolve(
        &self,
        addr: &str,
        resolver: Option<&crate::resolver::Resolver>,
        hosts: Option<&Hosts>,
    ) -> String {
        // Bracketed IPv6 literals must not be split on their inner colons.
        let Ok((host, port)) = split_host_port(addr) else {
            return addr.to_string();
        };

        // The hosts table wins over DNS, as in gost (chain.go:223-244).
        if let Some(hosts) = hosts {
            if let Some(ip) = hosts.lookup(host) {
                return join_host_port(&ip.to_string(), port);
            }
        }

        if let Some(resolver) = resolver {
            // Boxed to break the async recursion: a name-server lookup dials
            // through the chain, which resolves, which may dial again.
            if let Ok(ips) = Box::pin(resolver.resolve(host)).await {
                if let Some(ip) = ips.first() {
                    return join_host_port(&ip.to_string(), port);
                }
            }
        }

        addr.to_string()
    }
}

/// Joins a host and port, bracketing an IPv6 literal as Go's
/// `net.JoinHostPort` does.
fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

impl Default for Chain {
    fn default() -> Self {
        Self::empty()
    }
}

/// Performs the proxy handshake for one hop, using that node's protocol.
///
/// An unrecognised protocol is a hard error: returning the raw socket would
/// hand the caller a connection to the *proxy* while it believes it is talking
/// to the *target*, silently misrouting the traffic.
async fn connect_via(
    stream: TcpStream,
    node: &Node,
    target: &str,
) -> Result<TcpStream, ChainError> {
    match node.protocol.as_str() {
        "http" => http_connect(stream, target, node.user.as_ref()).await,
        "socks5" => socks5_connect(stream, target, node.user.as_ref()).await,
        "socks4" => socks4_connect(stream, target, node.user.as_ref(), false).await,
        "socks4a" => socks4_connect(stream, target, node.user.as_ref(), true).await,
        // "forward"/"direct"/"remote" hand the connection straight through;
        // the node itself is the endpoint rather than a proxy to traverse.
        "forward" | "direct" | "remote" | "" => Ok(stream),
        other => Err(ChainError::ProxyError(format!(
            "chain node protocol {:?} is not supported as a chain connector",
            other
        ))),
    }
}

fn basic_credentials(user: Option<&(String, Option<String>)>) -> Option<String> {
    use base64::Engine;
    let (name, pass) = user?;
    let raw = format!("{}:{}", name, pass.as_deref().unwrap_or(""));
    Some(base64::engine::general_purpose::STANDARD.encode(raw))
}

/// Reads exactly one HTTP response head off the wire, leaving any bytes the
/// peer coalesced after the terminator unread.
///
/// Reading into a large buffer would consume payload that belongs to the
/// tunnelled stream and then drop it, so the head is located with `peek`
/// first and only those bytes are consumed.
async fn read_response_head(stream: &mut TcpStream) -> Result<String, ChainError> {
    use tokio::io::AsyncReadExt;

    let mut buf = vec![0u8; crate::MEDIUM_BUFFER_SIZE];
    loop {
        let n = stream.peek(&mut buf).await.map_err(ChainError::Io)?;
        if n == 0 {
            return Err(ChainError::ProxyError(
                "proxy closed the connection during CONNECT".into(),
            ));
        }
        if let Some(pos) = buf[..n].windows(4).position(|w| w == b"\r\n\r\n") {
            let head_len = pos + 4;
            let mut head = vec![0u8; head_len];
            // Safe to consume: peek proved these bytes are already buffered.
            stream.read_exact(&mut head).await.map_err(ChainError::Io)?;
            return Ok(String::from_utf8_lossy(&head).into_owned());
        }
        if n == buf.len() {
            return Err(ChainError::ProxyError(
                "CONNECT response headers too large".into(),
            ));
        }
    }
}

/// HTTP CONNECT tunnel through a proxy.
async fn http_connect(
    mut stream: TcpStream,
    target: &str,
    user: Option<&(String, Option<String>)>,
) -> Result<TcpStream, ChainError> {
    use tokio::io::AsyncWriteExt;

    let mut req = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nProxy-Connection: keep-alive\r\n",
        target,
        target,
        crate::DEFAULT_USER_AGENT
    );
    if let Some(creds) = basic_credentials(user) {
        req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", creds));
    }
    req.push_str("\r\n");

    stream
        .write_all(req.as_bytes())
        .await
        .map_err(ChainError::Io)?;

    let head = read_response_head(&mut stream).await?;
    let status_line = head.lines().next().unwrap_or_default();
    // Check the status token specifically; a substring search for "200" also
    // matches a 407 whose headers happen to contain those digits.
    let code = status_line.split_whitespace().nth(1).unwrap_or_default();
    if code == "200" {
        Ok(stream)
    } else {
        Err(ChainError::ProxyError(format!(
            "HTTP CONNECT failed: {}",
            status_line
        )))
    }
}

/// SOCKS4/4a CONNECT through a proxy.
async fn socks4_connect(
    mut stream: TcpStream,
    target: &str,
    user: Option<&(String, Option<String>)>,
    allow_domain: bool,
) -> Result<TcpStream, ChainError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (host, port) = split_host_port(target)?;

    let mut req = vec![0x04, 0x01];
    req.extend_from_slice(&port.to_be_bytes());

    let domain = match host.parse::<std::net::Ipv4Addr>() {
        Ok(ip) => {
            req.extend_from_slice(&ip.octets());
            None
        }
        Err(_) if allow_domain => {
            // SOCKS4a signals "resolve this name" with an invalid 0.0.0.x address.
            req.extend_from_slice(&[0, 0, 0, 1]);
            Some(host)
        }
        Err(_) => {
            return Err(ChainError::ProxyError(
                "SOCKS4 requires an IPv4 target address; use socks4a for domains".into(),
            ))
        }
    };

    // USERID field, NUL-terminated.
    if let Some((name, _)) = user {
        req.extend_from_slice(name.as_bytes());
    }
    req.push(0x00);

    if let Some(domain) = domain {
        req.extend_from_slice(domain.as_bytes());
        req.push(0x00);
    }

    stream.write_all(&req).await.map_err(ChainError::Io)?;

    let mut resp = [0u8; 8];
    stream.read_exact(&mut resp).await.map_err(ChainError::Io)?;
    if resp[1] != 0x5A {
        return Err(ChainError::ProxyError(format!(
            "SOCKS4 connect rejected with code: 0x{:02X}",
            resp[1]
        )));
    }
    Ok(stream)
}

/// SOCKS5 CONNECT through a proxy.
async fn socks5_connect(
    mut stream: TcpStream,
    target: &str,
    user: Option<&(String, Option<String>)>,
) -> Result<TcpStream, ChainError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const METHOD_NO_AUTH: u8 = 0x00;
    const METHOD_USER_PASS: u8 = 0x02;
    const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;

    // Offer user/pass as well when credentials are configured, otherwise a
    // proxy that requires authentication can never be traversed.
    let methods: &[u8] = if user.is_some() {
        &[METHOD_NO_AUTH, METHOD_USER_PASS]
    } else {
        &[METHOD_NO_AUTH]
    };
    let mut greeting = vec![0x05, methods.len() as u8];
    greeting.extend_from_slice(methods);
    stream
        .write_all(&greeting)
        .await
        .map_err(ChainError::Io)?;

    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await.map_err(ChainError::Io)?;
    if buf[0] != 0x05 {
        return Err(ChainError::ProxyError("SOCKS5 handshake failed".into()));
    }
    match buf[1] {
        METHOD_NO_AUTH => {}
        METHOD_USER_PASS => {
            let (name, pass) = user.ok_or_else(|| {
                ChainError::ProxyError("proxy requires credentials but none were configured".into())
            })?;
            let pass = pass.as_deref().unwrap_or("");
            if name.len() > 255 || pass.len() > 255 {
                return Err(ChainError::ProxyError(
                    "SOCKS5 username/password exceeds 255 bytes".into(),
                ));
            }
            // RFC 1929 username/password sub-negotiation.
            let mut auth = vec![0x01, name.len() as u8];
            auth.extend_from_slice(name.as_bytes());
            auth.push(pass.len() as u8);
            auth.extend_from_slice(pass.as_bytes());
            stream.write_all(&auth).await.map_err(ChainError::Io)?;

            let mut reply = [0u8; 2];
            stream.read_exact(&mut reply).await.map_err(ChainError::Io)?;
            if reply[1] != 0x00 {
                return Err(ChainError::ProxyError(
                    "SOCKS5 authentication rejected".into(),
                ));
            }
        }
        METHOD_NONE_ACCEPTABLE => {
            return Err(ChainError::ProxyError(
                "SOCKS5 proxy rejected all offered authentication methods".into(),
            ))
        }
        other => {
            return Err(ChainError::ProxyError(format!(
                "SOCKS5 proxy selected unsupported auth method 0x{:02X}",
                other
            )))
        }
    }

    let (host, port) = split_host_port(target)?;

    // Send CONNECT request
    let mut req = vec![0x05, 0x01, 0x00]; // ver, cmd=connect, rsv
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        req.push(0x01); // IPv4
        req.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        req.push(0x04); // IPv6
        req.extend_from_slice(&ip.octets());
    } else {
        req.push(0x03); // Domain
        req.push(host.len() as u8);
        req.extend_from_slice(host.as_bytes());
    }
    req.extend_from_slice(&port.to_be_bytes());

    stream.write_all(&req).await.map_err(ChainError::Io)?;

    // Read response
    let mut resp = [0u8; 4];
    stream.read_exact(&mut resp).await.map_err(ChainError::Io)?;

    if resp[1] != 0x00 {
        return Err(ChainError::ProxyError(format!(
            "SOCKS5 connect failed with code: {}",
            resp[1]
        )));
    }

    // Read the rest of the response based on address type
    match resp[3] {
        0x01 => {
            let mut addr = [0u8; 6]; // 4 bytes IP + 2 bytes port
            stream.read_exact(&mut addr).await.map_err(ChainError::Io)?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.map_err(ChainError::Io)?;
            let mut addr = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut addr).await.map_err(ChainError::Io)?;
        }
        0x04 => {
            let mut addr = [0u8; 18]; // 16 bytes IPv6 + 2 bytes port
            stream.read_exact(&mut addr).await.map_err(ChainError::Io)?;
        }
        _ => {}
    }

    Ok(stream)
}

/// Splits a `host:port` pair, handling bracketed IPv6 literals the way Go's
/// `net.SplitHostPort` does.
fn split_host_port(addr: &str) -> Result<(&str, u16), ChainError> {
    let (host, port) = if let Some(rest) = addr.strip_prefix('[') {
        let (host, rest) = rest
            .split_once(']')
            .ok_or_else(|| ChainError::ProxyError("unbalanced IPv6 brackets".into()))?;
        let port = rest
            .strip_prefix(':')
            .ok_or_else(|| ChainError::ProxyError("missing port".into()))?;
        (host, port)
    } else {
        addr.rsplit_once(':')
            .ok_or_else(|| ChainError::ProxyError("invalid target address".into()))?
    };

    let port: u16 = port
        .parse()
        .map_err(|_| ChainError::ProxyError("invalid port".into()))?;
    Ok((host, port))
}

/// ChainOptions holds options for Chain.
#[derive(Clone, Default)]
pub struct ChainOptions {
    pub retries: usize,
    pub timeout: Duration,
    pub hosts: Option<Hosts>,
    pub resolver: Option<crate::resolver::Resolver>,
}

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("empty chain")]
    EmptyChain,
    #[error("connection timeout")]
    Timeout,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("proxy error: {0}")]
    ProxyError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::Handler; // needed for .handle() method

    #[test]
    fn test_chain_empty() {
        let c = Chain::empty();
        assert!(c.is_empty());
        assert_eq!(c.nodes().len(), 0);
    }

    #[test]
    fn test_chain_new() {
        let n1 = Node::parse("http://localhost:8080").unwrap();
        let n2 = Node::parse("socks5://localhost:1080").unwrap();
        let c = Chain::new(vec![n1, n2]);
        assert!(!c.is_empty());
        assert_eq!(c.nodes().len(), 2);
    }

    #[test]
    fn test_chain_last_node() {
        let n1 = Node::parse("http://localhost:8080").unwrap();
        let n2 = Node::parse("socks5://localhost:1080").unwrap();
        let c = Chain::new(vec![n1, n2]);
        assert_eq!(c.last_node().addr, "localhost:1080");
    }

    #[test]
    fn test_chain_last_node_empty() {
        let c = Chain::empty();
        assert!(c.last_node().addr.is_empty());
    }

    #[test]
    fn test_chain_add_node() {
        let mut c = Chain::empty();
        c.add_node(Node::parse("http://localhost:8080").unwrap());
        assert!(!c.is_empty());
        assert_eq!(c.nodes().len(), 1);
    }

    #[tokio::test]
    async fn test_chain_direct_dial() {
        // Start a simple TCP listener to test direct connection
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let c = Chain::empty();
        let handle = tokio::spawn(async move {
            let (_conn, _) = listener.accept().await.unwrap();
        });

        let conn = c.dial(&addr.to_string()).await;
        assert!(conn.is_ok());
        handle.await.ok();
    }

    #[tokio::test]
    async fn test_chain_direct_dial_timeout() {
        // Connect to a non-routable address to trigger timeout
        let c = Chain::empty();
        let opts = ChainOptions {
            timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let result = c.dial_with_options("192.0.2.1:12345", &opts).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_chain_direct_dial_invalid_address() {
        let c = Chain::empty();
        let result = c.dial("not-a-real-host-that-exists.invalid:9999").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_chain_dial_through_http_proxy() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Start a target server
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            conn.write_all(b"chain-target-data").await.unwrap();
        });

        // Start an HTTP proxy
        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let handler =
                crate::http_proxy::HttpHandler::new(crate::handler::HandlerOptions::default());
            let (conn, _) = proxy_listener.accept().await.unwrap();
            handler.handle(crate::conn::ProxyConn::from_tcp(conn)).await.ok();
        });

        // Create chain with the HTTP proxy
        let proxy_node = Node::parse(&format!("http://{}", proxy_addr)).unwrap();
        let chain = Chain::new(vec![proxy_node]);

        let mut conn = chain.dial(&target_addr.to_string()).await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"chain-target-data");
    }

    #[tokio::test]
    async fn test_chain_dial_through_socks5_proxy() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Start a target server
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            conn.write_all(b"socks5-chain-data").await.unwrap();
        });

        // Start a SOCKS5 proxy
        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let handler =
                crate::socks5::Socks5Handler::new(crate::handler::HandlerOptions::default());
            let (conn, _) = proxy_listener.accept().await.unwrap();
            handler.handle(crate::conn::ProxyConn::from_tcp(conn)).await.ok();
        });

        // Create chain with the SOCKS5 proxy
        let proxy_node = Node::parse(&format!("socks5://{}", proxy_addr)).unwrap();
        let chain = Chain::new(vec![proxy_node]);

        let mut conn = chain.dial(&target_addr.to_string()).await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"socks5-chain-data");
    }

    #[tokio::test]
    async fn test_chain_with_retries() {
        // Test that retries work on failure
        let c = Chain::empty();
        let opts = ChainOptions {
            retries: 3,
            timeout: Duration::from_millis(50),
            ..Default::default()
        };
        // Connect to unreachable address; should fail after 3 retries
        let result = c.dial_with_options("192.0.2.1:12345", &opts).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_chain_clone() {
        let n = Node::parse("http://localhost:8080").unwrap();
        let mut c = Chain::new(vec![n]);
        c.mark = 42;
        c.interface = "eth0".to_string();
        c.retries = 3;

        let c2 = c.clone();
        assert_eq!(c2.mark, 42);
        assert_eq!(c2.interface, "eth0");
        assert_eq!(c2.retries, 3);
        assert_eq!(c2.nodes().len(), 1);
    }

    #[tokio::test]
    async fn test_chain_resolve_with_hosts() {
        let mut hosts = Hosts::new(vec![]);
        hosts.add_host(crate::hosts::Host::new(
            "10.0.0.1".parse().unwrap(),
            "myhost",
            vec![],
        ));

        let c = Chain::empty();
        let resolved = c.resolve("myhost:80", None, Some(&hosts)).await;
        assert_eq!(resolved, "10.0.0.1:80");
    }

    #[tokio::test]
    async fn test_chain_resolve_no_hosts() {
        let c = Chain::empty();
        let resolved = c.resolve("example.com:443", None, None).await;
        assert_eq!(resolved, "example.com:443");
    }

    #[tokio::test]
    async fn test_chain_resolve_ipv6_host_is_bracketed() {
        let mut hosts = Hosts::new(vec![]);
        hosts.add_host(crate::hosts::Host::new(
            "::1".parse().unwrap(),
            "v6host",
            vec![],
        ));
        let c = Chain::empty();
        let resolved = c.resolve("v6host:443", None, Some(&hosts)).await;
        assert_eq!(resolved, "[::1]:443");
        assert!(resolved.parse::<std::net::SocketAddr>().is_ok());
    }

    #[test]
    fn test_chain_add_node_group() {
        let mut c = Chain::empty();
        let group = NodeGroup::new(vec![
            Node::parse("http://a:1").unwrap(),
            Node::parse("http://b:2").unwrap(),
        ]);
        c.add_node_group(group);
        assert_eq!(c.nodes().len(), 1); // first node of group
    }

    #[test]
    fn test_chain_default() {
        let c = Chain::default();
        assert!(c.is_empty());
        assert_eq!(c.retries, 0);
        assert_eq!(c.mark, 0);
    }
}
