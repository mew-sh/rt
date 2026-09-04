use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

use crate::chain::{Chain, ChainError, ChainOptions};
use crate::handler::{Handler, HandlerError, HandlerOptions};
use crate::permissions::Can;
use crate::transport::transport;

// SOCKS4 constants
const SOCKS4_VERSION: u8 = 0x04;
const CMD_CONNECT: u8 = 0x01;
const CMD_BIND: u8 = 0x02;

// SOCKS4 reply codes
const REP_GRANTED: u8 = 0x5A;
const REP_REJECTED: u8 = 0x5B;

/// SOCKS4 connector (client side).
pub struct Socks4Connector;

impl Socks4Connector {
    pub fn new() -> Self {
        Self
    }

    /// Perform SOCKS4 CONNECT through proxy.
    pub async fn connect(
        &self,
        mut conn: TcpStream,
        address: &str,
    ) -> Result<TcpStream, HandlerError> {
        let (host, port) = parse_address(address)?;
        let ip: Ipv4Addr = host
            .parse()
            .map_err(|_| HandlerError::Proxy("SOCKS4 requires IPv4 address".into()))?;

        let mut req = Vec::with_capacity(9);
        req.push(SOCKS4_VERSION);
        req.push(CMD_CONNECT);
        req.extend_from_slice(&port.to_be_bytes());
        req.extend_from_slice(&ip.octets());
        req.push(0x00); // null-terminated user ID

        conn.write_all(&req).await?;

        let mut resp = [0u8; 8];
        conn.read_exact(&mut resp).await?;

        if resp[1] != REP_GRANTED {
            return Err(HandlerError::Proxy(format!(
                "SOCKS4 connect rejected: code {}",
                resp[1]
            )));
        }

        Ok(conn)
    }
}

/// SOCKS4a connector (client side) - supports domain names.
pub struct Socks4aConnector;

impl Socks4aConnector {
    pub fn new() -> Self {
        Self
    }

    /// Perform SOCKS4a CONNECT through proxy (supports domain names).
    pub async fn connect(
        &self,
        mut conn: TcpStream,
        address: &str,
    ) -> Result<TcpStream, HandlerError> {
        let (host, port) = parse_address(address)?;

        let mut req = Vec::new();
        req.push(SOCKS4_VERSION);
        req.push(CMD_CONNECT);
        req.extend_from_slice(&port.to_be_bytes());

        // For SOCKS4a: use invalid IP 0.0.0.x where x != 0
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            req.extend_from_slice(&ip.octets());
            req.push(0x00); // null-terminated user ID
        } else {
            req.extend_from_slice(&[0, 0, 0, 1]); // 0.0.0.1 = SOCKS4a domain mode
            req.push(0x00); // null-terminated user ID
            req.extend_from_slice(host.as_bytes());
            req.push(0x00); // null-terminated domain
        }

        conn.write_all(&req).await?;

        let mut resp = [0u8; 8];
        conn.read_exact(&mut resp).await?;

        if resp[1] != REP_GRANTED {
            return Err(HandlerError::Proxy(format!(
                "SOCKS4a connect rejected: code {}",
                resp[1]
            )));
        }

        Ok(conn)
    }
}

/// SOCKS4(a) handler (server side).
pub struct Socks4Handler {
    options: HandlerOptions,
}

impl Socks4Handler {
    pub fn new(options: HandlerOptions) -> Self {
        Self { options }
    }

    /// Mirrors gost's retry precedence (socks.go:1733-1739).
    fn dial_setup(&self) -> (Chain, usize, ChainOptions) {
        let mut chain = self.options.chain.clone().unwrap_or_default();
        let chain_retries = chain.retries;
        chain.retries = 1;

        let retries = if self.options.retries > 0 {
            self.options.retries
        } else if chain_retries > 0 {
            chain_retries
        } else {
            1
        };

        // Start from the chain's own options so `?hosts=` and `?dns=` keep
        // working (main.rs pushes them onto the chain); only the retry count
        // and the timeout are overridden, mirroring gost's
        // TimeoutChainOption/HostsChainOption/ResolverChainOption trio.
        let mut opts = chain.default_options();
        opts.retries = 1;
        if self.options.timeout > Duration::ZERO {
            opts.timeout = self.options.timeout;
        }

        (chain, retries, opts)
    }

    async fn dial_target(&self, target: &str) -> Result<TcpStream, ChainError> {
        let (chain, retries, opts) = self.dial_setup();
        let mut last_err = ChainError::EmptyChain;
        for i in 0..retries {
            match chain.dial_with_options(target, &opts).await {
                Ok(cc) => return Ok(cc),
                Err(e) => {
                    debug!("[socks4] dial {} attempt {}/{}: {}", target, i + 1, retries, e);
                    last_err = e;
                }
            }
        }
        Err(last_err)
    }

    fn dial_timeout(&self) -> Duration {
        if self.options.timeout > Duration::ZERO {
            self.options.timeout
        } else {
            Duration::from_secs(crate::DIAL_TIMEOUT)
        }
    }

    /// gost: socks4Handler.handleConnect (socks.go:1703-1797)
    async fn handle_connect(
        &self,
        mut conn: TcpStream,
        target: &str,
        peer_addr: &str,
    ) -> Result<(), HandlerError> {
        if !Can(
            "tcp",
            target,
            self.options.whitelist.as_ref(),
            self.options.blacklist.as_ref(),
        ) {
            warn!("[socks4] {} - unauthorized to tcp connect to {}", peer_addr, target);
            send_reply(&mut conn, REP_REJECTED, "0.0.0.0", 0).await?;
            return Err(HandlerError::Forbidden);
        }

        if let Some(ref bypass) = self.options.bypass {
            if bypass.contains(target) {
                debug!("[socks4] {} - bypass {}", peer_addr, target);
                send_reply(&mut conn, REP_REJECTED, "0.0.0.0", 0).await?;
                return Ok(());
            }
        }

        match self.dial_target(target).await {
            Ok(cc) => {
                // gost replies `NewReply(Granted, nil)` (socks.go:1785): an
                // all-zero address, not the proxy's real outbound socket.
                send_reply(&mut conn, REP_GRANTED, "0.0.0.0", 0).await?;

                info!("[socks4] {} <-> {}", peer_addr, target);
                transport(conn, cc).await.ok();
                info!("[socks4] {} >-< {}", peer_addr, target);
                Ok(())
            }
            Err(e) => {
                debug!("[socks4] {} -> {} : {}", peer_addr, target, e);
                send_reply(&mut conn, REP_REJECTED, "0.0.0.0", 0).await?;
                Err(HandlerError::Chain(e))
            }
        }
    }

    /// gost: socks4Handler.handleBind (socks.go:1800-1830).
    ///
    /// gost only implements the chain-forwarding half and rejects the direct
    /// case outright; here the direct case is served with a real listener, in
    /// line with the SOCKS4 two-reply BIND sequence.
    async fn handle_bind(
        &self,
        mut conn: TcpStream,
        target: &str,
        is_socks4a: bool,
        peer_addr: &str,
    ) -> Result<(), HandlerError> {
        if !Can(
            "rtcp",
            target,
            self.options.whitelist.as_ref(),
            self.options.blacklist.as_ref(),
        ) {
            warn!("[socks4-bind] {} - unauthorized to tcp bind to {}", peer_addr, target);
            send_reply(&mut conn, REP_REJECTED, "0.0.0.0", 0).await?;
            return Err(HandlerError::Forbidden);
        }

        let chain = self.options.chain.clone().unwrap_or_default();
        if chain.is_empty() {
            return socks4_bind_on(conn, target, peer_addr).await;
        }

        // Forward the BIND request through the chain (socks.go:1810-1829).
        let node = chain.last_node();
        let cc = tokio::time::timeout(self.dial_timeout(), TcpStream::connect(&node.addr)).await;
        let mut cc = match cc {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                send_reply(&mut conn, REP_REJECTED, "0.0.0.0", 0).await?;
                return Err(HandlerError::Io(e));
            }
            Err(_) => {
                send_reply(&mut conn, REP_REJECTED, "0.0.0.0", 0).await?;
                return Err(HandlerError::Proxy("bind: chain dial timeout".into()));
            }
        };

        let (host, port) = parse_address(target)?;
        let mut req = vec![SOCKS4_VERSION, CMD_BIND];
        req.extend_from_slice(&port.to_be_bytes());
        if is_socks4a {
            req.extend_from_slice(&[0, 0, 0, 1]);
            req.push(0x00);
            req.extend_from_slice(host.as_bytes());
            req.push(0x00);
        } else {
            let ip: Ipv4Addr = host.parse().unwrap_or(Ipv4Addr::UNSPECIFIED);
            req.extend_from_slice(&ip.octets());
            req.push(0x00);
        }
        cc.write_all(&req).await?;

        info!("[socks4-bind] {} <-> {}", peer_addr, target);
        transport(conn, cc).await.ok();
        info!("[socks4-bind] {} >-< {}", peer_addr, target);
        Ok(())
    }
}

/// Serves a SOCKS4 BIND directly: bind a listener, reply with the bound
/// address, then on peer accept reply a second time with the peer's address
/// before splicing. Analogous to gost's socks5 `bindOn` (socks.go:1020-1114).
async fn socks4_bind_on(
    mut conn: TcpStream,
    addr: &str,
    peer_addr: &str,
) -> Result<(), HandlerError> {
    let ln = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            debug!("[socks4-bind] {} -> {} : {}", peer_addr, addr, e);
            send_reply(&mut conn, REP_REJECTED, "0.0.0.0", 0).await?;
            return Err(HandlerError::Io(e));
        }
    };

    let bound = ln.local_addr()?;
    let host = conn.local_addr().map(|a| a.ip()).unwrap_or(bound.ip());
    // SOCKS4 replies only carry IPv4 addresses.
    let ip4 = match host {
        IpAddr::V4(v) => v,
        IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
    };
    let socks_addr = SocketAddr::new(IpAddr::V4(ip4), bound.port());

    send_reply(&mut conn, REP_GRANTED, &ip4.to_string(), bound.port()).await?;
    info!("[socks4-bind] {} - BIND ON {} OK", peer_addr, socks_addr);

    enum Ev {
        Peer(TcpStream, SocketAddr),
        AcceptFailed(std::io::Error),
        Closed,
    }

    let ev = {
        let mut probe = [0u8; 1];
        tokio::select! {
            res = ln.accept() => match res {
                Ok((c, a)) => Ev::Peer(c, a),
                Err(e) => Ev::AcceptFailed(e),
            },
            _ = conn.read(&mut probe) => Ev::Closed,
        }
    };
    drop(ln);

    match ev {
        Ev::Peer(pconn, praddr) => {
            let pip = match praddr.ip() {
                IpAddr::V4(v) => v.to_string(),
                IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED.to_string(),
            };
            send_reply(&mut conn, REP_GRANTED, &pip, praddr.port()).await?;
            info!(
                "[socks4-bind] {} <- {} PEER {} ACCEPTED",
                peer_addr, socks_addr, praddr
            );
            transport(conn, pconn).await.ok();
            info!("[socks4-bind] {} >-< {}", peer_addr, praddr);
            Ok(())
        }
        Ev::AcceptFailed(e) => {
            debug!("[socks4-bind] {} <- {} : {}", peer_addr, addr, e);
            Err(HandlerError::Io(e))
        }
        Ev::Closed => {
            debug!("[socks4-bind] {} - control connection closed while binding", peer_addr);
            Ok(())
        }
    }
}

#[async_trait]
impl Handler for Socks4Handler {
    async fn handle(&self, mut conn: TcpStream) -> Result<(), HandlerError> {
        let peer_addr = conn
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        // Read version byte (already peeked by auto handler)
        let mut ver = [0u8; 1];
        conn.read_exact(&mut ver).await?;
        if ver[0] != SOCKS4_VERSION {
            return Err(HandlerError::Proxy(format!(
                "unsupported SOCKS version: {}",
                ver[0]
            )));
        }

        // Read command
        let mut cmd = [0u8; 1];
        conn.read_exact(&mut cmd).await?;

        // Read port
        let mut port_buf = [0u8; 2];
        conn.read_exact(&mut port_buf).await?;
        let port = u16::from_be_bytes(port_buf);

        // Read IP
        let mut ip_buf = [0u8; 4];
        conn.read_exact(&mut ip_buf).await?;
        let ip = Ipv4Addr::from(ip_buf);

        // Read user ID (null terminated)
        let mut user_id = Vec::new();
        loop {
            let mut b = [0u8; 1];
            conn.read_exact(&mut b).await?;
            if b[0] == 0 {
                break;
            }
            user_id.push(b[0]);
        }

        // Check for SOCKS4a: IP is 0.0.0.x where x != 0
        let is_socks4a = ip_buf[0] == 0 && ip_buf[1] == 0 && ip_buf[2] == 0 && ip_buf[3] != 0;
        let host = if is_socks4a {
            // Read domain name (null terminated)
            let mut domain = Vec::new();
            loop {
                let mut b = [0u8; 1];
                conn.read_exact(&mut b).await?;
                if b[0] == 0 {
                    break;
                }
                domain.push(b[0]);
            }
            String::from_utf8_lossy(&domain).to_string()
        } else {
            ip.to_string()
        };

        let target = format!("{}:{}", host, port);
        info!("[socks4] {} -> {}", peer_addr, target);

        match cmd[0] {
            CMD_CONNECT => self.handle_connect(conn, &target, &peer_addr).await,
            CMD_BIND => {
                self.handle_bind(conn, &target, is_socks4a, &peer_addr)
                    .await
            }
            _ => {
                send_reply(&mut conn, REP_REJECTED, "0.0.0.0", 0).await?;
                Err(HandlerError::Proxy(format!(
                    "unsupported SOCKS4 command: {}",
                    cmd[0]
                )))
            }
        }
    }
}

async fn send_reply(
    conn: &mut TcpStream,
    code: u8,
    addr: &str,
    port: u16,
) -> Result<(), HandlerError> {
    let ip: Ipv4Addr = addr.parse().unwrap_or(Ipv4Addr::UNSPECIFIED);
    let mut reply = vec![0x00, code]; // VN=0, CD=code
    reply.extend_from_slice(&port.to_be_bytes());
    reply.extend_from_slice(&ip.octets());
    conn.write_all(&reply).await?;
    Ok(())
}

fn parse_address(addr: &str) -> Result<(String, u16), HandlerError> {
    let (host, port_str) = addr
        .rsplit_once(':')
        .ok_or_else(|| HandlerError::Proxy(format!("invalid address: {}", addr)))?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| HandlerError::Proxy(format!("invalid port: {}", port_str)))?;
    Ok((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_socks4_handler_connect() {
        // Start a mock target server
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            conn.write_all(b"socks4 ok").await.unwrap();
        });

        // Start SOCKS4 proxy
        let handler = Socks4Handler::new(HandlerOptions::default());
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(conn).await.ok();
        });

        // Connect as SOCKS4 client
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();

        let ip = match target_addr.ip() {
            std::net::IpAddr::V4(ip4) => ip4,
            _ => panic!("expected IPv4"),
        };
        let port = target_addr.port();

        let mut req = vec![0x04, 0x01]; // VER=4, CMD=CONNECT
        req.extend_from_slice(&port.to_be_bytes());
        req.extend_from_slice(&ip.octets());
        req.push(0x00); // null user ID
        client.write_all(&req).await.unwrap();

        // Read reply
        let mut resp = [0u8; 8];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[1], 0x5A); // granted

        // Read data from target
        let mut buf = vec![0u8; 1024];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"socks4 ok");
    }

    #[tokio::test]
    async fn test_socks4a_handler_connect() {
        // Start a mock target server
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            conn.write_all(b"socks4a ok").await.unwrap();
        });

        // Start SOCKS4 proxy (supports 4a)
        let handler = Socks4Handler::new(HandlerOptions::default());
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(conn).await.ok();
        });

        // Connect as SOCKS4a client (with domain name as IP address)
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();

        let port = target_addr.port();
        let _target_host = format!("127.0.0.1:{}", port);

        // Use the Socks4aConnector for simplicity, but manually test the domain path
        let mut req = vec![0x04, 0x01]; // VER=4, CMD=CONNECT
        req.extend_from_slice(&port.to_be_bytes());
        req.extend_from_slice(&[0, 0, 0, 1]); // SOCKS4a indicator
        req.push(0x00); // null user ID
        req.extend_from_slice(b"127.0.0.1");
        req.push(0x00); // null domain terminator
        client.write_all(&req).await.unwrap();

        let mut resp = [0u8; 8];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[1], 0x5A); // granted

        let mut buf = vec![0u8; 1024];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"socks4a ok");
    }

    /// Helper: spawn a one-shot SOCKS4 proxy and return its address.
    async fn spawn_proxy(options: HandlerOptions) -> SocketAddr {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = proxy.local_addr().unwrap();
        tokio::spawn(async move {
            let handler = Socks4Handler::new(options);
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(conn).await.ok();
        });
        addr
    }

    /// Reads an 8-byte SOCKS4 reply and returns (code, ip, port).
    async fn read_reply(client: &mut TcpStream) -> (u8, Ipv4Addr, u16) {
        let mut resp = [0u8; 8];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[0], 0x00, "SOCKS4 reply VN must be 0");
        let port = u16::from_be_bytes([resp[2], resp[3]]);
        let ip = Ipv4Addr::new(resp[4], resp[5], resp[6], resp[7]);
        (resp[1], ip, port)
    }

    // ---- Defect 3: the CONNECT reply must not leak the outbound address ----

    #[tokio::test]
    async fn test_socks4_connect_reply_has_zero_address() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        tokio::spawn(async move {
            let (_c, _) = target.accept().await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let proxy_addr = spawn_proxy(HandlerOptions::default()).await;
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();

        let ip = match target_addr.ip() {
            IpAddr::V4(v) => v,
            _ => panic!("expected v4"),
        };
        let mut req = vec![SOCKS4_VERSION, CMD_CONNECT];
        req.extend_from_slice(&target_addr.port().to_be_bytes());
        req.extend_from_slice(&ip.octets());
        req.push(0x00);
        client.write_all(&req).await.unwrap();

        let mut resp = [0u8; 8];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(
            resp,
            [0x00, REP_GRANTED, 0, 0, 0, 0, 0, 0],
            "CONNECT reply must carry an all-zero address (gost parity)"
        );
    }

    // ---- Defect 4: SOCKS4 BIND ----

    #[tokio::test]
    async fn test_socks4_bind_roundtrip() {
        let proxy_addr = spawn_proxy(HandlerOptions::default()).await;
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();

        // BIND on 127.0.0.1:0 (ephemeral).
        let mut req = vec![SOCKS4_VERSION, CMD_BIND];
        req.extend_from_slice(&0u16.to_be_bytes());
        req.extend_from_slice(&[127, 0, 0, 1]);
        req.push(0x00);
        client.write_all(&req).await.unwrap();

        // First reply: the bound address.
        let (code, ip, port) = read_reply(&mut client).await;
        assert_eq!(code, REP_GRANTED);
        assert_ne!(port, 0, "the first BIND reply must carry the real bound port");
        let bound = SocketAddr::new(IpAddr::V4(ip), port);

        // A peer connects to the bound address.
        let mut peer = TcpStream::connect(bound).await.unwrap();
        let peer_local = peer.local_addr().unwrap();

        // Second reply: the peer's address.
        let (code2, pip, pport) = read_reply(&mut client).await;
        assert_eq!(code2, REP_GRANTED);
        assert_eq!(IpAddr::V4(pip), peer_local.ip());
        assert_eq!(pport, peer_local.port());

        // Spliced, both directions.
        peer.write_all(b"peer->client").await.unwrap();
        let mut buf = vec![0u8; 64];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"peer->client");

        client.write_all(b"client->peer").await.unwrap();
        let n = peer.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"client->peer");
    }

    #[tokio::test]
    async fn test_socks4_bind_denied_by_blacklist() {
        let bl = crate::permissions::Permissions::parse("rtcp:*:*").unwrap();
        let proxy_addr = spawn_proxy(HandlerOptions {
            blacklist: Some(bl),
            ..Default::default()
        })
        .await;

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let mut req = vec![SOCKS4_VERSION, CMD_BIND];
        req.extend_from_slice(&0u16.to_be_bytes());
        req.extend_from_slice(&[127, 0, 0, 1]);
        req.push(0x00);
        client.write_all(&req).await.unwrap();

        let (code, _, _) = read_reply(&mut client).await;
        assert_eq!(code, REP_REJECTED);
    }

    // ---- Defect 5: retries ----

    #[tokio::test]
    async fn test_socks4_connect_retries_then_rejects() {
        let proxy_addr = spawn_proxy(HandlerOptions {
            retries: 3,
            timeout: Duration::from_millis(100),
            ..Default::default()
        })
        .await;

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let mut req = vec![SOCKS4_VERSION, CMD_CONNECT];
        req.extend_from_slice(&1u16.to_be_bytes()); // port 1: nothing listening
        req.extend_from_slice(&[127, 0, 0, 1]);
        req.push(0x00);
        client.write_all(&req).await.unwrap();

        let (code, _, _) = read_reply(&mut client).await;
        assert_eq!(code, REP_REJECTED);
    }

    #[test]
    fn test_socks4_dial_setup_retry_precedence() {
        use crate::chain::Chain;
        use crate::node::Node;

        let node = || Node {
            addr: "127.0.0.1:1".into(),
            protocol: "socks5".into(),
            ..Default::default()
        };

        let (_, r, _) = Socks4Handler::new(HandlerOptions {
            chain: Some(Chain::new(vec![node()])),
            ..Default::default()
        })
        .dial_setup();
        assert_eq!(r, 1);

        let mut chain = Chain::new(vec![node()]);
        chain.retries = 5;
        let (c, r, _) = Socks4Handler::new(HandlerOptions {
            chain: Some(chain),
            ..Default::default()
        })
        .dial_setup();
        assert_eq!(r, 5, "the chain's Retries must be used when the handler's is 0");
        assert_eq!(c.retries, 1, "the inner chain loop must not retry as well");

        // Handler wins over chain (gost socks.go:1733-1739).
        let mut chain = Chain::new(vec![node()]);
        chain.retries = 5;
        let (_, r, o) = Socks4Handler::new(HandlerOptions {
            chain: Some(chain),
            retries: 3,
            timeout: Duration::from_millis(250),
            ..Default::default()
        })
        .dial_setup();
        assert_eq!(r, 3);
        assert_eq!(o.retries, 1);
        assert_eq!(o.timeout, Duration::from_millis(250));
    }

    #[tokio::test]
    async fn test_socks4_dial_target_actually_retries() {
        use crate::chain::Chain;
        use crate::node::Node;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let node_addr = ln.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        tokio::spawn(async move {
            while let Ok((conn, _)) = ln.accept().await {
                h.fetch_add(1, Ordering::SeqCst);
                drop(conn);
            }
        });

        let chain = Chain::new(vec![Node {
            addr: node_addr.to_string(),
            protocol: "socks5".into(),
            ..Default::default()
        }]);
        let handler = Socks4Handler::new(HandlerOptions {
            chain: Some(chain),
            retries: 3,
            timeout: Duration::from_millis(300),
            ..Default::default()
        });

        assert!(handler.dial_target("example.com:80").await.is_err());
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            hits.load(Ordering::SeqCst),
            3,
            "options.retries must drive the dial loop on the live path"
        );
    }

    #[test]
    fn test_socks4_dial_setup_keeps_chain_hosts() {
        use crate::chain::Chain;
        use crate::hosts::Hosts;

        let mut chain = Chain::empty();
        chain.hosts = Some(Hosts::new(vec![]));
        let (_, _, opts) = Socks4Handler::new(HandlerOptions {
            chain: Some(chain),
            ..Default::default()
        })
        .dial_setup();
        assert!(
            opts.hosts.is_some(),
            "the chain's hosts table must reach the dial options"
        );
    }

    #[tokio::test]
    async fn test_socks4_unsupported_command() {
        let proxy_addr = spawn_proxy(HandlerOptions::default()).await;
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();

        let mut req = vec![SOCKS4_VERSION, 0x09];
        req.extend_from_slice(&80u16.to_be_bytes());
        req.extend_from_slice(&[127, 0, 0, 1]);
        req.push(0x00);
        client.write_all(&req).await.unwrap();

        let (code, _, _) = read_reply(&mut client).await;
        assert_eq!(code, REP_REJECTED);
    }

    #[tokio::test]
    async fn test_socks4_connector() {
        // Start SOCKS4 proxy with our handler
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            conn.write_all(b"from target").await.unwrap();
        });

        let handler = Socks4Handler::new(HandlerOptions::default());
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(conn).await.ok();
        });

        // Use Socks4Connector
        let connector = Socks4Connector::new();
        let stream = TcpStream::connect(proxy_addr).await.unwrap();
        let mut conn = connector
            .connect(stream, &target_addr.to_string())
            .await
            .unwrap();

        let mut buf = vec![0u8; 1024];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"from target");
    }
}
