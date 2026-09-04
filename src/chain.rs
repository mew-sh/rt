use std::time::Duration;

use tokio::net::TcpStream;
use tracing::debug;

use crate::conn::ProxyConn;
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
    /// Live smux sessions, keyed by hop. Shared across clones so every dial
    /// through this chain reuses the same session per node — which is the
    /// entire reason the multiplexed transports exist.
    mux_dialers: std::sync::Arc<crate::mux_transport::MuxDialerPool>,
    /// Live QUIC connections, keyed by hop, for the same reason as the smux
    /// pool: one connection per node, a stream per dial.
    quic_transporters: std::sync::Arc<QuicTransporterPool>,
    /// One authenticated SSH session per hop, carrying many channels.
    ssh_transporters: std::sync::Arc<SshTransporterPool>,
    /// One KCP session per hop, with a stream per dial (gost's
    /// `kcpTransporter.sessions` map).
    kcp_transporters: std::sync::Arc<KcpTransporterPool>,
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
            mux_dialers: std::sync::Arc::new(crate::mux_transport::MuxDialerPool::new()),
            quic_transporters: std::sync::Arc::new(QuicTransporterPool::default()),
            ssh_transporters: std::sync::Arc::new(SshTransporterPool::default()),
            kcp_transporters: std::sync::Arc::new(KcpTransporterPool::default()),
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
            mux_dialers: std::sync::Arc::new(crate::mux_transport::MuxDialerPool::new()),
            quic_transporters: std::sync::Arc::new(QuicTransporterPool::default()),
            ssh_transporters: std::sync::Arc::new(SshTransporterPool::default()),
            kcp_transporters: std::sync::Arc::new(KcpTransporterPool::default()),
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
    ///
    /// Returns a [`ProxyConn`] rather than a `TcpStream` so a hop can layer a
    /// transport (currently TLS) over the socket before the next hop's
    /// protocol connector runs.
    pub async fn dial(&self, address: &str) -> Result<ProxyConn, ChainError> {
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
    ) -> Result<ProxyConn, ChainError> {
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
    ) -> Result<ProxyConn, ChainError> {
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
            let conn = self.connect_tcp(&target, timeout).await?;
            return Ok(ProxyConn::from_tcp(conn));
        }

        // Connect through proxy chain
        let nodes = self.nodes();
        if nodes.is_empty() {
            return Err(ChainError::EmptyChain);
        }

        let hop_target = |i: usize| -> &str {
            if i == nodes.len() - 1 {
                target.as_str()
            } else {
                nodes[i + 1].addr.as_str()
            }
        };

        // The first hop. A multiplexed transport has to own its dial: it hands
        // out a stream on a session it keeps alive across calls, so handing it
        // a freshly dialled socket would build a session per dial and make
        // `mtls` strictly more expensive than plain `tls`.
        let first = &nodes[0];
        debug!("[chain] connecting to first node: {}", first.addr);
        let mut current = if is_mux_transport(&first.transport) {
            self.dial_mux_hop(first, timeout).await?
        } else if first.transport == "quic" {
            self.dial_quic_hop(first).await?
        } else if first.transport == "kcp" {
            self.dial_kcp_hop(first).await?
        } else if first.transport == "ssh" {
            // An SSH hop owns its dial for the same reason as mux and QUIC:
            // one authenticated session carries many channels.
            return self.dial_ssh_hop(first, hop_target(0), timeout).await;
        } else {
            let conn = self.connect_tcp(&first.addr, timeout).await?;
            layer_transport(ProxyConn::from_tcp(conn), first).await?
        };
        current = connect_via(current, first, hop_target(0)).await?;

        // Remaining hops: each is reached through the previous one, so it
        // layers its transport over that connection and then runs its protocol
        // connector — gost's Dial -> Handshake -> Connect order
        // (chain.go:286-319).
        for (i, node) in nodes.iter().enumerate().skip(1) {
            if is_mux_transport(&node.transport)
                || node.transport == "quic"
                || node.transport == "ssh"
                || node.transport == "kcp"
            {
                // Reaching it would mean building a session over the previous
                // hop's connection, and a session per dial defeats the point.
                // gost dials such a hop through a sub-chain; not implemented.
                return Err(ChainError::ProxyError(format!(
                    "chain node transport {:?} is only supported on the first hop (in {})",
                    node.transport, node
                )));
            }
            current = layer_transport(current, node).await?;
            current = connect_via(current, node, hop_target(i)).await?;
        }

        Ok(current)
    }

    /// Opens an outbound datagram channel, tunnelling it through the chain when
    /// the last hop can carry UDP.
    ///
    /// With no chain, this is a plain UDP socket. With a SOCKS5 last hop it is
    /// gost's `CmdUDPTun` (0xF3), which carries datagrams over that hop's TCP
    /// control connection. Any other last hop cannot carry UDP, and that is an
    /// error rather than a silent direct send that would leak traffic around
    /// the proxy the operator configured.
    pub async fn dial_udp(&self, bind: std::net::SocketAddr) -> Result<UdpChannel, ChainError> {
        if self.is_empty() {
            let sock = tokio::net::UdpSocket::bind(bind)
                .await
                .map_err(ChainError::Io)?;
            return Ok(UdpChannel::Direct(sock));
        }

        let last = self.last_node();
        if last.protocol != "socks5" && last.protocol != "socks" {
            return Err(ChainError::ProxyError(format!(
                "chain last hop {:?} cannot carry UDP; only socks5 supports it (via CmdUDPTun)",
                last.protocol
            )));
        }

        // Reach the last hop through the rest of the chain, then ask it to
        // open a UDP association we tunnel over that same connection.
        let control = self.dial(&last.addr).await?;
        let connector = crate::socks5::Socks5Connector::new(last.user.clone());
        let tunnel = connector
            .udp_tunnel(control, "0.0.0.0:0", None)
            .await
            .map_err(|e| ChainError::ProxyError(format!("socks5 UDP tunnel failed: {}", e)))?;

        // A single TCP stream cannot serve concurrent reads and writes without
        // interleaving frames, so split it into pump tasks behind channels.
        let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<(Vec<u8>, String, u16)>(128);
        let (in_tx, in_rx) = tokio::sync::mpsc::channel::<(Vec<u8>, String, u16)>(128);

        let tunnel = std::sync::Arc::new(tokio::sync::Mutex::new(tunnel));
        let writer_tunnel = tunnel.clone();
        let writer = tokio::spawn(async move {
            while let Some((data, host, port)) = out_rx.recv().await {
                if writer_tunnel
                    .lock()
                    .await
                    .send_to(&data, &host, port)
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        let reader = tokio::spawn(async move {
            loop {
                let received = { tunnel.lock().await.recv_from().await };
                match received {
                    Ok(Some((data, host, port))) => {
                        if in_tx.send((data, host, port)).await.is_err() {
                            break;
                        }
                    }
                    // A clean end of stream or a framing error both end the
                    // association; the consumer sees the channel close.
                    Ok(None) | Err(_) => break,
                }
            }
        });

        Ok(UdpChannel::Tunnel {
            tx: out_tx,
            rx: tokio::sync::Mutex::new(in_rx),
            _pump: DropGuard(vec![writer, reader]),
        })
    }

    /// Opens a stream on this hop's KCP session, establishing it the first
    /// time. Like mux, QUIC and SSH, a KCP hop owns its dial because one
    /// session carries many streams.
    async fn dial_kcp_hop(&self, node: &Node) -> Result<ProxyConn, ChainError> {
        let config = crate::kcp::KcpConfig::from_node(node)
            .map_err(|e| ChainError::ProxyError(e.to_string()))?;
        let transporter = self
            .kcp_transporters
            .get_or_create(&format!("kcp|{}", node.addr), config)?;

        let stream = transporter
            .dial(&node.addr)
            .await
            .map_err(|e| ChainError::ProxyError(format!("kcp hop failed: {}", e)))?;
        Ok(ProxyConn::layered(Box::new(stream), None, None))
    }

    /// Opens a channel on this hop's SSH session, establishing and
    /// authenticating the session the first time.
    ///
    /// gost pairs `direct`/`remote`+ssh with its SSH forward transporter
    /// (route.go:203-208): the hop is the endpoint, so the channel it opens
    /// already reaches `target` and no further protocol connector runs.
    async fn dial_ssh_hop(
        &self,
        node: &Node,
        target: &str,
        timeout: Duration,
    ) -> Result<ProxyConn, ChainError> {
        let transporter = self.ssh_transporters.get_or_create(
            &format!("ssh|{}", node.addr),
            crate::ssh::SshConfig::from_node(node),
        )?;

        let addr = node.addr.clone();
        let session = transporter
            .session_over(&node.addr, || async move {
                tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr))
                    .await
                    .map_err(|_| {
                        crate::ssh::SshError::Config(format!("timed out connecting to {}", addr))
                    })?
                    .map_err(|e| crate::ssh::SshError::Config(e.to_string()))
            })
            .await
            .map_err(|e| ChainError::ProxyError(format!("ssh hop failed: {}", e)))?;

        session
            .connect(target)
            .await
            .map_err(|e| ChainError::ProxyError(format!("ssh channel to {} failed: {}", target, e)))
    }

    /// Opens a stream on this hop's QUIC connection, establishing the
    /// connection the first time.
    ///
    /// Like a mux hop, this owns its dial: QUIC carries many streams on one
    /// connection, so handing it a socket per dial would defeat the point.
    async fn dial_quic_hop(&self, node: &Node) -> Result<ProxyConn, ChainError> {
        let config = crate::quic_transport::quic_config_from_node(node)
            .map_err(|e| ChainError::ProxyError(e.to_string()))?;

        // Keyed by the hop's own parameters, since two nodes on the same host
        // may differ in `?cipher=` or keep-alive.
        let key = format!(
            "quic|{}|{}|{}",
            node.addr,
            node.get("cipher").unwrap_or(""),
            node.get("keepalive").unwrap_or("")
        );
        let transporter = self.quic_transporters.get_or_create(&key, config)?;

        let stream = transporter
            .dial(&node.addr)
            .await
            .map_err(|e| ChainError::ProxyError(format!("quic hop failed: {}", e)))?;

        Ok(ProxyConn::layered(Box::new(stream), None, None))
    }

    /// Opens a stream on this hop's smux session, building the session (and the
    /// TCP + TLS/WebSocket stack under it) the first time.
    async fn dial_mux_hop(&self, node: &Node, timeout: Duration) -> Result<ProxyConn, ChainError> {
        let mux = crate::mux_transport::mux_config_from_node(node)
            .map_err(|e| ChainError::ProxyError(e.to_string()))?;

        let addr = node.addr.clone();
        let host = hop_hostname(node);
        let insecure = !node.get_bool("secure");
        let opts = ws_options_for(node);
        let transport = node.transport.clone();

        let dialer = self
            .mux_dialers
            .get_or_create(&format!("{}|{}", transport, addr), mux, move || {
                let (addr, host, opts, transport) =
                    (addr.clone(), host.clone(), opts.clone(), transport.clone());
                async move {
                    let tcp = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr))
                        .await
                        .map_err(|_| {
                            std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                format!("timed out connecting to {}", addr),
                            )
                        })??;

                    let inner: Box<dyn crate::conn::AsyncStream> = match transport.as_str() {
                        "mtls" => Box::new(
                            crate::tls_transport::tls_connect_stream(tcp, &host, insecure).await?,
                        ),
                        "mws" => {
                            Box::new(crate::ws::ws_connect_stream(tcp, &host, "", &opts).await?)
                        }
                        // mwss: TLS first, then WebSocket over it.
                        _ => {
                            let tls =
                                crate::tls_transport::tls_connect_stream(tcp, &host, insecure)
                                    .await?;
                            Box::new(crate::ws::ws_connect_stream(tls, &host, "", &opts).await?)
                        }
                    };
                    Ok::<_, Box<dyn std::error::Error + Send + Sync>>(inner)
                }
            })
            .map_err(|e| ChainError::ProxyError(e.to_string()))?;

        let stream = dialer
            .dial()
            .await
            .map_err(|e| ChainError::ProxyError(format!("{} hop failed: {}", node.transport, e)))?;

        Ok(ProxyConn::layered(Box::new(stream), None, None))
    }

    /// Opens an outbound TCP connection, applying the chain's `-M` socket mark
    /// and `-I` interface binding.
    ///
    /// Both have to be set on the socket *before* it connects, so this cannot
    /// use `TcpStream::connect`. gost does the same thing from its dialer's
    /// `Control` callback (chain.go:167-191).
    async fn connect_tcp(&self, addr: &str, timeout: Duration) -> Result<TcpStream, ChainError> {
        if self.mark == 0 && self.interface.is_empty() {
            return tokio::time::timeout(timeout, TcpStream::connect(addr))
                .await
                .map_err(|_| ChainError::Timeout)?
                .map_err(ChainError::Io);
        }

        // TcpSocket needs a resolved address, unlike TcpStream::connect.
        let sockaddr = tokio::time::timeout(timeout, tokio::net::lookup_host(addr))
            .await
            .map_err(|_| ChainError::Timeout)?
            .map_err(ChainError::Io)?
            .next()
            .ok_or_else(|| ChainError::ProxyError(format!("could not resolve {}", addr)))?;

        let socket = if sockaddr.is_ipv4() {
            tokio::net::TcpSocket::new_v4()
        } else {
            tokio::net::TcpSocket::new_v6()
        }
        .map_err(ChainError::Io)?;

        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            let fd = socket.as_raw_fd();
            if self.mark != 0 {
                crate::sockopts::set_socket_mark(fd, self.mark).map_err(ChainError::Io)?;
            }
            if !self.interface.is_empty() {
                crate::sockopts::set_socket_interface(fd, &self.interface)
                    .map_err(ChainError::Io)?;
            }
        }

        tokio::time::timeout(timeout, socket.connect(sockaddr))
            .await
            .map_err(|_| ChainError::Timeout)?
            .map_err(ChainError::Io)
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

/// Layers a hop's transport over the connection before its protocol connector
/// runs, so `-F http+tls://proxy:443` speaks CONNECT inside TLS.
///
/// An unimplemented transport is a hard error rather than a silent fall back
/// to cleartext.
async fn layer_transport(stream: ProxyConn, node: &Node) -> Result<ProxyConn, ChainError> {
    match node.transport.as_str() {
        "" | "tcp" => Ok(stream),
        "tls" => {
            // gost verifies the peer only when `?secure=true` is set
            // (route.go:135); the default is to skip verification.
            let insecure = !node.get_bool("secure");
            let host = hop_hostname(node);
            let peer = stream.peer_addr();
            let local = stream.local_addr();
            let tls = crate::tls_transport::tls_connect_stream(stream, &host, insecure)
                .await
                .map_err(|e| {
                    ChainError::ProxyError(format!("TLS handshake with {} failed: {}", host, e))
                })?;
            Ok(ProxyConn::layered(Box::new(tls), peer, local))
        }
        "ws" | "wss" => {
            let host = hop_hostname(node);
            let opts = ws_options_for(node);
            let peer = stream.peer_addr();
            let local = stream.local_addr();

            // `wss` is TLS then WebSocket, so the two layers compose rather
            // than each needing their own socket.
            let inner: Box<dyn crate::conn::AsyncStream> = if node.transport == "wss" {
                let insecure = !node.get_bool("secure");
                Box::new(
                    crate::tls_transport::tls_connect_stream(stream, &host, insecure)
                        .await
                        .map_err(|e| {
                            ChainError::ProxyError(format!(
                                "TLS handshake with {} failed: {}",
                                host, e
                            ))
                        })?,
                )
            } else {
                Box::new(stream)
            };

            let ws = crate::ws::ws_connect_stream(inner, &host, "", &opts)
                .await
                .map_err(|e| {
                    ChainError::ProxyError(format!(
                        "WebSocket handshake with {} failed: {}",
                        host, e
                    ))
                })?;
            Ok(ProxyConn::layered(Box::new(ws), peer, local))
        }
        // Obfuscation only reframes the socket; the hop's protocol connector
        // then runs inside it exactly as it would over plain TCP.
        "ohttp" | "otls" => {
            let host = hop_hostname(node);
            let peer = stream.peer_addr();
            let local = stream.local_addr();
            let framed: Box<dyn crate::conn::AsyncStream> = if node.transport == "otls" {
                Box::new(
                    crate::obfs_transport::otls_connect(stream, &host)
                        .await
                        .map_err(|e| {
                            ChainError::ProxyError(format!(
                                "obfs-tls handshake with {} failed: {}",
                                host, e
                            ))
                        })?,
                )
            } else {
                Box::new(
                    crate::obfs_transport::ohttp_connect(stream, &host)
                        .await
                        .map_err(|e| {
                            ChainError::ProxyError(format!(
                                "obfs-http handshake with {} failed: {}",
                                host, e
                            ))
                        })?,
                )
            };
            Ok(ProxyConn::layered(framed, peer, local))
        }
        // `http2` layers only TLS here; its CONNECT is the protocol connector
        // below, which is how gost splits transporter from connector
        // (http2.go:122-199).
        "http2" => {
            let insecure = !node.get_bool("secure");
            let host = hop_hostname(node);
            let peer = stream.peer_addr();
            let local = stream.local_addr();
            let tls =
                crate::tls_transport::tls_connect_stream_alpn(stream, &host, insecure, &["h2"])
                    .await
                    .map_err(|e| {
                        ChainError::ProxyError(format!("TLS handshake with {} failed: {}", host, e))
                    })?;
            Ok(ProxyConn::layered(Box::new(tls), peer, local))
        }
        // Like `wss`, `h2` composes TLS underneath rather than opening a
        // second socket; `h2c` is the cleartext form.
        "h2" | "h2c" => {
            let host = hop_hostname(node);
            let config = crate::h2_transport::H2Config::from_node(node);
            let peer = stream.peer_addr();
            let local = stream.local_addr();

            let inner: Box<dyn crate::conn::AsyncStream> = if node.transport == "h2" {
                let insecure = !node.get_bool("secure");
                Box::new(
                    crate::tls_transport::tls_connect_stream_alpn(stream, &host, insecure, &["h2"])
                        .await
                        .map_err(|e| {
                            ChainError::ProxyError(format!(
                                "TLS handshake with {} failed: {}",
                                host, e
                            ))
                        })?,
                )
            } else {
                Box::new(stream)
            };

            let h2 = crate::h2_transport::h2_connect(inner, &host, &config)
                .await
                .map_err(|e| {
                    ChainError::ProxyError(format!("HTTP/2 tunnel to {} failed: {}", host, e))
                })?;
            Ok(ProxyConn::layered(Box::new(h2), peer, local))
        }
        other => Err(ChainError::ProxyError(format!(
            "chain node transport {:?} is not implemented",
            other
        ))),
    }
}

/// An outbound datagram channel: either a real UDP socket, or UDP tunnelled
/// over a SOCKS5 hop's TCP control connection.
///
/// gost gets this from `Chain.DialContext(ctx, "udp", ...)` (ss.go:300), which
/// is what lets `-L ssu://` and `-L udp://` relay through an upstream proxy.
///
/// Both variants expose `send_to`/`recv_from` taking `&self`, so a relay loop
/// can `select!` over them concurrently. A UDP socket supports that natively;
/// the tunnel is a single TCP stream, where frames must not interleave, so it
/// is driven by reader and writer tasks behind channels rather than a lock
/// that a blocked read would hold.
pub enum UdpChannel {
    Direct(tokio::net::UdpSocket),
    Tunnel {
        tx: tokio::sync::mpsc::Sender<(Vec<u8>, String, u16)>,
        rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<(Vec<u8>, String, u16)>>,
        /// Aborts the pump tasks when the channel is dropped, so a finished
        /// association does not leave the tunnel running.
        _pump: DropGuard,
    },
}

/// Aborts a set of tasks on drop.
pub struct DropGuard(Vec<tokio::task::JoinHandle<()>>);

impl Drop for DropGuard {
    fn drop(&mut self) {
        for h in &self.0 {
            h.abort();
        }
    }
}

impl UdpChannel {
    pub async fn send_to(&self, data: &[u8], host: &str, port: u16) -> std::io::Result<()> {
        match self {
            UdpChannel::Direct(sock) => {
                let addr = join_host_port(host, port);
                sock.send_to(data, &addr).await.map(|_| ())
            }
            UdpChannel::Tunnel { tx, .. } => tx
                .send((data.to_vec(), host.to_string(), port))
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "udp tunnel closed")
                }),
        }
    }

    /// Receives one datagram with its source address.
    pub async fn recv_from(&self) -> std::io::Result<(Vec<u8>, String, u16)> {
        match self {
            UdpChannel::Direct(sock) => {
                let mut buf = vec![0u8; 64 * 1024];
                let (n, from) = sock.recv_from(&mut buf).await?;
                buf.truncate(n);
                Ok((buf, from.ip().to_string(), from.port()))
            }
            UdpChannel::Tunnel { rx, .. } => rx.lock().await.recv().await.ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "udp tunnel closed")
            }),
        }
    }

    pub fn is_tunnelled(&self) -> bool {
        matches!(self, UdpChannel::Tunnel { .. })
    }
}

/// One `QuicTransporter` per hop configuration.
///
/// `QuicTransporter` already pools connections by address, but its config comes
/// from the node, so hops with different `?cipher=` or keep-alive settings need
/// their own.
#[derive(Default)]
pub struct QuicTransporterPool {
    inner: std::sync::Mutex<
        std::collections::HashMap<String, std::sync::Arc<crate::quic_transport::QuicTransporter>>,
    >,
}

impl std::fmt::Debug for QuicTransporterPool {
    // Hand-written because a transporter holds live endpoints, which are not
    // Debug, and `Chain` derives Debug.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let keys: Vec<String> = match self.inner.lock() {
            Ok(m) => m.keys().cloned().collect(),
            Err(p) => p.into_inner().keys().cloned().collect(),
        };
        f.debug_struct("QuicTransporterPool")
            .field("nodes", &keys)
            .finish()
    }
}

impl QuicTransporterPool {
    fn get_or_create(
        &self,
        key: &str,
        config: crate::quic_transport::QuicConfig,
    ) -> Result<std::sync::Arc<crate::quic_transport::QuicTransporter>, ChainError> {
        let mut map = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(existing) = map.get(key) {
            return Ok(existing.clone());
        }
        let created = std::sync::Arc::new(
            crate::quic_transport::QuicTransporter::new(config)
                .map_err(|e| ChainError::ProxyError(e.to_string()))?,
        );
        map.insert(key.to_string(), created.clone());
        Ok(created)
    }
}

/// One `KcpTransporter` per hop configuration.
#[derive(Default)]
pub struct KcpTransporterPool {
    inner: std::sync::Mutex<
        std::collections::HashMap<String, std::sync::Arc<crate::kcp::KcpTransporter>>,
    >,
}

impl std::fmt::Debug for KcpTransporterPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let keys: Vec<String> = match self.inner.lock() {
            Ok(m) => m.keys().cloned().collect(),
            Err(p) => p.into_inner().keys().cloned().collect(),
        };
        f.debug_struct("KcpTransporterPool")
            .field("nodes", &keys)
            .finish()
    }
}

impl KcpTransporterPool {
    fn get_or_create(
        &self,
        key: &str,
        config: crate::kcp::KcpConfig,
    ) -> Result<std::sync::Arc<crate::kcp::KcpTransporter>, ChainError> {
        let mut map = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(existing) = map.get(key) {
            return Ok(existing.clone());
        }
        let created = std::sync::Arc::new(
            crate::kcp::KcpTransporter::new(config)
                .map_err(|e| ChainError::ProxyError(e.to_string()))?,
        );
        map.insert(key.to_string(), created.clone());
        Ok(created)
    }
}

/// One `SshForwardTransporter` per hop, so a node's authenticated session is
/// reused across dials rather than rebuilt per connection.
#[derive(Default)]
pub struct SshTransporterPool {
    inner: std::sync::Mutex<
        std::collections::HashMap<String, std::sync::Arc<crate::ssh::SshForwardTransporter>>,
    >,
}

impl std::fmt::Debug for SshTransporterPool {
    // Hand-written because a transporter holds live sessions, which are not
    // Debug, and `Chain` derives Debug.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let keys: Vec<String> = match self.inner.lock() {
            Ok(m) => m.keys().cloned().collect(),
            Err(p) => p.into_inner().keys().cloned().collect(),
        };
        f.debug_struct("SshTransporterPool")
            .field("nodes", &keys)
            .finish()
    }
}

impl SshTransporterPool {
    fn get_or_create(
        &self,
        key: &str,
        config: crate::ssh::SshConfig,
    ) -> Result<std::sync::Arc<crate::ssh::SshForwardTransporter>, ChainError> {
        let mut map = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(existing) = map.get(key) {
            return Ok(existing.clone());
        }
        let created = std::sync::Arc::new(
            crate::ssh::SshForwardTransporter::new(config)
                .map_err(|e| ChainError::ProxyError(e.to_string()))?,
        );
        map.insert(key.to_string(), created.clone());
        Ok(created)
    }
}

/// Whether a hop's transport carries many streams over one session, and so
/// must own its dial rather than be layered over a socket it is handed.
fn is_mux_transport(transport: &str) -> bool {
    matches!(transport, "mtls" | "mws" | "mwss")
}

/// The name to present to a hop's transport: `?host=` when set, else the
/// hop's own hostname.
fn hop_hostname(node: &Node) -> String {
    node.get("host")
        .filter(|h| !h.is_empty())
        .map(|h| h.to_string())
        .unwrap_or_else(|| {
            split_host_port(&node.addr)
                .map(|(h, _)| h.to_string())
                .unwrap_or_else(|_| "localhost".to_string())
        })
}

fn ws_options_for(node: &Node) -> crate::ws::WsOptions {
    let mut opts = crate::ws::WsOptions::default();
    if let Some(path) = node.get("path").filter(|p| !p.is_empty()) {
        opts.path = path.to_string();
    }
    if let Some(agent) = node.get("agent").filter(|a| !a.is_empty()) {
        opts.user_agent = agent.to_string();
    }
    opts.enable_compression = node.get_bool("compression");
    opts.read_buffer_size = node.get_int("rbuf").max(0) as usize;
    opts.write_buffer_size = node.get_int("wbuf").max(0) as usize;
    opts
}

/// Performs the proxy handshake for one hop, using that node's protocol.
///
/// An unrecognised protocol is a hard error: returning the raw socket would
/// hand the caller a connection to the *proxy* while it believes it is talking
/// to the *target*, silently misrouting the traffic.
async fn connect_via(
    stream: ProxyConn,
    node: &Node,
    target: &str,
) -> Result<ProxyConn, ChainError> {
    match node.protocol.as_str() {
        // An empty protocol is gost's `auto`, whose connector is the HTTP one
        // for TCP (client.go:62-72). Treating it as a pass-through means no
        // CONNECT is ever sent, so a node like `-F tls://host:443` reaches the
        // proxy and then asks it for nothing.
        "http" | "" => http_connect(stream, target, node.user.as_ref()).await,
        // The TLS layer already ran; this opens the CONNECT stream on it.
        "http2" => {
            let peer = stream.peer_addr();
            let local = stream.local_addr();
            let tunnel = crate::http2_transport::http2_connect(stream, target)
                .await
                .map_err(|e| {
                    ChainError::ProxyError(format!("HTTP/2 CONNECT to {} failed: {}", target, e))
                })?;
            Ok(ProxyConn::layered(Box::new(tunnel), peer, local))
        }
        "socks5" => socks5_connect(stream, target, node).await,
        "socks4" => socks4_connect(stream, target, node.user.as_ref(), false).await,
        "socks4a" => socks4_connect(stream, target, node.user.as_ref(), true).await,
        "ss" => {
            // gost takes the cipher from the userinfo username, as on the
            // listener side (route.go:263, ss.go:589-590).
            let (method, password) = match node.user.as_ref() {
                Some((m, p)) => (m.as_str(), p.clone().unwrap_or_default()),
                None => ("plain", String::new()),
            };
            let connector = crate::ss::ShadowConnector::new(method, &password)
                .map_err(|e| ChainError::ProxyError(e.to_string()))?;
            let stream = connector
                .connect(stream, target)
                .await
                .map_err(|e| ChainError::ProxyError(e.to_string()))?;
            Ok(ProxyConn::layered(Box::new(stream), None, None))
        }
        "relay" => {
            let connector = crate::relay::RelayConnector::new(node.user.clone());
            let stream = connector
                .connect(stream, "tcp", target)
                .await
                .map_err(|e| ChainError::ProxyError(e.to_string()))?;
            Ok(ProxyConn::layered(Box::new(stream), None, None))
        }
        // "forward"/"direct"/"remote" hand the connection straight through;
        // the node itself is the endpoint rather than a proxy to traverse.
        "forward" | "direct" | "remote" => Ok(stream),
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

/// Reads exactly one HTTP response head, pushing back any bytes the peer
/// coalesced after the terminator.
///
/// Reading into a large buffer and discarding the remainder would drop payload
/// belonging to the tunnelled stream, so whatever is read past `\r\n\r\n` is
/// returned to the connection via `unread`.
async fn read_response_head(stream: &mut ProxyConn) -> Result<String, ChainError> {
    use tokio::io::AsyncReadExt;

    let mut acc: Vec<u8> = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];

    loop {
        let n = stream.read(&mut chunk).await.map_err(ChainError::Io)?;
        if n == 0 {
            return Err(ChainError::ProxyError(
                "proxy closed the connection during CONNECT".into(),
            ));
        }
        acc.extend_from_slice(&chunk[..n]);

        if let Some(pos) = acc.windows(4).position(|w| w == b"\r\n\r\n") {
            let head_len = pos + 4;
            stream.unread(&acc[head_len..]);
            return Ok(String::from_utf8_lossy(&acc[..head_len]).into_owned());
        }
        if acc.len() > crate::MEDIUM_BUFFER_SIZE {
            return Err(ChainError::ProxyError(
                "CONNECT response headers too large".into(),
            ));
        }
    }
}

/// HTTP CONNECT tunnel through a proxy.
async fn http_connect(
    mut stream: ProxyConn,
    target: &str,
    user: Option<&(String, Option<String>)>,
) -> Result<ProxyConn, ChainError> {
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
    mut stream: ProxyConn,
    target: &str,
    user: Option<&(String, Option<String>)>,
    allow_domain: bool,
) -> Result<ProxyConn, ChainError> {
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
    stream: ProxyConn,
    target: &str,
    node: &Node,
) -> Result<ProxyConn, ChainError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const METHOD_NO_AUTH: u8 = 0x00;
    const METHOD_USER_PASS: u8 = 0x02;
    const METHOD_TLS: u8 = 0x80;
    const METHOD_TLS_AUTH: u8 = 0x82;
    const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;

    let user = node.user.as_ref();

    // Offer user/pass as well when credentials are configured, otherwise a
    // proxy that requires authentication can never be traversed. gost also
    // offers its TLS method unless `?notls=true` (socks.go:1865-1877); a gost
    // server picks it when offered, so not offering it silently downgrades a
    // hop that gost would have encrypted.
    let mut methods = vec![METHOD_NO_AUTH];
    if user.is_some() {
        methods.push(METHOD_USER_PASS);
    }
    if !node.get_bool("notls") {
        methods.push(METHOD_TLS);
    }
    let mut greeting = vec![0x05, methods.len() as u8];
    greeting.extend_from_slice(&methods);
    let mut stream = stream;
    stream.write_all(&greeting).await.map_err(ChainError::Io)?;

    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await.map_err(ChainError::Io)?;
    if buf[0] != 0x05 {
        return Err(ChainError::ProxyError("SOCKS5 handshake failed".into()));
    }

    // Both TLS methods replace the socket before anything else is exchanged.
    // gost skips verification here (socks.go:1867): the certificate only
    // carries the key exchange.
    if buf[1] == METHOD_TLS || buf[1] == METHOD_TLS_AUTH {
        let host = hop_hostname(node);
        let peer = stream.peer_addr();
        let local = stream.local_addr();
        let tls = crate::tls_transport::tls_connect_stream(stream, &host, true)
            .await
            .map_err(|e| {
                ChainError::ProxyError(format!("SOCKS5 TLS handshake with {} failed: {}", host, e))
            })?;
        stream = ProxyConn::layered(Box::new(tls), peer, local);
    }

    match buf[1] {
        METHOD_NO_AUTH | METHOD_TLS => {}
        METHOD_USER_PASS | METHOD_TLS_AUTH => {
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
            stream
                .read_exact(&mut reply)
                .await
                .map_err(ChainError::Io)?;
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
    async fn test_chain_direct_dial_with_socket_options() {
        // A non-zero mark or a bound interface takes the TcpSocket path rather
        // than TcpStream::connect, because both options must be set before the
        // socket connects.
        //
        // SO_MARK needs CAP_NET_ADMIN, which an unprivileged process (a CI
        // container, for instance) does not have. Failing the dial in that case
        // is deliberate: a mark is a routing decision, and quietly dialling
        // without it could send traffic around the policy the operator asked
        // for. So the contract is "applied, or a clear error" — never a silent
        // success that ignored the mark.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let mut c = Chain::empty();
        c.mark = 100;

        let handle = tokio::spawn(async move {
            let (_conn, _) = listener.accept().await.unwrap();
        });

        match c.dial(&addr.to_string()).await {
            Ok(_) => {
                // The dial connected, so the accept must complete. Bound so a
                // regression here fails the test instead of hanging CI.
                tokio::time::timeout(std::time::Duration::from_secs(10), handle)
                    .await
                    .expect("accept did not complete after a successful dial")
                    .unwrap();
            }
            Err(ChainError::Io(e))
                if e.kind() == std::io::ErrorKind::PermissionDenied
                    || e.raw_os_error() == Some(1) =>
            {
                // EPERM: no CAP_NET_ADMIN. Refusing is the intended behaviour.
                // Nothing ever reached the listener, so the accept would block
                // forever — drop it rather than await it.
                handle.abort();
            }
            Err(e) => {
                handle.abort();
                panic!("dial failed for an unexpected reason: {e}");
            }
        }
    }

    #[tokio::test]
    async fn test_chain_direct_dial_with_socket_options_reports_bad_host() {
        // The TcpSocket path resolves the address itself, so a name that does
        // not resolve has to surface as an error rather than a panic.
        let mut c = Chain::empty();
        c.mark = 100;
        assert!(c.dial("no-such-host.invalid:80").await.is_err());
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
            handler
                .handle(crate::conn::ProxyConn::from_tcp(conn))
                .await
                .ok();
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
            handler
                .handle(crate::conn::ProxyConn::from_tcp(conn))
                .await
                .ok();
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
