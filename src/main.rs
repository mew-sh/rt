use clap::Parser;
use std::collections::HashMap;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{error, info, warn};

use rt::*;

#[derive(Parser, Debug)]
#[command(
    name = "rt",
    version = VERSION,
    about = "A tunnel and proxy tool written in Rust",
    disable_version_flag = true
)]
struct Cli {
    /// Listen address, can listen on multiple ports (required)
    #[arg(short = 'L', action = clap::ArgAction::Append)]
    listen: Vec<String>,

    /// Forward address, can make a forward chain
    #[arg(short = 'F', action = clap::ArgAction::Append)]
    forward: Vec<String>,

    /// Specify out connection mark
    #[arg(short = 'M', default_value = "0")]
    mark: i32,

    /// Configure file
    #[arg(short = 'C')]
    config_file: Option<String>,

    /// Interface to bind
    #[arg(short = 'I')]
    interface: Option<String>,

    /// Enable debug log
    #[arg(short = 'D')]
    debug: bool,

    /// Print version
    #[arg(short = 'V')]
    print_version: bool,

    /// Profiling HTTP server address (requires PROFILING env var)
    #[arg(short = 'P', default_value = ":6060")]
    pprof_addr: String,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if cli.print_version {
        println!(
            "rt {} (rustc {}/{})",
            VERSION,
            std::env::consts::OS,
            std::env::consts::ARCH
        );
        std::process::exit(0);
    }

    let log_level = if cli.debug { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level)),
        )
        .init();

    // Global cancellation token: cancelled on Ctrl+C to shut down all servers
    let cancel = CancellationToken::new();
    // Track all spawned server tasks so we can wait for them on shutdown
    let tracker = TaskTracker::new();

    if let Some(config_file) = &cli.config_file {
        match config::load_config(config_file) {
            Ok(cfg) => {
                if let Err(e) = start_from_config(cfg, &cancel, &tracker).await {
                    error!("Failed to start from config: {}", e);
                    std::process::exit(1);
                }
            }
            Err(e) => {
                error!("Failed to load config: {}", e);
                std::process::exit(1);
            }
        }
    } else if !cli.listen.is_empty() {
        if let Err(e) = start_from_cli(&cli, &cancel, &tracker).await {
            error!("Failed to start: {}", e);
            std::process::exit(1);
        }
    } else {
        use clap::CommandFactory;
        Cli::command().print_help().ok();
        println!();
        std::process::exit(0);
    }

    // Wait for Ctrl+C, then trigger graceful shutdown
    tokio::signal::ctrl_c().await.ok();
    info!("Shutting down...");
    cancel.cancel();

    // Close tracker and wait for all server tasks to drain
    tracker.close();
    tracker.wait().await;
    info!("All servers stopped.");
}

async fn start_from_cli(
    cli: &Cli,
    cancel: &CancellationToken,
    tracker: &TaskTracker,
) -> Result<(), Box<dyn std::error::Error>> {
    let chain = if cli.forward.is_empty() {
        Chain::empty()
    } else {
        let mut nodes = Vec::new();
        for f in &cli.forward {
            let node = Node::parse(f)?;
            ensure_chain_transport_supported(&node)?;
            nodes.push(node);
        }
        let mut chain = Chain::new(nodes);
        chain.mark = cli.mark;
        if let Some(ref iface) = cli.interface {
            chain.interface = iface.clone();
        }
        chain
    };

    for listen_addr in &cli.listen {
        let node = Node::parse(listen_addr)?;
        let chain = chain.clone();
        let cancel = cancel.clone();

        tracker.spawn(async move {
            if let Err(e) = run_server(node, chain, cancel).await {
                error!("Server error: {}", e);
            }
        });
    }

    Ok(())
}

async fn start_from_config(
    cfg: config::Config,
    cancel: &CancellationToken,
    tracker: &TaskTracker,
) -> Result<(), Box<dyn std::error::Error>> {
    for route in cfg.routes {
        let chain = if route.chain_nodes.is_empty() {
            Chain::empty()
        } else {
            let mut nodes = Vec::new();
            for ns in &route.chain_nodes {
                let node = Node::parse(ns)?;
                ensure_chain_transport_supported(&node)?;
                nodes.push(node);
            }
            let mut chain = Chain::new(nodes);
            chain.retries = route.retries;
            chain.mark = route.mark;
            chain.interface = route.interface.clone();
            chain
        };

        for ns in &route.serve_nodes {
            let node = Node::parse(ns)?;
            let chain = chain.clone();
            let cancel = cancel.clone();

            tracker.spawn(async move {
                if let Err(e) = run_server(node, chain, cancel).await {
                    error!("Server error: {}", e);
                }
            });
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Build HandlerOptions by extracting all query parameters from the node
// ---------------------------------------------------------------------------

fn build_handler_options(node: &Node, mut chain: Chain) -> HandlerOptions {
    // --- Authentication ---
    let authenticator: Option<Arc<dyn Authenticator>> = {
        // 1. Try loading from secrets file
        if let Some(secrets_path) = node.get("secrets") {
            match load_secrets_file(secrets_path) {
                Ok(au) => Some(Arc::new(au)),
                Err(e) => {
                    warn!("failed to load secrets file {}: {}", secrets_path, e);
                    None
                }
            }
        }
        // 2. Fall back to inline credentials
        else if let Some((ref user, ref pass)) = node.user {
            let mut kvs = HashMap::new();
            kvs.insert(user.clone(), pass.clone().unwrap_or_default());
            Some(Arc::new(LocalAuthenticator::new(kvs)))
        } else {
            None
        }
    };

    // --- Bypass ---
    let bypass: Option<Arc<bypass::Bypass>> = node.get("bypass").map(|s| {
        let (reversed, patterns_str) = if let Some(stripped) = s.strip_prefix('~') {
            (true, stripped)
        } else {
            (false, s)
        };
        let patterns: Vec<&str> = patterns_str.split(',').filter(|p| !p.is_empty()).collect();
        Arc::new(bypass::Bypass::from_patterns(reversed, &patterns))
    });

    // --- Whitelist / Blacklist ---
    let whitelist = node
        .get("whitelist")
        .and_then(|s| Permissions::parse(s).ok());
    let blacklist = node
        .get("blacklist")
        .and_then(|s| Permissions::parse(s).ok());

    // --- Hosts ---
    let hosts = node.get("hosts").and_then(|path| {
        let f = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) => {
                warn!("failed to open hosts file {}: {}", path, e);
                return None;
            }
        };
        let h = Hosts::new(vec![]);
        if let Err(e) = h.reload(f) {
            warn!("failed to parse hosts file {}: {}", path, e);
            return None;
        }
        Some(h)
    });

    // --- Timeout / Retries ---
    let timeout = node.get_duration("timeout");
    let retries = node.get_int("retry") as usize;

    // Push the per-listener dial settings onto this listener's copy of the
    // chain so every handler honours them via the plain `chain.dial()` path.
    chain.hosts = hosts;
    chain.timeout = timeout;
    if retries > 0 {
        chain.retries = retries;
    }

    // --- Resolver (?dns=, ?prefer=, ?ip=) ---
    // Snapshot the chain for the resolver before storing the resolver on it,
    // so name-server dials route through the chain without a reference cycle.
    let resolver = node.get("dns").and_then(resolver::Resolver::parse);
    if let Some(ref r) = resolver {
        r.init(
            Some(Arc::new(chain.clone())),
            timeout,
            node.get_duration("ttl"),
            node.get("prefer").unwrap_or(""),
            node.get("ip").and_then(|s| s.parse::<std::net::IpAddr>().ok()),
        );
        if let Some(spec) = node.get("dns") {
            spawn_period_reload(r.clone(), spec);
        }
    }
    chain.resolver = resolver;

    // --- Proxy Agent ---
    let proxy_agent = node.get("proxyAgent").unwrap_or("").to_string();

    // --- Host (for SNI proxy) ---
    let host = node.get("host").unwrap_or("").to_string();

    HandlerOptions {
        addr: node.addr.clone(),
        chain: Some(chain),
        users: node
            .user
            .as_ref()
            .map(|u| vec![u.clone()])
            .unwrap_or_default(),
        authenticator,
        whitelist,
        blacklist,
        bypass,
        retries,
        timeout,
        node: Some(node.clone()),
        host,
        proxy_agent,
        strategy: node.get("strategy").unwrap_or("round").to_string(),
        max_fails: node.get_int("max_fails").max(0) as u32,
        fail_timeout: node.get_duration("fail_timeout"),
        fastest_count: node.get_int("fastest_count").max(0) as usize,
        probe_resist: node.get("probe_resist").unwrap_or("").to_string(),
        knocking_host: node.get("knock").unwrap_or("").to_string(),
    }
}

/// Starts gost's periodic file-watch reload for a config source, but only when
/// the source is a real file and it asked for a reload period.
fn spawn_period_reload<R>(reloader: R, spec: &str)
where
    R: reload::Reloader + reload::Stoppable + Send + Sync + 'static,
{
    if reloader.period().is_zero() || !std::path::Path::new(spec).is_file() {
        return;
    }
    let path = spec.to_string();
    tokio::spawn(async move {
        if let Err(e) = reload::period_reload(&reloader, &path).await {
            warn!("reload of {} stopped: {}", path, e);
        }
    });
}

/// Load a secrets file into a LocalAuthenticator.
/// Format: one `username password` pair per line. Lines starting with # are comments.
fn load_secrets_file(path: &str) -> Result<LocalAuthenticator, std::io::Error> {
    let f = std::fs::File::open(path)?;
    let au = LocalAuthenticator::new(HashMap::new());
    au.reload(f)?;
    Ok(au)
}

/// Transports that a listener can actually serve today.
///
/// Everything else in gost's transport set (`tls`, `mtls`, `ws`, `mws`, `wss`,
/// `mwss`, `kcp`, `quic`, `h2`, `h2c`, `ssh`, `ohttp`, `otls`, `obfs4`, `ftcp`,
/// `vsock`, `tun`, `tap`) has type definitions in this crate but no wiring
/// between a listener and the handler dispatch, so accepting them would serve
/// plaintext TCP under an encrypted-looking scheme.
const SUPPORTED_LISTENER_TRANSPORTS: &[&str] = &[
    "tcp", "tls", "ws", "wss", "mtls", "mws", "mwss", "quic", "kcp", "udp", "rtcp", "rudp", "dns",
    "redu",
];

fn ensure_listener_transport_supported(
    node: &Node,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let transport = node.transport.as_str();
    // `ssh` is only a listener transport for gost's `forward` protocol. Letting
    // it through unconditionally would give `-L http+ssh://` a plain TCP
    // listener, which is the hole this gate exists to close.
    if transport == "ssh" {
        ssh::ssh_listener_support(&node.protocol)?;
        return Ok(());
    }
    if transport.is_empty() || SUPPORTED_LISTENER_TRANSPORTS.contains(&transport) {
        return Ok(());
    }
    Err(format!(
        "listener transport {:?} is not implemented (in {}); \
         refusing to start rather than fall back to plaintext TCP",
        transport, node
    )
    .into())
}

fn ensure_chain_transport_supported(node: &Node) -> Result<(), Box<dyn std::error::Error>> {
    let transport = node.transport.as_str();
    // Same reasoning as the listener gate: `ssh` is only a chain transport for
    // gost's direct/remote/forward protocols, not a general tunnel.
    if transport == "ssh" {
        ssh::ssh_chain_support(&node.protocol)?;
        return Ok(());
    }
    if matches!(
        transport,
        "" | "tcp" | "tls" | "ws" | "wss" | "mtls" | "mws" | "mwss" | "quic" | "kcp"
    ) {
        return Ok(());
    }
    Err(format!(
        "chain node transport {:?} is not implemented (in {}); \
         refusing to start rather than dial in cleartext",
        transport, node
    )
    .into())
}

// ---------------------------------------------------------------------------
// Server startup -- maps protocol schemes to handlers
// ---------------------------------------------------------------------------

async fn run_server(
    node: Node,
    chain: Chain,
    cancel: CancellationToken,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Refuse to start rather than quietly downgrading to plaintext TCP: a
    // `-L http+tls://` listener that silently accepts unencrypted traffic is
    // worse than one that fails to start.
    ensure_listener_transport_supported(&node)?;

    let handler_opts = build_handler_options(&node, chain);

    let addr = node.bind_addr();
    let protocol = node.protocol.clone();
    let remote = node.remote.clone();

    info!("{} on {}", node, addr);

    // Helper: create server, wire cancellation, serve
    // Boxes a handler so every arm of the protocol match has one type.
    macro_rules! serve {
        ($handler:expr) => {
            Box::new($handler) as Box<dyn Handler>
        };
        ($handler:expr, $_original_dst:expr) => {
            Box::new($handler) as Box<dyn Handler>
        };
    }

    // Protocol picks the handler; transport picks the listener. Keeping them
    // separate is what lets `-L http+tls://` terminate TLS and then run the
    // ordinary HTTP handler over the decrypted stream.
    let handler: Box<dyn Handler> = match protocol.as_str() {
        // --- Proxy protocols ---
        "http" => serve!(HttpHandler::new(handler_opts)),
        "socks5" | "socks" => serve!(Socks5Handler::new(handler_opts)),
        "socks4" | "socks4a" => serve!(Socks4Handler::new(handler_opts)),
        "ss" => {
            // gost takes the cipher from the userinfo username
            // (`ss://aes-256-gcm:password@host`), not from a query parameter.
            let method = node
                .user
                .as_ref()
                .map(|(m, _)| m.as_str())
                .filter(|m| !m.is_empty())
                .or_else(|| node.get("method"))
                .unwrap_or("plain");
            let password = node
                .user
                .as_ref()
                .and_then(|(_, p)| p.clone())
                .unwrap_or_default();
            serve!(ShadowHandler::new(method, &password, handler_opts)?)
        }
        // Shadowsocks over UDP. `normalize_transport` maps the `ssu` scheme to
        // the `udp` transport, so this is served by the UDP listener below.
        "ssu" => {
            let method = node
                .user
                .as_ref()
                .map(|(m, _)| m.as_str())
                .filter(|m| !m.is_empty())
                .or_else(|| node.get("method"))
                .unwrap_or("plain");
            let password = node
                .user
                .as_ref()
                .and_then(|(_, p)| p.clone())
                .unwrap_or_default();
            serve!(ss::ShadowUdpHandler::new(method, &password, handler_opts)?)
        }
        "http2" => serve!(Http2Handler::new(handler_opts)),
        "relay" => serve!(RelayHandler::new(&remote, handler_opts)),
        "sni" => serve!(SniHandler::new(handler_opts)),
        "tcp" => serve!(TcpDirectForwardHandler::new(&remote, handler_opts)),
        "udp" | "rudp" => serve!(UdpDirectForwardHandler::new(&remote, handler_opts)),
        "rtcp" => serve!(TcpRemoteForwardHandler::new(&remote, handler_opts)),
        "dns" | "dot" | "doh" => serve!(DnsHandler::new(&remote, handler_opts)),
        "red" | "redirect" => serve!(TcpRedirectHandler::new(handler_opts), true),
        "redu" | "redirectu" => serve!(redirect::UdpRedirectHandler::new(handler_opts)),
        "forward" => serve!(SshForwardHandler::new(handler_opts, SshConfig::from_node(&node))?),
        _ => {
            if !remote.is_empty() {
                serve!(TcpDirectForwardHandler::new(&remote, handler_opts))
            } else {
                serve!(handler::AutoHandler::new(handler_opts))
            }
        }
    };

    // Only a transparent proxy needs the pre-NAT destination, and it has to be
    // read from the raw socket before the stream is boxed.
    let capture_original_dst = matches!(protocol.as_str(), "red" | "redirect");

    match node.transport.as_str() {
        // `rudp` and `redu` still ride the TCP listener; they need the UDP
        // remote-forward and tproxy paths, which are not implemented yet.
        //
        // `forward+ssh` is a plain TCP listener in gost too (route.go:458-462):
        // the SSH server handshake happens per connection inside the handler,
        // which is also where authentication is enforced.
        "" | "tcp" | "ssh" | "rtcp" | "rudp" | "dns" | "redu" => {
            let server = Server::new(&addr, handler)
                .await?
                .with_original_dst(capture_original_dst);
            let server_cancel = server.cancel_token();
            let cancel_clone = cancel.clone();
            tokio::spawn(async move {
                cancel_clone.cancelled().await;
                server_cancel.cancel();
            });
            server.serve().await
        }
        "tls" => {
            let config = tls_server_config(&node)?;
            let server = TlsServer::new(&addr, config, handler).await?;
            let server_cancel = server.cancel_token();
            let cancel_clone = cancel.clone();
            tokio::spawn(async move {
                cancel_clone.cancelled().await;
                server_cancel.cancel();
            });
            server.serve().await
        }
        // KCP is a reliable protocol over UDP with smux on top, so like the
        // multiplexed transports one session yields many handler calls.
        "kcp" => {
            let config = kcp::KcpConfig::from_node(&node)?;
            let server = KcpListener::new(&addr, config, handler).await?;
            let server_cancel = server.cancel_token();
            let cancel_clone = cancel.clone();
            tokio::spawn(async move {
                cancel_clone.cancelled().await;
                server_cancel.cancel();
            });
            server.serve().await
        }
        // QUIC carries many bidirectional streams per connection, so like the
        // multiplexed transports one connection yields many handler calls.
        "quic" => {
            let quic = quic_transport::quic_config_from_node(&node)?;
            let server = QuicServer::new(&addr, tls_server_config(&node)?, quic, handler).await?;
            let server_cancel = server.cancel_token();
            let cancel_clone = cancel.clone();
            tokio::spawn(async move {
                cancel_clone.cancelled().await;
                server_cancel.cancel();
            });
            server.serve().await
        }
        // The multiplexed variants: one accepted connection becomes an smux
        // session, and every stream on it is dispatched to the handler.
        "mtls" | "mws" | "mwss" => {
            let mux = mux_transport::mux_config_from_node(&node)
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
            let server = match node.transport.as_str() {
                "mtls" => {
                    MuxServer::new_mtls(&addr, tls_server_config(&node)?, mux, handler).await?
                }
                "mwss" => {
                    MuxServer::new_mwss(
                        &addr,
                        ws_options(&node),
                        tls_server_config(&node)?,
                        mux,
                        handler,
                    )
                    .await?
                }
                _ => MuxServer::new_mws(&addr, ws_options(&node), mux, handler).await?,
            };
            let server_cancel = server.cancel_token();
            let cancel_clone = cancel.clone();
            tokio::spawn(async move {
                cancel_clone.cancelled().await;
                server_cancel.cancel();
            });
            server.serve().await
        }
        "ws" | "wss" => {
            let opts = ws_options(&node);
            let server = if node.transport == "wss" {
                let config = tls_server_config(&node)?;
                WsServer::new_tls(&addr, opts, config, handler).await?
            } else {
                WsServer::new(&addr, opts, handler).await?
            };
            let server_cancel = server.cancel_token();
            let cancel_clone = cancel.clone();
            tokio::spawn(async move {
                cancel_clone.cancelled().await;
                server_cancel.cancel();
            });
            server.serve().await
        }
        // A UDP listener yields one virtual connection per source address, so
        // the ordinary handlers serve it unchanged (gost's udp.go model).
        "udp" => {
            let server = UdpServer::new(&addr, udp_listen_config(&node), handler).await?;
            let server_cancel = server.cancel_token();
            let cancel_clone = cancel.clone();
            tokio::spawn(async move {
                cancel_clone.cancelled().await;
                server_cancel.cancel();
            });
            server.serve().await
        }
        other => Err(format!(
            "listener transport {:?} is not implemented (in {})",
            other, node
        )
        .into()),
    }
}

/// WebSocket options from the node's query parameters.
fn ws_options(node: &Node) -> WsOptions {
    let mut opts = WsOptions::default();
    if let Some(path) = node.get("path").filter(|p| !p.is_empty()) {
        opts.path = path.to_string();
    }
    if let Some(agent) = node.get("agent").filter(|a| !a.is_empty()) {
        opts.user_agent = agent.to_string();
    }
    opts.enable_compression = node.get_bool("compression");
    opts.read_buffer_size = node.get_int("rbuf").max(0) as usize;
    opts.write_buffer_size = node.get_int("wbuf").max(0) as usize;
    let timeout = node.get_duration("timeout");
    if !timeout.is_zero() {
        opts.handshake_timeout = timeout;
    }
    opts
}

/// UDP listener sizing from `?ttl=`, `?backlog=` and `?queue=`. Zero fields
/// fall back to gost's defaults inside the listener.
fn udp_listen_config(node: &Node) -> UdpListenConfig {
    UdpListenConfig {
        ttl: node.get_duration("ttl"),
        backlog: node.get_int("backlog").max(0) as usize,
        queue_size: node.get_int("queue").max(0) as usize,
    }
}

/// Builds the TLS configuration for a `+tls` listener from `?cert=` and
/// `?key=`, falling back to a generated self-signed certificate as gost does
/// when no key pair is configured.
fn tls_server_config(
    node: &Node,
) -> Result<rustls::ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let cert = node.get("cert").unwrap_or("");
    let key = node.get("key").unwrap_or("");

    if !cert.is_empty() && !key.is_empty() {
        return tls_listener::server_config_from_files(cert, key)
            .map_err(|e| format!("failed to load the TLS key pair {} / {}: {}", cert, key, e).into());
    }

    warn!(
        "[tls] no cert/key configured for {}; generating a self-signed certificate",
        node
    );
    let host = node.get("host").filter(|h| !h.is_empty()).unwrap_or("localhost");
    let (config, _cert_pem) = tls_listener::self_signed_config(host)?;
    Ok(config)
}
