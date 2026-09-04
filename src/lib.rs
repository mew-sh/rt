#![allow(
    dead_code,
    unused_imports,
    unused_mut,
    clippy::new_without_default,
    clippy::field_reassign_with_default,
    clippy::manual_flatten,
    clippy::collapsible_if
)]

pub mod auth;
pub mod bypass;
pub mod chain;
pub mod client;
pub mod config;
pub mod conn;
pub mod dns_proxy;
pub mod forward;
pub mod ftcp;
pub mod h2_transport;
pub mod handler;
pub mod hosts;
pub mod http2_transport;
pub mod http_proxy;
pub mod kcp;
pub mod mux;
pub mod mux_transport;
pub mod node;
pub mod obfs;
pub mod obfs_transport;
pub mod permissions;
pub mod quic_transport;
pub mod redirect;
pub mod relay;
pub mod reload;
pub mod remote_forward;
pub mod resolver;
pub mod selector;
pub mod server;
pub mod signal;
pub mod sni;
pub mod sockopts;
pub mod socks4;
pub mod socks5;
pub mod ss;
pub mod ssh;
pub mod tls_listener;
pub mod tls_transport;
pub mod transport;
pub mod tuntap;
pub mod udp;
pub mod vsock_transport;
pub mod ws;

pub use auth::{Authenticator, LocalAuthenticator};
pub use bypass::{Bypass, CidrMatcher, DomainMatcher, IpMatcher, Matcher};
pub use chain::{Chain, ChainOptions};
pub use client::{Client, ConnectOptions, Connector, DialOptions, HandshakeOptions, Transporter};
pub use conn::{AsyncStream, ProxyConn};
pub use dns_proxy::{DnsHandler, DnsUdpProxy};
pub use forward::{TcpDirectForwardHandler, UdpDirectForwardHandler};
pub use ftcp::{FakeTcpListenConfig, FakeTcpListener, FakeTcpTransporter};
pub use h2_transport::{H2Config, H2Handler, H2Stream};
pub use handler::{Handler, HandlerOptions};
pub use hosts::{Host, Hosts};
pub use http2_transport::{http2_connect, Http2Handler};
pub use http_proxy::{HttpConnector, HttpHandler};
pub use kcp::{
    kcp_connect, Crypt, KcpConfig, KcpListener, KcpStream, KcpTransporter, SnappyStream,
};
pub use mux::{MuxFrame, MuxSession};
pub use mux_transport::{
    mux_config_from_node, mux_config_from_values, MuxDialer, MuxDialerPool, MuxHandler, MuxServer,
    MuxStreamConn, SessionCount,
};
pub use node::{Node, NodeGroup, ParseNodeError};
pub use obfs::{Obfs4Transporter, ObfsHttpTransporter, ObfsTlsTransporter};
pub use permissions::{Can, Permissions, PortRange};
pub use quic_transport::{
    alpn_protocols, key_from_cipher, negotiated_alpn, quic_config_from_node, quic_transport_config,
    ConnectionCount, QuicConfig, QuicDialer, QuicListener, QuicServer, QuicStream, QuicTransporter,
    QUIC_ALPN,
};
pub use redirect::TcpRedirectHandler;
pub use relay::{RelayConn, RelayConnector, RelayHandler};
pub use reload::{Reloader, Stoppable};
pub use remote_forward::{TcpRemoteForwardHandler, TcpRemoteForwardListener};
pub use resolver::Resolver;
pub use selector::{FifoStrategy, Filter, NodeSelector, RandomStrategy, RoundStrategy, Strategy};
pub use server::Server;
pub use sni::SniHandler;
pub use socks4::{Socks4Connector, Socks4Handler, Socks4aConnector};
pub use socks5::{Socks5Connector, Socks5Handler, Socks5UdpTunnelConn};
pub use ss::{
    ShadowConnector, ShadowHandler, ShadowUdpConnector, ShadowUdpHandler, SsCipher, SsStream,
};
pub use ssh::{SshConfig, SshForwardHandler, SshTunnelTransporter};
pub use tls_listener::TlsServer;
pub use tuntap::{IpRoute, TapConfig, TapHandler, TunConfig, TunHandler};
pub use udp::{UdpListenConfig, UdpListener, UdpServer, UdpServerConn};
pub use vsock_transport::{VsockAddr, VsockListener, VsockTransporter};
pub use ws::{ws_connect_stream, WsOptions, WsServer, WsStream, DEFAULT_WS_PATH};

pub const VERSION: &str = "2.1.0";
pub const SMALL_BUFFER_SIZE: usize = 2 * 1024;
pub const MEDIUM_BUFFER_SIZE: usize = 8 * 1024;
pub const LARGE_BUFFER_SIZE: usize = 32 * 1024;
pub const KEEP_ALIVE_TIME: u64 = 180;
pub const DIAL_TIMEOUT: u64 = 5;
pub const HANDSHAKE_TIMEOUT: u64 = 5;
pub const CONNECT_TIMEOUT: u64 = 5;
pub const READ_TIMEOUT: u64 = 10;
pub const WRITE_TIMEOUT: u64 = 10;
pub const DEFAULT_USER_AGENT: &str = "Chrome/78.0.3904.106";
pub const DEFAULT_PROXY_AGENT: &str = "rt/2.1.0";
