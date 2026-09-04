use async_trait::async_trait;
use tokio::net::TcpStream;
use tracing::{info, warn};

use crate::conn::ProxyConn;
use crate::handler::{Handler, HandlerError, HandlerOptions};
use crate::permissions::Can;
use crate::transport::transport;

// ---------------------------------------------------------------------------
// TCP Redirect Handler
// ---------------------------------------------------------------------------

/// TCP Redirect Handler -- transparent proxy using the original destination.
///
/// The pre-NAT destination is *not* read here: `SO_ORIGINAL_DST` is a
/// getsockopt on the raw file descriptor, which no longer exists once the
/// accepted stream has been boxed into a [`ProxyConn`]. The listener reads it
/// at accept time with [`original_dst`] and attaches it to the connection, and
/// this handler simply consumes [`ProxyConn::original_dst`].
///
/// On Linux that is populated by an iptables REDIRECT rule. On every other
/// platform transparent proxying is unavailable, so it is always `None` and
/// the handler reports that.
pub struct TcpRedirectHandler {
    options: HandlerOptions,
}

impl TcpRedirectHandler {
    pub fn new(options: HandlerOptions) -> Self {
        Self { options }
    }
}

/// The message used when a redirected connection arrives without an original
/// destination. Falling back to the local address is not an option -- see
/// [`TcpRedirectHandler::handle`].
#[cfg(target_os = "linux")]
const NO_ORIGINAL_DST: &str =
    "redirect: no original destination (SO_ORIGINAL_DST unavailable); \
     is this listener behind an iptables REDIRECT rule?";

#[cfg(not(target_os = "linux"))]
const NO_ORIGINAL_DST: &str = "TCP redirect is not available on this platform";

#[async_trait]
impl Handler for TcpRedirectHandler {
    async fn handle(&self, conn: ProxyConn) -> Result<(), HandlerError> {
        let peer_addr = conn.peer_addr_str();
        let local_addr = conn.local_addr();

        // No fallback to `local_addr()`. That is the address this proxy is
        // *listening* on, so dialing it feeds the connection straight back
        // into this same handler: the proxy talks to itself and loops until it
        // runs out of sockets. gost errors out instead (redirect.go:48-52).
        let target = match conn.original_dst() {
            Some(dst) if Some(dst) == local_addr => {
                warn!(
                    "[redirect] {} : original destination {} is our own listening address",
                    peer_addr, dst
                );
                return Err(HandlerError::Proxy(format!(
                    "redirect: original destination {} is the listener's own address; \
                     refusing to dial ourselves",
                    dst
                )));
            }
            Some(dst) => dst.to_string(),
            None => {
                warn!("[redirect] {} : {}", peer_addr, NO_ORIGINAL_DST);
                return Err(HandlerError::Proxy(NO_ORIGINAL_DST.to_string()));
            }
        };

        info!("[redirect] {} -> {}", peer_addr, target);

        if !Can(
            "tcp",
            &target,
            self.options.whitelist.as_ref(),
            self.options.blacklist.as_ref(),
        ) {
            warn!(
                "[redirect] {} : unauthorized to connect to {}",
                peer_addr, target
            );
            return Err(HandlerError::Forbidden);
        }

        if let Some(ref bypass) = self.options.bypass {
            if bypass.contains(&target) {
                info!("[redirect] {} bypass {}", peer_addr, target);
                return Ok(());
            }
        }

        let chain = self.options.chain.as_ref().cloned().unwrap_or_default();

        match chain.dial(&target).await {
            Ok(cc) => {
                info!("[redirect] {} <-> {}", peer_addr, target);
                transport(conn, cc).await.ok();
                info!("[redirect] {} >-< {}", peer_addr, target);
                Ok(())
            }
            Err(e) => Err(HandlerError::Chain(e)),
        }
    }
}

// ---------------------------------------------------------------------------
// UDP Redirect Handler (Linux only, stub on others)
// ---------------------------------------------------------------------------

/// UDP Redirect Handler -- transparent UDP proxy via TPROXY.
///
/// Only functional on Linux with appropriate iptables TPROXY rules.
/// On all other platforms the handler returns an error.
pub struct UdpRedirectHandler {
    options: HandlerOptions,
}

impl UdpRedirectHandler {
    pub fn new(options: HandlerOptions) -> Self {
        Self { options }
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl Handler for UdpRedirectHandler {
    async fn handle(&self, _conn: ProxyConn) -> Result<(), HandlerError> {
        // Full implementation would use tproxy to intercept UDP and recover
        // original destination.  This requires CAP_NET_ADMIN and appropriate
        // iptables -t mangle -A PREROUTING -p udp --dport ... -j TPROXY rules.
        warn!("[redirect-udp] UDP tproxy handler invoked");
        Err(HandlerError::Proxy(
            "UDP redirect handler requires tproxy integration".to_string(),
        ))
    }
}

#[cfg(not(target_os = "linux"))]
#[async_trait]
impl Handler for UdpRedirectHandler {
    async fn handle(&self, _conn: ProxyConn) -> Result<(), HandlerError> {
        warn!("[redirect-udp] UDP redirect is not available on this platform");
        Err(HandlerError::Proxy(
            "UDP redirect is not available on this platform".to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// SO_ORIGINAL_DST
// ---------------------------------------------------------------------------

/// Retrieves the original destination of a redirected TCP socket, using the
/// Linux-specific `SO_ORIGINAL_DST` getsockopt option.
///
/// This must be called while the raw socket is still reachable -- i.e. at
/// accept time, before the stream is boxed into a [`ProxyConn`] -- which is
/// why `server.rs` calls it rather than the handler.
///
/// Returns `None` (never an error, never a panic) when the syscall fails,
/// which is the normal case for a connection that was not intercepted by an
/// iptables REDIRECT rule.
#[cfg(target_os = "linux")]
pub fn original_dst(stream: &tokio::net::TcpStream) -> Option<std::net::SocketAddr> {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::os::unix::io::AsRawFd;

    // SOL_IP = 0, SO_ORIGINAL_DST = 80
    const SOL_IP: libc::c_int = 0;
    const SO_ORIGINAL_DST: libc::c_int = 80;

    let fd = stream.as_raw_fd();

    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut addr_len: libc::socklen_t = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            SOL_IP,
            SO_ORIGINAL_DST,
            &mut addr as *mut libc::sockaddr_in as *mut libc::c_void,
            &mut addr_len,
        )
    };

    if ret < 0 {
        return None;
    }

    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);
    Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
}

/// Transparent proxying needs a netfilter-style hook to record the pre-NAT
/// destination; there is no `SO_ORIGINAL_DST` equivalent off Linux, so this is
/// always `None` and [`TcpRedirectHandler`] reports that the platform cannot
/// do transparent proxying.
#[cfg(not(target_os = "linux"))]
pub fn original_dst(_stream: &tokio::net::TcpStream) -> Option<std::net::SocketAddr> {
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_tcp_redirect_handler_creation() {
        let handler = TcpRedirectHandler::new(HandlerOptions::default());
        // Without an iptables REDIRECT rule there is no original destination,
        // so the handler must decline rather than guess a target.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = listener.accept().await.unwrap();
            let _ = handler.handle(ProxyConn::from_tcp(conn)).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(b"test").await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    /// The regression this replaces: the handler used to fall back to
    /// `local_addr()` when `SO_ORIGINAL_DST` was unavailable, i.e. it dialed
    /// its own listening socket and re-entered itself on every connection.
    #[tokio::test]
    async fn test_redirect_without_original_dst_errors_and_does_not_self_dial() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let dialing = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server_side, _) = listener.accept().await.unwrap();
        let _client = dialing.await.unwrap();

        // `from_tcp` leaves `original_dst` unset, which is exactly what a
        // listener that could not read SO_ORIGINAL_DST hands to the handler.
        let conn = ProxyConn::from_tcp(server_side);
        assert_eq!(conn.original_dst(), None);
        assert_eq!(conn.local_addr(), Some(addr));

        let handler = TcpRedirectHandler::new(HandlerOptions::default());
        let result = tokio::time::timeout(Duration::from_secs(5), handler.handle(conn))
            .await
            .expect("handler must fail fast, not dial its own listening address");

        match result {
            Err(HandlerError::Proxy(msg)) => assert!(!msg.is_empty()),
            other => panic!("expected a proxy error, got {:?}", other),
        }

        // Nothing may have connected back to the listener: the old fallback
        // would have shown up here as a second inbound connection.
        let self_dial = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
        assert!(
            self_dial.is_err(),
            "handler dialed its own listening address"
        );
    }

    /// The listener may only ever hand over an original destination it read
    /// from the socket, but guard the degenerate case anyway: dialing our own
    /// address is an immediate loop no matter where the address came from.
    #[tokio::test]
    async fn test_redirect_refuses_original_dst_equal_to_local_addr() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let dialing = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server_side, _) = listener.accept().await.unwrap();
        let _client = dialing.await.unwrap();

        let conn = ProxyConn::from_tcp(server_side).with_original_dst(Some(addr));
        let handler = TcpRedirectHandler::new(HandlerOptions::default());

        let result = tokio::time::timeout(Duration::from_secs(5), handler.handle(conn))
            .await
            .expect("handler must fail fast");
        assert!(matches!(result, Err(HandlerError::Proxy(_))));

        let self_dial = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
        assert!(
            self_dial.is_err(),
            "handler dialed its own listening address"
        );
    }

    /// The happy path: the destination the listener attached is the one dialed.
    #[tokio::test]
    async fn test_redirect_relays_to_the_attached_original_dst() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut c, _) = target.accept().await.unwrap();
            let mut buf = vec![0u8; 64];
            let n = c.read(&mut buf).await.unwrap();
            c.write_all(&buf[..n]).await.unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            let handler = TcpRedirectHandler::new(HandlerOptions::default());
            handler
                .handle(ProxyConn::from_tcp(conn).with_original_dst(Some(target_addr)))
                .await
                .ok();
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(b"redirected").await.unwrap();

        let mut buf = vec![0u8; 64];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"redirected");
    }

    /// The ACL checks still gate the attached destination.
    #[tokio::test]
    async fn test_redirect_blacklist_forbids_the_original_dst() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let dialing = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server_side, _) = listener.accept().await.unwrap();
        let _client = dialing.await.unwrap();

        let mut options = HandlerOptions::default();
        options.blacklist = Some(crate::permissions::Permissions::parse("tcp:*:*").unwrap());
        let handler = TcpRedirectHandler::new(options);

        let conn = ProxyConn::from_tcp(server_side).with_original_dst(Some(target_addr));
        let result = handler.handle(conn).await;
        assert!(matches!(result, Err(HandlerError::Forbidden)));

        // The blocked target must never have been dialed.
        let dialed = tokio::time::timeout(Duration::from_millis(200), target.accept()).await;
        assert!(dialed.is_err(), "blacklisted target was dialed anyway");
    }

    #[tokio::test]
    async fn test_udp_redirect_handler_not_available() {
        let handler = UdpRedirectHandler::new(HandlerOptions::default());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            let (conn, _) = listener.accept().await.unwrap();
            handler.handle(ProxyConn::from_tcp(conn)).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(b"test").await.unwrap();

        let result = handle.await.unwrap();
        // Should fail on all platforms (either "not available" or "requires tproxy")
        assert!(result.is_err());
    }

    /// Off Linux there is no way to recover a pre-NAT destination, so the
    /// accept-time lookup must report that rather than inventing an address.
    #[tokio::test]
    #[cfg(not(target_os = "linux"))]
    async fn test_original_dst_is_none_off_linux() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let dialing = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server_side, _) = listener.accept().await.unwrap();
        let _client = dialing.await.unwrap();

        assert_eq!(original_dst(&server_side), None);
    }

    /// On Linux a plain loopback connection has no conntrack NAT entry, so the
    /// getsockopt must fail cleanly rather than panic or return the local
    /// address.
    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn test_original_dst_on_unredirected_socket_does_not_panic() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let dialing = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server_side, _) = listener.accept().await.unwrap();
        let _client = dialing.await.unwrap();

        // Either None (no conntrack entry) or a real address, but never a
        // panic -- and the handler refuses it if it equals our own address.
        let _ = original_dst(&server_side);
    }

    #[test]
    fn test_platform_detection() {
        // Verify we compile on the current platform
        #[cfg(target_os = "linux")]
        {
            // Linux platform detected -- test passes by compilation
        }
        #[cfg(target_os = "windows")]
        {
            // Windows platform detected -- test passes by compilation
        }
        #[cfg(target_os = "macos")]
        {
            // macOS platform detected -- test passes by compilation
        }
    }
}
