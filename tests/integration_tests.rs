/// ============================================================================
/// Integration tests for rustun
///
/// These tests start real TCP servers and clients to verify end-to-end
/// protocol behavior across all major features.
/// ============================================================================
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// Import the Handler trait so .handle() is available on all handler types.
use rustun::Handler;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Start an echo server that reads data and writes it back.
async fn start_echo_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            if let Ok((mut conn, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    while let Ok(n) = conn.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        if conn.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        }
    });
    (addr, handle)
}

/// Start a server that writes a fixed message and closes.
async fn start_message_server(
    msg: &'static [u8],
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        if let Ok((mut conn, _)) = listener.accept().await {
            conn.write_all(msg).await.ok();
        }
    });
    (addr, handle)
}

// ---------------------------------------------------------------------------
// HTTP Proxy Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn integration_http_proxy_connect_tunnel() {
    let (target_addr, _target) = start_message_server(b"http-tunnel-ok").await;

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        let handler = rustun::HttpHandler::new(rustun::HandlerOptions::default());
        if let Ok((conn, _)) = proxy_listener.accept().await {
            let _ = handler.handle(rustun::ProxyConn::from_tcp(conn)).await;
        }
    });

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let req = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
        target_addr, target_addr
    );
    client.write_all(req.as_bytes()).await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = client.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains("200"), "Expected 200, got: {}", resp);

    let mut data = vec![0u8; 1024];
    let n = client.read(&mut data).await.unwrap();
    assert_eq!(&data[..n], b"http-tunnel-ok");
}

#[tokio::test]
async fn integration_http_proxy_rejects_blacklisted_host() {
    let blacklist = rustun::Permissions::parse("tcp:blocked.test:*").unwrap();
    let handler = rustun::HttpHandler::new(rustun::HandlerOptions {
        blacklist: Some(blacklist),
        ..Default::default()
    });

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((conn, _)) = proxy_listener.accept().await {
            let _ = handler.handle(rustun::ProxyConn::from_tcp(conn)).await;
        }
    });

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
        .write_all(b"CONNECT blocked.test:443 HTTP/1.1\r\nHost: blocked.test\r\n\r\n")
        .await
        .unwrap();

    let mut buf = vec![0u8; 4096];
    let n = client.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains("403"), "Expected 403, got: {}", resp);
}

// ---------------------------------------------------------------------------
// SOCKS5 Proxy Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn integration_socks5_connect_ipv4() {
    let (target_addr, _target) = start_message_server(b"socks5-ipv4-ok").await;

    let handler = rustun::Socks5Handler::new(rustun::HandlerOptions::default());
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((conn, _)) = proxy_listener.accept().await {
            let _ = handler.handle(rustun::ProxyConn::from_tcp(conn)).await;
        }
    });

    let connector = rustun::Socks5Connector::new(None);
    let stream = TcpStream::connect(proxy_addr).await.unwrap();
    let mut conn = connector
        .connect(stream, &target_addr.to_string())
        .await
        .unwrap();

    let mut buf = vec![0u8; 1024];
    let n = conn.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"socks5-ipv4-ok");
}

#[tokio::test]
async fn integration_socks5_auth_success_and_failure() {
    let (target_addr, _target) = start_message_server(b"auth-ok").await;

    let mut kvs = HashMap::new();
    kvs.insert("alice".to_string(), "secret".to_string());
    let auth = Arc::new(rustun::LocalAuthenticator::new(kvs));

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        // Accept two connections: one success, one failure
        for _ in 0..2 {
            if let Ok((conn, _)) = proxy_listener.accept().await {
                let h = rustun::Socks5Handler::new(rustun::HandlerOptions {
                    authenticator: Some(auth.clone()),
                    ..Default::default()
                });
                tokio::spawn(async move {
                    let _ = h.handle(rustun::ProxyConn::from_tcp(conn)).await;
                });
            }
        }
    });

    // --- Test 1: correct credentials ---
    let connector = rustun::Socks5Connector::new(Some(("alice".into(), Some("secret".into()))));
    let stream = TcpStream::connect(proxy_addr).await.unwrap();
    let result = connector.connect(stream, &target_addr.to_string()).await;
    assert!(
        result.is_ok(),
        "Auth with correct credentials should succeed"
    );

    // --- Test 2: wrong credentials ---
    let connector_bad = rustun::Socks5Connector::new(Some(("alice".into(), Some("wrong".into()))));
    let stream2 = TcpStream::connect(proxy_addr).await.unwrap();
    let result2 = connector_bad
        .connect(stream2, &target_addr.to_string())
        .await;
    assert!(result2.is_err(), "Auth with wrong credentials should fail");
}

// ---------------------------------------------------------------------------
// SOCKS4 Proxy Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn integration_socks4_connect() {
    let (target_addr, _target) = start_message_server(b"socks4-ok").await;

    let handler = rustun::Socks4Handler::new(rustun::HandlerOptions::default());
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((conn, _)) = proxy_listener.accept().await {
            let _ = handler.handle(rustun::ProxyConn::from_tcp(conn)).await;
        }
    });

    let connector = rustun::Socks4Connector::new();
    let stream = TcpStream::connect(proxy_addr).await.unwrap();
    let mut conn = connector
        .connect(stream, &target_addr.to_string())
        .await
        .unwrap();

    let mut buf = vec![0u8; 1024];
    let n = conn.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"socks4-ok");
}

#[tokio::test]
async fn integration_socks4a_domain_connect() {
    let (target_addr, _target) = start_message_server(b"socks4a-ok").await;

    let handler = rustun::Socks4Handler::new(rustun::HandlerOptions::default());
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((conn, _)) = proxy_listener.accept().await {
            let _ = handler.handle(rustun::ProxyConn::from_tcp(conn)).await;
        }
    });

    let connector = rustun::Socks4aConnector::new();
    let stream = TcpStream::connect(proxy_addr).await.unwrap();
    // SOCKS4a resolves domain to IP; use 127.0.0.1 as the "domain"
    let mut conn = connector
        .connect(stream, &target_addr.to_string())
        .await
        .unwrap();

    let mut buf = vec![0u8; 1024];
    let n = conn.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"socks4a-ok");
}

// ---------------------------------------------------------------------------
// TCP Forwarding Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn integration_tcp_direct_forward_echo() {
    let (echo_addr, _echo) = start_echo_server().await;

    let handler = rustun::TcpDirectForwardHandler::new(
        &echo_addr.to_string(),
        rustun::HandlerOptions::default(),
    );
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((conn, _)) = proxy_listener.accept().await {
            let _ = handler.handle(rustun::ProxyConn::from_tcp(conn)).await;
        }
    });

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client.write_all(b"forward-echo-test").await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = client.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"forward-echo-test");
}

#[tokio::test]
async fn integration_tcp_remote_forward_echo() {
    let (echo_addr, _echo) = start_echo_server().await;

    let handler = rustun::TcpRemoteForwardHandler::new(
        &echo_addr.to_string(),
        rustun::HandlerOptions::default(),
    );
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((conn, _)) = proxy_listener.accept().await {
            let _ = handler.handle(rustun::ProxyConn::from_tcp(conn)).await;
        }
    });

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client.write_all(b"remote-forward-test").await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = client.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"remote-forward-test");
}

// ---------------------------------------------------------------------------
// Relay Protocol Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn integration_relay_with_target() {
    let (target_addr, _target) = start_message_server(b"relay-target-ok").await;

    let handler =
        rustun::RelayHandler::new(&target_addr.to_string(), rustun::HandlerOptions::default());
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((conn, _)) = proxy_listener.accept().await {
            let _ = handler.handle(rustun::ProxyConn::from_tcp(conn)).await;
        }
    });

    let connector = rustun::RelayConnector::new(None);
    let stream = TcpStream::connect(proxy_addr).await.unwrap();
    let mut conn = connector.connect(stream, "tcp", "").await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = conn.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"relay-target-ok");
}

// ---------------------------------------------------------------------------
// Shadowsocks Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn integration_shadowsocks_plain_cipher() {
    let (target_addr, _target) = start_message_server(b"ss-plain-ok").await;

    let handler =
        rustun::ShadowHandler::new("plain", "testpass", rustun::HandlerOptions::default()).unwrap();
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((conn, _)) = proxy_listener.accept().await {
            let _ = handler.handle(rustun::ProxyConn::from_tcp(conn)).await;
        }
    });

    let connector = rustun::ShadowConnector::new("plain", "testpass").unwrap();
    let stream = TcpStream::connect(proxy_addr).await.unwrap();
    let mut conn = connector
        .connect(stream, &target_addr.to_string())
        .await
        .unwrap();

    let mut buf = vec![0u8; 1024];
    let n = conn.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"ss-plain-ok");
}

// ---------------------------------------------------------------------------
// Proxy Chain Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn integration_chain_through_http_proxy() {
    let (target_addr, _target) = start_message_server(b"chain-http-ok").await;

    // Start HTTP proxy
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        let handler = rustun::HttpHandler::new(rustun::HandlerOptions::default());
        if let Ok((conn, _)) = proxy_listener.accept().await {
            let _ = handler.handle(rustun::ProxyConn::from_tcp(conn)).await;
        }
    });

    // Dial through chain
    let node = rustun::Node::parse(&format!("http://{}", proxy_addr)).unwrap();
    let chain = rustun::Chain::new(vec![node]);

    let mut conn = chain.dial(&target_addr.to_string()).await.unwrap();
    let mut buf = vec![0u8; 1024];
    let n = conn.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"chain-http-ok");
}

#[tokio::test]
async fn integration_chain_through_socks5_proxy() {
    let (target_addr, _target) = start_message_server(b"chain-socks5-ok").await;

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        let handler = rustun::Socks5Handler::new(rustun::HandlerOptions::default());
        if let Ok((conn, _)) = proxy_listener.accept().await {
            let _ = handler.handle(rustun::ProxyConn::from_tcp(conn)).await;
        }
    });

    let node = rustun::Node::parse(&format!("socks5://{}", proxy_addr)).unwrap();
    let chain = rustun::Chain::new(vec![node]);

    let mut conn = chain.dial(&target_addr.to_string()).await.unwrap();
    let mut buf = vec![0u8; 1024];
    let n = conn.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"chain-socks5-ok");
}

// ---------------------------------------------------------------------------
// Auto Handler Detection Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn integration_auto_handler_detects_http() {
    let (target_addr, _target) = start_message_server(b"auto-http-ok").await;

    let handler = rustun::handler::AutoHandler::new(rustun::HandlerOptions::default());
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((conn, _)) = proxy_listener.accept().await {
            let _ = handler.handle(rustun::ProxyConn::from_tcp(conn)).await;
        }
    });

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let req = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
        target_addr, target_addr
    );
    client.write_all(req.as_bytes()).await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = client.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).contains("200"));
}

#[tokio::test]
async fn integration_auto_handler_detects_socks5() {
    let handler = rustun::handler::AutoHandler::new(rustun::HandlerOptions::default());
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((conn, _)) = proxy_listener.accept().await {
            let _ = handler.handle(rustun::ProxyConn::from_tcp(conn)).await;
        }
    });

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    // SOCKS5 greeting: version 5, 1 method, no auth
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();

    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[0], 0x05, "Should respond with SOCKS5 version");
    assert_eq!(resp[1], 0x00, "Should select no-auth method");
}

// ---------------------------------------------------------------------------
// Bypass Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn integration_bypass_blocks_matched_address() {
    let bypass = Arc::new(rustun::Bypass::from_patterns(
        false,
        &["10.0.0.0/8", "*.blocked.test"],
    ));
    let handler = rustun::Socks5Handler::new(rustun::HandlerOptions {
        bypass: Some(bypass),
        ..Default::default()
    });

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((conn, _)) = proxy_listener.accept().await {
            let _ = handler.handle(rustun::ProxyConn::from_tcp(conn)).await;
        }
    });

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    // SOCKS5 greeting
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();

    // Try to CONNECT to a bypassed domain
    let host = b"evil.blocked.test";
    let mut req = vec![0x05, 0x01, 0x00, 0x03];
    req.push(host.len() as u8);
    req.extend_from_slice(host);
    req.extend_from_slice(&443u16.to_be_bytes());
    client.write_all(&req).await.unwrap();

    let mut reply = [0u8; 4];
    if client.read_exact(&mut reply).await.is_ok() {
        // 0x02 = connection not allowed by ruleset
        assert_eq!(reply[1], 0x02, "Bypassed address should be rejected");
    }
}

// ---------------------------------------------------------------------------
// Obfuscation Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn integration_obfs_http_roundtrip() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Server side
    tokio::spawn(async move {
        let (conn, _) = listener.accept().await.unwrap();
        let obfs = rustun::obfs::ObfsHttpListener::new();
        let mut conn = obfs.accept_handshake(conn).await.unwrap();
        conn.write_all(b"obfs-http-integration").await.unwrap();
        conn.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    });

    // Client side
    let conn = TcpStream::connect(addr).await.unwrap();
    let obfs = rustun::obfs::ObfsHttpTransporter::new();
    let mut conn = obfs.handshake(conn, "test.example.com").await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = conn.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"obfs-http-integration");
}

#[tokio::test]
async fn integration_obfs_tls_roundtrip() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (conn, _) = listener.accept().await.unwrap();
        let obfs = rustun::obfs::ObfsTlsListener::new();
        let mut conn = obfs.accept_handshake(conn).await.unwrap();
        conn.write_all(b"obfs-tls-integration").await.unwrap();
        conn.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    });

    let conn = TcpStream::connect(addr).await.unwrap();
    let obfs = rustun::obfs::ObfsTlsTransporter::new();
    let mut conn = obfs.handshake(conn, "secure.example.com").await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = conn.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"obfs-tls-integration");
}

// ---------------------------------------------------------------------------
// Configuration Tests
// ---------------------------------------------------------------------------

#[test]
fn integration_config_parse_full() {
    let json = r#"{
        "Debug": true,
        "ServeNodes": ["http://:8080", "socks5://:1080"],
        "ChainNodes": ["http://upstream:3128"],
        "Retries": 3,
        "Mark": 42,
        "Interface": "eth0",
        "Routes": [
            {
                "ServeNodes": ["relay://:8443"],
                "ChainNodes": [],
                "Retries": 1,
                "Mark": 0,
                "Interface": ""
            }
        ]
    }"#;

    let cfg: rustun::config::Config = serde_json::from_str(json).unwrap();
    assert!(cfg.debug);
    assert_eq!(cfg.default_route.serve_nodes.len(), 2);
    assert_eq!(cfg.default_route.chain_nodes.len(), 1);
    assert_eq!(cfg.default_route.retries, 3);
    assert_eq!(cfg.default_route.mark, 42);
    assert_eq!(cfg.default_route.interface, "eth0");
    assert_eq!(cfg.routes.len(), 1);
    assert_eq!(cfg.routes[0].serve_nodes[0], "relay://:8443");
}

// ---------------------------------------------------------------------------
// Node Parsing Tests
// ---------------------------------------------------------------------------

#[test]
fn integration_node_parse_complex_url() {
    let node = rustun::Node::parse(
        "socks5+tls://admin:p%40ss@proxy.example.com:1443/target:80?timeout=10s&retry=3",
    )
    .unwrap();
    assert_eq!(node.protocol, "socks5");
    assert_eq!(node.transport, "tls");
    assert_eq!(node.addr, "proxy.example.com:1443");
    assert_eq!(node.remote, "target:80");
    assert_eq!(node.user, Some(("admin".into(), Some("p%40ss".into()))));
    assert_eq!(node.get("timeout"), Some("10s"));
    assert_eq!(node.get_int("retry"), 3);
}

// ---------------------------------------------------------------------------
// Server Echo Test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn integration_server_handles_concurrent_connections() {
    struct CounterHandler;

    #[async_trait::async_trait]
    impl Handler for CounterHandler {
        async fn handle(
            &self,
            mut conn: rustun::ProxyConn,
        ) -> Result<(), rustun::handler::HandlerError> {
            let mut buf = vec![0u8; 1024];
            let n = conn.read(&mut buf).await?;
            conn.write_all(&buf[..n]).await?;
            Ok(())
        }
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = rustun::Server::from_listener(listener, CounterHandler);
    let server_handle = tokio::spawn(async move {
        let _ = server.serve().await;
    });

    // Send 10 concurrent connections
    let mut handles = Vec::new();
    for i in 0..10u32 {
        handles.push(tokio::spawn(async move {
            let mut client = TcpStream::connect(addr).await.unwrap();
            let msg = format!("msg-{i}");
            client.write_all(msg.as_bytes()).await.unwrap();
            let mut buf = vec![0u8; 64];
            let n = client.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], msg.as_bytes());
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    server_handle.abort();
}

// ---------------------------------------------------------------------------
// TLS transport
//
// `-L http+tls://` terminates TLS and then runs the ordinary HTTP handler over
// the decrypted stream. Before the connection type was decoupled from
// TcpStream this could not work at all: the listener bound a plain TCP socket
// and served unencrypted traffic while reporting success.
// ---------------------------------------------------------------------------

/// A TLS client built on native-tls, deliberately a different implementation
/// from the rustls listener, so the test proves interoperability rather than
/// self-consistency.
fn tls_client() -> tokio_native_tls::TlsConnector {
    let connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .unwrap();
    tokio_native_tls::TlsConnector::from(connector)
}

#[tokio::test]
async fn integration_tls_listener_terminates_tls_and_runs_the_handler() {
    let (config, _cert_pem) = rustun::tls_listener::self_signed_config("localhost").unwrap();

    let (target_addr, _target) = start_message_server(b"tls-tunnel-ok").await;

    let handler = rustun::HttpHandler::new(rustun::HandlerOptions::default());
    let server = rustun::TlsServer::new("127.0.0.1:0", config, handler)
        .await
        .unwrap();
    let proxy_addr = server.local_addr().unwrap();
    let cancel = server.cancel_token();
    tokio::spawn(async move {
        server.serve().await.ok();
    });

    // A TLS client speaking HTTP CONNECT over the encrypted channel.
    let connector = tls_client();
    let tcp = TcpStream::connect(proxy_addr).await.unwrap();
    let mut tls = connector.connect("localhost", tcp).await.unwrap();

    let req = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
        target_addr, target_addr
    );
    tls.write_all(req.as_bytes()).await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tls.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains("200"), "expected 200 over TLS, got: {}", resp);

    let mut data = vec![0u8; 1024];
    let n = tls.read(&mut data).await.unwrap();
    assert_eq!(&data[..n], b"tls-tunnel-ok");

    cancel.cancel();
}

#[tokio::test]
async fn integration_tls_listener_rejects_a_plaintext_client() {
    let (config, _) = rustun::tls_listener::self_signed_config("localhost").unwrap();

    let handler = rustun::HttpHandler::new(rustun::HandlerOptions::default());
    let server = rustun::TlsServer::new("127.0.0.1:0", config, handler)
        .await
        .unwrap();
    let proxy_addr = server.local_addr().unwrap();
    let cancel = server.cancel_token();
    tokio::spawn(async move {
        server.serve().await.ok();
    });

    // Speaking cleartext to a TLS listener must not be served. This is the
    // regression guard for the old behaviour, where the transport was ignored
    // and a plaintext HTTP request would have been proxied happily.
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf))
        .await
        .expect("TLS listener should not hang on a plaintext client")
        .unwrap_or(0);

    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(
        !resp.contains("200"),
        "a plaintext client must not get a proxied tunnel, got: {:?}",
        resp
    );

    cancel.cancel();
}

#[tokio::test]
async fn integration_chain_through_an_https_proxy() {
    // The full stack: a chain hop that layers TLS and then speaks HTTP CONNECT
    // inside it, i.e. `-F http+tls://proxy:443`. Before the chain returned a
    // transport-agnostic connection this was impossible — it dialled the proxy
    // in cleartext and the TLS handshake never happened.
    let (target_addr, _target) = start_message_server(b"chain-over-tls-ok").await;

    let (config, _) = rustun::tls_listener::self_signed_config("localhost").unwrap();
    let proxy = rustun::TlsServer::new(
        "127.0.0.1:0",
        config,
        rustun::HttpHandler::new(rustun::HandlerOptions::default()),
    )
    .await
    .unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let cancel = proxy.cancel_token();
    tokio::spawn(async move {
        proxy.serve().await.ok();
    });

    let node = rustun::Node::parse(&format!("http+tls://{}", proxy_addr)).unwrap();
    assert_eq!(node.protocol, "http");
    assert_eq!(node.transport, "tls");

    let chain = rustun::Chain::new(vec![node]);
    let mut conn = chain.dial(&target_addr.to_string()).await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = conn.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"chain-over-tls-ok");

    cancel.cancel();
}

#[tokio::test]
async fn integration_chain_tls_hop_fails_against_a_plaintext_proxy() {
    // A `+tls` hop pointed at a cleartext proxy must fail the handshake rather
    // than silently proceed in the clear, which is what the old chain did.
    let plain_proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = plain_proxy.local_addr().unwrap();
    tokio::spawn(async move {
        let handler = rustun::HttpHandler::new(rustun::HandlerOptions::default());
        if let Ok((conn, _)) = plain_proxy.accept().await {
            let _ = handler.handle(rustun::ProxyConn::from_tcp(conn)).await;
        }
    });

    let node = rustun::Node::parse(&format!("http+tls://{}", proxy_addr)).unwrap();
    let chain = rustun::Chain::new(vec![node]);

    let result = tokio::time::timeout(
        Duration::from_secs(10),
        chain.dial("127.0.0.1:1"),
    )
    .await
    .expect("the TLS hop should fail rather than hang");

    assert!(
        result.is_err(),
        "a TLS chain hop must not succeed against a plaintext proxy"
    );
}
