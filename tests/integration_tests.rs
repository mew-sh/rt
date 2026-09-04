/// ============================================================================
/// Integration tests for rt
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
use rt::Handler;

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
        let handler = rt::HttpHandler::new(rt::HandlerOptions::default());
        if let Ok((conn, _)) = proxy_listener.accept().await {
            let _ = handler.handle(rt::ProxyConn::from_tcp(conn)).await;
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
    let blacklist = rt::Permissions::parse("tcp:blocked.test:*").unwrap();
    let handler = rt::HttpHandler::new(rt::HandlerOptions {
        blacklist: Some(blacklist),
        ..Default::default()
    });

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((conn, _)) = proxy_listener.accept().await {
            let _ = handler.handle(rt::ProxyConn::from_tcp(conn)).await;
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

    let handler = rt::Socks5Handler::new(rt::HandlerOptions::default());
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((conn, _)) = proxy_listener.accept().await {
            let _ = handler.handle(rt::ProxyConn::from_tcp(conn)).await;
        }
    });

    let connector = rt::Socks5Connector::new(None);
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
    let auth = Arc::new(rt::LocalAuthenticator::new(kvs));

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        // Accept two connections: one success, one failure
        for _ in 0..2 {
            if let Ok((conn, _)) = proxy_listener.accept().await {
                let h = rt::Socks5Handler::new(rt::HandlerOptions {
                    authenticator: Some(auth.clone()),
                    ..Default::default()
                });
                tokio::spawn(async move {
                    let _ = h.handle(rt::ProxyConn::from_tcp(conn)).await;
                });
            }
        }
    });

    // --- Test 1: correct credentials ---
    let connector = rt::Socks5Connector::new(Some(("alice".into(), Some("secret".into()))));
    let stream = TcpStream::connect(proxy_addr).await.unwrap();
    let result = connector.connect(stream, &target_addr.to_string()).await;
    assert!(
        result.is_ok(),
        "Auth with correct credentials should succeed"
    );

    // --- Test 2: wrong credentials ---
    let connector_bad = rt::Socks5Connector::new(Some(("alice".into(), Some("wrong".into()))));
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

    let handler = rt::Socks4Handler::new(rt::HandlerOptions::default());
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((conn, _)) = proxy_listener.accept().await {
            let _ = handler.handle(rt::ProxyConn::from_tcp(conn)).await;
        }
    });

    let connector = rt::Socks4Connector::new();
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

    let handler = rt::Socks4Handler::new(rt::HandlerOptions::default());
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((conn, _)) = proxy_listener.accept().await {
            let _ = handler.handle(rt::ProxyConn::from_tcp(conn)).await;
        }
    });

    let connector = rt::Socks4aConnector::new();
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

    let handler = rt::TcpDirectForwardHandler::new(
        &echo_addr.to_string(),
        rt::HandlerOptions::default(),
    );
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((conn, _)) = proxy_listener.accept().await {
            let _ = handler.handle(rt::ProxyConn::from_tcp(conn)).await;
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

    let handler = rt::TcpRemoteForwardHandler::new(
        &echo_addr.to_string(),
        rt::HandlerOptions::default(),
    );
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((conn, _)) = proxy_listener.accept().await {
            let _ = handler.handle(rt::ProxyConn::from_tcp(conn)).await;
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
        rt::RelayHandler::new(&target_addr.to_string(), rt::HandlerOptions::default());
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((conn, _)) = proxy_listener.accept().await {
            let _ = handler.handle(rt::ProxyConn::from_tcp(conn)).await;
        }
    });

    let connector = rt::RelayConnector::new(None);
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
        rt::ShadowHandler::new("plain", "testpass", rt::HandlerOptions::default()).unwrap();
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((conn, _)) = proxy_listener.accept().await {
            let _ = handler.handle(rt::ProxyConn::from_tcp(conn)).await;
        }
    });

    let connector = rt::ShadowConnector::new("plain", "testpass").unwrap();
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
        let handler = rt::HttpHandler::new(rt::HandlerOptions::default());
        if let Ok((conn, _)) = proxy_listener.accept().await {
            let _ = handler.handle(rt::ProxyConn::from_tcp(conn)).await;
        }
    });

    // Dial through chain
    let node = rt::Node::parse(&format!("http://{}", proxy_addr)).unwrap();
    let chain = rt::Chain::new(vec![node]);

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
        let handler = rt::Socks5Handler::new(rt::HandlerOptions::default());
        if let Ok((conn, _)) = proxy_listener.accept().await {
            let _ = handler.handle(rt::ProxyConn::from_tcp(conn)).await;
        }
    });

    let node = rt::Node::parse(&format!("socks5://{}", proxy_addr)).unwrap();
    let chain = rt::Chain::new(vec![node]);

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

    let handler = rt::handler::AutoHandler::new(rt::HandlerOptions::default());
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((conn, _)) = proxy_listener.accept().await {
            let _ = handler.handle(rt::ProxyConn::from_tcp(conn)).await;
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
    let handler = rt::handler::AutoHandler::new(rt::HandlerOptions::default());
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((conn, _)) = proxy_listener.accept().await {
            let _ = handler.handle(rt::ProxyConn::from_tcp(conn)).await;
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
    let bypass = Arc::new(rt::Bypass::from_patterns(
        false,
        &["10.0.0.0/8", "*.blocked.test"],
    ));
    let handler = rt::Socks5Handler::new(rt::HandlerOptions {
        bypass: Some(bypass),
        ..Default::default()
    });

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((conn, _)) = proxy_listener.accept().await {
            let _ = handler.handle(rt::ProxyConn::from_tcp(conn)).await;
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
        let obfs = rt::obfs::ObfsHttpListener::new();
        let mut conn = obfs.accept_handshake(conn).await.unwrap();
        conn.write_all(b"obfs-http-integration").await.unwrap();
        conn.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    });

    // Client side
    let conn = TcpStream::connect(addr).await.unwrap();
    let obfs = rt::obfs::ObfsHttpTransporter::new();
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
        let obfs = rt::obfs::ObfsTlsListener::new();
        let mut conn = obfs.accept_handshake(conn).await.unwrap();
        conn.write_all(b"obfs-tls-integration").await.unwrap();
        conn.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    });

    let conn = TcpStream::connect(addr).await.unwrap();
    let obfs = rt::obfs::ObfsTlsTransporter::new();
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

    let cfg: rt::config::Config = serde_json::from_str(json).unwrap();
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
    let node = rt::Node::parse(
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
            mut conn: rt::ProxyConn,
        ) -> Result<(), rt::handler::HandlerError> {
            let mut buf = vec![0u8; 1024];
            let n = conn.read(&mut buf).await?;
            conn.write_all(&buf[..n]).await?;
            Ok(())
        }
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = rt::Server::from_listener(listener, CounterHandler);
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
    let (config, _cert_pem) = rt::tls_listener::self_signed_config("localhost").unwrap();

    let (target_addr, _target) = start_message_server(b"tls-tunnel-ok").await;

    let handler = rt::HttpHandler::new(rt::HandlerOptions::default());
    let server = rt::TlsServer::new("127.0.0.1:0", config, handler)
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
    let (config, _) = rt::tls_listener::self_signed_config("localhost").unwrap();

    let handler = rt::HttpHandler::new(rt::HandlerOptions::default());
    let server = rt::TlsServer::new("127.0.0.1:0", config, handler)
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

    let (config, _) = rt::tls_listener::self_signed_config("localhost").unwrap();
    let proxy = rt::TlsServer::new(
        "127.0.0.1:0",
        config,
        rt::HttpHandler::new(rt::HandlerOptions::default()),
    )
    .await
    .unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let cancel = proxy.cancel_token();
    tokio::spawn(async move {
        proxy.serve().await.ok();
    });

    let node = rt::Node::parse(&format!("http+tls://{}", proxy_addr)).unwrap();
    assert_eq!(node.protocol, "http");
    assert_eq!(node.transport, "tls");

    let chain = rt::Chain::new(vec![node]);
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
        let handler = rt::HttpHandler::new(rt::HandlerOptions::default());
        if let Ok((conn, _)) = plain_proxy.accept().await {
            let _ = handler.handle(rt::ProxyConn::from_tcp(conn)).await;
        }
    });

    let node = rt::Node::parse(&format!("http+tls://{}", proxy_addr)).unwrap();
    let chain = rt::Chain::new(vec![node]);

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

#[tokio::test]
async fn integration_chain_through_a_websocket_proxy() {
    // `-F http+ws://proxy/ws`: the hop layers WebSocket, then speaks HTTP
    // CONNECT inside it. In gost `ws` is a transport carrying an inner proxy
    // protocol transparently, not a protocol of its own.
    let (target_addr, _target) = start_message_server(b"chain-over-ws-ok").await;

    let proxy = rt::WsServer::new(
        "127.0.0.1:0",
        rt::WsOptions::default(),
        rt::HttpHandler::new(rt::HandlerOptions::default()),
    )
    .await
    .unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let cancel = proxy.cancel_token();
    tokio::spawn(async move {
        proxy.serve().await.ok();
    });

    let node = rt::Node::parse(&format!("http+ws://{}", proxy_addr)).unwrap();
    assert_eq!(node.transport, "ws");

    let chain = rt::Chain::new(vec![node]);
    let mut conn = chain.dial(&target_addr.to_string()).await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = conn.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"chain-over-ws-ok");

    cancel.cancel();
}

#[tokio::test]
async fn integration_chain_ws_hop_respects_a_custom_path() {
    // gost serves only the configured path and 404s anything else, so a
    // mismatched `?path=` must fail the handshake rather than connect anyway.
    let mut opts = rt::WsOptions::default();
    opts.path = "/tunnel".to_string();

    let proxy = rt::WsServer::new(
        "127.0.0.1:0",
        opts,
        rt::HttpHandler::new(rt::HandlerOptions::default()),
    )
    .await
    .unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let cancel = proxy.cancel_token();
    tokio::spawn(async move {
        proxy.serve().await.ok();
    });

    // The default client path is /ws, which this server does not serve.
    let node = rt::Node::parse(&format!("http+ws://{}", proxy_addr)).unwrap();
    let chain = rt::Chain::new(vec![node]);
    assert!(
        chain.dial("127.0.0.1:1").await.is_err(),
        "a path mismatch must fail the WebSocket handshake"
    );

    cancel.cancel();
}

#[tokio::test]
async fn integration_udp_listener_serves_a_handler_per_peer() {
    // A UDP listener yields one virtual connection per source address, which
    // is what makes `-L udp://` serveable by the ordinary handlers.
    use tokio::net::UdpSocket;

    let listener = rt::UdpListener::bind("127.0.0.1:0", rt::UdpListenConfig::default())
        .await
        .unwrap();
    let server_addr = listener.local_addr();

    let mut listener = listener;
    tokio::spawn(async move {
        while let Some(mut conn) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 1024];
                while let Ok(n) = conn.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    let reply = format!("echo:{}", String::from_utf8_lossy(&buf[..n]));
                    if conn.write_all(reply.as_bytes()).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    // Two distinct client sockets must be served independently.
    for msg in ["one", "two"] {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(msg.as_bytes(), server_addr).await.unwrap();

        let mut buf = vec![0u8; 1024];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
            .await
            .expect("no reply from the UDP listener")
            .unwrap();
        assert_eq!(&buf[..n], format!("echo:{}", msg).as_bytes());
    }
}

#[tokio::test]
async fn integration_chain_through_an_mtls_proxy_reuses_one_session() {
    // `-F http+mtls://proxy:443`: the hop layers TLS, builds an smux session,
    // and opens a stream per dial. The point of the multiplexed variants is
    // that a second dial does NOT open a second TCP connection.
    let (target_addr, _target) = start_message_server(b"mtls-hop-ok").await;
    let (target2_addr, _target2) = start_message_server(b"mtls-hop-ok-2").await;

    let (config, _) = rt::tls_listener::self_signed_config("localhost").unwrap();
    let proxy = rt::MuxServer::new_mtls(
        "127.0.0.1:0",
        config,
        rt::mux::MuxConfig::default(),
        rt::HttpHandler::new(rt::HandlerOptions::default()),
    )
    .await
    .unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let sessions = proxy.session_count();
    let cancel = proxy.cancel_token();
    tokio::spawn(async move {
        proxy.serve().await.ok();
    });

    let node = rt::Node::parse(&format!("http+mtls://{}", proxy_addr)).unwrap();
    assert_eq!(node.transport, "mtls");
    let chain = rt::Chain::new(vec![node]);

    // Two dials through the same chain.
    let mut a = chain.dial(&target_addr.to_string()).await.unwrap();
    let mut b = chain.dial(&target2_addr.to_string()).await.unwrap();

    let mut buf = vec![0u8; 64];
    let n = a.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"mtls-hop-ok");
    let n = b.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"mtls-hop-ok-2");

    assert_eq!(
        sessions.get(),
        1,
        "two dials must share one smux session, not open a connection each"
    );

    cancel.cancel();
}

#[tokio::test]
async fn integration_chain_rejects_a_mux_hop_that_is_not_first() {
    // A mux hop reached through an earlier hop would have to build its session
    // over that hop's connection, which is a session per dial — the thing the
    // multiplexed transports exist to avoid. It must be an explicit error.
    // Hop 1 must genuinely work, otherwise the walk fails before it ever
    // reaches hop 2 and the test would pass for the wrong reason.
    let hop1_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hop1_addr = hop1_listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((conn, _)) = hop1_listener.accept().await {
            let handler = rt::HttpHandler::new(rt::HandlerOptions::default());
            tokio::spawn(async move {
                handler.handle(rt::ProxyConn::from_tcp(conn)).await.ok();
            });
        }
    });

    // Hop 2's address must accept a connection so hop 1's CONNECT succeeds.
    let hop2_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hop2_addr = hop2_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((conn, _)) = hop2_listener.accept().await {
            held.push(conn);
        }
    });

    let first = rt::Node::parse(&format!("http://{}", hop1_addr)).unwrap();
    let second = rt::Node::parse(&format!("http+mtls://{}", hop2_addr)).unwrap();
    let chain = rt::Chain::new(vec![first, second]);

    let err = match chain.dial("example.com:80").await {
        Ok(_) => panic!("a mux hop behind another hop must not succeed"),
        Err(e) => e.to_string(),
    };
    assert!(
        err.contains("only supported on the first hop"),
        "expected a clear limitation error, got: {}",
        err
    );
}

#[tokio::test]
async fn integration_chain_dial_udp_is_direct_without_a_chain() {
    use tokio::net::UdpSocket;

    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1024];
        let (n, from) = echo.recv_from(&mut buf).await.unwrap();
        echo.send_to(&buf[..n], from).await.unwrap();
    });

    let chain = rt::Chain::empty();
    let ch = chain
        .dial_udp("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    assert!(!ch.is_tunnelled(), "an empty chain must dial UDP directly");

    ch.send_to(b"direct", &echo_addr.ip().to_string(), echo_addr.port())
        .await
        .unwrap();
    let (data, _, _) = tokio::time::timeout(Duration::from_secs(5), ch.recv_from())
        .await
        .expect("no reply")
        .unwrap();
    assert_eq!(&data, b"direct");
}

#[tokio::test]
async fn integration_chain_dial_udp_tunnels_through_a_socks5_hop() {
    // `-F socks5://` carrying UDP over the hop's TCP control connection
    // (gost's CmdUDPTun). Without this, UDP leaks around the configured proxy.
    use tokio::net::UdpSocket;

    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1024];
        loop {
            let Ok((n, from)) = echo.recv_from(&mut buf).await else {
                break;
            };
            let mut reply = b"echo:".to_vec();
            reply.extend_from_slice(&buf[..n]);
            if echo.send_to(&reply, from).await.is_err() {
                break;
            }
        }
    });

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((conn, _)) = proxy.accept().await {
            let handler = rt::Socks5Handler::new(rt::HandlerOptions::default());
            tokio::spawn(async move {
                handler.handle(rt::ProxyConn::from_tcp(conn)).await.ok();
            });
        }
    });

    let node = rt::Node::parse(&format!("socks5://{}", proxy_addr)).unwrap();
    let chain = rt::Chain::new(vec![node]);

    let ch = chain
        .dial_udp("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    assert!(ch.is_tunnelled(), "a socks5 hop must tunnel UDP, not bypass it");

    ch.send_to(b"hello", &echo_addr.ip().to_string(), echo_addr.port())
        .await
        .unwrap();

    let (data, _, _) = tokio::time::timeout(Duration::from_secs(10), ch.recv_from())
        .await
        .expect("no reply came back through the tunnel")
        .unwrap();
    assert_eq!(&data, b"echo:hello");
}

#[tokio::test]
async fn integration_chain_dial_udp_refuses_a_hop_that_cannot_carry_udp() {
    // An http hop cannot carry UDP. Falling back to a direct send would route
    // traffic around the proxy the operator configured, so it must fail.
    let node = rt::Node::parse("http://127.0.0.1:1").unwrap();
    let chain = rt::Chain::new(vec![node]);

    let err = match chain.dial_udp("127.0.0.1:0".parse().unwrap()).await {
        Ok(_) => panic!("an http hop must not silently send UDP directly"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("cannot carry UDP"), "got: {}", err);
}

#[tokio::test]
async fn integration_ssu_relays_through_a_socks5_chain() {
    // `-L ssu:// -F socks5://`: the shadowsocks UDP relay must send its
    // datagrams through the configured proxy, not around it.
    use tokio::net::UdpSocket;

    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let Ok((n, from)) = echo.recv_from(&mut buf).await else {
                break;
            };
            let mut reply = b"ss-udp:".to_vec();
            reply.extend_from_slice(&buf[..n]);
            if echo.send_to(&reply, from).await.is_err() {
                break;
            }
        }
    });

    // The SOCKS5 hop that will carry the datagrams over its TCP connection.
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((conn, _)) = proxy.accept().await {
            let handler = rt::Socks5Handler::new(rt::HandlerOptions::default());
            tokio::spawn(async move {
                handler.handle(rt::ProxyConn::from_tcp(conn)).await.ok();
            });
        }
    });

    let hop = rt::Node::parse(&format!("socks5://{}", proxy_addr)).unwrap();
    let chain = rt::Chain::new(vec![hop]);

    let handler = rt::ShadowUdpHandler::new(
        "aes-256-gcm",
        "pw",
        rt::HandlerOptions {
            chain: Some(chain),
            ..Default::default()
        },
    )
    .unwrap();

    let ssu = rt::UdpServer::new(
        "127.0.0.1:0",
        rt::UdpListenConfig::default(),
        handler,
    )
    .await
    .unwrap();
    let ssu_addr = ssu.local_addr();
    let cancel = ssu.cancel_token();
    tokio::spawn(async move {
        ssu.serve().await.ok();
    });

    // A shadowsocks UDP client: salt || AEAD(addr || payload).
    let connector = rt::ShadowUdpConnector::new("aes-256-gcm", "pw").unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let frame = connector
        .encode_to(&echo_addr.to_string(), b"through-the-chain")
        .unwrap();
    client.send_to(&frame, ssu_addr).await.unwrap();

    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(10), client.recv_from(&mut buf))
        .await
        .expect("no reply came back through the ssu chain")
        .unwrap();

    let (origin, payload) = connector.decode_from(&buf[..n]).unwrap();
    assert_eq!(payload, b"ss-udp:through-the-chain");
    assert_eq!(
        origin,
        echo_addr.to_string(),
        "the reply must be attributed to the real target, not the proxy"
    );

    cancel.cancel();
}
