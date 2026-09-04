use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::conn::ProxyConn;
use crate::handler::{basic_proxy_auth, Handler, HandlerError, HandlerOptions};
use crate::permissions::Can;
use crate::transport::transport;
use crate::{DEFAULT_PROXY_AGENT, DEFAULT_USER_AGENT};

/// HTTP proxy connector (client side).
pub struct HttpConnector {
    pub user: Option<(String, Option<String>)>,
}

impl HttpConnector {
    pub fn new(user: Option<(String, Option<String>)>) -> Self {
        Self { user }
    }

    /// Send HTTP CONNECT to establish tunnel through proxy.
    pub async fn connect(
        &self,
        mut conn: TcpStream,
        address: &str,
    ) -> Result<TcpStream, HandlerError> {
        let mut req = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nProxy-Connection: keep-alive\r\n",
            address, address, DEFAULT_USER_AGENT
        );

        if let Some((ref user, ref pass)) = self.user {
            use base64::Engine;
            let p = pass.as_deref().unwrap_or("");
            let encoded =
                base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", user, p));
            req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", encoded));
        }
        req.push_str("\r\n");

        conn.write_all(req.as_bytes()).await?;

        // Read response
        let mut reader = BufReader::new(&mut conn);
        let mut status_line = String::new();
        reader.read_line(&mut status_line).await?;

        if !status_line.contains("200") {
            return Err(HandlerError::Proxy(format!(
                "HTTP CONNECT failed: {}",
                status_line.trim()
            )));
        }

        // Read headers until empty line
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await?;
            if line.trim().is_empty() {
                break;
            }
        }

        Ok(conn)
    }
}

/// HTTP proxy handler (server side).
pub struct HttpHandler {
    options: HandlerOptions,
}

impl HttpHandler {
    pub fn new(options: HandlerOptions) -> Self {
        Self { options }
    }

    fn proxy_agent(&self) -> &str {
        if self.options.proxy_agent.is_empty() {
            DEFAULT_PROXY_AGENT
        } else {
            &self.options.proxy_agent
        }
    }

    async fn authenticate(&self, user: &str, password: &str) -> bool {
        if let Some(ref auth) = self.options.authenticator {
            auth.authenticate(user, password)
        } else {
            true // No authenticator = allow all
        }
    }

    /// Answers a client that failed authentication.
    ///
    /// With probe resistance configured, and unless the request names the
    /// knocking host, this deliberately does *not* look like a proxy: a bare
    /// 407 with `Proxy-Authenticate` is exactly the fingerprint the feature
    /// exists to hide (gost http.go:366-425).
    async fn deny(
        &self,
        mut conn: ProxyConn,
        host: &str,
        proxy_connection_keep_alive: bool,
        request_head: &str,
        peer_addr: &str,
    ) -> Result<(), HandlerError> {
        let knock_matches = !self.options.knocking_host.is_empty()
            && host
                .split(':')
                .next()
                .unwrap_or(host)
                .eq_ignore_ascii_case(&self.options.knocking_host);

        let resist = if knock_matches {
            None
        } else {
            ProbeResist::parse(&self.options.probe_resist)
        };

        let Some(resist) = resist else {
            // No probe resistance: the ordinary challenge.
            let mut resp = String::from(
                "HTTP/1.1 407 Proxy Authentication Required\r\n\
                 Proxy-Authenticate: Basic realm=\"gost\"\r\n",
            );
            // gost only closes the connection when the client asked to keep it
            // alive, because it cannot serve a second request on the same one.
            if proxy_connection_keep_alive {
                resp.push_str("Connection: close\r\nProxy-Connection: close\r\n");
            }
            resp.push_str("Content-Length: 0\r\n\r\n");
            conn.write_all(resp.as_bytes()).await?;
            return Ok(());
        };

        match resist {
            ProbeResist::Code(code) => {
                conn.write_all(camouflage_headers(code, 0, None).as_bytes())
                    .await?;
            }
            ProbeResist::File(path) => match tokio::fs::read(&path).await {
                Ok(body) => {
                    conn.write_all(
                        camouflage_headers(200, body.len(), Some("text/html")).as_bytes(),
                    )
                    .await?;
                    conn.write_all(&body).await?;
                }
                Err(e) => {
                    debug!("[http] probe_resist file {} unreadable: {}", path, e);
                    conn.write_all(camouflage_headers(503, 0, None).as_bytes())
                        .await?;
                }
            },
            ProbeResist::Web(url) => match fetch_decoy(&url).await {
                Ok(response) => conn.write_all(&response).await?,
                Err(e) => {
                    debug!("[http] probe_resist web {} failed: {}", url, e);
                    conn.write_all(camouflage_headers(503, 0, None).as_bytes())
                        .await?;
                }
            },
            ProbeResist::Host(addr) => match TcpStream::connect(&addr).await {
                Ok(mut decoy) => {
                    // Replay the client's request, then hand the whole
                    // connection over, so the prober talks to a real server.
                    decoy.write_all(request_head.as_bytes()).await?;
                    info!("[http] {} <-> {} : probe_resist forward", peer_addr, addr);
                    transport(conn, decoy).await.ok();
                    return Ok(());
                }
                Err(e) => {
                    debug!("[http] probe_resist host {} unreachable: {}", addr, e);
                    conn.write_all(camouflage_headers(503, 0, None).as_bytes())
                        .await?;
                }
            },
        }

        Ok(())
    }
}

/// Rebuilds the request head so it can be replayed to a decoy server.
fn rebuild_request(method: &str, target: &str, headers: &[String]) -> String {
    let mut out = format!("{} {} HTTP/1.1\r\n", method, origin_form(target));
    for header in headers {
        // The credentials must not reach the decoy.
        if !header.to_lowercase().starts_with("proxy-") {
            out.push_str(header);
            out.push_str("\r\n");
        }
    }
    out.push_str("\r\n");
    out
}

/// Fetches a decoy page and returns the raw response to relay verbatim.
async fn fetch_decoy(url: &str) -> Result<Vec<u8>, HandlerError> {
    let url = if url.starts_with("http") {
        url.to_string()
    } else {
        format!("http://{}", url)
    };
    let parsed = url::Url::parse(&url)
        .map_err(|e| HandlerError::Proxy(format!("invalid probe_resist url: {}", e)))?;
    if parsed.scheme() != "http" {
        // Relaying an HTTPS decoy would need a TLS client here; gost uses
        // http.Get, which follows the scheme. Keep it explicit rather than
        // silently returning the wrong thing.
        return Err(HandlerError::Proxy(
            "probe_resist web: only http:// decoys are supported".into(),
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| HandlerError::Proxy("probe_resist url has no host".into()))?;
    let port = parsed.port().unwrap_or(80);
    let mut path = parsed.path().to_string();
    if let Some(q) = parsed.query() {
        path.push('?');
        path.push_str(q);
    }

    let mut decoy = TcpStream::connect((host, port)).await?;
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nConnection: close\r\n\r\n",
        if path.is_empty() { "/" } else { &path },
        host,
        DEFAULT_USER_AGENT
    );
    decoy.write_all(req.as_bytes()).await?;

    let mut body = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut decoy, &mut body).await?;
    Ok(body)
}

#[async_trait]
impl Handler for HttpHandler {
    async fn handle(&self, mut conn: ProxyConn) -> Result<(), HandlerError> {
        let peer_addr = conn.peer_addr_str();
        let local_addr = conn.local_addr_str();

        // Read the HTTP request
        let mut buf_reader = BufReader::new(&mut conn);
        let mut request_line = String::new();
        buf_reader.read_line(&mut request_line).await?;

        if request_line.is_empty() {
            return Ok(());
        }

        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(HandlerError::Proxy("malformed request".into()));
        }

        let method = parts[0];
        let target = parts[1];
        let _version = parts[2];

        // Read headers
        let mut headers = Vec::new();
        let mut proxy_auth = String::new();
        let mut host_header = String::new();
        loop {
            let mut line = String::new();
            buf_reader.read_line(&mut line).await?;
            if line.trim().is_empty() {
                break;
            }
            let trimmed = line.trim().to_string();
            if trimmed.to_lowercase().starts_with("proxy-authorization:") {
                proxy_auth = trimmed[20..].trim().to_string();
            } else if trimmed.to_lowercase().starts_with("host:") {
                host_header = trimmed[5..].trim().to_string();
            }
            headers.push(trimmed);
        }

        // The BufReader reads ahead, so bytes the client coalesced after the
        // header terminator are sitting in its buffer. Dropping the reader
        // without recovering them loses the request body of a POST/PUT, or the
        // TLS ClientHello a client sent together with its CONNECT.
        let pipelined = buf_reader.buffer().to_vec();
        drop(buf_reader);

        // Determine target host
        let host = if method == "CONNECT" {
            target.to_string()
        } else if let Ok(url) = url::Url::parse(target) {
            let h = url.host_str().unwrap_or(&host_header);
            let port = url.port().unwrap_or(80);
            format!("{}:{}", h, port)
        } else {
            let h = if host_header.is_empty() {
                target.to_string()
            } else {
                host_header.clone()
            };
            if !h.contains(':') {
                format!("{}:80", h)
            } else {
                h
            }
        };

        let (user, _, _) = basic_proxy_auth(&proxy_auth);
        let user_prefix = if !user.is_empty() {
            format!("{}@", user)
        } else {
            String::new()
        };
        info!(
            "[http] {}{} -> {} -> {}",
            user_prefix, peer_addr, local_addr, host
        );

        // Check permissions
        if !Can(
            "tcp",
            &host,
            self.options.whitelist.as_ref(),
            self.options.blacklist.as_ref(),
        ) {
            warn!(
                "[http] {} - {} : Unauthorized to connect to {}",
                peer_addr, local_addr, host
            );
            let resp = format!(
                "HTTP/1.1 403 Forbidden\r\nProxy-Agent: {}\r\n\r\n",
                self.proxy_agent()
            );
            conn.write_all(resp.as_bytes()).await?;
            return Ok(());
        }

        // Check bypass
        if let Some(ref bypass) = self.options.bypass {
            if bypass.contains(&host) {
                let resp = format!(
                    "HTTP/1.1 403 Forbidden\r\nProxy-Agent: {}\r\n\r\n",
                    self.proxy_agent()
                );
                conn.write_all(resp.as_bytes()).await?;
                info!("[http] {} - {} bypass {}", peer_addr, local_addr, host);
                return Ok(());
            }
        }

        // Authenticate
        let (u, p, _) = basic_proxy_auth(&proxy_auth);
        if !self.authenticate(&u, &p).await {
            let keep_alive = headers.iter().any(|h| {
                let l = h.to_lowercase();
                l.starts_with("proxy-connection:") && l.contains("keep-alive")
            });
            let request_head = rebuild_request(method, target, &headers);
            return self
                .deny(conn, &host, keep_alive, &request_head, &peer_addr)
                .await;
        }

        // Connect to target through chain
        let chain = self.options.chain.as_ref().cloned().unwrap_or_default();

        let retries = if self.options.retries > 0 {
            self.options.retries
        } else {
            1
        };

        let mut target_conn = None;
        let mut last_err = None;
        for _ in 0..retries {
            match chain.dial(&host).await {
                Ok(c) => {
                    target_conn = Some(c);
                    break;
                }
                Err(e) => {
                    debug!("[http] {} -> {} : {}", peer_addr, host, e);
                    last_err = Some(e);
                }
            }
        }

        let mut cc = match target_conn {
            Some(c) => c,
            None => {
                let resp = format!(
                    "HTTP/1.1 503 Service Unavailable\r\nProxy-Agent: {}\r\n\r\n",
                    self.proxy_agent()
                );
                conn.write_all(resp.as_bytes()).await?;
                return Err(HandlerError::Proxy(format!(
                    "failed to connect to {}: {:?}",
                    host, last_err
                )));
            }
        };

        if method == "CONNECT" {
            // HTTPS tunnel
            let resp = format!(
                "HTTP/1.1 200 Connection established\r\nProxy-Agent: {}\r\n\r\n",
                self.proxy_agent()
            );
            conn.write_all(resp.as_bytes()).await?;

            // Replay anything the client sent alongside the CONNECT.
            if !pipelined.is_empty() {
                cc.write_all(&pipelined).await?;
            }

            info!("[http] {} <-> {}", peer_addr, host);
            transport(conn, cc).await.ok();
            info!("[http] {} >-< {}", peer_addr, host);
        } else {
            // Forward the request. gost emits origin-form for a direct
            // connection and reserves absolute-form for an upstream proxy
            // (http.go:316 vs :472); some origin servers reject absolute-form.
            let request_target = origin_form(target);
            let mut req = format!("{} {} HTTP/1.1\r\n", method, request_target);
            for header in &headers {
                let lower = header.to_lowercase();
                if !lower.starts_with("proxy-authorization")
                    && !lower.starts_with("proxy-connection")
                {
                    req.push_str(header);
                    req.push_str("\r\n");
                }
            }
            req.push_str("\r\n");

            cc.write_all(req.as_bytes()).await?;
            // The body begins in whatever the header reader buffered.
            if !pipelined.is_empty() {
                cc.write_all(&pipelined).await?;
            }

            info!("[http] {} <-> {}", peer_addr, host);
            transport(conn, cc).await.ok();
            info!("[http] {} >-< {}", peer_addr, host);
        }

        Ok(())
    }
}

/// What to answer an unauthenticated client with instead of a 407, so the
/// listener does not advertise itself as a proxy to a prober.
///
/// gost's `probe_resist` (http.go:366-405).
#[derive(Debug, Clone, PartialEq)]
pub enum ProbeResist {
    /// Reply with a bare status code.
    Code(u16),
    /// Fetch a decoy site and relay its response.
    Web(String),
    /// Hand the whole connection to a decoy server.
    Host(String),
    /// Serve a decoy file as text/html.
    File(String),
}

impl ProbeResist {
    /// Parses gost's `<mode>:<value>` form. Anything else disables it, which is
    /// also what gost does — it only acts when the value splits into two parts.
    pub fn parse(spec: &str) -> Option<Self> {
        let (mode, value) = spec.split_once(':')?;
        if value.is_empty() {
            return None;
        }
        match mode {
            "code" => value.parse().ok().map(ProbeResist::Code),
            "web" => Some(ProbeResist::Web(value.to_string())),
            "host" => Some(ProbeResist::Host(value.to_string())),
            "file" => Some(ProbeResist::File(value.to_string())),
            _ => None,
        }
    }
}

/// Formats a UNIX timestamp as an RFC 7231 HTTP date, so the camouflage
/// response carries a plausible `Date` header.
pub fn http_date(unix_secs: u64) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let days = (unix_secs / 86_400) as i64;
    let secs_of_day = unix_secs % 86_400;
    // 1970-01-01 was a Thursday.
    let weekday = ((days + 4).rem_euclid(7)) as usize;

    // Civil-from-days, shifting the epoch to 0000-03-01 so leap days land at
    // the end of the cycle.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        DAYS[weekday],
        d,
        MONTHS[(m - 1) as usize],
        y,
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        503 => "Service Unavailable",
        _ => "OK",
    }
}

/// Builds the camouflage response headers gost sends when probe resistance
/// fires: an nginx `Server` banner and a current `Date`, with the
/// `Proxy-Authenticate` header deliberately absent (http.go:418-425).
fn camouflage_headers(code: u16, body_len: usize, content_type: Option<&str>) -> String {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nServer: nginx/1.14.1\r\nDate: {}\r\n",
        code,
        status_text(code),
        http_date(now_unix())
    );
    if let Some(ct) = content_type {
        head.push_str(&format!("Content-Type: {}\r\n", ct));
    }
    head.push_str(&format!("Content-Length: {}\r\n", body_len));
    if code == 200 {
        head.push_str("Connection: keep-alive\r\n");
    }
    head.push_str("\r\n");
    head
}

/// Converts an absolute-form request target (`http://host/path?q`) into the
/// origin form (`/path?q`) an origin server expects. Anything that is not an
/// absolute URL is passed through unchanged.
fn origin_form(target: &str) -> String {
    match url::Url::parse(target) {
        Ok(url) if url.has_host() => {
            let mut out = url.path().to_string();
            if out.is_empty() {
                out.push('/');
            }
            if let Some(q) = url.query() {
                out.push('?');
                out.push_str(q);
            }
            out
        }
        _ => target.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_http_handler_connect() {
        // Start a mock target server
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            conn.write_all(b"hello from target").await.unwrap();
        });

        // Start HTTP proxy
        let handler = HttpHandler::new(HandlerOptions::default());
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(ProxyConn::from_tcp(conn)).await.ok();
        });

        // Connect to proxy and issue CONNECT
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let req = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
            target_addr, target_addr
        );
        client.write_all(req.as_bytes()).await.unwrap();

        // Read response
        let mut buf = vec![0u8; 4096];
        let n = client.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("200"));

        // Read data from target
        let mut data_buf = vec![0u8; 4096];
        let n = client.read(&mut data_buf).await.unwrap();
        assert_eq!(&data_buf[..n], b"hello from target");
    }

    #[tokio::test]
    async fn test_http_handler_auth_required() {
        use std::collections::HashMap;
        use std::sync::Arc;

        let mut kvs = HashMap::new();
        kvs.insert("admin".into(), "secret".into());
        let auth = Arc::new(crate::auth::LocalAuthenticator::new(kvs));

        let handler = HttpHandler::new(HandlerOptions {
            authenticator: Some(auth),
            ..Default::default()
        });

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(ProxyConn::from_tcp(conn)).await.ok();
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        client.write_all(req.as_bytes()).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = client.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("407"));
    }

    #[tokio::test]
    async fn test_http_handler_bypass() {
        use std::sync::Arc;

        let bypass = Arc::new(crate::bypass::Bypass::from_patterns(
            false,
            &["blocked.com"],
        ));
        let handler = HttpHandler::new(HandlerOptions {
            bypass: Some(bypass),
            ..Default::default()
        });

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(ProxyConn::from_tcp(conn)).await.ok();
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let req = "CONNECT blocked.com:443 HTTP/1.1\r\nHost: blocked.com\r\n\r\n";
        client.write_all(req.as_bytes()).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = client.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("403"));
    }

    #[tokio::test]
    async fn test_http_handler_blacklist() {
        let blacklist = crate::permissions::Permissions::parse("tcp:evil.com:*").unwrap();
        let handler = HttpHandler::new(HandlerOptions {
            blacklist: Some(blacklist),
            ..Default::default()
        });

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(ProxyConn::from_tcp(conn)).await.ok();
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let req = "CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com\r\n\r\n";
        client.write_all(req.as_bytes()).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = client.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("403"));
    }

    #[tokio::test]
    async fn test_http_handler_auth_success() {
        use std::collections::HashMap;
        use std::sync::Arc;

        let mut kvs = HashMap::new();
        kvs.insert("admin".into(), "secret".into());
        let auth = Arc::new(crate::auth::LocalAuthenticator::new(kvs));

        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            conn.write_all(b"authenticated-ok").await.unwrap();
        });

        let handler = HttpHandler::new(HandlerOptions {
            authenticator: Some(auth),
            ..Default::default()
        });

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(ProxyConn::from_tcp(conn)).await.ok();
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        use base64::Engine;
        let creds = base64::engine::general_purpose::STANDARD.encode("admin:secret");
        let req = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Authorization: Basic {}\r\n\r\n",
            target_addr, target_addr, creds
        );
        client.write_all(req.as_bytes()).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = client.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("200"));

        let mut data = vec![0u8; 1024];
        let n = client.read(&mut data).await.unwrap();
        assert_eq!(&data[..n], b"authenticated-ok");
    }

    #[tokio::test]
    async fn test_http_handler_malformed_request() {
        let handler = HttpHandler::new(HandlerOptions::default());
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            // Malformed request should not panic
            handler.handle(ProxyConn::from_tcp(conn)).await.ok();
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(b"GARBAGE\r\n\r\n").await.unwrap();
        // Just verify it doesn't hang or panic
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    fn auth_opts(probe_resist: &str, knock: &str) -> HandlerOptions {
        let mut kvs = std::collections::HashMap::new();
        kvs.insert("u".to_string(), "p".to_string());
        HandlerOptions {
            authenticator: Some(std::sync::Arc::new(crate::auth::LocalAuthenticator::new(
                kvs,
            ))),
            probe_resist: probe_resist.to_string(),
            knocking_host: knock.to_string(),
            ..Default::default()
        }
    }

    /// Sends an unauthenticated CONNECT and returns the raw reply.
    async fn probe(options: HandlerOptions, host: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handler = HttpHandler::new(options);
        tokio::spawn(async move {
            let (conn, _) = listener.accept().await.unwrap();
            handler.handle(ProxyConn::from_tcp(conn)).await.ok();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "CONNECT {} HTTP/1.1
Host: {}

",
            host, host
        );
        client.write_all(req.as_bytes()).await.unwrap();

        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut client, &mut buf)
            .await
            .ok();
        String::from_utf8_lossy(&buf).to_string()
    }

    #[test]
    fn test_probe_resist_parse() {
        assert_eq!(ProbeResist::parse("code:404"), Some(ProbeResist::Code(404)));
        assert_eq!(
            ProbeResist::parse("file:/tmp/x.html"),
            Some(ProbeResist::File("/tmp/x.html".into()))
        );
        assert_eq!(
            ProbeResist::parse("host:1.2.3.4:80"),
            Some(ProbeResist::Host("1.2.3.4:80".into()))
        );
        // gost only acts when the value splits in two; anything else is off.
        assert_eq!(ProbeResist::parse("code"), None);
        assert_eq!(ProbeResist::parse(""), None);
        assert_eq!(ProbeResist::parse("bogus:x"), None);
        assert_eq!(ProbeResist::parse("code:notanumber"), None);
    }

    #[test]
    fn test_http_date_format() {
        // A known epoch second, so the civil-date arithmetic is pinned.
        assert_eq!(http_date(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
    }

    #[tokio::test]
    async fn test_without_probe_resist_a_failed_auth_still_challenges() {
        let resp = probe(auth_opts("", ""), "example.com:443").await;
        assert!(resp.starts_with("HTTP/1.1 407"), "got: {:?}", resp);
        assert!(resp.contains("Proxy-Authenticate"));
    }

    #[tokio::test]
    async fn test_probe_resist_code_hides_the_proxy() {
        let resp = probe(auth_opts("code:404", ""), "example.com:443").await;
        assert!(resp.starts_with("HTTP/1.1 404"), "got: {:?}", resp);
        // The whole point: nothing may identify this as a proxy.
        assert!(
            !resp.contains("Proxy-Authenticate") && !resp.contains("407"),
            "probe resistance must not leak the proxy challenge: {:?}",
            resp
        );
        assert!(resp.contains("Server: nginx/1.14.1"));
        assert!(resp.contains("Date: "));
    }

    #[tokio::test]
    async fn test_probe_resist_file_serves_a_decoy_page() {
        let dir = std::env::temp_dir();
        let path = dir.join("rt_probe_resist_decoy.html");
        tokio::fs::write(&path, b"<html>decoy</html>")
            .await
            .unwrap();

        let spec = format!("file:{}", path.display());
        let resp = probe(auth_opts(&spec, ""), "example.com:443").await;

        assert!(resp.starts_with("HTTP/1.1 200"), "got: {:?}", resp);
        assert!(resp.contains("Content-Type: text/html"));
        assert!(resp.contains("<html>decoy</html>"));
        assert!(!resp.contains("Proxy-Authenticate"));

        tokio::fs::remove_file(&path).await.ok();
    }

    #[tokio::test]
    async fn test_probe_resist_missing_file_falls_back_to_503() {
        let resp = probe(auth_opts("file:/no/such/decoy.html", ""), "example.com:443").await;
        assert!(resp.starts_with("HTTP/1.1 503"), "got: {:?}", resp);
        assert!(!resp.contains("Proxy-Authenticate"));
    }

    #[tokio::test]
    async fn test_knocking_host_bypasses_probe_resistance() {
        // An operator naming the knock host must still get the real 407.
        let resp = probe(
            auth_opts("code:404", "secret.example"),
            "secret.example:443",
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 407"), "got: {:?}", resp);
        assert!(resp.contains("Proxy-Authenticate"));
    }

    #[tokio::test]
    async fn test_probe_resist_web_relays_a_decoy_page() {
        // A minimal origin server standing in for the decoy site.
        let site = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let site_addr = site.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut c, _) = site.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = c.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            assert!(
                req.starts_with("GET /"),
                "decoy fetch should be a GET: {:?}",
                req
            );
            c.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\n<h1>decoy</h1>",
            )
            .await
            .unwrap();
        });

        let spec = format!("web:{}", site_addr);
        let resp = probe(auth_opts(&spec, ""), "example.com:443").await;

        assert!(resp.contains("<h1>decoy</h1>"), "got: {:?}", resp);
        assert!(!resp.contains("Proxy-Authenticate"));
        assert!(!resp.contains("407"));
    }

    #[tokio::test]
    async fn test_probe_resist_web_rejects_an_https_decoy() {
        // Relaying an https:// decoy would need a TLS client on this path.
        // It must be an explicit failure, not a wrong-looking success.
        assert!(fetch_decoy("https://example.com").await.is_err());
    }

    #[tokio::test]
    async fn test_probe_resist_unreachable_web_falls_back_to_503() {
        // 127.0.0.1:1 is closed, so the fetch fails.
        let resp = probe(auth_opts("web:127.0.0.1:1", ""), "example.com:443").await;
        assert!(resp.starts_with("HTTP/1.1 503"), "got: {:?}", resp);
        assert!(!resp.contains("Proxy-Authenticate"));
    }

    #[tokio::test]
    async fn test_probe_resist_host_forwards_to_a_decoy_server() {
        let decoy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let decoy_addr = decoy.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut c, _) = decoy.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = c.read(&mut buf).await.unwrap();
            // The proxy credentials must not be replayed to the decoy.
            assert!(!String::from_utf8_lossy(&buf[..n]).contains("Proxy-"));
            c.write_all(
                b"HTTP/1.1 200 OK
Content-Length: 5

hello",
            )
            .await
            .unwrap();
        });

        let spec = format!("host:{}", decoy_addr);
        let resp = probe(auth_opts(&spec, ""), "example.com:443").await;
        assert!(resp.contains("hello"), "got: {:?}", resp);
        assert!(!resp.contains("Proxy-Authenticate"));
    }

    #[test]
    fn test_origin_form() {
        assert_eq!(origin_form("http://example.com/a/b?x=1"), "/a/b?x=1");
        assert_eq!(origin_form("http://example.com"), "/");
        // Already origin-form, or not a URL at all: pass through untouched.
        assert_eq!(origin_form("/already/origin"), "/already/origin");
        assert_eq!(origin_form("example.com:443"), "example.com:443");
    }

    /// A POST whose body arrives in the same TCP segment as its headers must
    /// reach the origin server. The header reader buffers ahead, so those
    /// bytes were previously dropped along with the reader.
    #[tokio::test]
    async fn test_forward_mode_preserves_coalesced_request_body() {
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();

        let received = tokio::spawn(async move {
            let (mut conn, _) = origin.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let mut total = Vec::new();
            // Read until we have the terminator plus the body.
            while !total.windows(9).any(|w| w == b"BODY-HERE") {
                let n = conn.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                total.extend_from_slice(&buf[..n]);
            }
            String::from_utf8_lossy(&total).to_string()
        });

        let handler = HttpHandler::new(HandlerOptions::default());
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(ProxyConn::from_tcp(conn)).await.ok();
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        // Headers and body written together, as a client sending a small body does.
        let req = format!(
            "POST http://{}/submit HTTP/1.1\r\nHost: {}\r\nContent-Length: 9\r\n\r\nBODY-HERE",
            origin_addr, origin_addr
        );
        client.write_all(req.as_bytes()).await.unwrap();

        let got = tokio::time::timeout(std::time::Duration::from_secs(5), received)
            .await
            .expect("origin server did not receive the body")
            .unwrap();

        assert!(
            got.contains("BODY-HERE"),
            "request body was dropped: {:?}",
            got
        );
        assert!(
            got.starts_with("POST /submit HTTP/1.1"),
            "expected origin-form request line, got: {:?}",
            got.lines().next()
        );
    }
}
