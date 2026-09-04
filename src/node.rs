use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::bypass::Bypass;

#[derive(Debug, thiserror::Error)]
pub enum ParseNodeError {
    #[error("invalid node: empty string")]
    Empty,
    #[error("invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),
    #[error("invalid node: {0}")]
    Invalid(String),
}

/// A proxy node, mainly used to construct a proxy chain.
#[derive(Clone, Debug)]
pub struct Node {
    pub id: usize,
    pub addr: String,
    pub host: String,
    pub protocol: String,
    pub transport: String,
    pub remote: String,
    pub user: Option<(String, Option<String>)>, // (username, optional password)
    pub values: HashMap<String, String>,
    pub marker: Arc<FailMarker>,
    pub bypass: Option<Arc<Bypass>>,
}

impl Default for Node {
    fn default() -> Self {
        Self {
            id: 0,
            addr: String::new(),
            host: String::new(),
            protocol: String::new(),
            transport: String::new(),
            remote: String::new(),
            user: None,
            values: HashMap::new(),
            marker: Arc::new(FailMarker::new()),
            bypass: None,
        }
    }
}

impl Node {
    /// Parses the node info from a URL string.
    /// The pattern is [scheme://][user:pass@host]:port[/remote][?params]
    /// Scheme can be split by '+': http+tls means protocol=http, transport=tls
    pub fn parse(s: &str) -> Result<Self, ParseNodeError> {
        let s = s.trim();
        if s.is_empty() {
            return Err(ParseNodeError::Empty);
        }

        let s = if !s.contains("://") {
            format!("auto://{}", s)
        } else {
            s.to_string()
        };

        // Go's net/url accepts an empty host (`http://:8080`), the `url` crate
        // does not. Substitute a sentinel host so parsing succeeds, then strip
        // it back out so `addr` stays in gost's `:port` form.
        // The sentinel only exists so `Url::parse` accepts the string and we
        // can use it for the scheme, userinfo, path and query; the address
        // itself is read back off the original authority below.
        let (sentinel_url, _hostless) = insert_sentinel_host(&s);
        let u = url::Url::parse(&sentinel_url)?;

        // Take the address straight from the authority rather than rebuilding
        // it from `Url`. `Url::port()` returns None when the port equals the
        // scheme default, so `http://host:80` would otherwise silently lose
        // its port. Go's net/url keeps the authority as written, and gost
        // relies on that.
        let addr = raw_host_port(&s)
            .map(|hp| hp.to_string())
            .unwrap_or_else(|| u.host_str().unwrap_or_default().to_string());

        let host = addr.clone();
        let remote = u.path().trim_matches('/').to_string();

        let user = if !u.username().is_empty() {
            Some((
                u.username().to_string(),
                u.password().map(|p| p.to_string()),
            ))
        } else {
            None
        };

        let values: HashMap<String, String> = u
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();

        let scheme = u.scheme();
        let schemes: Vec<&str> = scheme.split('+').collect();

        let (protocol, transport) = if schemes.len() == 2 {
            (schemes[0].to_string(), schemes[1].to_string())
        } else {
            (schemes[0].to_string(), schemes[0].to_string())
        };

        let transport = normalize_transport(&transport);
        let protocol = normalize_protocol(&protocol);

        Ok(Node {
            id: 0,
            addr,
            host,
            protocol,
            transport,
            remote,
            user,
            values,
            marker: Arc::new(FailMarker::new()),
            bypass: None,
        })
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(|s| s.as_str())
    }

    pub fn get_bool(&self, key: &str) -> bool {
        self.values
            .get(key)
            .and_then(|v| parse_go_bool(v))
            .unwrap_or(false)
    }

    pub fn get_int(&self, key: &str) -> i64 {
        self.values
            .get(key)
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    }

    pub fn get_duration(&self, key: &str) -> Duration {
        match self.values.get(key) {
            // Go's GetDuration falls back to GetInt seconds when the value has
            // no unit suffix, so a bare integer means seconds.
            Some(v) => parse_duration(v).unwrap_or(Duration::ZERO),
            None => Duration::ZERO,
        }
    }

    /// The address to bind or dial, with gost's `:port` shorthand expanded to
    /// an explicit wildcard address that Rust's socket APIs accept.
    pub fn bind_addr(&self) -> String {
        if let Some(port) = self.addr.strip_prefix(':') {
            format!("0.0.0.0:{}", port)
        } else {
            self.addr.clone()
        }
    }

    pub fn mark_dead(&self) {
        self.marker.mark();
    }

    pub fn reset_dead(&self) {
        self.marker.reset();
    }
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.protocol.is_empty() {
            // An empty protocol is gost's `auto` scheme.
            if self.transport.is_empty() || self.transport == "tcp" {
                return write!(f, "auto://{}", self.addr);
            }
            return write!(f, "auto+{}://{}", self.transport, self.addr);
        }
        if self.protocol == self.transport || self.transport == "tcp" || self.transport.is_empty() {
            write!(f, "{}://{}", self.protocol, self.addr)
        } else {
            write!(f, "{}+{}://{}", self.protocol, self.transport, self.addr)
        }
    }
}

fn normalize_transport(t: &str) -> String {
    match t {
        "https" => "tls".to_string(),
        "tls" | "mtls" | "http2" | "h2" | "h2c" | "ws" | "mws" | "wss" | "mwss" | "kcp" | "ssh"
        | "quic" | "ohttp" | "otls" | "obfs4" | "tcp" | "udp" | "rtcp" | "rudp" | "tun" | "tap"
        | "ftcp" | "dns" | "redu" | "redirectu" | "vsock" | "ssu" => {
            if t == "ssu" {
                "udp".to_string()
            } else {
                t.to_string()
            }
        }
        _ => "tcp".to_string(),
    }
}

fn normalize_protocol(p: &str) -> String {
    match p {
        "https" => "http".to_string(),
        "socks" | "socks5" => "socks5".to_string(),
        "ss2" => "ss".to_string(),
        "http" | "http2" | "socks4" | "socks4a" | "ss" | "ssu" | "sni" | "tcp" | "udp" | "rtcp"
        | "rudp" | "direct" | "remote" | "forward" | "red" | "redirect" | "redu" | "redirectu"
        | "tun" | "tap" | "ftcp" | "dns" | "dot" | "doh" | "relay" => p.to_string(),
        "auto" => String::new(),
        _ => String::new(),
    }
}

/// Returns the `host:port` portion of a URL's authority exactly as written,
/// with any userinfo removed. Returns None when there is no `://`.
fn raw_host_port(s: &str) -> Option<&str> {
    let auth_start = s.find("://")? + 3;
    let auth_end = s[auth_start..]
        .find(['/', '?', '#'])
        .map(|i| auth_start + i)
        .unwrap_or(s.len());
    let authority = &s[auth_start..auth_end];
    Some(match authority.rfind('@') {
        Some(i) => &authority[i + 1..],
        None => authority,
    })
}

/// Rewrites a URL whose authority has no host (`http://:8080`, `http://u:p@:80`)
/// so the `url` crate will parse it. Returns the rewritten URL and whether a
/// sentinel was inserted.
fn insert_sentinel_host(s: &str) -> (String, bool) {
    const SENTINEL: &str = "0.0.0.0";

    let Some(scheme_end) = s.find("://") else {
        return (s.to_string(), false);
    };
    let auth_start = scheme_end + 3;

    let auth_end = s[auth_start..]
        .find(['/', '?', '#'])
        .map(|i| auth_start + i)
        .unwrap_or(s.len());
    let authority = &s[auth_start..auth_end];

    // The host starts after the last '@', which separates any userinfo.
    let host_start = match authority.rfind('@') {
        Some(i) => i + 1,
        None => 0,
    };
    let hostport = &authority[host_start..];

    if !hostport.is_empty() && !hostport.starts_with(':') {
        return (s.to_string(), false);
    }

    let mut out = String::with_capacity(s.len() + SENTINEL.len());
    out.push_str(&s[..auth_start + host_start]);
    out.push_str(SENTINEL);
    out.push_str(&s[auth_start + host_start..]);
    (out, true)
}

/// Mirrors Go's `strconv.ParseBool`, which the gost node accessors rely on.
fn parse_go_bool(s: &str) -> Option<bool> {
    match s {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

/// Parses a Go `time.ParseDuration` string. Go accepts a signed decimal with a
/// unit suffix and allows compound forms such as `1h30m` and fractions
/// such as `1.5s`. A bare integer is treated as seconds, matching gost's
/// `Node.GetDuration` fallback.
fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(secs) = s.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }

    let (negative, mut rest) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    if rest == "0" {
        return Some(Duration::ZERO);
    }

    let mut total = Duration::ZERO;
    let mut saw_unit = false;

    while !rest.is_empty() {
        let num_len = rest
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(rest.len());
        if num_len == 0 {
            return None;
        }
        let value: f64 = rest[..num_len].parse().ok()?;
        rest = &rest[num_len..];

        let unit_len = rest
            .find(|c: char| c.is_ascii_digit())
            .unwrap_or(rest.len());
        if unit_len == 0 {
            return None;
        }
        let nanos_per_unit = match &rest[..unit_len] {
            "ns" => 1.0,
            "us" | "µs" | "μs" => 1e3,
            "ms" => 1e6,
            "s" => 1e9,
            "m" => 60e9,
            "h" => 3600e9,
            _ => return None,
        };
        rest = &rest[unit_len..];

        let nanos = value * nanos_per_unit;
        if !nanos.is_finite() || nanos < 0.0 {
            return None;
        }
        total += Duration::from_nanos(nanos as u64);
        saw_unit = true;
    }

    if !saw_unit {
        return None;
    }
    // Go permits negative durations; gost only ever uses them as timeouts, so
    // clamp rather than propagate a value Duration cannot represent.
    Some(if negative { Duration::ZERO } else { total })
}

/// FailMarker tracks connection failure state for a node.
#[derive(Debug)]
pub struct FailMarker {
    fail_time: AtomicI64,
    fail_count: AtomicU32,
}

impl FailMarker {
    pub fn new() -> Self {
        Self {
            fail_time: AtomicI64::new(0),
            fail_count: AtomicU32::new(0),
        }
    }

    pub fn mark(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        self.fail_time.store(now, Ordering::Relaxed);
        self.fail_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn reset(&self) {
        self.fail_time.store(0, Ordering::Relaxed);
        self.fail_count.store(0, Ordering::Relaxed);
    }

    pub fn fail_time(&self) -> i64 {
        self.fail_time.load(Ordering::Relaxed)
    }

    pub fn fail_count(&self) -> u32 {
        self.fail_count.load(Ordering::Relaxed)
    }

    pub fn clone_marker(&self) -> FailMarker {
        FailMarker {
            fail_time: AtomicI64::new(self.fail_time.load(Ordering::Relaxed)),
            fail_count: AtomicU32::new(self.fail_count.load(Ordering::Relaxed)),
        }
    }
}

impl Default for FailMarker {
    fn default() -> Self {
        Self::new()
    }
}

/// NodeGroup is a group of nodes, typically used for load balancing.
#[derive(Clone, Debug)]
pub struct NodeGroup {
    pub id: usize,
    nodes: Arc<RwLock<Vec<Node>>>,
    selector: Option<Arc<dyn NodeSelector + Send + Sync>>,
}

use crate::selector::NodeSelector;

impl NodeGroup {
    pub fn new(nodes: Vec<Node>) -> Self {
        Self {
            id: 0,
            nodes: Arc::new(RwLock::new(nodes)),
            // Installed up front so the round-robin counter lives as long as
            // the group. Building one per call would restart it at zero every
            // time and always hand back the first node.
            selector: Some(Arc::new(crate::selector::DefaultSelector::new())),
        }
    }

    pub fn add_node(&self, node: Node) {
        self.nodes.write().unwrap().push(node);
    }

    pub fn nodes(&self) -> Vec<Node> {
        self.nodes.read().unwrap().clone()
    }

    pub fn get_node(&self, i: usize) -> Option<Node> {
        self.nodes.read().unwrap().get(i).cloned()
    }

    pub fn set_selector(&mut self, selector: Arc<dyn NodeSelector + Send + Sync>) {
        self.selector = Some(selector);
    }

    /// Selects the next node from the group.
    pub fn next(&self) -> Result<Node, crate::selector::SelectError> {
        let nodes = self.nodes.read().unwrap().clone();
        if nodes.is_empty() {
            return Err(crate::selector::SelectError::NoneAvailable);
        }

        match &self.selector {
            Some(selector) => selector.select(&nodes),
            None => Err(crate::selector::SelectError::NoneAvailable),
        }
    }
}

impl Default for NodeGroup {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_node_basic() {
        let node = Node::parse("http://localhost:8080").unwrap();
        assert_eq!(node.addr, "localhost:8080");
        assert_eq!(node.protocol, "http");
        assert_eq!(node.transport, "tcp");
    }

    #[test]
    fn test_parse_node_keeps_scheme_default_port() {
        // The `url` crate drops a port that matches the scheme default, which
        // silently turned `http://host:80` into a portless address.
        assert_eq!(Node::parse("http://1.2.3.4:80").unwrap().addr, "1.2.3.4:80");
        assert_eq!(
            Node::parse("https://1.2.3.4:443").unwrap().addr,
            "1.2.3.4:443"
        );
        assert_eq!(Node::parse("ws://1.2.3.4:80").unwrap().addr, "1.2.3.4:80");
    }

    #[test]
    fn test_parse_node_hostless_listen_address() {
        // gost's canonical `-L :8080` form; Go's net/url accepts an empty host.
        let node = Node::parse(":8080").unwrap();
        assert_eq!(node.addr, ":8080");
        assert_eq!(node.bind_addr(), "0.0.0.0:8080");

        let node = Node::parse("http://:8080").unwrap();
        assert_eq!(node.addr, ":8080");
        assert_eq!(node.protocol, "http");

        // Userinfo must not be mistaken for the host.
        let node = Node::parse("http://user:pass@:8080").unwrap();
        assert_eq!(node.addr, ":8080");
        assert_eq!(node.user, Some(("user".into(), Some("pass".into()))));
    }

    #[test]
    fn test_parse_node_ipv6_keeps_brackets() {
        let node = Node::parse("http://[::1]:8080").unwrap();
        assert_eq!(node.addr, "[::1]:8080");
        assert!(node.addr.parse::<std::net::SocketAddr>().is_ok());
    }

    #[test]
    fn test_get_bool_matches_go_parsebool() {
        let node = Node::parse("http://h:1?a=True&b=T&c=1&d=FALSE&e=yes").unwrap();
        assert!(node.get_bool("a"));
        assert!(node.get_bool("b"));
        assert!(node.get_bool("c"));
        assert!(!node.get_bool("d"));
        // Not a Go bool literal, so it is false rather than an error.
        assert!(!node.get_bool("e"));
        assert!(!node.get_bool("missing"));
    }

    #[test]
    fn test_get_duration_matches_go_syntax() {
        let node = Node::parse("http://h:1?a=1h30m&b=1.5s&c=500ms&d=30&e=100us&f=bogus").unwrap();
        assert_eq!(node.get_duration("a"), Duration::from_secs(5400));
        assert_eq!(node.get_duration("b"), Duration::from_millis(1500));
        assert_eq!(node.get_duration("c"), Duration::from_millis(500));
        // A bare integer means seconds, matching gost's GetDuration fallback.
        assert_eq!(node.get_duration("d"), Duration::from_secs(30));
        assert_eq!(node.get_duration("e"), Duration::from_micros(100));
        assert_eq!(node.get_duration("f"), Duration::ZERO);
    }

    #[test]
    fn test_parse_node_auto() {
        let node = Node::parse("localhost:8080").unwrap();
        assert_eq!(node.addr, "localhost:8080");
        assert_eq!(node.protocol, "");
        assert_eq!(node.transport, "tcp");
    }

    #[test]
    fn test_parse_node_with_auth() {
        let node = Node::parse("socks5://user:pass@localhost:1080").unwrap();
        assert_eq!(node.protocol, "socks5");
        assert_eq!(node.transport, "tcp");
        assert_eq!(node.user, Some(("user".into(), Some("pass".into()))));
    }

    #[test]
    fn test_parse_node_with_transport() {
        let node = Node::parse("http+tls://localhost:443").unwrap();
        assert_eq!(node.protocol, "http");
        assert_eq!(node.transport, "tls");
    }

    #[test]
    fn test_parse_node_socks() {
        let node = Node::parse("socks://localhost:1080").unwrap();
        assert_eq!(node.protocol, "socks5");
    }

    #[test]
    fn test_parse_node_https() {
        let node = Node::parse("https://localhost:443").unwrap();
        assert_eq!(node.protocol, "http");
        assert_eq!(node.transport, "tls");
    }

    #[test]
    fn test_parse_node_with_remote() {
        let node = Node::parse("tcp://localhost:8080/192.168.1.1:80").unwrap();
        assert_eq!(node.remote, "192.168.1.1:80");
    }

    #[test]
    fn test_parse_node_with_params() {
        let node = Node::parse("http://localhost:8080?timeout=5s&retry=3").unwrap();
        assert_eq!(node.get("timeout"), Some("5s"));
        assert_eq!(node.get("retry"), Some("3"));
        assert_eq!(node.get_int("retry"), 3);
    }

    #[test]
    fn test_parse_node_empty() {
        assert!(Node::parse("").is_err());
    }

    #[test]
    fn test_fail_marker() {
        let m = FailMarker::new();
        assert_eq!(m.fail_count(), 0);
        assert_eq!(m.fail_time(), 0);

        m.mark();
        assert_eq!(m.fail_count(), 1);
        assert!(m.fail_time() > 0);

        m.mark();
        assert_eq!(m.fail_count(), 2);

        m.reset();
        assert_eq!(m.fail_count(), 0);
        assert_eq!(m.fail_time(), 0);
    }

    #[test]
    fn test_node_display() {
        let node = Node::parse("http://localhost:8080").unwrap();
        assert_eq!(format!("{}", node), "http://localhost:8080");
    }

    #[test]
    fn test_parse_duration_fn() {
        assert_eq!(parse_duration("5"), Some(Duration::from_secs(5)));
        assert_eq!(parse_duration("5s"), Some(Duration::from_secs(5)));
        assert_eq!(parse_duration("100ms"), Some(Duration::from_millis(100)));
        assert_eq!(parse_duration("2m"), Some(Duration::from_secs(120)));
        assert_eq!(parse_duration("1h"), Some(Duration::from_secs(3600)));
        assert_eq!(parse_duration("invalid"), None);
    }

    #[test]
    fn test_node_group() {
        let n1 = Node::parse("http://localhost:8080").unwrap();
        let n2 = Node::parse("http://localhost:8081").unwrap();
        let group = NodeGroup::new(vec![n1.clone()]);
        group.add_node(n2);

        let nodes = group.nodes();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].addr, "localhost:8080");
        assert_eq!(nodes[1].addr, "localhost:8081");
    }
}
