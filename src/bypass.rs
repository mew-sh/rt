use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::RwLock;
use std::time::Duration;

use crate::auth::{parse_go_duration, split_line_ref};
use crate::permissions::split_host_port;
use crate::reload::{Reloader, Stoppable};

/// Parses a boolean exactly like Go's `strconv.ParseBool`.
///
/// Accepts: 1, t, T, TRUE, true, True, 0, f, F, FALSE, false, False.
/// Everything else is an error.
///
/// The previous `reverse` handling only recognised "true"/"1", so a config line
/// `reverse True` silently yielded `reversed = false` and INVERTED the entire
/// bypass policy (gost: bypass.go:237).
pub fn parse_bool(s: &str) -> Option<bool> {
    match s {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

/// Strips a valid port from `addr`, mirroring gost's `Bypass.Contains`
/// (bypass.go:161-166): it uses `net.SplitHostPort` and only strips when the
/// port parses to a value > 0.
///
/// The old hand-rolled version kept the brackets of an IPv6 literal
/// (`"[::1]:80"` -> `"[::1]"`), which then failed `IpAddr::parse`, so IPv6 and
/// CIDR bypass rules never fired. It also stripped `":0"`, which gost does not.
fn strip_port(addr: &str) -> &str {
    if let Ok((host, port)) = split_host_port(addr) {
        if !host.is_empty() && !port.is_empty() {
            // gost uses strconv.Atoi, which accepts values beyond u16.
            if let Ok(p) = port.parse::<i64>() {
                if p > 0 {
                    return host;
                }
            }
        }
    }
    addr
}

/// Matcher is a generic pattern matcher.
pub trait Matcher: Send + Sync + std::fmt::Debug {
    fn match_value(&self, v: &str) -> bool;
    fn description(&self) -> String;
}

/// Creates a Matcher based on the pattern:
/// - IP address -> IpMatcher
/// - CIDR notation -> CidrMatcher
/// - Otherwise -> DomainMatcher
pub fn new_matcher(pattern: &str) -> Option<Box<dyn Matcher>> {
    if pattern.is_empty() {
        return None;
    }
    if let Ok(ip) = pattern.parse::<IpAddr>() {
        return Some(Box::new(IpMatcher { ip }));
    }
    if let Ok(net) = pattern.parse::<ipnet::IpNet>() {
        return Some(Box::new(CidrMatcher { net }));
    }
    Some(Box::new(DomainMatcher::new(pattern)))
}

/// Matches a specific IP address.
#[derive(Debug)]
pub struct IpMatcher {
    pub ip: IpAddr,
}

impl Matcher for IpMatcher {
    fn match_value(&self, v: &str) -> bool {
        if let Ok(ip) = v.parse::<IpAddr>() {
            self.ip == ip
        } else {
            false
        }
    }

    fn description(&self) -> String {
        format!("ip {}", self.ip)
    }
}

/// Matches a CIDR range.
#[derive(Debug)]
pub struct CidrMatcher {
    pub net: ipnet::IpNet,
}

impl Matcher for CidrMatcher {
    fn match_value(&self, v: &str) -> bool {
        if let Ok(ip) = v.parse::<IpAddr>() {
            self.net.contains(&ip)
        } else {
            false
        }
    }

    fn description(&self) -> String {
        format!("cidr {}", self.net)
    }
}

/// Matches domain patterns with wildcard support.
#[derive(Debug)]
pub struct DomainMatcher {
    pattern: String,
    plain: String, // without leading dot/wildcard prefix
}

impl DomainMatcher {
    pub fn new(pattern: &str) -> Self {
        let (pat, plain) = if let Some(stripped) = pattern.strip_prefix('.') {
            (format!("*.{}", stripped), stripped.to_string())
        } else {
            (pattern.to_string(), pattern.to_string())
        };
        Self {
            pattern: pat,
            plain,
        }
    }
}

impl Matcher for DomainMatcher {
    fn match_value(&self, domain: &str) -> bool {
        if domain == self.plain {
            return true;
        }
        glob_match::glob_match(&self.pattern, domain)
    }

    fn description(&self) -> String {
        format!("domain {}", self.plain)
    }
}

/// Bypass is a filter for addresses (IP or domain).
/// It contains a list of matchers.
#[derive(Debug)]
pub struct Bypass {
    matchers: RwLock<Vec<Box<dyn Matcher>>>,
    reversed: RwLock<bool>,
    /// Reload period parsed from the `reload <duration>` directive
    /// (gost: bypass.go:231-234,259). Zero means "no live reloading".
    period: RwLock<Duration>,
    /// gost signals "stopped" with a closed channel and a negative Period().
    /// `reload::period_reload` cannot express a negative Duration, so the
    /// stopped state lives in this flag and `period()` reports Duration::ZERO
    /// once stopped, which makes `period_reload` return.
    stopped: AtomicBool,
}

impl Bypass {
    pub fn new(reversed: bool, matchers: Vec<Box<dyn Matcher>>) -> Self {
        Self {
            matchers: RwLock::new(matchers),
            reversed: RwLock::new(reversed),
            period: RwLock::new(Duration::ZERO),
            stopped: AtomicBool::new(false),
        }
    }

    pub fn from_patterns(reversed: bool, patterns: &[&str]) -> Self {
        let matchers: Vec<Box<dyn Matcher>> =
            patterns.iter().filter_map(|p| new_matcher(p)).collect();
        Self::new(reversed, matchers)
    }

    /// Checks whether the bypass includes the given address.
    pub fn contains(&self, addr: &str) -> bool {
        if addr.is_empty() {
            return false;
        }

        // Try to strip the port (see strip_port).
        let host = strip_port(addr);

        let matchers = self.matchers.read().unwrap();
        if matchers.is_empty() {
            return false;
        }

        let matched = matchers.iter().any(|m| m.match_value(host));
        let reversed = *self.reversed.read().unwrap();

        (!reversed && matched) || (reversed && !matched)
    }

    pub fn add_matchers(&self, new_matchers: Vec<Box<dyn Matcher>>) {
        self.matchers.write().unwrap().extend(new_matchers);
    }

    pub fn reversed(&self) -> bool {
        *self.reversed.read().unwrap()
    }

    /// Reload from a reader (line-based config).
    pub fn reload(&self, reader: impl std::io::Read) -> std::io::Result<()> {
        self.reload_impl(reader)
    }

    fn reload_impl(&self, reader: impl std::io::Read) -> std::io::Result<()> {
        use std::io::BufRead;

        if self.stopped() {
            return Ok(());
        }

        let buf = std::io::BufReader::new(reader);
        let mut matchers: Vec<Box<dyn Matcher>> = Vec::new();
        let mut reversed = false;
        let mut period = Duration::ZERO;

        for line in buf.lines() {
            let line = line?;
            // gost's bypass reader uses the package-level splitLine, which DOES
            // strip inline '#' comments (gost.go:195-197). That differs on
            // purpose from the auth-file reader; see auth::split_auth_line.
            let parts: Vec<&str> = split_line_ref(&line);
            if parts.is_empty() {
                continue;
            }
            match parts[0] {
                "reload" => {
                    // gost: period, _ = time.ParseDuration(ss[1])
                    if parts.len() > 1 {
                        period = parse_go_duration(parts[1]).unwrap_or(Duration::ZERO);
                    }
                }
                "reverse" => {
                    // gost: reversed, _ = strconv.ParseBool(ss[1])
                    if parts.len() > 1 {
                        reversed = parse_bool(parts[1]).unwrap_or(false);
                    }
                }
                _ => {
                    if let Some(m) = new_matcher(parts[0]) {
                        matchers.push(m);
                    }
                }
            }
        }

        *self.matchers.write().unwrap() = matchers;
        *self.reversed.write().unwrap() = reversed;
        *self.period.write().unwrap() = period;
        Ok(())
    }

    /// Returns the reload period (gost: `Period()`), or `Duration::ZERO` when
    /// stopped.
    pub fn period(&self) -> Duration {
        self.period_impl()
    }

    fn period_impl(&self) -> Duration {
        if self.stopped() {
            return Duration::ZERO;
        }
        *self.period.read().unwrap()
    }

    /// Stops live reloading (gost: `Stop()`).
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
    }

    /// Reports whether live reloading has been stopped (gost: `Stopped()`).
    pub fn stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }
}

impl Reloader for Bypass {
    fn reload(&self, reader: Box<dyn std::io::Read + Send>) -> std::io::Result<()> {
        self.reload_impl(reader)
    }

    fn period(&self) -> Duration {
        self.period_impl()
    }
}

impl Stoppable for Bypass {
    fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
    }

    fn stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }
}

impl Default for Bypass {
    fn default() -> Self {
        Self::new(false, Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_matcher() {
        let m = IpMatcher {
            ip: "192.168.1.1".parse().unwrap(),
        };
        assert!(m.match_value("192.168.1.1"));
        assert!(!m.match_value("192.168.1.2"));
        assert!(!m.match_value("invalid"));
    }

    #[test]
    fn test_cidr_matcher() {
        let m = CidrMatcher {
            net: "192.168.1.0/24".parse().unwrap(),
        };
        assert!(m.match_value("192.168.1.1"));
        assert!(m.match_value("192.168.1.254"));
        assert!(!m.match_value("192.168.2.1"));
    }

    #[test]
    fn test_domain_matcher_exact() {
        let m = DomainMatcher::new("example.com");
        assert!(m.match_value("example.com"));
        assert!(!m.match_value("sub.example.com"));
        assert!(!m.match_value("other.com"));
    }

    #[test]
    fn test_domain_matcher_wildcard() {
        let m = DomainMatcher::new("*.example.com");
        assert!(m.match_value("sub.example.com"));
        assert!(m.match_value("deep.sub.example.com"));
        assert!(!m.match_value("example.com"));
    }

    #[test]
    fn test_domain_matcher_dot_prefix() {
        let m = DomainMatcher::new(".example.com");
        assert!(m.match_value("example.com"));
        assert!(m.match_value("sub.example.com"));
    }

    #[test]
    fn test_new_matcher() {
        assert!(new_matcher("192.168.1.1")
            .unwrap()
            .match_value("192.168.1.1"));
        assert!(new_matcher("192.168.1.0/24")
            .unwrap()
            .match_value("192.168.1.100"));
        assert!(new_matcher("example.com")
            .unwrap()
            .match_value("example.com"));
        assert!(new_matcher("").is_none());
    }

    #[test]
    fn test_bypass_contains() {
        let bp = Bypass::from_patterns(false, &["192.168.1.0/24", "example.com"]);
        assert!(bp.contains("192.168.1.1"));
        assert!(bp.contains("192.168.1.1:8080"));
        assert!(bp.contains("example.com"));
        assert!(bp.contains("example.com:443"));
        assert!(!bp.contains("10.0.0.1"));
        assert!(!bp.contains("other.com"));
        assert!(!bp.contains(""));
    }

    #[test]
    fn test_bypass_reversed() {
        let bp = Bypass::from_patterns(true, &["192.168.1.0/24"]);
        // Reversed: contains returns true for addresses NOT in the list
        assert!(!bp.contains("192.168.1.1"));
        assert!(bp.contains("10.0.0.1"));
    }

    #[test]
    fn test_bypass_empty() {
        let bp = Bypass::new(false, Vec::new());
        assert!(!bp.contains("anything"));
    }

    // -----------------------------------------------------------------------
    // Defect E: IPv6 port stripping
    // -----------------------------------------------------------------------

    #[test]
    fn test_strip_port() {
        assert_eq!(strip_port("192.168.1.1:8080"), "192.168.1.1");
        assert_eq!(strip_port("example.com:443"), "example.com");
        // Brackets must be removed, not retained.
        assert_eq!(strip_port("[::1]:80"), "::1");
        assert_eq!(strip_port("[2001:db8::1]:443"), "2001:db8::1");
        // No port -> unchanged.
        assert_eq!(strip_port("example.com"), "example.com");
        assert_eq!(strip_port("::1"), "::1");
        assert_eq!(strip_port("2001:db8::1"), "2001:db8::1");
        assert_eq!(strip_port("192.168.1.1"), "192.168.1.1");
        // gost only strips when port > 0.
        assert_eq!(strip_port("host:0"), "host:0");
        assert_eq!(strip_port("[::1]:0"), "[::1]:0");
        // Non-numeric "port" -> unchanged.
        assert_eq!(strip_port("host:abc"), "host:abc");
    }

    #[test]
    fn test_bypass_bracketed_ipv6_ip_rule() {
        let bp = Bypass::from_patterns(false, &["::1", "2001:db8::1"]);
        // Previously "[::1]" was passed to IpAddr::parse and never matched.
        assert!(bp.contains("[::1]:80"), "bracketed IPv6 must match ip rule");
        assert!(bp.contains("[::1]:22"));
        assert!(bp.contains("::1"));
        assert!(bp.contains("[2001:db8::1]:443"));
        assert!(!bp.contains("[2001:db8::2]:443"));
    }

    #[test]
    fn test_bypass_bracketed_ipv6_cidr_rule() {
        let bp = Bypass::from_patterns(false, &["2001:db8::/32"]);
        assert!(
            bp.contains("[2001:db8::1]:443"),
            "bracketed IPv6 must match cidr rule"
        );
        assert!(bp.contains("2001:db8::1"));
        assert!(!bp.contains("[2001:db9::1]:443"));
    }

    #[test]
    fn test_bypass_does_not_strip_zero_port() {
        // gost strips the port only when it parses to > 0.
        let bp = Bypass::from_patterns(false, &["example.com"]);
        assert!(bp.contains("example.com:443"));
        assert!(!bp.contains("example.com:0"));
    }

    // -----------------------------------------------------------------------
    // Defect F: strconv.ParseBool for the `reverse` directive
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_bool_matches_go() {
        for s in ["1", "t", "T", "TRUE", "true", "True"] {
            assert_eq!(parse_bool(s), Some(true), "{s} should be true");
        }
        for s in ["0", "f", "F", "FALSE", "false", "False"] {
            assert_eq!(parse_bool(s), Some(false), "{s} should be false");
        }
        for s in ["", "yes", "no", "tRuE", "TrUe", "2", "on"] {
            assert_eq!(parse_bool(s), None, "{s} should be an error");
        }
    }

    #[test]
    fn test_bypass_reload_reverse_true_capitalised() {
        // `reverse True` previously yielded reversed = false, inverting the
        // whole policy.
        for directive in ["reverse True", "reverse TRUE", "reverse t", "reverse T"] {
            let bp = Bypass::default();
            let cfg = format!("{directive}\n192.168.1.0/24\n");
            bp.reload(cfg.as_bytes()).unwrap();
            assert!(bp.reversed(), "`{directive}` must set reversed = true");
            assert!(!bp.contains("192.168.1.1"));
            assert!(bp.contains("10.0.0.1"));
        }
    }

    #[test]
    fn test_bypass_reload_reverse_false_forms() {
        for directive in ["reverse False", "reverse 0", "reverse f", "reverse bogus"] {
            let bp = Bypass::default();
            let cfg = format!("{directive}\n192.168.1.0/24\n");
            bp.reload(cfg.as_bytes()).unwrap();
            assert!(!bp.reversed(), "`{directive}` must set reversed = false");
            assert!(bp.contains("192.168.1.1"));
        }
    }

    #[test]
    fn test_bypass_reload_strips_inline_comments() {
        // gost's bypass reader (splitLine) DOES strip inline '#'.
        let bp = Bypass::default();
        bp.reload(&b"reverse true # invert\n192.168.1.0/24 # lan\n# whole line\n"[..])
            .unwrap();
        assert!(bp.reversed());
        assert!(!bp.contains("192.168.1.1"));
    }

    // -----------------------------------------------------------------------
    // Defect H: the `reload` directive is stored and exposed
    // -----------------------------------------------------------------------

    #[test]
    fn test_bypass_reload_period_is_stored() {
        let bp = Bypass::default();
        assert_eq!(bp.period(), Duration::ZERO);

        bp.reload(&b"reload 30s\n192.168.1.0/24\n"[..]).unwrap();
        assert_eq!(bp.period(), Duration::from_secs(30));
        // The `reload` line must not become a matcher.
        assert!(!bp.contains("reload"));
        assert!(bp.contains("192.168.1.1"));

        bp.reload(&b"reload 2m\n"[..]).unwrap();
        assert_eq!(bp.period(), Duration::from_secs(120));
    }

    #[test]
    fn test_bypass_stop_makes_period_zero_and_reload_noop() {
        let bp = Bypass::default();
        bp.reload(&b"reload 30s\n192.168.1.0/24\n"[..]).unwrap();
        assert!(!bp.stopped());

        bp.stop();
        assert!(bp.stopped());
        assert_eq!(bp.period(), Duration::ZERO);

        bp.reload(&b"10.0.0.0/8\n"[..]).unwrap();
        assert!(bp.contains("192.168.1.1"));
        assert!(!bp.contains("10.0.0.1"));
    }

    #[test]
    fn test_bypass_reloader_trait_impl() {
        let bp = Bypass::default();
        Reloader::reload(&bp, Box::new(&b"reload 15s\nexample.com\n"[..])).unwrap();
        let r: &dyn Reloader = &bp;
        assert_eq!(r.period(), Duration::from_secs(15));
        assert!(bp.contains("example.com:80"));
    }
}
