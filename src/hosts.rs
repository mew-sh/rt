//! Static hostname table, ported from gost's `hosts.go`.

use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tracing::debug;

use crate::auth::{parse_go_duration, split_line_ref};
use crate::reload::{Reloader, Stoppable};

/// Host is a static mapping from hostname to IP.
#[derive(Clone, Debug)]
pub struct Host {
    pub ip: IpAddr,
    pub hostname: String,
    pub aliases: Vec<String>,
}

impl Host {
    pub fn new(ip: IpAddr, hostname: &str, aliases: Vec<String>) -> Self {
        Self {
            ip,
            hostname: hostname.to_string(),
            aliases,
        }
    }
}

#[derive(Debug, Default)]
struct Inner {
    hosts: RwLock<Vec<Host>>,
    /// Reload period parsed from the `reload <duration>` directive
    /// (gost: hosts.go:102-103, 124, 132-141). Zero means "no live reloading".
    period: RwLock<Duration>,
    /// gost signals "stopped" by closing a channel and returning a negative
    /// `Period()`. `reload::period_reload` cannot express a negative
    /// `Duration`, so the stopped state lives in this flag and `period()`
    /// reports `Duration::ZERO` once stopped, which makes `period_reload`
    /// return. Same convention as `Bypass`, `LocalAuthenticator` and
    /// `Resolver`.
    stopped: AtomicBool,
}

/// Hosts is a static table lookup for hostnames.
///
/// For each host a single line should be present with the following
/// information: `IP_address canonical_hostname [aliases...]`. Fields are
/// separated by blanks and/or tabs; text from a `#` to end of line is a
/// comment.
///
/// Cloning shares the underlying table (gost passes a `*Hosts` pointer
/// everywhere). This matters: `Chain::default_options` clones the `Hosts` on
/// every dial, and a live reload must be visible through those clones -- a
/// deep copy would freeze the table at the moment the chain was built.
#[derive(Debug, Clone, Default)]
pub struct Hosts {
    inner: Arc<Inner>,
}

impl Hosts {
    pub fn new(hosts: Vec<Host>) -> Self {
        Self {
            inner: Arc::new(Inner {
                hosts: RwLock::new(hosts),
                period: RwLock::new(Duration::ZERO),
                stopped: AtomicBool::new(false),
            }),
        }
    }

    pub fn add_host(&self, host: Host) {
        self.inner.hosts.write().unwrap().push(host);
    }

    pub fn add_hosts(&self, hosts: Vec<Host>) {
        self.inner.hosts.write().unwrap().extend(hosts);
    }

    /// A snapshot of the table.
    pub fn hosts(&self) -> Vec<Host> {
        self.inner.hosts.read().unwrap().clone()
    }

    pub fn len(&self) -> usize {
        self.inner.hosts.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.hosts.read().unwrap().is_empty()
    }

    /// Lookup searches for the IP address corresponding to the given host.
    ///
    /// gost v2's `Hosts.Lookup` is EXACT match only (hosts.go:66-77) -- there
    /// is deliberately no wildcard/suffix matching here.
    pub fn lookup(&self, host: &str) -> Option<IpAddr> {
        if host.is_empty() {
            return None;
        }
        let hosts = self.inner.hosts.read().unwrap();
        for h in hosts.iter() {
            if h.hostname == host {
                debug!("[hosts] hit: {} {}", host, h.ip);
                return Some(h.ip);
            }
            for alias in &h.aliases {
                if alias == host {
                    debug!("[hosts] hit: {} {}", host, h.ip);
                    return Some(h.ip);
                }
            }
        }
        None
    }

    /// Reload parses config from reader, then live reloads the hosts.
    /// gost: `Hosts.Reload` (hosts.go:85-129).
    pub fn reload(&self, reader: impl io::Read) -> io::Result<()> {
        self.reload_impl(reader)
    }

    fn reload_impl(&self, reader: impl io::Read) -> io::Result<()> {
        use io::BufRead;

        if self.stopped() {
            return Ok(());
        }

        let buf = io::BufReader::new(reader);
        let mut hosts = Vec::new();
        let mut period = Duration::ZERO;

        for line in buf.lines() {
            let line = line?;
            let parts = split_line_ref(&line);
            // gost: invalid lines (fewer than 2 fields) are ignored.
            if parts.len() < 2 {
                continue;
            }
            match parts[0] {
                "reload" => {
                    period = parse_go_duration(parts[1]).unwrap_or(Duration::ZERO);
                }
                _ => {
                    // Invalid IP addresses are ignored.
                    if let Ok(ip) = parts[0].parse::<IpAddr>() {
                        hosts.push(Host {
                            ip,
                            hostname: parts[1].to_string(),
                            aliases: parts[2..].iter().map(|s| s.to_string()).collect(),
                        });
                    }
                }
            }
        }

        *self.inner.hosts.write().unwrap() = hosts;
        *self.inner.period.write().unwrap() = period;
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
        *self.inner.period.read().unwrap()
    }

    /// Stops live reloading (gost: `Stop()`).
    pub fn stop(&self) {
        self.inner.stopped.store(true, Ordering::SeqCst);
    }

    /// Reports whether live reloading has been stopped (gost: `Stopped()`).
    pub fn stopped(&self) -> bool {
        self.inner.stopped.load(Ordering::SeqCst)
    }
}

impl Reloader for Hosts {
    fn reload(&self, reader: Box<dyn io::Read + Send>) -> io::Result<()> {
        self.reload_impl(reader)
    }

    fn period(&self) -> Duration {
        self.period_impl()
    }
}

impl Stoppable for Hosts {
    fn stop(&self) {
        self.inner.stopped.store(true, Ordering::SeqCst);
    }

    fn stopped(&self) -> bool {
        self.inner.stopped.load(Ordering::SeqCst)
    }
}

/// gost's `parseHosts` (cmd/gost/cfg.go:283-296): loads a hosts file, or
/// returns `None` when it cannot be opened. The caller is responsible for
/// spawning [`crate::reload::period_reload`].
pub fn parse_hosts(path: &str) -> Option<Hosts> {
    if path.is_empty() {
        return None;
    }
    let f = std::fs::File::open(path).ok()?;
    let hosts = Hosts::new(Vec::new());
    if let Err(e) = hosts.reload(f) {
        debug!("[hosts] {}: {}", path, e);
    }
    Some(hosts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hosts_lookup() {
        let hosts = Hosts::new(vec![
            Host::new("127.0.0.1".parse().unwrap(), "localhost", vec![]),
            Host::new(
                "192.168.1.1".parse().unwrap(),
                "router",
                vec!["gateway".into()],
            ),
        ]);

        assert_eq!(
            hosts.lookup("localhost"),
            Some("127.0.0.1".parse().unwrap())
        );
        assert_eq!(hosts.lookup("router"), Some("192.168.1.1".parse().unwrap()));
        assert_eq!(
            hosts.lookup("gateway"),
            Some("192.168.1.1".parse().unwrap())
        );
        assert_eq!(hosts.lookup("unknown"), None);
        assert_eq!(hosts.lookup(""), None);
    }

    #[test]
    fn test_hosts_lookup_is_exact_match_only() {
        // gost v2 has no wildcard matching; do not add one.
        let hosts = Hosts::new(vec![Host::new(
            "10.0.0.1".parse().unwrap(),
            "example.com",
            vec![],
        )]);
        assert_eq!(
            hosts.lookup("example.com"),
            Some("10.0.0.1".parse().unwrap())
        );
        assert_eq!(hosts.lookup("sub.example.com"), None);
        assert_eq!(hosts.lookup("example.co"), None);
        assert_eq!(hosts.lookup(".example.com"), None);
    }

    #[test]
    fn test_hosts_add() {
        let hosts = Hosts::new(vec![]);
        assert_eq!(hosts.lookup("test"), None);

        hosts.add_host(Host::new("10.0.0.1".parse().unwrap(), "test", vec![]));
        assert_eq!(hosts.lookup("test"), Some("10.0.0.1".parse().unwrap()));
        assert_eq!(hosts.len(), 1);
        assert!(!hosts.is_empty());
    }

    #[test]
    fn test_hosts_reload() {
        let hosts = Hosts::new(vec![]);
        let data = b"127.0.0.1 localhost\n192.168.1.1 router gateway\n# comment\n";
        hosts.reload(&data[..]).unwrap();

        assert_eq!(
            hosts.lookup("localhost"),
            Some("127.0.0.1".parse().unwrap())
        );
        assert_eq!(
            hosts.lookup("gateway"),
            Some("192.168.1.1".parse().unwrap())
        );
    }

    #[test]
    fn test_hosts_reload_ignores_invalid_lines() {
        let hosts = Hosts::new(vec![]);
        hosts
            .reload(
                &b"not-an-ip somename\n10.0.0.1\n10.0.0.2 ok\n\n   \n10.0.0.3 x # trailing\n"[..],
            )
            .unwrap();
        assert_eq!(hosts.lookup("somename"), None);
        assert_eq!(hosts.lookup("ok"), Some("10.0.0.2".parse().unwrap()));
        assert_eq!(hosts.lookup("x"), Some("10.0.0.3".parse().unwrap()));
        assert_eq!(hosts.len(), 2);
    }

    // -----------------------------------------------------------------------
    // reload period + Reloader/Stoppable
    // -----------------------------------------------------------------------

    #[test]
    fn test_hosts_reload_period_is_stored() {
        let hosts = Hosts::new(vec![]);
        assert_eq!(hosts.period(), Duration::ZERO);

        hosts
            .reload(&b"reload 30s\n127.0.0.1 localhost\n"[..])
            .unwrap();
        assert_eq!(hosts.period(), Duration::from_secs(30));
        // The `reload` line must not become a host entry.
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts.lookup("30s"), None);

        hosts.reload(&b"reload 2m\n"[..]).unwrap();
        assert_eq!(hosts.period(), Duration::from_secs(120));
        assert_eq!(hosts.len(), 0);
    }

    #[test]
    fn test_hosts_stop_makes_period_zero_and_reload_noop() {
        let hosts = Hosts::new(vec![]);
        hosts
            .reload(&b"reload 30s\n127.0.0.1 localhost\n"[..])
            .unwrap();
        assert!(!hosts.stopped());

        Stoppable::stop(&hosts);
        assert!(hosts.stopped());
        assert_eq!(hosts.period(), Duration::ZERO);

        hosts.reload(&b"10.0.0.1 other\n"[..]).unwrap();
        assert_eq!(
            hosts.lookup("localhost"),
            Some("127.0.0.1".parse().unwrap())
        );
        assert_eq!(hosts.lookup("other"), None);
    }

    #[test]
    fn test_hosts_reloader_trait_impl() {
        let hosts = Hosts::new(vec![]);
        Reloader::reload(&hosts, Box::new(&b"reload 15s\n10.1.1.1 h1 a1\n"[..])).unwrap();
        let r: &dyn Reloader = &hosts;
        assert_eq!(r.period(), Duration::from_secs(15));
        assert_eq!(hosts.lookup("a1"), Some("10.1.1.1".parse().unwrap()));
    }

    #[test]
    fn test_hosts_clone_shares_table() {
        // Chain::default_options clones Hosts on every dial; a live reload has
        // to be visible through the clone.
        let a = Hosts::new(vec![]);
        let b = a.clone();
        a.reload(&b"reload 5s\n10.2.2.2 shared\n"[..]).unwrap();
        assert_eq!(b.lookup("shared"), Some("10.2.2.2".parse().unwrap()));
        assert_eq!(b.period(), Duration::from_secs(5));

        b.add_host(Host::new("10.3.3.3".parse().unwrap(), "later", vec![]));
        assert_eq!(a.lookup("later"), Some("10.3.3.3".parse().unwrap()));
    }

    #[test]
    fn test_parse_hosts_missing_file() {
        assert!(parse_hosts("").is_none());
        assert!(parse_hosts("D:/definitely/not/a/real/hosts/file").is_none());
    }
}
