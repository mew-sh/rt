use std::collections::HashMap;
use std::io::{self, BufRead};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::RwLock;
use std::time::Duration;

use crate::reload::{Reloader, Stoppable};

/// Authenticator is a trait for user authentication.
pub trait Authenticator: Send + Sync {
    fn authenticate(&self, user: &str, password: &str) -> bool;
}

/// LocalAuthenticator authenticates using local key-value pairs.
pub struct LocalAuthenticator {
    kvs: RwLock<HashMap<String, String>>,
    /// Reload period parsed from the `reload <duration>` directive.
    /// Zero means "no live reloading" (gost: auth.go:120,127).
    period: RwLock<Duration>,
    /// gost signals "stopped" with a closed channel and a negative Period().
    /// `reload::period_reload` cannot express a negative Duration, so the
    /// stopped state is tracked with this flag instead and `period()` reports
    /// Duration::ZERO once stopped, which makes `period_reload` return.
    stopped: AtomicBool,
}

impl LocalAuthenticator {
    pub fn new(kvs: HashMap<String, String>) -> Self {
        Self {
            kvs: RwLock::new(kvs),
            period: RwLock::new(Duration::ZERO),
            stopped: AtomicBool::new(false),
        }
    }

    pub fn add(&self, k: String, v: String) {
        self.kvs.write().unwrap().insert(k, v);
    }

    /// Reload parses config from reader, then reloads the authenticator.
    pub fn reload(&self, reader: impl io::Read) -> io::Result<()> {
        self.reload_impl(reader)
    }

    fn reload_impl(&self, reader: impl io::Read) -> io::Result<()> {
        if self.stopped() {
            return Ok(());
        }

        let mut kvs = HashMap::new();
        let mut period = Duration::ZERO;

        let buf = io::BufReader::new(reader);
        for line in buf.lines() {
            let line = line?;
            let parts = split_auth_line(&line);
            if parts.is_empty() {
                continue;
            }

            match parts[0].as_str() {
                "reload" => {
                    // gost: period, _ = time.ParseDuration(ss[1]) (auth.go:99-102)
                    if parts.len() > 1 {
                        period = parse_go_duration(&parts[1]).unwrap_or(Duration::ZERO);
                    }
                }
                _ => {
                    let k = parts[0].clone();
                    let v = if parts.len() > 1 {
                        parts[1].clone()
                    } else {
                        String::new()
                    };
                    kvs.insert(k, v);
                }
            }
        }

        *self.period.write().unwrap() = period;
        *self.kvs.write().unwrap() = kvs;
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

impl Authenticator for LocalAuthenticator {
    fn authenticate(&self, user: &str, password: &str) -> bool {
        let kvs = self.kvs.read().unwrap();
        if kvs.is_empty() {
            return true;
        }
        match kvs.get(user) {
            Some(v) => v.is_empty() || password == v,
            None => false,
        }
    }
}

impl Reloader for LocalAuthenticator {
    fn reload(&self, reader: Box<dyn io::Read + Send>) -> io::Result<()> {
        self.reload_impl(reader)
    }

    fn period(&self) -> Duration {
        self.period_impl()
    }
}

impl Stoppable for LocalAuthenticator {
    fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
    }

    fn stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }
}

/// Parses a Go `time.ParseDuration` string.
///
/// Accepts a possibly signed sequence of decimal numbers, each with an optional
/// fraction and a required unit suffix: "300ms", "1.5h", "2h45m". Valid units
/// are "ns", "us" (or "µs"/"μs"), "ms", "s", "m", "h". A bare "0" is valid.
/// Negative durations are not representable by `std::time::Duration` and are
/// reported as an error (the caller then falls back to "no reloading").
pub fn parse_go_duration(s: &str) -> Option<Duration> {
    let mut rest = s;
    let mut neg = false;

    // Consume the sign.
    if let Some(r) = rest.strip_prefix('-') {
        neg = true;
        rest = r;
    } else if let Some(r) = rest.strip_prefix('+') {
        rest = r;
    }

    // Special case: "0" (and "+0"/"-0") with no unit.
    if rest == "0" {
        return Some(Duration::ZERO);
    }
    if rest.is_empty() {
        return None;
    }

    let mut total_nanos: f64 = 0.0;
    let mut saw_any = false;

    while !rest.is_empty() {
        // Leading number (digits with an optional fraction).
        let num_len = rest
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(rest.len());
        if num_len == 0 {
            return None;
        }
        let num_str = &rest[..num_len];
        if num_str == "." || num_str.matches('.').count() > 1 {
            return None;
        }
        let value: f64 = num_str.parse().ok()?;
        rest = &rest[num_len..];

        // Unit.
        let (unit_nanos, unit_len) = if rest.starts_with("ns") {
            (1.0, 2)
        } else if rest.starts_with("us") {
            (1_000.0, 2)
        } else if rest.starts_with("µs") {
            (1_000.0, "µs".len())
        } else if rest.starts_with("μs") {
            (1_000.0, "μs".len())
        } else if rest.starts_with("ms") {
            (1_000_000.0, 2)
        } else if rest.starts_with('s') {
            (1_000_000_000.0, 1)
        } else if rest.starts_with('m') {
            (60.0 * 1_000_000_000.0, 1)
        } else if rest.starts_with('h') {
            (3600.0 * 1_000_000_000.0, 1)
        } else {
            // Missing or unknown unit.
            return None;
        };
        rest = &rest[unit_len..];

        total_nanos += value * unit_nanos;
        saw_any = true;
    }

    if !saw_any {
        return None;
    }
    if neg && total_nanos > 0.0 {
        // Not representable by std::time::Duration.
        return None;
    }
    Some(Duration::from_nanos(total_nanos as u64))
}

/// Helper: split a line by white space, stripping an inline `#` comment.
///
/// This mirrors gost's package-level `splitLine` (gost.go:195-197), which IS
/// used by the bypass config reader. It is deliberately different from
/// [`split_auth_line`]; do not merge the two.
pub fn split_line_ref(line: &str) -> Vec<&str> {
    let line = if let Some(idx) = line.find('#') {
        &line[..idx]
    } else {
        line
    };
    line.split([' ', '\t'])
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Helper: split a secrets/auth-file line by white space.
///
/// This mirrors the LOCAL `split` closure inside gost's
/// `LocalAuthenticator.Reload` (auth.go:70-88):
///  * a line is skipped only when `#` is its FIRST character (after trimming),
///  * there is NO inline comment stripping.
///
/// The previous implementation truncated at the first `#` anywhere, so a
/// secrets line `admin s3cr3t#pass` produced the password `s3cr3t` instead of
/// `s3cr3t#pass`, silently weakening authentication.
pub fn split_auth_line(line: &str) -> Vec<String> {
    if line.is_empty() {
        return Vec::new();
    }
    let line = line.replace('\t', " ");
    let line = line.trim();

    if line.starts_with('#') {
        return Vec::new();
    }

    line.split(' ')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_authenticator_empty() {
        let au = LocalAuthenticator::new(HashMap::new());
        // Empty authenticator allows everything
        assert!(au.authenticate("any", "any"));
    }

    #[test]
    fn test_local_authenticator_basic() {
        let mut kvs = HashMap::new();
        kvs.insert("admin".into(), "secret".into());
        let au = LocalAuthenticator::new(kvs);

        assert!(au.authenticate("admin", "secret"));
        assert!(!au.authenticate("admin", "wrong"));
        assert!(!au.authenticate("unknown", "secret"));
    }

    #[test]
    fn test_local_authenticator_empty_password() {
        let mut kvs = HashMap::new();
        kvs.insert("admin".into(), String::new());
        let au = LocalAuthenticator::new(kvs);

        // Empty password in the store means any password is accepted
        assert!(au.authenticate("admin", "anything"));
        assert!(au.authenticate("admin", ""));
    }

    #[test]
    fn test_local_authenticator_add() {
        let au = LocalAuthenticator::new(HashMap::new());
        assert!(au.authenticate("user", "pass")); // empty = allow all

        au.add("user".into(), "pass".into());
        assert!(au.authenticate("user", "pass"));
        assert!(!au.authenticate("user", "wrong"));
    }

    #[test]
    fn test_local_authenticator_reload() {
        let au = LocalAuthenticator::new(HashMap::new());
        let data = b"admin secret\nuser pass123\n# comment line\n";
        au.reload(&data[..]).unwrap();

        assert!(au.authenticate("admin", "secret"));
        assert!(au.authenticate("user", "pass123"));
        assert!(!au.authenticate("admin", "wrong"));
        assert!(!au.authenticate("unknown", "any"));
    }

    // -----------------------------------------------------------------------
    // Defect G: '#' handling in the auth file
    // -----------------------------------------------------------------------

    #[test]
    fn test_split_auth_line() {
        assert_eq!(split_auth_line(""), Vec::<String>::new());
        assert_eq!(split_auth_line("# comment"), Vec::<String>::new());
        // '#' at column 0 after trimming is still a comment.
        assert_eq!(split_auth_line("   # comment"), Vec::<String>::new());
        assert_eq!(split_auth_line("\t# comment"), Vec::<String>::new());
        assert_eq!(split_auth_line("admin secret"), vec!["admin", "secret"]);
        assert_eq!(split_auth_line("admin\tsecret"), vec!["admin", "secret"]);
        assert_eq!(split_auth_line("admin  secret"), vec!["admin", "secret"]);
    }

    #[test]
    fn test_split_auth_line_keeps_inline_hash() {
        // gost does NO inline comment stripping in the auth file.
        assert_eq!(
            split_auth_line("admin s3cr3t#pass"),
            vec!["admin", "s3cr3t#pass"]
        );
        assert_eq!(
            split_auth_line("admin secret # not-a-comment"),
            vec!["admin", "secret", "#", "not-a-comment"]
        );
        // A '#' inside the username is likewise preserved.
        assert_eq!(split_auth_line("us#er pw"), vec!["us#er", "pw"]);
    }

    #[test]
    fn test_reload_password_containing_hash_is_not_truncated() {
        let au = LocalAuthenticator::new(HashMap::new());
        au.reload(&b"admin s3cr3t#pass\n"[..]).unwrap();

        assert!(
            au.authenticate("admin", "s3cr3t#pass"),
            "password containing '#' must be preserved"
        );
        assert!(
            !au.authenticate("admin", "s3cr3t"),
            "truncated password must NOT authenticate"
        );
    }

    #[test]
    fn test_reload_hash_at_column_zero_is_a_comment() {
        let au = LocalAuthenticator::new(HashMap::new());
        au.reload(&b"# admin secret\nreal pass\n  #indented comment\n"[..])
            .unwrap();

        assert!(!au.authenticate("admin", "secret"));
        assert!(!au.authenticate("#", "admin"));
        assert!(au.authenticate("real", "pass"));
    }

    // -----------------------------------------------------------------------
    // Defect H: the `reload` directive is stored and exposed
    // -----------------------------------------------------------------------

    #[test]
    fn test_reload_period_is_stored() {
        let au = LocalAuthenticator::new(HashMap::new());
        assert_eq!(au.period(), Duration::ZERO);

        au.reload(&b"reload 10s\nadmin secret\n"[..]).unwrap();
        assert_eq!(au.period(), Duration::from_secs(10));
        // The `reload` line must not become a credential.
        assert!(!au.authenticate("reload", "10s"));
        assert!(au.authenticate("admin", "secret"));

        au.reload(&b"reload 1m30s\n"[..]).unwrap();
        assert_eq!(au.period(), Duration::from_secs(90));
    }

    #[test]
    fn test_stop_makes_period_zero_and_reload_noop() {
        let au = LocalAuthenticator::new(HashMap::new());
        au.reload(&b"reload 10s\nadmin secret\n"[..]).unwrap();
        assert!(!au.stopped());

        au.stop();
        assert!(au.stopped());
        assert_eq!(au.period(), Duration::ZERO);

        // gost's Reload returns immediately once stopped.
        au.reload(&b"other pw\n"[..]).unwrap();
        assert!(au.authenticate("admin", "secret"));
        assert!(!au.authenticate("other", "pw"));
    }

    #[test]
    fn test_reloader_trait_impl() {
        fn as_reloader(r: &dyn Reloader) -> Duration {
            r.period()
        }
        let au = LocalAuthenticator::new(HashMap::new());
        Reloader::reload(&au, Box::new(&b"reload 5s\nadmin secret\n"[..])).unwrap();
        assert_eq!(as_reloader(&au), Duration::from_secs(5));
        assert!(au.authenticate("admin", "secret"));
    }

    #[test]
    fn test_parse_go_duration() {
        assert_eq!(parse_go_duration("0"), Some(Duration::ZERO));
        assert_eq!(parse_go_duration("10s"), Some(Duration::from_secs(10)));
        assert_eq!(parse_go_duration("300ms"), Some(Duration::from_millis(300)));
        assert_eq!(parse_go_duration("1.5h"), Some(Duration::from_secs(5400)));
        assert_eq!(parse_go_duration("2h45m"), Some(Duration::from_secs(9900)));
        assert_eq!(parse_go_duration("100us"), Some(Duration::from_micros(100)));
        assert_eq!(parse_go_duration("5ns"), Some(Duration::from_nanos(5)));
        // Go requires a unit (except for a bare 0).
        assert_eq!(parse_go_duration("10"), None);
        assert_eq!(parse_go_duration(""), None);
        assert_eq!(parse_go_duration("abc"), None);
        assert_eq!(parse_go_duration("10x"), None);
    }
}
