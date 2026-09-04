use std::fmt;

// ---------------------------------------------------------------------------
// Host/port splitting -- a faithful port of Go's net.SplitHostPort
// ---------------------------------------------------------------------------

/// Errors returned by [`split_host_port`], mirroring Go's `net.AddrError`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AddrError {
    #[error("address {0}: missing port in address")]
    MissingPort(String),
    #[error("address {0}: too many colons in address")]
    TooManyColons(String),
    #[error("address {0}: missing ']' in address")]
    MissingRBracket(String),
    #[error("address {0}: unexpected '[' in address")]
    UnexpectedLBracket(String),
    #[error("address {0}: unexpected ']' in address")]
    UnexpectedRBracket(String),
}

/// Splits a network address of the form "host:port", "host%zone:port",
/// "[host]:port" or "[host%zone]:port" into host or host%zone and port.
///
/// This is a direct port of Go's `net.SplitHostPort` and therefore:
///  * strips the surrounding brackets of an IPv6 literal
///    (`"[::1]:80"` -> `("::1", "80")`), and
///  * returns an error for malformed input such as a bare `"::1"`
///    (too many colons) so that callers can fail closed.
///
/// The previous implementation used `rsplit_once(':')`, which kept the
/// brackets (so a `::1` rule never matched `[::1]:22`) and happily accepted a
/// bare `::1` as host `":"` / port `"1"`. Both were filter-bypass bugs.
pub fn split_host_port(host_port: &str) -> Result<(&str, &str), AddrError> {
    let b = host_port.as_bytes();

    // The port starts after the last colon.
    let i = match host_port.rfind(':') {
        Some(i) => i,
        None => return Err(AddrError::MissingPort(host_port.to_string())),
    };

    let host: &str;
    let (mut j, mut k) = (0usize, 0usize);

    if b[0] == b'[' {
        // Expect the first ']' just before the last ':'.
        let end = match host_port.find(']') {
            Some(e) => e,
            None => return Err(AddrError::MissingRBracket(host_port.to_string())),
        };
        if end + 1 == host_port.len() {
            // There can't be a ':' behind the ']' now.
            return Err(AddrError::MissingPort(host_port.to_string()));
        } else if end + 1 == i {
            // The expected result.
        } else {
            // Either ']' isn't followed by a colon, or it is followed by a
            // colon that is not the last one.
            if b[end + 1] == b':' {
                return Err(AddrError::TooManyColons(host_port.to_string()));
            }
            return Err(AddrError::MissingPort(host_port.to_string()));
        }
        host = &host_port[1..end];
        j = 1;
        k = end + 1;
    } else {
        host = &host_port[..i];
        if host.contains(':') {
            return Err(AddrError::TooManyColons(host_port.to_string()));
        }
    }

    if host_port[j..].contains('[') {
        return Err(AddrError::UnexpectedLBracket(host_port.to_string()));
    }
    if host_port[k..].contains(']') {
        return Err(AddrError::UnexpectedRBracket(host_port.to_string()));
    }

    Ok((host, &host_port[i + 1..]))
}

// ---------------------------------------------------------------------------
// go-glob -- the glob engine gost uses for permissions
// ---------------------------------------------------------------------------

/// A port of `github.com/ryanuber/go-glob`'s `Glob`, the matcher gost uses for
/// whitelist/blacklist rules (permissions.go:10,124).
///
/// Only `*` is a metacharacter. `?`, `[`, `]`, `{`, `}` are LITERAL, unlike
/// the `glob_match` crate that was used before. Using a richer engine silently
/// turned a rule such as `tcp:host[1].evil.com:*` into a character class, so
/// the intended block stopped matching the literal hostname.
///
/// Note: bypass.rs intentionally keeps a richer engine because gost uses
/// `gobwas/glob` there (bypass.go:14,102).
pub fn go_glob(pattern: &str, subj: &str) -> bool {
    // Empty pattern can only match empty subject.
    if pattern.is_empty() {
        return subj == pattern;
    }

    // If the pattern _is_ a glob, it matches everything.
    if pattern == "*" {
        return true;
    }

    let parts: Vec<&str> = pattern.split('*').collect();

    if parts.len() == 1 {
        // No globs in pattern, so test for equality.
        return subj == pattern;
    }

    let leading_glob = pattern.starts_with('*');
    let trailing_glob = pattern.ends_with('*');
    let end = parts.len() - 1;

    let mut subj = subj;

    // Go over the leading parts and ensure they match.
    for (i, part) in parts.iter().enumerate().take(end) {
        let idx = subj.find(part);
        if i == 0 {
            // Check the first section. Requires special handling.
            // When `leading_glob` is true, parts[0] is "" and `find` yields 0.
            if !leading_glob && idx != Some(0) {
                return false;
            }
        } else if idx.is_none() {
            // Check that the middle parts match.
            return false;
        }

        // Trim evaluated text from subj as we loop over the pattern.
        let idx = idx.unwrap_or(0);
        subj = &subj[idx + part.len()..];
    }

    // Reached the last section. Requires special handling.
    trailing_glob || subj.ends_with(parts[end])
}

/// PortRange specifies a range of ports.
///
/// The bounds are `i64` rather than `u16` because gost stores them in an `int`
/// (permissions.go:21-23) and deliberately leaves out-of-range spans intact.
/// Squeezing them into a `u16` is not a lossless simplification: `70000-80000`
/// clamps in gost to `Min=70000, Max=65535`, an empty range that matches
/// nothing, whereas saturating both ends into a `u16` produces `65535-65535`
/// and would wrongly match port 65535.
#[derive(Clone, Debug)]
pub struct PortRange {
    pub min: i64,
    pub max: i64,
}

impl PortRange {
    pub fn parse(s: &str) -> Result<Self, PermissionError> {
        if s == "*" {
            return Ok(PortRange { min: 0, max: 65535 });
        }

        if let Some((min_str, max_str)) = s.split_once('-') {
            // gost parses the bounds with strconv.Atoi and then CLAMPS them to
            // [0, 65535] (permissions.go:53-54). Parsing them directly as u16
            // made "1000-99999" a hard parse error; the caller in main.rs does
            // `.ok()`, which silently disabled the whole whitelist/blacklist.
            // That is fail-open on a malformed config, so clamp like gost.
            let min: i64 = min_str
                .parse()
                .map_err(|_| PermissionError::InvalidPort(s.to_string()))?;
            let max: i64 = max_str
                .parse()
                .map_err(|_| PermissionError::InvalidPort(s.to_string()))?;
            // gost: realmin = maxint(0, minint(min, max))
            //       realmax = minint(65535, maxint(min, max))
            // `realmin > realmax` is possible (e.g. "70000-80000") and simply
            // means the range matches nothing; that state is preserved here.
            Ok(PortRange {
                min: min.min(max).max(0),
                max: min.max(max).min(65535),
            })
        } else {
            // Single port: gost errors when out of [0, 65535] (permissions.go:39-41).
            let port: i64 = s
                .parse()
                .map_err(|_| PermissionError::InvalidPort(s.to_string()))?;
            if !(0..=65535).contains(&port) {
                return Err(PermissionError::InvalidPort(s.to_string()));
            }
            Ok(PortRange {
                min: port,
                max: port,
            })
        }
    }

    pub fn contains(&self, port: u16) -> bool {
        let port = port as i64;
        port >= self.min && port <= self.max
    }
}

/// PortSet is a set of PortRange.
#[derive(Clone, Debug)]
pub struct PortSet(Vec<PortRange>);

impl PortSet {
    pub fn parse(s: &str) -> Result<Self, PermissionError> {
        if s.is_empty() {
            return Err(PermissionError::EmptyPort);
        }
        let ranges: Result<Vec<PortRange>, _> =
            s.split(',').map(|r| PortRange::parse(r.trim())).collect();
        Ok(PortSet(ranges?))
    }

    pub fn contains(&self, port: u16) -> bool {
        self.0.iter().any(|r| r.contains(port))
    }
}

/// StringSet is a set of glob patterns.
#[derive(Clone, Debug)]
pub struct StringSet(Vec<String>);

impl StringSet {
    pub fn parse(s: &str) -> Result<Self, PermissionError> {
        if s.is_empty() {
            return Err(PermissionError::EmptyString);
        }
        Ok(StringSet(s.split(',').map(|s| s.to_string()).collect()))
    }

    pub fn contains(&self, subj: &str) -> bool {
        self.0.iter().any(|s| go_glob(s, subj))
    }
}

/// Permission is a rule for whitelist/blacklist.
#[derive(Clone, Debug)]
pub struct Permission {
    pub actions: StringSet,
    pub hosts: StringSet,
    pub ports: PortSet,
}

/// Permissions is a set of Permission rules.
#[derive(Clone, Debug)]
pub struct Permissions(Vec<Permission>);

impl Permissions {
    /// Parse permissions from a space-separated string.
    /// Format: "action1,action2:host1,host2:port1,port2-port3"
    pub fn parse(s: &str) -> Result<Self, PermissionError> {
        if s.is_empty() {
            return Ok(Permissions(Vec::new()));
        }

        let mut perms = Vec::new();
        // gost splits on a literal " " (permissions.go:143), so a double space
        // or a tab yields an empty/odd field and is rejected. Using
        // split_whitespace() here accepted configs gost rejects; match gost.
        for perm_str in s.split(' ') {
            let parts: Vec<&str> = perm_str.split(':').collect();
            if parts.len() != 3 {
                return Err(PermissionError::InvalidFormat(perm_str.to_string()));
            }
            let actions = StringSet::parse(parts[0])?;
            let hosts = StringSet::parse(parts[1])?;
            let ports = PortSet::parse(parts[2])?;

            perms.push(Permission {
                actions,
                hosts,
                ports,
            });
        }

        Ok(Permissions(perms))
    }

    pub fn can(&self, action: &str, host: &str, port: u16) -> bool {
        self.0
            .iter()
            .any(|p| p.actions.contains(action) && p.hosts.contains(host) && p.ports.contains(port))
    }
}

/// Tests whether the given action and address is allowed by the whitelist and blacklist.
///
/// Fails CLOSED (returns false) whenever the address cannot be split into a
/// valid host/port pair, matching gost (permissions.go:209-219).
#[allow(non_snake_case)]
pub fn Can(
    action: &str,
    addr: &str,
    whitelist: Option<&Permissions>,
    blacklist: Option<&Permissions>,
) -> bool {
    let addr = if !addr.contains(':') {
        format!("{}:80", addr)
    } else {
        addr.to_string()
    };

    let (host, port_str) = match split_host_port(&addr) {
        Ok(v) => v,
        Err(_) => return false,
    };

    // gost uses strconv.Atoi here, which accepts values outside [0, 65535];
    // such a port can never be inside a PortRange anyway, so rejecting it
    // outright is equivalent for a whitelist and strictly safer for a
    // blacklist. Either way we fail closed.
    let port: u16 = match port_str.parse() {
        Ok(p) => p,
        Err(_) => return false,
    };

    let wl_ok = whitelist.is_none() || whitelist.unwrap().can(action, host, port);
    let bl_ok = blacklist.is_none() || !blacklist.unwrap().can(action, host, port);

    wl_ok && bl_ok
}

#[derive(Debug, thiserror::Error)]
pub enum PermissionError {
    #[error("invalid port: {0}")]
    InvalidPort(String),
    #[error("empty port")]
    EmptyPort,
    #[error("empty string")]
    EmptyString,
    #[error("invalid permission format: {0}")]
    InvalidFormat(String),
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.min == self.max {
            write!(f, "{}", self.min)
        } else {
            write!(f, "{}-{}", self.min, self.max)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_range_single() {
        let pr = PortRange::parse("80").unwrap();
        assert!(pr.contains(80));
        assert!(!pr.contains(81));
    }

    #[test]
    fn test_port_range_range() {
        let pr = PortRange::parse("80-90").unwrap();
        assert!(pr.contains(80));
        assert!(pr.contains(85));
        assert!(pr.contains(90));
        assert!(!pr.contains(79));
        assert!(!pr.contains(91));
    }

    #[test]
    fn test_port_range_wildcard() {
        let pr = PortRange::parse("*").unwrap();
        assert!(pr.contains(0));
        assert!(pr.contains(80));
        assert!(pr.contains(65535));
    }

    #[test]
    fn test_port_set() {
        let ps = PortSet::parse("80,443,8000-9000").unwrap();
        assert!(ps.contains(80));
        assert!(ps.contains(443));
        assert!(ps.contains(8080));
        assert!(!ps.contains(81));
    }

    #[test]
    fn test_string_set() {
        let ss = StringSet::parse("*.google.com,example.com").unwrap();
        assert!(ss.contains("www.google.com"));
        assert!(ss.contains("example.com"));
        assert!(!ss.contains("example.org"));
    }

    #[test]
    fn test_permissions_parse() {
        let perms = Permissions::parse("tcp,udp:*.google.com,example.com:80,443").unwrap();
        assert!(perms.can("tcp", "www.google.com", 80));
        assert!(perms.can("udp", "example.com", 443));
        assert!(!perms.can("tcp", "evil.com", 80));
        assert!(!perms.can("tcp", "www.google.com", 8080));
    }

    #[test]
    fn test_permissions_empty() {
        let perms = Permissions::parse("").unwrap();
        assert!(!perms.can("tcp", "anything", 80));
    }

    #[test]
    fn test_can_function() {
        let wl = Permissions::parse("tcp:*:80,443").unwrap();
        let bl = Permissions::parse("tcp:evil.com:*").unwrap();

        assert!(Can("tcp", "good.com:80", Some(&wl), Some(&bl)));
        assert!(!Can("tcp", "good.com:8080", Some(&wl), Some(&bl)));
        assert!(!Can("tcp", "evil.com:80", Some(&wl), Some(&bl)));
    }

    #[test]
    fn test_can_no_lists() {
        assert!(Can("tcp", "anything:80", None, None));
    }

    #[test]
    fn test_can_default_port() {
        let wl = Permissions::parse("tcp:*:80").unwrap();
        assert!(Can("tcp", "example.com", Some(&wl), None));
    }

    // -----------------------------------------------------------------------
    // Defect A: net.SplitHostPort semantics + fail-closed
    // -----------------------------------------------------------------------

    #[test]
    fn test_split_host_port_ipv4() {
        assert_eq!(split_host_port("1.2.3.4:80").unwrap(), ("1.2.3.4", "80"));
        assert_eq!(
            split_host_port("example.com:443").unwrap(),
            ("example.com", "443")
        );
    }

    #[test]
    fn test_split_host_port_strips_ipv6_brackets() {
        // The old rsplit_once(':') kept the brackets -> "[::1]".
        assert_eq!(split_host_port("[::1]:80").unwrap(), ("::1", "80"));
        assert_eq!(
            split_host_port("[fe80::1%eth0]:22").unwrap(),
            ("fe80::1%eth0", "22")
        );
    }

    #[test]
    fn test_split_host_port_errors() {
        // Bare IPv6: too many colons -> error (gost denies).
        assert!(split_host_port("::1").is_err());
        assert!(split_host_port("2001:db8::1").is_err());
        // No port at all.
        assert!(split_host_port("example.com").is_err());
        // Bracketed without a port.
        assert!(split_host_port("[::1]").is_err());
        // Missing closing bracket.
        assert!(split_host_port("[::1:80").is_err());
        // Stray bracket.
        assert!(split_host_port("a[b:80").is_err());
    }

    #[test]
    fn test_can_denies_blacklisted_bracketed_ipv6() {
        // Host sets are comma separated, so a literal "::1" host rule is built
        // via StringSet directly (the ':' separator makes it unwritable inline,
        // exactly as in gost).
        let bl = Permissions(vec![Permission {
            actions: StringSet::parse("tcp").unwrap(),
            hosts: StringSet(vec!["::1".to_string()]),
            ports: PortSet::parse("*").unwrap(),
        }]);

        // Previously the host parsed as "[::1]" and never matched -> ALLOWED.
        assert!(
            !Can("tcp", "[::1]:22", None, Some(&bl)),
            "bracketed IPv6 must match the bare ::1 blacklist rule"
        );
        assert!(!Can("tcp", "[::1]:80", None, Some(&bl)));
        // A different IPv6 address is unaffected.
        assert!(Can("tcp", "[::2]:22", None, Some(&bl)));
    }

    #[test]
    fn test_can_denies_bare_ipv6_without_port() {
        // "::1" contains ':' so no ":80" is appended; SplitHostPort errors and
        // gost denies. The old code parsed it as host ":" / port "1".
        assert!(!Can("tcp", "::1", None, None));
        assert!(!Can("tcp", "2001:db8::1", None, None));
        // ...even with a permissive whitelist.
        let wl = Permissions::parse("tcp:*:*").unwrap();
        assert!(!Can("tcp", "::1", Some(&wl), None));
    }

    #[test]
    fn test_can_whitelisted_bracketed_ipv6() {
        let wl = Permissions(vec![Permission {
            actions: StringSet::parse("tcp").unwrap(),
            hosts: StringSet(vec!["::1".to_string()]),
            ports: PortSet::parse("80").unwrap(),
        }]);
        assert!(Can("tcp", "[::1]:80", Some(&wl), None));
        assert!(!Can("tcp", "[::1]:81", Some(&wl), None));
    }

    // -----------------------------------------------------------------------
    // Defect B: port range clamping (fail-open on malformed config)
    // -----------------------------------------------------------------------

    #[test]
    fn test_port_range_clamps_out_of_range_max() {
        // gost: strconv.Atoi + clamp -> 1000-65535. Previously this was a hard
        // parse error, so main.rs's `.ok()` silently DISABLED the whole list.
        let pr = PortRange::parse("1000-99999").unwrap();
        assert_eq!(pr.min, 1000);
        assert_eq!(pr.max, 65535);
        assert!(pr.contains(1000));
        assert!(pr.contains(65535));
        assert!(!pr.contains(999));
    }

    #[test]
    fn test_port_range_clamps_low_bound() {
        // "-100-2000" splits as ("", "100-2000") -> parse error, same as gost's
        // Atoi("") error. But "0-99999" must clamp.
        let pr = PortRange::parse("0-99999").unwrap();
        assert_eq!(pr.min, 0);
        assert_eq!(pr.max, 65535);
    }

    #[test]
    fn test_port_range_reversed_bounds_clamped() {
        let pr = PortRange::parse("99999-1000").unwrap();
        assert_eq!(pr.min, 1000);
        assert_eq!(pr.max, 65535);
    }

    #[test]
    fn test_permissions_with_oversized_range_still_enforced() {
        // The whole point of defect B: the blacklist must survive parsing.
        let bl = Permissions::parse("tcp:evil.com:1000-99999")
            .expect("oversized range must parse like gost");
        assert!(!Can("tcp", "evil.com:8080", None, Some(&bl)));
        assert!(Can("tcp", "evil.com:80", None, Some(&bl)));
    }

    #[test]
    fn test_port_range_single_out_of_range_is_error() {
        assert!(PortRange::parse("99999").is_err());
        assert!(PortRange::parse("abc").is_err());
    }

    #[test]
    fn test_port_range_fully_out_of_range_matches_nothing() {
        // gost yields Min=70000, Max=65535 -- an empty range. Saturating both
        // bounds into a u16 would collapse this to 65535-65535 and start
        // matching port 65535, which gost never does.
        let pr = PortRange::parse("70000-80000").unwrap();
        assert_eq!((pr.min, pr.max), (70000, 65535));
        assert!(!pr.contains(65535));
        assert!(!pr.contains(0));

        // The same at the bottom end: "-2000--1000" is not parseable by gost
        // either (Atoi("") on the first field), but "0-0" must still work.
        let zero = PortRange::parse("0-0").unwrap();
        assert!(zero.contains(0));
        assert!(!zero.contains(1));
    }

    #[test]
    fn test_permissions_fully_out_of_range_whitelist_allows_nothing() {
        // A whitelist naming only unreachable ports must not silently permit
        // port 65535.
        let wl = Permissions::parse("tcp:*:70000-80000").unwrap();
        assert!(!Can("tcp", "example.com:65535", Some(&wl), None));
        assert!(!Can("tcp", "example.com:80", Some(&wl), None));
    }

    // -----------------------------------------------------------------------
    // Defect C: go-glob semantics (only '*' is special)
    // -----------------------------------------------------------------------

    #[test]
    fn test_go_glob_basics() {
        assert!(go_glob("*", "anything"));
        assert!(go_glob("", ""));
        assert!(!go_glob("", "x"));
        assert!(go_glob("abc", "abc"));
        assert!(!go_glob("abc", "abcd"));
        assert!(go_glob("*.google.com", "www.google.com"));
        assert!(go_glob("*.google.com", "a.b.google.com"));
        assert!(!go_glob("*.google.com", "google.com"));
        assert!(go_glob("www.*.com", "www.google.com"));
        assert!(go_glob("a*b*c", "axxbyyc"));
        assert!(!go_glob("a*b*c", "axxc"));
        assert!(go_glob("prefix*", "prefix-and-more"));
    }

    #[test]
    fn test_go_glob_treats_brackets_literally() {
        // gost rule `tcp:host[1].evil.com:*` matches the LITERAL hostname.
        assert!(go_glob("host[1].evil.com", "host[1].evil.com"));
        // With a character-class engine this would (wrongly) match:
        assert!(!go_glob("host[1].evil.com", "host1.evil.com"));
    }

    #[test]
    fn test_go_glob_treats_question_and_braces_literally() {
        assert!(go_glob("a?c", "a?c"));
        assert!(!go_glob("a?c", "abc"));
        assert!(go_glob("{a,b}.com", "{a,b}.com"));
        assert!(!go_glob("{a,b}.com", "a.com"));
        // '**' is just two globs to go-glob, not a path-recursive token.
        assert!(go_glob("**", "anything"));
    }

    #[test]
    fn test_blacklist_literal_bracket_host_is_enforced() {
        let bl = Permissions::parse("tcp:host[1].evil.com:*").unwrap();
        assert!(
            !Can("tcp", "host[1].evil.com:443", None, Some(&bl)),
            "literal bracket hostname must still be blocked"
        );
        // And it must NOT accidentally block a different host.
        assert!(Can("tcp", "host1.evil.com:443", None, Some(&bl)));
    }

    // -----------------------------------------------------------------------
    // Defect D: split on a literal " " like gost
    // -----------------------------------------------------------------------

    #[test]
    fn test_permissions_split_matches_gost() {
        // Single spaces: fine.
        let p = Permissions::parse("tcp:a.com:80 udp:b.com:53").unwrap();
        assert!(p.can("tcp", "a.com", 80));
        assert!(p.can("udp", "b.com", 53));

        // gost's strings.Split(s, " ") rejects double spaces and tabs.
        assert!(Permissions::parse("tcp:a.com:80  udp:b.com:53").is_err());
        assert!(Permissions::parse("tcp:a.com:80\tudp:b.com:53").is_err());
        assert!(Permissions::parse("tcp:a.com:80 ").is_err());
    }
}
