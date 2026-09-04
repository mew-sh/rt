use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::node::Node;

#[derive(Debug, thiserror::Error)]
pub enum SelectError {
    #[error("no node available")]
    NoneAvailable,
}

/// NodeSelector picks nodes and marks their status.
pub trait NodeSelector: Send + Sync + std::fmt::Debug {
    fn select(&self, nodes: &[Node]) -> Result<Node, SelectError>;
}

/// Strategy is a selection strategy (random, round-robin, fifo).
pub trait Strategy: Send + Sync + std::fmt::Debug {
    fn apply(&self, nodes: &[Node]) -> Node;
    fn name(&self) -> &str;
}

/// Filter filters nodes during selection.
pub trait Filter: Send + Sync + std::fmt::Debug {
    fn filter(&self, nodes: &[Node]) -> Vec<Node>;
    fn name(&self) -> &str;
}

/// Default selector implementation: round-robin with no filtering.
#[derive(Debug)]
pub struct DefaultSelector {
    counter: AtomicU64,
}

impl DefaultSelector {
    pub fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
        }
    }
}

impl Default for DefaultSelector {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeSelector for DefaultSelector {
    fn select(&self, nodes: &[Node]) -> Result<Node, SelectError> {
        if nodes.is_empty() {
            return Err(SelectError::NoneAvailable);
        }
        // Per-instance, not a process-global `static`: a shared counter makes
        // every node group in the process advance each other's round-robin.
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        Ok(nodes[n as usize % nodes.len()].clone())
    }
}

/// A selector that applies filters before handing the survivors to a strategy,
/// mirroring gost's `defaultSelector` (selector.go:29-46). Without this, a
/// node marked dead is still selected on the very next call.
#[derive(Debug)]
pub struct FilterSelector {
    filters: Vec<Box<dyn Filter>>,
    strategy: Box<dyn Strategy>,
}

impl FilterSelector {
    pub fn new(filters: Vec<Box<dyn Filter>>, strategy: Box<dyn Strategy>) -> Self {
        Self { filters, strategy }
    }

    /// The selector gost installs for a forward/chain node group: drop nodes
    /// with invalid ports, then nodes that have failed too recently.
    pub fn with_fail_filter(
        strategy: &str,
        max_fails: u32,
        fail_timeout: Duration,
    ) -> Self {
        Self::with_filters(strategy, max_fails, fail_timeout, 0)
    }

    /// As above, plus gost's fastest filter when `fastest_count` is non-zero
    /// (route.go:64-72). A zero count leaves the filter out entirely, which is
    /// what gost's "disabled" behaviour amounts to.
    pub fn with_filters(
        strategy: &str,
        max_fails: u32,
        fail_timeout: Duration,
        fastest_count: usize,
    ) -> Self {
        let mut filters: Vec<Box<dyn Filter>> = vec![
            Box::new(InvalidFilter),
            Box::new(FailFilter::new(max_fails, fail_timeout)),
        ];
        if fastest_count > 0 {
            filters.push(Box::new(FastestFilter::new(
                DEFAULT_PING_TIMEOUT,
                fastest_count,
            )));
        }
        Self::new(filters, new_strategy(strategy))
    }
}

impl NodeSelector for FilterSelector {
    fn select(&self, nodes: &[Node]) -> Result<Node, SelectError> {
        let mut candidates = nodes.to_vec();
        for filter in &self.filters {
            candidates = filter.filter(&candidates);
            if candidates.is_empty() {
                return Err(SelectError::NoneAvailable);
            }
        }
        Ok(self.strategy.apply(&candidates))
    }
}

/// Creates a strategy by name.
pub fn new_strategy(name: &str) -> Box<dyn Strategy> {
    match name {
        "random" => Box::new(RandomStrategy::new()),
        "fifo" => Box::new(FifoStrategy),
        _ => Box::new(RoundStrategy::new()),
    }
}

/// Round-robin strategy.
#[derive(Debug)]
pub struct RoundStrategy {
    counter: AtomicU64,
}

impl RoundStrategy {
    pub fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
        }
    }
}

impl Default for RoundStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl Strategy for RoundStrategy {
    fn apply(&self, nodes: &[Node]) -> Node {
        if nodes.is_empty() {
            return Node::default();
        }
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        nodes[n as usize % nodes.len()].clone()
    }

    fn name(&self) -> &str {
        "round"
    }
}

/// Random strategy.
#[derive(Debug)]
pub struct RandomStrategy;

impl RandomStrategy {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RandomStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl Strategy for RandomStrategy {
    fn apply(&self, nodes: &[Node]) -> Node {
        if nodes.is_empty() {
            return Node::default();
        }
        use rand::Rng;
        let idx = rand::thread_rng().gen_range(0..nodes.len());
        nodes[idx].clone()
    }

    fn name(&self) -> &str {
        "random"
    }
}

/// FIFO strategy - always pick the first available node.
#[derive(Debug)]
pub struct FifoStrategy;

impl Strategy for FifoStrategy {
    fn apply(&self, nodes: &[Node]) -> Node {
        if nodes.is_empty() {
            return Node::default();
        }
        nodes[0].clone()
    }

    fn name(&self) -> &str {
        "fifo"
    }
}

/// Default max fails and fail timeout for FailFilter.
pub const DEFAULT_MAX_FAILS: u32 = 1;
pub const DEFAULT_FAIL_TIMEOUT: Duration = Duration::from_secs(30);

/// FailFilter filters out dead nodes.
#[derive(Debug)]
pub struct FailFilter {
    pub max_fails: u32,
    pub fail_timeout: Duration,
}

impl FailFilter {
    pub fn new(max_fails: u32, fail_timeout: Duration) -> Self {
        Self {
            max_fails: if max_fails == 0 {
                DEFAULT_MAX_FAILS
            } else {
                max_fails
            },
            fail_timeout: if fail_timeout.is_zero() {
                DEFAULT_FAIL_TIMEOUT
            } else {
                fail_timeout
            },
        }
    }
}

impl Default for FailFilter {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_FAILS, DEFAULT_FAIL_TIMEOUT)
    }
}

impl Filter for FailFilter {
    fn filter(&self, nodes: &[Node]) -> Vec<Node> {
        if nodes.len() <= 1 {
            return nodes.to_vec();
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        nodes
            .iter()
            .filter(|n| {
                let count = n.marker.fail_count();
                let time = n.marker.fail_time();
                count < self.max_fails || (now - time) >= self.fail_timeout.as_secs() as i64
            })
            .cloned()
            .collect()
    }

    fn name(&self) -> &str {
        "fail"
    }
}

/// Default TCP ping timeout, matching gost's `NewFastestFilter` (selector.go:222-224).
pub const DEFAULT_PING_TIMEOUT: Duration = Duration::from_millis(3000);

#[derive(Debug, Clone, Copy)]
struct PingEntry {
    latency_ms: u64,
    /// Unix seconds after which this measurement is stale.
    expires_at: i64,
}

/// FastestFilter keeps the `top_count` lowest-latency nodes.
///
/// Latency is measured by timing a TCP connect, cached, and refreshed in the
/// background — a filter cannot await, and blocking selection on a probe would
/// add the probe's latency to every request. This mirrors gost
/// (selector.go:212-297), including its randomised cache TTL, which stops all
/// nodes expiring on the same tick.
#[derive(Debug)]
pub struct FastestFilter {
    top_count: usize,
    ping_timeout: Duration,
    results: Arc<Mutex<HashMap<usize, PingEntry>>>,
}

impl FastestFilter {
    pub fn new(ping_timeout: Duration, top_count: usize) -> Self {
        Self {
            top_count,
            ping_timeout: if ping_timeout.is_zero() {
                DEFAULT_PING_TIMEOUT
            } else {
                ping_timeout
            },
            results: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn now_secs() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }

    /// Returns the cached latency, kicking off a refresh when it is stale.
    ///
    /// An unmeasured node reports zero, so it sorts first and gets tried —
    /// the same behaviour as gost, where the map returns the zero value.
    fn latency_of(&self, node: &Node) -> u64 {
        let now = Self::now_secs();
        let mut results = self.results.lock().unwrap();
        let entry = results.get(&node.id).copied();

        let stale = entry.map(|e| e.expires_at < now).unwrap_or(true);
        if stale {
            // Hold off other refreshes for a few seconds so a slow probe is
            // not started once per selection (gost uses the same guard).
            results.insert(
                node.id,
                PingEntry {
                    latency_ms: entry.map(|e| e.latency_ms).unwrap_or(0),
                    expires_at: now + 5,
                },
            );
            self.spawn_probe(node.id, node.addr.clone());
        }

        entry.map(|e| e.latency_ms).unwrap_or(0)
    }

    fn spawn_probe(&self, id: usize, addr: String) {
        // Only measure when a runtime is available; `filter` is sync and may be
        // called from a plain test.
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let results = self.results.clone();
        let timeout = self.ping_timeout;

        handle.spawn(async move {
            let started = tokio::time::Instant::now();
            let reachable = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr))
                .await
                .is_ok_and(|r| r.is_ok());

            // An unreachable node is recorded at the timeout, so it sorts last
            // rather than looking instantaneous.
            let latency_ms = if reachable {
                started.elapsed().as_millis() as u64
            } else {
                timeout.as_millis() as u64
            };

            // Randomised TTL between 180 and 300 seconds, as in gost.
            let ttl = 300 - (120.0 * rand::random::<f64>()) as i64;
            let expires_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64
                + ttl;

            results.lock().unwrap().insert(
                id,
                PingEntry {
                    latency_ms,
                    expires_at,
                },
            );
        });
    }

    /// Records a latency directly. Used by tests to avoid depending on real
    /// network timing.
    pub fn set_latency(&self, node_id: usize, latency_ms: u64) {
        self.results.lock().unwrap().insert(
            node_id,
            PingEntry {
                latency_ms,
                expires_at: Self::now_secs() + 300,
            },
        );
    }
}

impl Filter for FastestFilter {
    fn filter(&self, nodes: &[Node]) -> Vec<Node> {
        // gost treats a zero count as "disabled" rather than "keep nothing".
        if self.top_count == 0 {
            return nodes.to_vec();
        }

        let mut scored: Vec<(u64, Node)> = nodes
            .iter()
            .map(|n| (self.latency_of(n), n.clone()))
            .collect();
        scored.sort_by_key(|(latency, _)| *latency);

        scored
            .into_iter()
            .take(self.top_count)
            .map(|(_, n)| n)
            .collect()
    }

    fn name(&self) -> &str {
        "fastest"
    }
}

/// InvalidFilter filters nodes with invalid ports.
#[derive(Debug)]
pub struct InvalidFilter;

impl Filter for InvalidFilter {
    fn filter(&self, nodes: &[Node]) -> Vec<Node> {
        nodes
            .iter()
            .filter(|n| {
                if let Some(idx) = n.addr.rfind(':') {
                    if let Ok(port) = n.addr[idx + 1..].parse::<u16>() {
                        return port > 0;
                    }
                }
                false
            })
            .cloned()
            .collect()
    }

    fn name(&self) -> &str {
        "invalid"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::Node;

    fn make_nodes(addrs: &[&str]) -> Vec<Node> {
        addrs
            .iter()
            .enumerate()
            .map(|(i, a)| {
                let mut n = Node::parse(&format!("http://{}", a)).unwrap();
                n.id = i + 1;
                n
            })
            .collect()
    }

    #[test]
    fn test_round_strategy() {
        let nodes = make_nodes(&["a:1", "b:2", "c:3"]);
        let s = RoundStrategy::new();
        let n1 = s.apply(&nodes);
        let n2 = s.apply(&nodes);
        let n3 = s.apply(&nodes);
        let n4 = s.apply(&nodes);

        // Should cycle through nodes
        assert_ne!(n1.addr, n2.addr);
        assert_ne!(n2.addr, n3.addr);
        assert_eq!(n1.addr, n4.addr);
    }

    #[test]
    fn test_random_strategy() {
        let nodes = make_nodes(&["a:1", "b:2", "c:3"]);
        let s = RandomStrategy::new();
        // Just verify it doesn't panic and returns valid nodes
        for _ in 0..10 {
            let n = s.apply(&nodes);
            assert!(!n.addr.is_empty());
        }
    }

    #[test]
    fn test_fifo_strategy() {
        let nodes = make_nodes(&["a:1", "b:2", "c:3"]);
        let s = FifoStrategy;
        assert_eq!(s.apply(&nodes).addr, "a:1");
        assert_eq!(s.apply(&nodes).addr, "a:1");
    }

    #[test]
    fn test_fifo_empty() {
        let s = FifoStrategy;
        let n = s.apply(&[]);
        assert!(n.addr.is_empty());
    }

    #[test]
    fn test_fail_filter() {
        let mut nodes = make_nodes(&["a:1", "b:2", "c:3"]);
        nodes[1].mark_dead(); // mark b as dead

        let f = FailFilter::new(1, Duration::from_secs(30));
        let filtered = f.filter(&nodes);
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].addr, "a:1");
        assert_eq!(filtered[1].addr, "c:3");
    }

    #[test]
    fn test_fail_filter_timeout_expired() {
        let nodes = make_nodes(&["a:1", "b:2"]);
        // Mark dead with time far in the past
        nodes[0].marker.mark();

        // With very short timeout (1 nanosecond), the failed node should be included again
        // because time since failure > fail_timeout
        let f = FailFilter {
            max_fails: 1,
            fail_timeout: Duration::from_nanos(1),
        };
        // Sleep briefly to ensure time has passed
        std::thread::sleep(Duration::from_millis(1));
        let filtered = f.filter(&nodes);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_invalid_filter() {
        let f = InvalidFilter;
        // Create nodes manually to control addr
        let mut valid = Node::default();
        valid.addr = "127.0.0.1:80".to_string();
        valid.id = 1;

        let mut invalid = Node::default();
        invalid.addr = "127.0.0.1".to_string(); // no port
        invalid.id = 2;

        let nodes = vec![valid, invalid];
        let filtered = f.filter(&nodes);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].addr, "127.0.0.1:80");
    }

    #[test]
    fn test_new_strategy() {
        assert_eq!(new_strategy("random").name(), "random");
        assert_eq!(new_strategy("fifo").name(), "fifo");
        assert_eq!(new_strategy("round").name(), "round");
        assert_eq!(new_strategy("unknown").name(), "round");
    }

    #[test]
    fn test_default_selector() {
        let nodes = make_nodes(&["a:1", "b:2"]);
        let sel = DefaultSelector::new();
        let n = sel.select(&nodes).unwrap();
        assert!(!n.addr.is_empty());
    }

    #[test]
    fn test_default_selector_empty() {
        let sel = DefaultSelector::new();
        assert!(sel.select(&[]).is_err());
    }

    #[test]
    fn test_default_selector_counter_is_per_instance() {
        // A process-global counter made every node group advance each other's
        // round-robin position.
        let nodes = make_nodes(&["a:1", "b:2"]);
        let a = DefaultSelector::new();
        let b = DefaultSelector::new();
        assert_eq!(a.select(&nodes).unwrap().addr, "a:1");
        assert_eq!(b.select(&nodes).unwrap().addr, "a:1");
        assert_eq!(a.select(&nodes).unwrap().addr, "b:2");
    }

    #[test]
    fn test_filter_selector_excludes_dead_nodes() {
        let nodes = make_nodes(&["good:1", "dead:2"]);
        let sel = FilterSelector::with_fail_filter("round", 1, Duration::from_secs(30));

        // Fail the second node past max_fails; it must stop being selected.
        nodes[1].mark_dead();

        for _ in 0..6 {
            assert_eq!(
                sel.select(&nodes).unwrap().addr,
                "good:1",
                "a node marked dead must be filtered out of selection"
            );
        }

        // Once it recovers it comes back into rotation.
        nodes[1].reset_dead();
        let picked: std::collections::HashSet<String> =
            (0..6).map(|_| sel.select(&nodes).unwrap().addr).collect();
        assert!(picked.contains("dead:2"), "recovered node should return to rotation");
    }

    #[test]
    fn test_filter_selector_errors_when_all_nodes_dead() {
        let nodes = make_nodes(&["a:1", "b:2"]);
        nodes[0].mark_dead();
        nodes[1].mark_dead();
        let sel = FilterSelector::with_fail_filter("round", 1, Duration::from_secs(30));
        assert!(sel.select(&nodes).is_err());
    }

    #[test]
    fn test_fastest_filter_keeps_the_lowest_latency_nodes() {
        let nodes = make_nodes(&["slow:1", "fast:2", "medium:3"]);
        let f = FastestFilter::new(Duration::from_millis(100), 2);
        // Seed the cache so the test does not depend on real network timing.
        f.set_latency(nodes[0].id, 300);
        f.set_latency(nodes[1].id, 10);
        f.set_latency(nodes[2].id, 100);

        let kept: Vec<String> = f.filter(&nodes).into_iter().map(|n| n.addr).collect();
        assert_eq!(kept, vec!["fast:2".to_string(), "medium:3".to_string()]);
    }

    #[test]
    fn test_fastest_filter_zero_count_is_disabled_not_empty() {
        // gost treats topCount == 0 as "filter off", not "discard everything".
        let nodes = make_nodes(&["a:1", "b:2"]);
        let f = FastestFilter::new(Duration::from_millis(100), 0);
        assert_eq!(f.filter(&nodes).len(), 2);
    }

    #[test]
    fn test_fastest_filter_keeps_all_when_fewer_than_top_count() {
        let nodes = make_nodes(&["a:1", "b:2"]);
        let f = FastestFilter::new(Duration::from_millis(100), 5);
        assert_eq!(f.filter(&nodes).len(), 2);
    }

    #[tokio::test]
    async fn test_fastest_filter_measures_a_real_node() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });

        let nodes = make_nodes(&[&addr.to_string(), "127.0.0.1:1"]);
        let f = FastestFilter::new(Duration::from_millis(200), 1);

        // First pass has no measurements yet and only schedules the probes.
        let _ = f.filter(&nodes);
        tokio::time::sleep(Duration::from_millis(400)).await;

        // The reachable node must now win over the refused one, which is
        // recorded at the timeout rather than as instantaneous.
        let kept = f.filter(&nodes);
        assert_eq!(kept[0].addr, addr.to_string());
    }

    #[test]
    fn test_invalid_filter_rejects_zero_and_missing_port() {
        let nodes = make_nodes(&["good:80", "noport", "zero:0"]);
        let kept: Vec<String> = InvalidFilter
            .filter(&nodes)
            .into_iter()
            .map(|n| n.addr)
            .collect();
        assert_eq!(kept, vec!["good:80".to_string()]);
    }
}
