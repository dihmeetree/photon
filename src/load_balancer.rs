/// High-performance load balancing implementation using Pingora
use anyhow::{anyhow, Result};
use arc_swap::ArcSwap;
use dashmap::DashMap;
use pingora_core::protocols::TcpKeepalive;
use pingora_core::upstreams::peer::HttpPeer;
use std::hash::{Hash, Hasher};
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use crate::config::{BackendConfig, LoadBalancingAlgorithm, TcpKeepaliveConfig, UpstreamConfig};

/// Trait for load balancing strategies
pub trait LoadBalancingStrategy: Send + Sync {
    /// Select an upstream server for the given request
    fn select(&self, key: &[u8]) -> Option<Arc<UpstreamServer>>;

    /// Update the list of available upstream servers
    fn update_upstreams(&self, upstreams: Vec<Arc<UpstreamServer>>);

    /// Get current upstream servers
    fn get_upstreams(&self) -> Vec<Arc<UpstreamServer>>;
}

/// Circuit breaker states
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CircuitState {
    /// Circuit is closed, requests flow normally
    Closed,
    /// Circuit is open, requests are rejected
    Open,
    /// Circuit is half-open, testing if service recovered
    HalfOpen,
}

/// Circuit breaker for upstream resilience
#[derive(Debug)]
pub struct CircuitBreaker {
    /// Current state of the circuit
    state: ArcSwap<CircuitState>,
    /// Failure count in current window
    failure_count: AtomicUsize,
    /// Success count in half-open state
    success_count: AtomicUsize,
    /// Last failure time (nanoseconds since UNIX_EPOCH)
    last_failure_time: AtomicU64,
    /// Failure threshold to open circuit
    failure_threshold: usize,
    /// Success threshold to close circuit from half-open
    recovery_threshold: usize,
    /// Timeout before trying half-open (seconds)
    timeout_seconds: u64,
}

impl CircuitBreaker {
    /// Create a new circuit breaker
    pub fn new(failure_threshold: usize, recovery_threshold: usize, timeout_seconds: u64) -> Self {
        Self {
            state: ArcSwap::new(Arc::new(CircuitState::Closed)),
            failure_count: AtomicUsize::new(0),
            success_count: AtomicUsize::new(0),
            last_failure_time: AtomicU64::new(0),
            failure_threshold,
            recovery_threshold,
            timeout_seconds,
        }
    }

    /// Check if request should be allowed through the circuit
    pub fn should_allow_request(&self) -> bool {
        match &**self.state.load() {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if timeout has elapsed to try half-open
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let last_failure = self.last_failure_time.load(Ordering::Relaxed);

                if now.saturating_sub(last_failure) >= self.timeout_seconds {
                    // Try to transition to half-open
                    let current_state = Arc::new(CircuitState::Open);
                    let new_state = Arc::new(CircuitState::HalfOpen);
                    if **self.state.compare_and_swap(&current_state, new_state)
                        == CircuitState::HalfOpen
                    {
                        self.success_count.store(0, Ordering::Relaxed);
                        return true;
                    }
                }
                false
            }
            CircuitState::HalfOpen => {
                // Allow a limited number of requests in half-open state
                self.success_count.load(Ordering::Relaxed) < self.recovery_threshold
            }
        }
    }

    /// Record a successful request
    pub fn record_success(&self) {
        // Single atomic load with immediate pattern matching
        match &**self.state.load() {
            CircuitState::Closed => {
                // Reset failure count on success
                self.failure_count.store(0, Ordering::Relaxed);
            }
            CircuitState::HalfOpen => {
                let success_count = self.success_count.fetch_add(1, Ordering::Relaxed);
                if success_count + 1 >= self.recovery_threshold {
                    // Transition back to closed
                    self.state.store(Arc::new(CircuitState::Closed));
                    self.failure_count.store(0, Ordering::Relaxed);
                    self.success_count.store(0, Ordering::Relaxed);
                }
            }
            CircuitState::Open => {
                // Ignore successes when open (shouldn't happen)
            }
        }
    }

    /// Record a failed request
    pub fn record_failure(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_failure_time.store(now, Ordering::Relaxed);

        // Single atomic load with immediate pattern matching
        match &**self.state.load() {
            CircuitState::Closed => {
                let failure_count = self.failure_count.fetch_add(1, Ordering::Relaxed);
                if failure_count + 1 >= self.failure_threshold {
                    // Transition to open
                    self.state.store(Arc::new(CircuitState::Open));
                }
            }
            CircuitState::HalfOpen => {
                // Transition back to open on any failure
                self.state.store(Arc::new(CircuitState::Open));
                self.success_count.store(0, Ordering::Relaxed);
            }
            CircuitState::Open => {
                // Already open, just update failure time
            }
        }
    }

    /// Get current circuit state
    pub fn get_state(&self) -> CircuitState {
        **self.state.load()
    }

    /// Check if circuit is available (closed or half-open)
    pub fn is_available(&self) -> bool {
        matches!(
            self.get_state(),
            CircuitState::Closed | CircuitState::HalfOpen
        )
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new(5, 3, 60) // 5 failures, 3 recovery attempts, 60 second timeout
    }
}

/// Upstream server representation with circuit breaker
#[derive(Debug)]
pub struct UpstreamServer {
    /// Server address
    pub address: String,
    /// Server weight (for weighted algorithms)
    pub weight: u32,
    /// Whether to use TLS
    pub tls: bool,
    /// SNI hostname for TLS connections
    pub sni_hostname: Option<String>,
    /// Maximum concurrent connections
    pub max_connections: Option<usize>,
    /// Current connection count
    pub current_connections: AtomicUsize,
    /// Whether the server is healthy
    pub healthy: ArcSwap<bool>,
    /// Circuit breaker for resilience
    pub circuit_breaker: CircuitBreaker,
    /// TCP keepalive configuration
    pub tcp_keepalive: Option<TcpKeepaliveConfig>,
    /// Connection timeout
    pub connection_timeout: Duration,
    /// Read timeout
    pub read_timeout: Duration,
    /// Write timeout
    pub write_timeout: Duration,
}

impl UpstreamServer {
    /// Create a new upstream server
    pub fn new(config: &UpstreamConfig) -> Self {
        Self {
            address: config.address.clone(),
            weight: config.weight,
            tls: config.tls,
            sni_hostname: config.sni_hostname.clone(),
            max_connections: config.max_connections,
            current_connections: AtomicUsize::new(0),
            healthy: ArcSwap::new(Arc::new(true)),
            circuit_breaker: CircuitBreaker::default(),
            tcp_keepalive: config.tcp_keepalive.clone(),
            connection_timeout: config.connection_timeout,
            read_timeout: config.read_timeout,
            write_timeout: config.write_timeout,
        }
    }

    /// Check if the server can accept new connections
    pub fn can_accept_connection(&self) -> bool {
        // Check health status
        if !**self.healthy.load() {
            return false;
        }

        // Check circuit breaker
        if !self.circuit_breaker.should_allow_request() {
            return false;
        }

        // Check connection limit
        if let Some(max_conn) = self.max_connections {
            self.current_connections.load(Ordering::Relaxed) < max_conn
        } else {
            true
        }
    }

    /// Increment connection count
    pub fn increment_connections(&self) {
        self.current_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement connection count
    pub fn decrement_connections(&self) {
        self.current_connections.fetch_sub(1, Ordering::Relaxed);
    }

    /// Mark server as healthy
    pub fn mark_healthy(&self) {
        self.healthy.store(Arc::new(true));
    }

    /// Mark server as unhealthy
    pub fn mark_unhealthy(&self) {
        self.healthy.store(Arc::new(false));
    }

    /// Check if server is healthy
    pub fn is_healthy(&self) -> bool {
        **self.healthy.load()
    }

    /// Convert to HttpPeer for Pingora with connection pooling optimizations
    pub fn to_http_peer(&self) -> HttpPeer {
        let sni = self.sni_hostname.as_deref().unwrap_or(&self.address);
        let mut peer = HttpPeer::new(&self.address, self.tls, sni.to_string());

        // Use configured timeouts
        peer.options.connection_timeout = Some(self.connection_timeout);
        peer.options.total_connection_timeout = Some(self.connection_timeout * 2);
        peer.options.read_timeout = Some(self.read_timeout);
        peer.options.write_timeout = Some(self.write_timeout);

        // Configure TCP keepalive if enabled
        if let Some(keepalive_config) = &self.tcp_keepalive {
            if keepalive_config.enabled {
                let tcp_keepalive = TcpKeepalive {
                    idle: keepalive_config.idle,
                    interval: keepalive_config.interval,
                    count: keepalive_config.count as usize,
                    #[cfg(target_os = "linux")]
                    user_timeout: Duration::from_secs(0), // Use system default
                };
                peer.options.tcp_keepalive = Some(tcp_keepalive);
            }
        }

        // Optimize buffer sizes
        peer.options.tcp_recv_buf = Some(65536); // 64KB

        peer
    }
}

/// Round-robin load balancing strategy with cached healthy upstreams
pub struct RoundRobinStrategy {
    upstreams: ArcSwap<Vec<Arc<UpstreamServer>>>,
    healthy_cache: ArcSwap<Vec<Arc<UpstreamServer>>>,
    counter: AtomicUsize,
    cache_generation: AtomicUsize,
}

impl RoundRobinStrategy {
    pub fn new(upstreams: Vec<Arc<UpstreamServer>>) -> Self {
        let healthy_upstreams: Vec<Arc<UpstreamServer>> = upstreams
            .iter()
            .filter(|upstream| upstream.can_accept_connection())
            .cloned()
            .collect();

        Self {
            upstreams: ArcSwap::new(Arc::new(upstreams)),
            healthy_cache: ArcSwap::new(Arc::new(healthy_upstreams)),
            counter: AtomicUsize::new(0),
            cache_generation: AtomicUsize::new(0),
        }
    }

    /// Update healthy cache periodically
    fn update_healthy_cache(&self) {
        let upstreams = self.upstreams.load();
        let healthy_upstreams: Vec<Arc<UpstreamServer>> = upstreams
            .iter()
            .filter(|upstream| upstream.can_accept_connection())
            .cloned()
            .collect();

        self.healthy_cache.store(Arc::new(healthy_upstreams));
        self.cache_generation.fetch_add(1, Ordering::Relaxed);
    }
}

impl LoadBalancingStrategy for RoundRobinStrategy {
    fn select(&self, _key: &[u8]) -> Option<Arc<UpstreamServer>> {
        // Use cached healthy upstreams for better performance
        let healthy_upstreams = self.healthy_cache.load();

        if healthy_upstreams.is_empty() {
            // Fallback: update cache and try again
            self.update_healthy_cache();
            let updated_healthy = self.healthy_cache.load();
            if updated_healthy.is_empty() {
                return None;
            }
            let index = self.counter.fetch_add(1, Ordering::Relaxed) % updated_healthy.len();
            return Some(updated_healthy[index].clone());
        }

        let index = self.counter.fetch_add(1, Ordering::Relaxed) % healthy_upstreams.len();

        // Double-check the selected upstream is still healthy
        let selected = &healthy_upstreams[index];
        if selected.can_accept_connection() {
            Some(selected.clone())
        } else {
            // Cache is stale, update it
            self.update_healthy_cache();
            let updated_healthy = self.healthy_cache.load();
            if updated_healthy.is_empty() {
                None
            } else {
                let new_index = index % updated_healthy.len();
                Some(updated_healthy[new_index].clone())
            }
        }
    }

    fn update_upstreams(&self, upstreams: Vec<Arc<UpstreamServer>>) {
        self.upstreams.store(Arc::new(upstreams));
        // Immediately update healthy cache when upstreams change
        self.update_healthy_cache();
    }

    fn get_upstreams(&self) -> Vec<Arc<UpstreamServer>> {
        (*self.upstreams.load()).to_vec()
    }
}

/// Least connections load balancing strategy
pub struct LeastConnectionsStrategy {
    upstreams: ArcSwap<Vec<Arc<UpstreamServer>>>,
}

impl LeastConnectionsStrategy {
    pub fn new(upstreams: Vec<Arc<UpstreamServer>>) -> Self {
        Self {
            upstreams: ArcSwap::new(Arc::new(upstreams)),
        }
    }
}

impl LoadBalancingStrategy for LeastConnectionsStrategy {
    fn select(&self, _key: &[u8]) -> Option<Arc<UpstreamServer>> {
        let upstreams = self.upstreams.load();
        upstreams
            .iter()
            .filter(|upstream| upstream.can_accept_connection())
            .min_by_key(|upstream| upstream.current_connections.load(Ordering::Relaxed))
            .cloned()
    }

    fn update_upstreams(&self, upstreams: Vec<Arc<UpstreamServer>>) {
        self.upstreams.store(Arc::new(upstreams));
    }

    fn get_upstreams(&self) -> Vec<Arc<UpstreamServer>> {
        (*self.upstreams.load()).to_vec()
    }
}

/// Weighted round-robin load balancing strategy using cumulative weights
pub struct WeightedRoundRobinStrategy {
    upstreams: ArcSwap<Vec<Arc<UpstreamServer>>>,
    cumulative_weights: ArcSwap<Vec<(Arc<UpstreamServer>, u32)>>,
    total_weight: AtomicUsize,
    counter: AtomicUsize,
}

impl WeightedRoundRobinStrategy {
    pub fn new(upstreams: Vec<Arc<UpstreamServer>>) -> Self {
        let (cumulative_weights, total_weight) = Self::build_cumulative_weights(&upstreams);
        Self {
            upstreams: ArcSwap::new(Arc::new(upstreams)),
            cumulative_weights: ArcSwap::new(Arc::new(cumulative_weights)),
            total_weight: AtomicUsize::new(total_weight as usize),
            counter: AtomicUsize::new(0),
        }
    }

    /// Build cumulative weights for efficient weighted selection
    fn build_cumulative_weights(
        upstreams: &[Arc<UpstreamServer>],
    ) -> (Vec<(Arc<UpstreamServer>, u32)>, u32) {
        let mut cumulative_weights = Vec::with_capacity(upstreams.len());
        let mut cumulative_weight = 0u32;

        for upstream in upstreams {
            cumulative_weight += upstream.weight;
            cumulative_weights.push((upstream.clone(), cumulative_weight));
        }

        (cumulative_weights, cumulative_weight)
    }
}

impl LoadBalancingStrategy for WeightedRoundRobinStrategy {
    fn select(&self, _key: &[u8]) -> Option<Arc<UpstreamServer>> {
        let cumulative_weights = self.cumulative_weights.load();
        let total_weight = self.total_weight.load(Ordering::Relaxed);

        if total_weight == 0 || cumulative_weights.is_empty() {
            return None;
        }

        // Filter healthy upstreams and recalculate weights if needed
        let healthy_upstreams: Vec<_> = cumulative_weights
            .iter()
            .filter(|(upstream, _)| upstream.can_accept_connection())
            .collect();

        if healthy_upstreams.is_empty() {
            return None;
        }

        // Calculate total weight of healthy upstreams
        let healthy_total_weight = healthy_upstreams
            .iter()
            .map(|(upstream, _)| upstream.weight)
            .sum::<u32>();

        if healthy_total_weight == 0 {
            return None;
        }

        // Use counter modulo total weight for selection
        let target_weight =
            (self.counter.fetch_add(1, Ordering::Relaxed) as u32) % healthy_total_weight;
        let mut current_weight = 0u32;

        for (upstream, _) in &healthy_upstreams {
            current_weight += upstream.weight;
            if target_weight < current_weight {
                return Some(upstream.clone());
            }
        }

        // Fallback to first healthy upstream
        healthy_upstreams
            .first()
            .map(|(upstream, _)| upstream.clone())
    }

    fn update_upstreams(&self, upstreams: Vec<Arc<UpstreamServer>>) {
        let (cumulative_weights, total_weight) = Self::build_cumulative_weights(&upstreams);
        self.upstreams.store(Arc::new(upstreams));
        self.cumulative_weights.store(Arc::new(cumulative_weights));
        self.total_weight
            .store(total_weight as usize, Ordering::Relaxed);
    }

    fn get_upstreams(&self) -> Vec<Arc<UpstreamServer>> {
        (*self.upstreams.load()).to_vec()
    }
}

/// IP hash load balancing strategy with cached healthy upstreams
pub struct IpHashStrategy {
    upstreams: ArcSwap<Vec<Arc<UpstreamServer>>>,
    healthy_cache: ArcSwap<Vec<Arc<UpstreamServer>>>,
}

impl IpHashStrategy {
    pub fn new(upstreams: Vec<Arc<UpstreamServer>>) -> Self {
        let healthy_upstreams: Vec<Arc<UpstreamServer>> = upstreams
            .iter()
            .filter(|upstream| upstream.can_accept_connection())
            .cloned()
            .collect();

        Self {
            upstreams: ArcSwap::new(Arc::new(upstreams)),
            healthy_cache: ArcSwap::new(Arc::new(healthy_upstreams)),
        }
    }

    /// Update healthy cache periodically
    fn update_healthy_cache(&self) {
        let upstreams = self.upstreams.load();
        let healthy_upstreams: Vec<Arc<UpstreamServer>> = upstreams
            .iter()
            .filter(|upstream| upstream.can_accept_connection())
            .cloned()
            .collect();

        self.healthy_cache.store(Arc::new(healthy_upstreams));
    }

    /// Hash the IP address to select an upstream
    fn hash_key(key: &[u8]) -> u64 {
        let mut hasher = ahash::AHasher::default();
        key.hash(&mut hasher);
        hasher.finish()
    }
}

impl LoadBalancingStrategy for IpHashStrategy {
    fn select(&self, key: &[u8]) -> Option<Arc<UpstreamServer>> {
        // Use cached healthy upstreams for better performance
        let healthy_upstreams = self.healthy_cache.load();

        if healthy_upstreams.is_empty() {
            // Fallback: update cache and try again
            self.update_healthy_cache();
            let healthy_upstreams = self.healthy_cache.load();
            if healthy_upstreams.is_empty() {
                return None;
            }
        }

        let hash = Self::hash_key(key);
        let index = (hash as usize) % healthy_upstreams.len();
        Some(healthy_upstreams[index].clone())
    }

    fn update_upstreams(&self, upstreams: Vec<Arc<UpstreamServer>>) {
        self.upstreams.store(Arc::new(upstreams));
        // Immediately update healthy cache when upstreams change
        self.update_healthy_cache();
    }

    fn get_upstreams(&self) -> Vec<Arc<UpstreamServer>> {
        (*self.upstreams.load()).to_vec()
    }
}

/// Consistent hashing load balancing strategy
pub struct ConsistentHashStrategy {
    upstreams: ArcSwap<Vec<Arc<UpstreamServer>>>,
    hash_ring: ArcSwap<Vec<(u64, Arc<UpstreamServer>)>>,
    virtual_nodes: u32,
}

impl ConsistentHashStrategy {
    pub fn new(upstreams: Vec<Arc<UpstreamServer>>) -> Self {
        let virtual_nodes = 150; // Default number of virtual nodes per server
        let hash_ring = Self::build_hash_ring(&upstreams, virtual_nodes);
        Self {
            upstreams: ArcSwap::new(Arc::new(upstreams)),
            hash_ring: ArcSwap::new(Arc::new(hash_ring)),
            virtual_nodes,
        }
    }

    /// Build hash ring with virtual nodes for better distribution
    fn build_hash_ring(
        upstreams: &[Arc<UpstreamServer>],
        virtual_nodes: u32,
    ) -> Vec<(u64, Arc<UpstreamServer>)> {
        let mut hash_ring = Vec::new();

        for upstream in upstreams {
            // Create virtual nodes based on weight
            let node_count = virtual_nodes * upstream.weight;
            for i in 0..node_count {
                let virtual_key = format!("{}:{}", upstream.address, i);
                let hash = Self::hash_key(virtual_key.as_bytes());
                hash_ring.push((hash, upstream.clone()));
            }
        }

        // Sort by hash value for binary search
        hash_ring.sort_by_key(|(hash, _)| *hash);
        hash_ring
    }

    /// Hash function using AHash for consistency
    fn hash_key(key: &[u8]) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = ahash::AHasher::default();
        key.hash(&mut hasher);
        hasher.finish()
    }

    /// Find the next available server on the hash ring
    fn find_server(
        ring: &[(u64, Arc<UpstreamServer>)],
        key_hash: u64,
    ) -> Option<Arc<UpstreamServer>> {
        if ring.is_empty() {
            return None;
        }

        // Binary search for the first server with hash >= key_hash
        let mut left = 0;
        let mut right = ring.len();

        while left < right {
            let mid = left + (right - left) / 2;
            if ring[mid].0 < key_hash {
                left = mid + 1;
            } else {
                right = mid;
            }
        }

        // Wrap around if we reached the end
        let index = if left >= ring.len() { 0 } else { left };

        // Find the next healthy server starting from this position
        for i in 0..ring.len() {
            let idx = (index + i) % ring.len();
            let (_, server) = &ring[idx];
            if server.can_accept_connection() {
                return Some(server.clone());
            }
        }

        None
    }
}

impl LoadBalancingStrategy for ConsistentHashStrategy {
    fn select(&self, key: &[u8]) -> Option<Arc<UpstreamServer>> {
        let hash_ring = self.hash_ring.load();
        let key_hash = Self::hash_key(key);
        Self::find_server(&hash_ring, key_hash)
    }

    fn update_upstreams(&self, upstreams: Vec<Arc<UpstreamServer>>) {
        let hash_ring = Self::build_hash_ring(&upstreams, self.virtual_nodes);
        self.upstreams.store(Arc::new(upstreams));
        self.hash_ring.store(Arc::new(hash_ring));
    }

    fn get_upstreams(&self) -> Vec<Arc<UpstreamServer>> {
        (*self.upstreams.load()).to_vec()
    }
}

/// Random load balancing strategy with cached healthy upstreams
pub struct RandomStrategy {
    upstreams: ArcSwap<Vec<Arc<UpstreamServer>>>,
    healthy_cache: ArcSwap<Vec<Arc<UpstreamServer>>>,
}

impl RandomStrategy {
    pub fn new(upstreams: Vec<Arc<UpstreamServer>>) -> Self {
        let healthy_upstreams: Vec<Arc<UpstreamServer>> = upstreams
            .iter()
            .filter(|upstream| upstream.can_accept_connection())
            .cloned()
            .collect();

        Self {
            upstreams: ArcSwap::new(Arc::new(upstreams)),
            healthy_cache: ArcSwap::new(Arc::new(healthy_upstreams)),
        }
    }

    /// Update healthy cache periodically
    fn update_healthy_cache(&self) {
        let upstreams = self.upstreams.load();
        let healthy_upstreams: Vec<Arc<UpstreamServer>> = upstreams
            .iter()
            .filter(|upstream| upstream.can_accept_connection())
            .cloned()
            .collect();

        self.healthy_cache.store(Arc::new(healthy_upstreams));
    }
}

impl LoadBalancingStrategy for RandomStrategy {
    fn select(&self, _key: &[u8]) -> Option<Arc<UpstreamServer>> {
        // Use cached healthy upstreams for better performance
        let healthy_upstreams = self.healthy_cache.load();

        if healthy_upstreams.is_empty() {
            // Fallback: update cache and try again
            self.update_healthy_cache();
            let healthy_upstreams = self.healthy_cache.load();
            if healthy_upstreams.is_empty() {
                return None;
            }
        }

        let index = rand::random::<usize>() % healthy_upstreams.len();
        Some(healthy_upstreams[index].clone())
    }

    fn update_upstreams(&self, upstreams: Vec<Arc<UpstreamServer>>) {
        self.upstreams.store(Arc::new(upstreams));
        // Immediately update healthy cache when upstreams change
        self.update_healthy_cache();
    }

    fn get_upstreams(&self) -> Vec<Arc<UpstreamServer>> {
        (*self.upstreams.load()).to_vec()
    }
}

/// Backend manager that handles multiple load balancing strategies
pub struct BackendManager {
    backends: DashMap<String, Arc<dyn LoadBalancingStrategy>>,
}

impl Default for BackendManager {
    fn default() -> Self {
        Self::new()
    }
}

impl BackendManager {
    /// Create a new backend manager
    pub fn new() -> Self {
        Self {
            backends: DashMap::new(),
        }
    }

    /// Add or update a backend
    pub fn add_backend(&self, name: String, config: &BackendConfig) -> Result<()> {
        let upstreams: Vec<Arc<UpstreamServer>> = config
            .upstreams
            .iter()
            .map(|upstream_config| Arc::new(UpstreamServer::new(upstream_config)))
            .collect();

        if upstreams.is_empty() {
            return Err(anyhow!("Backend '{}' has no upstream servers", name));
        }

        let algorithm = config
            .algorithm
            .as_ref()
            .unwrap_or(&LoadBalancingAlgorithm::RoundRobin);

        let strategy: Arc<dyn LoadBalancingStrategy> = match algorithm {
            LoadBalancingAlgorithm::RoundRobin => Arc::new(RoundRobinStrategy::new(upstreams)),
            LoadBalancingAlgorithm::LeastConnections => {
                Arc::new(LeastConnectionsStrategy::new(upstreams))
            }
            LoadBalancingAlgorithm::WeightedRoundRobin => {
                Arc::new(WeightedRoundRobinStrategy::new(upstreams))
            }
            LoadBalancingAlgorithm::IpHash => Arc::new(IpHashStrategy::new(upstreams)),
            LoadBalancingAlgorithm::ConsistentHash => {
                Arc::new(ConsistentHashStrategy::new(upstreams))
            }
            LoadBalancingAlgorithm::Random => Arc::new(RandomStrategy::new(upstreams)),
        };

        self.backends.insert(name, strategy);
        Ok(())
    }

    /// Remove a backend
    pub fn remove_backend(&self, name: &str) {
        self.backends.remove(name);
    }

    /// Get a backend strategy
    pub fn get_backend(&self, name: &str) -> Option<Arc<dyn LoadBalancingStrategy>> {
        self.backends.get(name).map(|entry| entry.value().clone())
    }

    /// Select an upstream server from a backend
    pub fn select_upstream(&self, backend_name: &str, key: &[u8]) -> Option<Arc<UpstreamServer>> {
        self.get_backend(backend_name)?.select(key)
    }

    /// Update upstreams for a backend
    pub fn update_backend_upstreams(
        &self,
        backend_name: &str,
        upstreams: Vec<Arc<UpstreamServer>>,
    ) {
        if let Some(backend) = self.get_backend(backend_name) {
            backend.update_upstreams(upstreams);
        }
    }

    /// Get all backend names
    pub fn get_backend_names(&self) -> Vec<String> {
        self.backends
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Get upstreams for a backend
    pub fn get_backend_upstreams(&self, backend_name: &str) -> Vec<Arc<UpstreamServer>> {
        self.get_backend(backend_name)
            .map(|backend| backend.get_upstreams())
            .unwrap_or_default()
    }
}
