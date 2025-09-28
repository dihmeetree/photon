/// High-performance load balancing implementation using Pingora
use anyhow::{anyhow, Result};
use arc_swap::ArcSwap;
use dashmap::DashMap;
use pingora_core::upstreams::peer::HttpPeer;
use std::hash::{Hash, Hasher};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use crate::config::{BackendConfig, LoadBalancingAlgorithm, UpstreamConfig};

/// Trait for load balancing strategies
pub trait LoadBalancingStrategy: Send + Sync {
    /// Select an upstream server for the given request
    fn select(&self, key: &[u8]) -> Option<Arc<UpstreamServer>>;

    /// Update the list of available upstream servers
    fn update_upstreams(&self, upstreams: Vec<Arc<UpstreamServer>>);

    /// Get current upstream servers
    fn get_upstreams(&self) -> Vec<Arc<UpstreamServer>>;
}

/// Upstream server representation
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
        }
    }

    /// Check if the server can accept new connections
    pub fn can_accept_connection(&self) -> bool {
        if !**self.healthy.load() {
            return false;
        }

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

    /// Convert to HttpPeer for Pingora
    pub fn to_http_peer(&self) -> HttpPeer {
        let sni = self.sni_hostname.as_deref().unwrap_or(&self.address);
        HttpPeer::new(&self.address, self.tls, sni.to_string())
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

/// Weighted round-robin load balancing strategy
pub struct WeightedRoundRobinStrategy {
    upstreams: ArcSwap<Vec<Arc<UpstreamServer>>>,
    weighted_list: ArcSwap<Vec<Arc<UpstreamServer>>>,
    counter: AtomicUsize,
}

impl WeightedRoundRobinStrategy {
    pub fn new(upstreams: Vec<Arc<UpstreamServer>>) -> Self {
        let weighted_list = Self::build_weighted_list(&upstreams);
        Self {
            upstreams: ArcSwap::new(Arc::new(upstreams)),
            weighted_list: ArcSwap::new(Arc::new(weighted_list)),
            counter: AtomicUsize::new(0),
        }
    }

    /// Build a weighted list where each upstream appears according to its weight
    fn build_weighted_list(upstreams: &[Arc<UpstreamServer>]) -> Vec<Arc<UpstreamServer>> {
        let mut weighted_list = Vec::new();
        for upstream in upstreams {
            for _ in 0..upstream.weight {
                weighted_list.push(upstream.clone());
            }
        }
        weighted_list
    }
}

impl LoadBalancingStrategy for WeightedRoundRobinStrategy {
    fn select(&self, _key: &[u8]) -> Option<Arc<UpstreamServer>> {
        let weighted_list = self.weighted_list.load();
        let healthy_list: Vec<_> = weighted_list
            .iter()
            .filter(|upstream| upstream.can_accept_connection())
            .collect();

        if healthy_list.is_empty() {
            return None;
        }

        let index = self.counter.fetch_add(1, Ordering::Relaxed) % healthy_list.len();
        Some(healthy_list[index].clone())
    }

    fn update_upstreams(&self, upstreams: Vec<Arc<UpstreamServer>>) {
        let weighted_list = Self::build_weighted_list(&upstreams);
        self.upstreams.store(Arc::new(upstreams));
        self.weighted_list.store(Arc::new(weighted_list));
    }

    fn get_upstreams(&self) -> Vec<Arc<UpstreamServer>> {
        (*self.upstreams.load()).to_vec()
    }
}

/// IP hash load balancing strategy
pub struct IpHashStrategy {
    upstreams: ArcSwap<Vec<Arc<UpstreamServer>>>,
}

impl IpHashStrategy {
    pub fn new(upstreams: Vec<Arc<UpstreamServer>>) -> Self {
        Self {
            upstreams: ArcSwap::new(Arc::new(upstreams)),
        }
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
        let upstreams = self.upstreams.load();
        let healthy_upstreams: Vec<_> = upstreams
            .iter()
            .filter(|upstream| upstream.can_accept_connection())
            .collect();

        if healthy_upstreams.is_empty() {
            return None;
        }

        let hash = Self::hash_key(key);
        let index = (hash as usize) % healthy_upstreams.len();
        Some(healthy_upstreams[index].clone())
    }

    fn update_upstreams(&self, upstreams: Vec<Arc<UpstreamServer>>) {
        self.upstreams.store(Arc::new(upstreams));
    }

    fn get_upstreams(&self) -> Vec<Arc<UpstreamServer>> {
        (*self.upstreams.load()).to_vec()
    }
}

/// Random load balancing strategy
pub struct RandomStrategy {
    upstreams: ArcSwap<Vec<Arc<UpstreamServer>>>,
}

impl RandomStrategy {
    pub fn new(upstreams: Vec<Arc<UpstreamServer>>) -> Self {
        Self {
            upstreams: ArcSwap::new(Arc::new(upstreams)),
        }
    }
}

impl LoadBalancingStrategy for RandomStrategy {
    fn select(&self, _key: &[u8]) -> Option<Arc<UpstreamServer>> {
        let upstreams = self.upstreams.load();
        let healthy_upstreams: Vec<_> = upstreams
            .iter()
            .filter(|upstream| upstream.can_accept_connection())
            .collect();

        if healthy_upstreams.is_empty() {
            return None;
        }

        let index = rand::random::<usize>() % healthy_upstreams.len();
        Some(healthy_upstreams[index].clone())
    }

    fn update_upstreams(&self, upstreams: Vec<Arc<UpstreamServer>>) {
        self.upstreams.store(Arc::new(upstreams));
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
