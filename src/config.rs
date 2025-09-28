/// Configuration management for the API Gateway
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

/// Main configuration structure for the API Gateway
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Server configuration
    pub server: ServerConfig,
    /// Load balancing configuration
    pub load_balancing: LoadBalancingConfig,
    /// Route configurations
    pub routes: Vec<RouteConfig>,
    /// Middleware configurations
    pub middleware: MiddlewareConfig,
    /// Health check configuration
    pub health_check: HealthCheckConfig,
    /// Metrics and monitoring configuration
    pub metrics: MetricsConfig,
    /// Response caching configuration
    #[serde(default = "default_cache_config")]
    pub cache: CacheConfig,
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// HTTP listening address
    pub http_addr: SocketAddr,
    /// HTTPS listening address (optional)
    pub https_addr: Option<SocketAddr>,
    /// TLS certificate file path (required if https_addr is set)
    pub tls_cert: Option<String>,
    /// TLS private key file path (required if https_addr is set)
    pub tls_key: Option<String>,
    /// Connection timeout
    #[serde(with = "humantime_serde")]
    pub connection_timeout: Duration,
    /// Maximum concurrent connections
    pub max_connections: Option<usize>,
    /// Upgrade socket path for zero downtime reloads
    #[serde(default = "default_upgrade_sock")]
    pub upgrade_sock: String,
}

/// Load balancing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancingConfig {
    /// Default load balancing algorithm
    pub algorithm: LoadBalancingAlgorithm,
    /// Backend servers configuration
    pub backends: HashMap<String, BackendConfig>,
}

/// Load balancing algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancingAlgorithm {
    /// Round-robin algorithm
    RoundRobin,
    /// Least connections algorithm
    LeastConnections,
    /// Weighted round-robin algorithm
    WeightedRoundRobin,
    /// IP hash algorithm
    IpHash,
    /// Consistent hashing algorithm
    ConsistentHash,
    /// Random algorithm
    Random,
}

/// Backend server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    /// List of upstream servers
    pub upstreams: Vec<UpstreamConfig>,
    /// Health check settings for this backend
    pub health_check: Option<BackendHealthCheckConfig>,
    /// Load balancing algorithm override
    pub algorithm: Option<LoadBalancingAlgorithm>,
}

/// TCP keepalive configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpKeepaliveConfig {
    /// Enable TCP keepalive
    #[serde(default)]
    pub enabled: bool,
    /// Time before sending keepalive probes
    #[serde(with = "humantime_serde", default = "default_keepalive_idle")]
    pub idle: Duration,
    /// Interval between keepalive probes
    #[serde(with = "humantime_serde", default = "default_keepalive_interval")]
    pub interval: Duration,
    /// Number of failed probes before connection is dropped
    #[serde(default = "default_keepalive_count")]
    pub count: u32,
}

/// Upstream server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    /// Server address
    pub address: String,
    /// Server weight (for weighted algorithms)
    #[serde(default = "default_weight")]
    pub weight: u32,
    /// Whether to use TLS for connections to this upstream
    #[serde(default)]
    pub tls: bool,
    /// SNI hostname for TLS connections
    pub sni_hostname: Option<String>,
    /// Maximum concurrent connections to this upstream
    pub max_connections: Option<usize>,
    /// TCP keepalive configuration
    pub tcp_keepalive: Option<TcpKeepaliveConfig>,
    /// Connection timeout
    #[serde(with = "humantime_serde", default = "default_connection_timeout")]
    pub connection_timeout: Duration,
    /// Read timeout
    #[serde(with = "humantime_serde", default = "default_read_timeout")]
    pub read_timeout: Duration,
    /// Write timeout
    #[serde(with = "humantime_serde", default = "default_write_timeout")]
    pub write_timeout: Duration,
}

/// Route configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    /// Route identifier
    pub id: String,
    /// Path pattern (supports regex)
    pub path: String,
    /// HTTP methods to match
    pub methods: Option<Vec<String>>,
    /// Host header to match
    pub host: Option<String>,
    /// Backend to route to
    pub backend: String,
    /// Route-specific middleware
    pub middleware: Option<Vec<String>>,
    /// Request timeout
    #[serde(with = "humantime_serde")]
    pub timeout: Option<Duration>,
    /// Number of retries
    pub retries: Option<u32>,
    /// WebSocket configuration
    pub websocket: Option<WebSocketConfig>,
    /// Route-specific cache configuration
    pub cache: Option<RouteCacheConfig>,
}

/// WebSocket-specific configuration for routes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketConfig {
    /// Enable WebSocket proxying for this route
    pub enabled: bool,
    /// Allowed WebSocket protocols (subprotocols)
    pub protocols: Option<Vec<String>>,
    /// WebSocket-specific timeout (overrides route timeout)
    #[serde(with = "humantime_serde")]
    pub timeout: Option<Duration>,
    /// Idle timeout for WebSocket connections
    #[serde(with = "humantime_serde")]
    pub idle_timeout: Option<Duration>,
    /// Maximum message size in bytes
    pub max_message_size: Option<usize>,
}

/// Middleware configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiddlewareConfig {
    /// Rate limiting configuration
    pub rate_limiting: Option<RateLimitingConfig>,
    /// Authentication configuration
    pub authentication: Option<AuthenticationConfig>,
    /// CORS configuration
    pub cors: Option<CorsConfig>,
    /// Request/response modification
    pub transform: Option<TransformConfig>,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitingConfig {
    /// Requests per second limit
    pub requests_per_second: u32,
    /// Burst capacity
    pub burst: Option<u32>,
    /// Rate limiting key (ip, header, etc.)
    pub key: RateLimitingKey,
}

/// Rate limiting key types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitingKey {
    /// Limit by client IP address
    Ip,
    /// Limit by header value
    Header(String),
    /// Limit by query parameter
    QueryParam(String),
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationConfig {
    /// Authentication type
    pub auth_type: AuthenticationType,
    /// JWT configuration (if using JWT)
    pub jwt: Option<JwtConfig>,
    /// API key configuration (if using API keys)
    pub api_key: Option<ApiKeyConfig>,
}

/// Authentication types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationType {
    /// JSON Web Token authentication
    Jwt,
    /// API key authentication
    ApiKey,
    /// Basic authentication
    Basic,
}

/// JWT configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    /// JWT secret or public key
    pub secret: String,
    /// JWT algorithm
    pub algorithm: String,
    /// Token header name
    #[serde(default = "default_jwt_header")]
    pub header: String,
}

/// API key configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyConfig {
    /// Valid API keys
    pub keys: Vec<String>,
    /// API key header name
    #[serde(default = "default_api_key_header")]
    pub header: String,
}

/// CORS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfig {
    /// Allowed origins
    pub allowed_origins: Vec<String>,
    /// Allowed methods
    pub allowed_methods: Vec<String>,
    /// Allowed headers
    pub allowed_headers: Vec<String>,
    /// Maximum age for preflight requests
    #[serde(with = "humantime_serde")]
    pub max_age: Option<Duration>,
}

/// Request/response transformation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformConfig {
    /// Request header modifications
    pub request_headers: Option<HeaderTransformConfig>,
    /// Response header modifications
    pub response_headers: Option<HeaderTransformConfig>,
}

/// Header transformation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderTransformConfig {
    /// Headers to add
    pub add: Option<HashMap<String, String>>,
    /// Headers to remove
    pub remove: Option<Vec<String>>,
    /// Headers to set (overwrite)
    pub set: Option<HashMap<String, String>>,
}

/// Health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// Global health check interval
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    /// Health check timeout
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
    /// Number of consecutive failures before marking unhealthy
    pub failure_threshold: u32,
    /// Number of consecutive successes before marking healthy
    pub success_threshold: u32,
}

/// Backend-specific health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendHealthCheckConfig {
    /// Health check type
    pub check_type: HealthCheckType,
    /// Health check path (for HTTP checks)
    pub path: Option<String>,
    /// Expected status code (for HTTP checks)
    pub expected_status: Option<u16>,
    /// Custom interval for this backend
    #[serde(with = "humantime_serde")]
    pub interval: Option<Duration>,
}

/// Health check types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthCheckType {
    /// TCP connection health check
    Tcp,
    /// HTTP health check
    Http,
    /// HTTPS health check
    Https,
}

/// Metrics and monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Enable Prometheus metrics
    pub prometheus: bool,
    /// Prometheus metrics endpoint
    #[serde(default = "default_metrics_path")]
    pub metrics_path: String,
    /// Metrics server address
    pub metrics_addr: Option<SocketAddr>,
    /// Enable detailed request metrics
    pub detailed_metrics: bool,
}

/// Response caching configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Enable response caching
    pub enabled: bool,
    /// Maximum number of entries in cache
    #[serde(default = "default_max_cache_entries")]
    pub max_entries: usize,
    /// Default TTL for cached responses (seconds)
    #[serde(with = "humantime_serde", default = "default_cache_ttl")]
    pub default_ttl: Duration,
    /// Maximum size of cacheable response body
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,
    /// Whether to cache responses with query parameters
    #[serde(default)]
    pub cache_with_query_params: bool,
}

/// Route-specific cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteCacheConfig {
    /// Enable caching for this route (overrides global setting)
    pub enabled: bool,
    /// Route-specific TTL (overrides global default_ttl)
    #[serde(with = "humantime_serde")]
    pub ttl: Option<Duration>,
    /// Route-specific max body size (overrides global max_body_size)
    pub max_body_size: Option<usize>,
    /// Route-specific query parameter caching (overrides global setting)
    pub cache_with_query_params: Option<bool>,
    /// HTTP methods to cache for this route (defaults to ["GET"])
    pub methods: Option<Vec<String>>,
}

impl Config {
    /// Load configuration from a file
    pub fn from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path))?;

        let config = if path.ends_with(".yaml") || path.ends_with(".yml") {
            serde_yaml::from_str(&content)
                .with_context(|| format!("Failed to parse YAML config file: {}", path))?
        } else if path.ends_with(".toml") {
            toml::from_str(&content)
                .with_context(|| format!("Failed to parse TOML config file: {}", path))?
        } else if path.ends_with(".json") {
            serde_json::from_str(&content)
                .with_context(|| format!("Failed to parse JSON config file: {}", path))?
        } else {
            return Err(anyhow::anyhow!(
                "Unsupported config file format. Supported formats: .yaml, .yml, .toml, .json"
            ));
        };

        Ok(config)
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        // Validate server configuration
        if let Some(_https_addr) = &self.server.https_addr {
            if self.server.tls_cert.is_none() || self.server.tls_key.is_none() {
                return Err(anyhow::anyhow!(
                    "TLS certificate and key must be provided when HTTPS is enabled"
                ));
            }
        }

        // Validate routes reference existing backends
        for route in &self.routes {
            if !self.load_balancing.backends.contains_key(&route.backend) {
                return Err(anyhow::anyhow!(
                    "Route '{}' references non-existent backend '{}'",
                    route.id,
                    route.backend
                ));
            }
        }

        // Validate backends have at least one upstream
        for (name, backend) in &self.load_balancing.backends {
            if backend.upstreams.is_empty() {
                return Err(anyhow::anyhow!(
                    "Backend '{}' must have at least one upstream server",
                    name
                ));
            }
        }

        Ok(())
    }
}

// Default value functions
fn default_weight() -> u32 {
    1
}

fn default_jwt_header() -> String {
    "Authorization".to_string()
}

fn default_api_key_header() -> String {
    "X-API-Key".to_string()
}

fn default_metrics_path() -> String {
    "/metrics".to_string()
}

fn default_keepalive_idle() -> Duration {
    Duration::from_secs(60)
}

fn default_keepalive_interval() -> Duration {
    Duration::from_secs(10)
}

fn default_keepalive_count() -> u32 {
    9
}

fn default_connection_timeout() -> Duration {
    Duration::from_secs(5)
}

fn default_read_timeout() -> Duration {
    Duration::from_secs(30)
}

fn default_write_timeout() -> Duration {
    Duration::from_secs(30)
}

fn default_upgrade_sock() -> String {
    "/tmp/photon_upgrade.sock".to_string()
}

fn default_max_cache_entries() -> usize {
    10000
}

fn default_cache_ttl() -> Duration {
    Duration::from_secs(300) // 5 minutes
}

fn default_max_body_size() -> usize {
    1024 * 1024 // 1MB
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default
            max_entries: default_max_cache_entries(),
            default_ttl: default_cache_ttl(),
            max_body_size: default_max_body_size(),
            cache_with_query_params: false,
        }
    }
}

fn default_cache_config() -> CacheConfig {
    CacheConfig::default()
}
