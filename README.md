# ⚡ Photon API Gateway

**Photon** is a production-ready, ultra-high-performance API Gateway built with Cloudflare Pingora. Featuring advanced load balancing, health checks, middleware support, and comprehensive monitoring. Optimized for enterprise-scale deployments with light-speed performance.

## Features

### 🚀 Extreme Performance

- **Built on Cloudflare Pingora** - Leverages battle-tested infrastructure
- **Trie-based route matching** - O(log n) performance with optimized pattern categorization
- **HTTP-compliant response caching** - RFC 7231 compliant with proper cache headers
- **JWT token caching** - 5-minute TTL reduces cryptographic overhead
- **Lock-free metrics collection** - Crossbeam channels eliminate contention
- **Batched health checks** - Worker pools for scalable health monitoring
- **High-performance request ID generation** - 10.5M IDs/second (95ns each)
- **Production-ready JWT validation** - HMAC-SHA256 with timing-safe comparison
- **Zero-copy optimizations** - Minimal allocations in hot paths

### ⚖️ Advanced Load Balancing

- Multiple algorithms: Round Robin, Least Connections, Weighted Round Robin, IP Hash, Random
- Real-time health checking with automatic failover
- Backend-specific algorithm configuration
- Connection pooling and limits

### 🛡️ Security & Middleware

- **Production JWT validation** - HMAC-SHA256, expiration, signature verification
- **API Key authentication** - Header and query parameter support
- **Lock-free rate limiting** - High-performance token bucket with atomic operations
- **CORS support** - Configurable origins, methods, and headers
- **Header transformation** - Add/remove/modify request/response headers
- **Advanced routing** - Regex pattern matching with host-based routing
- **Request tracing** - Unique request IDs for distributed tracing

### 🔌 WebSocket Support

- **RFC 6455 compliant WebSocket proxying** - Full protocol support for real-time communication
- **Per-route WebSocket configuration** - Configurable timeouts, protocols, and message limits
- **Protocol validation** - Restrict allowed WebSocket subprotocols for security
- **WebSocket metrics** - Dedicated Prometheus metrics for upgrades, connections, and messages
- **Authentication integration** - Apply existing auth middleware to WebSocket upgrades
- **Production-ready** - Proper header forwarding and error handling

### 📊 Monitoring & Observability

- **Prometheus metrics integration** - HTTP requests, responses, errors, and latency
- **WebSocket metrics** - Upgrades, active connections, messages, and durations
- **Health check monitoring** - Backend availability and response times
- **Request tracing** - Unique request IDs for distributed tracing
- **Comprehensive logging** - Structured logging with performance optimization
- **Real-time metrics dashboard** - Live performance monitoring

### 💾 Advanced Caching

- **HTTP-compliant response caching** - RFC 7231 compliant with proper cache control
- **Cache status headers** - X-Cache, X-Cache-Key, Age headers for debugging
- **Multi-format HTTP date parsing** - RFC 1123, RFC 850, ANSI C support
- **LRU eviction** - Intelligent cache management with hit count optimization
- **Configurable TTL** - Per-route and global cache expiration policies
- **Query parameter handling** - Optional caching with query parameters

### 🔧 Configuration

- YAML/JSON/TOML configuration support
- Hot-reloading of routes and backends
- Environment variable substitution
- Validation and error checking

## Quick Start

### Prerequisites

- Rust 1.70+
- Cargo

### Installation

```bash
# Clone the repository
git clone https://github.com/dihmeetree/photon.git
cd photon

# Build the project
cargo build --release

# Run with default configuration
cargo run -- --config config.yaml
```

### Configuration

Create a `config.yaml` file (see `config.yaml` for a complete example):

```yaml
server:
  http_addr: "0.0.0.0:8080"

load_balancing:
  backends:
    web_service:
      algorithm: "round_robin"
      upstreams:
        - address: "127.0.0.1:3001"
          weight: 1
        - address: "127.0.0.1:3002"
          weight: 1

routes:
  - id: "api"
    path: "/api/**"
    backend: "web_service"
    methods: ["GET", "POST"]
    timeout: "30s" # Route-specific timeout
    retries: 3 # Number of retry attempts

# Response caching configuration
cache:
  enabled: true
  max_entries: 10000
  default_ttl: "300s" # 5 minutes
  max_body_size: 1048576 # 1MB
  cache_with_query_params: false

health_check:
  interval: "10s"
  timeout: "5s"

metrics:
  prometheus: true
  metrics_addr: "127.0.0.1:9090"
  metrics_path: "/metrics" # Configurable metrics endpoint path
  detailed_metrics: true # Enable detailed request metrics
```

### Running

```bash
# Run with custom configuration
./target/release/photon --config myconfig.yaml

# Run with debug logging
RUST_LOG=debug ./target/release/photon --config config.yaml

# Run in daemon mode
./target/release/photon --config config.yaml --daemon

# View all available options
./target/release/photon --help
```

### Command Line Options

```
⚡ Photon - Ultra-high-performance API Gateway built with Cloudflare Pingora

Usage: photon [OPTIONS]

Options:
  -c, --config <CONFIG>      Configuration file path [default: config.yaml]
  -l, --log-level <LEVEL>    Log level [default: info]
  -d, --daemon               Enable daemon mode
  -u, --upgrade              Enable upgrade mode for zero downtime reload
  -h, --help                 Print help information
  -V, --version              Print version information
```

## Zero Downtime Reload

Photon supports zero downtime reloading using Pingora's built-in graceful upgrade system. This allows you to:

- **Deploy new versions** without dropping connections
- **Update configurations** without service interruption
- **Restart the gateway** with zero impact to clients

### Configuration

Add the upgrade socket configuration to your `config.yaml`:

```yaml
server:
  # Zero downtime reload configuration
  upgrade_sock: "/tmp/photon_upgrade.sock"
```

### Performing Zero Downtime Reload

**Step 1**: Signal the running instance to prepare for graceful shutdown:

```bash
pkill -SIGQUIT photon
```

**Step 2**: Immediately start the new instance with upgrade mode:

```bash
./target/release/photon --config config.yaml --daemon --upgrade
```

**Combined command** for seamless operation:

```bash
pkill -SIGQUIT photon && ./target/release/photon --config config.yaml --daemon --upgrade
```

### What Happens During Reload

1. 🛑 **Old process** receives SIGQUIT and stops accepting new connections
2. 🔄 **Socket handover** occurs via the upgrade socket
3. 🚀 **New process** immediately takes over and serves new requests
4. ⏳ **Old process** continues serving existing requests until completion
5. ✅ **Zero connection drops** - clients experience seamless service

### Testing Zero Downtime Reload

**Basic Test:**

```bash
# Terminal 1: Start continuous requests
while true; do
    curl -s -w "Status: %{http_code}, Time: %{time_total}s\n" http://127.0.0.1:8080/
    sleep 0.1
done

# Terminal 2: Perform reload
pkill -SIGQUIT photon && ./target/release/photon --config config.yaml --daemon --upgrade
```

**Load Test:**

```bash
# Start load test
wrk -t4 -c100 -d30s --latency http://127.0.0.1:8080/

# Perform upgrade during load test (in another terminal)
pkill -SIGQUIT photon && ./target/release/photon --config config.yaml --daemon --upgrade
```

### Expected Results

✅ **No 502/503 errors** during upgrade
✅ **No connection refused errors**
✅ **Continuous response flow** without interruption
✅ **Process PID changes** but service remains available

This enterprise-grade capability makes Photon ideal for production environments requiring high availability and seamless deployments.

## Load Balancing Algorithms

### Round Robin

Distributes requests evenly across all healthy upstreams.

```yaml
algorithm: "round_robin"
```

### Least Connections

Routes requests to the upstream with the fewest active connections.

```yaml
algorithm: "least_connections"
```

### Weighted Round Robin

Distributes requests based on upstream weights.

```yaml
algorithm: "weighted_round_robin"
upstreams:
  - address: "server1:8080"
    weight: 3
  - address: "server2:8080"
    weight: 1 # Gets 1/4 of traffic
```

### IP Hash

Routes requests from the same client IP to the same upstream (sticky sessions).

```yaml
algorithm: "ip_hash"
```

### Random

Routes requests randomly across healthy upstreams.

```yaml
algorithm: "random"
```

## Health Checks

The gateway supports multiple health check types:

### TCP Health Checks

Simple TCP connection test.

```yaml
health_check:
  check_type: "tcp"
  interval: "10s"
```

### HTTP Health Checks

HTTP GET request to a specific path.

```yaml
health_check:
  check_type: "http"
  path: "/health"
  expected_status: 200
  interval: "15s"
```

### HTTPS Health Checks

HTTPS GET request for TLS-enabled upstreams.

```yaml
health_check:
  check_type: "https"
  path: "/api/health"
  expected_status: 200
  interval: "15s"
```

## Middleware

### Rate Limiting

High-performance, lock-free token bucket rate limiting with configurable keys:

```yaml
middleware:
  rate_limiting:
    requests_per_second: 10000 # High-throughput support
    burst: 20000 # Handle traffic spikes
    key: "ip" # Rate limit by IP
    # key: "header:X-API-Key"     # Rate limit by API key
    # key: "header:User-Agent"    # Rate limit by user agent
```

**Performance Features:**

- Lock-free atomic operations with sub-second precision
- Millions of rate limiting decisions per second
- Memory-efficient token bucket implementation

### Authentication

Production-ready authentication with multiple methods:

```yaml
middleware:
  authentication:
    auth_type: "jwt"
    jwt:
      secret: "your-256-bit-secret-key-here"
      algorithm: "HS256" # HMAC-SHA256 with timing-safe validation
      header: "Authorization" # Header containing JWT token


    # Alternative: API Key authentication
    # auth_type: "api_key"
    # api_key:
    #   header: "X-API-Key"       # Header containing API key
    #   query: "api_key"          # Query parameter containing API key
```

**Security Features:**

- HMAC-SHA256 signature verification with timing-safe comparison
- JWT expiration (`exp`) and not-before (`nbf`) validation
- Production-ready cryptographic operations
- Base64 URL-safe encoding/decoding

### CORS

Cross-Origin Resource Sharing configuration.

```yaml
middleware:
  cors:
    allowed_origins: ["https://myapp.com"]
    allowed_methods: ["GET", "POST", "PUT", "DELETE"]
    allowed_headers: ["Content-Type", "Authorization"]
```

### WebSocket Configuration

Photon provides full WebSocket proxying support with per-route configuration:

```yaml
routes:
  # WebSocket chat application
  - id: "websocket_chat"
    path: "/ws/chat/**"
    methods: ["GET"] # WebSocket upgrades start as GET requests
    backend: "chat_service"
    websocket:
      enabled: true
      protocols: ["chat-protocol", "echo-protocol"] # Allowed subprotocols
      timeout: "300s" # 5 minutes for WebSocket connections
      idle_timeout: "60s" # Close idle connections after 1 minute
      max_message_size: 65536 # 64KB max message size

  # WebSocket API with authentication
  - id: "websocket_api"
    path: "/ws/api/**"
    methods: ["GET"]
    backend: "api_service"
    middleware: ["auth"] # Authentication applies to WebSocket upgrades
    websocket:
      enabled: true
      timeout: "600s" # 10 minutes for API WebSocket connections
      idle_timeout: "120s" # 2 minute idle timeout
      max_message_size: 1048576 # 1MB max message size for API
```

**WebSocket Features:**

- **RFC 6455 compliant** - Full WebSocket protocol support
- **Protocol validation** - Restrict allowed subprotocols for security
- **Per-route configuration** - Timeouts, protocols, and limits per route
- **Authentication integration** - Apply existing middleware to WebSocket upgrades
- **Comprehensive metrics** - Track upgrades, connections, and message counts
- **Production-ready** - Proper error handling and header forwarding

## Response Caching

Photon includes a high-performance, HTTP-compliant response caching system that significantly reduces backend load and improves response times.

### Cache Configuration

```yaml
cache:
  enabled: true
  max_entries: 10000          # Maximum cache entries
  default_ttl: "300s"         # Default cache TTL (5 minutes)
  max_body_size: 1048576      # Maximum cacheable response size (1MB)
  cache_with_query_params: false # Whether to cache responses with query parameters
```

### Cache Features

#### **HTTP RFC 7231 Compliance**

- **Cache-Control header parsing** - Respects `max-age`, `no-cache`, `no-store`
- **Expires header support** - RFC 1123, RFC 850, and ANSI C date formats
- **Conditional requests** - `If-Modified-Since` and `Last-Modified` headers
- **Vary header handling** - Cache varies based on specified headers

#### **Cache Status Headers**

Photon adds helpful cache debugging headers to responses:

```http
X-Cache: HIT                    # Cache status: HIT, MISS, STALE
X-Cache-Key: GET:/api/users     # Cache key used for this request
Age: 45                         # Seconds since response was cached
```

#### **Intelligent Cache Management**

- **LRU eviction** - Least Recently Used items are evicted first
- **Hit count optimization** - Frequently accessed items stay in cache longer
- **Memory-efficient storage** - Compressed response bodies when beneficial
- **Automatic cleanup** - Expired entries are removed during maintenance

### Cache Behavior

#### **What Gets Cached**

✅ **Cacheable responses:**
- GET requests with 200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501 status codes
- Responses with `Cache-Control: max-age=X` headers
- Responses with future `Expires` headers
- Responses smaller than `max_body_size`

❌ **Non-cacheable responses:**
- POST, PUT, DELETE, PATCH requests
- Responses with `Cache-Control: no-cache` or `no-store`
- Responses with `Set-Cookie` headers
- Responses larger than `max_body_size`
- Error responses (5xx status codes)

#### **Cache Key Generation**

Cache keys are generated using:
```
{method}:{path}:{query_params_hash}:{vary_headers_hash}
```

Examples:
- `GET:/api/users` (simple GET request)
- `GET:/api/search:q=rust` (with query parameters, if enabled)
- `GET:/api/data:accept-encoding=gzip` (with Vary header)

#### **TTL Determination**

Cache TTL is determined in order of precedence:

1. **Cache-Control max-age** - `Cache-Control: max-age=3600`
2. **Expires header** - `Expires: Thu, 01 Dec 2023 16:00:00 GMT`
3. **Default TTL** - Configured `default_ttl` value
4. **Minimum 60 seconds** - Prevents cache thrashing

### Performance Impact

#### **Cache Hit Performance**

- **Sub-millisecond response times** - Cached responses served in <1ms
- **Zero backend load** - Cache hits don't touch upstream servers
- **Reduced network overhead** - Responses served from gateway memory

#### **Cache Statistics**

Monitor cache performance with Prometheus metrics:

```
# Cache hit ratio
gateway_cache_hits_total / (gateway_cache_hits_total + gateway_cache_misses_total)

# Cache memory usage
gateway_cache_entries_total
gateway_cache_memory_bytes

# Cache efficiency
gateway_cache_evictions_total
gateway_cache_expired_total
```

### Production Tuning

#### **Memory Management**

Configure cache size based on available memory:

```yaml
cache:
  max_entries: 50000          # ~500MB for 10KB average responses
  max_body_size: 2097152      # 2MB max response size
```

#### **TTL Optimization**

Balance cache hit ratio with data freshness:

```yaml
cache:
  default_ttl: "600s"         # 10 minutes for frequently updated APIs
  # default_ttl: "3600s"      # 1 hour for stable content
  # default_ttl: "86400s"     # 24 hours for static assets
```

#### **Selective Caching**

Enable query parameter caching for read-only APIs:

```yaml
cache:
  cache_with_query_params: true  # Cache /api/search?q=term responses
```

### Cache Debugging

#### **Response Headers**

Check cache behavior using response headers:

```bash
curl -I http://localhost:8080/api/data
# HTTP/1.1 200 OK
# X-Cache: MISS
# X-Cache-Key: GET:/api/data
# Cache-Control: max-age=300

curl -I http://localhost:8080/api/data
# HTTP/1.1 200 OK
# X-Cache: HIT
# X-Cache-Key: GET:/api/data
# Age: 5
```

#### **Cache Metrics**

Monitor cache performance:

```bash
curl http://localhost:9090/metrics | grep cache
# gateway_cache_hits_total 1250
# gateway_cache_misses_total 150
# gateway_cache_entries_total 450
```

This caching system provides enterprise-grade performance improvements while maintaining full HTTP compliance and providing comprehensive monitoring and debugging capabilities.

## Monitoring

### Prometheus Metrics

The gateway exposes comprehensive metrics at the configurable path (default `/metrics`):

**HTTP Metrics:**

- `gateway_requests_total` - Total requests processed
- `gateway_request_duration_seconds` - Request duration histogram
- `gateway_upstream_errors_total` - Upstream connection errors
- `gateway_healthy_upstreams` - Number of healthy upstreams
- `gateway_active_connections` - Active client connections

**WebSocket Metrics:**

- `gateway_websocket_upgrades_total` - Total WebSocket upgrade requests
- `gateway_websocket_connections_active` - Currently active WebSocket connections
- `gateway_websocket_messages_total` - Total WebSocket messages processed
- `gateway_websocket_connection_duration_seconds` - WebSocket connection duration histogram

### Health Status

Check Photon and backend health at `/health`.

### Request Tracing

Every request gets a unique ID (`X-Request-ID`) for distributed tracing with light-speed generation.

## Performance Optimization

### High-Performance Features

Photon includes numerous performance optimizations for enterprise workloads:

#### Memory Optimization

- **Pre-allocated collections** - `Vec::with_capacity()` and `HashMap::with_capacity()`
- **Arc-based sharing** - Routes stored as `Arc<CompiledRoute>` to avoid cloning
- **String interning** - Pre-allocated header strings eliminate repeated allocations
- **Efficient IP handling** - Direct byte manipulation instead of string conversion

#### Concurrency Optimization

- **Lock-free rate limiting** - Atomic operations with sub-second precision
- **Cached healthy upstreams** - Avoid rebuilding server lists on every request
- **Lock-free refill algorithms** - High-performance token bucket implementation
- **Atomic request counters** - Fast request ID generation without locks

#### Request Processing Optimization

- **Optimized request IDs** - 95ns generation vs 200-500ns for UUIDs
- **Fast route matching** - 55ns per lookup with optimized regex compilation
- **Zero-copy header operations** - Minimize string allocations in hot paths
- **Efficient load balancing keys** - Raw IP bytes for consistent hashing

### Configuration Tuning

#### Connection Limits

Configure connection limits per upstream:

```yaml
upstreams:
  - address: "backend:8080"
    max_connections: 100 # Per-upstream connection limit
    weight: 1 # Load balancing weight
```

#### TCP Keepalive

Configure TCP keepalive for upstream connections to detect failed connections and maintain long-lived connections efficiently:

```yaml
upstreams:
  - address: "backend:8080"
    tcp_keepalive:
      enabled: true
      idle: "60s" # Time before sending keepalive probes
      interval: "10s" # Interval between keepalive probes
      count: 9 # Max failed probes before dropping connection
    connection_timeout: "30s"
    read_timeout: "30s"
    write_timeout: "30s"
```

**Benefits:**

- Detects failed connections faster than default TCP timeouts
- Maintains connection pools efficiently
- Reduces latency by avoiding broken connection attempts
- Configurable per upstream for optimal performance

#### Timeouts and Retries

Set appropriate timeouts for your workload:

```yaml
server:
  connection_timeout: "30s" # Client connection timeout
  max_connections: 10000 # Total concurrent connections

routes:
  - path: "/api/**"
    timeout: "60s" # Route-specific request timeout (overrides upstream defaults)
    retries: 3 # Retry configuration (handled by Pingora's internal retry mechanisms)

health_check:
  interval: "10s" # Health check frequency
  timeout: "5s" # Health check timeout
  failure_threshold: 3 # Failures before marking unhealthy
  success_threshold: 2 # Successes before marking healthy
```

**Timeout Behavior:**

- Route-specific timeouts override upstream connection timeouts
- Applied to read, write, and total connection timeouts
- Helps isolate slow routes from affecting other traffic

**Retry Behavior:**

- Retries are handled by Pingora's robust internal retry mechanisms
- Provides connection-level retry logic for failed requests
- Automatic failover to healthy upstreams

#### Rate Limiting Performance

Optimize rate limiting for high throughput:

```yaml
middleware:
  rate_limiting:
    requests_per_second: 10000 # High-performance rate limiting
    burst: 20000 # Allow traffic bursts
    key: "ip" # or "header:X-API-Key" for per-API-key limits
```

## Production Deployment

### Docker

```dockerfile
FROM rust:1.70-alpine AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/target/release/photon /usr/local/bin/
ENTRYPOINT ["photon"]
```

### Systemd Service

```ini
[Unit]
Description=Photon API Gateway
After=network.target

[Service]
Type=simple
User=photon
ExecStart=/usr/local/bin/photon --config /etc/photon/config.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## Library Usage

Photon can also be used as a library in your Rust applications:

```toml
[dependencies]
photon = { path = "path/to/photon" }
```

```rust
use photon::{ApiGateway, Config};
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load configuration
    let config = Config::from_file("config.yaml")?;

    // Create and start Photon
    let gateway = ApiGateway::new(Arc::new(config))?;
    gateway.run()?;

    Ok(())
}
```

### Available Components

- `ApiGateway` - Main gateway implementation
- `RouteManager` - Request routing with regex patterns
- `BackendManager` - Load balancing and upstream management
- `MiddlewareChain` - Middleware processing pipeline
- `HealthCheckManager` - Health monitoring for upstreams
- `MetricsCollector` - Prometheus metrics collection

## Development

### Running Tests

```bash
# Run all tests
cargo test

# Run with release optimizations
cargo test --release

# Run specific test modules
cargo test routes::tests
```

### Code Quality

```bash
# Check for clippy warnings
cargo clippy -- -D warnings

# Format code
cargo fmt

# Check formatting
cargo fmt -- --check
```

### Performance Benchmarks

Photon includes comprehensive benchmarks to measure and validate performance optimizations:

```bash
# Run all benchmarks
cargo bench

# Run specific benchmarks
cargo bench route_matching
cargo bench request_id_generation

# Generate detailed HTML reports
cargo bench -- --verbose

# Save baseline for performance regression testing
cargo bench -- --save-baseline v1.0

# Compare against baseline
cargo bench -- --baseline v1.0
```

#### Benchmark Results

Current performance metrics on modern hardware:

| Component                 | Performance          | Throughput                   |
| ------------------------- | -------------------- | ---------------------------- |
| **Trie Route Matching**   | O(log n) performance | 15-25% faster than regex    |
| **JWT Token Caching**     | 5-minute TTL         | Reduces crypto overhead      |
| **Response Caching**      | RFC 7231 compliant   | Sub-millisecond cache hits   |
| **Lock-free Metrics**     | Crossbeam channels   | Zero-contention collection   |
| **Batched Health Checks** | Worker pools         | Scalable concurrent checks   |
| **Request ID Generation** | 95.2ns per ID        | ~10.5M IDs/second            |
| **Rate Limiting**         | Lock-free atomic ops | Millions of decisions/second |

#### Benchmark Reports

Detailed performance reports are generated in `target/criterion/` including:

- Performance graphs and statistical analysis
- Regression detection and historical comparisons
- Memory usage and allocation patterns
- CPU utilization metrics

#### Adding Custom Benchmarks

Create benchmarks in `benches/` directory:

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use gateway::YourComponent;

fn benchmark_your_feature(c: &mut Criterion) {
    c.bench_function("your_feature", |b| {
        b.iter(|| {
            black_box(your_performance_critical_code())
        })
    });
}

criterion_group!(benches, benchmark_your_feature);
criterion_main!(benches);
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run the quality checks:
   ```bash
   cargo test --release      # Run all tests
   cargo clippy -- -D warnings  # Check code quality
   cargo fmt                 # Format code consistently
   ```
6. Submit a pull request

## License

Licensed under the Apache License, Version 2.0.
