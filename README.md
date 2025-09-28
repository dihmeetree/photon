# ⚡ Photon API Gateway

**Photon** is a production-ready, ultra-high-performance API Gateway built with Cloudflare Pingora. Featuring advanced load balancing, health checks, middleware support, and comprehensive monitoring. Optimized for enterprise-scale deployments with light-speed performance.

## Features

### 🚀 Extreme Performance

- **Built on Cloudflare Pingora** - Leverages battle-tested infrastructure
- **Lock-free algorithms** - Eliminates contention in critical paths
- **Optimized memory allocation** - Pre-allocated collections and Arc-based sharing
- **High-performance request ID generation** - 10.5M IDs/second (95ns each)
- **Ultra-fast route matching** - 18M routes/second (55ns each)
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

### 📊 Monitoring & Observability

- Prometheus metrics integration
- Health check monitoring
- Request tracing with unique IDs
- Comprehensive logging
- Real-time metrics dashboard

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
  worker_threads: 4

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

health_check:
  interval: "10s"
  timeout: "5s"

metrics:
  prometheus: true
  metrics_addr: "127.0.0.1:9090"
```

### Running

```bash
# Run with custom configuration
./target/release/photon --config myconfig.yaml

# Run with debug logging
RUST_LOG=debug ./target/release/photon --config config.yaml

# Run in daemon mode
./target/release/photon --config config.yaml --daemon
```

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

## Monitoring

### Prometheus Metrics

The gateway exposes comprehensive metrics at `/metrics`:

- `gateway_requests_total` - Total requests processed
- `gateway_request_duration_seconds` - Request duration histogram
- `gateway_upstream_errors_total` - Upstream connection errors
- `gateway_healthy_upstreams` - Number of healthy upstreams
- `gateway_active_connections` - Active client connections

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

#### Worker Threads

Set optimal worker thread count:

```yaml
server:
  worker_threads: 8 # Usually 2x CPU cores for CPU-bound workloads
```

#### Connection Limits

Configure connection limits per upstream:

```yaml
upstreams:
  - address: "backend:8080"
    max_connections: 100 # Per-upstream connection limit
    weight: 1 # Load balancing weight
```

#### Timeouts and Retries

Set appropriate timeouts for your workload:

```yaml
server:
  connection_timeout: "30s" # Client connection timeout
  max_connections: 10000 # Total concurrent connections

routes:
  - path: "/api/**"
    timeout: "60s" # Request timeout
    retries: 3 # Retry failed requests

health_check:
  interval: "10s" # Health check frequency
  timeout: "5s" # Health check timeout
  failure_threshold: 3 # Failures before marking unhealthy
  success_threshold: 2 # Successes before marking healthy
```

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
| **Route Matching**        | 55.4ns per lookup    | ~18M routes/second           |
| **Request ID Generation** | 95.2ns per ID        | ~10.5M IDs/second            |
| **JWT Validation**        | Production-ready     | Optimized HMAC-SHA256        |
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
5. Run `cargo test` and `cargo clippy`
6. Submit a pull request

## License

Licensed under the Apache License, Version 2.0.
