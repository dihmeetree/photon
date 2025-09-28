//! Photon - Ultra-high-performance API Gateway library
//!
//! Photon provides a complete API Gateway implementation built on
//! Cloudflare's Pingora framework, featuring light-speed performance:
//! - Load balancing with multiple algorithms
//! - Health checking for upstream servers
//! - Middleware chain processing (auth, rate limiting, CORS, etc.)
//! - Request routing with regex patterns
//! - Prometheus metrics collection
//! - Production-ready performance optimizations

pub mod cache;
pub mod config;
pub mod gateway;
pub mod health;
pub mod load_balancer;
pub mod metrics;
pub mod middleware;
pub mod routes;

pub use cache::{CacheEntry, CacheStatus, ResponseCache};
pub use config::*;
pub use gateway::{ApiGateway, RequestContext};
pub use routes::{CompiledRoute, RouteManager};
