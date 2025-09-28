/// ⚡ Photon - Core API Gateway implementation using Pingora
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use log::{debug, error, info, warn};
use pingora_core::{
    server::{configuration::Opt, Server},
    upstreams::peer::{HttpPeer, Peer},
    Result as PingoraResult,
};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::{net::SocketAddr, sync::Arc, time::Instant};

use crate::{
    config::Config,
    health::HealthCheckManager,
    load_balancer::{BackendManager, UpstreamServer},
    metrics::MetricsCollector,
    middleware::MiddlewareChain,
    routes::RouteManager,
};

/// Pre-allocated strings for better performance
static GATEWAY_HEADER: OnceLock<String> = OnceLock::new();
static X_REQUEST_ID_HEADER: OnceLock<String> = OnceLock::new();
static X_FORWARDED_FOR_HEADER: OnceLock<String> = OnceLock::new();

fn init_static_strings() {
    GATEWAY_HEADER.get_or_init(|| "Photon/1.0".to_string());
    X_REQUEST_ID_HEADER.get_or_init(|| "X-Request-ID".to_string());
    X_FORWARDED_FOR_HEADER.get_or_init(|| "X-Forwarded-For".to_string());
}

/// Request context that carries information throughout the request lifecycle
#[derive(Debug)]
pub struct RequestContext {
    /// Request start time
    pub start_time: Instant,
    /// Selected backend name
    pub backend_name: Option<String>,
    /// Selected upstream server
    pub upstream: Option<Arc<UpstreamServer>>,
    /// Route ID that matched this request
    pub route_id: Option<String>,
    /// Client IP address
    pub client_ip: SocketAddr,
    /// Unique request ID for tracing
    pub request_id: String,
    /// Custom context data for middleware (only allocated when needed)
    pub custom_data: Option<std::collections::HashMap<String, String>>,
}

impl RequestContext {
    /// Create a new request context with optimized request ID
    pub fn new(client_ip: SocketAddr, request_counter: u64) -> Self {
        // Use high-performance request ID instead of UUID for better performance
        let request_id = format!(
            "req-{:016x}-{:08x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
            request_counter
        );

        Self {
            start_time: Instant::now(),
            backend_name: None,
            upstream: None,
            route_id: None,
            client_ip,
            request_id,
            custom_data: None,
        }
    }

    /// Get request duration
    pub fn duration(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }

    /// Set custom data value (allocates HashMap on first use)
    pub fn set_custom_data(&mut self, key: String, value: String) {
        if self.custom_data.is_none() {
            self.custom_data = Some(std::collections::HashMap::new());
        }
        if let Some(ref mut data) = self.custom_data {
            data.insert(key, value);
        }
    }

    /// Get custom data value
    pub fn get_custom_data(&self, key: &str) -> Option<&String> {
        self.custom_data.as_ref()?.get(key)
    }

    /// Check if custom data exists
    pub fn has_custom_data(&self, key: &str) -> bool {
        self.custom_data.as_ref().is_some_and(|data| data.contains_key(key))
    }
}

/// ⚡ Photon - Ultra-high-performance API Gateway implementation
#[derive(Clone)]
pub struct ApiGateway {
    /// Configuration
    config: Arc<Config>,
    /// Backend manager for load balancing
    backend_manager: Arc<BackendManager>,
    /// Route manager for request routing
    route_manager: Arc<RouteManager>,
    /// Middleware chain processor
    middleware_chain: Arc<MiddlewareChain>,
    /// Health check manager
    health_check_manager: Arc<HealthCheckManager>,
    /// Metrics collector
    metrics_collector: Arc<MetricsCollector>,
    /// Request ID counter for performance
    request_counter: Arc<AtomicU64>,
}

impl ApiGateway {
    /// Create a new Photon API Gateway instance
    pub async fn new(config: Arc<Config>) -> Result<Self> {
        // Initialize static strings for performance
        init_static_strings();

        // Validate configuration
        config.validate()?;

        // Initialize backend manager
        let backend_manager = Arc::new(BackendManager::new());
        for (name, backend_config) in &config.load_balancing.backends {
            backend_manager.add_backend(name.clone(), backend_config)?;
        }

        // Initialize route manager
        let route_manager = Arc::new(RouteManager::new(&config.routes)?);

        // Initialize middleware chain
        let middleware_chain = Arc::new(MiddlewareChain::new(&config.middleware)?);

        // Initialize health check manager
        let health_check_manager = Arc::new(HealthCheckManager::new(
            config.health_check.clone(),
            backend_manager.clone(),
        ));

        // Initialize health checkers with backend configurations
        health_check_manager.initialize_checkers(&config.load_balancing.backends).await?;

        // Initialize metrics collector
        let metrics_collector = Arc::new(MetricsCollector::new(&config.metrics)?);

        Ok(Self {
            config,
            backend_manager,
            route_manager,
            middleware_chain,
            health_check_manager,
            metrics_collector,
            request_counter: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Start the Photon API Gateway server
    pub fn run(&self) -> Result<()> {
        info!("⚡ Starting Photon API Gateway server");

        // Create Pingora server
        let opt = Opt::default();
        let mut server = Server::new(Some(opt))?;
        server.bootstrap();

        // Create proxy service
        let mut proxy_service =
            pingora_proxy::http_proxy_service(&server.configuration, self.clone());

        // Add HTTP listener
        proxy_service.add_tcp(&self.config.server.http_addr.to_string());
        info!("HTTP server listening on {}", self.config.server.http_addr);

        // Add HTTPS listener if configured
        if let Some(https_addr) = &self.config.server.https_addr {
            if let (Some(cert_path), Some(key_path)) =
                (&self.config.server.tls_cert, &self.config.server.tls_key)
            {
                let tls_settings =
                    pingora_core::listeners::tls::TlsSettings::intermediate(cert_path, key_path)?;
                proxy_service.add_tls_with_settings(&https_addr.to_string(), None, tls_settings);
                info!("HTTPS server listening on {}", https_addr);
            }
        }

        server.add_service(proxy_service);

        // Add metrics service if enabled
        if self.config.metrics.prometheus {
            if let Some(metrics_addr) = &self.config.metrics.metrics_addr {
                let mut metrics_service =
                    pingora_core::services::listening::Service::prometheus_http_service();
                metrics_service.add_tcp(&metrics_addr.to_string());
                server.add_service(metrics_service);
                info!("Metrics server listening on {}", metrics_addr);
            }
        }

        info!("⚡ Photon API Gateway started successfully");
        info!("Server ready! Accepting connections on all configured ports");
        info!("Metrics available at http://127.0.0.1:9090/metrics");
        info!("Ready to proxy requests");

        // Run the server (this blocks forever)
        server.run_forever();
    }
}

#[async_trait]
impl ProxyHttp for ApiGateway {
    type CTX = RequestContext;

    /// Create a new request context
    fn new_ctx(&self) -> Self::CTX {
        // This will be updated with the actual client IP in early_request_filter
        let request_counter = self.request_counter.fetch_add(1, Ordering::Relaxed);
        RequestContext::new("0.0.0.0:0".parse().unwrap(), request_counter)
    }

    /// Early request filter - runs before routing
    async fn early_request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<()> {
        // Update context with actual client IP
        if let Some(client_addr) = session.client_addr() {
            if let Some(inet_addr) = client_addr.as_inet() {
                ctx.client_ip = *inet_addr;
            }
        }

        // Add request ID header using pre-allocated string
        session
            .req_header_mut()
            .insert_header(X_REQUEST_ID_HEADER.get().unwrap().as_str(), &ctx.request_id)
            .map_err(|e| {
                error!("Failed to add request ID header: {}", e);
                pingora_core::Error::new_str("Failed to add request ID header")
            })?;

        debug!(
            "Processing request {} from {}",
            ctx.request_id, ctx.client_ip
        );

        Ok(())
    }

    /// Request filter - main routing and middleware processing
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<bool> {
        // Record request metrics
        self.metrics_collector.record_request();

        // Find matching route
        let route = match self.route_manager.find_route(session.req_header()) {
            Some(route) => {
                ctx.route_id = Some(route.config.id.clone());
                ctx.backend_name = Some(route.config.backend.clone());
                route
            }
            None => {
                warn!(
                    "No route found for {} {}",
                    session.req_header().method,
                    session.req_header().uri.path()
                );

                let mut error_response = ResponseHeader::build(404, None).unwrap();
                error_response
                    .insert_header("content-type", "text/plain")
                    .unwrap();

                session
                    .write_response_header(Box::new(error_response), false)
                    .await?;
                session
                    .write_response_body(Some(Bytes::from_static(b"Not Found")), true)
                    .await?;
                // Note: Session will be finished automatically

                return Ok(true); // Early return
            }
        };

        // Process middleware chain
        debug!("Processing middleware for route: {}", route.config.id);
        match self
            .middleware_chain
            .process_request(session, ctx, &route)
            .await
        {
            Ok(should_continue) => {
                debug!(
                    "Middleware processing result: should_continue = {}",
                    should_continue
                );
                if !should_continue {
                    debug!("Middleware indicated to continue to upstream");
                } else {
                    debug!("Middleware handled the response, returning early");
                    return Ok(true); // Middleware handled the response
                }
            }
            Err(e) => {
                error!("Middleware error: {}", e);

                let mut error_response = ResponseHeader::build(500, None).unwrap();
                error_response
                    .insert_header("content-type", "text/plain")
                    .unwrap();

                session
                    .write_response_header(Box::new(error_response), false)
                    .await?;
                session
                    .write_response_body(Some(Bytes::from_static(b"Internal Server Error")), true)
                    .await?;
                // Note: Session will be finished automatically

                return Ok(true);
            }
        }

        debug!("Request filter completed, continuing to upstream selection");
        Ok(false) // Continue to upstream
    }

    /// Select upstream peer for the request
    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<Box<HttpPeer>> {
        let backend_name = ctx.backend_name.as_ref().ok_or_else(|| {
            error!("No backend selected for request {}", ctx.request_id);
            pingora_core::Error::new_str("No backend selected")
        })?;

        debug!("Looking for backend: {}", backend_name);

        // Create load balancing key (use client IP bytes for better performance)
        let lb_key = match ctx.client_ip.ip() {
            std::net::IpAddr::V4(ipv4) => ipv4.octets().to_vec(),
            std::net::IpAddr::V6(ipv6) => ipv6.octets().to_vec(),
        };

        // Select upstream using load balancer
        let upstream = self
            .backend_manager
            .select_upstream(backend_name, &lb_key)
            .ok_or_else(|| {
                error!(
                    "No healthy upstream available for backend '{}' in request {}",
                    backend_name, ctx.request_id
                );
                pingora_core::Error::new_str("No healthy upstream available")
            })?;

        // Update context
        ctx.upstream = Some(upstream.clone());

        // Increment connection count
        upstream.increment_connections();

        // Convert to HttpPeer
        let peer = Box::new(upstream.to_http_peer());

        info!(
            "Selected upstream {} for request {} (backend: {})",
            upstream.address, ctx.request_id, backend_name
        );

        Ok(peer)
    }

    /// Filter upstream requests
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<()> {
        // Process middleware for upstream request modifications
        if let Some(route) = ctx
            .route_id
            .as_ref()
            .and_then(|id| self.route_manager.get_route(id))
        {
            if let Err(e) = self
                .middleware_chain
                .process_upstream_request(session, upstream_request, ctx, &route)
                .await
            {
                error!("Upstream request middleware error: {}", e);
                return Err(pingora_core::Error::new_str(
                    "Upstream request middleware error",
                ));
            }
        }

        // Add tracing headers
        let client_ip_str = ctx.client_ip.ip().to_string();
        upstream_request
            .insert_header(
                X_FORWARDED_FOR_HEADER.get().unwrap().as_str(),
                &client_ip_str,
            )
            .map_err(|e| {
                error!("Failed to add X-Forwarded-For header: {}", e);
                pingora_core::Error::new_str("Failed to add forwarded header")
            })?;

        upstream_request
            .insert_header(X_REQUEST_ID_HEADER.get().unwrap().as_str(), &ctx.request_id)
            .map_err(|e| {
                error!("Failed to add request ID to upstream: {}", e);
                pingora_core::Error::new_str("Failed to add request ID")
            })?;

        Ok(())
    }

    /// Filter upstream responses
    fn upstream_response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<()> {
        // Process middleware for response modifications
        // Note: Since this is a sync method, we can't run async middleware here
        // Response middleware would typically be applied in the logging phase or
        // through a different mechanism that supports async operations

        // Add gateway identification header
        upstream_response
            .insert_header("X-Gateway", GATEWAY_HEADER.get().unwrap().as_str())
            .map_err(|e| {
                error!("Failed to add gateway header: {}", e);
                pingora_core::Error::new_str("Failed to add gateway header")
            })?;

        // Add request ID to response
        upstream_response
            .insert_header(X_REQUEST_ID_HEADER.get().unwrap().as_str(), &ctx.request_id)
            .map_err(|e| {
                error!("Failed to add request ID to response: {}", e);
                pingora_core::Error::new_str("Failed to add request ID")
            })?;

        Ok(())
    }

    /// Handle connection errors
    fn fail_to_connect(
        &self,
        _session: &mut Session,
        peer: &HttpPeer,
        ctx: &mut Self::CTX,
        mut e: Box<pingora_core::Error>,
    ) -> Box<pingora_core::Error> {
        warn!(
            "Failed to connect to upstream {} for request {}: {}",
            peer.address(),
            ctx.request_id,
            e
        );

        // Record circuit breaker failure and mark upstream as potentially unhealthy
        if let Some(upstream) = &ctx.upstream {
            warn!(
                "Recording failure for upstream {} circuit breaker",
                upstream.address
            );
            upstream.circuit_breaker.record_failure();
            // The health check manager will handle health status
        }

        // Record error metrics
        self.metrics_collector.record_upstream_error();

        // Return the error (retries would be handled at a higher level)
        e.set_retry(false);
        e
    }

    /// Clean up after request completion
    async fn logging(
        &self,
        session: &mut Session,
        e: Option<&pingora_core::Error>,
        ctx: &mut Self::CTX,
    ) {
        // Decrement connection count
        if let Some(upstream) = &ctx.upstream {
            upstream.decrement_connections();
        }

        // Record metrics
        let status_code = session
            .response_written()
            .map(|resp| resp.status.as_u16())
            .unwrap_or(0);

        let duration = ctx.duration();

        self.metrics_collector
            .record_response(status_code, duration);

        // Record circuit breaker success for successful responses
        if let Some(upstream) = &ctx.upstream {
            if status_code < 500 {
                upstream.circuit_breaker.record_success();
            } else {
                upstream.circuit_breaker.record_failure();
            }
        }

        // Log request completion
        let log_level = if status_code >= 500 {
            log::Level::Error
        } else if status_code >= 400 {
            log::Level::Warn
        } else {
            log::Level::Info
        };

        log::log!(
            log_level,
            "Request {} completed: {} {} -> {} ({}ms) [{}]",
            ctx.request_id,
            session.req_header().method,
            session.req_header().uri.path(),
            status_code,
            duration.as_millis(),
            ctx.upstream
                .as_ref()
                .map(|u| u.address.as_str())
                .unwrap_or("no-upstream")
        );

        if let Some(error) = e {
            error!("Request {} encountered error: {}", ctx.request_id, error);
            self.metrics_collector.record_error();
        }
    }
}
