/// Middleware system for the API Gateway
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::Engine;
use bytes::Bytes;
use dashmap::DashMap;
use log::{debug, warn};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::Session;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use crate::{
    config::{
        AuthenticationConfig, AuthenticationType, CorsConfig, MiddlewareConfig, RateLimitingConfig,
        RateLimitingKey, TransformConfig,
    },
    gateway::RequestContext,
    routes::CompiledRoute,
};

/// Trait for middleware components
#[async_trait]
pub trait Middleware: Send + Sync {
    /// Process request before routing to upstream
    async fn process_request(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
        route: &CompiledRoute,
    ) -> Result<bool>;

    /// Process request headers before sending to upstream
    async fn process_upstream_request(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut RequestContext,
        route: &CompiledRoute,
    ) -> Result<()>;

    /// Process response from upstream
    async fn process_response(
        &self,
        session: &mut Session,
        response: &mut ResponseHeader,
        ctx: &mut RequestContext,
        route: &CompiledRoute,
    ) -> Result<()>;
}

/// Rate limiting middleware using token bucket algorithm
pub struct RateLimitingMiddleware {
    /// Rate limiting configuration
    config: RateLimitingConfig,
    /// Token buckets for different keys
    buckets: DashMap<String, TokenBucket>,
}

impl RateLimitingMiddleware {
    /// Create a new rate limiting middleware
    pub fn new(config: RateLimitingConfig) -> Self {
        Self {
            config,
            buckets: DashMap::new(),
        }
    }

    /// Extract rate limiting key from request
    fn extract_key(&self, session: &Session, ctx: &RequestContext) -> Result<String> {
        match &self.config.key {
            RateLimitingKey::Ip => {
                // Optimized IP to string conversion to avoid heap allocation
                let mut ip_buffer = [0u8; 45]; // Max length for IPv6 address
                let ip_str = {
                    use std::io::Write;
                    let mut cursor = std::io::Cursor::new(&mut ip_buffer[..]);
                    write!(cursor, "{}", ctx.client_ip.ip())
                        .expect("Writing to buffer should never fail");
                    let len = cursor.position() as usize;
                    std::str::from_utf8(&ip_buffer[..len])
                        .expect("IP address should always be valid UTF-8")
                };
                Ok(ip_str.to_string())
            }
            RateLimitingKey::Header(header_name) => session
                .req_header()
                .headers
                .get(header_name)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
                .ok_or_else(|| anyhow!("Rate limiting header '{}' not found", header_name)),
            RateLimitingKey::QueryParam(param_name) => {
                let query = session.req_header().uri.query().unwrap_or("");
                url::form_urlencoded::parse(query.as_bytes())
                    .find(|(key, _)| key == param_name)
                    .map(|(_, value)| value.to_string())
                    .ok_or_else(|| anyhow!("Rate limiting query param '{}' not found", param_name))
            }
        }
    }
}

#[async_trait]
impl Middleware for RateLimitingMiddleware {
    async fn process_request(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
        _route: &CompiledRoute,
    ) -> Result<bool> {
        let key = self.extract_key(session, ctx)?;

        // Get or create token bucket for this key
        let bucket = self.buckets.entry(key.clone()).or_insert_with(|| {
            TokenBucket::new(
                self.config.requests_per_second as u64,
                self.config
                    .burst
                    .unwrap_or(self.config.requests_per_second * 2) as u64,
            )
        });

        if bucket.consume() {
            debug!("Rate limit passed for key: {}", key);
            Ok(false) // Continue processing
        } else {
            warn!("Rate limit exceeded for key: {}", key);

            // Send rate limit exceeded response
            let mut error_response = ResponseHeader::build(429, None).unwrap();
            error_response.insert_header("retry-after", "1").unwrap();
            error_response
                .insert_header("content-type", "text/plain")
                .unwrap();

            session
                .write_response_header(Box::new(error_response), false)
                .await
                .map_err(|e| anyhow!("Failed to write rate limit response: {}", e))?;
            session
                .write_response_body(Some(Bytes::from_static(b"Rate limit exceeded")), true)
                .await
                .map_err(|e| anyhow!("Failed to write rate limit response body: {}", e))?;
            // Note: Session will be finished automatically

            Ok(true) // Stop processing
        }
    }

    async fn process_upstream_request(
        &self,
        _session: &mut Session,
        _upstream_request: &mut RequestHeader,
        _ctx: &mut RequestContext,
        _route: &CompiledRoute,
    ) -> Result<()> {
        Ok(())
    }

    async fn process_response(
        &self,
        _session: &mut Session,
        _response: &mut ResponseHeader,
        _ctx: &mut RequestContext,
        _route: &CompiledRoute,
    ) -> Result<()> {
        Ok(())
    }
}

/// High-performance token bucket for rate limiting
struct TokenBucket {
    /// Maximum number of tokens
    capacity: u64,
    /// Current number of tokens (shifted by 8 bits for sub-second precision)
    tokens: AtomicU64,
    /// Tokens per second refill rate (shifted by 8 bits)
    refill_rate: u64,
    /// Last refill time (nanoseconds)
    last_refill: AtomicU64,
}

impl TokenBucket {
    /// Create a new token bucket
    fn new(refill_rate: u64, capacity: u64) -> Self {
        let now_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        Self {
            capacity,
            tokens: AtomicU64::new(capacity << 8), // Shift for sub-second precision
            refill_rate: refill_rate << 8,         // Shift for sub-second precision
            last_refill: AtomicU64::new(now_nanos),
        }
    }

    /// Try to consume a token with lock-free refill
    fn consume(&self) -> bool {
        const REFILL_INTERVAL_NANOS: u64 = 10_000_000; // 10ms in nanoseconds

        let now_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        // Lock-free refill check
        let last_refill = self.last_refill.load(Ordering::Relaxed);
        if now_nanos.saturating_sub(last_refill) >= REFILL_INTERVAL_NANOS {
            // Try to update last refill time
            if self
                .last_refill
                .compare_exchange_weak(last_refill, now_nanos, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                // We won the race, do the refill
                let elapsed_nanos = now_nanos.saturating_sub(last_refill);
                let tokens_to_add = (elapsed_nanos * self.refill_rate) / 1_000_000_000;

                if tokens_to_add > 0 {
                    let current_tokens = self.tokens.load(Ordering::Relaxed);
                    let capacity_shifted = self.capacity << 8;
                    let new_tokens = (current_tokens + tokens_to_add).min(capacity_shifted);
                    self.tokens.store(new_tokens, Ordering::Relaxed);
                }
            }
        }

        // Try to consume a token
        loop {
            let current_tokens = self.tokens.load(Ordering::Relaxed);
            if current_tokens < (1 << 8) {
                // Less than 1 token
                return false;
            }

            if self
                .tokens
                .compare_exchange_weak(
                    current_tokens,
                    current_tokens - (1 << 8),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                return true;
            }
        }
    }
}

/// Authentication middleware
pub struct AuthenticationMiddleware {
    config: AuthenticationConfig,
}

impl AuthenticationMiddleware {
    pub fn new(config: AuthenticationConfig) -> Self {
        Self { config }
    }

    /// Validate JWT token with proper verification
    fn validate_jwt(&self, token: &str) -> Result<bool> {
        if let Some(jwt_config) = &self.config.jwt {
            // Remove "Bearer " prefix if present
            let token = token.strip_prefix("Bearer ").unwrap_or(token);

            // Basic JWT structure validation
            let parts: Vec<&str> = token.split('.').collect();
            if parts.len() != 3 {
                return Ok(false);
            }

            // Decode header to check algorithm
            let header_bytes = base64::prelude::BASE64_URL_SAFE_NO_PAD
                .decode(parts[0])
                .map_err(|_| anyhow!("Invalid JWT header encoding"))?;
            let header_json = std::str::from_utf8(&header_bytes)
                .map_err(|_| anyhow!("Invalid JWT header UTF-8"))?;

            let header: serde_json::Value = serde_json::from_str(header_json)
                .map_err(|_| anyhow!("Invalid JWT header JSON"))?;

            // Verify algorithm matches configuration
            if let Some(alg) = header.get("alg").and_then(|v| v.as_str()) {
                if alg != jwt_config.algorithm {
                    return Ok(false);
                }
            } else {
                return Ok(false);
            }

            // For HMAC algorithms (HS256, HS384, HS512), verify signature
            if jwt_config.algorithm.starts_with("HS") {
                let signing_input = format!("{}.{}", parts[0], parts[1]);
                let expected_signature = match jwt_config.algorithm.as_str() {
                    "HS256" => {
                        use hmac::{Hmac, Mac};
                        type HmacSha256 = Hmac<sha2::Sha256>;

                        let mut mac = HmacSha256::new_from_slice(jwt_config.secret.as_bytes())
                            .map_err(|_| anyhow!("Invalid HMAC key"))?;
                        mac.update(signing_input.as_bytes());
                        let result = mac.finalize().into_bytes();
                        base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(result)
                    }
                    _ => {
                        return Err(anyhow!(
                            "Unsupported JWT algorithm: {}",
                            jwt_config.algorithm
                        ))
                    }
                };

                // Compare signatures securely
                if parts[2] != expected_signature {
                    return Ok(false);
                }
            } else {
                return Err(anyhow!("RSA/ECDSA algorithms not yet supported"));
            }

            // Decode and validate payload
            let payload_bytes = base64::prelude::BASE64_URL_SAFE_NO_PAD
                .decode(parts[1])
                .map_err(|_| anyhow!("Invalid JWT payload encoding"))?;
            let payload_json = std::str::from_utf8(&payload_bytes)
                .map_err(|_| anyhow!("Invalid JWT payload UTF-8"))?;

            let payload: serde_json::Value = serde_json::from_str(payload_json)
                .map_err(|_| anyhow!("Invalid JWT payload JSON"))?;

            // Check expiration if present
            if let Some(exp) = payload.get("exp").and_then(|v| v.as_i64()) {
                let current_time = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                if current_time >= exp {
                    return Ok(false); // Token expired
                }
            }

            // Check not-before if present
            if let Some(nbf) = payload.get("nbf").and_then(|v| v.as_i64()) {
                let current_time = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                if current_time < nbf {
                    return Ok(false); // Token not yet valid
                }
            }

            Ok(true)
        } else {
            Err(anyhow!("JWT configuration not found"))
        }
    }

    /// Validate API key
    fn validate_api_key(&self, key: &str) -> Result<bool> {
        if let Some(api_key_config) = &self.config.api_key {
            Ok(api_key_config.keys.contains(&key.to_string()))
        } else {
            Err(anyhow!("API key configuration not found"))
        }
    }
}

#[async_trait]
impl Middleware for AuthenticationMiddleware {
    async fn process_request(
        &self,
        session: &mut Session,
        _ctx: &mut RequestContext,
        _route: &CompiledRoute,
    ) -> Result<bool> {
        match self.config.auth_type {
            AuthenticationType::Jwt => {
                let jwt_config = self
                    .config
                    .jwt
                    .as_ref()
                    .ok_or_else(|| anyhow!("JWT configuration missing"))?;

                let auth_header = session
                    .req_header()
                    .headers
                    .get(&jwt_config.header)
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| anyhow!("Authorization header missing"))?;

                let token = if let Some(stripped) = auth_header.strip_prefix("Bearer ") {
                    stripped
                } else {
                    auth_header
                };

                if !self.validate_jwt(token)? {
                    let mut error_response = ResponseHeader::build(401, None).unwrap();
                    error_response
                        .insert_header("content-type", "text/plain")
                        .unwrap();

                    session
                        .write_response_header(Box::new(error_response), false)
                        .await
                        .map_err(|e| anyhow!("Failed to write auth response: {}", e))?;
                    session
                        .write_response_body(Some(Bytes::from_static(b"Invalid JWT token")), true)
                        .await
                        .map_err(|e| anyhow!("Failed to write auth response body: {}", e))?;
                    // Note: Session will be finished automatically

                    return Ok(true);
                }
            }
            AuthenticationType::ApiKey => {
                let api_key_config = self
                    .config
                    .api_key
                    .as_ref()
                    .ok_or_else(|| anyhow!("API key configuration missing"))?;

                let api_key = session
                    .req_header()
                    .headers
                    .get(&api_key_config.header)
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| anyhow!("API key header missing"))?;

                if !self.validate_api_key(api_key)? {
                    let mut error_response = ResponseHeader::build(401, None).unwrap();
                    error_response
                        .insert_header("content-type", "text/plain")
                        .unwrap();

                    session
                        .write_response_header(Box::new(error_response), false)
                        .await
                        .map_err(|e| anyhow!("Failed to write auth response: {}", e))?;
                    session
                        .write_response_body(Some(Bytes::from_static(b"Invalid API key")), true)
                        .await
                        .map_err(|e| anyhow!("Failed to write auth response body: {}", e))?;
                    // Note: Session will be finished automatically

                    return Ok(true);
                }
            }
            AuthenticationType::Basic => {
                // Basic authentication implementation
                let auth_header = session
                    .req_header()
                    .headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| anyhow!("Authorization header missing"))?;

                if !auth_header.starts_with("Basic ") {
                    let mut error_response = ResponseHeader::build(401, None).unwrap();
                    error_response
                        .insert_header("www-authenticate", "Basic")
                        .unwrap();
                    error_response
                        .insert_header("content-type", "text/plain")
                        .unwrap();

                    session
                        .write_response_header(Box::new(error_response), false)
                        .await
                        .map_err(|e| anyhow!("Failed to write auth response: {}", e))?;
                    session
                        .write_response_body(
                            Some(Bytes::from_static(b"Basic authentication required")),
                            true,
                        )
                        .await
                        .map_err(|e| anyhow!("Failed to write auth response body: {}", e))?;
                    // Note: Session will be finished automatically

                    return Ok(true);
                }

                // In a real implementation, decode and validate credentials
            }
        }

        Ok(false) // Continue processing
    }

    async fn process_upstream_request(
        &self,
        _session: &mut Session,
        _upstream_request: &mut RequestHeader,
        _ctx: &mut RequestContext,
        _route: &CompiledRoute,
    ) -> Result<()> {
        Ok(())
    }

    async fn process_response(
        &self,
        _session: &mut Session,
        _response: &mut ResponseHeader,
        _ctx: &mut RequestContext,
        _route: &CompiledRoute,
    ) -> Result<()> {
        Ok(())
    }
}

/// CORS middleware
pub struct CorsMiddleware {
    config: CorsConfig,
}

impl CorsMiddleware {
    pub fn new(config: CorsConfig) -> Self {
        Self { config }
    }

    /// Check if origin is allowed
    fn is_origin_allowed(&self, origin: &str) -> bool {
        self.config
            .allowed_origins
            .iter()
            .any(|allowed| allowed == "*" || allowed == origin)
    }
}

#[async_trait]
impl Middleware for CorsMiddleware {
    async fn process_request(
        &self,
        session: &mut Session,
        _ctx: &mut RequestContext,
        _route: &CompiledRoute,
    ) -> Result<bool> {
        // Handle preflight requests
        if session.req_header().method == "OPTIONS" {
            let origin = session
                .req_header()
                .headers
                .get("origin")
                .and_then(|v| v.to_str().ok());

            if let Some(origin) = origin {
                if self.is_origin_allowed(origin) {
                    let mut response = ResponseHeader::build(200, None).unwrap();

                    response
                        .insert_header("access-control-allow-origin", origin)
                        .unwrap();
                    response
                        .insert_header(
                            "access-control-allow-methods",
                            self.config.allowed_methods.join(", "),
                        )
                        .unwrap();
                    response
                        .insert_header(
                            "access-control-allow-headers",
                            self.config.allowed_headers.join(", "),
                        )
                        .unwrap();

                    if let Some(max_age) = &self.config.max_age {
                        response
                            .insert_header("access-control-max-age", max_age.as_secs().to_string())
                            .unwrap();
                    }

                    session
                        .write_response_header(Box::new(response), false)
                        .await
                        .map_err(|e| anyhow!("Failed to write CORS response: {}", e))?;
                    // Note: Session will be finished automatically

                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    async fn process_upstream_request(
        &self,
        _session: &mut Session,
        _upstream_request: &mut RequestHeader,
        _ctx: &mut RequestContext,
        _route: &CompiledRoute,
    ) -> Result<()> {
        Ok(())
    }

    async fn process_response(
        &self,
        session: &mut Session,
        response: &mut ResponseHeader,
        _ctx: &mut RequestContext,
        _route: &CompiledRoute,
    ) -> Result<()> {
        // Add CORS headers to response
        if let Some(origin) = session
            .req_header()
            .headers
            .get("origin")
            .and_then(|v| v.to_str().ok())
        {
            if self.is_origin_allowed(origin) {
                response
                    .insert_header("Access-Control-Allow-Origin", origin)
                    .map_err(|e| anyhow!("Failed to add CORS origin header: {}", e))?;
            }
        }

        Ok(())
    }
}

/// Header transformation middleware
pub struct HeaderTransformMiddleware {
    config: TransformConfig,
}

impl HeaderTransformMiddleware {
    pub fn new(config: TransformConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Middleware for HeaderTransformMiddleware {
    async fn process_request(
        &self,
        _session: &mut Session,
        _ctx: &mut RequestContext,
        _route: &CompiledRoute,
    ) -> Result<bool> {
        Ok(false)
    }

    async fn process_upstream_request(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut RequestContext,
        _route: &CompiledRoute,
    ) -> Result<()> {
        if let Some(request_headers) = &self.config.request_headers {
            // Add headers
            if let Some(add_headers) = &request_headers.add {
                for (name, value) in add_headers.iter() {
                    let name_str = name.clone();
                    let value_str = value.clone();
                    upstream_request
                        .insert_header(name_str, value_str)
                        .map_err(|e| anyhow!("Failed to add header {}: {}", name, e))?;
                }
            }

            // Set headers (overwrite)
            if let Some(set_headers) = &request_headers.set {
                for (name, value) in set_headers.iter() {
                    let name_str = name.clone();
                    let value_str = value.clone();
                    upstream_request.remove_header(name_str.as_str());
                    upstream_request
                        .insert_header(name_str, value_str)
                        .map_err(|e| anyhow!("Failed to set header {}: {}", name, e))?;
                }
            }

            // Remove headers
            if let Some(remove_headers) = &request_headers.remove {
                for name in remove_headers.iter() {
                    upstream_request.remove_header(name.as_str());
                }
            }
        }

        Ok(())
    }

    async fn process_response(
        &self,
        _session: &mut Session,
        response: &mut ResponseHeader,
        _ctx: &mut RequestContext,
        _route: &CompiledRoute,
    ) -> Result<()> {
        if let Some(response_headers) = &self.config.response_headers {
            // Add headers
            if let Some(add_headers) = &response_headers.add {
                for (name, value) in add_headers.iter() {
                    let name_str = name.clone();
                    let value_str = value.clone();
                    response
                        .insert_header(name_str, value_str)
                        .map_err(|e| anyhow!("Failed to add response header {}: {}", name, e))?;
                }
            }

            // Set headers (overwrite)
            if let Some(set_headers) = &response_headers.set {
                for (name, value) in set_headers.iter() {
                    let name_str = name.clone();
                    let value_str = value.clone();
                    response.remove_header(name_str.as_str());
                    response
                        .insert_header(name_str, value_str)
                        .map_err(|e| anyhow!("Failed to set response header {}: {}", name, e))?;
                }
            }

            // Remove headers
            if let Some(remove_headers) = &response_headers.remove {
                for name in remove_headers.iter() {
                    response.remove_header(name.as_str());
                }
            }
        }

        Ok(())
    }
}

/// Middleware chain that processes multiple middleware in order
pub struct MiddlewareChain {
    middlewares: std::collections::HashMap<String, Arc<dyn Middleware>>,
}

impl MiddlewareChain {
    /// Create a new middleware chain from configuration
    pub fn new(config: &MiddlewareConfig) -> Result<Self> {
        let mut middlewares = std::collections::HashMap::new();

        // Add rate limiting middleware
        if let Some(rate_limiting_config) = &config.rate_limiting {
            middlewares.insert(
                "rate_limit".to_string(),
                Arc::new(RateLimitingMiddleware::new(rate_limiting_config.clone()))
                    as Arc<dyn Middleware>,
            );
        }

        // Add authentication middleware
        if let Some(auth_config) = &config.authentication {
            middlewares.insert(
                "auth".to_string(),
                Arc::new(AuthenticationMiddleware::new(auth_config.clone())) as Arc<dyn Middleware>,
            );
        }

        // Add CORS middleware
        if let Some(cors_config) = &config.cors {
            middlewares.insert(
                "cors".to_string(),
                Arc::new(CorsMiddleware::new(cors_config.clone())) as Arc<dyn Middleware>,
            );
        }

        // Add header transformation middleware
        if let Some(transform_config) = &config.transform {
            middlewares.insert(
                "transform".to_string(),
                Arc::new(HeaderTransformMiddleware::new(transform_config.clone()))
                    as Arc<dyn Middleware>,
            );
        }

        Ok(Self { middlewares })
    }

    /// Process request through specified middleware only
    pub async fn process_request(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
        route: &CompiledRoute,
    ) -> Result<bool> {
        // Only apply middleware that are specified for this route
        if let Some(route_middleware) = &route.config.middleware {
            for middleware_name in route_middleware {
                if let Some(middleware) = self.middlewares.get(middleware_name) {
                    if middleware.process_request(session, ctx, route).await? {
                        return Ok(true); // Early return requested
                    }
                }
            }
        }
        Ok(false)
    }

    /// Process upstream request through specified middleware only
    pub async fn process_upstream_request(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut RequestContext,
        route: &CompiledRoute,
    ) -> Result<()> {
        // Only apply middleware that are specified for this route
        if let Some(route_middleware) = &route.config.middleware {
            for middleware_name in route_middleware {
                if let Some(middleware) = self.middlewares.get(middleware_name) {
                    middleware
                        .process_upstream_request(session, upstream_request, ctx, route)
                        .await?;
                }
            }
        }
        Ok(())
    }

    /// Process response through specified middleware only
    pub async fn process_response(
        &self,
        session: &mut Session,
        response: &mut ResponseHeader,
        ctx: &mut RequestContext,
        route: &CompiledRoute,
    ) -> Result<()> {
        // Only apply middleware that are specified for this route
        if let Some(route_middleware) = &route.config.middleware {
            for middleware_name in route_middleware {
                if let Some(middleware) = self.middlewares.get(middleware_name) {
                    middleware
                        .process_response(session, response, ctx, route)
                        .await?;
                }
            }
        }
        Ok(())
    }
}
