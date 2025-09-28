/// High-performance response caching using Pingora's production-grade memory cache
use anyhow::Result;
use bytes::Bytes;
use log::debug;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_memory_cache::{CacheStatus as PingoraCacheStatus, MemoryCache};
use std::time::Duration;

use crate::config::CacheConfig;

/// Cache status for responses
#[derive(Debug, Clone, Copy)]
pub enum CacheStatus {
    Hit,
    Miss,
    Stale,
    Expired,
}

impl From<PingoraCacheStatus> for CacheStatus {
    fn from(status: PingoraCacheStatus) -> Self {
        match status {
            PingoraCacheStatus::Hit | PingoraCacheStatus::LockHit => CacheStatus::Hit,
            PingoraCacheStatus::Miss => CacheStatus::Miss,
            PingoraCacheStatus::Expired => CacheStatus::Expired,
            PingoraCacheStatus::Stale(_) => CacheStatus::Stale,
        }
    }
}

impl CacheStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            CacheStatus::Hit => "HIT",
            CacheStatus::Miss => "MISS",
            CacheStatus::Stale => "STALE",
            CacheStatus::Expired => "EXPIRED",
        }
    }
}

/// Cached response entry
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub headers: ResponseHeader,
    pub body: Bytes,
}

/// High-performance response cache using Pingora's TinyUFO algorithm
pub struct ResponseCache {
    /// Underlying memory cache with TinyUFO (TinyLFU + S3-FIFO) algorithm
    cache: MemoryCache<String, CacheEntry>,
    /// Cache configuration
    config: CacheConfig,
}

impl ResponseCache {
    /// Create a new response cache with the given configuration
    pub fn new(config: CacheConfig) -> Self {
        Self {
            cache: MemoryCache::new(config.max_entries),
            config,
        }
    }

    /// Generate cache key from request headers
    pub fn generate_cache_key(&self, headers: &RequestHeader) -> Option<String> {
        // Simple cache key: method + path + query (if enabled) + vary headers
        let method = headers.method.as_str();
        let path = headers.uri.path();

        let mut key = format!("{}:{}", method, path);

        // Add query parameters if enabled
        if self.config.cache_with_query_params {
            if let Some(query) = headers.uri.query() {
                key.push('?');
                key.push_str(query);
            }
        }

        // Add accept-encoding for content negotiation
        if let Some(accept_encoding) = headers.headers.get("accept-encoding") {
            if let Ok(encoding) = accept_encoding.to_str() {
                key.push_str("__ae:");
                key.push_str(encoding);
            }
        }

        Some(key)
    }

    /// Get cached response
    pub fn get(&self, cache_key: &str) -> Option<(CacheEntry, CacheStatus)> {
        let (entry, status) = self.cache.get(cache_key);
        entry.map(|e| (e, status.into()))
    }

    /// Store response in cache
    pub fn put(&self, cache_key: String, headers: ResponseHeader, body: Bytes) -> Result<()> {
        // Check if response is cacheable
        let status_code = headers.status.as_u16();
        if !self.is_cacheable(status_code, &headers, body.len()) {
            return Ok(());
        }

        // Calculate TTL
        let ttl = self.calculate_ttl(&headers);

        let entry = CacheEntry { headers, body };

        self.cache.put(&cache_key, entry, ttl);

        debug!("Cached response with key: {} (TTL: {:?})", cache_key, ttl);
        Ok(())
    }

    /// Check if a response is cacheable
    pub fn is_cacheable(
        &self,
        status_code: u16,
        headers: &ResponseHeader,
        body_size: usize,
    ) -> bool {
        // Check status code
        if !Self::is_cacheable_status(status_code) {
            return false;
        }

        // Check body size
        if body_size > self.config.max_body_size {
            return false;
        }

        // Check cache control headers
        if let Some(cache_control) = headers.headers.get("cache-control") {
            if let Ok(cc) = cache_control.to_str() {
                if cc.contains("no-cache") || cc.contains("no-store") || cc.contains("private") {
                    return false;
                }
            }
        }

        // Don't cache responses with Set-Cookie headers
        if headers.headers.contains_key("set-cookie") {
            return false;
        }

        true
    }

    /// Check if status code is cacheable
    fn is_cacheable_status(status: u16) -> bool {
        matches!(
            status,
            200 | 203 | 204 | 206 | 300 | 301 | 404 | 405 | 410 | 414 | 501
        )
    }

    /// Calculate TTL from headers
    fn calculate_ttl(&self, headers: &ResponseHeader) -> Option<Duration> {
        // Check Cache-Control max-age first
        if let Some(cache_control) = headers.headers.get("cache-control") {
            if let Ok(cc) = cache_control.to_str() {
                if let Some(max_age) = Self::parse_max_age(cc) {
                    return Some(Duration::from_secs(max_age));
                }
            }
        }

        // Check Expires header
        if let Some(expires) = headers.headers.get("expires") {
            if let Ok(expires_str) = expires.to_str() {
                if let Some(ttl) = Self::parse_expires(expires_str) {
                    return Some(ttl);
                }
            }
        }

        // Use default TTL
        Some(self.config.default_ttl)
    }

    /// Parse max-age from Cache-Control header
    fn parse_max_age(cache_control: &str) -> Option<u64> {
        for directive in cache_control.split(',') {
            let directive = directive.trim();
            if let Some(max_age_str) = directive.strip_prefix("max-age=") {
                if let Ok(max_age) = max_age_str.trim().parse::<u64>() {
                    return Some(max_age);
                }
            }
        }
        None
    }

    /// Parse Expires header
    fn parse_expires(expires: &str) -> Option<Duration> {
        // Try different HTTP date formats
        use chrono::{DateTime, Utc};

        // RFC 1123 format
        if let Ok(dt) = DateTime::parse_from_rfc2822(expires) {
            let now = Utc::now();
            let dt_utc = dt.with_timezone(&Utc);
            if dt_utc > now {
                return (dt_utc - now).to_std().ok();
            }
        }

        // RFC 3339 format (fallback)
        if let Ok(dt) = DateTime::parse_from_rfc3339(expires) {
            let now = Utc::now();
            let dt_utc = dt.with_timezone(&Utc);
            if dt_utc > now {
                return (dt_utc - now).to_std().ok();
            }
        }

        None
    }

    /// Add cache status headers to response
    pub fn add_cache_headers(
        &self,
        headers: &mut ResponseHeader,
        status: CacheStatus,
        cache_key: Option<&str>,
    ) -> Result<()> {
        // Add X-Cache header
        headers
            .insert_header("X-Cache", status.as_str())
            .map_err(|e| anyhow::anyhow!("Failed to add X-Cache header: {}", e))?;

        // Add X-Cache-Key header if provided
        if let Some(key) = cache_key {
            headers
                .insert_header("X-Cache-Key", key)
                .map_err(|e| anyhow::anyhow!("Failed to add X-Cache-Key header: {}", e))?;
        }

        // Add Age header for cache hits
        if matches!(status, CacheStatus::Hit | CacheStatus::Stale) {
            headers
                .insert_header("Age", "0") // Simplified for now
                .map_err(|e| anyhow::anyhow!("Failed to add Age header: {}", e))?;
        }

        Ok(())
    }

    /// Get cache statistics (for monitoring)
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            max_entries: self.config.max_entries,
            // Note: TinyUFO doesn't expose current entry count easily
            // This would need to be tracked separately if needed
            current_entries: 0,
        }
    }
}

/// Cache statistics
#[derive(Debug)]
pub struct CacheStats {
    pub max_entries: usize,
    pub current_entries: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;
    use pingora_http::{RequestHeader, ResponseHeader};

    fn create_test_cache() -> ResponseCache {
        let config = CacheConfig {
            enabled: true,
            max_entries: 1000,
            default_ttl: Duration::from_secs(300),
            max_body_size: 1024 * 1024,
            cache_with_query_params: false,
        };
        ResponseCache::new(config)
    }

    fn create_test_request() -> RequestHeader {
        RequestHeader::build(Method::GET, b"/test", None).unwrap()
    }

    fn create_test_response() -> ResponseHeader {
        let mut resp = ResponseHeader::build(200, None).unwrap();
        resp.insert_header("content-type", "text/plain").unwrap();
        resp
    }

    #[test]
    fn test_cache_key_generation() {
        let cache = create_test_cache();
        let headers = create_test_request();

        let key = cache.generate_cache_key(&headers).unwrap();
        assert_eq!(key, "GET:/test");
    }

    #[test]
    fn test_cache_put_get() {
        let cache = create_test_cache();
        let headers = create_test_response();
        let body = Bytes::from("test response");

        // Put in cache
        cache
            .put("test_key".to_string(), headers.clone(), body.clone())
            .unwrap();

        // Get from cache
        let result = cache.get("test_key");
        assert!(result.is_some());

        let (entry, status) = result.unwrap();
        assert!(matches!(status, CacheStatus::Hit));
        assert_eq!(entry.body, body);
    }

    #[test]
    fn test_cacheable_status_codes() {
        assert!(ResponseCache::is_cacheable_status(200));
        assert!(ResponseCache::is_cacheable_status(404));
        assert!(!ResponseCache::is_cacheable_status(500));
        assert!(!ResponseCache::is_cacheable_status(503));
    }

    #[test]
    fn test_max_age_parsing() {
        assert_eq!(ResponseCache::parse_max_age("max-age=3600"), Some(3600));
        assert_eq!(
            ResponseCache::parse_max_age("public, max-age=600"),
            Some(600)
        );
        assert_eq!(ResponseCache::parse_max_age("no-cache"), None);
    }
}
