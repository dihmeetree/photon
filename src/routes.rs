/// Request routing implementation for the API Gateway
use anyhow::{anyhow, Result};
use log::debug;
use pingora_http::RequestHeader;
use regex::Regex;
use smallstr::SmallString;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use crate::config::{RouteConfig, WebSocketConfig};

/// Cache for common regex patterns to avoid recompilation
static COMMON_REGEX_PATTERNS: OnceLock<HashMap<String, Regex>> = OnceLock::new();

/// High-performance route trie for fast path matching
#[derive(Debug, Clone)]
pub struct RouteTrieNode {
    /// Routes that match exactly at this node
    exact_routes: Vec<Arc<CompiledRoute>>,
    /// Child nodes for path segments
    children: HashMap<SmallString<[u8; 16]>, Box<RouteTrieNode>>,
    /// Wildcard child for patterns like /api/*
    wildcard_child: Option<Box<RouteTrieNode>>,
    /// Double wildcard for patterns like /api/**
    double_wildcard_routes: Vec<Arc<CompiledRoute>>,
}

impl Default for RouteTrieNode {
    fn default() -> Self {
        Self::new()
    }
}

impl RouteTrieNode {
    /// Create a new empty trie node
    pub fn new() -> Self {
        Self {
            exact_routes: Vec::new(),
            children: HashMap::new(),
            wildcard_child: None,
            double_wildcard_routes: Vec::new(),
        }
    }

    /// Insert a route into the trie (optimized without cloning)
    pub fn insert(&mut self, path_segments: &[&str], route: Arc<CompiledRoute>) {
        if path_segments.is_empty() {
            self.exact_routes.push(route);
            return;
        }

        let segment = path_segments[0];
        let remaining = &path_segments[1..];

        if segment == "**" {
            // Double wildcard matches everything from here
            self.double_wildcard_routes.push(route);
        } else if segment == "*" {
            // Single wildcard - direct mutable access, no cloning needed
            if self.wildcard_child.is_none() {
                self.wildcard_child = Some(Box::new(RouteTrieNode::new()));
            }
            // Direct mutable access to the boxed node
            self.wildcard_child
                .as_mut()
                .unwrap()
                .insert(remaining, route);
        } else {
            // Exact segment match - direct mutable access, no cloning needed
            let segment_key: SmallString<[u8; 16]> = SmallString::from_str(segment);
            if !self.children.contains_key(&segment_key) {
                self.children
                    .insert(segment_key.clone(), Box::new(RouteTrieNode::new()));
            }
            // Direct mutable access to the boxed node
            self.children
                .get_mut(&segment_key)
                .unwrap()
                .insert(remaining, route);
        }
    }

    /// Find matching routes for a path
    pub fn find_matches(&self, path_segments: &[&str], matches: &mut Vec<Arc<CompiledRoute>>) {
        // Add exact matches at this level
        matches.extend(self.exact_routes.iter().cloned());

        // Add double wildcard matches (they match everything from here)
        matches.extend(self.double_wildcard_routes.iter().cloned());

        if path_segments.is_empty() {
            return;
        }

        let segment = path_segments[0];
        let remaining = &path_segments[1..];

        // Try exact match first
        let segment_key: SmallString<[u8; 16]> = SmallString::from_str(segment);
        if let Some(child) = self.children.get(&segment_key) {
            child.find_matches(remaining, matches);
        }

        // Try wildcard match
        if let Some(wildcard_child) = &self.wildcard_child {
            wildcard_child.find_matches(remaining, matches);
        }
    }
}

/// Initialize common regex patterns cache
fn get_common_patterns() -> &'static HashMap<String, Regex> {
    COMMON_REGEX_PATTERNS.get_or_init(|| {
        let mut patterns = HashMap::new();

        // Pre-compile common API patterns
        if let Ok(regex) = Regex::new("^/api/.*$") {
            patterns.insert("/api/**".to_string(), regex);
        }
        if let Ok(regex) = Regex::new("^/api/v[0-9]+/.*$") {
            patterns.insert("/api/v*/***".to_string(), regex);
        }
        if let Ok(regex) = Regex::new("^/assets/.*$") {
            patterns.insert("/assets/**".to_string(), regex);
        }
        if let Ok(regex) = Regex::new("^/static/.*$") {
            patterns.insert("/static/**".to_string(), regex);
        }
        if let Ok(regex) = Regex::new("^.*$") {
            patterns.insert("/**".to_string(), regex);
        }

        patterns
    })
}

/// Compiled route with regex pattern for efficient matching
#[derive(Debug, Clone)]
pub struct CompiledRoute {
    /// Original route configuration
    pub config: RouteConfig,
    /// Compiled path regex pattern
    pub path_regex: Regex,
    /// Compiled host regex pattern (if specified)
    pub host_regex: Option<Regex>,
}

impl CompiledRoute {
    /// Create a new compiled route from configuration
    pub fn new(config: RouteConfig) -> Result<Self> {
        // Check cache for common patterns first for better performance
        let path_regex = if let Some(cached_regex) = get_common_patterns().get(&config.path) {
            cached_regex.clone()
        } else if config.path.starts_with('^') && config.path.ends_with('$') {
            // Already a regex pattern
            Regex::new(&config.path)
                .map_err(|e| anyhow!("Invalid path regex '{}': {}", config.path, e))?
        } else {
            // Convert glob-like pattern to regex
            let regex_pattern = glob_to_regex(&config.path)?;
            Regex::new(&regex_pattern)
                .map_err(|e| anyhow!("Failed to compile path pattern '{}': {}", config.path, e))?
        };

        // Compile host pattern if specified
        let host_regex = if let Some(host_pattern) = &config.host {
            let regex_pattern = if host_pattern.starts_with('^') && host_pattern.ends_with('$') {
                host_pattern.clone()
            } else {
                glob_to_regex(host_pattern)?
            };
            Some(
                Regex::new(&regex_pattern)
                    .map_err(|e| anyhow!("Invalid host regex '{}': {}", host_pattern, e))?,
            )
        } else {
            None
        };

        Ok(Self {
            config,
            path_regex,
            host_regex,
        })
    }

    /// Check if this route matches the given request
    pub fn matches(&self, req: &RequestHeader) -> bool {
        // Check HTTP method
        if let Some(methods) = &self.config.methods {
            let method_str = req.method.as_str();
            if !methods.iter().any(|m| m.eq_ignore_ascii_case(method_str)) {
                return false;
            }
        }

        // Check path
        if !self.path_regex.is_match(req.uri.path()) {
            return false;
        }

        // Check host header
        if let Some(host_regex) = &self.host_regex {
            if let Some(host_header) = req.headers.get("host") {
                if let Ok(host_str) = host_header.to_str() {
                    if !host_regex.is_match(host_str) {
                        return false;
                    }
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }

        true
    }

    /// Fast method check without expensive operations
    pub fn matches_method(&self, method: &http::Method) -> bool {
        if let Some(methods) = &self.config.methods {
            let method_str = method.as_str();
            methods.iter().any(|m| m.eq_ignore_ascii_case(method_str))
        } else {
            true // No method restriction
        }
    }

    /// Check for fast exact path matches before expensive regex
    pub fn has_exact_path_match(&self, path: &str) -> bool {
        // For simple patterns without regex metacharacters, do direct string comparison
        let pattern = &self.config.path;

        // Check for exact matches
        if pattern == path {
            return true;
        }

        // Check for simple prefix patterns like "/api/*" -> "/api/"
        if pattern.ends_with("/*") {
            let prefix = &pattern[..pattern.len() - 2]; // Remove "/*"
            if path.starts_with(prefix) {
                return true;
            }
        }

        // Check for simple prefix patterns like "/api/**" -> "/api/"
        if pattern.ends_with("/**") {
            let prefix = &pattern[..pattern.len() - 3]; // Remove "/**"
            if path.starts_with(prefix) {
                return true;
            }
        }

        false
    }

    /// Check if this route supports WebSocket upgrades
    pub fn supports_websocket(&self) -> bool {
        self.config
            .websocket
            .as_ref()
            .map(|ws| ws.enabled)
            .unwrap_or(false)
    }

    /// Check if a request is a WebSocket upgrade request
    pub fn is_websocket_upgrade_request(&self, req: &RequestHeader) -> bool {
        // Check if route supports WebSocket
        if !self.supports_websocket() {
            return false;
        }

        // HTTP/1.1 requirement for upgrades
        if req.version != http::Version::HTTP_11 {
            return false;
        }

        // Check for Upgrade header with "websocket" value
        let has_upgrade = req
            .headers
            .get("upgrade")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false);

        // Check for Connection header with "upgrade" value
        let has_connection_upgrade = req
            .headers
            .get("connection")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_lowercase().contains("upgrade"))
            .unwrap_or(false);

        // Check for WebSocket key (required by RFC 6455)
        let has_ws_key = req.headers.get("sec-websocket-key").is_some();

        // Check for WebSocket version (required by RFC 6455)
        let has_ws_version = req
            .headers
            .get("sec-websocket-version")
            .and_then(|v| v.to_str().ok())
            .map(|v| v == "13") // RFC 6455 requires version 13
            .unwrap_or(false);

        has_upgrade && has_connection_upgrade && has_ws_key && has_ws_version
    }

    /// Get WebSocket configuration for this route
    pub fn websocket_config(&self) -> Option<&WebSocketConfig> {
        self.config.websocket.as_ref()
    }

    /// Validate WebSocket subprotocol against configured protocols
    pub fn validate_websocket_protocol(&self, requested_protocol: &str) -> bool {
        if let Some(ws_config) = &self.config.websocket {
            if let Some(allowed_protocols) = &ws_config.protocols {
                return allowed_protocols
                    .iter()
                    .any(|p| p.eq_ignore_ascii_case(requested_protocol));
            }
        }
        // If no protocols configured, allow any protocol
        true
    }

    /// Check if caching is enabled for this route
    pub fn is_cache_enabled(&self) -> bool {
        // Check route-specific cache configuration first
        if let Some(ref cache_config) = self.config.cache {
            return cache_config.enabled;
        }
        // If no route-specific config, defaults to false (cache disabled)
        false
    }

    /// Check if caching is enabled for the given HTTP method
    pub fn is_cache_enabled_for_method(&self, method: &http::Method) -> bool {
        if !self.is_cache_enabled() {
            return false;
        }

        // Check if method is allowed for caching in route config
        if let Some(ref cache_config) = self.config.cache {
            if let Some(ref methods) = cache_config.methods {
                return methods
                    .iter()
                    .any(|m| m.eq_ignore_ascii_case(method.as_str()));
            }
        }

        // Default to only GET requests if no methods specified
        method == http::Method::GET
    }
}

/// Route manager for handling request routing with optimized storage
pub struct RouteManager {
    /// Compiled routes in priority order (Arc to avoid cloning)
    routes: Vec<Arc<CompiledRoute>>,
    /// Route lookup by ID (Arc to avoid cloning)
    route_by_id: HashMap<String, Arc<CompiledRoute>>,
    /// High-performance trie for fast path matching
    route_trie: RouteTrieNode,
    /// Routes that require regex matching (complex patterns)
    regex_routes: Vec<Arc<CompiledRoute>>,
}

impl RouteManager {
    /// Create a new route manager from route configurations
    pub fn new(route_configs: &[RouteConfig]) -> Result<Self> {
        let mut routes = Vec::with_capacity(route_configs.len());
        let mut route_by_id = HashMap::with_capacity(route_configs.len());
        let mut route_trie = RouteTrieNode::new();
        let mut regex_routes = Vec::new();

        for config in route_configs {
            let compiled_route = Arc::new(CompiledRoute::new(config.clone())?);

            // Check for duplicate route IDs
            if route_by_id.contains_key(&config.id) {
                return Err(anyhow!("Duplicate route ID: {}", config.id));
            }

            route_by_id.insert(config.id.clone(), compiled_route.clone());
            routes.push(compiled_route.clone());

            // Categorize routes for optimal matching
            if Self::is_simple_pattern(&config.path) {
                // Simple patterns go into the trie
                let segments: Vec<&str> = config
                    .path
                    .trim_matches('/')
                    .split('/')
                    .filter(|s| !s.is_empty())
                    .collect();
                route_trie.insert(&segments, compiled_route);
            } else {
                // Complex patterns require regex matching
                regex_routes.push(compiled_route);
            }
        }

        // Sort routes by priority (more specific routes first)
        routes.sort_by(|a, b| {
            // Routes with host patterns have higher priority
            match (a.host_regex.is_some(), b.host_regex.is_some()) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => {
                    // Routes with method restrictions have higher priority
                    match (a.config.methods.is_some(), b.config.methods.is_some()) {
                        (true, false) => std::cmp::Ordering::Less,
                        (false, true) => std::cmp::Ordering::Greater,
                        _ => {
                            // Routes with longer paths have higher priority
                            b.config.path.len().cmp(&a.config.path.len())
                        }
                    }
                }
            }
        });

        // Sort regex routes by specificity
        regex_routes.sort_by(|a, b| {
            // More specific patterns first
            let a_specificity = Self::calculate_specificity(&a.config.path);
            let b_specificity = Self::calculate_specificity(&b.config.path);
            b_specificity.cmp(&a_specificity)
        });

        debug!(
            "Loaded {} routes ({} trie, {} regex)",
            routes.len(),
            routes.len() - regex_routes.len(),
            regex_routes.len()
        );
        for route in &routes {
            debug!(
                "Route '{}': {} {} -> backend '{}'",
                route.config.id,
                route
                    .config
                    .methods
                    .as_ref()
                    .map(|m| m.join(","))
                    .unwrap_or_else(|| "*".to_string()),
                route.config.path,
                route.config.backend
            );
        }

        Ok(Self {
            routes,
            route_by_id,
            route_trie,
            regex_routes,
        })
    }

    /// Check if a pattern is simple enough for trie matching
    fn is_simple_pattern(path: &str) -> bool {
        // Simple patterns: exact paths, single wildcards (*), double wildcards (**)
        // Complex patterns: regex, character classes, etc.
        !path.contains('[')
            && !path.contains('{')
            && !path.contains('^')
            && !path.contains('$')
            && !path.contains('+')
    }

    /// Calculate pattern specificity for sorting
    fn calculate_specificity(path: &str) -> i32 {
        let mut score = 0;
        for segment in path.split('/') {
            match segment {
                "**" => score -= 10,                // Very generic
                "*" => score -= 5,                  // Generic
                s if s.contains('*') => score -= 2, // Partially generic
                s if !s.is_empty() => score += 10,  // Specific
                _ => {}
            }
        }
        score
    }

    /// Find the first matching route for a request with optimized trie-based matching
    pub fn find_route(&self, req: &RequestHeader) -> Option<Arc<CompiledRoute>> {
        let path = req.uri.path();
        let method = &req.method;

        // Ultra-fast trie-based matching for simple patterns
        let segments: Vec<&str> = path
            .trim_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();
        let mut trie_matches = Vec::new();
        self.route_trie.find_matches(&segments, &mut trie_matches);

        // Check trie matches first (fastest path)
        for route in &trie_matches {
            if route.matches_method(method) && route.matches(req) {
                debug!(
                    "Route '{}' trie-matched for {} {}",
                    route.config.id, req.method, path
                );
                return Some(route.clone());
            }
        }

        // Fast path: try exact prefix matches for remaining routes
        for route in &self.routes {
            if !route.matches_method(method) {
                continue;
            }

            if route.has_exact_path_match(path) {
                debug!(
                    "Route '{}' fast-matched for {} {}",
                    route.config.id, req.method, path
                );
                return Some(route.clone());
            }
        }

        // Fallback to regex matching for complex patterns
        for route in &self.regex_routes {
            if route.matches(req) {
                debug!(
                    "Route '{}' regex-matched for {} {}",
                    route.config.id, req.method, path
                );
                return Some(route.clone());
            }
        }

        debug!("No route matched for {} {}", req.method, path);
        None
    }

    /// Get a route by ID
    pub fn get_route(&self, id: &str) -> Option<Arc<CompiledRoute>> {
        self.route_by_id.get(id).cloned()
    }

    /// Get all routes
    pub fn get_routes(&self) -> &[Arc<CompiledRoute>] {
        &self.routes
    }

    /// Get route count
    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    /// Check if a route ID exists
    pub fn has_route(&self, id: &str) -> bool {
        self.route_by_id.contains_key(id)
    }
}

/// Convert a glob-like pattern to a regex pattern
fn glob_to_regex(pattern: &str) -> Result<String> {
    let mut regex = String::with_capacity(pattern.len() * 2);
    regex.push('^');

    let mut chars = pattern.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '*' => {
                if chars.peek() == Some(&'*') {
                    // ** means match anything including path separators
                    chars.next(); // consume the second *
                    regex.push_str(".*");
                } else {
                    // * means match anything except path separators
                    regex.push_str("[^/]*");
                }
            }
            '?' => {
                regex.push_str("[^/]");
            }
            '[' => {
                regex.push('[');
                // Copy character class as-is
                for ch in chars.by_ref() {
                    regex.push(ch);
                    if ch == ']' {
                        break;
                    }
                }
            }
            // Escape regex special characters
            '.' | '+' | '(' | ')' | '{' | '}' | '^' | '$' | '|' | '\\' => {
                regex.push('\\');
                regex.push(ch);
            }
            _ => {
                regex.push(ch);
            }
        }
    }

    regex.push('$');
    Ok(regex)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn create_request(method: &str, path: &str, host: Option<&str>) -> RequestHeader {
        let mut req = RequestHeader::build(method, path.as_bytes(), None).unwrap();
        if let Some(host) = host {
            req.insert_header("host", host).unwrap();
        }
        req
    }

    #[test]
    fn test_glob_to_regex() {
        assert_eq!(glob_to_regex("/api/*").unwrap(), "^/api/[^/]*$");
        assert_eq!(glob_to_regex("/api/**").unwrap(), "^/api/.*$");
        assert_eq!(
            glob_to_regex("/api/v?/users").unwrap(),
            "^/api/v[^/]/users$"
        );
        assert_eq!(
            glob_to_regex("/static/*.{js,css}").unwrap(),
            "^/static/[^/]*\\.\\{js,css\\}$"
        );
    }

    #[test]
    fn test_route_matching() {
        let config = RouteConfig {
            id: "test".to_string(),
            path: "/api/*".to_string(),
            methods: Some(vec!["GET".to_string(), "POST".to_string()]),
            host: Some("example.com".to_string()),
            backend: "test-backend".to_string(),
            middleware: None,
            timeout: None,
            retries: None,
            websocket: None,
            cache: None,
        };

        let route = CompiledRoute::new(config).unwrap();

        // Should match
        assert!(route.matches(&create_request("GET", "/api/users", Some("example.com"))));
        assert!(route.matches(&create_request("POST", "/api/posts", Some("example.com"))));

        // Should not match - wrong method
        assert!(!route.matches(&create_request("DELETE", "/api/users", Some("example.com"))));

        // Should not match - wrong path
        assert!(!route.matches(&create_request("GET", "/v1/users", Some("example.com"))));

        // Should not match - wrong host
        assert!(!route.matches(&create_request("GET", "/api/users", Some("other.com"))));

        // Should not match - no host
        assert!(!route.matches(&create_request("GET", "/api/users", None)));
    }

    #[test]
    fn test_route_priority() {
        let configs = vec![
            RouteConfig {
                id: "generic".to_string(),
                path: "/api/*".to_string(),
                methods: None,
                host: None,
                backend: "generic-backend".to_string(),
                middleware: None,
                timeout: None,
                retries: None,
                websocket: None,
                cache: None,
            },
            RouteConfig {
                id: "specific".to_string(),
                path: "/api/users/*".to_string(),
                methods: Some(vec!["GET".to_string()]),
                host: Some("api.example.com".to_string()),
                backend: "specific-backend".to_string(),
                middleware: None,
                timeout: None,
                retries: None,
                websocket: None,
                cache: None,
            },
        ];

        let manager = RouteManager::new(&configs).unwrap();

        // More specific route should match first
        let req = create_request("GET", "/api/users/123", Some("api.example.com"));
        let route = manager.find_route(&req).unwrap();
        assert_eq!(route.config.id, "specific");

        // Generic route should match when specific doesn't
        let req = create_request("POST", "/api/posts", None);
        let route = manager.find_route(&req).unwrap();
        assert_eq!(route.config.id, "generic");
    }
}
