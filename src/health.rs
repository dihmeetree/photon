/// Health check system for upstream servers
use anyhow::{anyhow, Result};
use log::{debug, info, warn};
use pingora_timeout::{sleep, timeout};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::net::TcpStream;

use crate::{
    config::{BackendHealthCheckConfig, HealthCheckConfig, HealthCheckType},
    load_balancer::{BackendManager, UpstreamServer},
};

/// High-performance health check status for an upstream server
#[derive(Debug, Clone)]
pub struct HealthStatus {
    /// Whether the server is currently healthy
    pub healthy: bool,
    /// Number of consecutive failures
    pub consecutive_failures: u32,
    /// Number of consecutive successes
    pub consecutive_successes: u32,
    /// Last check timestamp (nanos since UNIX_EPOCH for better performance)
    pub last_check_nanos: u64,
    /// Last error message (if any)
    pub last_error: Option<String>,
}

impl HealthStatus {
    /// Get last check as Instant
    pub fn last_check(&self) -> std::time::Instant {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let duration_since = now.saturating_sub(self.last_check_nanos);
        std::time::Instant::now() - std::time::Duration::from_nanos(duration_since)
    }
}

impl Default for HealthStatus {
    fn default() -> Self {
        let now_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        Self {
            healthy: true, // Start assuming healthy
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_check_nanos: now_nanos,
            last_error: None,
        }
    }
}

/// Health checker for a specific upstream server
pub struct UpstreamHealthChecker {
    /// Upstream server reference
    upstream: Arc<UpstreamServer>,
    /// Health check configuration
    config: BackendHealthCheckConfig,
    /// Current health status
    status: Arc<std::sync::RwLock<HealthStatus>>,
    /// Whether health checks are running
    running: AtomicBool,
}

impl UpstreamHealthChecker {
    /// Create a new health checker for an upstream
    pub fn new(upstream: Arc<UpstreamServer>, config: BackendHealthCheckConfig) -> Self {
        Self {
            upstream,
            config,
            status: Arc::new(std::sync::RwLock::new(HealthStatus::default())),
            running: AtomicBool::new(false),
        }
    }

    /// Start health checking for this upstream with jittered scheduling
    pub async fn start(&self, global_config: &HealthCheckConfig) {
        if self.running.swap(true, Ordering::Relaxed) {
            return; // Already running
        }

        let upstream = self.upstream.clone();
        let config = self.config.clone();
        let global_config = global_config.clone();
        let status = self.status.clone();
        let running = Arc::new(AtomicBool::new(true));
        let running_check = running.clone();

        tokio::spawn(async move {
            let base_interval = config.interval.unwrap_or(global_config.interval);

            // Add jitter to prevent thundering herd
            let jitter = rand::random::<f64>() * 0.2; // ±10% jitter
            let jitter_multiplier = 1.0 + (jitter - 0.1);
            let check_interval =
                Duration::from_secs_f64(base_interval.as_secs_f64() * jitter_multiplier);

            info!(
                "Starting health checks for upstream {} (interval: {:?}, jittered: {:?})",
                upstream.address, base_interval, check_interval
            );

            // Initial random delay to spread out health checks
            let initial_delay = Duration::from_millis(rand::random::<u64>() % 1000);
            sleep(initial_delay).await;

            while running_check.load(Ordering::Relaxed) {
                let check_start = std::time::Instant::now();
                let check_result =
                    Self::perform_health_check(&upstream, &config, &global_config).await;
                let check_duration = check_start.elapsed();

                // Update health status and determine next check interval
                let is_healthy = {
                    let mut status_guard = status.write().unwrap();
                    status_guard.last_check_nanos = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos() as u64;

                    match check_result {
                        Ok(_) => {
                            status_guard.consecutive_successes += 1;
                            status_guard.consecutive_failures = 0;
                            status_guard.last_error = None;

                            // Mark as healthy if we have enough consecutive successes
                            if status_guard.consecutive_successes >= global_config.success_threshold
                            {
                                if !status_guard.healthy {
                                    info!("Upstream {} is now healthy", upstream.address);
                                    upstream.mark_healthy();
                                }
                                status_guard.healthy = true;
                            }
                        }
                        Err(e) => {
                            status_guard.consecutive_failures += 1;
                            status_guard.consecutive_successes = 0;
                            status_guard.last_error = Some(e.to_string());

                            // Mark as unhealthy if we have enough consecutive failures
                            if status_guard.consecutive_failures >= global_config.failure_threshold
                            {
                                if status_guard.healthy {
                                    warn!("Upstream {} is now unhealthy: {}", upstream.address, e);
                                    upstream.mark_unhealthy();
                                }
                                status_guard.healthy = false;
                            }
                        }
                    }
                    status_guard.healthy
                };

                // Adaptive interval based on health status and check duration
                let sleep_duration = if is_healthy {
                    check_interval
                } else {
                    // More frequent checks for unhealthy upstreams
                    Duration::from_secs_f64(check_interval.as_secs_f64() * 0.5)
                }
                .saturating_sub(check_duration); // Account for check execution time

                if sleep_duration > Duration::ZERO {
                    sleep(sleep_duration).await;
                }
            }

            info!("Health checks stopped for upstream {}", upstream.address);
        });
    }

    /// Stop health checking
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    /// Get current health status
    pub fn get_status(&self) -> HealthStatus {
        self.status.read().unwrap().clone()
    }

    /// Perform a single health check
    async fn perform_health_check(
        upstream: &UpstreamServer,
        config: &BackendHealthCheckConfig,
        global_config: &HealthCheckConfig,
    ) -> Result<()> {
        let check_timeout = global_config.timeout;

        match config.check_type {
            HealthCheckType::Tcp => Self::tcp_health_check(&upstream.address, check_timeout).await,
            HealthCheckType::Http => {
                Self::http_health_check(
                    &upstream.address,
                    config.path.as_deref().unwrap_or("/health"),
                    config.expected_status.unwrap_or(200),
                    false,
                    check_timeout,
                )
                .await
            }
            HealthCheckType::Https => {
                Self::http_health_check(
                    &upstream.address,
                    config.path.as_deref().unwrap_or("/health"),
                    config.expected_status.unwrap_or(200),
                    true,
                    check_timeout,
                )
                .await
            }
        }
    }

    /// Perform TCP health check
    async fn tcp_health_check(address: &str, check_timeout: Duration) -> Result<()> {
        debug!("Performing TCP health check for {}", address);

        timeout(check_timeout, TcpStream::connect(address))
            .await
            .map_err(|_| anyhow!("TCP health check timeout"))?
            .map_err(|e| anyhow!("TCP connection failed: {}", e))?;

        debug!("TCP health check passed for {}", address);
        Ok(())
    }

    /// Perform HTTP/HTTPS health check
    async fn http_health_check(
        address: &str,
        path: &str,
        expected_status: u16,
        use_tls: bool,
        check_timeout: Duration,
    ) -> Result<()> {
        debug!(
            "Performing {} health check for {} (path: {}, expected status: {})",
            if use_tls { "HTTPS" } else { "HTTP" },
            address,
            path,
            expected_status
        );

        let scheme = if use_tls { "https" } else { "http" };
        let url = format!("{}://{}{}", scheme, address, path);

        // Create HTTP client with timeout and proper TLS verification
        let client = reqwest::Client::builder()
            .timeout(check_timeout)
            .https_only(use_tls) // Only allow HTTPS when TLS is enabled
            .build()
            .map_err(|e| anyhow!("Failed to create HTTP client: {}", e))?;

        let response = client
            .get(&url)
            .send()
            .await
            .map_err(|e| anyhow!("HTTP request failed: {}", e))?;

        let status_code = response.status().as_u16();
        if status_code == expected_status {
            debug!(
                "HTTP health check passed for {} (status: {})",
                address, status_code
            );
            Ok(())
        } else {
            Err(anyhow!(
                "HTTP health check failed: expected status {}, got {}",
                expected_status,
                status_code
            ))
        }
    }
}

/// Manager for all health checks
pub struct HealthCheckManager {
    /// Global health check configuration
    config: HealthCheckConfig,
    /// Backend manager reference
    backend_manager: Arc<BackendManager>,
    /// Health checkers for each upstream
    checkers: std::sync::RwLock<HashMap<String, Arc<UpstreamHealthChecker>>>,
    /// Whether health checks are running
    running: AtomicBool,
}

impl HealthCheckManager {
    /// Create a new health check manager
    pub fn new(config: HealthCheckConfig, backend_manager: Arc<BackendManager>) -> Self {
        Self {
            config,
            backend_manager,
            checkers: std::sync::RwLock::new(HashMap::new()),
            running: AtomicBool::new(false),
        }
    }

    /// Initialize health checkers for all configured backends with proper backend configs
    pub async fn initialize_checkers(
        &self,
        backend_configs: &std::collections::HashMap<String, crate::config::BackendConfig>,
    ) -> Result<()> {
        for (backend_name, backend_config) in backend_configs {
            let upstreams = self.backend_manager.get_backend_upstreams(backend_name);

            for upstream in upstreams {
                // Use backend-specific health check configuration or defaults
                let health_check_config =
                    if let Some(backend_health_config) = &backend_config.health_check {
                        backend_health_config.clone()
                    } else {
                        // Default health check configuration
                        BackendHealthCheckConfig {
                            check_type: HealthCheckType::Http,
                            path: Some("/health".to_string()),
                            expected_status: Some(200),
                            interval: None,
                        }
                    };

                let checker = Arc::new(UpstreamHealthChecker::new(
                    upstream.clone(),
                    health_check_config,
                ));

                let checker_key = format!("{}:{}", backend_name, upstream.address);
                self.checkers.write().unwrap().insert(checker_key, checker);
            }
        }

        info!(
            "Initialized {} health checkers with backend-specific configurations",
            self.checkers.read().unwrap().len()
        );

        Ok(())
    }

    /// Start all health checks
    pub async fn start(&self) -> Result<()> {
        if self.running.swap(true, Ordering::Relaxed) {
            return Ok(()); // Already running
        }

        info!("Starting health check manager");

        let checkers = self.checkers.read().unwrap().clone();
        for checker in checkers.values() {
            checker.start(&self.config).await;
        }

        info!(
            "Health check manager started with {} checkers",
            checkers.len()
        );
        Ok(())
    }

    /// Stop all health checks
    pub fn stop(&self) {
        if !self.running.swap(false, Ordering::Relaxed) {
            return; // Already stopped
        }

        info!("Stopping health check manager");

        let checkers = self.checkers.read().unwrap();
        for checker in checkers.values() {
            checker.stop();
        }

        info!("Health check manager stopped");
    }

    /// Add health checker for a new upstream
    pub async fn add_upstream_checker(
        &self,
        backend_name: &str,
        upstream: Arc<UpstreamServer>,
        config: Option<BackendHealthCheckConfig>,
    ) -> Result<()> {
        let health_check_config = config.unwrap_or(BackendHealthCheckConfig {
            check_type: HealthCheckType::Tcp,
            path: None,
            expected_status: None,
            interval: None,
        });

        let checker = Arc::new(UpstreamHealthChecker::new(
            upstream.clone(),
            health_check_config,
        ));

        let checker_key = format!("{}:{}", backend_name, upstream.address);

        // Add to checkers map
        self.checkers
            .write()
            .unwrap()
            .insert(checker_key, checker.clone());

        // Start health checking if manager is running
        if self.running.load(Ordering::Relaxed) {
            checker.start(&self.config).await;
        }

        debug!(
            "Added health checker for upstream {} in backend {}",
            upstream.address, backend_name
        );

        Ok(())
    }

    /// Remove health checker for an upstream
    pub fn remove_upstream_checker(&self, backend_name: &str, upstream_address: &str) {
        let checker_key = format!("{}:{}", backend_name, upstream_address);

        if let Some(checker) = self.checkers.write().unwrap().remove(&checker_key) {
            checker.stop();
            debug!(
                "Removed health checker for upstream {} in backend {}",
                upstream_address, backend_name
            );
        }
    }

    /// Get health status for all upstreams
    pub fn get_health_status(&self) -> HashMap<String, HealthStatus> {
        let checkers = self.checkers.read().unwrap();
        checkers
            .iter()
            .map(|(key, checker)| (key.clone(), checker.get_status()))
            .collect()
    }

    /// Get health status for a specific upstream
    pub fn get_upstream_health_status(
        &self,
        backend_name: &str,
        upstream_address: &str,
    ) -> Option<HealthStatus> {
        let checker_key = format!("{}:{}", backend_name, upstream_address);
        self.checkers
            .read()
            .unwrap()
            .get(&checker_key)
            .map(|checker| checker.get_status())
    }

    /// Get health statistics
    pub fn get_health_stats(&self) -> HealthStats {
        let checkers = self.checkers.read().unwrap();
        let mut stats = HealthStats::default();

        for checker in checkers.values() {
            let status = checker.get_status();
            stats.total_upstreams += 1;
            if status.healthy {
                stats.healthy_upstreams += 1;
            } else {
                stats.unhealthy_upstreams += 1;
            }
        }

        stats
    }
}

/// Health statistics
#[derive(Debug, Default, Clone)]
pub struct HealthStats {
    /// Total number of upstreams
    pub total_upstreams: u32,
    /// Number of healthy upstreams
    pub healthy_upstreams: u32,
    /// Number of unhealthy upstreams
    pub unhealthy_upstreams: u32,
}

impl HealthStats {
    /// Get health percentage
    pub fn health_percentage(&self) -> f64 {
        if self.total_upstreams == 0 {
            100.0
        } else {
            (self.healthy_upstreams as f64 / self.total_upstreams as f64) * 100.0
        }
    }
}
