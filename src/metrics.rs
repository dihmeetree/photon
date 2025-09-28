/// Metrics collection and monitoring for the API Gateway
use anyhow::Result;
use prometheus::{Counter, Histogram, HistogramOpts, IntCounter, IntGauge, Opts, Registry};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use crate::config::MetricsConfig;

/// Batched metrics for efficient updates
#[derive(Debug, Default)]
pub struct MetricsBatch {
    /// Number of requests in this batch
    pub requests: u64,
    /// Number of errors in this batch
    pub errors: u64,
    /// Number of upstream errors in this batch
    pub upstream_errors: u64,
    /// Total duration in seconds for all requests in this batch
    pub total_duration_seconds: f64,
    /// Number of 2xx responses
    pub responses_2xx: u64,
    /// Number of 3xx responses
    pub responses_3xx: u64,
    /// Number of 4xx responses
    pub responses_4xx: u64,
    /// Number of 5xx responses
    pub responses_5xx: u64,
    /// Other status codes
    pub responses_other: u64,
}

impl MetricsBatch {
    /// Create a new empty metrics batch
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a request to the batch
    pub fn add_request(&mut self) {
        self.requests += 1;
    }

    /// Add a response to the batch
    pub fn add_response(&mut self, status_code: u16, duration: Duration) {
        self.total_duration_seconds += duration.as_secs_f64();

        match status_code {
            200..=299 => self.responses_2xx += 1,
            300..=399 => self.responses_3xx += 1,
            400..=499 => self.responses_4xx += 1,
            500..=599 => self.responses_5xx += 1,
            _ => self.responses_other += 1,
        }
    }

    /// Add an error to the batch
    pub fn add_error(&mut self) {
        self.errors += 1;
    }

    /// Add an upstream error to the batch
    pub fn add_upstream_error(&mut self) {
        self.upstream_errors += 1;
    }

    /// Check if the batch is empty
    pub fn is_empty(&self) -> bool {
        self.requests == 0 && self.errors == 0 && self.upstream_errors == 0
    }

    /// Clear the batch
    pub fn clear(&mut self) {
        *self = Self::default();
    }
}

/// Metrics collector for the API Gateway
pub struct MetricsCollector {
    /// Prometheus registry
    registry: Registry,

    // Request metrics
    /// Total number of requests
    requests_total: IntCounter,
    /// Number of requests in flight
    requests_in_flight: IntGauge,
    /// Request duration histogram
    request_duration: Histogram,
    /// Response status code counters
    response_status_total: Counter,

    // Upstream metrics
    /// Total number of upstream requests
    upstream_requests_total: IntCounter,
    /// Number of upstream connection errors
    upstream_errors_total: IntCounter,
    /// Upstream response time histogram
    upstream_duration: Histogram,

    // Backend metrics
    /// Number of healthy upstreams per backend
    healthy_upstreams: IntGauge,
    /// Number of unhealthy upstreams per backend
    unhealthy_upstreams: IntGauge,

    // System metrics
    /// Number of active connections
    active_connections: IntGauge,
    /// Gateway errors
    gateway_errors_total: IntCounter,

    /// Configuration
    config: MetricsConfig,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new(config: &MetricsConfig) -> Result<Self> {
        let registry = Registry::new();

        // Request metrics
        let requests_total = IntCounter::with_opts(Opts::new(
            "gateway_requests_total",
            "Total number of HTTP requests processed by the gateway",
        ))?;
        registry.register(Box::new(requests_total.clone()))?;

        let requests_in_flight = IntGauge::with_opts(Opts::new(
            "gateway_requests_in_flight",
            "Number of HTTP requests currently being processed",
        ))?;
        registry.register(Box::new(requests_in_flight.clone()))?;

        let request_duration = Histogram::with_opts(
            HistogramOpts::new(
                "gateway_request_duration_seconds",
                "HTTP request duration in seconds",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
        )?;
        registry.register(Box::new(request_duration.clone()))?;

        let response_status_total = Counter::with_opts(Opts::new(
            "gateway_response_status_total",
            "Total number of responses by HTTP status code group",
        ))?;
        registry.register(Box::new(response_status_total.clone()))?;

        // Upstream metrics
        let upstream_requests_total = IntCounter::with_opts(Opts::new(
            "gateway_upstream_requests_total",
            "Total number of requests sent to upstream servers",
        ))?;
        registry.register(Box::new(upstream_requests_total.clone()))?;

        let upstream_errors_total = IntCounter::with_opts(Opts::new(
            "gateway_upstream_errors_total",
            "Total number of upstream connection errors",
        ))?;
        registry.register(Box::new(upstream_errors_total.clone()))?;

        let upstream_duration = Histogram::with_opts(
            HistogramOpts::new(
                "gateway_upstream_duration_seconds",
                "Upstream request duration in seconds",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
        )?;
        registry.register(Box::new(upstream_duration.clone()))?;

        // Backend metrics
        let healthy_upstreams = IntGauge::with_opts(Opts::new(
            "gateway_healthy_upstreams",
            "Number of healthy upstream servers per backend",
        ))?;
        registry.register(Box::new(healthy_upstreams.clone()))?;

        let unhealthy_upstreams = IntGauge::with_opts(Opts::new(
            "gateway_unhealthy_upstreams",
            "Number of unhealthy upstream servers per backend",
        ))?;
        registry.register(Box::new(unhealthy_upstreams.clone()))?;

        // System metrics
        let active_connections = IntGauge::with_opts(Opts::new(
            "gateway_active_connections",
            "Number of active client connections",
        ))?;
        registry.register(Box::new(active_connections.clone()))?;

        let gateway_errors_total = IntCounter::with_opts(Opts::new(
            "gateway_errors_total",
            "Total number of gateway errors",
        ))?;
        registry.register(Box::new(gateway_errors_total.clone()))?;

        Ok(Self {
            registry,
            requests_total,
            requests_in_flight,
            request_duration,
            response_status_total,
            upstream_requests_total,
            upstream_errors_total,
            upstream_duration,
            healthy_upstreams,
            unhealthy_upstreams,
            active_connections,
            gateway_errors_total,
            config: config.clone(),
        })
    }

    /// Record a new request
    pub fn record_request(&self) {
        self.requests_total.inc();
        self.requests_in_flight.inc();
    }

    /// Record a completed response with status code grouping to limit cardinality
    pub fn record_response(&self, status_code: u16, duration: Duration) {
        self.requests_in_flight.dec();
        self.request_duration.observe(duration.as_secs_f64());

        // Record status code if detailed metrics are enabled, but group to reduce cardinality
        if self.config.detailed_metrics {
            // Group status codes to reduce metric cardinality
            let _status_group = match status_code {
                200..=299 => "2xx",
                300..=399 => "3xx",
                400..=499 => "4xx",
                500..=599 => "5xx",
                _ => "other",
            };
            // For now, just increment the total counter to avoid high cardinality
            // In production, you'd want to use labeled metrics with status_group
            self.response_status_total.inc();
        }
    }

    /// Apply a batch of metrics updates efficiently
    pub fn apply_batch(&self, batch: &MetricsBatch) {
        if batch.is_empty() {
            return;
        }

        // Apply request metrics
        if batch.requests > 0 {
            self.requests_total.inc_by(batch.requests);
        }

        // Apply error metrics
        if batch.errors > 0 {
            self.gateway_errors_total.inc_by(batch.errors);
        }

        // Apply upstream error metrics
        if batch.upstream_errors > 0 {
            self.upstream_errors_total.inc_by(batch.upstream_errors);
        }

        // Apply duration metrics (average duration for the batch)
        if batch.requests > 0 && batch.total_duration_seconds > 0.0 {
            let avg_duration = batch.total_duration_seconds / batch.requests as f64;
            // Record multiple observations for batched requests
            for _ in 0..batch.requests {
                self.request_duration.observe(avg_duration);
            }
        }

        // Apply status code metrics if detailed metrics are enabled
        if self.config.detailed_metrics {
            let total_responses = batch.responses_2xx
                + batch.responses_3xx
                + batch.responses_4xx
                + batch.responses_5xx
                + batch.responses_other;
            if total_responses > 0 {
                self.response_status_total.inc_by(total_responses as f64);
            }
        }
    }

    /// Record an upstream request
    pub fn record_upstream_request(&self) {
        self.upstream_requests_total.inc();
    }

    /// Record an upstream error
    pub fn record_upstream_error(&self) {
        self.upstream_errors_total.inc();
    }

    /// Record upstream response duration
    pub fn record_upstream_duration(&self, duration: Duration) {
        self.upstream_duration.observe(duration.as_secs_f64());
    }

    /// Update backend health metrics
    pub fn update_backend_health(&self, healthy_count: i64, unhealthy_count: i64) {
        self.healthy_upstreams.set(healthy_count);
        self.unhealthy_upstreams.set(unhealthy_count);
    }

    /// Record a new connection
    pub fn record_connection_opened(&self) {
        self.active_connections.inc();
    }

    /// Record a closed connection
    pub fn record_connection_closed(&self) {
        self.active_connections.dec();
    }

    /// Record a gateway error
    pub fn record_error(&self) {
        self.gateway_errors_total.inc();
    }

    /// Get the metrics registry for Prometheus exposition
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Get current metrics snapshot
    pub fn get_metrics_snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            requests_total: self.requests_total.get(),
            requests_in_flight: self.requests_in_flight.get(),
            upstream_requests_total: self.upstream_requests_total.get(),
            upstream_errors_total: self.upstream_errors_total.get(),
            healthy_upstreams: self.healthy_upstreams.get(),
            unhealthy_upstreams: self.unhealthy_upstreams.get(),
            active_connections: self.active_connections.get(),
            gateway_errors_total: self.gateway_errors_total.get(),
        }
    }

    /// Export metrics in Prometheus format
    pub fn export_metrics(&self) -> Result<String> {
        use prometheus::Encoder;
        let encoder = prometheus::TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(String::from_utf8(buffer)?)
    }
}

/// Snapshot of current metrics values
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    /// Total requests processed
    pub requests_total: u64,
    /// Requests currently in flight
    pub requests_in_flight: i64,
    /// Total upstream requests
    pub upstream_requests_total: u64,
    /// Total upstream errors
    pub upstream_errors_total: u64,
    /// Number of healthy upstreams
    pub healthy_upstreams: i64,
    /// Number of unhealthy upstreams
    pub unhealthy_upstreams: i64,
    /// Active connections
    pub active_connections: i64,
    /// Total gateway errors
    pub gateway_errors_total: u64,
}

impl MetricsSnapshot {
    /// Calculate request success rate
    pub fn request_success_rate(&self) -> f64 {
        if self.requests_total == 0 {
            return 100.0;
        }

        let success_requests = self.requests_total - self.gateway_errors_total;
        (success_requests as f64 / self.requests_total as f64) * 100.0
    }

    /// Calculate upstream error rate
    pub fn upstream_error_rate(&self) -> f64 {
        if self.upstream_requests_total == 0 {
            return 0.0;
        }

        (self.upstream_errors_total as f64 / self.upstream_requests_total as f64) * 100.0
    }

    /// Calculate backend health percentage
    pub fn backend_health_percentage(&self) -> f64 {
        let total_upstreams = self.healthy_upstreams + self.unhealthy_upstreams;
        if total_upstreams == 0 {
            return 100.0;
        }

        (self.healthy_upstreams as f64 / total_upstreams as f64) * 100.0
    }
}

/// Metrics middleware for automatic metric collection
pub struct MetricsMiddleware {
    collector: Arc<MetricsCollector>,
}

impl MetricsMiddleware {
    /// Create a new metrics middleware
    pub fn new(collector: Arc<MetricsCollector>) -> Self {
        Self { collector }
    }

    /// Record request start
    pub fn on_request_start(&self) {
        self.collector.record_request();
    }

    /// Record request completion
    pub fn on_request_complete(&self, status_code: u16, duration: Duration) {
        self.collector.record_response(status_code, duration);
    }

    /// Record upstream request
    pub fn on_upstream_request(&self) {
        self.collector.record_upstream_request();
    }

    /// Record upstream error
    pub fn on_upstream_error(&self) {
        self.collector.record_upstream_error();
    }

    /// Record upstream response
    pub fn on_upstream_response(&self, duration: Duration) {
        self.collector.record_upstream_duration(duration);
    }

    /// Record connection opened
    pub fn on_connection_opened(&self) {
        self.collector.record_connection_opened();
    }

    /// Record connection closed
    pub fn on_connection_closed(&self) {
        self.collector.record_connection_closed();
    }

    /// Record gateway error
    pub fn on_gateway_error(&self) {
        self.collector.record_error();
    }
}

/// High-performance metrics aggregator with batching
pub struct MetricsAggregator {
    collector: Arc<MetricsCollector>,
    current_batch: std::sync::Mutex<MetricsBatch>,
    batch_size_threshold: usize,
    time_threshold_ms: u64,
    last_flush_time: AtomicU64,
}

impl MetricsAggregator {
    /// Create a new metrics aggregator
    pub fn new(
        collector: Arc<MetricsCollector>,
        batch_size: usize,
        flush_interval_ms: u64,
    ) -> Self {
        let now_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            collector,
            current_batch: std::sync::Mutex::new(MetricsBatch::new()),
            batch_size_threshold: batch_size,
            time_threshold_ms: flush_interval_ms,
            last_flush_time: AtomicU64::new(now_millis),
        }
    }

    /// Add a request to the batch
    pub fn record_request(&self) {
        if let Ok(mut batch) = self.current_batch.try_lock() {
            batch.add_request();
            self.check_and_flush(&mut batch);
        } else {
            // Fallback to direct recording if lock is contended
            self.collector.record_request();
        }
    }

    /// Add a response to the batch
    pub fn record_response(&self, status_code: u16, duration: Duration) {
        if let Ok(mut batch) = self.current_batch.try_lock() {
            batch.add_response(status_code, duration);
            self.check_and_flush(&mut batch);
        } else {
            // Fallback to direct recording if lock is contended
            self.collector.record_response(status_code, duration);
        }
    }

    /// Add an error to the batch
    pub fn record_error(&self) {
        if let Ok(mut batch) = self.current_batch.try_lock() {
            batch.add_error();
            self.check_and_flush(&mut batch);
        } else {
            // Fallback to direct recording if lock is contended
            self.collector.record_error();
        }
    }

    /// Add an upstream error to the batch
    pub fn record_upstream_error(&self) {
        if let Ok(mut batch) = self.current_batch.try_lock() {
            batch.add_upstream_error();
            self.check_and_flush(&mut batch);
        } else {
            // Fallback to direct recording if lock is contended
            self.collector.record_upstream_error();
        }
    }

    /// Check if batch should be flushed and flush if needed
    fn check_and_flush(&self, batch: &mut MetricsBatch) {
        let should_flush = self.should_flush(batch);
        if should_flush {
            self.flush_batch(batch);
        }
    }

    /// Check if batch should be flushed based on size or time
    fn should_flush(&self, batch: &MetricsBatch) -> bool {
        // Check size threshold
        if batch.requests >= self.batch_size_threshold as u64 {
            return true;
        }

        // Check time threshold
        let now_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let last_flush = self.last_flush_time.load(Ordering::Relaxed);

        now_millis.saturating_sub(last_flush) >= self.time_threshold_ms
    }

    /// Flush the current batch to metrics collector
    fn flush_batch(&self, batch: &mut MetricsBatch) {
        if !batch.is_empty() {
            self.collector.apply_batch(batch);
            batch.clear();

            let now_millis = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            self.last_flush_time.store(now_millis, Ordering::Relaxed);
        }
    }

    /// Force flush any pending metrics
    pub fn flush(&self) {
        if let Ok(mut batch) = self.current_batch.lock() {
            self.flush_batch(&mut batch);
        }
    }
}

/// Periodic metrics updater for background metrics
pub struct MetricsUpdater {
    collector: Arc<MetricsCollector>,
    running: std::sync::atomic::AtomicBool,
}

impl MetricsUpdater {
    /// Create a new metrics updater
    pub fn new(collector: Arc<MetricsCollector>) -> Self {
        Self {
            collector,
            running: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Start periodic metrics updates
    pub async fn start(&self, update_interval: Duration) {
        use std::sync::atomic::Ordering;

        if self.running.swap(true, Ordering::Relaxed) {
            return; // Already running
        }

        let _collector = self.collector.clone();
        let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let running_check = running.clone();

        tokio::spawn(async move {
            while running_check.load(Ordering::Relaxed) {
                // Update backend health metrics here
                // This would typically query the health check manager
                // For now, we'll skip this as it requires integration

                tokio::time::sleep(update_interval).await;
            }
        });
    }

    /// Stop periodic updates
    pub fn stop(&self) {
        self.running
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }
}
