use criterion::{black_box, criterion_group, criterion_main, Criterion};
use photon::{RouteConfig, RouteManager};
use pingora_http::RequestHeader;

fn benchmark_route_matching(c: &mut Criterion) {
    // Setup test routes
    let routes = vec![
        RouteConfig {
            id: "api_users".to_string(),
            path: "/api/users/*".to_string(),
            methods: Some(vec!["GET".to_string(), "POST".to_string()]),
            host: Some("api.example.com".to_string()),
            backend: "users_backend".to_string(),
            middleware: None,
            timeout: None,
            retries: None,
        },
        RouteConfig {
            id: "api_orders".to_string(),
            path: "/api/orders/*".to_string(),
            methods: Some(vec!["GET".to_string(), "POST".to_string()]),
            host: Some("api.example.com".to_string()),
            backend: "orders_backend".to_string(),
            middleware: None,
            timeout: None,
            retries: None,
        },
        RouteConfig {
            id: "static_assets".to_string(),
            path: "/assets/**".to_string(),
            methods: Some(vec!["GET".to_string()]),
            host: None,
            backend: "static_backend".to_string(),
            middleware: None,
            timeout: None,
            retries: None,
        },
        RouteConfig {
            id: "catch_all".to_string(),
            path: "/**".to_string(),
            methods: None,
            host: None,
            backend: "default_backend".to_string(),
            middleware: None,
            timeout: None,
            retries: None,
        },
    ];

    let route_manager = RouteManager::new(&routes).unwrap();

    // Create test request headers
    let mut req = RequestHeader::build("GET", b"/api/users/123", None).unwrap();
    req.insert_header("host", "api.example.com").unwrap();

    c.bench_function("route_matching", |b| {
        b.iter(|| black_box(route_manager.find_route(&req)))
    });
}

fn benchmark_request_id_generation(c: &mut Criterion) {
    use std::sync::atomic::{AtomicU64, Ordering};
    let counter = AtomicU64::new(0);

    c.bench_function("request_id_generation", |b| {
        b.iter(|| {
            let request_counter = counter.fetch_add(1, Ordering::Relaxed);
            black_box(format!(
                "req-{:016x}-{:08x}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64,
                request_counter
            ))
        })
    });
}

criterion_group!(
    benches,
    benchmark_route_matching,
    benchmark_request_id_generation
);
criterion_main!(benches);
