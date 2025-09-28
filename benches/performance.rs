use criterion::{black_box, criterion_group, criterion_main, Criterion};
use photon::{RouteConfig, RouteManager};
use pingora_http::RequestHeader;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
            websocket: None,
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
            websocket: None,
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
            websocket: None,
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
            websocket: None,
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
    use std::fmt::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    let counter = AtomicU64::new(0);

    c.bench_function("request_id_generation", |b| {
        b.iter(|| {
            let request_counter = counter.fetch_add(1, Ordering::Relaxed);
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;

            // Optimized version: pre-allocate with exact capacity
            let mut request_id = String::with_capacity(32); // "req-" + 16 hex + "-" + 8 hex = 32 chars
            write!(
                &mut request_id,
                "req-{:016x}-{:08x}",
                timestamp, request_counter
            )
            .expect("Writing to String should never fail");

            request_id.shrink_to_fit(); // Ensure no wasted memory
            black_box(request_id)
        })
    });
}

fn benchmark_ip_hash_key_generation(c: &mut Criterion) {
    let ipv4_addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    let ipv6_addr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

    c.bench_function("ip_hash_key_generation_ipv4", |b| {
        b.iter(|| {
            // Optimized version: use stack-allocated arrays
            let lb_key = match ipv4_addr {
                IpAddr::V4(ipv4) => ipv4.octets().to_vec(),
                IpAddr::V6(_) => unreachable!(),
            };
            black_box(lb_key)
        })
    });

    c.bench_function("ip_hash_key_generation_ipv6", |b| {
        b.iter(|| {
            // Optimized version: use stack-allocated arrays
            let lb_key = match ipv6_addr {
                IpAddr::V4(_) => unreachable!(),
                IpAddr::V6(ipv6) => ipv6.octets().to_vec(),
            };
            black_box(lb_key)
        })
    });
}

fn benchmark_ip_to_string_conversion(c: &mut Criterion) {
    let ipv4_addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    let ipv6_addr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

    c.bench_function("ip_to_string_optimized_ipv4", |b| {
        b.iter(|| {
            // Optimized version: stack-allocated buffer
            let mut ip_buffer = [0u8; 45]; // Max length for IPv6 address
            let ip_str = {
                use std::io::Write;
                let mut cursor = std::io::Cursor::new(&mut ip_buffer[..]);
                write!(cursor, "{}", ipv4_addr).expect("Writing to buffer should never fail");
                let len = cursor.position() as usize;
                std::str::from_utf8(&ip_buffer[..len])
                    .expect("IP address should always be valid UTF-8")
            };
            black_box(ip_str.to_string())
        })
    });

    c.bench_function("ip_to_string_optimized_ipv6", |b| {
        b.iter(|| {
            // Optimized version: stack-allocated buffer
            let mut ip_buffer = [0u8; 45]; // Max length for IPv6 address
            let ip_str = {
                use std::io::Write;
                let mut cursor = std::io::Cursor::new(&mut ip_buffer[..]);
                write!(cursor, "{}", ipv6_addr).expect("Writing to buffer should never fail");
                let len = cursor.position() as usize;
                std::str::from_utf8(&ip_buffer[..len])
                    .expect("IP address should always be valid UTF-8")
            };
            black_box(ip_str.to_string())
        })
    });

    c.bench_function("ip_to_string_naive", |b| {
        b.iter(|| {
            // Naive version: direct to_string()
            black_box(ipv4_addr.to_string())
        })
    });
}

criterion_group!(
    benches,
    benchmark_route_matching,
    benchmark_request_id_generation,
    benchmark_ip_hash_key_generation,
    benchmark_ip_to_string_conversion
);
criterion_main!(benches);
