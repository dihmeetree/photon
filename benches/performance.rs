use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use photon::{CacheConfig, ResponseCache, RouteConfig, RouteManager};
use pingora_http::{RequestHeader, ResponseHeader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;

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
            cache: None,
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
            cache: None,
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
            cache: None,
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
            cache: None,
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

fn benchmark_cache_operations(c: &mut Criterion) {
    // Setup cache with production-grade Pingora memory cache
    let config = CacheConfig {
        enabled: true,
        max_entries: 10000,
        default_ttl: Duration::from_secs(300),
        max_body_size: 1024 * 1024,
        cache_with_query_params: false,
    };
    let cache = ResponseCache::new(config);

    // Pre-populate cache with test data
    let test_response = ResponseHeader::build(200, None).unwrap();
    let test_body = Bytes::from("test response body");

    for i in 0..100 {
        let key = format!("test_key_{}", i);
        cache
            .put(key, test_response.clone(), test_body.clone())
            .unwrap();
    }

    // Create test request for cache key generation
    let test_request = RequestHeader::build("GET", b"/api/test", None).unwrap();

    c.bench_function("cache_key_generation", |b| {
        b.iter(|| black_box(cache.generate_cache_key(&test_request)))
    });

    c.bench_function("cache_hit_lookup", |b| {
        b.iter(|| {
            // Lookup existing key (cache hit)
            black_box(cache.get("test_key_50"))
        })
    });

    c.bench_function("cache_miss_lookup", |b| {
        b.iter(|| {
            // Lookup non-existing key (cache miss)
            black_box(cache.get("non_existing_key"))
        })
    });

    c.bench_function("cache_put_operation", |b| {
        let mut counter = 0;
        b.iter(|| {
            counter += 1;
            let key = format!("bench_key_{}", counter);
            black_box(cache.put(key, test_response.clone(), test_body.clone()))
        })
    });
}

fn benchmark_concurrent_route_matching(c: &mut Criterion) {
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
            cache: None,
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
            cache: None,
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
            cache: None,
        },
    ];

    let route_manager = Arc::new(RouteManager::new(&routes).unwrap());

    c.bench_function("concurrent_route_matching_8_threads", |b| {
        b.iter(|| {
            let manager = route_manager.clone();
            let counter = Arc::new(AtomicUsize::new(0));

            let handles: Vec<_> = (0..8)
                .map(|_| {
                    let manager_clone = manager.clone();
                    let counter_clone = counter.clone();

                    thread::spawn(move || {
                        let mut req = RequestHeader::build("GET", b"/api/users/123", None).unwrap();
                        req.insert_header("host", "api.example.com").unwrap();

                        for _ in 0..100 {
                            let route = manager_clone.find_route(&req);
                            if route.is_some() {
                                counter_clone.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    })
                })
                .collect();

            for handle in handles {
                handle.join().unwrap();
            }

            black_box(counter.load(Ordering::Relaxed))
        })
    });
}

fn benchmark_concurrent_cache_operations(c: &mut Criterion) {
    let config = CacheConfig {
        enabled: true,
        max_entries: 10000,
        default_ttl: Duration::from_secs(300),
        max_body_size: 1024 * 1024,
        cache_with_query_params: false,
    };
    let cache = Arc::new(ResponseCache::new(config));

    // Pre-populate cache
    let test_response = ResponseHeader::build(200, None).unwrap();
    let test_body = Bytes::from("test response body");

    for i in 0..1000 {
        let key = format!("test_key_{}", i);
        cache
            .put(key, test_response.clone(), test_body.clone())
            .unwrap();
    }

    c.bench_function("concurrent_cache_reads_8_threads", |b| {
        b.iter(|| {
            let cache_clone = cache.clone();
            let counter = Arc::new(AtomicUsize::new(0));

            let handles: Vec<_> = (0..8)
                .map(|_| {
                    let cache = cache_clone.clone();
                    let counter_clone = counter.clone();

                    thread::spawn(move || {
                        for i in 0..100 {
                            let key = format!("test_key_{}", i % 100);
                            if cache.get(&key).is_some() {
                                counter_clone.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    })
                })
                .collect();

            for handle in handles {
                handle.join().unwrap();
            }

            black_box(counter.load(Ordering::Relaxed))
        })
    });

    c.bench_function("concurrent_cache_writes_8_threads", |b| {
        b.iter(|| {
            let cache_clone = cache.clone();
            let counter = Arc::new(AtomicUsize::new(0));
            // Clone the test objects inside the closure to avoid capture issues
            let test_response_clone = test_response.clone();
            let test_body_clone = test_body.clone();

            let handles: Vec<_> = (0..8)
                .map(|thread_id| {
                    let cache = cache_clone.clone();
                    let counter_clone = counter.clone();
                    let test_response = test_response_clone.clone();
                    let test_body = test_body_clone.clone();

                    thread::spawn(move || {
                        for i in 0..50 {
                            let key = format!("bench_key_{}_{}", thread_id, i);
                            if cache
                                .put(key, test_response.clone(), test_body.clone())
                                .is_ok()
                            {
                                counter_clone.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    })
                })
                .collect();

            for handle in handles {
                handle.join().unwrap();
            }

            black_box(counter.load(Ordering::Relaxed))
        })
    });
}

fn benchmark_memory_allocation_patterns(c: &mut Criterion) {
    c.bench_function("string_allocation_with_capacity", |b| {
        b.iter(|| {
            // Optimized: pre-allocate with known capacity
            let mut s = String::with_capacity(64);
            for i in 0..10 {
                s.push_str(&format!("item{},", i));
            }
            black_box(s)
        })
    });

    c.bench_function("string_allocation_naive", |b| {
        b.iter(|| {
            // Naive: reallocate as needed
            let mut s = String::new();
            for i in 0..10 {
                s.push_str(&format!("item{},", i));
            }
            black_box(s)
        })
    });

    c.bench_function("vec_allocation_with_capacity", |b| {
        b.iter(|| {
            // Optimized: pre-allocate with known capacity
            let mut v = Vec::with_capacity(100);
            for i in 0..100 {
                v.push(i);
            }
            black_box(v)
        })
    });

    c.bench_function("vec_allocation_naive", |b| {
        b.iter(|| {
            // Naive: reallocate as needed
            let mut v = Vec::new();
            for i in 0..100 {
                v.push(i);
            }
            black_box(v)
        })
    });
}

fn benchmark_error_response_performance(c: &mut Criterion) {
    c.bench_function("pre_allocated_error_response", |b| {
        b.iter(|| {
            // Simulate pre-allocated error response usage
            let response = photon::gateway::get_error_response(404);
            let body = photon::gateway::get_error_body(404);
            black_box((response, body))
        })
    });

    c.bench_function("dynamic_error_response", |b| {
        b.iter(|| {
            // Simulate dynamic error response creation
            let mut response = ResponseHeader::build(404, None).unwrap();
            response
                .insert_header("content-type", "text/plain")
                .unwrap();
            response.insert_header("content-length", "9").unwrap();
            let body = Bytes::from_static(b"Not Found");
            black_box((response, body))
        })
    });
}

criterion_group!(
    benches,
    benchmark_route_matching,
    benchmark_request_id_generation,
    benchmark_ip_hash_key_generation,
    benchmark_ip_to_string_conversion,
    benchmark_cache_operations,
    // New concurrent benchmarks
    benchmark_concurrent_route_matching,
    benchmark_concurrent_cache_operations,
    benchmark_memory_allocation_patterns,
    benchmark_error_response_performance
);
criterion_main!(benches);
