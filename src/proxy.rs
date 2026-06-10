use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full, Limited};
use hyper::header::{HOST, HeaderValue, UPGRADE};
use hyper::{Request, Response, StatusCode};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::ban::{BanManager, Violation};
use crate::bandwidth::{BandwidthLimiter, ThrottledBody};
use crate::config::Config;
use crate::health::HealthManager;
use crate::protocol;
use crate::ratelimit::RateLimiter;
use crate::waf;

/// Standard body type for boxed response streams.
pub type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

/// [Integrated Security Pipeline]
/// Executes a sequence of checks: Rate Limiting, Protocol Integrity, URI/Header size, and WAF signatures.
async fn verify_request(
    req: &Request<hyper::body::Incoming>,
    remote_addr: SocketAddr,
    config: &Config,
    ban_manager: &BanManager,
    rate_limiter: &RateLimiter,
) -> Result<(), Response<BoxBody>> {
    // let ip = remote_addr.ip(); // [OLD CODE] Using direct connection IP
    let ip = get_real_ip(req.headers(), remote_addr); // [NEW CODE] Using real IP from Cloudflare

    // Task 1: Rate Limiting (Check RPS quota per IP)
    if !rate_limiter.check(ip, config) {
        warn!("Rate Limit Exceeded from {}", ip);
        ban_manager.punish(ip, Violation::RateLimit, config).await;
        return Err(error_response(StatusCode::TOO_MANY_REQUESTS));
    }

    // Task 2: Protocol Integrity (Check for URI control chars, Host uniqueness, and Smuggling)
    if let Err(e) = protocol::validate_uri(req.uri())
        .and_then(|_| protocol::validate_host(req.headers(), req.method(), req.uri()))
        .and_then(|_| protocol::validate_smuggling(req.headers()))
    {
        warn!(
            "Protocol Violation from {}: {}",
            ip,
            <protocol::ProtocolError as Into<&'static str>>::into(e)
        );
        ban_manager.punish(ip, Violation::Protocol, config).await;
        return Err(error_response(StatusCode::BAD_REQUEST));
    }

    // Task 3: Resource Thresholds (Check URI length and HTTP Method validity)
    let l = &config.limit;
    if req.headers().len() > l.max_header_count {
        warn!(
            "Too many headers from {} ({} > {})",
            ip,
            req.headers().len(),
            l.max_header_count
        );
        ban_manager.punish(ip, Violation::Protocol, config).await;
        return Err(error_response(StatusCode::BAD_REQUEST));
    }
    let uri_len = req.uri().path().len() + req.uri().query().map(|q| q.len() + 1).unwrap_or(0);
    if uri_len > l.max_uri_size {
        warn!("URI Too Long from {}", ip);
        ban_manager.punish(ip, Violation::Protocol, config).await;
        return Err(error_response(StatusCode::URI_TOO_LONG));
    }

    match *req.method() {
        hyper::Method::GET
        | hyper::Method::POST
        | hyper::Method::PUT
        | hyper::Method::DELETE
        | hyper::Method::PATCH
        | hyper::Method::HEAD
        | hyper::Method::OPTIONS => {}
        _ => {
            warn!("Invalid Method from {}: {}", ip, req.method());
            ban_manager.punish(ip, Violation::Protocol, config).await;
            return Err(error_response(StatusCode::METHOD_NOT_ALLOWED));
        }
    }

    // Task 4: WAF Header Inspection (Quick signature matching on headers)
    if let Err(reason) = waf::header(req.uri(), req.method(), req.headers()) {
        warn!("WAF Header Block from {}: {}", ip, reason);
        ban_manager.punish(ip, Violation::Waf, config).await;
        return Err(error_response(StatusCode::FORBIDDEN));
    }

    Ok(())
}

/// [Load Balancer]
/// Selects the next healthy upstream address using an atomic Round-Robin counter.
fn select_upstream(
    upstreams: &[String],
    counter: &AtomicUsize,
    health_manager: &HealthManager,
) -> Option<String> {
    let len = upstreams.len();
    let start_idx = counter.fetch_add(1, Ordering::Relaxed);

    for i in 0..len {
        let idx = (start_idx + i) % len;
        let addr = &upstreams[idx];
        // Only return if marked healthy by Active Health Check
        if health_manager.is_healthy(addr) {
            return Some(addr.clone());
        }
    }
    None
}

/// Handler for plain HTTP requests. Automatically redirects everything to HTTPS.
pub async fn http_proxy(
    req: Request<hyper::body::Incoming>,
    remote_addr: SocketAddr,
    config: Arc<Config>,
    ban_manager: Arc<BanManager>,
    rate_limiter: Arc<RateLimiter>,
) -> Result<Response<BoxBody>, hyper::Error> {
    // [1] Verify security even for redirects
    if let Err(err_res) =
        verify_request(&req, remote_addr, &config, &ban_manager, &rate_limiter).await
    {
        return Ok(err_res);
    }

    // [2] Build and return HTTPS redirect response
    let host = req
        .headers()
        .get(HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let https_uri = format!("https://{}{}", host, path);

    Ok(Response::builder()
        .status(StatusCode::PERMANENT_REDIRECT)
        .header("Location", https_uri)
        .body(Empty::<Bytes>::new().map_err(|n| match n {}).boxed())
        .unwrap_or_else(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR)))
}

/// Handler for secure HTTPS requests. Main entry for routing and WAF body inspection.
pub async fn https_proxy(
    req: Request<hyper::body::Incoming>,
    remote_addr: SocketAddr,
    config: Arc<Config>,
    ban_manager: Arc<BanManager>,
    rate_limiter: Arc<RateLimiter>,
    bandwidth_limiter: Arc<BandwidthLimiter>,
    health_manager: Arc<HealthManager>,
    client: Arc<crate::server::HttpClient>,
) -> Result<Response<BoxBody>, hyper::Error> {
    // [1] Initial Security verification
    if let Err(err_res) =
        verify_request(&req, remote_addr, &config, &ban_manager, &rate_limiter).await
    {
        return Ok(err_res);
    }

    let (parts, body) = req.into_parts();
    let remote_ip = get_real_ip(&parts.headers, remote_addr);
    let max_bw = config.limit.max_bandwidth;

    // [2] Conditional Body Buffering: Only buffer for payload-heavy methods to save memory
    let final_req: Request<BoxBody> = if matches!(
        parts.method,
        hyper::Method::POST | hyper::Method::PUT | hyper::Method::PATCH
    ) {
        let body_bytes = match Limited::new(body, config.limit.max_body_size)
            .collect()
            .await
        {
            Ok(c) => c.to_bytes(),
            Err(_) => {
                ban_manager
                    .punish(remote_ip, Violation::Protocol, &config)
                    .await;
                return Ok(error_response(StatusCode::PAYLOAD_TOO_LARGE));
            }
        };
        // Task: WAF Body Check (Deep inspection of payload)
        if let Err(reason) = waf::body(&parts.headers, &body_bytes) {
            warn!("WAF Body Block from {}: {}", remote_ip, reason);
            ban_manager.punish(remote_ip, Violation::Waf, &config).await;
            return Ok(error_response(StatusCode::FORBIDDEN));
        }
        Request::from_parts(parts, Full::new(body_bytes).map_err(|n| match n {}).boxed())
    } else {
        // Just stream the body for GET/HEAD etc.
        Request::from_parts(parts, body.map_err(|e| e).boxed())
    };

    // [3] Routing and Dispatch
    let result = timeout(Duration::from_secs(config.timeout.c_body_timeout), async {
        let domain = get_host(&final_req);
        let path = final_req.uri().path();

        let vhost = config.vhosts.get(domain)?;
        let mut best_match = None;
        // Optimized LPM Routing
        for (route_path, upstreams) in &vhost.routers {
            if path.starts_with(route_path) {
                if let Some(counter) = vhost.routers_state.get(route_path) {
                    best_match = Some((upstreams, counter));
                    break;
                }
            }
        }

        let (upstreams, counter) = best_match?;
        let addr = select_upstream(upstreams, counter, &health_manager)?;

        // Task: Proxying Mode Selection
        if is_websocket(&final_req) {
            // WebSockets need direct TCP streaming
            let stream = timeout(
                Duration::from_secs(config.timeout.s_connect),
                TcpStream::connect(&addr),
            )
            .await
            .ok()?
            .ok()?;
            Some(
                handle_websocket(
                    final_req,
                    stream,
                    addr,
                    config.timeout.s_response,
                    config.timeout.s_websocket_idle,
                    bandwidth_limiter,
                    remote_ip,
                    max_bw,
                )
                .await,
            )
        } else {
            // Standard HTTP uses connection pooling
            Some(
                handle_http(
                    final_req,
                    client,
                    addr,
                    config.timeout.s_response,
                    bandwidth_limiter,
                    remote_ip,
                    max_bw,
                )
                .await,
            )
        }
    })
    .await;

    // [4] Handle final outcome including timeouts
    match result {
        Ok(Some(res)) => res,
        Ok(None) => {
            debug!("Routing failed or no healthy upstreams for {}", remote_ip);
            Ok(error_response(StatusCode::BAD_GATEWAY))
        }
        Err(_) => {
            warn!("Request Timeout for {} - Punishing IP", remote_ip);
            ban_manager
                .punish(remote_ip, Violation::Timeout, &config)
                .await;
            Ok(error_response(StatusCode::GATEWAY_TIMEOUT))
        }
    }
}

/// Logic for proxying standard HTTP requests with connection reuse and bandwidth throttling.
async fn handle_http(
    mut req: Request<BoxBody>,
    client: Arc<crate::server::HttpClient>,
    upstream_addr: String,
    timeout_sec: u64,
    bandwidth_limiter: Arc<BandwidthLimiter>,
    remote_ip: IpAddr,
    max_bw: u64,
) -> Result<Response<BoxBody>, hyper::Error> {
    // Auto protocol
    if req.version() == hyper::Version::HTTP_2 {
        *req.version_mut() = hyper::Version::HTTP_11;
    }

    // Rewrite URI to point to backend upstream
    let uri_str = format!(
        "http://{}{}",
        upstream_addr,
        req.uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/")
    );
    if let Ok(uri) = uri_str.parse() {
        *req.uri_mut() = uri;
    }

    // Execute pooled request
    match timeout(Duration::from_secs(timeout_sec), client.request(req)).await {
        Ok(Ok(res)) => {
            let (parts, body) = res.into_parts();
            let mut res_builder = Response::builder()
                .status(parts.status)
                .version(parts.version);
            let mut headers = parts.headers;

            // Response Sanitization
            sanitize_response_headers(&mut headers);

            // Bandwidth Throttling & DLP (Masking)
            let throttled_body = ThrottledBody::new(
                body.map_err(|e| e.into()),
                bandwidth_limiter,
                remote_ip,
                max_bw,
            );
            let final_body = waf::apply_dlp(&headers, throttled_body.boxed()).await;

            if let Some(h) = res_builder.headers_mut() {
                *h = headers;
            }
            Ok(res_builder
                .body(final_body.boxed())
                .unwrap_or_else(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR)))
        }
        _ => Ok(error_response(StatusCode::GATEWAY_TIMEOUT)),
    }
}

/// Logic for proxying WebSockets using bidirectional byte streaming with precise throttling.
async fn handle_websocket(
    mut req: Request<BoxBody>,
    stream: TcpStream,
    _addr: String,
    rs_timeout_sec: u64,
    idle_timeout_sec: u64,
    bandwidth_limiter: Arc<BandwidthLimiter>,
    remote_ip: IpAddr,
    max_bw: u64,
) -> Result<Response<BoxBody>, hyper::Error> {
    // Establish backend handshake
    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .handshake(crate::server::TokioIo::new(stream))
        .await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut proxy_req = Request::builder()
        .method(req.method())
        .uri(req.uri())
        .version(req.version());
    if let Some(h) = proxy_req.headers_mut() {
        *h = req.headers().clone();
    }
    let proxy_req = proxy_req
        .body(Empty::<Bytes>::new().map_err(|n| match n {}).boxed())
        .unwrap_or_else(|_| Request::new(Empty::new().boxed()));

    let mut backend_res = match timeout(
        Duration::from_secs(rs_timeout_sec),
        sender.send_request(proxy_req),
    )
    .await
    {
        Ok(Ok(res)) => res,
        _ => return Ok(error_response(StatusCode::GATEWAY_TIMEOUT)),
    };

    // If handshake is successful, perform protocol upgrade
    if backend_res.status() == StatusCode::SWITCHING_PROTOCOLS {
        let mut res = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
        if let Some(h) = res.headers_mut() {
            *h = backend_res.headers().clone();
            sanitize_response_headers(h);
        }

        let up_client = hyper::upgrade::on(&mut req);
        let up_backend = hyper::upgrade::on(&mut backend_res);

        // Task: Bidirectional WebSocket Throttling Loop
        tokio::spawn(async move {
            if let (Ok(up_c), Ok(up_b)) = tokio::join!(up_client, up_backend) {
                let (mut cr, mut cw) = tokio::io::split(crate::server::TokioIo::new(up_c));
                let (mut br, mut bw) = tokio::io::split(crate::server::TokioIo::new(up_b));
                let idle = Duration::from_secs(idle_timeout_sec);

                let c2b = async {
                    let mut buf = [0u8; 8192];
                    while let Ok(Ok(n)) =
                        timeout(idle, tokio::io::AsyncReadExt::read(&mut cr, &mut buf)).await
                    {
                        if n == 0 {
                            break;
                        }
                        // Rate control before writing to backend
                        while max_bw > 0
                            && !bandwidth_limiter.try_consume(remote_ip, max_bw, n as u64)
                        {
                            tokio::time::sleep(Duration::from_millis(5)).await;
                        }
                        if tokio::io::AsyncWriteExt::write_all(&mut bw, &buf[..n])
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                };
                let b2c = async {
                    let mut buf = [0u8; 8192];
                    while let Ok(Ok(n)) =
                        timeout(idle, tokio::io::AsyncReadExt::read(&mut br, &mut buf)).await
                    {
                        if n == 0 {
                            break;
                        }
                        // Rate control before writing to client
                        while max_bw > 0
                            && !bandwidth_limiter.try_consume(remote_ip, max_bw, n as u64)
                        {
                            tokio::time::sleep(Duration::from_millis(5)).await;
                        }
                        if tokio::io::AsyncWriteExt::write_all(&mut cw, &buf[..n])
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                };
                tokio::join!(c2b, b2c);
            }
        });
        Ok(res
            .body(Empty::new().map_err(|n| match n {}).boxed())
            .unwrap())
    } else {
        // Fallback for failed upgrades
        let (parts, body) = backend_res.into_parts();
        Ok(Response::from_parts(
            parts,
            ThrottledBody::new(
                body.map_err(|e| e.into()),
                bandwidth_limiter,
                remote_ip,
                max_bw,
            )
            .boxed(),
        ))
    }
}

/// Extract the real client IP from Cloudflare header or fall back to remote_addr.
fn get_real_ip(headers: &hyper::HeaderMap, remote_addr: SocketAddr) -> IpAddr {
    headers
        .get("CF-Connecting-IP")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<IpAddr>().ok())
        .unwrap_or_else(|| remote_addr.ip())
}

/// Extracts domain name from Host header or URI.
fn get_host<B>(req: &Request<B>) -> &str {
    req.uri()
        .host()
        .or_else(|| {
            req.headers()
                .get(HOST)
                .and_then(|h| h.to_str().ok()?.split(':').next())
        })
        .unwrap_or("localhost")
}

/// Checks if the request is a WebSocket upgrade attempt.
fn is_websocket<B>(req: &Request<B>) -> bool {
    let upgrade = |h: &HeaderValue| {
        h.to_str()
            .ok()
            .map(|s| s.to_ascii_lowercase().contains("websocket"))
            .unwrap_or(false)
    };
    req.headers().get(UPGRADE).map(upgrade).unwrap_or(false)
}

/// Task: Header Sanitization
/// Strips sensitive backend headers and injects mandatory security headers.
fn sanitize_response_headers(headers: &mut hyper::HeaderMap) {
    for h in &["Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime"] {
        headers.remove(*h);
    }

    headers.remove(hyper::header::CONTENT_LENGTH);
    headers.remove(hyper::header::TRANSFER_ENCODING);

    let mut s = |k, v| headers.insert(k, HeaderValue::from_static(v));

    s(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains; preload",
    );
    s("X-Frame-Options", "DENY");
    s("X-Content-Type-Options", "nosniff");
    s("X-XSS-Protection", "1; mode=block");
    s("Referrer-Policy", "strict-origin-when-cross-origin");
    s(
        "Permissions-Policy",
        "geolocation=(), microphone=(), camera=()",
    );
}

/// Generates a standard error response with security headers.
fn error_response(status: StatusCode) -> Response<BoxBody> {
    let mut res = match Response::builder()
        .status(status)
        .body(Empty::new().map_err(|n| match n {}).boxed())
    {
        Ok(r) => r,
        Err(_) => Response::new(Empty::new().map_err(|n| match n {}).boxed()),
    };
    sanitize_response_headers(res.headers_mut());
    res
}
