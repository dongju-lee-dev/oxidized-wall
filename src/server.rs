use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
pub use hyper_util::rt::TokioIo;
use hyper_util::rt::TokioTimer;
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

use crate::ban::BanManager;
use crate::bandwidth::BandwidthLimiter;
use crate::config::Config;
use crate::health::HealthManager;
use crate::proxy;
use crate::ratelimit::RateLimiter;

pub type HttpClient = Client<HttpConnector, proxy::BoxBody>;

/// Loop for accepting plain HTTP connections.
pub async fn http_server(
    addr: SocketAddr,
    config: Arc<Config>,
    limit: Arc<Semaphore>,
    ban_manager: Arc<BanManager>,
    rate_limiter: Arc<RateLimiter>,
    cancel_token: CancellationToken,
) {
    let listener = TcpListener::bind(addr).await.expect("Failed to bind");
    info!("HTTP Server listening on {}", addr);

    // Prepare connection builder with HTTP/1.1 and H2 support
    let mut builder = auto::Builder::new(TokioExecutor::new());
    configure_builder(&mut builder, &config);

    let mut conn_set = JoinSet::new();

    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                info!("Stopping HTTP listener on {}", addr);
                break;
            }
            res = listener.accept() => {
                let (stream, remote_addr) = match res {
                    Ok(conn) => conn,
                    Err(e) => { error!("Accept error: {}", e); continue; }
                };

                // Apply low-level network optimizations
                let _ = stream.set_nodelay(true);

                // Quick IP ban check before accepting the connection
                if ban_manager.check(remote_addr.ip()).await {
                    debug!("Blocked banned IP (HTTP): {}", remote_addr.ip());
                    continue;
                }

                // Acquire global connection permit (concurrency limit)
                let permit = match limit.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => break,
                };

                let io = TokioIo::new(stream);
                let builder = builder.clone();
                let config = config.clone();
                let ban_manager = ban_manager.clone();
                let rate_limiter = rate_limiter.clone();
                let cancel_token = cancel_token.clone();

                // Spawn task to serve the individual connection
                conn_set.spawn(async move {
                    let _permit = permit;
                    let service = service_fn(move |req| {
                        proxy::http_proxy(req, remote_addr, config.clone(), ban_manager.clone(), rate_limiter.clone())
                    });

                    let conn = builder.serve_connection(io, service);
                    let mut conn = std::pin::pin!(conn);

                    tokio::select! {
                        res = conn.as_mut() => {
                            if let Err(e) = res { debug!("HTTP Connection error: {:?}", e); }
                        }
                        _ = cancel_token.cancelled() => {
                            conn.as_mut().graceful_shutdown();
                            let _ = conn.await;
                        }
                    }
                });
            }
            _ = conn_set.join_next(), if !conn_set.is_empty() => {}
        }
    }
    while let Some(_) = conn_set.join_next().await {}
}

/// Loop for accepting secure HTTPS connections with TLS termination.
pub async fn https_server(
    addr: SocketAddr,
    config: Arc<Config>,
    limit: Arc<Semaphore>,
    ban_manager: Arc<BanManager>,
    rate_limiter: Arc<RateLimiter>,
    bandwidth_limiter: Arc<BandwidthLimiter>,
    health_manager: Arc<HealthManager>,
    client: Arc<HttpClient>,
    cancel_token: CancellationToken,
) {
    let listener = TcpListener::bind(addr).await.expect("Failed to bind HTTPS");
    info!("HTTPS Server listening on {}", addr);

    let mut builder = auto::Builder::new(TokioExecutor::new());
    configure_builder(&mut builder, &config);

    let tls_acceptor = TlsAcceptor::from(config.tls.clone());
    let mut conn_set = JoinSet::new();

    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                info!("Stopping HTTPS listener on {}", addr);
                break;
            }
            res = listener.accept() => {
                let (stream, remote_addr) = match res {
                    Ok(conn) => conn,
                    Err(e) => { error!("Accept error: {}", e); continue; }
                };

                let _ = stream.set_nodelay(true);

                if ban_manager.check(remote_addr.ip()).await {
                    debug!("Blocked banned IP (HTTPS): {}", remote_addr.ip());
                    continue;
                }

                let permit = match limit.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => break,
                };

                let io_builder = builder.clone();
                let acceptor = tls_acceptor.clone();
                let config = config.clone();
                let ban_manager = ban_manager.clone();
                let rate_limiter = rate_limiter.clone();
                let bandwidth_limiter = bandwidth_limiter.clone();
                let health_manager = health_manager.clone();
                let client = client.clone();
                let cancel_token = cancel_token.clone();

                conn_set.spawn(async move {
                    let _permit = permit;
                    let tls_handshake_timeout = Duration::from_secs(config.timeout.c_tls_handshake);

                    // Execute TLS Handshake with configured timeout
                    match timeout(tls_handshake_timeout, acceptor.accept(stream)).await {
                        Ok(Ok(tls_stream)) => {
                            let service = service_fn(move |req| {
                                proxy::https_proxy(req, remote_addr, config.clone(), ban_manager.clone(), rate_limiter.clone(), bandwidth_limiter.clone(), health_manager.clone(), client.clone())
                            });

                            let conn = io_builder.serve_connection(TokioIo::new(tls_stream), service);
                            let mut conn = std::pin::pin!(conn);

                            tokio::select! {
                                res = conn.as_mut() => {
                                    if let Err(e) = res { debug!("HTTPS Connection error: {:?}", e); }
                                }
                                _ = cancel_token.cancelled() => {
                                    conn.as_mut().graceful_shutdown();
                                    let _ = conn.await;
                                }
                            }
                        }
                        Ok(Err(e)) => debug!("TLS Handshake Error: {:?}", e),
                        Err(_) => debug!("TLS Handshake Timeout"),
                    }
                });
            }
            _ = conn_set.join_next(), if !conn_set.is_empty() => {}
        }
    }
    while let Some(_) = conn_set.join_next().await {}
}

/// Applies HTTP/1.1 and HTTP/2 specific settings from configuration to the connection builder.
fn configure_builder(builder: &mut auto::Builder<TokioExecutor>, config: &Config) {
    let t = &config.timeout;
    let l = &config.limit;

    builder
        .http1()
        .header_read_timeout(Duration::from_secs(t.c_header_read))
        .max_headers(l.max_header_count)
        .timer(TokioTimer::new());

    builder
        .http2()
        .keep_alive_interval(Duration::from_secs(t.c_keep_alive_idle))
        .keep_alive_timeout(Duration::from_secs(t.c_keep_alive_timeout))
        .max_concurrent_streams(l.c_h2_max_streams)
        .max_header_list_size(l.max_header_size as u32)
        .timer(TokioTimer::new());
}
