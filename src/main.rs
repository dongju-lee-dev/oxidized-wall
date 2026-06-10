use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use notify::Watcher;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{Level, error, info};
use tracing_subscriber;

mod ban;
mod bandwidth;
mod config;
mod health;
mod protocol;
mod proxy;
mod ratelimit;
mod server;
mod waf;

/// Main entry point of the Oxidized Wall security proxy.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // [1] Initialize structured logging with INFO level as default
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_level(true)
        .init();

    // [2] Install global crypto provider for Rustls (Ring)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    info!("=== Oxidized Wall Starting ===");

    // [3] Load configuration from static TOML file
    info!("Loading configuration...");
    let config = Arc::new(config::Config::load("config.toml").await?);

    // [4] Initialize core shared components
    info!("Initializing Components...");
    let ban_manager = Arc::new(ban::BanManager::new());
    let rate_limiter = Arc::new(ratelimit::RateLimiter::new());
    let bandwidth_limiter = Arc::new(bandwidth::BandwidthLimiter::new());
    let health_manager = Arc::new(health::HealthManager::new());

    // [5] Initialize connection pool for backend HTTP requests
    let client = Arc::new(Client::builder(TokioExecutor::new()).build_http());

    // [6] Start background task for
    ban_manager.clone().spawn_cleanup_task();
    rate_limiter.clone().spawn_cleanup_task();
    health_manager.clone().spawn_checker(config.clone());

    // [6.1] Setup Certificate Hot-Reloading
    let config_for_notify = config.clone();
    let handle = tokio::runtime::Handle::current();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(event) = res {
            if event.kind.is_modify() || event.kind.is_create() || event.kind.is_remove() {
                let cfg = config_for_notify.clone();
                handle.spawn(async move {
                    if let Err(e) = cfg.reload_certs().await {
                        error!("Failed to hot-reload certificates: {}", e);
                    }
                });
            }
        }
    })?;

    let certs_path = Path::new("certs");
    if certs_path.exists() {
        watcher.watch(certs_path, notify::RecursiveMode::NonRecursive)?;
        info!("Started watching 'certs/' for hot-reloading.");
    }

    // [7] Prepare for server orchestration and graceful shutdown
    let cancel_token = CancellationToken::new();
    let mut server_set = JoinSet::new();
    let limit = Arc::new(Semaphore::new(config.network.max_connections));

    // [8] Spawn HTTP servers for each configured address
    for addr_str in &config.network.http_addrs {
        let addr: SocketAddr = addr_str.parse().expect("Invalid HTTP Address");
        server_set.spawn(server::http_server(
            addr,
            config.clone(),
            limit.clone(),
            ban_manager.clone(),
            rate_limiter.clone(),
            cancel_token.clone(),
        ));
    }

    // [9] Spawn HTTPS (TLS) servers for each configured address
    for addr_str in &config.network.https_addrs {
        let addr: SocketAddr = addr_str.parse().expect("Invalid HTTPS Address");
        server_set.spawn(server::https_server(
            addr,
            config.clone(),
            limit.clone(),
            ban_manager.clone(),
            rate_limiter.clone(),
            bandwidth_limiter.clone(),
            health_manager.clone(),
            client.clone(),
            cancel_token.clone(),
        ));
    }

    info!("Oxidized Wall is ready and serving.");

    // [10] Block until SIGINT (Ctrl+C) is received
    if let Err(e) = tokio::signal::ctrl_c().await {
        error!("Failed to listen for Ctrl+C: {}", e);
    }

    // [11] Start graceful shutdown sequence
    info!("Shutdown signal received. Cancelling listeners...");
    cancel_token.cancel();

    // [12] Wait for all connection tasks to finish processing
    while let Some(res) = server_set.join_next().await {
        if let Err(e) = res {
            error!("Server task error: {:?}", e);
        }
    }

    info!("=== Oxidized Wall Stopped ===");
    Ok(())
}
