use dashmap::DashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{info, warn};

use crate::config::Config;

/// Manages the health status of all upstream servers using periodic probing.
pub struct HealthManager {
    // Mapping of Upstream address to its last known healthy status.
    statuses: DashMap<String, bool>,
}

impl HealthManager {
    pub fn new() -> Self {
        Self { statuses: DashMap::new() }
    }

    /// Check if a specific upstream is currently marked as healthy.
    pub fn is_healthy(&self, addr: &str) -> bool {
        self.statuses.get(addr).map(|r| *r.value()).unwrap_or(true)
    }

    /// Background task that extracts all unique upstreams and probes them every 10 seconds.
    pub fn spawn_checker(self: Arc<Self>, config: Arc<Config>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            
            let mut upstreams = Vec::new();
            for vhost in config.vhosts.values() {
                for (_, addrs) in &vhost.routers {
                    for addr in addrs {
                        if !upstreams.contains(addr) { upstreams.push(addr.clone()); }
                    }
                }
            }

            info!("Active Health Check started for {} upstreams", upstreams.len());

            loop {
                interval.tick().await;
                for addr in &upstreams {
                    let is_healthy = self.probe_upstream(addr).await;
                    let old_status = self.statuses.insert(addr.clone(), is_healthy);
                    if Some(is_healthy) != old_status {
                        if is_healthy { info!("Upstream {} is now HEALTHY", addr); }
                        else { warn!("Upstream {} is now UNHEALTHY", addr); }
                    }
                }
            }
        });
    }

    /// Probes a single upstream by attempting a TCP connection with a 2-second timeout.
    async fn probe_upstream(&self, addr: &str) -> bool {
        timeout(Duration::from_secs(2), TcpStream::connect(addr)).await.map(|r| r.is_ok()).unwrap_or(false)
    }
}
