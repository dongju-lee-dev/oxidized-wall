use crate::config::Config;
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

struct RateState {
    count: u32,
    last_reset: Instant,
}

/// High-performance IP-based rate limiter using DashMap for concurrent access.
pub struct RateLimiter {
    records: Arc<DashMap<IpAddr, RateState>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            records: Arc::new(DashMap::new()),
        }
    }

    /// Task: Inactive IP Cleanup
    /// Removes records that haven't been seen for 10 seconds to save memory.
    pub fn spawn_cleanup_task(&self) {
        let records = self.records.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let now = Instant::now();
                records.retain(|_, state| {
                    now.duration_since(state.last_reset) < Duration::from_secs(10)
                });
            }
        });
    }

    /// Checks if the request from the IP is within the RPS (Requests Per Second) limit.
    pub fn check(&self, ip: IpAddr, config: &Config) -> bool {
        let max_rps = config.limit.max_rps;
        if max_rps == 0 {
            return true;
        }
        let now = Instant::now();
        let mut entry = self.records.entry(ip).or_insert(RateState {
            count: 0,
            last_reset: now,
        });

        if now.duration_since(entry.last_reset) >= Duration::from_secs(1) {
            entry.count = 1;
            entry.last_reset = now;
            true
        } else {
            if entry.count < max_rps {
                entry.count += 1;
                true
            } else {
                false
            }
        }
    }
}
