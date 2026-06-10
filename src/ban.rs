use crate::config::Config;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::warn;

/// Types of security violations that can trigger an IP ban.
#[derive(Debug, Clone, Copy)]
pub enum Violation {
    Timeout,
    Protocol,
    Waf,
    RateLimit,
}

struct BanEntry {
    expire_at: Instant,
}

/// Global manager for temporary IP bans.
#[derive(Clone)]
pub struct BanManager {
    banned_ips: Arc<RwLock<HashMap<IpAddr, BanEntry>>>,
}

impl BanManager {
    pub fn new() -> Self {
        Self {
            banned_ips: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Periodically removes expired ban entries from memory.
    pub fn spawn_cleanup_task(&self) {
        let list = self.banned_ips.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let now = Instant::now();
                let mut map = list.write().await;
                map.retain(|_, entry| entry.expire_at > now);
            }
        });
    }

    /// Punishes an IP by banning it for a duration specified in the config based on the violation type.
    pub async fn punish(&self, ip: IpAddr, violation: Violation, config: &Config) {
        let duration_sec = match violation {
            Violation::Timeout => config.ban.ban_timeout,
            Violation::Protocol => config.ban.ban_protocol,
            Violation::Waf => config.ban.ban_waf,
            Violation::RateLimit => config.ban.ban_rate_limit,
        };
        if duration_sec > 0 {
            warn!(
                "Punishing IP: {} for {:?} ({}s)",
                ip, violation, duration_sec
            );
            self.ban(ip, Duration::from_secs(duration_sec)).await;
        }
    }

    pub async fn ban(&self, ip: IpAddr, duration: Duration) {
        let expire_at = Instant::now() + duration;
        self.banned_ips
            .write()
            .await
            .insert(ip, BanEntry { expire_at });
    }

    /// Checks if an IP is currently banned. Handles lazy cleanup of expired entries.
    pub async fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        {
            let list = self.banned_ips.read().await;
            if let Some(entry) = list.get(&ip) {
                if now <= entry.expire_at {
                    return true;
                }
            } else {
                return false;
            }
        }
        let mut list = self.banned_ips.write().await;
        if let Some(entry) = list.get(&ip) {
            if now > entry.expire_at {
                list.remove(&ip);
                false
            } else {
                true
            }
        } else {
            false
        }
    }
}
