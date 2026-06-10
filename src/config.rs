use std::collections::HashMap;
use std::io::Cursor;
use std::path::Path;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, RwLock};

use rustls::ServerConfig as TlsServerConfig;
use rustls::server::{ClientHello, ResolvesServerCert, ResolvesServerCertUsingSni};
use rustls::sign::CertifiedKey;
use serde::Deserialize;
use tokio::fs;
use tracing::info;

/// High-level configuration structure for the proxy.
#[derive(Debug, Clone)]
pub struct Config {
    pub network: NetworkConfig,
    pub timeout: TimeoutConfig,
    pub limit: LimitConfig,
    pub ban: BanConfig,
    pub vhosts: HashMap<String, VHostConfig>,
    pub tls: Arc<TlsServerConfig>,
    pub cert_resolver: Arc<CertResolver>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NetworkConfig {
    pub http_addrs: Vec<String>,
    pub https_addrs: Vec<String>,
    pub max_connections: usize,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TimeoutConfig {
    pub c_tls_handshake: u64,
    pub c_header_read: u64,
    pub c_keep_alive_idle: u64,
    pub c_keep_alive_timeout: u64,
    pub c_body_timeout: u64,
    pub s_connect: u64,
    pub s_response: u64,
    pub s_websocket_idle: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LimitConfig {
    pub max_uri_size: usize,
    pub max_header_size: usize,
    pub max_header_count: usize,
    pub max_body_size: usize,
    pub c_h2_max_streams: u32,
    pub max_rps: u32,
    pub max_bandwidth: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BanConfig {
    pub ban_timeout: u64,
    pub ban_protocol: u64,
    pub ban_waf: u64,
    pub ban_rate_limit: u64,
}

/// Runtime configuration for a specific virtual host.
#[derive(Debug, Clone)]
pub struct VHostConfig {
    pub cert_path: String,
    pub key_path: String,
    pub routers: Vec<(String, Vec<String>)>,
    pub routers_state: HashMap<String, Arc<AtomicUsize>>,
}

#[derive(Debug)]
pub struct CertResolver {
    inner: RwLock<Arc<ResolvesServerCertUsingSni>>,
}

impl CertResolver {
    pub fn new(resolver: ResolvesServerCertUsingSni) -> Self {
        Self {
            inner: RwLock::new(Arc::new(resolver)),
        }
    }

    pub fn update(&self, resolver: ResolvesServerCertUsingSni) {
        let mut writer = self
            .inner
            .write()
            .expect("Failed to lock CertResolver for write");
        *writer = Arc::new(resolver);
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        self.inner
            .read()
            .expect("Failed to lock CertResolver for read")
            .resolve(client_hello)
    }
}

#[derive(Deserialize)]
struct RawConfig {
    network: NetworkConfig,
    timeout: TimeoutConfig,
    limit: LimitConfig,
    ban: BanConfig,
    vhosts: Vec<RawVHost>,
}

#[derive(Deserialize)]
struct RawVHost {
    domain: String,
    cert_path: String,
    key_path: String,
    routers: HashMap<String, Vec<String>>,
}

impl Config {
    pub async fn load<P: AsRef<Path>>(
        path: P,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let content = fs::read_to_string(path).await?;
        let raw: RawConfig = toml::from_str(&content)?;

        let mut vhosts = HashMap::with_capacity(raw.vhosts.len());
        let mut resolver = ResolvesServerCertUsingSni::new();

        for rv in raw.vhosts {
            let mut routers_state = HashMap::with_capacity(rv.routers.len());
            let mut sorted_routers = Vec::with_capacity(rv.routers.len());

            for (path, upstreams) in rv.routers {
                routers_state.insert(path.clone(), Arc::new(AtomicUsize::new(0)));
                sorted_routers.push((path, upstreams));
            }

            sorted_routers.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

            let cert_bytes = fs::read(&rv.cert_path).await?;
            let key_bytes = fs::read(&rv.key_path).await?;
            let certs = rustls_pemfile::certs(&mut Cursor::new(cert_bytes))
                .collect::<Result<Vec<_>, _>>()?;
            let private_key = rustls_pemfile::private_key(&mut Cursor::new(key_bytes))?
                .ok_or("No private key found")?;
            let key = rustls::crypto::ring::sign::any_supported_type(&private_key)
                .map_err(|_| "Invalid private key")?;
            let certified_key = CertifiedKey::new(certs, key);

            resolver.add(&rv.domain, certified_key)?;
            info!("Loaded VHost: {}", rv.domain);

            vhosts.insert(
                rv.domain,
                VHostConfig {
                    cert_path: rv.cert_path,
                    key_path: rv.key_path,
                    routers: sorted_routers,
                    routers_state,
                },
            );
        }

        let cert_resolver = Arc::new(CertResolver::new(resolver));

        let mut tls = TlsServerConfig::builder_with_protocol_versions(&[
            &rustls::version::TLS13,
            &rustls::version::TLS12,
        ])
        .with_no_client_auth()
        .with_cert_resolver(cert_resolver.clone());
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        Ok(Config {
            network: raw.network,
            timeout: raw.timeout,
            limit: raw.limit,
            ban: raw.ban,
            vhosts,
            tls: Arc::new(tls),
            cert_resolver,
        })
    }

    /// Reloads all certificates from disk and updates the resolver.
    pub async fn reload_certs(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Hot-reloading certificates...");
        let mut new_resolver = ResolvesServerCertUsingSni::new();

        for (domain, vhost) in &self.vhosts {
            let cert_bytes = fs::read(&vhost.cert_path).await?;
            let key_bytes = fs::read(&vhost.key_path).await?;

            let certs = rustls_pemfile::certs(&mut Cursor::new(cert_bytes))
                .collect::<Result<Vec<_>, _>>()?;
            let private_key = rustls_pemfile::private_key(&mut Cursor::new(key_bytes))?
                .ok_or("No private key found")?;
            let key = rustls::crypto::ring::sign::any_supported_type(&private_key)
                .map_err(|_| "Invalid private key")?;
            let certified_key = CertifiedKey::new(certs, key);

            new_resolver.add(domain, certified_key)?;
            info!("Reloaded certificate for domain: {}", domain);
        }

        self.cert_resolver.update(new_resolver);
        info!("Certificate hot-reload complete.");
        Ok(())
    }
}
