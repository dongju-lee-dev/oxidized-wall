# Oxidized Wall

A modern Web Application Firewall (WAF) and Reverse Proxy built on a high-performance asynchronous engine (Hyper/Tokio).

## Core Features

*   **High-Performance Proxy Engine:** Full support for HTTP/1.1, HTTP/2, and WebSockets.
*   **Intelligent WAF:** Real-time blocking of major web attacks such as SQL Injection, XSS, and Directory Traversal.
*   **Granular Resource Control:** Per-IP Rate Limiting and Bandwidth Throttling.
*   **Protocol Integrity Guard:** Defense against protocol-level attacks like Request Smuggling, Host header spoofing, and malformed URIs.
*   **Data Leakage Prevention (DLP):** Automatic masking of sensitive information (emails, credit card numbers) in response data.
*   **Real-time Response:** Automatic IP banning for violations and zero-downtime certificate hot-reloading.

---

## Quick Start

### 1. Clone and Enter Repository
```bash
git clone https://github.com/your-username/oxidized-wall.git
cd oxidized-wall
```

### 2. Create Configuration File
```bash
# Copy the example configuration to create your active config.
cp config.example.toml config.toml
```
*Edit `config.toml` to match your domain, certificate paths, and backend server addresses.*

### 3. Run (Using Cargo)
```bash
cargo run --release
```

4. Run (Using Docker)
```bash
docker build -t oxidized-wall .
docker run -p 80:80 -p 443:443 -v $(pwd):/app oxidized-wall
```

