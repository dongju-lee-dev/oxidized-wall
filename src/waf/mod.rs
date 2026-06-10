use crate::proxy::BoxBody;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::{HeaderMap, Method, Uri, header::USER_AGENT};

pub mod core;
pub mod dlp;
pub mod file;
pub mod path;
pub mod structure;

/// [Phase 1: Header and Metadata Inspection]
/// High-speed check performed before processing the request body.
/// Targets URI-based injections and malicious bots.
pub fn header(uri: &Uri, _method: &Method, headers: &HeaderMap) -> Result<(), &'static str> {
    // 1. Normalize and check URI
    let raw_path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let normalized_path = path::normalize_url(raw_path);

    if path::is_traversal(&normalized_path) { return Err("Directory Traversal detected"); }
    
    // Optimized: Single-pass byte scanning for all injections
    if core::is_attack(normalized_path.as_bytes()) { return Err("Malicious pattern detected in URI"); }

    // 2. Check for Parameter Pollution in Query
    if let Some(query) = uri.query() {
        if structure::has_parameter_pollution(query) { return Err("HTTP Parameter Pollution detected in URI"); }
    }

    // 3. Reputation check via User-Agent
    if let Some(ua) = headers.get(USER_AGENT).and_then(|v| v.to_str().ok()) {
        if structure::is_malicious_bot(ua) { return Err("Malicious Bot detected"); }
    }
    Ok(())
}

pub fn body(headers: &HeaderMap, body_bytes: &[u8]) -> Result<(), &'static str> {
    // 1. File Security: Magic Number & Content-Type Mismatch
    file::check_magic_number(body_bytes)?;
    if let Some(ct) = headers.get(hyper::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()) {
        if !file::is_allowed_file_type(ct, body_bytes) {
            return Err("File signature mismatch with Content-Type");
        }
    }

    // 2. Structural check
    let body_str = String::from_utf8_lossy(body_bytes);
    if !structure::check_json_depth(&body_str, 10) { return Err("JSON nesting too deep"); }
    
    // 2. Obfuscation & Pollution Check
    if structure::is_high_density(&body_str, 0.4) { return Err("High payload density detected"); }
    if structure::has_parameter_pollution(&body_str) { return Err("Parameter Pollution detected in payload"); }

    // 3. Optimized: High-speed byte-level signature matching
    if core::is_attack(body_bytes) { return Err("Malicious pattern detected in payload"); }

    Ok(())
}

/// [Phase 3: Outbound Data Leakage Prevention]
/// Inspects and sanitizes the content being sent back to the user (DLP).
/// Only processes text-based content to avoid memory issues with large binary files.
pub async fn apply_dlp(headers: &HeaderMap, body: BoxBody) -> BoxBody {
    // Task: Content-Type Filtering
    // Only apply masking to text-like data to preserve performance and binary integrity.
    let is_text = headers.get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            let s = s.to_lowercase();
            s.contains("text/") || s.contains("json") || s.contains("xml") || s.contains("javascript")
        })
        .unwrap_or(false);

    if !is_text { return body; }

    match body.collect().await {
        Ok(collected) => {
            let bytes = collected.to_bytes();
            let original = String::from_utf8_lossy(&bytes);

            // Mask sensitive info (emails, credit cards)
            let masked = dlp::mask_sensitive_info(&original);

            http_body_util::Full::new(Bytes::from(masked))
                .map_err(|never| match never {})
                .boxed()
        }
        // In case of error, return empty body to avoid leaking partial data
        Err(_) => http_body_util::Empty::new()
            .map_err(|never| match never {})
            .boxed(),
    }
}
