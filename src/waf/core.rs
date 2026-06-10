use regex::bytes::RegexSet;
use std::sync::OnceLock;

/// Pre-compiled set of all malicious patterns.
/// Using RegexSet allows scanning for multiple patterns in a single pass over the byte array.
static ATTACK_PATTERNS: OnceLock<RegexSet> = OnceLock::new();

fn get_patterns() -> &'static RegexSet {
    ATTACK_PATTERNS.get_or_init(|| {
        RegexSet::new(&[
            // SQL Injection
            r"(?i)union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|' OR '1'='1'|--",
            // XSS
            r"(?i)<script.*?>|javascript:|onerror\s*=|onload\s*=|alert\(|<iframe>",
            // Command Injection
            r"(?i);\s*(ls|rm|cat|id|whoami|pwd|wget|curl)|&&|\|\||\||\$\(.*?\)",
        ]).expect("Failed to compile WAF RegexSet")
    })
}

/// Detects any type of injection attack in a single pass over raw bytes.
/// Optimized: No UTF-8 string conversion, No multiple scans.
pub fn is_attack(input: &[u8]) -> bool {
    get_patterns().is_match(input)
}
