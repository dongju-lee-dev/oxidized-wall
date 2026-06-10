use aho_corasick::AhoCorasick;
use std::sync::OnceLock;

/// Pre-compiled Aho-Corasick automaton for fixed path patterns.
static TRAVERSAL_MATCHER: OnceLock<AhoCorasick> = OnceLock::new();

fn get_traversal_matcher() -> &'static AhoCorasick {
    TRAVERSAL_MATCHER.get_or_init(|| {
        let patterns = &[
            "../", "..\\", "/etc/passwd", "windows/system32", "boot.ini",
            "%2e%2e%2f", "%2e%2e%5c" // Also catch common encodings
        ];
        AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(patterns)
            .expect("Failed to build Aho-Corasick")
    })
}

/// Task 1: Efficient URL Normalization
pub fn normalize_url(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let mut hex = String::new();
            if let Some(h1) = chars.next() { hex.push(h1); }
            if let Some(h2) = chars.next() { hex.push(h2); }
            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                result.push(byte as char); continue;
            }
            result.push('%'); result.push_str(&hex);
        } else { result.push(c); }
    }
    result
}

/// Task 2: High-speed Traversal Detection using Aho-Corasick.
pub fn is_traversal(input: &str) -> bool {
    get_traversal_matcher().is_match(input)
}
