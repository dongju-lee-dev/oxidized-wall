/// Task 1: JSON Depth Integrity Check
/// Prevents Denial of Service (DoS) attacks that use extremely deep JSON/array nesting.
pub fn check_json_depth(input: &str, max_depth: usize) -> bool {
    let mut current_depth = 0;
    for c in input.chars() {
        if c == '{' || c == '[' {
            current_depth += 1;
            if current_depth > max_depth { return false; }
        } else if c == '}' || c == ']' {
            if current_depth > 0 { current_depth -= 1; }
        }
    }
    true
}

/// Task 2: Malicious Bot Detection
/// Checks User-Agent strings for signatures of common automated attack tools and scanners.
pub fn is_malicious_bot(user_agent: &str) -> bool {
    let ua = user_agent.to_lowercase();
    ua.contains("sqlmap") || ua.contains("nikto") || 
    ua.contains("nmap") || ua.contains("masscan") ||
    ua.contains("dirbuster") || ua.contains("gobuster")
}

/// Task 3: Payload Density Analysis
/// Calculates the ratio of special characters to letters/numbers.
/// High density often indicates obfuscated scripts or exploitation attempts.
pub fn is_high_density(input: &str, threshold: f32) -> bool {
    if input.is_empty() { return false; }
    let special_chars = input.chars().filter(|c| !c.is_alphanumeric() && !c.is_whitespace()).count();
    let density = special_chars as f32 / input.len() as f32;
    density > threshold
}

/// Task 4: Parameter Pollution Detection
/// Scans query strings or form data for duplicate parameter keys which can bypass logic.
pub fn has_parameter_pollution(input: &str) -> bool {
    use std::collections::HashSet;
    let mut seen_keys = HashSet::new();
    for pair in input.split('&') {
        if let Some(key) = pair.split('=').next() {
            if !key.is_empty() && !seen_keys.insert(key) { return true; }
        }
    }
    false
}
