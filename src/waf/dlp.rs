use regex::Regex;
use std::sync::OnceLock;

/// Task 1: Sensitive Data Masking (DLP Core)
/// Automatically identifies and masks emails and credit card numbers in the data stream.
pub fn mask_sensitive_info(input: &str) -> String {
    static EMAIL_RE: OnceLock<Regex> = OnceLock::new();
    static CARD_RE: OnceLock<Regex> = OnceLock::new();

    let email_re = EMAIL_RE.get_or_init(|| {
        Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
            .expect("Invalid Email Regex")
    });
    
    let card_re = CARD_RE.get_or_init(|| {
        Regex::new(r"\b(?:\d[ -]*?){13,16}\b")
            .expect("Invalid Card Regex")
    });

    // Step 1: Mask Emails (user@example.com -> ****@example.com)
    let masked = email_re.replace_all(input, |caps: &regex::Captures| {
        let full = &caps[0];
        if let Some(at_idx) = full.find('@') {
            format!("****{}", &full[at_idx..])
        } else {
            full.to_string()
        }
    });

    // Step 2: Mask Credit Cards (Mask entire 13-16 digit sequence)
    card_re.replace_all(&masked, "****-****-****-****").to_string()
}
