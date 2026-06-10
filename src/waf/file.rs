/// Task 1: File Magic Number Verification
/// Inspects the first few bytes of the payload to verify the actual file type.
/// Prevents uploading malicious scripts disguised as images or documents.
pub fn check_magic_number(body: &[u8]) -> Result<(), &'static str> {
    if body.len() < 4 { return Ok(()); } // Too small to be a relevant file

    // Common malicious signatures to block (e.g., Executables)
    if body.starts_with(b"MZ") { return Err("Executable file upload blocked (.exe/.dll)"); }
    if body.starts_with(&[0x7F, 0x45, 0x4C, 0x46]) { return Err("ELF executable upload blocked"); }

    // If it looks like a script, block it
    if body.starts_with(b"#!/") || body.starts_with(b"<?php") {
        return Err("Script file upload blocked");
    }

    Ok(())
}

/// Task 2: Content-Type and Magic Number mismatch detection
/// Validates if the declared Content-Type matches the actual file signature.
pub fn is_allowed_file_type(content_type: &str, body: &[u8]) -> bool {
    if body.len() < 4 { return true; }

    match content_type {
        "image/jpeg" => body.starts_with(&[0xFF, 0xD8, 0xFF]),
        "image/png" => body.starts_with(&[0x89, 0x50, 0x4E, 0x47]),
        "image/gif" => body.starts_with(b"GIF8"),
        "application/pdf" => body.starts_with(b"%PDF"),
        "application/zip" => body.starts_with(b"PK\x03\x04"),
        _ => true, // Allow other types but magic number check above will still block dangerous ones
    }
}
