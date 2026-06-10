use hyper::{
    HeaderMap, Method, Uri,
    header::{CONTENT_LENGTH, HOST, TRANSFER_ENCODING},
};

pub enum ProtocolError {
    InvalidUri(String),
    InvalidHost(String),
    RequestSmuggling(String),
}

impl From<ProtocolError> for &'static str {
    fn from(err: ProtocolError) -> Self {
        match err {
            ProtocolError::InvalidUri(_) => "Invalid characters in URI",
            ProtocolError::InvalidHost(_) => "Invalid or duplicate Host header",
            ProtocolError::RequestSmuggling(_) => "Request Smuggling detected (CL/TE mixed)",
        }
    }
}

/// Task 1: URI Integrity Check
/// Inspects the URI for control characters like \0, \n, \r which can be used for injection or bypass attacks.
pub fn validate_uri(uri: &Uri) -> Result<(), ProtocolError> {
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    for c in path_and_query.chars() {
        if c.is_control() {
            return Err(ProtocolError::InvalidUri(format!(
                "Control character detected: {:?}",
                c
            )));
        }
    }
    Ok(())
}

/// Task 2: Host Header Validation
/// Ensures the Host header is present and unique.
/// This is critical for HTTP/1.1 to prevent Host Header Injection or routing confusion.
pub fn validate_host(headers: &HeaderMap, method: &Method, uri: &Uri) -> Result<(), ProtocolError> {
    if *method != Method::CONNECT {
        let hosts: Vec<_> = headers.get_all(HOST).iter().collect();
        
        if hosts.is_empty() && uri.host().is_none() { 
            return Err(ProtocolError::InvalidHost("Missing Host or Authority".into())); 
        }
        
        if hosts.len() > 1 { 
            return Err(ProtocolError::InvalidHost("Duplicate Host header".into())); 
        }
    }
    Ok(())
}

/// Task 3: Request Smuggling Prevention
/// Blocks requests that contain both Content-Length and Transfer-Encoding headers.
/// This prevents desynchronization between the proxy and backend servers.
pub fn validate_smuggling(headers: &HeaderMap) -> Result<(), ProtocolError> {
    if headers.contains_key(CONTENT_LENGTH) && headers.contains_key(TRANSFER_ENCODING) {
        return Err(ProtocolError::RequestSmuggling(
            "Both CL and TE present".into(),
        ));
    }
    Ok(())
}
