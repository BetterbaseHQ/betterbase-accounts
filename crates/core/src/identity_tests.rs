use super::*;

#[test]
fn extract_domain_strips_scheme_and_path() {
    assert_eq!(extract_domain("https://example.com"), "example.com");
    assert_eq!(extract_domain("https://example.com/path"), "example.com");
    assert_eq!(extract_domain("http://localhost:8080"), "localhost:8080");
}

#[test]
fn format_handle_works() {
    assert_eq!(format_handle("alice", "example.com"), "alice@example.com");
}

#[test]
fn parse_handle_valid() {
    let (user, domain) = parse_handle("alice@example.com").unwrap();
    assert_eq!(user, "alice");
    assert_eq!(domain, "example.com");
}

#[test]
fn parse_handle_invalid() {
    assert!(parse_handle("noat").is_err());
    assert!(parse_handle("@nodomain").is_err());
    assert!(parse_handle("nolocal@").is_err());
    assert!(parse_handle("a@@b.com").is_err());
    // Null byte injection
    assert!(parse_handle("user\0@domain.com").is_err());
}

#[test]
fn personal_space_id_is_deterministic() {
    let id1 = personal_space_id("https://accounts.example.com", "user-uuid", "client-uuid");
    let id2 = personal_space_id("https://accounts.example.com", "user-uuid", "client-uuid");
    assert_eq!(id1, id2);
}

#[test]
fn personal_space_id_differs_by_param() {
    let id1 = personal_space_id("https://accounts.example.com", "user-1", "client-1");
    let id2 = personal_space_id("https://accounts.example.com", "user-2", "client-1");
    assert_ne!(id1, id2);
}

#[test]
fn compute_did_key_format() {
    // Use a known P-256 test key
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": b64.encode([0u8; 32]),
        "y": b64.encode([2u8; 32]),
    });
    let did = compute_did_key(&jwk).unwrap();
    assert!(
        did.starts_with("did:key:z"),
        "DID should start with did:key:z, got: {}",
        did
    );
}
