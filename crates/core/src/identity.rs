//! Identity types: handles, DID keys, PersonalSpaceID.
//!
//! Matches Go server `services/identity.go`, `services/did.go`, `services/spaceid.go`.

use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("invalid handle format")]
    InvalidHandle,
    #[error("invalid public key")]
    InvalidPublicKey,
}

// ─── Handle ──────────────────────────────────────────────────────────────────

/// Extract the host portion from an issuer URL.
///
/// E.g., `"https://accounts.example.com"` → `"accounts.example.com"`.
pub fn extract_domain(issuer: &str) -> &str {
    let s = issuer.strip_prefix("https://").unwrap_or(issuer);
    let s = s.strip_prefix("http://").unwrap_or(s);
    // Strip path
    s.split('/').next().unwrap_or(s)
}

/// Format a handle from username and domain: `"user@domain"`.
pub fn format_handle(username: &str, domain: &str) -> String {
    format!("{}@{}", username, domain)
}

/// Parse a handle string into `(username, domain)`.
///
/// Validates that:
/// - The string contains exactly one `@`
/// - Neither part is empty
/// - No null bytes are present (security: prevents header injection)
pub fn parse_handle(handle: &str) -> Result<(String, String), IdentityError> {
    // Reject null bytes
    if handle.contains('\0') {
        return Err(IdentityError::InvalidHandle);
    }
    let at_count = handle.bytes().filter(|&b| b == b'@').count();
    if at_count != 1 {
        return Err(IdentityError::InvalidHandle);
    }
    let (user, domain) = handle.split_once('@').unwrap();
    if user.is_empty() || domain.is_empty() {
        return Err(IdentityError::InvalidHandle);
    }
    Ok((user.to_string(), domain.to_string()))
}

// ─── DID Key ─────────────────────────────────────────────────────────────────

/// Multicodec prefix for P-256 public keys (two-byte varint: 0x1200).
const P256_MULTICODEC: &[u8] = &[0x80, 0x24]; // varint encoding of 0x1200

/// Compute a `did:key` DID from a P-256 JWK public key.
///
/// The JWK must contain `"x"` and `"y"` fields (base64url, no padding).
/// Returns a `did:key:zDn...` string.
pub fn compute_did_key(jwk: &serde_json::Value) -> Result<String, IdentityError> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let x_str = jwk["x"].as_str().ok_or(IdentityError::InvalidPublicKey)?;
    let y_str = jwk["y"].as_str().ok_or(IdentityError::InvalidPublicKey)?;

    let x_bytes = b64
        .decode(x_str)
        .map_err(|_| IdentityError::InvalidPublicKey)?;
    let y_bytes = b64
        .decode(y_str)
        .map_err(|_| IdentityError::InvalidPublicKey)?;

    if x_bytes.len() != 32 || y_bytes.len() != 32 {
        return Err(IdentityError::InvalidPublicKey);
    }

    // Compressed point: 0x02 if y is even, 0x03 if y is odd
    let prefix = if y_bytes[31] % 2 == 0 { 0x02u8 } else { 0x03u8 };
    let mut compressed = Vec::with_capacity(33);
    compressed.push(prefix);
    compressed.extend_from_slice(&x_bytes);

    // Build multibase payload: multicodec prefix + compressed point
    let mut payload = Vec::with_capacity(2 + 33);
    payload.extend_from_slice(P256_MULTICODEC);
    payload.extend_from_slice(&compressed);

    // Base58btc encode with 'z' multibase prefix
    let encoded = bs58::encode(&payload).into_string();
    Ok(format!("did:key:z{}", encoded))
}

// ─── PersonalSpaceID ─────────────────────────────────────────────────────────

/// DNS UUID namespace (RFC 4122).
const UUID_DNS: Uuid = uuid::uuid!("6ba7b810-9dad-11d1-80b4-00c04fd430c8");

/// Compute the PersonalSpaceID for a user.
///
/// Formula (matching Go server):
/// ```text
/// LESS_NS = UUID5(DNS, "less.so")
/// personal_space_id = UUID5(LESS_NS, "{issuer}\x00{user_id}\x00{client_id}")
/// ```
pub fn personal_space_id(issuer: &str, user_id: &str, client_id: &str) -> Uuid {
    let less_ns = Uuid::new_v5(&UUID_DNS, b"less.so");
    let mut input = String::new();
    input.push_str(issuer);
    input.push('\0');
    input.push_str(user_id);
    input.push('\0');
    input.push_str(client_id);
    Uuid::new_v5(&less_ns, input.as_bytes())
}

#[cfg(test)]
mod tests {
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
}
