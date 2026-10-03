//! Identity types: handles, DID keys, PersonalSpaceID.

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
/// Formula:
/// ```text
/// BETTERBASE_NS = UUID5(DNS, "betterbase.dev")
/// personal_space_id = UUID5(BETTERBASE_NS, "{issuer}\x00{user_id}\x00{client_id}")
/// ```
pub fn personal_space_id(issuer: &str, user_id: &str, client_id: &str) -> Uuid {
    let betterbase_ns = Uuid::new_v5(&UUID_DNS, b"betterbase.dev");
    let mut input = String::new();
    input.push_str(issuer);
    input.push('\0');
    input.push_str(user_id);
    input.push('\0');
    input.push_str(client_id);
    Uuid::new_v5(&betterbase_ns, input.as_bytes())
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod tests;
