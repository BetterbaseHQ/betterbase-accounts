//! ES256 key management: P-256 keypair generation, JWKS output.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
use p256::{
    ecdsa::SigningKey,
    elliptic_curve::sec1::ToSec1Point,
    elliptic_curve::Generate,
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    PublicKey,
};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Es256Error {
    #[error("key generation failed: {0}")]
    Generation(String),
    #[error("invalid key encoding: {0}")]
    Encoding(String),
    #[error("invalid key: {0}")]
    InvalidKey(String),
}

/// Generate a new P-256 keypair.
///
/// Returns `(private_key_pkcs8_der, public_key_spki_der)`.
pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), Es256Error> {
    let signing_key = SigningKey::generate();
    let private_der = signing_key
        .to_pkcs8_der()
        .map_err(|e| Es256Error::Generation(e.to_string()))?
        .as_bytes()
        .to_vec();
    let public_key: PublicKey = signing_key.verifying_key().into();
    let public_der = public_key
        .to_public_key_der()
        .map_err(|e| Es256Error::Generation(e.to_string()))?
        .as_bytes()
        .to_vec();
    Ok((private_der, public_der))
}

/// A JSON Web Key (public key representation for JWKS endpoint).
#[derive(Debug, Clone, Serialize)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
    #[serde(rename = "use")]
    pub use_: Option<String>,
    pub kid: String,
    pub alg: String,
}

impl Jwk {
    /// Build a JWK from SPKI DER bytes.
    pub fn from_spki_der(kid: i32, spki_der: &[u8]) -> Result<Self, Es256Error> {
        use p256::PublicKey;
        let public_key = PublicKey::from_public_key_der(spki_der)
            .map_err(|e| Es256Error::InvalidKey(e.to_string()))?;
        let point = public_key.to_sec1_point(false);
        let x = B64URL.encode(
            point
                .x()
                .ok_or_else(|| Es256Error::InvalidKey("missing x".into()))?,
        );
        let y = B64URL.encode(
            point
                .y()
                .ok_or_else(|| Es256Error::InvalidKey("missing y".into()))?,
        );
        Ok(Jwk {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x,
            y,
            use_: Some("sig".to_string()),
            kid: kid.to_string(),
            alg: "ES256".to_string(),
        })
    }

    /// Build a JWK from PKCS#8 DER private key bytes (derives public key).
    pub fn from_pkcs8_der(kid: i32, pkcs8_der: &[u8]) -> Result<Self, Es256Error> {
        let signing_key = SigningKey::from_pkcs8_der(pkcs8_der)
            .map_err(|e| Es256Error::InvalidKey(e.to_string()))?;
        let spki_der = signing_key
            .verifying_key()
            .to_public_key_der()
            .map_err(|e| Es256Error::Encoding(e.to_string()))?;
        Self::from_spki_der(kid, spki_der.as_bytes())
    }

    /// Construct the JWK as a `serde_json::Value` (for storage in DB / JWT claims).
    pub fn to_json_value(&self) -> serde_json::Value {
        serde_json::json!({
            "kty": self.kty,
            "crv": self.crv,
            "x": self.x,
            "y": self.y,
            "use": self.use_,
            "kid": self.kid,
            "alg": self.alg,
        })
    }
}

/// Convert SPKI DER public key bytes to SEC1 uncompressed point bytes.
///
/// `DecodingKey::from_ec_der` in `jsonwebtoken` (rust_crypto backend) calls
/// `VerifyingKey::from_sec1_bytes`, so we must pass raw uncompressed-point bytes
/// (`0x04 || x || y`), not SPKI DER.
pub fn spki_der_to_sec1(spki_der: &[u8]) -> Result<Vec<u8>, Es256Error> {
    let public_key = PublicKey::from_public_key_der(spki_der)
        .map_err(|e| Es256Error::InvalidKey(e.to_string()))?;
    Ok(public_key.to_sec1_point(false).as_bytes().to_vec())
}

/// JWKS response body.
#[derive(Debug, Serialize)]
pub struct Jwks {
    pub keys: Vec<serde_json::Value>,
}

impl Jwks {
    /// Build a JWKS from a list of `(key_id, SPKI_DER)` pairs.
    pub fn from_signing_keys(keys: &[(i32, Vec<u8>)]) -> Result<Self, Es256Error> {
        let mut jwks = Vec::with_capacity(keys.len());
        for (kid, spki_der) in keys {
            let jwk = Jwk::from_spki_der(*kid, spki_der)?;
            jwks.push(jwk.to_json_value());
        }
        Ok(Jwks { keys: jwks })
    }
}

/// Compute the JWK thumbprint (SHA-256 of canonical form) for a public key JWK.
///
/// Per RFC 7638: hash of `{"crv":"P-256","kty":"EC","x":"...","y":"..."}` (lexicographic field order).
pub fn jwk_thumbprint(jwk: &serde_json::Value) -> Option<String> {
    use sha2::{Digest, Sha256};
    let x = jwk["x"].as_str()?;
    let y = jwk["y"].as_str()?;
    // RFC 7638 canonical form (required members in lexicographic order, no whitespace)
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    let hash = Sha256::digest(canonical.as_bytes());
    Some(B64URL.encode(hash))
}

#[cfg(test)]
#[path = "es256_tests.rs"]
mod tests;
