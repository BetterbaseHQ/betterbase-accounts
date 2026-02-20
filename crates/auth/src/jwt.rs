//! JWT token creation and validation.
//!
//! Mirrors Go server `services/jwt.go`.
//!
//! Token types:
//! - Auth (HS256, 14d) — internal session after OPAQUE login
//! - State (HS256, 60s) — ephemeral OPAQUE init→finalize binding
//! - OAuthAccess (ES256, 15m) — OAuth access token for client apps
//! - OAuthState (HS256, 10m) — preserves OAuth params across login redirect
//! - Verification (HS256, 15m) — one-time email verification proof

use chrono::{Duration, Utc};
use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

// ─── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("token expired")]
    TokenExpired,
    #[error("invalid token")]
    InvalidToken,
    #[error("key not found")]
    KeyNotFound,
    #[error("JWT error: {0}")]
    Internal(String),
}

impl From<jsonwebtoken::errors::Error> for JwtError {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        use jsonwebtoken::errors::ErrorKind;
        match e.kind() {
            ErrorKind::ExpiredSignature => JwtError::TokenExpired,
            _ => JwtError::InvalidToken,
        }
    }
}

// ─── Claims ──────────────────────────────────────────────────────────────────

/// Auth token claims — HS256, 14-day lifetime.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthClaims {
    pub sub: String,
    pub exp: i64,
    pub iat: i64,
}

/// State token claims — HS256, 60-second lifetime.
#[derive(Debug, Serialize, Deserialize)]
pub struct StateClaims {
    /// UUID of the registration or login state record.
    pub sub: String,
    pub exp: i64,
    pub iat: i64,
}

/// OAuth access token claims — ES256, 15-minute lifetime.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OAuthAccessClaims {
    pub sub: String,
    pub iss: String,
    pub aud: Vec<String>,
    pub exp: i64,
    pub iat: i64,
    pub client_id: String,
    pub grant_id: String,
    pub scope: String,
    pub did: String,
    pub personal_space_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mailbox_id: Option<String>,
}

/// OAuth state token claims — HS256, 10-minute lifetime.
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthStateClaims {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keys_jwk: Option<serde_json::Value>,
    pub exp: i64,
    pub iat: i64,
}

/// Email verification token claims — HS256, 15-minute lifetime.
#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationClaims {
    pub sub: String,
    pub email: String,
    pub purpose: String,
    pub jti: String,
    pub exp: i64,
    pub iat: i64,
}

// ─── Key provider traits ──────────────────────────────────────────────────────

/// Provider for the current HS256 signing key.
pub trait HmacKeyProvider: Send + Sync {
    fn current_key(&self) -> (i32, Vec<u8>);
    fn key_by_id(&self, kid: i32) -> Option<Vec<u8>>;
}

/// Provider for the current ES256 signing key.
pub trait Es256KeyProvider: Send + Sync {
    fn current_private_key_der(&self) -> (i32, Vec<u8>);
    fn public_key_der_by_id(&self, kid: i32) -> Option<Vec<u8>>;
}

// ─── JwtService ──────────────────────────────────────────────────────────────

/// JWT token service.
///
/// Holds in-memory copies of the current signing keys. Keys are loaded at
/// startup and don't change during a server's lifetime (key rotation restarts
/// the server in the standard deploy flow).
pub struct JwtService {
    /// HS256: (key_id, secret)
    hmac_key_id: i32,
    hmac_key: Vec<u8>,

    /// ES256: (key_id, PKCS#8 DER)
    es256_key_id: i32,
    es256_private_der: Vec<u8>,

    /// ES256 public keys by ID (SPKI DER), for validation
    es256_public_keys: Vec<(i32, Vec<u8>)>,

    pub issuer: String,
}

impl JwtService {
    pub fn new(
        hmac_key_id: i32,
        hmac_key: Vec<u8>,
        es256_key_id: i32,
        es256_private_der: Vec<u8>,
        es256_public_keys: Vec<(i32, Vec<u8>)>,
        issuer: String,
    ) -> Self {
        Self {
            hmac_key_id,
            hmac_key,
            es256_key_id,
            es256_private_der,
            es256_public_keys,
            issuer,
        }
    }

    // ─── Auth token ──────────────────────────────────────────────────────────

    pub fn create_auth_token(&self, account_id: &str) -> Result<String, JwtError> {
        let now = Utc::now();
        let claims = AuthClaims {
            sub: account_id.to_string(),
            iat: now.timestamp(),
            exp: (now + Duration::days(14)).timestamp(),
        };
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(self.hmac_key_id.to_string());
        encode(&header, &claims, &EncodingKey::from_secret(&self.hmac_key))
            .map_err(|e| JwtError::Internal(e.to_string()))
    }

    pub fn validate_auth_token(&self, token: &str) -> Result<AuthClaims, JwtError> {
        let header = jsonwebtoken::decode_header(token).map_err(|_| JwtError::InvalidToken)?;
        let kid = header.kid.as_deref().and_then(|k| k.parse::<i32>().ok());
        let key = self.hmac_key_for_kid(kid)?;
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        let data: TokenData<AuthClaims> =
            decode(token, &DecodingKey::from_secret(&key), &validation)?;
        Ok(data.claims)
    }

    // ─── State token ─────────────────────────────────────────────────────────

    pub fn create_state_token(&self, state_id: &str) -> Result<String, JwtError> {
        let now = Utc::now();
        let claims = StateClaims {
            sub: state_id.to_string(),
            iat: now.timestamp(),
            exp: (now + Duration::seconds(60)).timestamp(),
        };
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(self.hmac_key_id.to_string());
        encode(&header, &claims, &EncodingKey::from_secret(&self.hmac_key))
            .map_err(|e| JwtError::Internal(e.to_string()))
    }

    pub fn validate_state_token(&self, token: &str) -> Result<String, JwtError> {
        let header = jsonwebtoken::decode_header(token).map_err(|_| JwtError::InvalidToken)?;
        let kid = header.kid.as_deref().and_then(|k| k.parse::<i32>().ok());
        let key = self.hmac_key_for_kid(kid)?;
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        let data: TokenData<StateClaims> =
            decode(token, &DecodingKey::from_secret(&key), &validation)?;
        Ok(data.claims.sub)
    }

    // ─── OAuth state token ────────────────────────────────────────────────────

    pub fn create_oauth_state_token(&self, claims: OAuthStateClaims) -> Result<String, JwtError> {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(self.hmac_key_id.to_string());
        encode(&header, &claims, &EncodingKey::from_secret(&self.hmac_key))
            .map_err(|e| JwtError::Internal(e.to_string()))
    }

    pub fn validate_oauth_state_token(&self, token: &str) -> Result<OAuthStateClaims, JwtError> {
        let header = jsonwebtoken::decode_header(token).map_err(|_| JwtError::InvalidToken)?;
        let kid = header.kid.as_deref().and_then(|k| k.parse::<i32>().ok());
        let key = self.hmac_key_for_kid(kid)?;
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        let data: TokenData<OAuthStateClaims> =
            decode(token, &DecodingKey::from_secret(&key), &validation)?;
        Ok(data.claims)
    }

    // ─── OAuth access token ───────────────────────────────────────────────────

    pub fn create_oauth_access_token(&self, claims: OAuthAccessClaims) -> Result<String, JwtError> {
        let private_key = EncodingKey::from_ec_der(&self.es256_private_der);
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.es256_key_id.to_string());
        encode(&header, &claims, &private_key).map_err(|e| JwtError::Internal(e.to_string()))
    }

    pub fn validate_oauth_access_token(&self, token: &str) -> Result<OAuthAccessClaims, JwtError> {
        let header = jsonwebtoken::decode_header(token).map_err(|_| JwtError::InvalidToken)?;
        let kid = header.kid.as_deref().and_then(|k| k.parse::<i32>().ok());
        let public_spki = self.es256_public_for_kid(kid)?;
        // DecodingKey::from_ec_der expects SEC1 uncompressed point bytes (0x04||x||y),
        // not SPKI DER. Convert here.
        let sec1 =
            crate::es256::spki_der_to_sec1(&public_spki).map_err(|_| JwtError::KeyNotFound)?;
        let mut validation = Validation::new(Algorithm::ES256);
        validation.validate_exp = true;
        // Don't validate aud here — callers check it
        validation.validate_aud = false;
        let data: TokenData<OAuthAccessClaims> =
            decode(token, &DecodingKey::from_ec_der(&sec1), &validation)?;
        Ok(data.claims)
    }

    // ─── Verification token ───────────────────────────────────────────────────

    pub fn create_verification_token(
        &self,
        email: &str,
        purpose: &str,
    ) -> Result<String, JwtError> {
        let now = Utc::now();
        let claims = VerificationClaims {
            sub: email.to_string(),
            email: email.to_string(),
            purpose: purpose.to_string(),
            jti: Uuid::new_v4().to_string(),
            iat: now.timestamp(),
            exp: (now + Duration::minutes(15)).timestamp(),
        };
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(self.hmac_key_id.to_string());
        encode(&header, &claims, &EncodingKey::from_secret(&self.hmac_key))
            .map_err(|e| JwtError::Internal(e.to_string()))
    }

    pub fn validate_verification_token(&self, token: &str) -> Result<VerificationClaims, JwtError> {
        let header = jsonwebtoken::decode_header(token).map_err(|_| JwtError::InvalidToken)?;
        let kid = header.kid.as_deref().and_then(|k| k.parse::<i32>().ok());
        let key = self.hmac_key_for_kid(kid)?;
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        let data: TokenData<VerificationClaims> =
            decode(token, &DecodingKey::from_secret(&key), &validation)?;
        Ok(data.claims)
    }

    // ─── Key helpers ─────────────────────────────────────────────────────────

    fn hmac_key_for_kid(&self, kid: Option<i32>) -> Result<Vec<u8>, JwtError> {
        match kid {
            Some(id) if id == self.hmac_key_id => Ok(self.hmac_key.clone()),
            // If no kid or unknown kid, fall back to current key (backward compat)
            _ => Ok(self.hmac_key.clone()),
        }
    }

    fn es256_public_for_kid(&self, kid: Option<i32>) -> Result<Vec<u8>, JwtError> {
        let id = kid.unwrap_or(self.es256_key_id);
        self.es256_public_keys
            .iter()
            .find(|(k, _)| *k == id)
            .map(|(_, der)| der.clone())
            .ok_or(JwtError::KeyNotFound)
    }

    /// Current ES256 key ID (for JWKS generation in es256 module).
    pub fn es256_key_id(&self) -> i32 {
        self.es256_key_id
    }

    /// All ES256 public keys (SPKI DER), for JWKS endpoint.
    pub fn es256_public_keys(&self) -> &[(i32, Vec<u8>)] {
        &self.es256_public_keys
    }
}

// ─── Token expiry helpers for OAuthState ─────────────────────────────────────

impl OAuthStateClaims {
    pub fn new(
        client_id: String,
        redirect_uri: String,
        scope: String,
        state: String,
        code_challenge: String,
        code_challenge_method: String,
        keys_jwk: Option<serde_json::Value>,
    ) -> Self {
        let now = Utc::now();
        OAuthStateClaims {
            client_id,
            redirect_uri,
            scope,
            state,
            code_challenge,
            code_challenge_method,
            keys_jwk,
            iat: now.timestamp(),
            exp: (now + Duration::minutes(10)).timestamp(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_service() -> JwtService {
        // Use the es256 module to generate test keys
        let (private_der, public_der) = crate::es256::generate_keypair().unwrap();
        JwtService::new(
            1,
            vec![0u8; 32],
            1,
            private_der.clone(),
            vec![(1, public_der)],
            "https://accounts.example.com".to_string(),
        )
    }

    #[test]
    fn auth_token_roundtrip() {
        let svc = test_service();
        let token = svc.create_auth_token("user-uuid").unwrap();
        let claims = svc.validate_auth_token(&token).unwrap();
        assert_eq!(claims.sub, "user-uuid");
    }

    #[test]
    fn state_token_roundtrip() {
        let svc = test_service();
        let token = svc.create_state_token("state-uuid").unwrap();
        let id = svc.validate_state_token(&token).unwrap();
        assert_eq!(id, "state-uuid");
    }

    #[test]
    fn verification_token_roundtrip() {
        let svc = test_service();
        let token = svc
            .create_verification_token("user@example.com", "registration")
            .unwrap();
        let claims = svc.validate_verification_token(&token).unwrap();
        assert_eq!(claims.email, "user@example.com");
        assert_eq!(claims.purpose, "registration");
        assert!(!claims.jti.is_empty());
    }

    #[test]
    fn oauth_access_token_roundtrip() {
        let svc = test_service();
        let now = Utc::now();
        let claims = OAuthAccessClaims {
            sub: "user-uuid".to_string(),
            iss: svc.issuer.clone(),
            aud: vec!["client-uuid".to_string()],
            exp: (now + Duration::minutes(15)).timestamp(),
            iat: now.timestamp(),
            client_id: "client-uuid".to_string(),
            grant_id: "grant-uuid".to_string(),
            scope: "openid profile".to_string(),
            did: "did:key:zABC".to_string(),
            personal_space_id: "space-uuid".to_string(),
            mailbox_id: None,
        };
        let token = svc.create_oauth_access_token(claims.clone()).unwrap();
        let decoded = svc.validate_oauth_access_token(&token).unwrap();
        assert_eq!(decoded.sub, "user-uuid");
        assert_eq!(decoded.scope, "openid profile");
    }
}
