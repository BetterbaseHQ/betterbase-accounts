//! API request and response types.
//!
//! All types use `serde` for JSON serialization. Mirrors Go `protocol/types.go`.

use serde::{Deserialize, Serialize};

// ─── Error response ───────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

// ─── Verification ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SendVerificationCodeRequest {
    pub email: String,
    #[serde(default)]
    pub username: String,
    pub purpose: String,
    #[serde(default)]
    pub cap_token: String,
}

#[derive(Debug, Deserialize)]
pub struct ConfirmVerificationCodeRequest {
    pub email: String,
    pub code: String,
    pub purpose: String,
}

#[derive(Debug, Serialize)]
pub struct ConfirmVerificationCodeResponse {
    pub verification_token: String,
}

// ─── Registration ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PasswordInitRequest {
    /// Base64-encoded OPAQUE RegistrationRequest
    pub opaque_request: String,
    pub email: String,
    pub username: String,
    #[serde(default)]
    pub cap_token: String,
    pub verification_token: String,
}

#[derive(Debug, Serialize)]
pub struct PasswordInitResponse {
    /// Base64-encoded OPAQUE RegistrationResponse
    pub opaque_response: String,
    pub state_token: String,
    /// Account ID for client-side key derivation
    pub user_id: String,
}

#[derive(Debug, Deserialize)]
pub struct PasswordFinalizeRequest {
    /// Base64-encoded OPAQUE RegistrationUpload
    pub opaque_record: String,
    /// Base64-encoded 41-byte versioned AES-KW wrapped root key
    pub wrapped_root_key: String,
    pub state_token: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub auth_token: String,
    pub user_id: String,
}

// ─── Login ────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct LoginInitRequest {
    /// Base64-encoded OPAQUE CredentialRequest (KE1)
    pub opaque_ke1: String,
    pub username: String,
    #[serde(default)]
    pub cap_token: String,
}

#[derive(Debug, Serialize)]
pub struct LoginInitResponse {
    /// Base64-encoded OPAQUE CredentialResponse (KE2)
    pub opaque_ke2: String,
    pub login_token: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginFinalizeRequest {
    /// Base64-encoded OPAQUE CredentialFinalization (KE3)
    pub opaque_ke3: String,
    pub login_token: String,
}

// ─── Validate ─────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ValidateResponse {
    pub id: String,
    pub handle: String,
    pub email: String,
}

// ─── Password Change ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PasswordChangeInitRequest {
    #[serde(default)]
    pub username: String,
    pub opaque_ke1: String,
}

#[derive(Debug, Serialize)]
pub struct PasswordChangeInitResponse {
    pub opaque_ke2: String,
    pub login_token: String,
}

#[derive(Debug, Deserialize)]
pub struct PasswordChangeVerifyRequest {
    pub opaque_ke3: String,
    pub login_token: String,
    pub opaque_request: String,
}

#[derive(Debug, Serialize)]
pub struct PasswordChangeVerifyResponse {
    pub opaque_response: String,
    pub state_token: String,
}

#[derive(Debug, Deserialize)]
pub struct PasswordChangeCompleteRequest {
    pub opaque_record: String,
    pub wrapped_root_key: String,
    pub state_token: String,
}

// ─── Recovery ─────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct StoreRecoveryBlobRequest {
    pub blob: String,
}

#[derive(Debug, Serialize)]
pub struct GetRecoveryBlobResponse {
    pub blob: String,
}

#[derive(Debug, Deserialize)]
pub struct RecoverInitRequest {
    pub email: String,
    pub opaque_request: String,
    #[serde(default)]
    pub cap_token: String,
    pub verification_token: String,
}

#[derive(Debug, Serialize)]
pub struct RecoverInitResponse {
    pub opaque_response: String,
    pub state_token: String,
    pub user_id: String,
}

#[derive(Debug, Deserialize)]
pub struct RecoverFinalizeRequest {
    pub opaque_record: String,
    #[serde(default)]
    pub wrapped_root_key: String,
    pub state_token: String,
    #[serde(default)]
    pub new_blob: String,
}

// ─── User Keys ────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct UserKey {
    pub service: String,
    #[serde(rename = "keyName")]
    pub key_name: String,
    /// Hex-encoded key material
    #[serde(rename = "keyMaterial")]
    pub key_material: String,
    #[serde(rename = "serialNumber")]
    pub serial_number: i64,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
pub struct StoreKeyRequest {
    /// Hex-encoded key material
    #[serde(rename = "keyMaterial")]
    pub key_material: String,
}

// ─── Root Key ─────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct GetRootKeyResponse {
    /// Base64-encoded 41-byte wrapped root key
    pub wrapped_root_key: String,
}

#[derive(Debug, Deserialize)]
pub struct SetRootKeyRequest {
    /// Base64-encoded 41-byte wrapped root key
    pub wrapped_root_key: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GrantWrappedKey {
    pub grant_id: String,
    pub client_id: String,
    /// Base64-encoded 41-byte wrapped scoped key
    pub wrapped_scoped_key: String,
}

#[derive(Debug, Serialize)]
pub struct GetGrantWrappedKeysResponse {
    pub grants: Vec<GrantWrappedKey>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct GrantKeyUpdate {
    pub grant_id: String,
    pub wrapped_scoped_key: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateGrantWrappedKeysRequest {
    pub grants: Vec<GrantKeyUpdate>,
}

#[derive(Debug, Deserialize)]
pub struct RotateRootKeyRequest {
    pub wrapped_root_key: String,
    #[serde(default)]
    pub grants: Vec<GrantKeyUpdate>,
    #[serde(default)]
    pub recovery_blob: String,
}

// ─── OAuth ────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct OAuthConsentRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    #[serde(default)]
    pub keys_jwk: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct OAuthConsentResponse {
    /// Full redirect URI with `code` and `state` query params
    pub redirect_uri: String,
}

/// OAuth token request (JSON body).
#[derive(Debug, Deserialize)]
pub struct OAuthTokenRequest {
    pub grant_type: String,
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub redirect_uri: String,
    #[serde(default)]
    pub code_verifier: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub refresh_token: String,
    /// Extended PKCE thumbprint (only for sync/files scopes)
    #[serde(default)]
    pub keys_jwk_thumbprint: String,
}

#[derive(Debug, Serialize)]
pub struct OAuthTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub refresh_token: String,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keys_jwe: Option<String>,
    /// user@domain identity handle (not in JWT to avoid leaking to resource servers)
    #[serde(skip_serializing_if = "String::is_empty")]
    pub handle: String,
}

#[derive(Debug, Serialize)]
pub struct OAuthUserInfoResponse {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
}

/// `GET /oauth/grant-keypair` response
#[derive(Debug, Serialize)]
pub struct GrantKeypairResponse {
    /// Always emitted (empty string when absent), matching Go's no-omitempty field.
    pub app_keypair_blob: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrapped_scoped_key: Option<String>,
}

/// `POST /oauth/mailbox` request
#[derive(Debug, Deserialize)]
pub struct RegisterMailboxRequest {
    pub mailbox_id: String,
}

/// `GET /v1/users/{username}/keys/{client_id}` response
#[derive(Debug, Serialize)]
pub struct UserPublicKeyResponse {
    pub handle: String,
    pub client_id: String,
    pub public_key: serde_json::Value,
    pub did: String,
    pub issuer: String,
    pub user_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub mailbox_id: String,
}

/// `GET /v1/users/by-thumbprint/{thumbprint}` response
#[derive(Debug, Serialize)]
pub struct UserByThumbprintResponse {
    pub handle: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<serde_json::Value>,
}

// ─── Discovery ────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ServerMetadataResponse {
    pub version: u32,
    pub federation: bool,
    pub accounts_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub federation_ws: Option<String>,
    pub jwks_uri: String,
    pub webfinger: String,
    pub protocols: Vec<String>,
    pub pow_required: bool,
}

#[derive(Debug, Serialize)]
pub struct WebFingerResponse {
    pub subject: String,
    pub links: Vec<WebFingerLink>,
}

#[derive(Debug, Serialize)]
pub struct WebFingerLink {
    pub rel: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
}
