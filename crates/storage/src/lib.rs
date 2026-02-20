#![forbid(unsafe_code)]

pub mod postgres;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::time::Duration;
use thiserror::Error;
use uuid::Uuid;

// ─── Error types ─────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("account not found")]
    AccountNotFound,
    #[error("account already exists")]
    AccountExists,
    #[error("state not found")]
    StateNotFound,
    #[error("state expired")]
    StateExpired,
    #[error("key not found")]
    KeyNotFound,
    #[error("maximum keys per service exceeded")]
    MaxKeysExceeded,
    #[error("OAuth client not found")]
    OAuthClientNotFound,
    #[error("OAuth code not found")]
    OAuthCodeNotFound,
    #[error("OAuth code expired")]
    OAuthCodeExpired,
    #[error("OAuth grant not found")]
    OAuthGrantNotFound,
    #[error("refresh token not found")]
    RefreshTokenNotFound,
    #[error("refresh token expired")]
    RefreshTokenExpired,
    #[error("refresh token reused")]
    RefreshTokenReused {
        /// The grant whose tokens should be revoked.
        grant_id: Uuid,
    },
    #[error("invalid redirect URI")]
    InvalidRedirectURI,
    #[error("recovery blob not found")]
    RecoveryBlobNotFound,
    #[error("verification code not found")]
    VerificationCodeNotFound,
    #[error("verification code expired")]
    VerificationCodeExpired,
    #[error("too many verification attempts")]
    VerificationMaxAttempts,
    #[error("verification send rate limited")]
    VerificationRateLimited,
    #[error("login rate limited")]
    LoginRateLimited,
    #[error("recovery rate limited")]
    RecoveryRateLimited,
    #[error("wrapped root key not found")]
    WrappedRootKeyNotFound,
    #[error("verification token already used")]
    VerificationTokenUsed,
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("internal error: {0}")]
    Internal(String),
}

// ─── Domain types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Account {
    pub id: Uuid,
    pub issuer: String,
    pub username: String,
    pub email: String,
    /// OPAQUE registration record bytes (None if not yet registered)
    pub opaque_record: Option<Vec<u8>>,
    /// AES-KW wrapped root key (None if not set)
    pub wrapped_root_key: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct RegistrationState {
    pub id: Uuid,
    pub account_id: Uuid,
    pub username: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct LoginState {
    pub id: Uuid,
    /// None for fake-login states (non-existent accounts)
    pub account_id: Option<Uuid>,
    pub username: String,
    /// Serialized opaque-ke ServerLogin state bytes
    pub state: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct JwtKey {
    pub id: i32,
    pub secret_key: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct UserKey {
    pub account_id: Uuid,
    pub service: String,
    pub key_name: String,
    pub key_material: Vec<u8>,
    pub serial_number: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct OAuthClient {
    pub id: Uuid,
    pub name: String,
    /// Bcrypt hash of client secret, or None for public clients
    pub secret_hash: Option<String>,
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct OAuthCode {
    pub code: String,
    pub client_id: Uuid,
    pub account_id: Uuid,
    pub redirect_uri: String,
    pub scope: String,
    pub code_challenge: String,
    /// JWE-wrapped scoped key for extended PKCE delivery
    pub keys_jwe: Option<String>,
    /// JWK thumbprint of the ephemeral key (for extended PKCE binding)
    pub keys_jwk_thumbprint: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct OAuthGrant {
    pub id: Uuid,
    pub client_id: Uuid,
    pub account_id: Uuid,
    pub scope: String,
    pub keys_jwk_thumbprint: Option<String>,
    pub app_public_key: Option<serde_json::Value>,
    /// AES-256-GCM encrypted keypair blob
    pub app_keypair_blob: Option<String>,
    /// AES-KW wrapped scoped encryption key (41 bytes)
    pub wrapped_scoped_key: Option<Vec<u8>>,
    /// 64-hex-char mailbox ID
    pub mailbox_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct OAuthRefreshToken {
    pub id: Uuid,
    pub grant_id: Uuid,
    /// SHA-256 hash of the raw token bytes
    pub token_hash: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct OAuthSigningKey {
    pub id: i32,
    /// PKCS#8 DER
    pub private_key: Vec<u8>,
    /// SPKI DER
    pub public_key: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct VerificationCode {
    pub id: Uuid,
    pub email: String,
    /// SHA-256 hash of the 6-digit code string
    pub code_hash: Vec<u8>,
    pub purpose: String,
    pub attempts: i32,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Input to batch grant key updates.
#[derive(Debug, Clone)]
pub struct GrantKeyUpdate {
    pub grant_id: Uuid,
    pub wrapped_scoped_key: Vec<u8>,
}

// ─── Storage traits ───────────────────────────────────────────────────────────

#[async_trait]
pub trait AccountStorage: Send + Sync {
    async fn get_or_create_account(
        &self,
        issuer: &str,
        username: &str,
        email: &str,
    ) -> Result<Account, StorageError>;
    async fn get_account_by_id(&self, id: Uuid) -> Result<Account, StorageError>;
    async fn get_account_by_username(
        &self,
        issuer: &str,
        username: &str,
    ) -> Result<Account, StorageError>;
    async fn get_account_by_email(
        &self,
        issuer: &str,
        email: &str,
    ) -> Result<Account, StorageError>;
    async fn finalize_registration(
        &self,
        account_id: Uuid,
        opaque_record: &[u8],
    ) -> Result<(), StorageError>;
    async fn finalize_registration_with_root_key(
        &self,
        account_id: Uuid,
        opaque_record: &[u8],
        wrapped_root_key: &[u8],
    ) -> Result<(), StorageError>;
    async fn update_registration(
        &self,
        account_id: Uuid,
        opaque_record: &[u8],
    ) -> Result<(), StorageError>;
    async fn delete_account(&self, account_id: Uuid) -> Result<(), StorageError>;
}

#[async_trait]
pub trait RootKeyStorage: Send + Sync {
    async fn get_wrapped_root_key(&self, account_id: Uuid) -> Result<Vec<u8>, StorageError>;
    async fn set_wrapped_root_key(
        &self,
        account_id: Uuid,
        wrapped_key: &[u8],
    ) -> Result<(), StorageError>;
}

#[async_trait]
pub trait RegistrationStateStorage: Send + Sync {
    async fn create_registration_state(
        &self,
        state: &RegistrationState,
    ) -> Result<(), StorageError>;
    async fn get_registration_state(&self, id: Uuid) -> Result<RegistrationState, StorageError>;
    /// Atomically get and delete the registration state (prevents TOCTOU replay).
    async fn consume_registration_state(&self, id: Uuid)
        -> Result<RegistrationState, StorageError>;
}

#[async_trait]
pub trait LoginStateStorage: Send + Sync {
    async fn create_login_state(&self, state: &LoginState) -> Result<(), StorageError>;
    async fn get_login_state(&self, id: Uuid) -> Result<LoginState, StorageError>;
    /// Atomically get and delete the login state (prevents TOCTOU replay).
    async fn consume_login_state(&self, id: Uuid) -> Result<LoginState, StorageError>;
}

#[async_trait]
pub trait JwtKeyStorage: Send + Sync {
    async fn get_current_jwt_key(&self) -> Result<JwtKey, StorageError>;
    async fn get_jwt_key_by_id(&self, id: i32) -> Result<JwtKey, StorageError>;
    /// Insert a new JWT key if none exists; no-op otherwise.
    async fn ensure_jwt_key(&self, secret_key: &[u8]) -> Result<(), StorageError>;
}

#[async_trait]
pub trait UserKeyStorage: Send + Sync {
    async fn list_user_keys(&self, account_id: Uuid) -> Result<Vec<UserKey>, StorageError>;
    async fn get_user_key(
        &self,
        account_id: Uuid,
        service: &str,
        key_name: &str,
    ) -> Result<UserKey, StorageError>;
    async fn store_user_key(
        &self,
        account_id: Uuid,
        service: &str,
        key_name: &str,
        key_material: &[u8],
    ) -> Result<(), StorageError>;
}

#[async_trait]
pub trait OAuthClientStorage: Send + Sync {
    async fn create_oauth_client(&self, client: &OAuthClient) -> Result<(), StorageError>;
    async fn get_oauth_client(&self, client_id: Uuid) -> Result<OAuthClient, StorageError>;
    async fn validate_redirect_uri(&self, client_id: Uuid, uri: &str)
        -> Result<bool, StorageError>;
}

#[async_trait]
pub trait OAuthCodeStorage: Send + Sync {
    async fn create_oauth_code(&self, code: &OAuthCode) -> Result<(), StorageError>;
    async fn get_oauth_code(&self, code: &str) -> Result<OAuthCode, StorageError>;
    /// Atomically get and delete the code.
    async fn consume_oauth_code(&self, code: &str) -> Result<OAuthCode, StorageError>;
    async fn delete_oauth_code(&self, code: &str) -> Result<(), StorageError>;
}

#[async_trait]
pub trait OAuthGrantStorage: Send + Sync {
    async fn get_or_create_oauth_grant(
        &self,
        client_id: Uuid,
        account_id: Uuid,
        scope: &str,
    ) -> Result<OAuthGrant, StorageError>;
    async fn get_or_create_oauth_grant_with_thumbprint(
        &self,
        client_id: Uuid,
        account_id: Uuid,
        scope: &str,
        thumbprint: &str,
    ) -> Result<OAuthGrant, StorageError>;
    async fn get_oauth_grant(&self, grant_id: Uuid) -> Result<OAuthGrant, StorageError>;
    async fn get_oauth_grant_by_account_and_client(
        &self,
        account_id: Uuid,
        client_id: Uuid,
    ) -> Result<OAuthGrant, StorageError>;
    async fn get_account_by_key_thumbprint(
        &self,
        thumbprint: &str,
    ) -> Result<(Account, OAuthGrant), StorageError>;
    async fn update_grant_last_used(&self, grant_id: Uuid) -> Result<(), StorageError>;
    async fn update_grant_keypair(
        &self,
        grant_id: Uuid,
        public_key: &serde_json::Value,
        blob: &str,
    ) -> Result<(), StorageError>;
    async fn update_grant_wrapped_scoped_key(
        &self,
        grant_id: Uuid,
        wrapped_scoped_key: &[u8],
    ) -> Result<(), StorageError>;
    /// First-write-wins: does nothing if already set.
    async fn update_grant_mailbox_id(
        &self,
        grant_id: Uuid,
        mailbox_id: &str,
    ) -> Result<(), StorageError>;
    async fn list_grants_for_account(
        &self,
        account_id: Uuid,
    ) -> Result<Vec<OAuthGrant>, StorageError>;
    async fn batch_update_grant_wrapped_keys(
        &self,
        updates: &[GrantKeyUpdate],
    ) -> Result<(), StorageError>;
}

#[async_trait]
pub trait OAuthRefreshTokenStorage: Send + Sync {
    async fn create_refresh_token(&self, token: &OAuthRefreshToken) -> Result<(), StorageError>;
    async fn get_refresh_token_by_hash(
        &self,
        hash: &[u8],
    ) -> Result<OAuthRefreshToken, StorageError>;
    async fn delete_refresh_token(&self, token_id: Uuid) -> Result<(), StorageError>;
    async fn delete_refresh_tokens_by_grant(&self, grant_id: Uuid) -> Result<(), StorageError>;
    /// Atomically: delete old token, record it as used, create new token.
    async fn rotate_refresh_token(
        &self,
        old_token_id: Uuid,
        old_token_hash: &[u8],
        grant_id: Uuid,
        new_token: &OAuthRefreshToken,
    ) -> Result<(), StorageError>;
}

#[async_trait]
pub trait OAuthSigningKeyStorage: Send + Sync {
    /// Insert signing key if none exists; no-op otherwise.
    async fn ensure_oauth_signing_key(
        &self,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<(), StorageError>;
    async fn get_current_signing_key(&self) -> Result<OAuthSigningKey, StorageError>;
    async fn get_signing_key_by_id(&self, kid: i32) -> Result<OAuthSigningKey, StorageError>;
    async fn list_signing_keys(&self) -> Result<Vec<OAuthSigningKey>, StorageError>;
}

#[async_trait]
pub trait RecoveryStorage: Send + Sync {
    async fn store_recovery_blob(&self, account_id: Uuid, blob: &[u8]) -> Result<(), StorageError>;
    async fn get_recovery_blob_by_email(
        &self,
        issuer: &str,
        email: &str,
    ) -> Result<Vec<u8>, StorageError>;
    async fn delete_recovery_blob(&self, account_id: Uuid) -> Result<(), StorageError>;
}

#[async_trait]
pub trait VerificationStorage: Send + Sync {
    async fn create_verification_code(&self, code: &VerificationCode) -> Result<(), StorageError>;
    async fn get_latest_verification_code_by_email(
        &self,
        email: &str,
        purpose: &str,
    ) -> Result<VerificationCode, StorageError>;
    async fn increment_verification_attempts(&self, id: Uuid) -> Result<(), StorageError>;
    async fn delete_verification_code(&self, id: Uuid) -> Result<(), StorageError>;
    async fn check_and_increment_send_rate(
        &self,
        email: &str,
        max_sends: i32,
        window: Duration,
        identity_hash_key: &[u8],
    ) -> Result<(), StorageError>;
}

#[async_trait]
pub trait RateLimitStorage: Send + Sync {
    /// Returns `Ok(())` if allowed, `Err(LoginRateLimited)` if locked out.
    async fn check_login_allowed(&self, issuer: &str, username: &str) -> Result<(), StorageError>;
    /// Returns the lockout duration if a new lockout was applied, or `None`.
    async fn record_failed_login(
        &self,
        issuer: &str,
        username: &str,
        max_attempts: i32,
        window: Duration,
    ) -> Result<Option<Duration>, StorageError>;
    async fn clear_login_attempts(&self, issuer: &str, username: &str) -> Result<(), StorageError>;
    async fn check_and_increment_recovery_rate(
        &self,
        email: &str,
        max_requests: i32,
        window: Duration,
        identity_hash_key: &[u8],
    ) -> Result<(), StorageError>;
}

#[async_trait]
pub trait VerificationTokenStorage: Send + Sync {
    /// Marks a verification token JTI as used. Returns `Err(VerificationTokenUsed)` on reuse.
    async fn consume_verification_token(
        &self,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), StorageError>;
}

#[async_trait]
pub trait CleanupStorage: Send + Sync {
    async fn cleanup_expired_states(&self) -> Result<(), StorageError>;
    async fn cleanup_expired_oauth_codes(&self) -> Result<(), StorageError>;
    async fn cleanup_expired_refresh_tokens(&self) -> Result<(), StorageError>;
    async fn cleanup_used_refresh_tokens(&self, older_than: Duration) -> Result<(), StorageError>;
    async fn cleanup_expired_verification_codes(&self) -> Result<(), StorageError>;
    async fn cleanup_expired_verification_tokens(&self) -> Result<(), StorageError>;
}

/// Atomic composite operations that span multiple domain entities.
#[async_trait]
pub trait CompositeStorage: Send + Sync {
    /// Update OPAQUE registration + root key in one transaction.
    async fn update_registration_and_root_key(
        &self,
        account_id: Uuid,
        opaque_record: &[u8],
        wrapped_root_key: &[u8],
    ) -> Result<(), StorageError>;
    /// Atomic root key rotation: update root key + batch update grant keys + update recovery blob.
    async fn rotate_root_key(
        &self,
        account_id: Uuid,
        wrapped_root_key: &[u8],
        grant_updates: &[GrantKeyUpdate],
        recovery_blob: &[u8],
    ) -> Result<(), StorageError>;
}

// ─── Supertrait ───────────────────────────────────────────────────────────────

/// Convenience supertrait combining all storage traits.
pub trait Storage:
    AccountStorage
    + RootKeyStorage
    + RegistrationStateStorage
    + LoginStateStorage
    + JwtKeyStorage
    + UserKeyStorage
    + OAuthClientStorage
    + OAuthCodeStorage
    + OAuthGrantStorage
    + OAuthRefreshTokenStorage
    + OAuthSigningKeyStorage
    + RecoveryStorage
    + VerificationStorage
    + VerificationTokenStorage
    + RateLimitStorage
    + CleanupStorage
    + CompositeStorage
{
}

impl<T> Storage for T where
    T: AccountStorage
        + RootKeyStorage
        + RegistrationStateStorage
        + LoginStateStorage
        + JwtKeyStorage
        + UserKeyStorage
        + OAuthClientStorage
        + OAuthCodeStorage
        + OAuthGrantStorage
        + OAuthRefreshTokenStorage
        + OAuthSigningKeyStorage
        + RecoveryStorage
        + VerificationStorage
        + VerificationTokenStorage
        + RateLimitStorage
        + CleanupStorage
        + CompositeStorage
{
}
