//! Account recovery: store/fetch recovery blob, and OPAQUE re-registration.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use base64::{
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL},
    Engine as _,
};
use betterbase_accounts_auth::{
    jwt::{JwtError, StatePurpose},
    opaque::OpaqueError,
};
use betterbase_accounts_core::email::validate_email;
use betterbase_accounts_core::protocol::*;
use betterbase_accounts_storage::{
    AccountStorage, CompositeStorage, RateLimitStorage, RecoveryStorage, RegistrationState,
    RegistrationStateStorage, StorageError, VerificationTokenStorage,
};
use std::time::Duration;
use uuid::Uuid;

use crate::{error::ApiError, handlers::auth::extract_auth, state::AppState};

const RECOVERY_MAX_REQUESTS: i32 = 5;
const RECOVERY_WINDOW: Duration = Duration::from_secs(3600);

pub(super) fn validate_recovery_blob(blob: &str) -> Result<(), ApiError> {
    // v2 encrypts a 32-byte root key with AES-GCM: a 12-byte nonce and
    // 48-byte ciphertext (including the 16-byte authentication tag).
    let blob_val: serde_json::Value =
        serde_json::from_str(blob).map_err(|_| ApiError::bad_request("blob must be valid JSON"))?;
    if blob_val.get("version").and_then(|v| v.as_u64()) != Some(2)
        || blob_val.get("alg").and_then(|v| v.as_str()) != Some("A256GCM")
        || !blob_val
            .get("iv")
            .and_then(|v| v.as_str())
            .and_then(|v| B64URL.decode(v).ok())
            .is_some_and(|v| v.len() == 12)
        || !blob_val
            .get("ciphertext")
            .and_then(|v| v.as_str())
            .and_then(|v| B64URL.decode(v).ok())
            .is_some_and(|v| v.len() == 48)
    {
        return Err(ApiError::bad_request("invalid recovery blob format"));
    }
    Ok(())
}

/// POST /v1/accounts/recovery-blob (auth-gated)
pub async fn handle_store_recovery_blob(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<StoreRecoveryBlobRequest>,
) -> Result<StatusCode, ApiError> {
    let auth_ctx = extract_auth(&state, &headers).await?;

    validate_recovery_blob(&req.blob)?;

    state
        .storage
        .store_recovery_blob(auth_ctx.account_id, req.blob.as_bytes())
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// POST /v1/accounts/recovery-blob/fetch
///
/// Authorization: Bearer <verification_token with purpose=recovery>
pub async fn handle_get_recovery_blob(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<GetRecoveryBlobResponse>, ApiError> {
    // Extract verification token from Authorization header
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::not_found("not found"))?;

    let claims = state
        .jwt
        .validate_verification_token(token)
        .map_err(|_| ApiError::not_found("not found"))?;

    if claims.purpose != betterbase_accounts_core::purpose::RECOVERY {
        return Err(ApiError::not_found("not found"));
    }

    // AUD-007: this read does NOT consume the one-use JTI. The recovery
    // page fetches the blob before calling recover/init, and the client
    // may need several decrypt attempts (wrong phrase) — single use is
    // enforced at the state-changing boundary (recover/init). The blob
    // itself is encrypted; re-reading it while the token is unused
    // discloses nothing beyond what the token already authorizes.

    // Fetch blob by email — uniform 404 on all failures
    let (blob_bytes, root_key_version) = state
        .storage
        .get_recovery_blob_with_root_version_by_email(&state.config.issuer, &claims.email)
        .await
        .map_err(|_| ApiError::not_found("not found"))?;

    let blob = String::from_utf8(blob_bytes).map_err(|_| ApiError::not_found("not found"))?;

    Ok(Json(GetRecoveryBlobResponse {
        blob,
        root_key_version,
    }))
}

/// POST /v1/accounts/recover/init
pub async fn handle_recover_init(
    State(state): State<AppState>,
    Json(req): Json<RecoverInitRequest>,
) -> Result<Json<RecoverInitResponse>, ApiError> {
    // CAP check
    state
        .cap
        .verify(&req.cap_token)
        .await
        .map_err(|_| ApiError::bad_request("invalid CAP token"))?;

    // Validate + consume verification token
    let v_claims = state
        .jwt
        .validate_verification_token(&req.verification_token)
        .map_err(|e| match e {
            JwtError::TokenExpired => ApiError::bad_request("verification token expired"),
            _ => ApiError::bad_request("invalid verification token"),
        })?;

    if v_claims.purpose != betterbase_accounts_core::purpose::RECOVERY {
        return Err(ApiError::bad_request("invalid verification token purpose"));
    }

    // The verified token email is authoritative (AUD-003): reject any request
    // email that does not match it, and resolve the account from the verified
    // identity. Otherwise a token for one email could recover an unrelated
    // account supplied in the request body.
    validate_email(&req.email).map_err(|_| ApiError::bad_request("invalid email"))?;
    let canonical_email = betterbase_accounts_core::email::canonicalize_email(&v_claims.email);
    let requested_email = betterbase_accounts_core::email::canonicalize_email(&req.email);
    if requested_email != canonical_email {
        return Err(ApiError::bad_request(
            "verification token is not valid for this email",
        ));
    }

    // Reject a blob decrypted before another session rotated the root, before
    // consuming the email proof so the user can fetch the current blob and retry.
    let account = state
        .storage
        .get_account_by_email(&state.config.issuer, &canonical_email)
        .await?;
    if req
        .expected_root_version
        .is_some_and(|version| version != account.root_key_version)
    {
        return Err(StorageError::RootKeyVersionConflict.into());
    }

    let jti_exp =
        chrono::DateTime::from_timestamp(v_claims.exp, 0).unwrap_or_else(chrono::Utc::now);
    state
        .storage
        .consume_verification_token(&v_claims.jti, jti_exp)
        .await
        .map_err(|e| match e {
            StorageError::VerificationTokenUsed => {
                ApiError::bad_request("verification token already used")
            }
            _ => ApiError::from(e),
        })?;

    // Recovery rate limit
    state
        .storage
        .check_and_increment_recovery_rate(
            &canonical_email,
            RECOVERY_MAX_REQUESTS,
            RECOVERY_WINDOW,
            &state.identity_hash_key,
        )
        .await?;

    // Decode OPAQUE request
    let opaque_bytes = B64
        .decode(&req.opaque_request)
        .map_err(|_| ApiError::bad_request("invalid opaque_request encoding"))?;

    let credential_id = account.id.as_bytes().to_vec();
    let result = state
        .opaque
        .registration_start(&opaque_bytes, &credential_id)
        .map_err(|e| match e {
            OpaqueError::InvalidRequest => ApiError::bad_request("invalid OPAQUE request"),
            _ => {
                tracing::error!("OPAQUE registration start error: {e}");
                ApiError::internal()
            }
        })?;

    let state_id = Uuid::new_v4();
    let now = chrono::Utc::now();
    let reg_state = RegistrationState {
        root_key_version: account.root_key_version,
        id: state_id,
        account_id: account.id,
        username: account.username.clone(),
        created_at: now,
        expires_at: now + chrono::Duration::seconds(60),
    };
    state.storage.create_registration_state(&reg_state).await?;

    let state_token = state
        .jwt
        .create_state_token(
            &state_id.to_string(),
            StatePurpose::Recovery,
            account.credentials_version,
        )
        .map_err(|_| ApiError::internal())?;

    Ok(Json(RecoverInitResponse {
        opaque_response: B64.encode(&result.response),
        state_token,
        user_id: account.id.to_string(),
    }))
}

/// POST /v1/accounts/recover/finalize
pub async fn handle_recover_finalize(
    State(state): State<AppState>,
    Json(req): Json<RecoverFinalizeRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    let state_claims = state
        .jwt
        .validate_state_token(&req.state_token, StatePurpose::Recovery)
        .map_err(ApiError::from)?;
    let state_id = Uuid::parse_str(&state_claims.sub)
        .map_err(|_| ApiError::bad_request("invalid state token"))?;

    // Atomically consume registration state (prevents replay)
    let reg_state = state.storage.consume_registration_state(state_id).await?;

    let opaque_record = B64
        .decode(&req.opaque_record)
        .map_err(|_| ApiError::bad_request("invalid opaque_record encoding"))?;

    let opaque_record_final =
        state
            .opaque
            .registration_finish(&opaque_record)
            .map_err(|e| match e {
                OpaqueError::InvalidRecord => ApiError::bad_request("invalid OPAQUE record"),
                _ => {
                    tracing::error!("OPAQUE registration finish error: {e}");
                    ApiError::internal()
                }
            })?;

    let new_key = if req.wrapped_root_key.is_empty() {
        None
    } else {
        let key = B64
            .decode(&req.wrapped_root_key)
            .map_err(|_| ApiError::bad_request("invalid wrapped_root_key encoding"))?;
        if key.len() != 41 {
            return Err(ApiError::bad_request("wrapped_root_key must be 41 bytes"));
        }
        Some(key)
    };

    if !req.new_blob.is_empty() {
        validate_recovery_blob(&req.new_blob)?;
    }

    // All recovery writes and session revocation commit together, including
    // legacy requests that leave the wrapped root key unchanged.
    let new_version = state
        .storage
        .update_credentials_and_revoke_sessions(
            reg_state.account_id,
            &opaque_record_final,
            new_key.as_deref(),
            state_claims.cred_ver,
            reg_state.root_key_version,
            if req.new_blob.is_empty() {
                None
            } else {
                Some(req.new_blob.as_bytes())
            },
        )
        .await?;
    let auth_token = state
        .jwt
        .create_auth_token(&reg_state.account_id.to_string(), new_version)
        .map_err(|_| ApiError::internal())?;

    Ok(Json(AuthResponse {
        auth_token,
        user_id: reg_state.account_id.to_string(),
    }))
}

#[cfg(test)]
#[path = "recovery_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "recovery_session_revocation_tests.rs"]
mod session_revocation_tests;

#[cfg(test)]
#[path = "recovery_blob_fetch_tests.rs"]
mod blob_fetch_tests;
