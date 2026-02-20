//! Account recovery: store/fetch recovery blob, and OPAQUE re-registration.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use less_accounts_auth::{jwt::JwtError, opaque::OpaqueError};
use less_accounts_core::protocol::*;
use less_accounts_storage::{
    AccountStorage, CompositeStorage, RateLimitStorage, RecoveryStorage, RegistrationState,
    RegistrationStateStorage, StorageError, VerificationTokenStorage,
};
use std::time::Duration;
use uuid::Uuid;

use crate::{error::ApiError, handlers::auth::extract_auth, state::AppState};

const RECOVERY_MAX_REQUESTS: i32 = 5;
const RECOVERY_WINDOW: Duration = Duration::from_secs(3600);

/// POST /v1/accounts/recovery-blob (auth-gated)
pub async fn handle_store_recovery_blob(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<StoreRecoveryBlobRequest>,
) -> Result<StatusCode, ApiError> {
    let auth_ctx = extract_auth(&state, &headers)?;

    // Validate blob JSON format (version=2, alg=A256GCM, iv, ciphertext)
    let blob_val: serde_json::Value = serde_json::from_str(&req.blob)
        .map_err(|_| ApiError::bad_request("blob must be valid JSON"))?;

    if blob_val.get("version").and_then(|v| v.as_u64()) != Some(2)
        || blob_val.get("alg").and_then(|v| v.as_str()) != Some("A256GCM")
        || blob_val.get("iv").is_none()
        || blob_val.get("ciphertext").is_none()
    {
        return Err(ApiError::bad_request("invalid recovery blob format"));
    }

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

    if claims.purpose != "recovery" {
        return Err(ApiError::not_found("not found"));
    }

    // Consume JTI
    let jti_exp = chrono::DateTime::from_timestamp(claims.exp, 0).unwrap_or_else(chrono::Utc::now);
    state
        .storage
        .consume_verification_token(&claims.jti, jti_exp)
        .await
        .map_err(|_| ApiError::not_found("not found"))?;

    // Fetch blob by email — uniform 404 on all failures
    let blob_bytes = state
        .storage
        .get_recovery_blob_by_email(&state.config.issuer, &claims.email)
        .await
        .map_err(|_| ApiError::not_found("not found"))?;

    let blob = String::from_utf8(blob_bytes).map_err(|_| ApiError::not_found("not found"))?;

    Ok(Json(GetRecoveryBlobResponse { blob }))
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

    if v_claims.purpose != "recovery" {
        return Err(ApiError::bad_request("invalid verification token purpose"));
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

    let canonical_email = less_accounts_core::email::canonicalize_email(&req.email);

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

    // Look up account
    let account = state
        .storage
        .get_account_by_email(&state.config.issuer, &canonical_email)
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
        id: state_id,
        account_id: account.id,
        username: account.username.clone(),
        state: result.response.clone(),
        created_at: now,
        expires_at: now + chrono::Duration::seconds(60),
    };
    state.storage.create_registration_state(&reg_state).await?;

    let state_token = state
        .jwt
        .create_state_token(&state_id.to_string())
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
    let state_id_str = state
        .jwt
        .validate_state_token(&req.state_token)
        .map_err(ApiError::from)?;
    let state_id =
        Uuid::parse_str(&state_id_str).map_err(|_| ApiError::bad_request("invalid state token"))?;

    let reg_state = state.storage.get_registration_state(state_id).await?;

    let opaque_record = B64
        .decode(&req.opaque_record)
        .map_err(|_| ApiError::bad_request("invalid opaque_record encoding"))?;

    let password_file = state
        .opaque
        .registration_finish(&opaque_record)
        .map_err(|e| match e {
            OpaqueError::InvalidRecord => ApiError::bad_request("invalid OPAQUE record"),
            _ => {
                tracing::error!("OPAQUE registration finish error: {e}");
                ApiError::internal()
            }
        })?;

    // Optional new wrapped root key
    if !req.wrapped_root_key.is_empty() {
        let new_key = B64
            .decode(&req.wrapped_root_key)
            .map_err(|_| ApiError::bad_request("invalid wrapped_root_key encoding"))?;
        if new_key.len() != 41 {
            return Err(ApiError::bad_request("wrapped_root_key must be 41 bytes"));
        }
        state
            .storage
            .update_registration_and_root_key(reg_state.account_id, &password_file, &new_key)
            .await?;
    } else {
        state
            .storage
            .update_registration(reg_state.account_id, &password_file)
            .await?;
    }

    // Optional new recovery blob (best-effort)
    if !req.new_blob.is_empty() {
        let _ = state
            .storage
            .store_recovery_blob(reg_state.account_id, req.new_blob.as_bytes())
            .await;
    }

    let _ = state.storage.delete_registration_state(state_id).await;

    let auth_token = state
        .jwt
        .create_auth_token(&reg_state.account_id.to_string())
        .map_err(|_| ApiError::internal())?;

    Ok(Json(AuthResponse {
        auth_token,
        user_id: reg_state.account_id.to_string(),
    }))
}
