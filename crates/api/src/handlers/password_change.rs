//! Three-step authenticated password change flow.

use axum::{extract::State, http::HeaderMap, Json};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use less_accounts_auth::opaque::OpaqueError;
use less_accounts_core::protocol::*;
use less_accounts_storage::{
    AccountStorage, CompositeStorage, LoginState, LoginStateStorage, RegistrationState,
    RegistrationStateStorage,
};
use uuid::Uuid;

use crate::{error::ApiError, handlers::auth::extract_auth, state::AppState};

/// POST /v1/accounts/password/change/init
///
/// Start password change by verifying old password via OPAQUE login.
pub async fn handle_password_change_init(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<PasswordChangeInitRequest>,
) -> Result<Json<PasswordChangeInitResponse>, ApiError> {
    let auth_ctx = extract_auth(&state, &headers)?;

    // Load account to get existing OPAQUE registration
    let account = state.storage.get_account_by_id(auth_ctx.account_id).await?;
    let password_file = account
        .opaque_registration
        .ok_or_else(|| ApiError::bad_request("account not registered"))?;

    let ke1 = B64
        .decode(&req.opaque_ke1)
        .map_err(|_| ApiError::bad_request("invalid opaque_ke1 encoding"))?;

    let credential_id = account.id.as_bytes().to_vec();
    let result = state
        .opaque
        .login_start(&ke1, Some(&password_file), &credential_id)
        .map_err(|e| match e {
            OpaqueError::InvalidKE1 => ApiError::bad_request("invalid OPAQUE KE1"),
            _ => {
                tracing::error!("OPAQUE login start error: {e}");
                ApiError::internal()
            }
        })?;

    let state_id = Uuid::new_v4();
    let now = chrono::Utc::now();
    let login_state = LoginState {
        id: state_id,
        account_id: Some(account.id),
        username: account.username,
        state: result.server_state,
        created_at: now,
        expires_at: now + chrono::Duration::seconds(60),
    };
    state.storage.create_login_state(&login_state).await?;

    let login_token = state
        .jwt
        .create_state_token(&state_id.to_string())
        .map_err(|_| ApiError::internal())?;

    Ok(Json(PasswordChangeInitResponse {
        opaque_ke2: B64.encode(&result.ke2),
        login_token,
    }))
}

/// POST /v1/accounts/password/change/verify
///
/// Verify old password (KE3) and start new OPAQUE registration.
pub async fn handle_password_change_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<PasswordChangeVerifyRequest>,
) -> Result<Json<PasswordChangeVerifyResponse>, ApiError> {
    let auth_ctx = extract_auth(&state, &headers)?;

    // Validate login token
    let state_id_str = state
        .jwt
        .validate_state_token(&req.login_token)
        .map_err(crate::error::ApiError::from)?;
    let state_id =
        Uuid::parse_str(&state_id_str).map_err(|_| ApiError::bad_request("invalid login token"))?;

    let login_state = state.storage.get_login_state(state_id).await?;

    // Verify this login state belongs to the authenticated account
    if login_state.account_id != Some(auth_ctx.account_id) {
        return Err(ApiError::forbidden(
            "login state does not belong to this account",
        ));
    }

    let ke3 = B64
        .decode(&req.opaque_ke3)
        .map_err(|_| ApiError::bad_request("invalid opaque_ke3 encoding"))?;

    // Verify old password
    state
        .opaque
        .login_finish(&ke3, &login_state.state)
        .map_err(|_| ApiError::unauthorized("old password verification failed"))?;

    let _ = state.storage.delete_login_state(state_id).await;

    // Start registration for new password
    let new_opaque_bytes = B64
        .decode(&req.opaque_request)
        .map_err(|_| ApiError::bad_request("invalid opaque_request encoding"))?;

    let credential_id = auth_ctx.account_id.as_bytes().to_vec();
    let reg_result = state
        .opaque
        .registration_start(&new_opaque_bytes, &credential_id)
        .map_err(|e| match e {
            OpaqueError::InvalidRequest => ApiError::bad_request("invalid OPAQUE request"),
            _ => {
                tracing::error!("OPAQUE registration start error: {e}");
                ApiError::internal()
            }
        })?;

    let new_state_id = Uuid::new_v4();
    let now = chrono::Utc::now();
    let reg_state = RegistrationState {
        id: new_state_id,
        account_id: auth_ctx.account_id,
        username: login_state.username,
        state: reg_result.response.clone(),
        created_at: now,
        expires_at: now + chrono::Duration::seconds(60),
    };
    state.storage.create_registration_state(&reg_state).await?;

    let new_state_token = state
        .jwt
        .create_state_token(&new_state_id.to_string())
        .map_err(|_| ApiError::internal())?;

    Ok(Json(PasswordChangeVerifyResponse {
        opaque_response: B64.encode(&reg_result.response),
        state_token: new_state_token,
    }))
}

/// POST /v1/accounts/password/change/complete
///
/// Finalize new password registration and update root key.
pub async fn handle_password_change_complete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<PasswordChangeCompleteRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    let auth_ctx = extract_auth(&state, &headers)?;

    let state_id_str = state
        .jwt
        .validate_state_token(&req.state_token)
        .map_err(crate::error::ApiError::from)?;
    let state_id =
        Uuid::parse_str(&state_id_str).map_err(|_| ApiError::bad_request("invalid state token"))?;

    let reg_state = state.storage.get_registration_state(state_id).await?;

    // Verify ownership
    if reg_state.account_id != auth_ctx.account_id {
        return Err(ApiError::forbidden("state does not belong to this account"));
    }

    let opaque_record = B64
        .decode(&req.opaque_record)
        .map_err(|_| ApiError::bad_request("invalid opaque_record encoding"))?;

    let wrapped_root_key = B64
        .decode(&req.wrapped_root_key)
        .map_err(|_| ApiError::bad_request("invalid wrapped_root_key encoding"))?;
    if wrapped_root_key.len() != 41 {
        return Err(ApiError::bad_request("wrapped_root_key must be 41 bytes"));
    }

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

    state
        .storage
        .update_registration_and_root_key(reg_state.account_id, &password_file, &wrapped_root_key)
        .await?;

    let _ = state.storage.delete_registration_state(state_id).await;

    let new_auth_token = state
        .jwt
        .create_auth_token(&reg_state.account_id.to_string())
        .map_err(|_| ApiError::internal())?;

    Ok(Json(AuthResponse {
        auth_token: new_auth_token,
        user_id: reg_state.account_id.to_string(),
    }))
}
