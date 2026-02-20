//! OPAQUE password registration, login, validate, and account deletion.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use std::time::Duration;

use less_accounts_auth::{jwt::JwtError, middleware::AuthContext, opaque::OpaqueError};
use less_accounts_core::{email::validate_email, protocol::*, username::validate_username};
use less_accounts_storage::{
    AccountStorage, LoginState, LoginStateStorage, RateLimitStorage, RegistrationState,
    RegistrationStateStorage, StorageError, VerificationTokenStorage,
};
use uuid::Uuid;

use crate::{error::ApiError, state::AppState};

const LOGIN_MAX_ATTEMPTS: i32 = 8;
const LOGIN_WINDOW: Duration = Duration::from_secs(15 * 60);

/// POST /v1/accounts/password/init
pub async fn handle_password_init(
    State(state): State<AppState>,
    Json(req): Json<PasswordInitRequest>,
) -> Result<Json<PasswordInitResponse>, ApiError> {
    // CAP check
    state
        .cap
        .verify(&req.cap_token)
        .await
        .map_err(|_| ApiError::bad_request("invalid CAP token"))?;

    // Validate inputs
    validate_email(&req.email).map_err(|_| ApiError::bad_request("invalid email"))?;
    validate_username(&req.username).map_err(|_| ApiError::bad_request("invalid username"))?;

    // Validate + consume verification token
    let v_claims = state
        .jwt
        .validate_verification_token(&req.verification_token)
        .map_err(|e| match e {
            JwtError::TokenExpired => ApiError::unauthorized("verification token expired"),
            _ => ApiError::unauthorized("invalid verification token"),
        })?;

    if v_claims.purpose != "registration"
        || v_claims.email.to_lowercase() != req.email.to_lowercase()
    {
        return Err(ApiError::unauthorized("invalid verification token"));
    }

    // Consume JTI (one-time-use)
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

    // Decode OPAQUE request
    let opaque_bytes = B64
        .decode(&req.opaque_request)
        .map_err(|_| ApiError::bad_request("invalid opaque_request encoding"))?;

    // Get or create account (pre-creates if not exists)
    let canonical_email = less_accounts_core::email::canonicalize_email(&req.email);
    let canonical_username = less_accounts_core::username::canonicalize_username(&req.username);
    let account = state
        .storage
        .get_or_create_account(&state.config.issuer, &canonical_username, &canonical_email)
        .await?;

    // OPAQUE registration start
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

    // Create registration state
    let state_id = Uuid::new_v4();
    let now = chrono::Utc::now();
    let reg_state = RegistrationState {
        id: state_id,
        account_id: account.id,
        username: canonical_username,
        state: result.response.clone(),
        created_at: now,
        expires_at: now + chrono::Duration::seconds(60),
    };
    state.storage.create_registration_state(&reg_state).await?;

    let state_token = state
        .jwt
        .create_state_token(&state_id.to_string())
        .map_err(|_| ApiError::internal())?;

    Ok(Json(PasswordInitResponse {
        opaque_response: B64.encode(&result.response),
        state_token,
        user_id: account.id.to_string(),
    }))
}

/// POST /v1/accounts/password/finalize
pub async fn handle_password_finalize(
    State(state): State<AppState>,
    Json(req): Json<PasswordFinalizeRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    // Validate state token
    let state_id_str = state
        .jwt
        .validate_state_token(&req.state_token)
        .map_err(ApiError::from)?;
    let state_id =
        Uuid::parse_str(&state_id_str).map_err(|_| ApiError::bad_request("invalid state token"))?;

    // Load registration state
    let reg_state = state.storage.get_registration_state(state_id).await?;

    // Decode OPAQUE record
    let opaque_record = B64
        .decode(&req.opaque_record)
        .map_err(|_| ApiError::bad_request("invalid opaque_record encoding"))?;

    // Decode and validate wrapped root key (must be 41 bytes)
    let wrapped_root_key = B64
        .decode(&req.wrapped_root_key)
        .map_err(|_| ApiError::bad_request("invalid wrapped_root_key encoding"))?;
    if wrapped_root_key.len() != 41 {
        return Err(ApiError::bad_request("wrapped_root_key must be 41 bytes"));
    }

    // OPAQUE finalize
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

    // Persist + delete state
    state
        .storage
        .finalize_registration_with_root_key(
            reg_state.account_id,
            &password_file,
            &wrapped_root_key,
        )
        .await?;
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

/// POST /v1/auth/login/init
pub async fn handle_login_init(
    State(state): State<AppState>,
    Json(req): Json<LoginInitRequest>,
) -> Result<Json<LoginInitResponse>, ApiError> {
    // CAP check
    state
        .cap
        .verify(&req.cap_token)
        .await
        .map_err(|_| ApiError::bad_request("invalid CAP token"))?;

    validate_username(&req.username).map_err(|_| ApiError::bad_request("invalid username"))?;

    let canonical_username = less_accounts_core::username::canonicalize_username(&req.username);

    // Check rate limit
    state
        .storage
        .check_login_allowed(&state.config.issuer, &canonical_username)
        .await?;

    // Decode KE1
    let ke1 = B64
        .decode(&req.opaque_ke1)
        .map_err(|_| ApiError::bad_request("invalid opaque_ke1 encoding"))?;

    // Look up account (use fake if not found)
    let account = state
        .storage
        .get_account_by_username(&state.config.issuer, &canonical_username)
        .await;

    let (account_id, password_file_bytes): (Option<Uuid>, Option<Vec<u8>>) = match account {
        Ok(a) => (Some(a.id), a.opaque_registration),
        Err(StorageError::AccountNotFound) => (None, None),
        Err(e) => return Err(ApiError::from(e)),
    };

    // Credential ID: account UUID bytes, or random for fake login
    let credential_id: Vec<u8> = match account_id {
        Some(id) => id.as_bytes().to_vec(),
        None => {
            // Deterministic fake ID derived from username (anti-enumeration)
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(format!("fake:{}", canonical_username).as_bytes());
            hash[..16].to_vec()
        }
    };

    let result = state
        .opaque
        .login_start(&ke1, password_file_bytes.as_deref(), &credential_id)
        .map_err(|e| match e {
            OpaqueError::InvalidKE1 => ApiError::bad_request("invalid OPAQUE KE1"),
            _ => {
                tracing::error!("OPAQUE login start error: {e}");
                ApiError::internal()
            }
        })?;

    // Store login state
    let state_id = Uuid::new_v4();
    let now = chrono::Utc::now();
    let login_state = LoginState {
        id: state_id,
        account_id,
        username: canonical_username,
        state: result.server_state,
        created_at: now,
        expires_at: now + chrono::Duration::seconds(60),
    };
    state.storage.create_login_state(&login_state).await?;

    let login_token = state
        .jwt
        .create_state_token(&state_id.to_string())
        .map_err(|_| ApiError::internal())?;

    Ok(Json(LoginInitResponse {
        opaque_ke2: B64.encode(&result.ke2),
        login_token,
    }))
}

/// POST /v1/auth/login/finalize
pub async fn handle_login_finalize(
    State(state): State<AppState>,
    Json(req): Json<LoginFinalizeRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    // Validate login token
    let state_id_str = state
        .jwt
        .validate_state_token(&req.login_token)
        .map_err(ApiError::from)?;
    let state_id =
        Uuid::parse_str(&state_id_str).map_err(|_| ApiError::bad_request("invalid login token"))?;

    // Load login state
    let login_state = state.storage.get_login_state(state_id).await?;

    // Decode KE3
    let ke3 = B64
        .decode(&req.opaque_ke3)
        .map_err(|_| ApiError::bad_request("invalid opaque_ke3 encoding"))?;

    // OPAQUE finalize
    let result = state.opaque.login_finish(&ke3, &login_state.state);
    let _ = state.storage.delete_login_state(state_id).await;

    match result {
        Ok(()) => {}
        Err(_) => {
            // Record failed attempt
            if let Some(_account_id) = login_state.account_id {
                let _ = state
                    .storage
                    .record_failed_login(
                        &state.config.issuer,
                        &login_state.username,
                        LOGIN_MAX_ATTEMPTS,
                        LOGIN_WINDOW,
                    )
                    .await;
            }
            return Err(ApiError::unauthorized("authentication failed"));
        }
    }

    // Clear login attempts on success
    let account_id = login_state
        .account_id
        .ok_or_else(|| ApiError::unauthorized("authentication failed"))?;
    let _ = state
        .storage
        .clear_login_attempts(&state.config.issuer, &login_state.username)
        .await;

    let auth_token = state
        .jwt
        .create_auth_token(&account_id.to_string())
        .map_err(|_| ApiError::internal())?;

    Ok(Json(AuthResponse {
        auth_token,
        user_id: account_id.to_string(),
    }))
}

/// GET /v1/auth/validate
pub async fn handle_validate(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ValidateResponse>, ApiError> {
    let auth_ctx = extract_auth(&state, &headers)?;
    let account = state.storage.get_account_by_id(auth_ctx.account_id).await?;

    let handle = less_accounts_core::identity::format_handle(
        &account.username,
        &state.config.identity_domain,
    );

    Ok(Json(ValidateResponse {
        id: account.id.to_string(),
        handle,
        email: account.email,
    }))
}

/// DELETE /v1/accounts
pub async fn handle_delete_account(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let auth_ctx = extract_auth(&state, &headers)?;
    state.storage.delete_account(auth_ctx.account_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

pub fn extract_auth(state: &AppState, headers: &HeaderMap) -> Result<AuthContext, ApiError> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::unauthorized("authorization required"))?;

    let claims = state.jwt.validate_auth_token(token).map_err(|e| match e {
        JwtError::TokenExpired => ApiError::unauthorized("token expired"),
        _ => ApiError::unauthorized("invalid token"),
    })?;

    let account_id =
        Uuid::parse_str(&claims.sub).map_err(|_| ApiError::unauthorized("invalid token"))?;

    Ok(AuthContext { account_id })
}

pub fn extract_oauth_token(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<less_accounts_auth::jwt::OAuthAccessClaims, ApiError> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::unauthorized("authorization required"))?;

    state
        .jwt
        .validate_oauth_access_token(token)
        .map_err(|e| match e {
            JwtError::TokenExpired => ApiError::unauthorized("token expired"),
            _ => ApiError::unauthorized("invalid token"),
        })
}
