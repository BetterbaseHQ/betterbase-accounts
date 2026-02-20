//! Email verification code send and confirm.

use axum::{extract::State, http::StatusCode, Json};
use less_accounts_core::{
    email::{canonicalize_email, validate_email},
    protocol::*,
    username::validate_username,
};
use less_accounts_storage::{AccountStorage, StorageError};

use crate::{error::ApiError, state::AppState, verification};

/// POST /v1/accounts/verify/send
pub async fn handle_send_verification_code(
    State(state): State<AppState>,
    Json(req): Json<SendVerificationCodeRequest>,
) -> Result<StatusCode, ApiError> {
    // CAP check
    state
        .cap
        .verify(&req.cap_token)
        .await
        .map_err(|_| ApiError::bad_request("invalid CAP token"))?;

    validate_email(&req.email).map_err(|_| ApiError::bad_request("invalid email"))?;

    match req.purpose.as_str() {
        "registration" => {
            validate_username(&req.username)
                .map_err(|_| ApiError::bad_request("invalid username"))?;

            let canonical_email = canonicalize_email(&req.email);
            let canonical_username =
                less_accounts_core::username::canonicalize_username(&req.username);

            // Check availability — return 204 without sending if not available
            // (the error will surface at registration time)
            let by_email = state
                .storage
                .get_account_by_email(&state.config.issuer, &canonical_email)
                .await;
            let by_username = state
                .storage
                .get_account_by_username(&state.config.issuer, &canonical_username)
                .await;

            // If there's an existing registered account with that email, send
            // an "already registered" notice instead of a code.
            // For MVP: just proceed with sending the code regardless.
            // Conflict will be caught at finalize time.
            let _ = by_email;
            let _ = by_username;

            verification::send_code(&state, &canonical_email, "registration")
                .await
                .map_err(|e| match e {
                    StorageError::VerificationRateLimited => {
                        ApiError::too_many_requests("too many verification emails sent")
                    }
                    _ => ApiError::from(e),
                })?;
        }
        "recovery" => {
            let canonical_email = canonicalize_email(&req.email);

            // Anti-enumeration: silently succeed if no account
            let result = verification::send_code(&state, &canonical_email, "recovery").await;
            match result {
                Ok(()) => {}
                Err(StorageError::VerificationRateLimited) => {
                    return Err(ApiError::too_many_requests(
                        "too many verification emails sent",
                    ));
                }
                Err(_) => {
                    // Silently succeed even on internal errors (anti-enumeration)
                }
            }
        }
        _ => return Err(ApiError::bad_request("invalid purpose")),
    }

    Ok(StatusCode::NO_CONTENT)
}

/// POST /v1/accounts/verify/confirm
pub async fn handle_confirm_verification_code(
    State(state): State<AppState>,
    Json(req): Json<ConfirmVerificationCodeRequest>,
) -> Result<Json<ConfirmVerificationCodeResponse>, ApiError> {
    validate_email(&req.email).map_err(|_| ApiError::bad_request("invalid email"))?;

    // Code must be 6 digits
    if req.code.len() != 6 || !req.code.chars().all(|c| c.is_ascii_digit()) {
        return Err(ApiError::bad_request("invalid verification code format"));
    }

    match req.purpose.as_str() {
        "registration" | "recovery" => {}
        _ => return Err(ApiError::bad_request("invalid purpose")),
    }

    let canonical_email = canonicalize_email(&req.email);

    let _code_id = verification::verify_code(&state, &canonical_email, &req.purpose, &req.code)
        .await
        .map_err(|e| match e {
            StorageError::VerificationCodeNotFound
            | StorageError::VerificationCodeExpired
            | StorageError::VerificationMaxAttempts => {
                ApiError::bad_request("invalid verification code")
            }
            _ => ApiError::from(e),
        })?;

    let verification_token = state
        .jwt
        .create_verification_token(&canonical_email, &req.purpose)
        .map_err(|_| ApiError::internal())?;

    Ok(Json(ConfirmVerificationCodeResponse { verification_token }))
}
