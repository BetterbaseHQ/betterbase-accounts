//! Common API error type that maps to HTTP responses.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use betterbase_accounts_storage::StorageError;
use serde_json::json;

pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, msg)
    }

    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, msg)
    }

    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, msg)
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, msg)
    }

    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, msg)
    }

    pub fn too_many_requests(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, msg)
    }

    pub fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = json!({ "error": self.message });
        (self.status, axum::Json(body)).into_response()
    }
}

impl From<StorageError> for ApiError {
    fn from(e: StorageError) -> Self {
        match e {
            StorageError::AccountNotFound => ApiError::not_found("account not found"),
            StorageError::AccountExists => ApiError::conflict("account already exists"),
            StorageError::StateNotFound | StorageError::StateExpired => {
                ApiError::bad_request("invalid or expired state")
            }
            StorageError::KeyNotFound => ApiError::not_found("key not found"),
            StorageError::MaxKeysExceeded => ApiError::bad_request("maximum keys exceeded"),
            StorageError::OAuthClientNotFound => ApiError::not_found("client not found"),
            StorageError::OAuthCodeNotFound | StorageError::OAuthCodeExpired => {
                ApiError::bad_request("invalid or expired code")
            }
            StorageError::OAuthGrantNotFound => ApiError::not_found("grant not found"),
            StorageError::InvalidRedirectURI => ApiError::bad_request("invalid redirect URI"),
            StorageError::RefreshTokenNotFound | StorageError::RefreshTokenExpired => {
                ApiError::bad_request("invalid or expired refresh token")
            }
            StorageError::RefreshTokenReused { .. } => {
                ApiError::unauthorized("refresh token reuse detected")
            }
            StorageError::RecoveryBlobNotFound => ApiError::not_found("not found"),
            StorageError::VerificationCodeNotFound
            | StorageError::VerificationCodeExpired
            | StorageError::VerificationMaxAttempts => {
                ApiError::bad_request("invalid verification code")
            }
            StorageError::VerificationRateLimited => {
                ApiError::too_many_requests("too many verification emails sent")
            }
            StorageError::LoginRateLimited => {
                ApiError::too_many_requests("too many failed login attempts")
            }
            StorageError::RecoveryRateLimited => {
                ApiError::too_many_requests("too many recovery requests")
            }
            StorageError::WrappedRootKeyNotFound => {
                ApiError::not_found("wrapped root key not found")
            }
            StorageError::VerificationTokenUsed => {
                ApiError::bad_request("verification token already used")
            }
            StorageError::Database(e) => {
                tracing::error!("database error: {e}");
                ApiError::internal()
            }
            StorageError::Internal(msg) => {
                tracing::error!("storage internal error: {msg}");
                ApiError::internal()
            }
        }
    }
}

impl From<betterbase_accounts_auth::jwt::JwtError> for ApiError {
    fn from(e: betterbase_accounts_auth::jwt::JwtError) -> Self {
        use betterbase_accounts_auth::jwt::JwtError;
        match e {
            JwtError::TokenExpired => ApiError::unauthorized("token expired"),
            JwtError::InvalidToken | JwtError::KeyNotFound => {
                ApiError::unauthorized("invalid token")
            }
            JwtError::Internal(msg) => {
                tracing::error!("JWT internal error: {msg}");
                ApiError::internal()
            }
        }
    }
}
