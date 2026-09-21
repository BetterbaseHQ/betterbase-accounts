//! Auth middleware: extracts and validates Bearer auth tokens.

use axum::{
    body::Body,
    extract::State,
    http::{header::AUTHORIZATION, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use uuid::Uuid;

use crate::jwt::JwtService;

/// Key for storing the authenticated account ID in request extensions.
#[derive(Clone, Debug)]
pub struct AuthContext {
    pub account_id: Uuid,
}

/// Extract the Bearer token from an Authorization header.
pub fn extract_bearer_token(header: &str) -> Option<&str> {
    header.strip_prefix("Bearer ")
}

// The unfenced `auth_middleware` was removed (AUD-011 review): it
// validated auth JWTs without the credentials_version check and was
// wired into no router — wiring it up later would silently reintroduce
// the vulnerability extract_auth now prevents. Route handlers use
// `crate::handlers::auth::extract_auth`.

pub async fn oauth_auth_middleware(
    State(jwt): State<Arc<JwtService>>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    let auth_header = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let token = match auth_header.and_then(extract_bearer_token) {
        Some(t) => t,
        None => {
            return (StatusCode::UNAUTHORIZED, "authorization required").into_response();
        }
    };

    let claims = match jwt.validate_oauth_access_token(token) {
        Ok(c) => c,
        Err(e) => {
            let msg = if matches!(e, crate::jwt::JwtError::TokenExpired) {
                "token expired"
            } else {
                "invalid token"
            };
            return (StatusCode::UNAUTHORIZED, msg).into_response();
        }
    };

    req.extensions_mut().insert(claims);
    next.run(req).await
}
