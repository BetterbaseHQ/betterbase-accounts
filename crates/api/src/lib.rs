#![forbid(unsafe_code)]
//! HTTP API layer: Axum router and all request handlers.

pub mod error;
pub mod handlers;
pub mod state;
pub mod verification;

use axum::{
    http::{header, HeaderValue, Method},
    middleware,
    response::Response,
    routing::{delete, get, post, put},
    Router,
};
use tower_http::{
    cors::{Any, CorsLayer},
    limit::RequestBodyLimitLayer,
};

use handlers::{
    auth, discovery, keys, oauth, password_change, recovery, rootkey, verification as vh, webui,
};
use state::AppState;

const MAX_BODY_SIZE: usize = 64 * 1024; // 64 KB

/// Build the complete Axum router with all routes.
pub fn build_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE, header::ACCEPT])
        .allow_origin(Any);

    Router::new()
        // Health
        .route("/health", get(health))
        // Verification
        .route(
            "/v1/accounts/verify/send",
            post(vh::handle_send_verification_code),
        )
        .route(
            "/v1/accounts/verify/confirm",
            post(vh::handle_confirm_verification_code),
        )
        // Registration
        .route(
            "/v1/accounts/password/init",
            post(auth::handle_password_init),
        )
        .route(
            "/v1/accounts/password/finalize",
            post(auth::handle_password_finalize),
        )
        // Login
        .route("/v1/auth/login/init", post(auth::handle_login_init))
        .route("/v1/auth/login/finalize", post(auth::handle_login_finalize))
        // Auth-gated account ops
        .route("/v1/auth/validate", get(auth::handle_validate))
        .route("/v1/accounts", delete(auth::handle_delete_account))
        // User keys
        .route("/v1/keys", get(keys::handle_list_keys))
        .route("/v1/keys/{service}/{key_name}", put(keys::handle_store_key))
        .route("/v1/keys/{service}/{key_name}", get(keys::handle_get_key))
        // Root key
        .route("/v1/accounts/root-key", get(rootkey::handle_get_root_key))
        .route("/v1/accounts/root-key", put(rootkey::handle_set_root_key))
        .route(
            "/v1/accounts/grants/wrapped-keys",
            get(rootkey::handle_get_grant_wrapped_keys),
        )
        .route(
            "/v1/accounts/grants/wrapped-keys",
            put(rootkey::handle_update_grant_wrapped_keys),
        )
        .route(
            "/v1/accounts/rotate-root-key",
            post(rootkey::handle_rotate_root_key),
        )
        // Password change
        .route(
            "/v1/accounts/password/change/init",
            post(password_change::handle_password_change_init),
        )
        .route(
            "/v1/accounts/password/change/verify",
            post(password_change::handle_password_change_verify),
        )
        .route(
            "/v1/accounts/password/change/complete",
            post(password_change::handle_password_change_complete),
        )
        // Recovery
        .route(
            "/v1/accounts/recovery-blob",
            post(recovery::handle_store_recovery_blob),
        )
        .route(
            "/v1/accounts/recovery-blob/fetch",
            post(recovery::handle_get_recovery_blob),
        )
        .route(
            "/v1/accounts/recover/init",
            post(recovery::handle_recover_init),
        )
        .route(
            "/v1/accounts/recover/finalize",
            post(recovery::handle_recover_finalize),
        )
        // OAuth
        .route("/oauth/authorize", get(oauth::handle_oauth_authorize))
        .route("/oauth/consent", post(oauth::handle_oauth_consent))
        .route("/oauth/token", post(oauth::handle_oauth_token))
        .route("/oauth/userinfo", get(oauth::handle_oauth_userinfo))
        .route("/oauth/mailbox", post(oauth::handle_register_mailbox))
        .route("/oauth/grant-keypair", get(oauth::handle_grant_keypair))
        // JWKS
        .route("/.well-known/jwks.json", get(oauth::handle_jwks))
        // User public key lookups
        .route(
            "/v1/users/{username}/keys/{client_id}",
            get(oauth::handle_user_public_key),
        )
        .route(
            "/v1/users/by-thumbprint/{thumbprint}",
            get(oauth::handle_user_by_thumbprint),
        )
        // Discovery
        .route(
            "/.well-known/less-platform",
            get(discovery::handle_server_metadata),
        )
        .route("/.well-known/webfinger", get(discovery::handle_webfinger))
        // SPA catch-all
        .fallback(webui::handle_spa)
        // Middleware (applied in reverse order)
        .layer(middleware::map_response(set_protocol_version_header))
        .layer(RequestBodyLimitLayer::new(MAX_BODY_SIZE))
        .layer(cors)
        .with_state(state)
}

/// Add `X-Protocol-Version: 1` to every response (immutable v1 contract).
async fn set_protocol_version_header(mut resp: Response) -> Response {
    resp.headers_mut()
        .insert("x-protocol-version", HeaderValue::from_static("1"));
    resp
}

async fn health() -> &'static str {
    "ok"
}
