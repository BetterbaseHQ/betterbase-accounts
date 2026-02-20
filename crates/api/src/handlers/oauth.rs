//! OAuth 2.0 + PKCE handlers.
//!
//! Implements: authorize, consent, token (code exchange + refresh), userinfo,
//! JWKS, mailbox registration, grant keypair, user public key lookup.

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use base64::{
    engine::general_purpose::STANDARD as B64, engine::general_purpose::URL_SAFE_NO_PAD as B64URL,
    Engine as _,
};
use p256::elliptic_curve::sec1::{FromEncodedPoint as _, ToEncodedPoint as _};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use less_accounts_auth::es256::Jwks;
use less_accounts_auth::jwt::{OAuthAccessClaims, OAuthStateClaims};
use less_accounts_core::{
    identity::{compute_did_key, format_handle, personal_space_id},
    protocol::*,
};
use less_accounts_storage::{
    AccountStorage, OAuthClient, OAuthClientStorage, OAuthCode, OAuthCodeStorage, OAuthGrant,
    OAuthGrantStorage, OAuthRefreshToken, OAuthRefreshTokenStorage, OAuthSigningKeyStorage,
    StorageError,
};
use subtle::ConstantTimeEq as _;

use crate::{
    error::ApiError,
    handlers::auth::{extract_auth, extract_oauth_token},
    state::AppState,
};

const WRAPPED_SCOPED_KEY_SIZE: usize = 41;
const MAX_KEYPAIR_BLOB_SIZE: usize = 1024;
const MAILBOX_ID_LENGTH: usize = 64;
const OAUTH_CODE_EXPIRY_SECS: i64 = 600; // 10 minutes
const REFRESH_TOKEN_EXPIRY_SECS: i64 = 30 * 24 * 3600; // 30 days

/// OIDC scopes always allowed
const OIDC_SCOPES: &[&str] = &["openid", "profile", "email", "address", "phone"];
/// Capability scopes gated by OAuth client config
const CAPABILITY_SCOPES: &[&str] = &["sync", "files", "keys", "inference"];

// ─── Authorize ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AuthorizeQuery {
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub keys_jwk: Option<String>,
    pub response_type: Option<String>,
}

/// GET /oauth/authorize
pub async fn handle_oauth_authorize(
    State(state): State<AppState>,
    Query(q): Query<AuthorizeQuery>,
) -> Response {
    let client_id_str = match &q.client_id {
        Some(s) => s.clone(),
        None => return oauth_error_redirect(None, None, "invalid_request", "missing client_id"),
    };

    let client_id = match Uuid::parse_str(&client_id_str) {
        Ok(id) => id,
        Err(_) => return oauth_error_redirect(None, None, "invalid_request", "invalid client_id"),
    };

    let redirect_uri = match &q.redirect_uri {
        Some(s) => s.clone(),
        None => return oauth_error_redirect(None, None, "invalid_request", "missing redirect_uri"),
    };

    // Load client and validate redirect URI
    let client = match state.storage.get_oauth_client(client_id).await {
        Ok(c) => c,
        Err(_) => return oauth_error_redirect(None, None, "invalid_client", "unknown client"),
    };

    if !client.redirect_uris.iter().any(|u| u == &redirect_uri) {
        return oauth_error_redirect(None, None, "invalid_request", "invalid redirect_uri");
    }

    let client_state = match q.state.clone() {
        Some(s) if !s.is_empty() => s,
        _ => {
            return oauth_error_redirect(
                Some(&redirect_uri),
                None,
                "invalid_request",
                "state parameter required",
            )
        }
    };

    // Validate response_type = code
    if q.response_type.as_deref() != Some("code") {
        return oauth_error_redirect(
            Some(&redirect_uri),
            Some(&client_state),
            "unsupported_response_type",
            "only 'code' is supported",
        );
    }

    // Validate code_challenge_method = S256
    if q.code_challenge_method.as_deref() != Some("S256") {
        return oauth_error_redirect(
            Some(&redirect_uri),
            Some(&client_state),
            "invalid_request",
            "code_challenge_method must be S256",
        );
    }

    let code_challenge = match &q.code_challenge {
        Some(s) => s.clone(),
        None => {
            return oauth_error_redirect(
                Some(&redirect_uri),
                Some(&client_state),
                "invalid_request",
                "code_challenge required",
            );
        }
    };

    let scope = match q.scope.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => {
            return oauth_error_redirect(
                Some(&redirect_uri),
                Some(&client_state),
                "invalid_request",
                "scope parameter required",
            )
        }
    };

    // Validate scopes
    if let Err(msg) = validate_scopes_against_client(scope, &client) {
        return oauth_error_redirect(
            Some(&redirect_uri),
            Some(&client_state),
            "invalid_scope",
            &msg,
        );
    }

    // Parse optional keys_jwk (base64url-encoded JSON, matching TS client encodePublicJwk)
    let keys_jwk: Option<serde_json::Value> = match &q.keys_jwk {
        Some(s) => {
            let decoded = match B64URL.decode(s) {
                Ok(b) => b,
                Err(_) => {
                    return oauth_error_redirect(
                        Some(&redirect_uri),
                        Some(&client_state),
                        "invalid_request",
                        "invalid keys_jwk encoding",
                    )
                }
            };
            match serde_json::from_slice(&decoded) {
                Ok(v) => {
                    // Validate it's a P-256 public key
                    if validate_p256_public_key(&v).is_err() {
                        return oauth_error_redirect(
                            Some(&redirect_uri),
                            Some(&client_state),
                            "invalid_request",
                            "invalid keys_jwk",
                        );
                    }
                    Some(v)
                }
                Err(_) => {
                    return oauth_error_redirect(
                        Some(&redirect_uri),
                        Some(&client_state),
                        "invalid_request",
                        "invalid keys_jwk JSON",
                    )
                }
            }
        }
        None => None,
    };

    // Create OAuth state JWT
    let oauth_state_claims = OAuthStateClaims::new(
        client_id_str.clone(),
        redirect_uri.clone(),
        scope.to_string(),
        client_state,
        code_challenge,
        "S256".to_string(),
        keys_jwk,
    );

    let state_token = match state.jwt.create_oauth_state_token(oauth_state_claims) {
        Ok(t) => t,
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    // Redirect to SPA consent page (must match Go server's URL format)
    let client_name = client.name.clone();
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("oauth", &state_token);
    serializer.append_pair("client_id", &client_id_str);
    serializer.append_pair("client_name", &client_name);
    serializer.append_pair("scope", scope);
    if let Some(kjwk) = &q.keys_jwk {
        serializer.append_pair("keys_jwk", kjwk);
    }
    let query = serializer.finish();
    let consent_url = format!("{}/consent?{}", state.config.web_base_url, query);
    Redirect::to(&consent_url).into_response()
}

// ─── Consent ─────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ConsentBody {
    // OAuth state JWT created by /oauth/authorize
    pub oauth_state: Option<String>,
    // User decision (true = allow, false = deny)
    #[serde(default)]
    pub approved: bool,
    #[serde(default)]
    pub keys_jwe: Option<String>,
    #[serde(default)]
    pub keys_jwk_thumbprint: Option<String>,
    #[serde(default)]
    pub wrapped_scoped_key: Option<String>,
    #[serde(default)]
    pub app_public_key_jwk: Option<String>,
    #[serde(default)]
    pub app_keypair_blob: Option<String>,
}

/// POST /oauth/consent (auth-gated)
pub async fn handle_oauth_consent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ConsentBody>,
) -> Response {
    let auth_ctx = match extract_auth(&state, &headers) {
        Ok(ctx) => ctx,
        Err(e) => return e.into_response(),
    };

    let state_token = match &req.oauth_state {
        Some(t) => t.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "missing oauth_state"})),
            )
                .into_response();
        }
    };

    // Validate OAuth state JWT
    let oauth_state = match state.jwt.validate_oauth_state_token(&state_token) {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid or expired state_token"})),
            )
                .into_response();
        }
    };

    let client_id = match Uuid::parse_str(&oauth_state.client_id) {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid client_id").into_response(),
    };

    // Handle deny — return JSON with redirect_uri (SPA does the redirect)
    if !req.approved {
        let deny_url = build_redirect_url_with_error(
            &oauth_state.redirect_uri,
            &oauth_state.state,
            "access_denied",
            "user denied the request",
        );
        return (
            StatusCode::OK,
            Json(OAuthConsentResponse {
                redirect_uri: deny_url,
            }),
        )
            .into_response();
    }

    // Store wrapped scoped key if provided (first-write-wins, matching Go behavior)
    if let Some(ref wsk) = req.wrapped_scoped_key {
        let key_bytes = match B64.decode(wsk) {
            Ok(b) => b,
            Err(_) => {
                return write_oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "invalid wrapped scoped key",
                );
            }
        };
        if key_bytes.len() != WRAPPED_SCOPED_KEY_SIZE {
            return write_oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "invalid wrapped scoped key: must be 41 bytes",
            );
        }
        let grant = match state
            .storage
            .get_or_create_oauth_grant(client_id, auth_ctx.account_id, &oauth_state.scope)
            .await
        {
            Ok(g) => g,
            Err(e) => return ApiError::from(e).into_response(),
        };
        if grant.wrapped_scoped_key.is_none() || grant.wrapped_scoped_key.as_deref() == Some(&[]) {
            let _ = state
                .storage
                .update_grant_wrapped_scoped_key(grant.id, &key_bytes)
                .await;
        }
    }

    // Store app keypair blob if provided (matching Go behavior)
    if let Some(ref blob) = req.app_keypair_blob {
        if blob.len() > MAX_KEYPAIR_BLOB_SIZE {
            return write_oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "app_keypair_blob too large",
            );
        }
        if let Some(ref pub_key_str) = req.app_public_key_jwk {
            let pub_key: serde_json::Value = match serde_json::from_str(pub_key_str) {
                Ok(v) => v,
                Err(_) => {
                    return write_oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "invalid app_public_key_jwk: invalid JSON",
                    );
                }
            };
            let canonical = match validate_p256_public_key(&pub_key) {
                Ok(c) => c,
                Err(_) => {
                    return write_oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "invalid app_public_key_jwk",
                    );
                }
            };
            let grant = match state
                .storage
                .get_or_create_oauth_grant(client_id, auth_ctx.account_id, &oauth_state.scope)
                .await
            {
                Ok(g) => g,
                Err(e) => return ApiError::from(e).into_response(),
            };
            let _ = state
                .storage
                .update_grant_keypair(grant.id, &canonical, blob)
                .await;
        }
    }

    // Generate authorization code
    // Pass through keys_jwe and keys_jwk_thumbprint from request (SPA generates JWE client-side)
    let raw_code = generate_random_token();
    let now = chrono::Utc::now();

    let code_record = OAuthCode {
        code: raw_code.clone(),
        client_id,
        account_id: auth_ctx.account_id,
        redirect_uri: oauth_state.redirect_uri.clone(),
        scope: oauth_state.scope.clone(),
        code_challenge: oauth_state.code_challenge.clone(),
        keys_jwe: req.keys_jwe.clone(),
        keys_jwk_thumbprint: req.keys_jwk_thumbprint.clone(),
        created_at: now,
        expires_at: now + chrono::Duration::seconds(OAUTH_CODE_EXPIRY_SECS),
    };

    if let Err(e) = state.storage.create_oauth_code(&code_record).await {
        return ApiError::from(e).into_response();
    }

    // Return JSON with redirect_uri (SPA does the redirect via window.location.href)
    let redirect = build_redirect_url(&oauth_state.redirect_uri, &oauth_state.state, &raw_code);
    (
        StatusCode::OK,
        Json(OAuthConsentResponse {
            redirect_uri: redirect,
        }),
    )
        .into_response()
}

// ─── Token ───────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct TokenForm {
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

/// POST /oauth/token
///
/// Per RFC 6749 §4.1.3, the token endpoint MUST accept `application/x-www-form-urlencoded`.
/// We also accept `application/json` for compatibility with our TypeScript client.
pub async fn handle_oauth_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let req: TokenForm = {
        let content_type = headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if content_type.starts_with("application/x-www-form-urlencoded") {
            match serde_urlencoded::from_bytes(&body) {
                Ok(f) => f,
                Err(_) => {
                    return write_oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "invalid form body",
                    );
                }
            }
        } else if content_type.starts_with("application/json") || content_type.is_empty() {
            match serde_json::from_slice(&body) {
                Ok(f) => f,
                Err(_) => {
                    return write_oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "invalid request body",
                    );
                }
            }
        } else {
            return write_oauth_error(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "invalid_request",
                "unsupported Content-Type; use application/x-www-form-urlencoded",
            );
        }
    };
    match req.grant_type.as_str() {
        "authorization_code" => handle_authorization_code_grant(&state, req).await,
        "refresh_token" => handle_refresh_token_grant(&state, req).await,
        _ => write_oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "supported: authorization_code, refresh_token",
        ),
    }
}

async fn handle_authorization_code_grant(state: &AppState, req: TokenForm) -> Response {
    let client_id = match Uuid::parse_str(&req.client_id) {
        Ok(id) => id,
        Err(_) => {
            return write_oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_client",
                "invalid client_id",
            );
        }
    };

    if req.code.is_empty() {
        return write_oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code is required",
        );
    }
    if req.redirect_uri.is_empty() {
        return write_oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect_uri is required",
        );
    }
    if req.code_verifier.is_empty() {
        return write_oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code_verifier is required (PKCE)",
        );
    }

    // Atomically consume the authorization code
    let code = match state.storage.consume_oauth_code(&req.code).await {
        Ok(c) => c,
        Err(StorageError::OAuthCodeNotFound | StorageError::OAuthCodeExpired) => {
            return write_oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "invalid or expired code",
            );
        }
        Err(e) => return ApiError::from(e).into_response(),
    };

    // Validate client_id and redirect_uri
    if code.client_id != client_id {
        return write_oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "client_id mismatch",
        );
    }
    if code.redirect_uri != req.redirect_uri {
        return write_oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "redirect_uri mismatch",
        );
    }

    // Verify PKCE
    let pkce_ok = if let Some(ref thumbprint) = code.keys_jwk_thumbprint {
        // Extended PKCE: require keys_jwk_thumbprint in request and validate it matches
        if req.keys_jwk_thumbprint.is_empty() {
            return write_oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "keys_jwk_thumbprint required",
            );
        }
        if !bool::from(
            req.keys_jwk_thumbprint
                .as_bytes()
                .ct_eq(thumbprint.as_bytes()),
        ) {
            return write_oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "keys_jwk_thumbprint mismatch",
            );
        }
        verify_pkce_with_thumbprint(&req.code_verifier, thumbprint, &code.code_challenge)
    } else {
        verify_pkce(&req.code_verifier, &code.code_challenge)
    };

    if !pkce_ok {
        return write_oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "invalid code_verifier",
        );
    }

    // Get or create grant
    let grant = match if code.keys_jwk_thumbprint.is_some() {
        state
            .storage
            .get_or_create_oauth_grant_with_thumbprint(
                client_id,
                code.account_id,
                &code.scope,
                code.keys_jwk_thumbprint.as_deref().unwrap_or(""),
            )
            .await
    } else {
        state
            .storage
            .get_or_create_oauth_grant(client_id, code.account_id, &code.scope)
            .await
    } {
        Ok(g) => g,
        Err(e) => return ApiError::from(e).into_response(),
    };

    // Fetch account for handle in response
    let account = match state.storage.get_account_by_id(grant.account_id).await {
        Ok(a) => a,
        Err(e) => return ApiError::from(e).into_response(),
    };

    // Issue access token
    let access_token = match issue_access_token(state, &grant, &code.scope).await {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    // Issue refresh token
    let (raw_refresh, refresh_record) = new_refresh_token(grant.id);
    if let Err(e) = state.storage.create_refresh_token(&refresh_record).await {
        return ApiError::from(e).into_response();
    }

    let _ = state.storage.update_grant_last_used(grant.id).await;

    let handle = format_handle(&account.username, &state.config.identity_domain);
    let response = OAuthTokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 15 * 60,
        refresh_token: raw_refresh,
        scope: code.scope,
        keys_jwe: code.keys_jwe, // only returned on first exchange
        handle,
    };

    (StatusCode::OK, Json(response)).into_response()
}

async fn handle_refresh_token_grant(state: &AppState, req: TokenForm) -> Response {
    if req.refresh_token.is_empty() {
        return write_oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "missing refresh_token",
        );
    }

    let token_hash = sha256_hash(req.refresh_token.as_bytes());

    // Look up the active refresh token. Previously-used tokens will not be
    // found here (they were deleted by rotate_refresh_token). Reuse of a
    // token that races with a concurrent rotation is caught atomically by
    // the unique constraint inside rotate_refresh_token below.
    let old_token = match state.storage.get_refresh_token_by_hash(&token_hash).await {
        Ok(t) => t,
        Err(StorageError::RefreshTokenNotFound | StorageError::RefreshTokenExpired) => {
            return write_oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "invalid or expired refresh_token",
            );
        }
        Err(e) => return ApiError::from(e).into_response(),
    };

    let grant = match state.storage.get_oauth_grant(old_token.grant_id).await {
        Ok(g) => g,
        Err(e) => return ApiError::from(e).into_response(),
    };

    // Fetch account for handle in response
    let account = match state.storage.get_account_by_id(grant.account_id).await {
        Ok(a) => a,
        Err(e) => return ApiError::from(e).into_response(),
    };

    // Validate client_id matches grant (required)
    if req.client_id.is_empty() {
        return write_oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_id is required",
        );
    }
    let cid = match Uuid::parse_str(&req.client_id) {
        Ok(id) => id,
        Err(_) => {
            return write_oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_client",
                "invalid client_id",
            )
        }
    };
    if grant.client_id != cid {
        return write_oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client",
            "client_id mismatch",
        );
    }

    // Issue new access token
    let access_token = match issue_access_token(state, &grant, &grant.scope).await {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    // Rotate refresh token (atomically: delete old, record as used, create new).
    // If a concurrent request already used this token, rotate_refresh_token
    // detects the unique constraint violation, revokes the grant's tokens
    // inside the transaction, and returns RefreshTokenReused.
    let (new_raw, new_record) = new_refresh_token(grant.id);
    match state
        .storage
        .rotate_refresh_token(old_token.id, &token_hash, grant.id, &new_record)
        .await
    {
        Ok(()) => {}
        Err(StorageError::RefreshTokenReused { grant_id }) => {
            tracing::warn!(grant_id = %grant_id, "refresh token reuse detected during rotation, grant tokens revoked");
            return write_oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_grant",
                "refresh token reuse detected",
            );
        }
        Err(e) => return ApiError::from(e).into_response(),
    }

    let _ = state.storage.update_grant_last_used(grant.id).await;

    let handle = format_handle(&account.username, &state.config.identity_domain);
    let response = OAuthTokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 15 * 60,
        refresh_token: new_raw,
        scope: grant.scope,
        keys_jwe: None, // not returned on refresh
        handle,
    };

    (StatusCode::OK, Json(response)).into_response()
}

// ─── UserInfo ────────────────────────────────────────────────────────────────

/// GET /oauth/userinfo
pub async fn handle_oauth_userinfo(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<OAuthUserInfoResponse>, ApiError> {
    let claims = extract_oauth_token(&state, &headers)?;

    let account_id =
        Uuid::parse_str(&claims.sub).map_err(|_| ApiError::unauthorized("invalid token"))?;

    let scopes: Vec<&str> = claims.scope.split_whitespace().collect();

    // openid scope is required for this endpoint
    if !scopes.contains(&"openid") {
        return Err(ApiError::forbidden("openid scope required"));
    }

    let account = state.storage.get_account_by_id(account_id).await?;

    let preferred_username = if scopes.contains(&"profile") {
        Some(format_handle(
            &account.username,
            &state.config.identity_domain,
        ))
    } else {
        None
    };

    let (email, email_verified) = if scopes.contains(&"email") {
        (Some(account.email.clone()), Some(true))
    } else {
        (None, None)
    };

    Ok(Json(OAuthUserInfoResponse {
        sub: claims.sub,
        preferred_username,
        email,
        email_verified,
    }))
}

// ─── JWKS ────────────────────────────────────────────────────────────────────

/// GET /.well-known/jwks.json
pub async fn handle_jwks(State(state): State<AppState>) -> Response {
    let signing_keys = match state.storage.list_signing_keys().await {
        Ok(k) => k,
        Err(e) => {
            tracing::error!("failed to list signing keys: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    let pairs: Vec<(i32, Vec<u8>)> = signing_keys
        .into_iter()
        .map(|k| (k.id, k.public_key))
        .collect();

    let jwks = match Jwks::from_signing_keys(&pairs) {
        Ok(j) => j,
        Err(e) => {
            tracing::error!("failed to build JWKS: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        Json(jwks),
    )
        .into_response()
}

// ─── Mailbox ─────────────────────────────────────────────────────────────────

/// POST /oauth/mailbox (OAuth-gated)
pub async fn handle_register_mailbox(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RegisterMailboxRequest>,
) -> Result<StatusCode, ApiError> {
    let claims = extract_oauth_token(&state, &headers)?;

    // Validate mailbox ID: must be 64 lowercase hex chars
    if req.mailbox_id.len() != MAILBOX_ID_LENGTH
        || !req
            .mailbox_id
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
    {
        return Err(ApiError::bad_request(
            "mailbox_id must be 64 lowercase hex characters",
        ));
    }

    let grant_id =
        Uuid::parse_str(&claims.grant_id).map_err(|_| ApiError::unauthorized("invalid token"))?;

    // First-write-wins
    state
        .storage
        .update_grant_mailbox_id(grant_id, &req.mailbox_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

// ─── Grant keypair ───────────────────────────────────────────────────────────

/// GET /oauth/grant-keypair?client_id=
pub async fn handle_grant_keypair(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Result<Json<GrantKeypairResponse>, ApiError> {
    let auth_ctx = extract_auth(&state, &headers)?;

    let client_id_str = q
        .get("client_id")
        .ok_or_else(|| ApiError::bad_request("missing client_id"))?;
    let client_id =
        Uuid::parse_str(client_id_str).map_err(|_| ApiError::bad_request("invalid client_id"))?;

    // Return empty blob if no grant exists (first-time consent), matching Go behavior
    let grant = state
        .storage
        .get_oauth_grant_by_account_and_client(auth_ctx.account_id, client_id)
        .await;

    match grant {
        Ok(g) => Ok(Json(GrantKeypairResponse {
            app_keypair_blob: g.app_keypair_blob.unwrap_or_default(),
            wrapped_scoped_key: g.wrapped_scoped_key.map(|k| B64.encode(&k)),
        })),
        Err(StorageError::OAuthGrantNotFound) => Ok(Json(GrantKeypairResponse {
            app_keypair_blob: String::new(),
            wrapped_scoped_key: None,
        })),
        Err(e) => Err(ApiError::from(e)),
    }
}

// ─── User public key ─────────────────────────────────────────────────────────

/// GET /v1/users/{username}/keys/{client_id}
pub async fn handle_user_public_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((username, client_id_str)): Path<(String, String)>,
) -> Result<Json<UserPublicKeyResponse>, ApiError> {
    // Requires OAuth access token
    let claims = extract_oauth_token(&state, &headers)?;

    // Callers can only look up keys for their own client (app)
    if claims.client_id != client_id_str {
        return Err(ApiError::not_found("not found"));
    }

    if username.is_empty() || client_id_str.is_empty() {
        return Err(ApiError::not_found("not found"));
    }

    let client_id =
        Uuid::parse_str(&client_id_str).map_err(|_| ApiError::not_found("not found"))?;

    // Look up account by username (any user, not just the caller)
    let account = state
        .storage
        .get_account_by_username(&state.config.issuer, &username)
        .await
        .map_err(|_| ApiError::not_found("not found"))?;

    let grant = state
        .storage
        .get_oauth_grant_by_account_and_client(account.id, client_id)
        .await
        .map_err(|_| ApiError::not_found("not found"))?;

    let public_key = grant
        .app_public_key
        .ok_or_else(|| ApiError::not_found("not found"))?;

    // Anti-enumeration: treat malformed keys same as missing
    let did = compute_did_key(&public_key).map_err(|_| ApiError::not_found("not found"))?;

    Ok(Json(UserPublicKeyResponse {
        handle: format_handle(&account.username, &state.config.identity_domain),
        client_id: client_id_str,
        public_key,
        did,
        issuer: state.config.issuer.clone(),
        user_id: account.id.to_string(),
        mailbox_id: grant.mailbox_id.unwrap_or_default(),
    }))
}

// ─── User by thumbprint ──────────────────────────────────────────────────────

/// GET /v1/users/by-thumbprint/{thumbprint}
pub async fn handle_user_by_thumbprint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(thumbprint): Path<String>,
) -> Result<Json<UserByThumbprintResponse>, ApiError> {
    // Requires auth token
    let _auth_ctx = extract_auth(&state, &headers)?;

    // Validate thumbprint is non-empty base64url (anti-enumeration: return 404 for bad format)
    if thumbprint.is_empty()
        || !thumbprint
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ApiError::not_found("not found"));
    }

    let (account, grant) = state
        .storage
        .get_account_by_key_thumbprint(&thumbprint)
        .await
        .map_err(|e| match e {
            StorageError::AccountNotFound | StorageError::OAuthGrantNotFound => {
                ApiError::not_found("not found")
            }
            _ => ApiError::from(e),
        })?;

    let handle = format_handle(&account.username, &state.config.identity_domain);

    let public_key = grant.app_public_key.clone();
    let did = public_key
        .as_ref()
        .and_then(|jwk| compute_did_key(jwk).ok());

    Ok(Json(UserByThumbprintResponse {
        handle,
        did,
        public_key,
    }))
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn validate_scopes(scope: &str) -> Result<(), String> {
    for s in scope.split_whitespace() {
        if !OIDC_SCOPES.contains(&s) && !CAPABILITY_SCOPES.contains(&s) {
            return Err(format!("unknown scope: {s}"));
        }
    }
    Ok(())
}

fn validate_scopes_against_client(scope: &str, client: &OAuthClient) -> Result<(), String> {
    validate_scopes(scope)?;

    let scopes: Vec<&str> = scope.split_whitespace().collect();

    // Check capability scopes are allowed by client
    for s in &scopes {
        if CAPABILITY_SCOPES.contains(s) && !client.allowed_scopes.iter().any(|a| a == s) {
            return Err(format!("scope '{s}' not allowed for this client"));
        }
    }

    // 'files' requires 'sync'
    if scopes.contains(&"files") && !scopes.contains(&"sync") {
        return Err("'files' scope requires 'sync'".to_string());
    }

    Ok(())
}

/// Validate that a JWK value is a P-256 public key (no private key fields).
/// Verifies the point is actually on the P-256 curve (prevents invalid-curve attacks).
/// Returns the canonical form on success.
fn validate_p256_public_key(jwk: &serde_json::Value) -> Result<serde_json::Value, String> {
    let kty = jwk.get("kty").and_then(|v| v.as_str());
    let crv = jwk.get("crv").and_then(|v| v.as_str());
    let x_str = jwk.get("x").and_then(|v| v.as_str());
    let y_str = jwk.get("y").and_then(|v| v.as_str());

    if kty != Some("EC") || crv != Some("P-256") {
        return Err("must be EC P-256".into());
    }
    let (x_str, y_str) = match (x_str, y_str) {
        (Some(x), Some(y)) => (x, y),
        _ => return Err("missing x or y".into()),
    };
    // No private key
    if jwk.get("d").is_some() {
        return Err("private key not allowed".into());
    }

    // Decode coordinates
    let x_bytes = B64URL.decode(x_str).map_err(|_| "invalid x".to_string())?;
    let y_bytes = B64URL.decode(y_str).map_err(|_| "invalid y".to_string())?;

    // Verify point is on the P-256 curve
    let x_field =
        p256::FieldBytes::from_exact_iter(x_bytes.iter().copied()).ok_or("x must be 32 bytes")?;
    let y_field =
        p256::FieldBytes::from_exact_iter(y_bytes.iter().copied()).ok_or("y must be 32 bytes")?;
    let encoded_point =
        p256::EncodedPoint::from_affine_coordinates(&x_field, &y_field, /* compress */ false);
    let affine: p256::AffinePoint =
        Option::from(p256::AffinePoint::from_encoded_point(&encoded_point))
            .ok_or("point is not on P-256 curve")?;

    // Re-encode from validated point for canonical output (ensures consistent
    // base64url encoding for thumbprint computation)
    let validated = affine.to_encoded_point(false);
    let x_canonical = B64URL.encode(validated.x().expect("affine point has x"));
    let y_canonical = B64URL.encode(validated.y().expect("affine point has y"));

    Ok(serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x_canonical,
        "y": y_canonical
    }))
}

fn verify_pkce(verifier: &str, challenge: &str) -> bool {
    let hash = Sha256::digest(verifier.as_bytes());
    let computed = B64URL.encode(hash);
    computed.as_bytes().ct_eq(challenge.as_bytes()).into()
}

fn verify_pkce_with_thumbprint(verifier: &str, thumbprint: &str, challenge: &str) -> bool {
    let mut input = verifier.as_bytes().to_vec();
    input.extend_from_slice(thumbprint.as_bytes());
    let hash = Sha256::digest(&input);
    let computed = B64URL.encode(hash);
    computed.as_bytes().ct_eq(challenge.as_bytes()).into()
}

/// Generate a cryptographically random token (32 bytes, base64url-encoded).
fn generate_random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    B64URL.encode(bytes)
}

fn sha256_hash(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

fn new_refresh_token(grant_id: Uuid) -> (String, OAuthRefreshToken) {
    let raw = generate_random_token();
    let hash = sha256_hash(raw.as_bytes());
    let now = chrono::Utc::now();
    let record = OAuthRefreshToken {
        id: Uuid::new_v4(),
        grant_id,
        token_hash: hash,
        created_at: now,
        expires_at: now + chrono::Duration::seconds(REFRESH_TOKEN_EXPIRY_SECS),
    };
    (raw, record)
}

async fn issue_access_token(
    state: &AppState,
    grant: &OAuthGrant,
    scope: &str,
) -> Result<String, ApiError> {
    let _account = state.storage.get_account_by_id(grant.account_id).await?;

    let scopes: Vec<&str> = scope.split_whitespace().collect();

    let mut aud = vec![grant.client_id.to_string()];
    if scopes.contains(&"sync") || scopes.contains(&"files") {
        aud.push("less-sync".to_string());
    }
    if scopes.contains(&"inference") {
        aud.push("less-inference".to_string());
    }

    let did = grant
        .app_public_key
        .as_ref()
        .and_then(|jwk| compute_did_key(jwk).ok())
        .unwrap_or_default();

    let space_id = personal_space_id(
        &state.config.issuer,
        &grant.account_id.to_string(),
        &grant.client_id.to_string(),
    );

    let now = chrono::Utc::now();
    let claims = OAuthAccessClaims {
        sub: grant.account_id.to_string(),
        iss: state.config.issuer.clone(),
        aud,
        exp: (now + chrono::Duration::minutes(15)).timestamp(),
        iat: now.timestamp(),
        client_id: grant.client_id.to_string(),
        grant_id: grant.id.to_string(),
        scope: scope.to_string(),
        did,
        personal_space_id: space_id.to_string(),
        mailbox_id: grant.mailbox_id.clone(),
    };

    state
        .jwt
        .create_oauth_access_token(claims)
        .map_err(|_| ApiError::internal())
}

fn build_redirect_url(redirect_uri: &str, state: &str, code: &str) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("code", code);
    if !state.is_empty() {
        serializer.append_pair("state", state);
    }
    let query = serializer.finish();
    let sep = if redirect_uri.contains('?') { "&" } else { "?" };
    format!("{redirect_uri}{sep}{query}")
}

fn build_redirect_url_with_error(
    redirect_uri: &str,
    state: &str,
    error: &str,
    description: &str,
) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("state", state);
    serializer.append_pair("error", error);
    serializer.append_pair("error_description", description);
    let query = serializer.finish();
    let sep = if redirect_uri.contains('?') { "&" } else { "?" };
    format!("{redirect_uri}{sep}{query}")
}

fn oauth_error_redirect(
    redirect_uri: Option<&str>,
    state: Option<&str>,
    error: &str,
    description: &str,
) -> Response {
    if let Some(uri) = redirect_uri {
        return redirect_with_error(uri, state.unwrap_or(""), error, description);
    }
    write_oauth_error(StatusCode::BAD_REQUEST, error, description)
}

fn redirect_with_error(
    redirect_uri: &str,
    state: &str,
    error: &str,
    description: &str,
) -> Response {
    let url = build_redirect_url_with_error(redirect_uri, state, error, description);
    Redirect::to(&url).into_response()
}

fn write_oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": error,
            "error_description": description,
        })),
    )
        .into_response()
}
