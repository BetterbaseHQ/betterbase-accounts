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
use p256::elliptic_curve::sec1::{FromSec1Point as _, ToSec1Point as _};
use rand::RngExt;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use betterbase_accounts_auth::es256::Jwks;
use betterbase_accounts_auth::jwt::{OAuthAccessClaims, OAuthStateClaims};
use betterbase_accounts_core::{
    identity::{compute_did_key, format_handle, personal_space_id},
    protocol::*,
};
use betterbase_accounts_storage::{
    AccountStorage, ConsentKeyInstall, OAuthClient, OAuthClientStorage, OAuthCode,
    OAuthCodeStorage, OAuthGrant, OAuthGrantStorage, OAuthRefreshToken, OAuthRefreshTokenStorage,
    OAuthSigningKeyStorage, StorageError,
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
const OIDC_SCOPES: &[&str] = &["openid", "profile", "email"];
/// Capability scopes gated by OAuth client config
const CAPABILITY_SCOPES: &[&str] = &["sync", "files", "inference"];

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

    // Redirect to SPA consent page. Only the signed state token is passed:
    // the consent page fetches its display and wrapping context from
    // /oauth/consent-context keyed by this token, so nothing trust-relevant
    // travels as an unsigned URL parameter (AUD-005).
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("oauth", &state_token);
    let query = serializer.finish();
    let consent_url = format!("{}/consent?{}", state.config.web_base_url, query);
    Redirect::to(&consent_url).into_response()
}

// ─── Consent ─────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ConsentContextQuery {
    pub oauth_state: String,
}

#[derive(serde::Serialize)]
pub struct ConsentContextResponse {
    pub client_id: String,
    pub client_name: String,
    pub scope: String,
    pub redirect_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keys_jwk: Option<serde_json::Value>,
}

/// GET /oauth/consent-context (auth-gated)
///
/// Server-validated authorization context for the consent page, derived from
/// the signed OAuth state. The consent UI must use this for the displayed
/// client/scope and for the key-wrapping recipient — never unsigned URL
/// parameters (AUD-005).
pub async fn handle_oauth_consent_context(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ConsentContextQuery>,
) -> Response {
    // Auth-gated: only the signed-in account may read its authorization context.
    if let Err(e) = extract_auth(&state, &headers).await {
        return e.into_response();
    }

    let oauth_state = match state.jwt.validate_oauth_state_token(&q.oauth_state) {
        Ok(c) => c,
        Err(_) => {
            return write_oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "invalid or expired oauth_state",
            );
        }
    };

    let client_id = match Uuid::parse_str(&oauth_state.client_id) {
        Ok(id) => id,
        Err(_) => {
            return write_oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "invalid client");
        }
    };

    let client = match state.storage.get_oauth_client(client_id).await {
        Ok(c) => c,
        Err(_) => {
            return write_oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "unknown client");
        }
    };

    (
        StatusCode::OK,
        Json(ConsentContextResponse {
            client_id: oauth_state.client_id,
            client_name: client.name,
            scope: oauth_state.scope,
            redirect_uri: oauth_state.redirect_uri,
            keys_jwk: oauth_state.keys_jwk,
        }),
    )
        .into_response()
}

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
    /// Version of the account root key the client derived its key
    /// material under. Required whenever key material is submitted: a
    /// rotation since the consent page loaded means the material is
    /// wrapped under a retired root and would strand the grant
    /// (AUD-008/009 residual).
    #[serde(default)]
    pub root_key_version: Option<i64>,
}

/// POST /oauth/consent (auth-gated)
pub async fn handle_oauth_consent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ConsentBody>,
) -> Response {
    let auth_ctx = match extract_auth(&state, &headers).await {
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

    // AUD-005: bind the key-delivery recipient to the signed authorization
    // state. A wrapped-keys payload may only be delivered when the state
    // carries a keys_jwk recipient, and its thumbprint must match that signed
    // recipient — never an independently supplied one. For the sync flow (the
    // only flow where the consent page delivers keys) an approved consent
    // must carry the pair: silence would be a silent downgrade of the
    // client's extended PKCE flow.
    let sync_key_delivery =
        oauth_state.keys_jwk.is_some() && oauth_state.scope.split(' ').any(|s| s == "sync");
    if req.keys_jwe.is_some() || req.keys_jwk_thumbprint.is_some() || sync_key_delivery {
        let Some(signed_jwk) = &oauth_state.keys_jwk else {
            return write_oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "authorization request did not include a key recipient",
            );
        };
        let (Some(_), Some(thumbprint)) = (&req.keys_jwe, &req.keys_jwk_thumbprint) else {
            return write_oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "keys_jwe and keys_jwk_thumbprint must be supplied together",
            );
        };
        let expected = match jwk_thumbprint_b64(signed_jwk) {
            Ok(t) => t,
            Err(_) => {
                return write_oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "invalid keys_jwk in authorization state",
                );
            }
        };
        if !constant_time_str_eq(thumbprint, &expected) {
            return write_oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "keys_jwk_thumbprint does not match the authorization request",
            );
        }
    }

    // Store wrapped scoped key if provided. When the app keypair is
    // co-submitted (the consent page always pairs them), the install goes
    // through the atomic bundle path below instead — first-write-wins here
    // only handles a wrapper submitted without a keypair.
    if let (Some(ref wsk), None) = (&req.wrapped_scoped_key, &req.app_keypair_blob) {
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
        let Some(root_key_version) = req.root_key_version else {
            return write_oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "key material requires root_key_version (the version of the root key it was derived under)",
            );
        };
        let grant = match state
            .storage
            .get_or_create_oauth_grant(client_id, auth_ctx.account_id, &oauth_state.scope)
            .await
        {
            Ok(g) => g,
            Err(e) => return ApiError::from(e).into_response(),
        };
        if grant.wrapped_scoped_key.is_none() || grant.wrapped_scoped_key.as_deref() == Some(&[]) {
            if let Err(e) = state
                .storage
                .update_grant_wrapped_scoped_key_root_checked(
                    grant.id,
                    &key_bytes,
                    root_key_version,
                )
                .await
            {
                if matches!(e, StorageError::RootKeyVersionConflict) {
                    return write_oauth_error(
                        StatusCode::CONFLICT,
                        "invalid_grant_state",
                        "root key rotated since the consent page loaded — re-authenticate and retry",
                    );
                }
                tracing::error!(error = %e, "failed to persist wrapped scoped key");
                return write_oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "failed to save scoped key",
                );
            }
        }
    }

    // Store app keypair blob if provided (AUD-008: atomically with the
    // wrapped scoped key — a keypair overwrite is only accepted when the
    // submitted wrapper matches the grant's stored one, so a client acting
    // on a stale/failed read cannot silently replace existing key
    // material).
    if let Some(ref blob) = req.app_keypair_blob {
        if blob.len() > MAX_KEYPAIR_BLOB_SIZE {
            return write_oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "app_keypair_blob too large",
            );
        }
        let Some(ref pub_key_str) = req.app_public_key_jwk else {
            return write_oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "app_keypair_blob requires app_public_key_jwk",
            );
        };
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
        let Some(ref wsk) = req.wrapped_scoped_key else {
            return write_oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "app_keypair_blob requires wrapped_scoped_key (key material must land atomically)",
            );
        };
        let Some(root_key_version) = req.root_key_version else {
            return write_oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "key material requires root_key_version (the version of the root key it was derived under)",
            );
        };
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
        match state
            .storage
            .install_consent_key_bundle(grant.id, &key_bytes, &canonical, blob, root_key_version)
            .await
        {
            Ok(ConsentKeyInstall::Installed) => {}
            Ok(ConsentKeyInstall::StaleRoot) => {
                tracing::warn!(
                    grant_id = %grant.id,
                    expected_root_version = root_key_version,
                    "consent key bundle rejected: account root key rotated since derivation"
                );
                return write_oauth_error(
                    StatusCode::CONFLICT,
                    "invalid_grant_state",
                    "root key rotated since the consent page loaded — re-authenticate and retry",
                );
            }
            Ok(ConsentKeyInstall::Conflict) => {
                tracing::warn!(
                    grant_id = %grant.id,
                    "consent key bundle rejected: submitted wrapped key does not match stored state"
                );
                return write_oauth_error(
                    StatusCode::CONFLICT,
                    "invalid_grant_state",
                    "grant key material changed since the consent page loaded — retry consent",
                );
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to persist consent key bundle");
                return write_oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "failed to save app credentials",
                );
            }
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
/// Per RFC 6749 §4.1.3, the token endpoint accepts `application/x-www-form-urlencoded`.
pub async fn handle_oauth_token(
    State(state): State<AppState>,
    axum::extract::Form(req): axum::extract::Form<TokenForm>,
) -> Response {
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

    (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(response),
    )
        .into_response()
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
    // found here (they were deleted by rotate_refresh_token); a used hash is
    // resolved from used_refresh_tokens below and revokes the surviving
    // family (sequential reuse, AUD-004). Reuse that races with a concurrent
    // rotation is caught by the conflict check inside rotate_refresh_token.
    let old_token = match state.storage.get_refresh_token_by_hash(&token_hash).await {
        Ok(t) => t,
        Err(StorageError::RefreshTokenExpired) => {
            return write_oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "invalid or expired refresh_token",
            );
        }
        Err(StorageError::RefreshTokenNotFound) => {
            // AUD-004 sequential reuse: the presented token was already
            // rotated (its hash now lives in used_refresh_tokens).
            // Presenting it again must revoke the surviving family —
            // otherwise a copied token keeps its thief's replacement alive
            // even after the legitimate client presents the original.
            match state
                .storage
                .get_used_refresh_grant_by_hash(&token_hash)
                .await
            {
                Ok(Some(grant_id)) => {
                    if let Err(e) = state.storage.delete_refresh_tokens_by_grant(grant_id).await {
                        tracing::error!(
                            grant_id = %grant_id,
                            error = %e,
                            "failed to revoke refresh family after sequential reuse"
                        );
                        return ApiError::from(e).into_response();
                    }
                    tracing::warn!(
                        grant_id = %grant_id,
                        "refresh token reuse detected (sequential), grant tokens revoked"
                    );
                    // 400 per RFC 6749 (invalid_grant); the description —
                    // not the status — carries the reuse signal, so the
                    // response does not oracle whether a token was once
                    // valid.
                    return write_oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "refresh token reuse detected",
                    );
                }
                Ok(None) => {
                    return write_oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "invalid or expired refresh_token",
                    );
                }
                Err(e) => return ApiError::from(e).into_response(),
            }
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

    // AUD-013: the stored grant's scope must still be permitted for this
    // client. The grant tracks the latest authorized scope (the
    // code-exchange UPSERT narrows/widens it on every consent), and a
    // capability withdrawn from the client after consent must stop
    // flowing on refresh instead of being granted forever.
    let client = match state.storage.get_oauth_client(grant.client_id).await {
        Ok(c) => c,
        Err(e) => return ApiError::from(e).into_response(),
    };
    if let Err(reason) = validate_scopes_against_client(&grant.scope, &client) {
        tracing::warn!(
            grant_id = %grant.id,
            client_id = %grant.client_id,
            reason = %reason,
            "refresh denied: grant scope no longer permitted for this client"
        );
        return write_oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "grant scope no longer permitted for this client",
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
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "refresh token reuse detected",
            );
        }
        Err(StorageError::RefreshTokenNotFound) => {
            return write_oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "refresh token revoked",
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

    (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(response),
    )
        .into_response()
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
    let auth_ctx = extract_auth(&state, &headers).await?;

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
    let _auth_ctx = extract_auth(&state, &headers).await?;

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
    if x_bytes.len() != 32 || y_bytes.len() != 32 {
        return Err("coordinates must be 32 bytes".into());
    }
    let x_field = p256::FieldBytes::try_from(x_bytes.as_slice()).expect("length checked above");
    let y_field = p256::FieldBytes::try_from(y_bytes.as_slice()).expect("length checked above");
    let encoded_point =
        p256::Sec1Point::from_affine_coordinates(&x_field, &y_field, /* compress */ false);
    let affine: p256::AffinePoint =
        Option::from(p256::AffinePoint::from_sec1_point(&encoded_point))
            .ok_or("point is not on P-256 curve")?;

    // Re-encode from validated point for canonical output (ensures consistent
    // base64url encoding for thumbprint computation)
    let validated = affine.to_sec1_point(false);
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

/// RFC 7638 JWK thumbprint (SHA-256, base64url) for an EC P-256 public key.
/// Mirrors the browser's `computeJwkThumbprint` for the recipient binding.
fn jwk_thumbprint_b64(jwk: &serde_json::Value) -> Result<String, String> {
    let kty = jwk.get("kty").and_then(|v| v.as_str());
    let crv = jwk.get("crv").and_then(|v| v.as_str());
    let x = jwk.get("x").and_then(|v| v.as_str());
    let y = jwk.get("y").and_then(|v| v.as_str());
    match (kty, crv, x, y) {
        (Some("EC"), Some("P-256"), Some(x), Some(y)) => {
            // Required members in lexicographic order per RFC 7638 §3.2.
            let input = format!("{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}");
            Ok(B64URL.encode(Sha256::digest(input.as_bytes())))
        }
        _ => Err("not an EC P-256 public key".to_owned()),
    }
}

/// Constant-time string comparison (thumbprints are public but compare
/// uniformly anyway to avoid short-circuit leaks).
fn constant_time_str_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
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
    rand::rng().fill(&mut bytes);
    B64URL.encode(bytes)
}

pub(crate) fn sha256_hash(data: &[u8]) -> Vec<u8> {
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
    let scopes: Vec<&str> = scope.split_whitespace().collect();

    let mut aud = vec![grant.client_id.to_string()];
    if scopes.contains(&"sync") || scopes.contains(&"files") {
        aud.push("betterbase-sync".to_string());
    }
    if scopes.contains(&"inference") {
        aud.push("betterbase-inference".to_string());
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

#[cfg(test)]
mod consent_tests {
    use axum::http::StatusCode;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use serde_json::json;
    use tower::ServiceExt;

    use crate::test_support::{get_json, post_json, test_app, TestApp, TEST_ISSUER};

    use super::*;

    const REDIRECT_URI: &str = "http://localhost:5381/";
    const REDIRECT_URI_ENC: &str = "http%3A%2F%2Flocalhost%3A5381%2F";

    fn keys_jwk() -> serde_json::Value {
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": B64URL.encode([1u8; 32]),
            "y": B64URL.encode([2u8; 32]),
        })
    }

    /// Known-answer vector pinning the RFC 7638 construction shared by the
    /// server, the browser (`computeJwkThumbprint`), and the SDK. A drift in
    /// any implementation breaks extended PKCE at runtime only.
    #[test]
    fn jwk_thumbprint_matches_the_shared_known_answer() {
        let jwk = keys_jwk();
        assert_eq!(
            jwk_thumbprint_b64(&jwk).expect("thumbprint"),
            // SHA-256 over {"crv":"P-256","kty":"EC","x":"AQEB...","y":"AgIC..."}
            "kOFKxjJdOqJD5G4Yuw-cxHe64VGyxKEO_hoV83QfGj0"
        );
    }

    #[tokio::test]
    async fn authorize_redirect_carries_only_the_signed_state_token() {
        // AUD-005: the consent URL must contain ONLY the signed `oauth`
        // token — reintroducing unsigned params (client name, keys, scope)
        // would let them be spoofed on the consent page.
        let Some(app) = test_app().await else {
            return;
        };
        let client_id = Uuid::new_v4();
        app.storage
            .create_oauth_client(&OAuthClient {
                id: client_id,
                name: "Spoofable Name".to_owned(),
                secret_hash: None,
                redirect_uris: vec![REDIRECT_URI.to_owned()],
                allowed_scopes: vec!["openid".to_owned(), "sync".to_owned()],
                created_at: chrono::Utc::now(),
            })
            .await
            .expect("create client");

        let uri = format!(
            "/oauth/authorize?client_id={client_id}&redirect_uri={REDIRECT_URI_ENC}&response_type=code&scope=openid%20sync&state=client-state&code_challenge=challenge&code_challenge_method=S256"
        );
        let request = axum::http::Request::builder()
            .method("GET")
            .uri(&uri)
            .body(axum::body::Body::empty())
            .expect("build request");
        let response = app.router.clone().oneshot(request).await.expect("dispatch");

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .expect("location header")
            .to_owned();

        let (base, query) = location.split_once('?').expect("consent query");
        assert!(
            base.ends_with("/consent"),
            "unexpected consent base: {base}"
        );
        let pairs: Vec<(String, String)> = form_urlencoded::parse(query.as_bytes())
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(
            pairs.len(),
            1,
            "consent redirect must carry exactly one param: {location}"
        );
        assert_eq!(pairs[0].0, "oauth");
        // The token is a signed JWT (three segments), not a passthrough of
        // any client-supplied value.
        assert_eq!(pairs[0].1.split('.').count(), 3);
    }

    #[tokio::test]
    async fn consent_rejects_partial_key_delivery_pair() {
        let Some((app, client_id, token)) = app_with_client_and_account().await else {
            return;
        };
        let state = state_token(&app, &client_id, Some(keys_jwk()));

        // thumbprint without keys_jwe
        let (status, body) = post_json(
            &app,
            "/oauth/consent",
            Some(&token),
            &json!({
                "oauth_state": state.clone(),
                "approved": true,
                "keys_jwk_thumbprint": "irrelevant",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body["error_description"],
            "keys_jwe and keys_jwk_thumbprint must be supplied together"
        );

        // keys_jwe without thumbprint
        let (status, _) = post_json(
            &app,
            "/oauth/consent",
            Some(&token),
            &json!({
                "oauth_state": state,
                "approved": true,
                "keys_jwe": "some-jwe",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn consent_requires_key_delivery_for_the_sync_flow() {
        let Some((app, client_id, token)) = app_with_client_and_account().await else {
            return;
        };
        // The signed state carries a recipient and the sync scope, but the
        // consent posts no key delivery: a silent downgrade must fail loudly.
        let state = state_token(&app, &client_id, Some(keys_jwk()));

        let (status, body) = post_json(
            &app,
            "/oauth/consent",
            Some(&token),
            &json!({
                "oauth_state": state,
                "approved": true,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body["error_description"],
            "keys_jwe and keys_jwk_thumbprint must be supplied together"
        );
    }

    async fn app_with_client_and_account() -> Option<(TestApp, String, String)> {
        let app = test_app().await?;
        let client_id = Uuid::new_v4();
        app.storage
            .create_oauth_client(&OAuthClient {
                id: client_id,
                name: "Test Client".to_owned(),
                secret_hash: None,
                redirect_uris: vec![REDIRECT_URI.to_owned()],
                allowed_scopes: vec!["openid".to_owned(), "sync".to_owned()],
                created_at: chrono::Utc::now(),
            })
            .await
            .expect("create client");

        let account = app
            .storage
            .get_or_create_account(TEST_ISSUER, "consenter", "consenter@example.test")
            .await
            .expect("create account");
        let token = app.auth_token(&account.id.to_string());
        Some((app, client_id.to_string(), token))
    }

    fn state_token(app: &TestApp, client_id: &str, keys_jwk: Option<serde_json::Value>) -> String {
        app.jwt
            .create_oauth_state_token(OAuthStateClaims::new(
                client_id.to_owned(),
                REDIRECT_URI.to_owned(),
                "openid sync".to_owned(),
                "client-state".to_owned(),
                "challenge".to_owned(),
                "S256".to_owned(),
                keys_jwk,
            ))
            .expect("state token")
    }

    #[tokio::test]
    async fn consent_rejects_thumbprint_that_does_not_match_signed_recipient() {
        let Some((app, client_id, token)) = app_with_client_and_account().await else {
            return;
        };
        let state = state_token(&app, &client_id, Some(keys_jwk()));

        let (status, body) = post_json(
            &app,
            "/oauth/consent",
            Some(&token),
            &json!({
                "oauth_state": state,
                "approved": true,
                "keys_jwe": "some-jwe",
                "keys_jwk_thumbprint": "attacker-chosen-thumbprint",
            }),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body["error_description"],
            "keys_jwk_thumbprint does not match the authorization request"
        );
    }

    #[tokio::test]
    async fn consent_accepts_thumbprint_matching_signed_recipient() {
        let Some((app, client_id, token)) = app_with_client_and_account().await else {
            return;
        };
        let jwk = keys_jwk();
        let state = state_token(&app, &client_id, Some(jwk.clone()));
        let thumbprint = jwk_thumbprint_b64(&jwk).expect("thumbprint");

        let (status, body) = post_json(
            &app,
            "/oauth/consent",
            Some(&token),
            &json!({
                "oauth_state": state,
                "approved": true,
                "keys_jwe": "some-jwe",
                "keys_jwk_thumbprint": thumbprint,
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "body: {body}");
        let redirect = body["redirect_uri"].as_str().expect("redirect");
        assert!(redirect.starts_with(REDIRECT_URI));
        assert!(redirect.contains("code="));
    }

    #[tokio::test]
    async fn consent_rejects_key_delivery_without_a_signed_recipient() {
        let Some((app, client_id, token)) = app_with_client_and_account().await else {
            return;
        };
        let state = state_token(&app, &client_id, None);

        let (status, body) = post_json(
            &app,
            "/oauth/consent",
            Some(&token),
            &json!({
                "oauth_state": state,
                "approved": true,
                "keys_jwe": "some-jwe",
                "keys_jwk_thumbprint": "whatever",
            }),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body["error_description"],
            "authorization request did not include a key recipient"
        );
    }

    #[tokio::test]
    async fn consent_context_returns_fields_from_the_signed_state() {
        let Some((app, client_id, token)) = app_with_client_and_account().await else {
            return;
        };
        let state = state_token(&app, &client_id, Some(keys_jwk()));

        let (status, body) = get_json(
            &app,
            &format!("/oauth/consent-context?oauth_state={state}"),
            Some(&token),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["client_id"], client_id);
        assert_eq!(body["client_name"], "Test Client");
        assert_eq!(body["scope"], "openid sync");
        assert_eq!(body["redirect_uri"], REDIRECT_URI);
        assert_eq!(body["keys_jwk"]["kty"], "EC");
    }

    #[tokio::test]
    async fn consent_context_rejects_invalid_state() {
        let Some((app, _client_id, token)) = app_with_client_and_account().await else {
            return;
        };
        let (status, _) = get_json(
            &app,
            "/oauth/consent-context?oauth_state=not-a-jwt",
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn consent_context_requires_authentication() {
        let Some((app, client_id, _token)) = app_with_client_and_account().await else {
            return;
        };
        let state = state_token(&app, &client_id, None);
        let (status, _) = get_json(
            &app,
            &format!("/oauth/consent-context?oauth_state={state}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}

#[cfg(test)]
mod refresh_tests {
    use axum::http::StatusCode;

    use crate::test_support::{post_form, test_app};

    use super::*;

    const REDIRECT_URI: &str = "http://localhost:5381/";

    /// Seed client + account + grant + one active refresh token; return
    /// (client_id, raw_refresh_token).
    async fn seed_refresh_token(app: &crate::test_support::TestApp) -> (String, String) {
        let client_id = Uuid::new_v4();
        app.storage
            .create_oauth_client(&OAuthClient {
                id: client_id,
                name: "refresh test client".to_owned(),
                secret_hash: None,
                redirect_uris: vec![REDIRECT_URI.to_owned()],
                allowed_scopes: vec!["openid".to_owned()],
                created_at: chrono::Utc::now(),
            })
            .await
            .expect("create client");
        let tail = &client_id.simple().to_string()[..12];
        let account = app
            .storage
            .get_or_create_account(
                crate::test_support::TEST_ISSUER,
                &format!("user{tail}"),
                &format!("user{tail}@example.test"),
            )
            .await
            .expect("create account");
        let grant = app
            .storage
            .get_or_create_oauth_grant(client_id, account.id, "openid")
            .await
            .expect("create grant");

        let raw = generate_random_token();
        let now = chrono::Utc::now();
        app.storage
            .create_refresh_token(&OAuthRefreshToken {
                id: Uuid::new_v4(),
                grant_id: grant.id,
                token_hash: sha256_hash(raw.as_bytes()),
                created_at: now,
                expires_at: now + chrono::Duration::days(1),
            })
            .await
            .expect("create refresh token");
        (client_id.to_string(), raw)
    }

    fn refresh_form(client_id: &str, token: &str) -> String {
        format!(
            "grant_type=refresh_token&refresh_token={}&client_id={}",
            token, client_id
        )
    }

    #[tokio::test]
    async fn sequential_reuse_of_rotated_token_revokes_surviving_family() {
        let Some(app) = test_app().await else {
            return;
        };
        let (client_id, raw1) = seed_refresh_token(&app).await;

        // Legitimate rotation.
        let (status, body) =
            post_form(&app, "/oauth/token", None, &refresh_form(&client_id, &raw1)).await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        let raw2 = body["refresh_token"]
            .as_str()
            .expect("new token")
            .to_owned();

        // AUD-004 sequential reuse: the already-rotated token is presented
        // again (a copied token used by its thief, or a stale tab). The
        // surviving replacement must be revoked, not left active. 400 per
        // RFC 6749; the description carries the reuse signal.
        let (status, body) =
            post_form(&app, "/oauth/token", None, &refresh_form(&client_id, &raw1)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
        assert_eq!(body["error"], "invalid_grant");
        assert!(
            body["error_description"]
                .as_str()
                .unwrap_or_default()
                .contains("reuse"),
            "body: {body}"
        );

        // The replacement family is dead. A revoked token was deleted
        // without being recorded as used, so it presents as a plain
        // invalid_grant (400) rather than a reuse detection (401).
        let (status, body) =
            post_form(&app, "/oauth/token", None, &refresh_form(&client_id, &raw2)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
        assert_eq!(body["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn concurrent_presentation_of_one_token_kills_family() {
        let Some(app) = test_app().await else {
            return;
        };
        let (client_id, raw1) = seed_refresh_token(&app).await;

        // Two in-flight refreshes presenting the same token: exactly one
        // rotation can win; the loser's duplicate insert must revoke the
        // family (including the winner's fresh replacement) instead of
        // erroring with a broken transaction and leaving it alive.
        let (r1, r2) = {
            let form = refresh_form(&client_id, &raw1);
            tokio::join!(
                post_form(&app, "/oauth/token", None, &form),
                post_form(&app, "/oauth/token", None, &form),
            )
        };
        let ok_count = usize::from(r1.0 == StatusCode::OK) + usize::from(r2.0 == StatusCode::OK);
        assert_eq!(ok_count, 1, "responses: {r1:?} {r2:?}");
        let raw2 = if r1.0 == StatusCode::OK { r1.1 } else { r2.1 }["refresh_token"]
            .as_str()
            .expect("new token")
            .to_owned();

        // Family revoked: the winner's replacement no longer refreshes.
        let (status, body) =
            post_form(&app, "/oauth/token", None, &refresh_form(&client_id, &raw2)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
        assert_eq!(body["error"], "invalid_grant");
    }

    /// Seed a client + account + refreshable grant with an explicit grant
    /// scope and client allowed-scopes (storage-level grant creation does
    /// not re-validate policy, which is what these tests vary).
    async fn seed_scoped_refresh(
        app: &crate::test_support::TestApp,
        allowed: &[&str],
        grant_scope: &str,
    ) -> (String, String, Uuid) {
        let client_id = Uuid::new_v4();
        app.storage
            .create_oauth_client(&OAuthClient {
                id: client_id,
                name: "scope test client".to_owned(),
                secret_hash: None,
                redirect_uris: vec![REDIRECT_URI.to_owned()],
                allowed_scopes: allowed.iter().map(|s| s.to_string()).collect(),
                created_at: chrono::Utc::now(),
            })
            .await
            .expect("create client");
        let tail = &client_id.simple().to_string()[..12];
        let account = app
            .storage
            .get_or_create_account(
                crate::test_support::TEST_ISSUER,
                &format!("user{tail}"),
                &format!("user{tail}@example.test"),
            )
            .await
            .expect("create account");
        let grant = app
            .storage
            .get_or_create_oauth_grant(client_id, account.id, grant_scope)
            .await
            .expect("create grant");

        let raw = generate_random_token();
        let now = chrono::Utc::now();
        app.storage
            .create_refresh_token(&OAuthRefreshToken {
                id: Uuid::new_v4(),
                grant_id: grant.id,
                token_hash: sha256_hash(raw.as_bytes()),
                created_at: now,
                expires_at: now + chrono::Duration::days(1),
            })
            .await
            .expect("create refresh token");
        (client_id.to_string(), raw, account.id)
    }

    #[tokio::test]
    async fn refresh_grants_the_latest_authorized_scope_not_the_first() {
        // AUD-013: a broad consent followed by a later narrow authorization
        // must not let refresh resurrect the broad scope.
        let Some(app) = test_app().await else {
            return;
        };
        let (client_id, raw, account_id) =
            seed_scoped_refresh(&app, &["openid", "sync"], "openid sync").await;

        // A later, narrower authorization for the same account+client (the
        // code-exchange path): the stored grant must track it.
        let narrow = app
            .storage
            .get_or_create_oauth_grant(Uuid::parse_str(&client_id).unwrap(), account_id, "openid")
            .await
            .expect("narrow authorization");
        assert_eq!(narrow.scope, "openid", "grant must track the latest scope");

        let (status, body) =
            post_form(&app, "/oauth/token", None, &refresh_form(&client_id, &raw)).await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(
            body["scope"], "openid",
            "refresh must not regain the broad scope: {body}"
        );
    }

    #[tokio::test]
    async fn refresh_fails_when_the_client_lost_the_capability() {
        // AUD-013: a capability withdrawn from the client after consent must
        // stop flowing on refresh.
        let Some(app) = test_app().await else {
            return;
        };
        // Grant (storage-level) holds "openid sync", but the client's policy
        // only permits "openid".
        let (client_id, raw, _account_id) =
            seed_scoped_refresh(&app, &["openid"], "openid sync").await;

        let (status, body) =
            post_form(&app, "/oauth/token", None, &refresh_form(&client_id, &raw)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
        assert_eq!(body["error"], "invalid_grant");
        assert!(
            body["error_description"]
                .as_str()
                .unwrap_or_default()
                .contains("no longer permitted"),
            "body: {body}"
        );
    }
}

#[cfg(test)]
mod consent_bundle_tests {
    use base64::engine::general_purpose::STANDARD as B64;
    use serde_json::json;

    use crate::test_support::{get_json, post_json, test_app};

    use super::*;

    const REDIRECT_URI: &str = "http://localhost:5381/";

    async fn seed() -> Option<(crate::test_support::TestApp, String, String)> {
        let app = test_app().await?;
        let client_id = Uuid::new_v4();
        app.storage
            .create_oauth_client(&OAuthClient {
                id: client_id,
                name: "bundle client".to_owned(),
                secret_hash: None,
                redirect_uris: vec![REDIRECT_URI.to_owned()],
                allowed_scopes: vec!["openid".to_owned(), "sync".to_owned()],
                created_at: chrono::Utc::now(),
            })
            .await
            .expect("create client");
        let account = app
            .storage
            .get_or_create_account(
                crate::test_support::TEST_ISSUER,
                "bundle",
                "bundle@example.test",
            )
            .await
            .expect("create account");
        let token = app.auth_token(&account.id.to_string());
        Some((app, client_id.to_string(), token))
    }

    fn consent_body(state: &str, wrapped: &[u8], blob: &str) -> serde_json::Value {
        consent_body_with_root_version(state, wrapped, blob, 0)
    }

    fn consent_body_with_root_version(
        state: &str,
        wrapped: &[u8],
        blob: &str,
        root_key_version: i64,
    ) -> serde_json::Value {
        json!({
            "oauth_state": state,
            "approved": true,
            "wrapped_scoped_key": B64.encode(wrapped),
            "app_keypair_blob": blob,
            "root_key_version": root_key_version,
            // Real P-256 point (validate_p256_public_key checks on-curve).
            "app_public_key_jwk": json!({
                "kty": "EC",
                "crv": "P-256",
                "x": "-fdJbZAPB-1JvgW0Z-yAicImzBmEkhx396ojqztJHFw",
                "y": "DZagJ-DypVyEsBj3y3CdosboodfJAP9u9Z4hItYM4NM",
            }).to_string(),
        })
    }

    fn state_for(app: &crate::test_support::TestApp, client_id: &str) -> String {
        app.jwt
            .create_oauth_state_token(OAuthStateClaims::new(
                client_id.to_owned(),
                REDIRECT_URI.to_owned(),
                "openid".to_owned(),
                "client-state".to_owned(),
                "challenge".to_owned(),
                "S256".to_owned(),
                None,
            ))
            .expect("state token")
    }

    #[tokio::test]
    async fn consent_bundle_installs_atomically_on_empty_grant() {
        let Some((app, client_id, token)) = seed().await else {
            return;
        };
        let state = state_for(&app, &client_id);
        let wrapped = vec![7u8; WRAPPED_SCOPED_KEY_SIZE];
        let (status, body) = post_json(
            &app,
            "/oauth/consent",
            Some(&token),
            &consent_body(&state, &wrapped, "blob-v1"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");

        // The bundle landed together.
        let (status, body) = get_json(
            &app,
            &format!("/oauth/grant-keypair?client_id={client_id}"),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["app_keypair_blob"], "blob-v1");
        assert_eq!(body["wrapped_scoped_key"], B64.encode(&wrapped));
    }

    #[tokio::test]
    async fn consent_bundle_rejects_material_derived_under_rotated_root() {
        let Some((app, client_id, token)) = seed().await else {
            return;
        };
        let state = state_for(&app, &client_id);
        let wrapped = vec![7u8; WRAPPED_SCOPED_KEY_SIZE];

        // AUD-008/009 residual: the account's root key rotated (bump the
        // committed version) after this client derived its key material.
        // Installing the bundle would strand the grant under a root
        // nobody holds anymore.
        // The interleaving under test only needs the committed version to
        // have moved; bump it directly (a full API rotation needs valid
        // wrapped material unrelated to this check).
        sqlx::query("UPDATE accounts SET root_key_version = 1 WHERE email = 'bundle@example.test'")
            .execute(app.storage.pool())
            .await
            .expect("bump root version");

        let (status, body) = post_json(
            &app,
            "/oauth/consent",
            Some(&token),
            &consent_body_with_root_version(&state, &wrapped, "blob-stale", 0),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "body: {body}");
        assert!(body["error"]
            .as_str()
            .unwrap_or("")
            .contains("invalid_grant_state"));

        // Nothing was written for this grant.
        let (status, body) = get_json(
            &app,
            &format!("/oauth/grant-keypair?client_id={client_id}"),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["app_keypair_blob"], "");

        // A client that re-derived under the CURRENT root succeeds.
        let state = state_for(&app, &client_id);
        let (status, body) = post_json(
            &app,
            "/oauth/consent",
            Some(&token),
            &consent_body_with_root_version(&state, &wrapped, "blob-fresh", 1),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(body_text(&body), "");
    }

    fn body_text(body: &serde_json::Value) -> String {
        body.as_str().unwrap_or("").to_string()
    }

    #[tokio::test]
    async fn consent_bundle_rejects_stale_read_overwriting_keypair() {
        let Some((app, client_id, token)) = seed().await else {
            return;
        };
        // First consent installs W1 + keypair-v1.
        let state = state_for(&app, &client_id);
        let w1 = vec![1u8; WRAPPED_SCOPED_KEY_SIZE];
        let (status, body) = post_json(
            &app,
            "/oauth/consent",
            Some(&token),
            &consent_body(&state, &w1, "keypair-v1"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");

        // AUD-008: a client whose grant read failed generates a fresh
        // scoped key and submits W2 + keypair-v2. The server must reject:
        // overwriting the keypair under a different wrapper strands the
        // existing key material.
        let state2 = state_for(&app, &client_id);
        let w2 = vec![2u8; WRAPPED_SCOPED_KEY_SIZE];
        let (status, body) = post_json(
            &app,
            "/oauth/consent",
            Some(&token),
            &consent_body(&state2, &w2, "keypair-v2"),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "body: {body}");
        assert_eq!(body["error"], "invalid_grant_state");

        // Stored state unchanged: W1 + keypair-v1 intact.
        let (status, body) = get_json(
            &app,
            &format!("/oauth/grant-keypair?client_id={client_id}"),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["app_keypair_blob"], "keypair-v1");
        assert_eq!(body["wrapped_scoped_key"], B64.encode(&w1));

        // A consistent resubmission (same wrapper) replaces the keypair.
        let state3 = state_for(&app, &client_id);
        let (status, body) = post_json(
            &app,
            "/oauth/consent",
            Some(&token),
            &consent_body(&state3, &w1, "keypair-v1b"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        let (_, body) = get_json(
            &app,
            &format!("/oauth/grant-keypair?client_id={client_id}"),
            Some(&token),
        )
        .await;
        assert_eq!(body["app_keypair_blob"], "keypair-v1b");
        assert_eq!(body["wrapped_scoped_key"], B64.encode(&w1));
    }

    #[tokio::test]
    async fn consent_keypair_without_wrapped_key_is_rejected() {
        let Some((app, client_id, token)) = seed().await else {
            return;
        };
        let state = state_for(&app, &client_id);
        let mut body = consent_body(&state, &[0u8; WRAPPED_SCOPED_KEY_SIZE], "blob");
        body.as_object_mut().unwrap().remove("wrapped_scoped_key");
        let (status, body) = post_json(&app, "/oauth/consent", Some(&token), &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
        assert!(
            body["error_description"]
                .as_str()
                .unwrap_or_default()
                .contains("atomically"),
            "body: {body}"
        );
    }
}
