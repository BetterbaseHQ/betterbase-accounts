//! Well-known discovery endpoints: server metadata and WebFinger.

use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use betterbase_accounts_core::protocol::*;
use betterbase_accounts_storage::{AccountStorage, StorageError};
use serde::Deserialize;

use crate::state::{ApiConfig, AppState};

/// GET /.well-known/betterbase
///
/// The issuer is the identity anchor; service URLs (accounts endpoint,
/// jwks, webfinger) are advertised from `accounts_public_url`, which equals
/// the issuer unless the services are hosted on a different domain (e.g.
/// identities at `betterbase.dev`, API at `accounts.betterbase.dev`).
fn server_metadata(cfg: &ApiConfig) -> ServerMetadataResponse {
    ServerMetadataResponse {
        version: 1,
        federation: cfg.federation_ws_endpoint.is_some(),
        accounts_endpoint: cfg.accounts_public_url.clone(),
        sync_endpoint: cfg.sync_endpoint.clone(),
        federation_ws: cfg.federation_ws_endpoint.clone(),
        jwks_uri: format!("{}/.well-known/jwks.json", cfg.accounts_public_url),
        webfinger: format!("{}/.well-known/webfinger", cfg.accounts_public_url),
        protocols: vec!["betterbase-rpc-v1".to_string()],
        pow_required: cfg.cap_enabled,
        cap_key_id: (!cfg.cap_key_id.is_empty()).then(|| cfg.cap_key_id.clone()),
    }
}

pub async fn handle_server_metadata(State(state): State<AppState>) -> Response {
    let meta = server_metadata(&state.config);

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (
                header::CACHE_CONTROL,
                "public, max-age=3600, stale-while-revalidate=86400",
            ),
        ],
        Json(meta),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct WebFingerQuery {
    pub resource: Option<String>,
}

/// GET /.well-known/webfinger?resource=acct:user@domain
/// The self link points at the canonical profile URL on the hosted service
/// (accounts_public_url), which differs from the identity-anchor issuer
/// when the API is served on another domain.
fn webfinger_self_link(cfg: &ApiConfig, username: &str) -> WebFingerLink {
    WebFingerLink {
        rel: "self".to_string(),
        href: Some(format!("{}/v1/users/{}", cfg.accounts_public_url, username)),
    }
}

pub async fn handle_webfinger(
    State(state): State<AppState>,
    Query(query): Query<WebFingerQuery>,
) -> Response {
    let resource = match query.resource {
        Some(r) => r,
        None => {
            return (StatusCode::BAD_REQUEST, "resource parameter required").into_response();
        }
    };

    // Parse acct: URI
    let acct = match resource.strip_prefix("acct:") {
        Some(a) => a,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "only acct: resources are supported",
            )
                .into_response();
        }
    };

    let parts: Vec<&str> = acct.splitn(2, '@').collect();
    if parts.len() != 2 {
        return (StatusCode::BAD_REQUEST, "invalid acct: URI").into_response();
    }

    let (username, domain) = (parts[0], parts[1]);

    // Validate domain matches ours
    if domain != state.config.identity_domain {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }

    // Look up account
    let account = state
        .storage
        .get_account_by_username(&state.config.issuer, username)
        .await;

    let account = match account {
        Ok(a) => a,
        Err(StorageError::AccountNotFound) => {
            return (StatusCode::NOT_FOUND, "not found").into_response();
        }
        Err(e) => {
            tracing::error!("webfinger storage error: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    let mut links = vec![webfinger_self_link(&state.config, &account.username)];

    if let Some(sync) = &state.config.sync_endpoint {
        links.push(WebFingerLink {
            rel: "https://betterbase.dev/rel/sync".to_string(),
            href: Some(sync.clone()),
        });
    }

    let response = WebFingerResponse {
        subject: resource,
        links,
    };

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/jrd+json"),
            (header::CACHE_CONTROL, "public, max-age=300"),
        ],
        Json(response),
    )
        .into_response()
}

#[cfg(test)]
#[path = "discovery_tests.rs"]
mod tests;
