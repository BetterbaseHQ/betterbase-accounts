//! Root key management: get/set wrapped root key, grant wrapped keys, rotation.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use less_accounts_core::protocol::*;
use less_accounts_storage::{
    CompositeStorage, GrantKeyUpdate as StorageGrantKeyUpdate, OAuthGrantStorage, RootKeyStorage,
};
use uuid::Uuid;

use crate::{error::ApiError, handlers::auth::extract_auth, state::AppState};

const WRAPPED_KEY_SIZE: usize = 41;

/// GET /v1/accounts/root-key
pub async fn handle_get_root_key(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<GetRootKeyResponse>, ApiError> {
    let auth_ctx = extract_auth(&state, &headers)?;

    let key = state
        .storage
        .get_wrapped_root_key(auth_ctx.account_id)
        .await?;

    Ok(Json(GetRootKeyResponse {
        wrapped_root_key: B64.encode(&key),
    }))
}

/// PUT /v1/accounts/root-key
pub async fn handle_set_root_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SetRootKeyRequest>,
) -> Result<StatusCode, ApiError> {
    let auth_ctx = extract_auth(&state, &headers)?;

    let key = B64
        .decode(&req.wrapped_root_key)
        .map_err(|_| ApiError::bad_request("invalid wrapped_root_key encoding"))?;
    if key.len() != WRAPPED_KEY_SIZE {
        return Err(ApiError::bad_request("wrapped_root_key must be 41 bytes"));
    }

    state
        .storage
        .set_wrapped_root_key(auth_ctx.account_id, &key)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// GET /v1/accounts/grants/wrapped-keys
pub async fn handle_get_grant_wrapped_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<GetGrantWrappedKeysResponse>, ApiError> {
    let auth_ctx = extract_auth(&state, &headers)?;

    let grants = state
        .storage
        .list_grants_for_account(auth_ctx.account_id)
        .await?;

    let grant_keys: Vec<GrantWrappedKey> = grants
        .into_iter()
        .filter_map(|g| {
            g.wrapped_scoped_key.map(|k| GrantWrappedKey {
                grant_id: g.id.to_string(),
                client_id: g.client_id.to_string(),
                wrapped_scoped_key: B64.encode(&k),
            })
        })
        .collect();

    Ok(Json(GetGrantWrappedKeysResponse { grants: grant_keys }))
}

/// PUT /v1/accounts/grants/wrapped-keys
pub async fn handle_update_grant_wrapped_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<UpdateGrantWrappedKeysRequest>,
) -> Result<StatusCode, ApiError> {
    let auth_ctx = extract_auth(&state, &headers)?;

    let mut updates = Vec::with_capacity(req.grants.len());
    for update in &req.grants {
        let grant_id = Uuid::parse_str(&update.grant_id)
            .map_err(|_| ApiError::bad_request("invalid grant_id"))?;

        // Verify ownership
        let grant = state.storage.get_oauth_grant(grant_id).await?;
        if grant.account_id != auth_ctx.account_id {
            return Err(ApiError::forbidden("grant does not belong to this account"));
        }

        let key = B64
            .decode(&update.wrapped_scoped_key)
            .map_err(|_| ApiError::bad_request("invalid wrapped_scoped_key encoding"))?;
        if key.len() != WRAPPED_KEY_SIZE {
            return Err(ApiError::bad_request("wrapped_scoped_key must be 41 bytes"));
        }

        updates.push(StorageGrantKeyUpdate {
            grant_id,
            wrapped_scoped_key: key,
        });
    }

    state
        .storage
        .batch_update_grant_wrapped_keys(&updates)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// POST /v1/accounts/rotate-root-key
pub async fn handle_rotate_root_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RotateRootKeyRequest>,
) -> Result<StatusCode, ApiError> {
    let auth_ctx = extract_auth(&state, &headers)?;

    let new_root_key = B64
        .decode(&req.wrapped_root_key)
        .map_err(|_| ApiError::bad_request("invalid wrapped_root_key encoding"))?;
    if new_root_key.len() != WRAPPED_KEY_SIZE {
        return Err(ApiError::bad_request("wrapped_root_key must be 41 bytes"));
    }

    let mut grant_updates = Vec::with_capacity(req.grants.len());
    for update in &req.grants {
        let grant_id = Uuid::parse_str(&update.grant_id)
            .map_err(|_| ApiError::bad_request("invalid grant_id"))?;

        let key = B64
            .decode(&update.wrapped_scoped_key)
            .map_err(|_| ApiError::bad_request("invalid wrapped_scoped_key encoding"))?;
        if key.len() != WRAPPED_KEY_SIZE {
            return Err(ApiError::bad_request("wrapped_scoped_key must be 41 bytes"));
        }

        grant_updates.push(StorageGrantKeyUpdate {
            grant_id,
            wrapped_scoped_key: key,
        });
    }

    let recovery_blob = if req.recovery_blob.is_empty() {
        vec![]
    } else {
        B64.decode(&req.recovery_blob)
            .map_err(|_| ApiError::bad_request("invalid recovery_blob encoding"))?
    };

    state
        .storage
        .rotate_root_key(
            auth_ctx.account_id,
            &new_root_key,
            &grant_updates,
            &recovery_blob,
        )
        .await?;

    Ok(StatusCode::NO_CONTENT)
}
