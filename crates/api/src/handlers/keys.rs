//! User key storage: list, store, and retrieve per-service keys.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use betterbase_accounts_core::protocol::*;
use betterbase_accounts_storage::UserKeyStorage;

use crate::{error::ApiError, handlers::auth::extract_auth, state::AppState};

const VALID_SERVICES: &[&str] = &["sync", "accounts"];
const MIN_KEY_MATERIAL_BYTES: usize = 16;
const MAX_KEY_MATERIAL_BYTES: usize = 128;

/// GET /v1/keys
pub async fn handle_list_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<UserKey>>, ApiError> {
    let auth_ctx = extract_auth(&state, &headers)?;

    let keys = state.storage.list_user_keys(auth_ctx.account_id).await?;

    let response: Vec<UserKey> = keys
        .into_iter()
        .map(|k| UserKey {
            service: k.service,
            key_name: k.key_name,
            key_material: hex::encode(&k.key_material),
            serial_number: k.serial_number,
            updated_at: k.updated_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(response))
}

/// PUT /v1/keys/{service}/{keyName}
pub async fn handle_store_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((service, key_name)): Path<(String, String)>,
    Json(req): Json<StoreKeyRequest>,
) -> Result<StatusCode, ApiError> {
    let auth_ctx = extract_auth(&state, &headers)?;

    // Validate service
    if !VALID_SERVICES.contains(&service.as_str()) {
        return Err(ApiError::bad_request(format!(
            "invalid service (must be one of: {})",
            VALID_SERVICES.join(", ")
        )));
    }

    // Validate key name (1-32 chars, alphanumeric + hyphens/underscores)
    if key_name.is_empty() || key_name.len() > 32 {
        return Err(ApiError::bad_request("key name must be 1-32 characters"));
    }

    // Decode and validate key material
    let key_bytes = hex::decode(&req.key_material)
        .map_err(|_| ApiError::bad_request("key_material must be hex-encoded"))?;
    if key_bytes.len() < MIN_KEY_MATERIAL_BYTES || key_bytes.len() > MAX_KEY_MATERIAL_BYTES {
        return Err(ApiError::bad_request(format!(
            "key_material must be {}-{} bytes",
            MIN_KEY_MATERIAL_BYTES, MAX_KEY_MATERIAL_BYTES
        )));
    }

    state
        .storage
        .store_user_key(auth_ctx.account_id, &service, &key_name, &key_bytes)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// GET /v1/keys/{service}/{keyName}
pub async fn handle_get_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((service, key_name)): Path<(String, String)>,
) -> Result<Json<UserKey>, ApiError> {
    let auth_ctx = extract_auth(&state, &headers)?;

    let k = state
        .storage
        .get_user_key(auth_ctx.account_id, &service, &key_name)
        .await?;

    Ok(Json(UserKey {
        service: k.service,
        key_name: k.key_name,
        key_material: hex::encode(&k.key_material),
        serial_number: k.serial_number,
        updated_at: k.updated_at.to_rfc3339(),
    }))
}
