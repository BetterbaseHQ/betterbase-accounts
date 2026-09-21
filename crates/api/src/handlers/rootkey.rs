//! Root key management: get/set wrapped root key, grant wrapped keys, rotation.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use betterbase_accounts_core::protocol::*;
use betterbase_accounts_storage::{
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
    let auth_ctx = extract_auth(&state, &headers).await?;

    let (key, root_key_version) = state
        .storage
        .get_root_key_with_version(auth_ctx.account_id)
        .await?;

    Ok(Json(GetRootKeyResponse {
        wrapped_root_key: B64.encode(&key),
        root_key_version,
    }))
}

/// PUT /v1/accounts/root-key
pub async fn handle_set_root_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SetRootKeyRequest>,
) -> Result<StatusCode, ApiError> {
    let auth_ctx = extract_auth(&state, &headers).await?;

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
    let auth_ctx = extract_auth(&state, &headers).await?;

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
    let auth_ctx = extract_auth(&state, &headers).await?;

    // AUD-009 review: fence the rewrap against root rotations — wrappers
    // prepared under an older root must not overwrite a newer rotation's
    // rewraps.
    let (_, current_version) = state
        .storage
        .get_root_key_with_version(auth_ctx.account_id)
        .await?;
    if current_version != req.expected_root_version {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "root key changed since these wrappers were prepared — re-read and retry",
        ));
    }

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
    let auth_ctx = extract_auth(&state, &headers).await?;

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

        // Verify ownership — prevent IDOR attacks
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

    // AUD-009: completeness + CAS are enforced in storage — the rotation
    // locks the account's grant set, requires the submitted list to cover
    // it exactly, and compare-and-swaps on the root key version.
    state
        .storage
        .rotate_root_key(
            auth_ctx.account_id,
            req.expected_root_version,
            &new_root_key,
            &grant_updates,
            &recovery_blob,
        )
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod rotation_tests {
    use base64::engine::general_purpose::STANDARD as B64;
    use serde_json::json;

    use crate::test_support::{get_json, post_json, test_app, TEST_ISSUER};

    use super::*;

    use betterbase_accounts_storage::{
        AccountStorage, OAuthClient, OAuthClientStorage, OAuthGrantStorage, RecoveryStorage,
    };

    async fn seed() -> Option<crate::test_support::TestApp> {
        let app = test_app().await?;
        let account = app
            .storage
            .get_or_create_account(TEST_ISSUER, "rotator", "rotator@example.test")
            .await
            .expect("create account");
        let client_id = Uuid::new_v4();
        app.storage
            .create_oauth_client(&OAuthClient {
                id: client_id,
                name: "rot client".to_owned(),
                secret_hash: None,
                redirect_uris: vec!["http://localhost:5381/".to_owned()],
                allowed_scopes: vec!["openid".to_owned()],
                created_at: chrono::Utc::now(),
            })
            .await
            .expect("create client");
        app.storage
            .get_or_create_oauth_grant(client_id, account.id, "openid")
            .await
            .expect("create grant");
        app.storage
            .store_recovery_blob(account.id, b"old-recovery-blob")
            .await
            .expect("store recovery blob");
        Some(app)
    }

    fn rotate_body(version: i64, grant_ids: &[String]) -> serde_json::Value {
        json!({
            "wrapped_root_key": B64.encode(vec![9u8; WRAPPED_KEY_SIZE]),
            "expected_root_version": version,
            "grants": grant_ids.iter().map(|id| json!({
                "grant_id": id,
                "wrapped_scoped_key": B64.encode(vec![8u8; WRAPPED_KEY_SIZE]),
            })).collect::<Vec<_>>(),
            "recovery_blob": B64.encode(b"new-recovery-blob"),
        })
    }

    #[tokio::test]
    async fn rotation_with_current_version_and_full_grant_set_succeeds() {
        let Some(app) = seed().await else {
            return;
        };
        let account = app
            .storage
            .get_account_by_email(TEST_ISSUER, "rotator@example.test")
            .await
            .expect("account");
        let token = app.auth_token(&account.id.to_string());

        let (_, root) = get_json(&app, "/v1/accounts/root-key", Some(&token)).await;
        assert_eq!(root["root_key_version"], 0);
        let grants = app
            .storage
            .list_grants_for_account(account.id)
            .await
            .expect("grants");
        let ids: Vec<String> = grants.iter().map(|g| g.id.to_string()).collect();

        let (status, body) = post_json(
            &app,
            "/v1/accounts/rotate-root-key",
            Some(&token),
            &rotate_body(0, &ids),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "body: {body}");

        // Version advanced, root replaced, recovery blob replaced.
        let (_, root) = get_json(&app, "/v1/accounts/root-key", Some(&token)).await;
        assert_eq!(root["root_key_version"], 1);
        assert_eq!(
            root["wrapped_root_key"],
            B64.encode(vec![9u8; WRAPPED_KEY_SIZE])
        );
        let blob = app
            .storage
            .get_recovery_blob_by_email(TEST_ISSUER, "rotator@example.test")
            .await
            .expect("blob");
        assert_eq!(blob, b"new-recovery-blob".to_vec());
    }

    #[tokio::test]
    async fn rotation_prepared_against_stale_version_is_rejected() {
        let Some(app) = seed().await else {
            return;
        };
        let account = app
            .storage
            .get_account_by_email(TEST_ISSUER, "rotator@example.test")
            .await
            .expect("account");
        let token = app.auth_token(&account.id.to_string());
        let grants = app
            .storage
            .list_grants_for_account(account.id)
            .await
            .expect("grants");
        let ids: Vec<String> = grants.iter().map(|g| g.id.to_string()).collect();

        // First rotation wins and bumps the version to 1.
        let (status, _) = post_json(
            &app,
            "/v1/accounts/rotate-root-key",
            Some(&token),
            &rotate_body(0, &ids),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // A concurrent rotation prepared against version 0 must be
        // rejected, not overwrite the newer root (AUD-009 CAS).
        let (status, body) = post_json(
            &app,
            "/v1/accounts/rotate-root-key",
            Some(&token),
            &rotate_body(0, &ids),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "body: {body}");
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("root key changed"),
            "body: {body}"
        );
        let (_, root) = get_json(&app, "/v1/accounts/root-key", Some(&token)).await;
        assert_eq!(root["root_key_version"], 1);
    }

    #[tokio::test]
    async fn rotation_missing_a_grant_is_rejected_unchanged() {
        let Some(app) = seed().await else {
            return;
        };
        let account = app
            .storage
            .get_account_by_email(TEST_ISSUER, "rotator@example.test")
            .await
            .expect("account");
        let token = app.auth_token(&account.id.to_string());

        // A second grant appears after the client snapshotted the set —
        // submitting only the snapshotted (empty) list must be rejected:
        // committing it would strand every grant under the old root.
        let client_id = Uuid::new_v4();
        app.storage
            .create_oauth_client(&OAuthClient {
                id: client_id,
                name: "late client".to_owned(),
                secret_hash: None,
                redirect_uris: vec!["http://localhost:5381/".to_owned()],
                allowed_scopes: vec!["openid".to_owned()],
                created_at: chrono::Utc::now(),
            })
            .await
            .expect("create late client");
        app.storage
            .get_or_create_oauth_grant(client_id, account.id, "openid")
            .await
            .expect("create late grant");

        let (status, body) = post_json(
            &app,
            "/v1/accounts/rotate-root-key",
            Some(&token),
            &rotate_body(0, &[]),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "body: {body}");
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("every grant"),
            "body: {body}"
        );

        // Nothing changed: version still 0, root untouched.
        let (_, root) = get_json(&app, "/v1/accounts/root-key", Some(&token)).await;
        assert_eq!(root["root_key_version"], 0);
    }

    #[tokio::test]
    async fn rotation_without_recovery_blob_deletes_the_stale_one() {
        let Some(app) = seed().await else {
            return;
        };
        let account = app
            .storage
            .get_account_by_email(TEST_ISSUER, "rotator@example.test")
            .await
            .expect("account");
        let token = app.auth_token(&account.id.to_string());
        let grants = app
            .storage
            .list_grants_for_account(account.id)
            .await
            .expect("grants");
        let ids: Vec<String> = grants.iter().map(|g| g.id.to_string()).collect();

        let mut body = rotate_body(0, &ids);
        body["recovery_blob"] = json!("");
        let (status, body_resp) =
            post_json(&app, "/v1/accounts/rotate-root-key", Some(&token), &body).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "body: {body_resp}");

        // The old blob decrypts to the retired root — it must not survive
        // as a false recovery path.
        let blob = app
            .storage
            .get_recovery_blob_by_email(TEST_ISSUER, "rotator@example.test")
            .await;
        assert!(blob.is_err(), "stale recovery blob must be deleted");
    }
}
