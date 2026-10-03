//! Upgrade populated historical schemas through the same migrator used at startup.
use super::{test_support::*, PostgresStorage};
use crate::{LoginStateStorage, OAuthGrantStorage};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

const DATA_TABLES: &[&str] = &[
    "accounts",
    "login_states",
    "registration_states",
    "user_keys",
    "oauth_clients",
    "oauth_grants",
    "oauth_codes",
    "oauth_refresh_tokens",
    "used_refresh_tokens",
    "recovery_blobs",
];

async fn snapshot(pool: &PgPool) -> Vec<Vec<Value>> {
    let mut rows = Vec::new();
    for table in DATA_TABLES {
        rows.push(sqlx::query_scalar(&format!("SELECT to_jsonb(t) - ARRAY['credentials_version', 'root_key_version'] FROM {table} t ORDER BY to_jsonb(t)::text"))
            .fetch_all(pool).await.unwrap());
    }
    rows
}

async fn seed(pool: &PgPool, version: i64) -> (Uuid, Uuid, Uuid, Uuid) {
    let account: Uuid = sqlx::query_scalar("INSERT INTO accounts (issuer, username, email, opaque_record, wrapped_root_key) VALUES ($1, 'legacy', 'legacy@example.com', 'opaque', 'root') RETURNING id")
        .bind(TEST_ISSUER).fetch_one(pool).await.unwrap();
    // An unfinished signup must stay unfinished after upgrading, too.
    sqlx::query("INSERT INTO accounts (issuer, username, email) VALUES ($1, 'reserved', 'reserved@example.com')").bind(TEST_ISSUER).execute(pool).await.unwrap();
    let login = Uuid::new_v4();
    sqlx::query("INSERT INTO login_states (id, account_id, username, state, expires_at) VALUES ($1, $2, 'legacy', 'login', NOW() + INTERVAL '1 hour')").bind(login).bind(account).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO login_states (id, username, state, expires_at) VALUES ($1, 'unknown', 'fake', NOW() + INTERVAL '1 hour')").bind(Uuid::new_v4()).execute(pool).await.unwrap();
    let registration = Uuid::new_v4();
    sqlx::query("INSERT INTO registration_states (id, account_id, username, expires_at) VALUES ($1, $2, 'legacy', NOW() + INTERVAL '1 hour')").bind(registration).bind(account).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO user_keys (account_id, service, key_name, key_material, serial_number) VALUES ($1, 'sync', 'key', 'encrypted', 42)").bind(account).execute(pool).await.unwrap();
    let client: Uuid = sqlx::query_scalar("INSERT INTO oauth_clients (name, redirect_uris, allowed_scopes) VALUES ('legacy', '[\"https://example.test/cb\"]', ARRAY['sync']) RETURNING id").fetch_one(pool).await.unwrap();
    let grant: Uuid = sqlx::query_scalar("INSERT INTO oauth_grants (client_id, account_id, scope, app_public_key, app_keypair_blob, wrapped_scoped_key, keys_jwk_thumbprint, mailbox_id) VALUES ($1, $2, 'openid sync', '{\"kty\":\"EC\"}', 'encrypted-bundle', 'wrapped', 'thumbprint', $3) RETURNING id")
        .bind(client).bind(account).bind("a".repeat(64)).fetch_one(pool).await.unwrap();
    sqlx::query("INSERT INTO oauth_codes (code, client_id, account_id, redirect_uri, scope, code_challenge, expires_at) VALUES ('code', $1, $2, 'https://example.test/cb', 'sync', 'challenge', NOW() + INTERVAL '1 hour')").bind(client).bind(account).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO oauth_refresh_tokens (grant_id, token_hash, expires_at) VALUES ($1, 'refresh', NOW() + INTERVAL '1 day')").bind(grant).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO used_refresh_tokens (token_hash, grant_id) VALUES ('used', $1)")
        .bind(grant)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO recovery_blobs (account_id, blob) VALUES ($1, 'recovery')")
        .bind(account)
        .execute(pool)
        .await
        .unwrap();
    if version >= 2 {
        sqlx::query("UPDATE accounts SET credentials_version = 7 WHERE id = $1")
            .bind(account)
            .execute(pool)
            .await
            .unwrap();
    }
    if version >= 3 {
        sqlx::query("UPDATE accounts SET root_key_version = 11 WHERE id = $1")
            .bind(account)
            .execute(pool)
            .await
            .unwrap();
    }
    if version >= 4 {
        sqlx::query("UPDATE login_states SET credentials_version = 7 WHERE id = $1")
            .bind(login)
            .execute(pool)
            .await
            .unwrap();
    }
    if version >= 5 {
        sqlx::query("UPDATE login_states SET root_key_version = 11 WHERE id = $1")
            .bind(login)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("UPDATE registration_states SET root_key_version = 11 WHERE id = $1")
            .bind(registration)
            .execute(pool)
            .await
            .unwrap();
    }
    (account, login, registration, grant)
}

#[tokio::test]
async fn every_historical_schema_upgrades_without_losing_data_or_resetting_versions() {
    let latest = sqlx::migrate!().iter().last().unwrap().version;
    for version in 1..=latest {
        let Some(storage) = test_storage_at(version).await else {
            return;
        };
        let (account_id, login_id, registration_id, grant_id) = seed(storage.pool(), version).await;
        let before = snapshot(storage.pool()).await;
        PostgresStorage::run_migrations(storage.pool())
            .await
            .unwrap();
        assert_eq!(
            snapshot(storage.pool()).await,
            before,
            "upgrade from {version} altered existing data"
        );
        let account = storage.get_account_by_id(account_id).await.unwrap();
        assert_eq!(
            account.credentials_version,
            if version >= 2 { 7 } else { 0 }
        );
        assert_eq!(account.root_key_version, if version >= 3 { 11 } else { 0 });
        let login = storage.get_login_state(login_id).await.unwrap();
        assert_eq!(login.credentials_version, if version >= 4 { 7 } else { 0 });
        assert_eq!(login.root_key_version, if version >= 5 { 11 } else { 0 });
        let registration = storage
            .get_registration_state(registration_id)
            .await
            .unwrap();
        assert_eq!(
            registration.root_key_version,
            if version >= 5 { 11 } else { 0 }
        );
        assert_eq!(
            storage
                .get_oauth_grant(grant_id)
                .await
                .unwrap()
                .app_keypair_blob
                .as_deref(),
            Some("encrypted-bundle")
        );
        let reserved = storage
            .get_account_by_username(TEST_ISSUER, "reserved")
            .await
            .unwrap();
        assert!(reserved.opaque_record.is_none());
        assert!(reserved.wrapped_root_key.is_none());
        let fresh = storage
            .get_or_create_account(TEST_ISSUER, "fresh", "fresh@example.com")
            .await
            .unwrap();
        assert_eq!((fresh.credentials_version, fresh.root_key_version), (0, 0));
        // Re-running startup must neither change data nor append duplicate history.
        let after = snapshot(storage.pool()).await;
        PostgresStorage::run_migrations(storage.pool())
            .await
            .unwrap();
        assert_eq!(snapshot(storage.pool()).await, after);
        let history: Vec<i64> = sqlx::query_scalar(
            "SELECT version FROM _sqlx_migrations WHERE success ORDER BY version",
        )
        .fetch_all(storage.pool())
        .await
        .unwrap();
        assert_eq!(history, (1..=latest).collect::<Vec<_>>());
        storage.pool().close().await;
    }
}

#[tokio::test]
async fn concurrent_startup_upgrades_apply_each_migration_once() {
    let Some(storage) = test_storage_at(1).await else {
        return;
    };
    seed(storage.pool(), 1).await;
    let before = snapshot(storage.pool()).await;
    let (first, second) = tokio::join!(
        PostgresStorage::run_migrations(storage.pool()),
        PostgresStorage::run_migrations(storage.pool())
    );
    first.unwrap();
    second.unwrap();
    assert_eq!(snapshot(storage.pool()).await, before);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations WHERE success")
        .fetch_one(storage.pool())
        .await
        .unwrap();
    assert_eq!(count, sqlx::migrate!().iter().count() as i64);
}

#[tokio::test]
async fn startup_rejects_changed_migration_history_before_applying_pending_changes() {
    let Some(storage) = test_storage_at(1).await else {
        return;
    };
    seed(storage.pool(), 1).await;
    let before = snapshot(storage.pool()).await;
    sqlx::query("UPDATE _sqlx_migrations SET checksum = 'changed'::bytea WHERE version = 1")
        .execute(storage.pool())
        .await
        .unwrap();
    let result = PostgresStorage::run_migrations(storage.pool()).await;
    assert!(
        matches!(result, Err(sqlx::Error::Migrate(error)) if matches!(*error, sqlx::migrate::MigrateError::VersionMismatch(1)))
    );
    assert_eq!(snapshot(storage.pool()).await, before);
    let versions: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM _sqlx_migrations ORDER BY version")
            .fetch_all(storage.pool())
            .await
            .unwrap();
    assert_eq!(versions, vec![1]);
}
