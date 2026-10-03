use super::test_support::*;
use crate::CleanupStorage;
use std::time::Duration;
use uuid::Uuid;

#[tokio::test]
async fn cleanup_removes_only_expired_records_and_retains_replay_evidence() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let account = create_account(&storage).await;
    let client: Uuid =
        sqlx::query_scalar("INSERT INTO oauth_clients (name) VALUES ('cleanup') RETURNING id")
            .fetch_one(storage.pool())
            .await
            .unwrap();
    let grant: Uuid = sqlx::query_scalar("INSERT INTO oauth_grants (client_id, account_id, scope) VALUES ($1, $2, 'sync') RETURNING id").bind(client).bind(account.id).fetch_one(storage.pool()).await.unwrap();
    // Keep expiry far enough from wall-clock time that slow CI cannot cross it.
    for (label, expiry) in [
        ("expired", chrono::Utc::now() - chrono::Duration::hours(1)),
        ("live", chrono::Utc::now() + chrono::Duration::days(1)),
    ] {
        sqlx::query("INSERT INTO registration_states (id, account_id, username, expires_at) VALUES ($1, $2, $3, $4)").bind(Uuid::new_v4()).bind(account.id).bind(label).bind(expiry).execute(storage.pool()).await.unwrap();
        sqlx::query("INSERT INTO login_states (id, account_id, username, state, expires_at) VALUES ($1, $2, $3, $4, $5)").bind(Uuid::new_v4()).bind(account.id).bind(label).bind(b"state".as_slice()).bind(expiry).execute(storage.pool()).await.unwrap();
        sqlx::query("INSERT INTO oauth_codes (code, client_id, account_id, redirect_uri, scope, code_challenge, expires_at) VALUES ($1, $2, $3, 'https://example.test', 'sync', 'challenge', $4)").bind(label).bind(client).bind(account.id).bind(expiry).execute(storage.pool()).await.unwrap();
        sqlx::query("INSERT INTO oauth_refresh_tokens (grant_id, token_hash, expires_at) VALUES ($1, $2, $3)").bind(grant).bind(label.as_bytes()).bind(expiry).execute(storage.pool()).await.unwrap();
        sqlx::query("INSERT INTO email_verification_codes (email, code_hash, purpose, expires_at) VALUES ($1, $2, 'registration', $3)").bind(label).bind(label.as_bytes()).bind(expiry).execute(storage.pool()).await.unwrap();
        sqlx::query("INSERT INTO used_verification_tokens (jti, expires_at) VALUES ($1, $2)")
            .bind(label)
            .bind(expiry)
            .execute(storage.pool())
            .await
            .unwrap();
    }
    for (label, age) in [("old", 8), ("recent", 6), ("now", 0)] {
        sqlx::query(
            "INSERT INTO used_refresh_tokens (token_hash, grant_id, used_at) VALUES ($1, $2, $3)",
        )
        .bind(label.as_bytes())
        .bind(grant)
        .bind(chrono::Utc::now() - chrono::Duration::days(age))
        .execute(storage.pool())
        .await
        .unwrap();
    }
    for _ in 0..2 {
        // Repeated cleanup is harmless.
        storage.cleanup_expired_states().await.unwrap();
        storage.cleanup_expired_oauth_codes().await.unwrap();
        storage.cleanup_expired_refresh_tokens().await.unwrap();
        storage.cleanup_expired_verification_codes().await.unwrap();
        storage.cleanup_expired_verification_tokens().await.unwrap();
        storage
            .cleanup_used_refresh_tokens(Duration::from_secs(7 * 86400))
            .await
            .unwrap();
        for (table, column, bytes) in [
            ("registration_states", "username", false),
            ("login_states", "username", false),
            ("oauth_codes", "code", false),
            ("oauth_refresh_tokens", "token_hash", true),
            ("email_verification_codes", "email", false),
            ("used_verification_tokens", "jti", false),
        ] {
            let column = if bytes {
                format!("convert_from({column}, 'UTF8')")
            } else {
                column.to_owned()
            };
            let remaining: Vec<String> =
                sqlx::query_scalar(&format!("SELECT {column} FROM {table}"))
                    .fetch_all(storage.pool())
                    .await
                    .unwrap();
            assert_eq!(remaining, vec!["live"], "{table}");
        }
        let retained: Vec<String> = sqlx::query_scalar(
            "SELECT convert_from(token_hash, 'UTF8') FROM used_refresh_tokens ORDER BY used_at",
        )
        .fetch_all(storage.pool())
        .await
        .unwrap();
        assert_eq!(retained, vec!["recent", "now"]);
        assert!(storage.get_account_by_id(account.id).await.is_ok());
    }
}
