use super::super::test_support::{test_storage, TEST_ISSUER};
use super::*;

const WINDOW: Duration = Duration::from_secs(300);

#[tokio::test]
async fn login_threshold_escalation_and_identity_isolation() {
    let Some(storage) = test_storage().await else {
        return;
    };
    storage
        .check_login_allowed(TEST_ISSUER, "alice")
        .await
        .unwrap();
    for seconds in [900, 3600, 86400, 86400] {
        for _ in 0..2 {
            assert_eq!(
                storage
                    .record_failed_login(TEST_ISSUER, "alice", 3, WINDOW)
                    .await
                    .unwrap(),
                None
            );
        }
        assert_eq!(
            storage
                .record_failed_login(TEST_ISSUER, "alice", 3, WINDOW)
                .await
                .unwrap(),
            Some(Duration::from_secs(seconds))
        );
        assert!(matches!(
            storage.check_login_allowed(TEST_ISSUER, "alice").await,
            Err(StorageError::LoginRateLimited)
        ));
        storage
            .check_login_allowed(TEST_ISSUER, "bob")
            .await
            .unwrap();
        storage
            .check_login_allowed("https://other.test", "alice")
            .await
            .unwrap();
        storage
            .clear_login_attempts(TEST_ISSUER, "alice")
            .await
            .unwrap();
        storage
            .check_login_allowed(TEST_ISSUER, "alice")
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn first_failure_after_success_or_lockout_starts_a_new_window() {
    let Some(storage) = test_storage().await else {
        return;
    };
    for after_lockout in [false, true] {
        storage
            .record_failed_login(
                TEST_ISSUER,
                "alice",
                if after_lockout { 1 } else { 3 },
                WINDOW,
            )
            .await
            .unwrap();
        if !after_lockout {
            storage
                .clear_login_attempts(TEST_ISSUER, "alice")
                .await
                .unwrap();
        }
        storage
            .record_failed_login(TEST_ISSUER, "alice", 3, WINDOW)
            .await
            .unwrap();
        let started: Option<chrono::DateTime<Utc>> = sqlx::query_scalar(
            "SELECT first_failed_at FROM login_attempts WHERE issuer = $1 AND username = 'alice'",
        )
        .bind(TEST_ISSUER)
        .fetch_one(&storage.pool)
        .await
        .unwrap();
        assert!(
            started.is_some(),
            "failure after reset must start the counting window"
        );
        // Advance the stored window instead of sleeping.
        sqlx::query("UPDATE login_attempts SET first_failed_at = NOW() - INTERVAL '10 minutes', locked_until = NOW() - INTERVAL '1 second'")
            .execute(&storage.pool).await.unwrap();
        storage
            .check_login_allowed(TEST_ISSUER, "alice")
            .await
            .unwrap();
        assert_eq!(
            storage
                .record_failed_login(TEST_ISSUER, "alice", 3, WINDOW)
                .await
                .unwrap(),
            None
        );
        let count: i32 = sqlx::query_scalar(
            "SELECT failed_count FROM login_attempts WHERE issuer = $1 AND username = 'alice'",
        )
        .bind(TEST_ISSUER)
        .fetch_one(&storage.pool)
        .await
        .unwrap();
        assert_eq!(count, 1);
    }
}

#[tokio::test]
async fn recovery_limit_is_atomic_and_resets_after_window() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let mut tasks = tokio::task::JoinSet::new();
    // Share the pool, so requests really contend on the same identity.
    for _ in 0..12 {
        let storage = PostgresStorage::new(storage.pool.clone());
        tasks.spawn(async move {
            storage
                .check_and_increment_recovery_rate("alice@example.test", 3, WINDOW, b"secret")
                .await
        });
    }
    let mut accepted = 0;
    while let Some(result) = tasks.join_next().await {
        match result.unwrap() {
            Ok(()) => accepted += 1,
            Err(StorageError::RecoveryRateLimited) => {}
            other => panic!("unexpected result: {other:?}"),
        }
    }
    assert_eq!(accepted, 3);
    storage
        .check_and_increment_recovery_rate("bob@example.test", 3, WINDOW, b"secret")
        .await
        .unwrap();
    sqlx::query("UPDATE recovery_requests SET window_start = NOW() - INTERVAL '10 minutes'")
        .execute(&storage.pool)
        .await
        .unwrap();
    storage
        .check_and_increment_recovery_rate("alice@example.test", 3, WINDOW, b"secret")
        .await
        .unwrap();
}
