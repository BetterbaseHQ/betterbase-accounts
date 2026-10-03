//! Bootstrap and selection contracts, including concurrent first startup.
use super::{test_support::test_storage, PostgresStorage};
use crate::{JwtKeyStorage, OAuthSigningKeyStorage, StorageError};
use sqlx::Connection;

#[tokio::test]
async fn jwt_keys_bootstrap_once_and_select_current_and_historical_keys() {
    let Some(storage) = test_storage().await else {
        return;
    };
    assert!(matches!(
        storage.get_current_jwt_key().await,
        Err(StorageError::KeyNotFound)
    ));
    assert!(matches!(
        storage.get_jwt_key_by_id(123).await,
        Err(StorageError::KeyNotFound)
    ));
    storage.ensure_jwt_key(&[1; 32]).await.unwrap();
    let first = storage.get_current_jwt_key().await.unwrap();
    storage.ensure_jwt_key(&[2; 32]).await.unwrap();
    assert_eq!(storage.get_current_jwt_key().await.unwrap().id, first.id);
    assert_eq!(
        storage.get_current_jwt_key().await.unwrap().secret_key,
        vec![1; 32]
    );
    let next: i32 =
        sqlx::query_scalar("INSERT INTO jwt_keys (secret_key) VALUES ($1) RETURNING id")
            .bind(vec![3u8; 32])
            .fetch_one(&storage.pool)
            .await
            .unwrap();
    assert_eq!(storage.get_current_jwt_key().await.unwrap().id, next);
    assert_eq!(
        storage
            .get_jwt_key_by_id(first.id)
            .await
            .unwrap()
            .secret_key,
        vec![1; 32]
    );
    assert_eq!(
        storage.get_jwt_key_by_id(next).await.unwrap().secret_key,
        vec![3; 32]
    );
}

#[tokio::test]
async fn signing_keys_bootstrap_once_and_preserve_key_pairs_and_history() {
    let Some(storage) = test_storage().await else {
        return;
    };
    assert!(storage.list_signing_keys().await.unwrap().is_empty());
    assert!(matches!(
        storage.get_current_signing_key().await,
        Err(StorageError::KeyNotFound)
    ));
    assert!(matches!(
        storage.get_signing_key_by_id(123).await,
        Err(StorageError::KeyNotFound)
    ));
    storage
        .ensure_oauth_signing_key(b"private-1", b"public-1")
        .await
        .unwrap();
    let first = storage.get_current_signing_key().await.unwrap();
    storage
        .ensure_oauth_signing_key(b"private-2", b"public-2")
        .await
        .unwrap();
    assert_eq!(storage.list_signing_keys().await.unwrap().len(), 1);
    let next: i32 = sqlx::query_scalar(
        "INSERT INTO oauth_signing_keys (private_key, public_key) VALUES ($1, $2) RETURNING id",
    )
    .bind(b"private-3".as_slice())
    .bind(b"public-3".as_slice())
    .fetch_one(&storage.pool)
    .await
    .unwrap();
    assert_eq!(storage.get_current_signing_key().await.unwrap().id, next);
    let old = storage.get_signing_key_by_id(first.id).await.unwrap();
    assert_eq!(old.private_key, b"private-1");
    assert_eq!(old.public_key, b"public-1");
    let keys = storage.list_signing_keys().await.unwrap();
    assert_eq!(
        keys.iter().map(|k| k.id).collect::<Vec<_>>(),
        vec![first.id, next]
    );
    assert_eq!(keys[1].private_key, b"private-3");
    assert_eq!(keys[1].public_key, b"public-3");
}

async fn concurrent_bootstrap(storage: PostgresStorage, table: &'static str) {
    // Hold both initializers at the database boundary. This reproduces the
    // empty-table INSERT/WHERE NOT EXISTS race without timing-based sleeps.
    let mut connection = sqlx::PgConnection::connect_with(&storage.pool.connect_options())
        .await
        .unwrap();
    let mut blocker = connection.begin().await.unwrap();
    sqlx::query(&format!("LOCK TABLE {table} IN SHARE MODE"))
        .execute(&mut *blocker)
        .await
        .unwrap();
    let mut tasks = tokio::task::JoinSet::new();
    for n in [1u8, 2] {
        let storage = storage.clone();
        tasks.spawn(async move {
            if table == "jwt_keys" {
                storage.ensure_jwt_key(&[n; 32]).await.unwrap();
                storage.get_current_jwt_key().await.unwrap().secret_key
            } else {
                storage
                    .ensure_oauth_signing_key(&[n; 32], &[n + 10; 32])
                    .await
                    .unwrap();
                let key = storage.get_current_signing_key().await.unwrap();
                assert_eq!(key.public_key, vec![key.private_key[0] + 10; 32]);
                key.private_key
            }
        });
    }
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM pg_locks WHERE relation = $1::regclass AND NOT granted",
            )
            .bind(table)
            .fetch_one(&mut *blocker)
            .await
            .unwrap();
            if waiting == 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("both initializers must reach the table lock");
    blocker.commit().await.unwrap();
    let first = tasks.join_next().await.unwrap().unwrap();
    let second = tasks.join_next().await.unwrap().unwrap();
    let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
        .fetch_one(&storage.pool)
        .await
        .unwrap();
    assert_eq!(count, 1, "concurrent startup must install exactly one key");
    assert_eq!(first, second, "all instances must load the same key");
}

#[tokio::test]
async fn concurrent_jwt_bootstrap_installs_one_key() {
    let Some(storage) = test_storage().await else {
        return;
    };
    concurrent_bootstrap(storage, "jwt_keys").await;
}

#[tokio::test]
async fn concurrent_signing_bootstrap_installs_one_key_pair() {
    let Some(storage) = test_storage().await else {
        return;
    };
    concurrent_bootstrap(storage, "oauth_signing_keys").await;
}
