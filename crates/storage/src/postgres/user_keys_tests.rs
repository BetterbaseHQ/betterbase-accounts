use super::super::test_support::{create_account, test_storage};
use super::*;
use crate::AccountStorage;

#[tokio::test]
async fn quota_allows_updates_and_is_scoped_to_account_and_service() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let account = create_account(&storage).await;
    for n in 0..10 {
        storage
            .store_user_key(account.id, "sync", &format!("key-{n}"), &[1; 16])
            .await
            .unwrap();
    }
    assert!(matches!(
        storage
            .store_user_key(account.id, "sync", "overflow", &[1; 16])
            .await,
        Err(StorageError::MaxKeysExceeded)
    ));
    storage
        .store_user_key(account.id, "sync", "key-0", &[2; 32])
        .await
        .unwrap();
    let key = storage
        .get_user_key(account.id, "sync", "key-0")
        .await
        .unwrap();
    assert_eq!(key.serial_number, 2);
    assert_eq!(key.key_material, vec![2; 32]);
    storage
        .store_user_key(account.id, "accounts", "key-0", &[3; 16])
        .await
        .unwrap();
    let other = storage
        .get_or_create_account("https://example.test", "bob", "bob@example.test")
        .await
        .unwrap();
    assert!(matches!(
        storage.get_user_key(other.id, "sync", "key-0").await,
        Err(StorageError::KeyNotFound)
    ));
    assert!(storage.list_user_keys(other.id).await.unwrap().is_empty());
    storage
        .store_user_key(other.id, "sync", "key-0", &[4; 16])
        .await
        .unwrap();
    assert_eq!(storage.list_user_keys(account.id).await.unwrap().len(), 11);
}

#[tokio::test]
async fn concurrent_inserts_cannot_exceed_key_quota() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let account = create_account(&storage).await;
    for n in 0..9 {
        storage
            .store_user_key(account.id, "sync", &format!("key-{n}"), &[1; 16])
            .await
            .unwrap();
    }
    let mut tasks = tokio::task::JoinSet::new();
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(12));
    for n in 0..12 {
        let storage = PostgresStorage::new(storage.pool.clone());
        let barrier = barrier.clone();
        tasks.spawn(async move {
            barrier.wait().await;
            storage
                .store_user_key(account.id, "sync", &format!("new-{n}"), &[1; 16])
                .await
        });
    }
    let mut accepted = 0;
    while let Some(result) = tasks.join_next().await {
        match result.unwrap() {
            Ok(()) => accepted += 1,
            Err(StorageError::MaxKeysExceeded) => {}
            other => panic!("unexpected result: {other:?}"),
        }
    }
    assert_eq!(accepted, 1);
    assert_eq!(storage.list_user_keys(account.id).await.unwrap().len(), 10);
}
