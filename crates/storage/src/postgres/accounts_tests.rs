use uuid::Uuid;

use super::super::test_support::*;

#[tokio::test]
async fn get_or_create_and_fetch_account_roundtrip() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let created = storage
        .get_or_create_account(TEST_ISSUER, TEST_USERNAME, TEST_EMAIL)
        .await
        .expect("create account");

    assert_eq!(created.issuer, TEST_ISSUER);
    assert_eq!(created.username, TEST_USERNAME);
    assert_eq!(created.email, TEST_EMAIL);
    assert!(created.opaque_record.is_none());
    assert!(created.wrapped_root_key.is_none());

    let by_id = storage
        .get_account_by_id(created.id)
        .await
        .expect("get by id");
    assert_eq!(by_id.id, created.id);
    assert_eq!(by_id.email, TEST_EMAIL);

    let by_username = storage
        .get_account_by_username(TEST_ISSUER, TEST_USERNAME)
        .await
        .expect("get by username");
    assert_eq!(by_username.id, created.id);

    let by_email = storage
        .get_account_by_email(TEST_ISSUER, TEST_EMAIL)
        .await
        .expect("get by email");
    assert_eq!(by_email.id, created.id);
}

#[tokio::test]
async fn get_or_create_account_is_idempotent() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let first = storage
        .get_or_create_account(TEST_ISSUER, TEST_USERNAME, TEST_EMAIL)
        .await
        .expect("first create");
    let second = storage
        .get_or_create_account(TEST_ISSUER, TEST_USERNAME, TEST_EMAIL)
        .await
        .expect("second create");
    assert_eq!(first.id, second.id);
}

#[tokio::test]
async fn get_missing_account_returns_not_found() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let missing = Uuid::new_v4();
    assert!(matches!(
        storage.get_account_by_id(missing).await.unwrap_err(),
        StorageError::AccountNotFound
    ));
    assert!(matches!(
        storage
            .get_account_by_username(TEST_ISSUER, "nobody")
            .await
            .unwrap_err(),
        StorageError::AccountNotFound
    ));
    assert!(matches!(
        storage
            .get_account_by_email(TEST_ISSUER, "nobody@example.com")
            .await
            .unwrap_err(),
        StorageError::AccountNotFound
    ));
}

#[tokio::test]
async fn finalize_registration_with_root_key_roundtrip() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let account = create_account(&storage).await;
    let opaque_record = vec![0x01, 0x02, 0x03];
    let wrapped_root_key = vec![0xAA; 48];

    storage
        .finalize_registration_with_root_key(account.id, &opaque_record, &wrapped_root_key)
        .await
        .expect("finalize registration");

    let fetched = storage
        .get_account_by_id(account.id)
        .await
        .expect("get account");
    assert_eq!(
        fetched.opaque_record.as_deref(),
        Some(opaque_record.as_slice())
    );
    assert_eq!(
        fetched.wrapped_root_key.as_deref(),
        Some(wrapped_root_key.as_slice())
    );

    let key = storage
        .get_wrapped_root_key(account.id)
        .await
        .expect("get wrapped root key");
    assert_eq!(key, wrapped_root_key);
}

#[tokio::test]
async fn finalize_registration_for_missing_account_errors() {
    let Some(storage) = test_storage().await else {
        return;
    };
    assert!(matches!(
        storage
            .finalize_registration_with_root_key(Uuid::new_v4(), b"record", b"key")
            .await
            .unwrap_err(),
        StorageError::AccountNotFound
    ));
}

#[tokio::test]
async fn set_wrapped_root_key_roundtrip() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let account = create_account(&storage).await;
    assert!(matches!(
        storage.get_wrapped_root_key(account.id).await.unwrap_err(),
        StorageError::WrappedRootKeyNotFound
    ));

    let key = vec![0xBB; 32];
    storage
        .set_wrapped_root_key(account.id, &key)
        .await
        .expect("set wrapped root key");
    assert_eq!(storage.get_wrapped_root_key(account.id).await.unwrap(), key);

    let rotated = vec![0xCC; 32];
    storage
        .set_wrapped_root_key(account.id, &rotated)
        .await
        .expect("rotate wrapped root key");
    assert_eq!(
        storage.get_wrapped_root_key(account.id).await.unwrap(),
        rotated
    );
}

#[tokio::test]
async fn delete_account_removes_it() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let account = create_account(&storage).await;
    storage.delete_account(account.id).await.expect("delete");
    assert!(matches!(
        storage.get_account_by_id(account.id).await.unwrap_err(),
        StorageError::AccountNotFound
    ));
}
