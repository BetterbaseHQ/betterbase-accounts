use uuid::Uuid;

use super::super::test_support::*;

#[tokio::test]
async fn username_conflict_with_a_different_email_is_rejected() {
    let Some(storage) = test_storage().await else {
        return;
    };
    storage
        .get_or_create_account(TEST_ISSUER, "alice", TEST_EMAIL)
        .await
        .expect("create account");
    assert!(matches!(
        storage
            .get_or_create_account(TEST_ISSUER, "alice", "mallory@example.com")
            .await
            .unwrap_err(),
        StorageError::AccountExists
    ));
}

#[tokio::test]
async fn email_conflict_with_a_different_username_is_rejected() {
    let Some(storage) = test_storage().await else {
        return;
    };
    storage
        .get_or_create_account(TEST_ISSUER, "alice", TEST_EMAIL)
        .await
        .expect("create account");
    assert!(matches!(
        storage
            .get_or_create_account(TEST_ISSUER, "mallory", TEST_EMAIL)
            .await
            .unwrap_err(),
        StorageError::AccountExists
    ));
}

#[tokio::test]
async fn signup_finalize_is_compare_and_set_on_unregistered_accounts() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let account = create_account(&storage).await;
    storage
        .finalize_registration_with_root_key(account.id, b"record-1", &[0x01; 41])
        .await
        .expect("first finalize");

    // A second completion (concurrent signup, replayed finalize, or
    // attacker racing a victim) must not replace the credentials.
    assert!(matches!(
        storage
            .finalize_registration_with_root_key(account.id, b"record-2", &[0x02; 41])
            .await
            .unwrap_err(),
        StorageError::AccountExists
    ));

    let reloaded = storage.get_account_by_id(account.id).await.expect("reload");
    assert_eq!(
        reloaded.opaque_record.as_deref(),
        Some(b"record-1".as_slice())
    );
}

#[tokio::test]
async fn signup_finalize_for_missing_account_returns_not_found() {
    let Some(storage) = test_storage().await else {
        return;
    };
    assert!(matches!(
        storage
            .finalize_registration_with_root_key(Uuid::new_v4(), b"record", &[0x01; 41])
            .await
            .unwrap_err(),
        StorageError::AccountNotFound
    ));
}
