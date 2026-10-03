use chrono::{Duration, Utc};
use uuid::Uuid;

use super::super::test_support::*;
use super::super::PostgresStorage;
use crate::RegistrationState;

async fn create_state(storage: &PostgresStorage, expires_in: Duration) -> RegistrationState {
    let account = create_account(storage).await;
    let state = RegistrationState {
        root_key_version: account.root_key_version,
        id: Uuid::new_v4(),
        account_id: account.id,
        username: account.username,
        created_at: Utc::now(),
        expires_at: Utc::now() + expires_in,
    };
    storage
        .create_registration_state(&state)
        .await
        .expect("create registration state");
    state
}

#[tokio::test]
async fn create_get_and_consume_registration_state_roundtrip() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let state = create_state(&storage, Duration::minutes(1)).await;

    let fetched = storage
        .get_registration_state(state.id)
        .await
        .expect("get registration state");
    assert_eq!(fetched.account_id, state.account_id);
    assert_eq!(fetched.username, state.username);

    let consumed = storage
        .consume_registration_state(state.id)
        .await
        .expect("consume registration state");
    assert_eq!(consumed.id, state.id);

    // Consume is one-shot: the second attempt must not find the state.
    assert!(matches!(
        storage
            .consume_registration_state(state.id)
            .await
            .unwrap_err(),
        StorageError::StateNotFound
    ));
}

#[tokio::test]
async fn get_expired_registration_state_returns_expired() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let state = create_state(&storage, Duration::minutes(-1)).await;
    assert!(matches!(
        storage.get_registration_state(state.id).await.unwrap_err(),
        StorageError::StateExpired
    ));
}

#[tokio::test]
async fn consume_expired_state_deletes_it_and_returns_expired() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let state = create_state(&storage, Duration::minutes(-1)).await;
    assert!(matches!(
        storage
            .consume_registration_state(state.id)
            .await
            .unwrap_err(),
        StorageError::StateExpired
    ));
    // The expired state was deleted, not retained for replay.
    assert!(matches!(
        storage
            .consume_registration_state(state.id)
            .await
            .unwrap_err(),
        StorageError::StateNotFound
    ));
}

#[tokio::test]
async fn missing_registration_state_returns_not_found() {
    let Some(storage) = test_storage().await else {
        return;
    };
    assert!(matches!(
        storage
            .get_registration_state(Uuid::new_v4())
            .await
            .unwrap_err(),
        StorageError::StateNotFound
    ));
}
