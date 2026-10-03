use super::super::test_support::{create_account, test_storage};
use super::*;

#[tokio::test]
async fn real_and_fake_login_states_preserve_versions_and_are_single_use() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let account = create_account(&storage).await;
    for account_id in [Some(account.id), None] {
        let state = LoginState {
            id: Uuid::new_v4(),
            account_id,
            username: "alice".into(),
            state: vec![1, 2, 3],
            credentials_version: 7,
            root_key_version: 11,
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::minutes(1),
        };
        storage.create_login_state(&state).await.unwrap();
        let fetched = storage.get_login_state(state.id).await.unwrap();
        assert_eq!(fetched.account_id, account_id);
        assert_eq!(fetched.credentials_version, 7);
        assert_eq!(fetched.root_key_version, 11);
        let (a, b) = tokio::join!(
            storage.consume_login_state(state.id),
            storage.consume_login_state(state.id)
        );
        let mut successes = 0;
        for result in [a, b] {
            match result {
                Ok(consumed) => {
                    successes += 1;
                    assert_eq!(consumed.state, state.state);
                }
                Err(StorageError::StateNotFound) => {}
                other => panic!("unexpected result: {other:?}"),
            }
        }
        assert_eq!(successes, 1);
        assert!(matches!(
            storage.get_login_state(state.id).await,
            Err(StorageError::StateNotFound)
        ));
    }
}

#[tokio::test]
async fn expired_login_states_are_rejected_and_consumed() {
    let Some(storage) = test_storage().await else {
        return;
    };
    let state = LoginState {
        id: Uuid::new_v4(),
        account_id: None,
        username: "missing".into(),
        state: vec![1],
        credentials_version: 0,
        root_key_version: 0,
        created_at: Utc::now() - chrono::Duration::minutes(2),
        expires_at: Utc::now() - chrono::Duration::minutes(1),
    };
    storage.create_login_state(&state).await.unwrap();
    assert!(matches!(
        storage.get_login_state(state.id).await,
        Err(StorageError::StateExpired)
    ));
    assert!(matches!(
        storage.consume_login_state(state.id).await,
        Err(StorageError::StateExpired)
    ));
    assert!(matches!(
        storage.consume_login_state(state.id).await,
        Err(StorageError::StateNotFound)
    ));
}
