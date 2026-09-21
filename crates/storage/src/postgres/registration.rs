use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{RegistrationState, RegistrationStateStorage, StorageError};

use super::PostgresStorage;

struct RegistrationStateRow {
    id: Uuid,
    account_id: Uuid,
    username: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl From<RegistrationStateRow> for RegistrationState {
    fn from(r: RegistrationStateRow) -> Self {
        RegistrationState {
            id: r.id,
            account_id: r.account_id,
            username: r.username,
            created_at: r.created_at,
            expires_at: r.expires_at,
        }
    }
}

#[async_trait]
impl RegistrationStateStorage for PostgresStorage {
    async fn create_registration_state(
        &self,
        state: &RegistrationState,
    ) -> Result<(), StorageError> {
        sqlx::query!(
            r#"
            INSERT INTO registration_states (id, account_id, username, created_at, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            "#,
            state.id,
            state.account_id,
            state.username,
            state.created_at,
            state.expires_at,
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::from)?;
        Ok(())
    }

    async fn get_registration_state(&self, id: Uuid) -> Result<RegistrationState, StorageError> {
        let now = Utc::now();
        let row = sqlx::query_as!(
            RegistrationStateRow,
            r#"
            SELECT id, account_id, username, created_at, expires_at
            FROM registration_states
            WHERE id = $1
            "#,
            id,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .ok_or(StorageError::StateNotFound)?;

        if row.expires_at < now {
            return Err(StorageError::StateExpired);
        }
        Ok(row.into())
    }

    async fn consume_registration_state(
        &self,
        id: Uuid,
    ) -> Result<RegistrationState, StorageError> {
        // Atomically delete + return. Expired states are also deleted here
        // (not left for cleanup) so they cannot be replayed.
        let now = Utc::now();
        let row = sqlx::query_as!(
            RegistrationStateRow,
            r#"
            DELETE FROM registration_states
            WHERE id = $1
            RETURNING id, account_id, username, created_at, expires_at
            "#,
            id,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .ok_or(StorageError::StateNotFound)?;

        if row.expires_at < now {
            return Err(StorageError::StateExpired);
        }
        Ok(row.into())
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use uuid::Uuid;

    use super::super::test_support::*;
    use super::super::PostgresStorage;
    use crate::RegistrationState;

    async fn create_state(storage: &PostgresStorage, expires_in: Duration) -> RegistrationState {
        let account = create_account(storage).await;
        let state = RegistrationState {
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
}
