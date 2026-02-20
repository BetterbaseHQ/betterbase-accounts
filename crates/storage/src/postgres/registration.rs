use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{RegistrationState, RegistrationStateStorage, StorageError};

use super::PostgresStorage;

struct RegistrationStateRow {
    id: Uuid,
    account_id: Uuid,
    username: String,
    state: Vec<u8>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl From<RegistrationStateRow> for RegistrationState {
    fn from(r: RegistrationStateRow) -> Self {
        RegistrationState {
            id: r.id,
            account_id: r.account_id,
            username: r.username,
            state: r.state,
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
            INSERT INTO registration_states (id, account_id, username, state, created_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            state.id,
            state.account_id,
            state.username,
            state.state.as_slice(),
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
            SELECT id, account_id, username, state, created_at, expires_at
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

    async fn delete_registration_state(&self, id: Uuid) -> Result<(), StorageError> {
        sqlx::query!("DELETE FROM registration_states WHERE id = $1", id,)
            .execute(&self.pool)
            .await
            .map_err(StorageError::from)?;
        Ok(())
    }
}
