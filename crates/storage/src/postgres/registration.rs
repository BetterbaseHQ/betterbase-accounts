use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{RegistrationState, RegistrationStateStorage, StorageError};

use super::PostgresStorage;

struct RegistrationStateRow {
    root_key_version: i64,
    id: Uuid,
    account_id: Uuid,
    username: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl From<RegistrationStateRow> for RegistrationState {
    fn from(r: RegistrationStateRow) -> Self {
        RegistrationState {
            root_key_version: r.root_key_version,
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
            INSERT INTO registration_states (id, account_id, username, created_at, expires_at, root_key_version)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            state.id,
            state.account_id,
            state.username,
            state.created_at,
            state.expires_at,
            state.root_key_version,
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
            SELECT id, account_id, username, created_at, expires_at, root_key_version
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
            RETURNING id, account_id, username, created_at, expires_at, root_key_version
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
#[path = "registration_tests.rs"]
mod tests;
