use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{Account, AccountStorage, RootKeyStorage, StorageError};

use super::PostgresStorage;

struct AccountRow {
    root_key_version: i32,
    credentials_version: i32,
    id: Uuid,
    issuer: String,
    username: String,
    email: String,
    opaque_record: Option<Vec<u8>>,
    wrapped_root_key: Option<Vec<u8>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<AccountRow> for Account {
    fn from(r: AccountRow) -> Self {
        Account {
            root_key_version: i64::from(r.root_key_version),
            credentials_version: i64::from(r.credentials_version),
            id: r.id,
            issuer: r.issuer,
            username: r.username,
            email: r.email,
            opaque_record: r.opaque_record,
            wrapped_root_key: r.wrapped_root_key,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[async_trait]
impl AccountStorage for PostgresStorage {
    async fn get_credentials_version(&self, account_id: Uuid) -> Result<Option<i64>, StorageError> {
        let version = sqlx::query_scalar!(
            "SELECT credentials_version FROM accounts WHERE id = $1",
            account_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?;
        Ok(version.map(i64::from))
    }

    async fn revoke_account_sessions(&self, account_id: Uuid) -> Result<i64, StorageError> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;
        let new_version = sqlx::query_scalar!(
            r#"
            UPDATE accounts
            SET credentials_version = credentials_version + 1, updated_at = NOW()
            WHERE id = $1
            RETURNING credentials_version
            "#,
            account_id
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(StorageError::from)?
        .ok_or(StorageError::AccountNotFound)?
        .into();
        sqlx::query!(
            "DELETE FROM oauth_refresh_tokens WHERE grant_id IN (SELECT id FROM oauth_grants WHERE account_id = $1)",
            account_id
        )
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;
        tx.commit().await.map_err(StorageError::from)?;
        Ok(new_version)
    }

    async fn get_or_create_account(
        &self,
        issuer: &str,
        username: &str,
        email: &str,
    ) -> Result<Account, StorageError> {
        // Idempotent account reservation for signup (AUD-006): the
        // (issuer, username) conflict path returns the existing row, which is
        // only acceptable when it is an exact retry with the same email. Any
        // other collision — a different email claiming an existing username,
        // or a different username claiming an existing email — must not hand
        // back an existing account for the caller to overwrite.
        let row = sqlx::query_as!(
            AccountRow,
            r#"
            INSERT INTO accounts (issuer, username, email)
            VALUES ($1, $2, $3)
            ON CONFLICT (issuer, username) DO UPDATE SET issuer = EXCLUDED.issuer
            RETURNING id, issuer, username, email,
                      opaque_record, wrapped_root_key, credentials_version, root_key_version,
                      created_at, updated_at
            "#,
            issuer,
            username,
            email,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match e {
            // Unique violation on (issuer, email): same email under a new username.
            sqlx::Error::Database(db) if db.is_unique_violation() => StorageError::AccountExists,
            other => StorageError::Database(other),
        })?;

        if row.email != email {
            return Err(StorageError::AccountExists);
        }

        Ok(row.into())
    }

    async fn get_account_by_id(&self, id: Uuid) -> Result<Account, StorageError> {
        let row = sqlx::query_as!(
            AccountRow,
            r#"
            SELECT id, issuer, username, email,
                   opaque_record, wrapped_root_key, credentials_version, root_key_version,
                   created_at, updated_at
            FROM accounts WHERE id = $1
            "#,
            id,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .ok_or(StorageError::AccountNotFound)?;

        Ok(row.into())
    }

    async fn get_account_by_username(
        &self,
        issuer: &str,
        username: &str,
    ) -> Result<Account, StorageError> {
        let row = sqlx::query_as!(
            AccountRow,
            r#"
            SELECT id, issuer, username, email,
                   opaque_record, wrapped_root_key, credentials_version, root_key_version,
                   created_at, updated_at
            FROM accounts WHERE issuer = $1 AND username = $2
            "#,
            issuer,
            username,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .ok_or(StorageError::AccountNotFound)?;

        Ok(row.into())
    }

    async fn get_account_by_email(
        &self,
        issuer: &str,
        email: &str,
    ) -> Result<Account, StorageError> {
        let row = sqlx::query_as!(
            AccountRow,
            r#"
            SELECT id, issuer, username, email,
                   opaque_record, wrapped_root_key, credentials_version, root_key_version,
                   created_at, updated_at
            FROM accounts WHERE issuer = $1 AND email = $2
            "#,
            issuer,
            email,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .ok_or(StorageError::AccountNotFound)?;

        Ok(row.into())
    }

    async fn finalize_registration(
        &self,
        account_id: Uuid,
        opaque_record: &[u8],
    ) -> Result<(), StorageError> {
        let rows = sqlx::query!(
            r#"
            UPDATE accounts
            SET opaque_record = $2
            WHERE id = $1
            "#,
            account_id,
            opaque_record,
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::from)?;

        if rows.rows_affected() == 0 {
            return Err(StorageError::AccountNotFound);
        }
        Ok(())
    }

    async fn finalize_registration_with_root_key(
        &self,
        account_id: Uuid,
        opaque_record: &[u8],
        wrapped_root_key: &[u8],
    ) -> Result<(), StorageError> {
        // Compare-and-set completion for signup (AUD-006): the initial
        // registration may only write credentials to an account that is not
        // yet registered. Concurrent or replayed completions must not replace
        // an existing account's credentials. (Recovery uses
        // update_registration / update_registration_and_root_key instead.)
        let rows = sqlx::query!(
            r#"
            UPDATE accounts
            SET opaque_record = $2, wrapped_root_key = $3
            WHERE id = $1 AND opaque_record IS NULL
            "#,
            account_id,
            opaque_record,
            wrapped_root_key,
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::from)?;

        if rows.rows_affected() == 0 {
            let registered =
                sqlx::query!("SELECT 1 AS one FROM accounts WHERE id = $1", account_id)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(StorageError::from)?;
            return Err(if registered.is_some() {
                StorageError::AccountExists
            } else {
                StorageError::AccountNotFound
            });
        }
        Ok(())
    }

    async fn update_registration(
        &self,
        account_id: Uuid,
        opaque_record: &[u8],
    ) -> Result<(), StorageError> {
        let rows = sqlx::query!(
            r#"
            UPDATE accounts
            SET opaque_record = $2
            WHERE id = $1
            "#,
            account_id,
            opaque_record,
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::from)?;

        if rows.rows_affected() == 0 {
            return Err(StorageError::AccountNotFound);
        }
        Ok(())
    }

    async fn delete_account(&self, account_id: Uuid) -> Result<(), StorageError> {
        sqlx::query!("DELETE FROM accounts WHERE id = $1", account_id)
            .execute(&self.pool)
            .await
            .map_err(StorageError::from)?;
        Ok(())
    }
}

#[async_trait]
impl RootKeyStorage for PostgresStorage {
    async fn get_root_key_with_version(
        &self,
        account_id: Uuid,
    ) -> Result<(Vec<u8>, i64), StorageError> {
        let row = sqlx::query!(
            "SELECT wrapped_root_key, root_key_version FROM accounts WHERE id = $1",
            account_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .ok_or(StorageError::AccountNotFound)?;
        Ok((
            row.wrapped_root_key.unwrap_or_default(),
            i64::from(row.root_key_version),
        ))
    }

    async fn get_wrapped_root_key(&self, account_id: Uuid) -> Result<Vec<u8>, StorageError> {
        let row = sqlx::query!(
            "SELECT wrapped_root_key FROM accounts WHERE id = $1",
            account_id,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .ok_or(StorageError::AccountNotFound)?;

        row.wrapped_root_key
            .ok_or(StorageError::WrappedRootKeyNotFound)
    }

    async fn set_wrapped_root_key(
        &self,
        account_id: Uuid,
        wrapped_key: &[u8],
    ) -> Result<(), StorageError> {
        let rows = sqlx::query!(
            "UPDATE accounts SET wrapped_root_key = $2 WHERE id = $1",
            account_id,
            wrapped_key,
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::from)?;

        if rows.rows_affected() == 0 {
            return Err(StorageError::AccountNotFound);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "accounts_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "accounts_reservation_tests.rs"]
mod reservation_tests;
