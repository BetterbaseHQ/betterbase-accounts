use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{Account, AccountStorage, RootKeyStorage, StorageError};

use super::PostgresStorage;

struct AccountRow {
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
                      opaque_record, wrapped_root_key,
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
                   opaque_record, wrapped_root_key,
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
                   opaque_record, wrapped_root_key,
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
                   opaque_record, wrapped_root_key,
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
mod tests {
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
}

#[cfg(test)]
mod reservation_tests {
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
}
