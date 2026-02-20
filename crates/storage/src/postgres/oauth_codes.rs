use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{OAuthCode, OAuthCodeStorage, StorageError};

use super::PostgresStorage;

struct OAuthCodeRow {
    code: String,
    client_id: Uuid,
    account_id: Uuid,
    redirect_uri: String,
    scope: String,
    code_challenge: String,
    keys_jwe: Option<String>,
    keys_jwk_thumbprint: Option<String>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl From<OAuthCodeRow> for OAuthCode {
    fn from(r: OAuthCodeRow) -> Self {
        OAuthCode {
            code: r.code,
            client_id: r.client_id,
            account_id: r.account_id,
            redirect_uri: r.redirect_uri,
            scope: r.scope,
            code_challenge: r.code_challenge,
            keys_jwe: r.keys_jwe,
            keys_jwk_thumbprint: r.keys_jwk_thumbprint,
            created_at: r.created_at,
            expires_at: r.expires_at,
        }
    }
}

#[async_trait]
impl OAuthCodeStorage for PostgresStorage {
    async fn create_oauth_code(&self, code: &OAuthCode) -> Result<(), StorageError> {
        sqlx::query!(
            r#"
            INSERT INTO oauth_codes
                (code, client_id, account_id, redirect_uri, scope,
                 code_challenge, keys_jwe, keys_jwk_thumbprint, created_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
            code.code,
            code.client_id,
            code.account_id,
            code.redirect_uri,
            code.scope,
            code.code_challenge,
            code.keys_jwe,
            code.keys_jwk_thumbprint,
            code.created_at,
            code.expires_at,
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::from)?;
        Ok(())
    }

    async fn get_oauth_code(&self, code: &str) -> Result<OAuthCode, StorageError> {
        let now = Utc::now();
        let row = sqlx::query_as!(
            OAuthCodeRow,
            r#"
            SELECT code, client_id, account_id, redirect_uri, scope,
                   code_challenge, keys_jwe, keys_jwk_thumbprint, created_at, expires_at
            FROM oauth_codes WHERE code = $1
            "#,
            code,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .ok_or(StorageError::OAuthCodeNotFound)?;

        if row.expires_at < now {
            return Err(StorageError::OAuthCodeExpired);
        }
        Ok(row.into())
    }

    async fn consume_oauth_code(&self, code: &str) -> Result<OAuthCode, StorageError> {
        let now = Utc::now();
        let row = sqlx::query_as!(
            OAuthCodeRow,
            r#"
            DELETE FROM oauth_codes WHERE code = $1
            RETURNING code, client_id, account_id, redirect_uri, scope,
                      code_challenge, keys_jwe, keys_jwk_thumbprint, created_at, expires_at
            "#,
            code,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .ok_or(StorageError::OAuthCodeNotFound)?;

        if row.expires_at < now {
            return Err(StorageError::OAuthCodeExpired);
        }
        Ok(row.into())
    }

    async fn delete_oauth_code(&self, code: &str) -> Result<(), StorageError> {
        sqlx::query!("DELETE FROM oauth_codes WHERE code = $1", code)
            .execute(&self.pool)
            .await
            .map_err(StorageError::from)?;
        Ok(())
    }
}
