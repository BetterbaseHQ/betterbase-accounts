use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{OAuthClient, OAuthClientStorage, StorageError};

use super::PostgresStorage;

struct OAuthClientRow {
    id: Uuid,
    name: String,
    secret_hash: Option<String>,
    redirect_uris: serde_json::Value,
    allowed_scopes: Vec<String>,
    created_at: DateTime<Utc>,
}

impl TryFrom<OAuthClientRow> for OAuthClient {
    type Error = StorageError;

    fn try_from(r: OAuthClientRow) -> Result<Self, Self::Error> {
        let redirect_uris: Vec<String> = serde_json::from_value(r.redirect_uris)
            .map_err(|e| StorageError::Internal(format!("invalid redirect_uris JSON: {e}")))?;

        Ok(OAuthClient {
            id: r.id,
            name: r.name,
            secret_hash: r.secret_hash,
            redirect_uris,
            allowed_scopes: r.allowed_scopes,
            created_at: r.created_at,
        })
    }
}

#[async_trait]
impl OAuthClientStorage for PostgresStorage {
    async fn create_oauth_client(&self, client: &OAuthClient) -> Result<(), StorageError> {
        let redirect_uris = serde_json::to_value(&client.redirect_uris)
            .map_err(|e| StorageError::Internal(e.to_string()))?;

        sqlx::query!(
            r#"
            INSERT INTO oauth_clients (id, name, secret_hash, redirect_uris, allowed_scopes)
            VALUES ($1, $2, $3, $4, $5)
            "#,
            client.id,
            client.name,
            client.secret_hash,
            redirect_uris,
            client.allowed_scopes.as_slice(),
        )
        .execute(&self.pool)
        .await
        .map_err(StorageError::from)?;

        Ok(())
    }

    async fn get_oauth_client(&self, client_id: Uuid) -> Result<OAuthClient, StorageError> {
        let row = sqlx::query_as!(
            OAuthClientRow,
            r#"
            SELECT id, name, secret_hash, redirect_uris, allowed_scopes, created_at
            FROM oauth_clients WHERE id = $1
            "#,
            client_id,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .ok_or(StorageError::OAuthClientNotFound)?;

        row.try_into()
    }

    async fn validate_redirect_uri(
        &self,
        client_id: Uuid,
        uri: &str,
    ) -> Result<bool, StorageError> {
        let row = sqlx::query!(
            "SELECT redirect_uris FROM oauth_clients WHERE id = $1",
            client_id,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::from)?
        .ok_or(StorageError::OAuthClientNotFound)?;

        let uris: Vec<String> = serde_json::from_value(row.redirect_uris)
            .map_err(|e| StorageError::Internal(format!("invalid redirect_uris JSON: {e}")))?;

        Ok(uris.iter().any(|u| u == uri))
    }
}
