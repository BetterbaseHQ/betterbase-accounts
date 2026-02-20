#![forbid(unsafe_code)]
//! CAP proof-of-work token verification.
//!
//! Mirrors Go server `server/cap.go`.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CapError {
    #[error("CAP token required")]
    TokenMissing,
    #[error("CAP token invalid")]
    TokenInvalid,
    #[error("CAP service unavailable: {0}")]
    ServiceError(String),
}

/// Configuration for the CAP service.
#[derive(Debug, Clone)]
pub struct CapConfig {
    /// When false, `verify()` is always a no-op (dev mode).
    pub enabled: bool,
    /// Base URL for the CAP server (e.g., `http://cap:3000`).
    pub verify_url: String,
    /// API key ID from the CAP dashboard.
    pub key_id: String,
    /// API secret from the CAP dashboard.
    pub secret: String,
}

#[derive(Serialize)]
struct VerifyRequest<'a> {
    secret: &'a str,
    response: &'a str,
}

#[derive(Deserialize)]
struct VerifyResponse {
    success: bool,
    #[allow(dead_code)]
    error: Option<String>,
}

/// CAP proof-of-work verification service.
pub struct CapService {
    config: CapConfig,
    client: reqwest::Client,
}

impl CapService {
    pub fn new(config: CapConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .expect("reqwest client build"),
        }
    }

    /// Verify a CAP token.
    ///
    /// Returns `Ok(())` if disabled, token is valid, or on success.
    /// Returns `Err(CapError::TokenMissing)` if token is empty.
    /// Returns `Err(CapError::TokenInvalid)` if verification fails.
    pub async fn verify(&self, token: &str) -> Result<(), CapError> {
        if !self.config.enabled {
            return Ok(());
        }

        if token.is_empty() {
            return Err(CapError::TokenMissing);
        }

        let url = format!(
            "{}/{}/siteverify",
            self.config.verify_url, self.config.key_id
        );

        let body = VerifyRequest {
            secret: &self.config.secret,
            response: token,
        };

        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| CapError::ServiceError(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(CapError::ServiceError(format!(
                "unexpected status {}",
                resp.status()
            )));
        }

        let result: VerifyResponse = resp
            .json()
            .await
            .map_err(|e| CapError::ServiceError(e.to_string()))?;

        if !result.success {
            return Err(CapError::TokenInvalid);
        }

        Ok(())
    }
}
