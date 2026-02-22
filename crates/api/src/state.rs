//! Shared application state injected into every Axum handler.

use std::sync::Arc;

use betterbase_accounts_auth::{jwt::JwtService, opaque::OpaqueService};
use betterbase_accounts_cap::CapService;
use betterbase_accounts_email::Mailer;
use betterbase_accounts_storage::postgres::PostgresStorage;

/// Server configuration derived from environment variables.
#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// OAuth issuer URL (e.g. `https://accounts.betterbase.dev`)
    pub issuer: String,
    /// Identity domain extracted from issuer (e.g. `betterbase.dev`)
    pub identity_domain: String,
    /// Optional sync endpoint URL
    pub sync_endpoint: Option<String>,
    /// Optional federation WebSocket endpoint
    pub federation_ws_endpoint: Option<String>,
    /// Web base URL (for email links, etc.)
    pub web_base_url: String,
    /// Whether CAP proof-of-work is required
    pub cap_enabled: bool,
}

/// Shared state available to all handlers via `State<AppState>`.
#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<PostgresStorage>,
    pub jwt: Arc<JwtService>,
    pub opaque: Arc<OpaqueService>,
    pub cap: Arc<CapService>,
    pub mailer: Arc<dyn Mailer + Send + Sync>,
    pub config: Arc<ApiConfig>,
    /// HMAC-SHA256 key for hashing emails in rate-limit records
    pub identity_hash_key: Vec<u8>,
}
