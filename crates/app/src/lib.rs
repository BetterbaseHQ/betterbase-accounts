#![forbid(unsafe_code)]
//! Application bootstrap: config, startup, background tasks, graceful shutdown.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use less_accounts_auth::{es256::generate_keypair, jwt::JwtService, opaque::OpaqueService};
use less_accounts_cap::{CapConfig, CapService};
use less_accounts_email::{DevMailer, Mailer, SmtpConfig, SmtpMailer};
use less_accounts_storage::{
    postgres::PostgresStorage, CleanupStorage, JwtKeyStorage, OAuthSigningKeyStorage,
};
use tokio::time;
use tracing::info;

use less_accounts_api::state::{ApiConfig, AppState};

/// Application configuration loaded from environment variables.
pub struct AppConfig {
    /// PostgreSQL connection URL
    pub database_url: String,
    /// Hex-encoded OPAQUE ServerSetup blob
    pub opaque_server_setup: String,
    /// OAuth issuer URL
    pub oauth_issuer: String,
    /// HMAC key for privacy-hashing emails in rate limits (hex, 32 bytes)
    pub identity_hash_key: String,
    /// HTTP listen address (default 0.0.0.0:5377)
    pub listen_addr: String,
    /// Optional sync endpoint URL
    pub sync_endpoint: Option<String>,
    /// Optional federation WebSocket endpoint
    pub federation_ws_endpoint: Option<String>,
    /// Web base URL for UI links
    pub web_base_url: String,
    /// Log format: "text" or "json"
    pub log_format: String,

    // CAP config
    pub cap_enabled: bool,
    pub cap_key_id: String,
    pub cap_secret: String,
    pub cap_verify_url: String,

    // SMTP config
    pub smtp_dev_mode: bool,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    pub smtp_from: String,
}

impl AppConfig {
    pub fn from_env() -> Result<Self> {
        Ok(AppConfig {
            database_url: require_env("DATABASE_URL")?,
            opaque_server_setup: require_env("OPAQUE_SERVER_SETUP")?,
            oauth_issuer: require_env("OAUTH_ISSUER")?,
            identity_hash_key: require_env("IDENTITY_HASH_KEY")?,
            listen_addr: std::env::var("LISTEN_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:5377".to_string()),
            sync_endpoint: std::env::var("SYNC_ENDPOINT").ok(),
            federation_ws_endpoint: std::env::var("FEDERATION_WS_ENDPOINT").ok(),
            web_base_url: std::env::var("WEB_BASE_URL").unwrap_or_default(),
            log_format: std::env::var("LOG_FORMAT").unwrap_or_else(|_| "text".to_string()),

            cap_enabled: std::env::var("CAP_KEY_ID")
                .ok()
                .filter(|s| !s.is_empty())
                .is_some(),
            cap_key_id: std::env::var("CAP_KEY_ID").unwrap_or_default(),
            cap_secret: std::env::var("CAP_SECRET").unwrap_or_default(),
            cap_verify_url: std::env::var("CAP_VERIFY_URL")
                .unwrap_or_else(|_| "http://cap:3000".to_string()),

            smtp_dev_mode: std::env::var("SMTP_DEV_MODE")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
            smtp_host: std::env::var("SMTP_HOST").unwrap_or_default(),
            smtp_port: std::env::var("SMTP_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(587),
            smtp_username: std::env::var("SMTP_USERNAME").unwrap_or_default(),
            smtp_password: std::env::var("SMTP_PASSWORD").unwrap_or_default(),
            smtp_from: std::env::var("SMTP_FROM").unwrap_or_else(|_| "noreply@less.so".to_string()),
        })
    }
}

/// Run the server: boot all services, start background tasks, serve HTTP.
pub async fn run(config: AppConfig) -> Result<()> {
    // Connect to database and run migrations
    info!("connecting to database");
    let storage = PostgresStorage::connect_and_migrate(&config.database_url)
        .await
        .context("failed to connect to database")?;
    let storage = Arc::new(storage);

    // Bootstrap JWT HMAC key
    info!("bootstrapping JWT key");
    let hmac_secret: Vec<u8> = {
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        bytes.to_vec()
    };
    storage
        .ensure_jwt_key(&hmac_secret)
        .await
        .context("failed to ensure JWT key")?;
    let jwt_key = storage
        .get_current_jwt_key()
        .await
        .context("failed to get JWT key")?;

    // Bootstrap ES256 signing key for OAuth access tokens
    info!("bootstrapping ES256 signing key");
    let (priv_der, pub_der) = generate_keypair().context("failed to generate ES256 keypair")?;
    storage
        .ensure_oauth_signing_key(&priv_der, &pub_der)
        .await
        .context("failed to ensure OAuth signing key")?;
    let signing_key = storage
        .get_current_signing_key()
        .await
        .context("failed to get signing key")?;

    // Get all public signing keys for JWKS / token validation
    let all_signing_keys = storage
        .list_signing_keys()
        .await
        .context("failed to list signing keys")?;
    let public_keys: Vec<(i32, Vec<u8>)> = all_signing_keys
        .into_iter()
        .map(|k| (k.id, k.public_key))
        .collect();

    // Initialize services
    info!("initializing OPAQUE service");
    let opaque = Arc::new(
        OpaqueService::from_hex(&config.opaque_server_setup)
            .context("failed to initialize OPAQUE service")?,
    );

    let identity_hash_key =
        hex::decode(&config.identity_hash_key).context("IDENTITY_HASH_KEY must be hex")?;
    if identity_hash_key.len() != 32 {
        anyhow::bail!("IDENTITY_HASH_KEY must be 32 bytes");
    }

    let identity_domain = extract_domain(&config.oauth_issuer).to_string();

    let jwt = Arc::new(JwtService::new(
        jwt_key.id,
        jwt_key.secret_key,
        signing_key.id,
        signing_key.private_key,
        public_keys,
        config.oauth_issuer.clone(),
    ));

    let cap = Arc::new(CapService::new(CapConfig {
        enabled: config.cap_enabled,
        verify_url: config.cap_verify_url.clone(),
        key_id: config.cap_key_id.clone(),
        secret: config.cap_secret.clone(),
    }));

    let mailer: Arc<dyn Mailer + Send + Sync> = if config.smtp_dev_mode {
        info!("using dev mailer (emails logged to stdout)");
        Arc::new(DevMailer)
    } else {
        Arc::new(SmtpMailer::new(SmtpConfig {
            host: config.smtp_host.clone(),
            port: config.smtp_port,
            username: config.smtp_username.clone(),
            password: config.smtp_password.clone(),
            from: config.smtp_from.clone(),
        }))
    };

    let api_config = Arc::new(ApiConfig {
        issuer: config.oauth_issuer.clone(),
        identity_domain,
        sync_endpoint: config.sync_endpoint.clone(),
        federation_ws_endpoint: config.federation_ws_endpoint.clone(),
        web_base_url: config.web_base_url.clone(),
        cap_enabled: config.cap_enabled,
    });

    let app_state = AppState {
        storage: storage.clone(),
        jwt,
        opaque,
        cap,
        mailer,
        config: api_config,
        identity_hash_key,
    };

    // Build router
    let router = less_accounts_api::build_router(app_state);

    // Background cleanup loop (every 60 seconds)
    let cleanup_storage = storage.clone();
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            if let Err(e) = cleanup_storage.cleanup_expired_states().await {
                tracing::warn!("cleanup_expired_states error: {e}");
            }
            if let Err(e) = cleanup_storage.cleanup_expired_oauth_codes().await {
                tracing::warn!("cleanup_expired_oauth_codes error: {e}");
            }
            if let Err(e) = cleanup_storage.cleanup_expired_refresh_tokens().await {
                tracing::warn!("cleanup_expired_refresh_tokens error: {e}");
            }
            if let Err(e) = cleanup_storage
                .cleanup_used_refresh_tokens(Duration::from_secs(7 * 24 * 3600))
                .await
            {
                tracing::warn!("cleanup_used_refresh_tokens error: {e}");
            }
            if let Err(e) = cleanup_storage.cleanup_expired_verification_codes().await {
                tracing::warn!("cleanup_expired_verification_codes error: {e}");
            }
            if let Err(e) = cleanup_storage.cleanup_expired_verification_tokens().await {
                tracing::warn!("cleanup_expired_verification_tokens error: {e}");
            }
        }
    });

    // Start HTTP server
    let addr: SocketAddr = config.listen_addr.parse().context("invalid LISTEN_ADDR")?;
    info!("listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .context("failed to bind")?;

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;

    Ok(())
}

async fn shutdown_signal() {
    use tokio::signal;

    #[cfg(unix)]
    {
        let mut sigterm =
            signal::unix::signal(signal::unix::SignalKind::terminate()).expect("SIGTERM");
        tokio::select! {
            _ = signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        signal::ctrl_c().await.ok();
    }

    info!("shutdown signal received");
}

fn extract_domain(issuer: &str) -> &str {
    let s = issuer.strip_prefix("https://").unwrap_or(issuer);
    let s = s.strip_prefix("http://").unwrap_or(s);
    s.split('/').next().unwrap_or(s)
}

fn require_env(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("missing required environment variable: {key}"))
}
