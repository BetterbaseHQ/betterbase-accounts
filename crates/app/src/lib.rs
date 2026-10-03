#![forbid(unsafe_code)]
//! Application bootstrap: config, startup, background tasks, graceful shutdown.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use betterbase_accounts_auth::{es256::generate_keypair, jwt::JwtService, opaque::OpaqueService};
use betterbase_accounts_cap::{CapConfig, CapService};
use betterbase_accounts_email::{DevMailer, Mailer, SmtpConfig, SmtpMailer};
use betterbase_accounts_storage::{
    postgres::PostgresStorage, CleanupStorage, JwtKeyStorage, OAuthSigningKeyStorage,
};
use rand::RngExt;
use tokio::time;
use tracing::info;

use betterbase_accounts_api::state::{ApiConfig, AppState};

/// Application configuration loaded from environment variables.
pub struct AppConfig {
    /// PostgreSQL connection URL
    pub database_url: String,
    /// Hex-encoded OPAQUE ServerSetup blob
    pub opaque_server_setup: String,
    /// OAuth issuer URL
    pub oauth_issuer: String,
    /// Base URL the accounts API endpoints advertised in discovery are
    /// served at, when different from the issuer (e.g. issuer
    /// `https://betterbase.dev` — the identity anchor that handles and
    /// WebFinger resolve — while the API lives at
    /// `https://accounts.betterbase.dev`). Defaults to the issuer.
    pub accounts_public_url: Option<String>,
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
        Self::from_lookup(|name| std::env::var(name))
    }

    // Inject the environment reader so tests never mutate process-global state.
    fn from_lookup(get: impl Fn(&str) -> Result<String, std::env::VarError>) -> Result<Self> {
        let required = |name: &str| -> Result<String> {
            let value = get(name)
                .with_context(|| format!("missing required environment variable: {name}"))?;
            anyhow::ensure!(!value.trim().is_empty(), "{name} must not be empty");
            Ok(value)
        };
        let config = AppConfig {
            database_url: required("DATABASE_URL")?,
            opaque_server_setup: required("OPAQUE_SERVER_SETUP")?,
            oauth_issuer: required("OAUTH_ISSUER")?,
            accounts_public_url: match get("ACCOUNTS_PUBLIC_URL") {
                Ok(raw) => Some(Self::normalize_public_url(&raw)?),
                Err(std::env::VarError::NotUnicode(_)) => {
                    anyhow::bail!("ACCOUNTS_PUBLIC_URL is not valid UTF-8")
                }
                Err(_) => None,
            },
            identity_hash_key: required("IDENTITY_HASH_KEY")?,
            listen_addr: get("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:5377".to_string()),
            sync_endpoint: get("SYNC_ENDPOINT").ok(),
            federation_ws_endpoint: get("FEDERATION_WS_ENDPOINT").ok(),
            web_base_url: get("WEB_BASE_URL").unwrap_or_default(),
            log_format: get("LOG_FORMAT").unwrap_or_else(|_| "text".to_string()),

            cap_enabled: get("CAP_KEY_ID").ok().filter(|s| !s.is_empty()).is_some(),
            cap_key_id: get("CAP_KEY_ID").unwrap_or_default(),
            cap_secret: get("CAP_SECRET").unwrap_or_default(),
            cap_verify_url: get("CAP_VERIFY_URL").unwrap_or_else(|_| "http://cap:3000".to_string()),

            smtp_dev_mode: get("SMTP_DEV_MODE")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
            smtp_host: get("SMTP_HOST").unwrap_or_default(),
            smtp_port: match get("SMTP_PORT") {
                Ok(value) => value
                    .parse()
                    .context("SMTP_PORT must be an integer from 1 to 65535")?,
                Err(std::env::VarError::NotPresent) => 587,
                Err(_) => anyhow::bail!("SMTP_PORT is not valid UTF-8"),
            },
            smtp_username: get("SMTP_USERNAME").unwrap_or_default(),
            smtp_password: get("SMTP_PASSWORD").unwrap_or_default(),
            smtp_from: get("SMTP_FROM").unwrap_or_else(|_| "noreply@betterbase.dev".to_string()),
        };

        config.validate()?;
        Ok(config)
    }

    /// Normalizes ACCOUNTS_PUBLIC_URL into the canonical form discovery
    /// joins `/.well-known/*` paths onto: the parsed serialization (lowercase
    /// scheme/host, no empty port, no surrounding whitespace) without the
    /// trailing slash. Rejects anything that is not a bare http(s) base URL:
    /// no path, query, fragment, or userinfo — credentials embedded here
    /// would be published verbatim in the public discovery document.
    fn normalize_public_url(raw: &str) -> Result<String> {
        let invalid = || {
            anyhow::anyhow!(
                "ACCOUNTS_PUBLIC_URL must be a bare base URL like \
                 'https://accounts.betterbase.dev' (scheme + host, no \
                 path/query/userinfo), got '{raw}'"
            )
        };
        let parsed = url::Url::parse(raw.trim()).map_err(|_| invalid())?;
        let valid = (parsed.scheme() == "http" || parsed.scheme() == "https")
            && parsed.host_str().is_some_and(|h| !h.is_empty())
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.path() == "/"
            && parsed.query().is_none()
            && parsed.fragment().is_none();
        if !valid {
            return Err(invalid());
        }
        let serialized = parsed.as_str();
        Ok(serialized
            .strip_suffix('/')
            .unwrap_or(serialized)
            .to_string())
    }

    /// Reject invalid configuration before startup performs database writes.
    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            !self.database_url.trim().is_empty(),
            "DATABASE_URL must not be empty"
        );
        OpaqueService::from_hex(&self.opaque_server_setup)
            .context("invalid OPAQUE_SERVER_SETUP")?;
        let key = hex::decode(&self.identity_hash_key).context("IDENTITY_HASH_KEY must be hex")?;
        anyhow::ensure!(key.len() == 32, "IDENTITY_HASH_KEY must be 32 bytes");
        self.listen_addr
            .parse::<SocketAddr>()
            .context("invalid LISTEN_ADDR")?;
        validate_http_url(&self.oauth_issuer, "OAUTH_ISSUER")?;
        // When discovery defaults to the issuer, it needs a bare service base.
        if self.accounts_public_url.is_none() {
            Self::normalize_public_url(&self.oauth_issuer)
                .context("OAUTH_ISSUER with a path requires ACCOUNTS_PUBLIC_URL")?;
        }
        if self.cap_enabled {
            anyhow::ensure!(
                !self.cap_key_id.trim().is_empty(),
                "CAP_KEY_ID is required when CAP is enabled"
            );
            anyhow::ensure!(
                !self.cap_secret.trim().is_empty(),
                "CAP_SECRET is required when CAP is enabled"
            );
            validate_http_url(&self.cap_verify_url, "CAP_VERIFY_URL")?;
        }
        anyhow::ensure!(
            self.smtp_port != 0,
            "SMTP_PORT must be an integer from 1 to 65535"
        );
        if let Some(url) = self.accounts_public_url.as_deref() {
            let canonical = Self::normalize_public_url(url)?;
            if canonical != url {
                anyhow::bail!(
                    "ACCOUNTS_PUBLIC_URL must be normalized: '{url}' \
                     (expected '{canonical}'); from_env normalizes it automatically"
                );
            }
        }
        if !self.smtp_dev_mode && self.smtp_host.trim().is_empty() {
            anyhow::bail!(
                "SMTP_HOST is required when SMTP_DEV_MODE is not true: email delivery is \
                 enabled (production default) but no mail server is configured. Set \
                 SMTP_HOST (and credentials), or set SMTP_DEV_MODE=true for local \
                 development (emails are logged instead of sent)."
            );
        }
        Ok(())
    }
}

/// Run the server: boot all services, start background tasks, serve HTTP.
pub async fn run(config: AppConfig) -> Result<()> {
    run_until(config, shutdown_signal()).await
}

async fn run_until(
    config: AppConfig,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let (router, storage) = build_app(&config).await?;
    let addr: SocketAddr = config.listen_addr.parse().context("invalid LISTEN_ADDR")?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .context("failed to bind")?;
    info!("listening on {}", listener.local_addr()?);
    serve_with_cleanup(listener, router, storage, shutdown).await
}

async fn build_app(config: &AppConfig) -> Result<(axum::Router, Arc<PostgresStorage>)> {
    config.validate()?;
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
        rand::rng().fill(&mut bytes);
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

    // Handles read `user@<issuer domain>`; service URLs advertised in
    // discovery come from ACCOUNTS_PUBLIC_URL when the services are hosted
    // on a different domain than the identity anchor (issuer).
    let identity_domain = extract_domain(&config.oauth_issuer).to_string();
    let accounts_public_url = config
        .accounts_public_url
        .clone()
        .unwrap_or_else(|| config.oauth_issuer.clone());

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
        accounts_public_url,
        sync_endpoint: config.sync_endpoint.clone(),
        federation_ws_endpoint: config.federation_ws_endpoint.clone(),
        web_base_url: config.web_base_url.clone(),
        cap_enabled: config.cap_enabled,
        cap_key_id: config.cap_key_id.clone(),
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
    let router = betterbase_accounts_api::build_router(app_state);

    Ok((router, storage))
}

async fn cleanup_once(storage: &dyn CleanupStorage) {
    if let Err(e) = storage.cleanup_expired_states().await {
        tracing::warn!("cleanup_expired_states error: {e}");
    }
    if let Err(e) = storage.cleanup_expired_oauth_codes().await {
        tracing::warn!("cleanup_expired_oauth_codes error: {e}");
    }
    if let Err(e) = storage.cleanup_expired_refresh_tokens().await {
        tracing::warn!("cleanup_expired_refresh_tokens error: {e}");
    }
    if let Err(e) = storage
        .cleanup_used_refresh_tokens(Duration::from_secs(7 * 24 * 3600))
        .await
    {
        tracing::warn!("cleanup_used_refresh_tokens error: {e}");
    }
    if let Err(e) = storage.cleanup_expired_verification_codes().await {
        tracing::warn!("cleanup_expired_verification_codes error: {e}");
    }
    if let Err(e) = storage.cleanup_expired_verification_tokens().await {
        tracing::warn!("cleanup_expired_verification_tokens error: {e}");
    }
    // Abandoned reservations must not permanently squat usernames/emails.
    if let Err(e) = storage
        .cleanup_unregistered_accounts(Duration::from_secs(7 * 24 * 3600))
        .await
    {
        tracing::warn!("cleanup_unregistered_accounts error: {e}");
    }
}

async fn serve_with_cleanup(
    listener: tokio::net::TcpListener,
    router: axum::Router,
    storage: Arc<dyn CleanupStorage>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    // JoinSet aborts its tasks if this future is cancelled as well as on normal
    // shutdown. Binding happens first, so a bind failure cannot leak a worker.
    let mut workers = tokio::task::JoinSet::new();
    workers.spawn(async move {
        let mut interval = time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            cleanup_once(storage.as_ref()).await;
        }
    });
    let result = axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await;
    workers.abort_all();
    while workers.join_next().await.is_some() {}
    result.context("server error")
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

fn validate_http_url(raw: &str, name: &str) -> Result<()> {
    let url = url::Url::parse(raw).with_context(|| format!("invalid {name}"))?;
    anyhow::ensure!(
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "{name} must be an HTTP(S) URL without userinfo, query, or fragment"
    );
    Ok(())
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;

#[cfg(test)]
mod config_tests;

#[cfg(test)]
mod lifecycle_tests;
