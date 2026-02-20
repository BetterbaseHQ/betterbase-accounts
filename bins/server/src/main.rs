#![forbid(unsafe_code)]
//! less-accounts server entry point.

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let config = less_accounts_app::AppConfig::from_env()?;

    // Set up tracing
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    if config.log_format == "json" {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }

    less_accounts_app::run(config).await
}
