#![forbid(unsafe_code)]

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // TODO: let config = less_accounts_app::AppConfig::from_env()?;
    // less_accounts_app::run(config).await
    Ok(())
}
