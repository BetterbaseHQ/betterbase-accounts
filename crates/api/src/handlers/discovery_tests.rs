use super::*;

fn base_config() -> ApiConfig {
    ApiConfig {
        issuer: "https://betterbase.dev".to_string(),
        identity_domain: "betterbase.dev".to_string(),
        accounts_public_url: "https://betterbase.dev".to_string(),
        sync_endpoint: Some("https://sync.betterbase.dev/api/v1".to_string()),
        federation_ws_endpoint: None,
        web_base_url: String::new(),
        cap_enabled: false,
        cap_key_id: String::new(),
    }
}

#[test]
fn metadata_advertises_service_urls_from_accounts_public_url() {
    // Identity anchor at the apex, API/UI hosted on the subdomain.
    let mut cfg = base_config();
    cfg.accounts_public_url = "https://accounts.betterbase.dev".to_string();

    let meta = server_metadata(&cfg);

    assert_eq!(meta.accounts_endpoint, "https://accounts.betterbase.dev");
    assert_eq!(
        meta.jwks_uri,
        "https://accounts.betterbase.dev/.well-known/jwks.json"
    );
    assert_eq!(
        meta.webfinger,
        "https://accounts.betterbase.dev/.well-known/webfinger"
    );
    // sync endpoint is independent of where accounts is hosted
    assert_eq!(
        meta.sync_endpoint.as_deref(),
        Some("https://sync.betterbase.dev/api/v1")
    );
}

#[test]
fn webfinger_self_link_points_at_the_hosted_service() {
    let mut cfg = base_config();
    cfg.accounts_public_url = "https://accounts.betterbase.dev".to_string();
    assert_eq!(
        webfinger_self_link(&cfg, "alice").href.as_deref(),
        Some("https://accounts.betterbase.dev/v1/users/alice")
    );
    // issuer-hosted default keeps the pre-split behavior
    assert_eq!(
        webfinger_self_link(&base_config(), "alice").href.as_deref(),
        Some("https://betterbase.dev/v1/users/alice")
    );
}

#[test]
fn metadata_defaults_to_the_issuer_when_services_are_issuer_hosted() {
    let meta = server_metadata(&base_config());

    assert_eq!(meta.accounts_endpoint, "https://betterbase.dev");
    assert_eq!(
        meta.jwks_uri,
        "https://betterbase.dev/.well-known/jwks.json"
    );
    assert_eq!(
        meta.webfinger,
        "https://betterbase.dev/.well-known/webfinger"
    );
}
