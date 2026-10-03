#![forbid(unsafe_code)]
//! oauth-client — CLI for managing OAuth clients in the database.
//!
//! Usage:
//!   oauth-client create --name "App Name" --redirect-uri "https://..." [--scope sync] ...
//!   oauth-client list

use anyhow::{bail, Context, Result};
use betterbase_accounts_storage::{postgres::PostgresStorage, OAuthClient, OAuthClientStorage};
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }

    match args[1].as_str() {
        "create" => create_client(&args[2..]).await,
        "list" => {
            if args.len() != 2 {
                bail!("list takes no arguments");
            }
            list_clients().await
        }
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        cmd => {
            eprintln!("Unknown command: {cmd}");
            print_usage();
            std::process::exit(1);
        }
    }
}

fn print_usage() {
    println!(
        r#"oauth-client — OAuth 2.0 client management

Usage:
  oauth-client <command> [options]

Commands:
  create    Create a new OAuth client
  list      List all OAuth clients
  help      Show this help

Environment Variables:
  DATABASE_URL  PostgreSQL connection URL (required)

Create Options:
  --name          Client display name (required)
  --redirect-uri  Allowed redirect URI (repeatable)
  --scope         Allowed capability scope: 'sync', 'files', 'inference', 'keys' (repeatable)

Examples:
  oauth-client create --name "Notes App" --redirect-uri "http://localhost:5381/callback" --scope sync
  oauth-client list
"#
    );
}

async fn connect() -> Result<PostgresStorage> {
    let url = std::env::var("DATABASE_URL").context("DATABASE_URL is required")?;
    PostgresStorage::connect_and_migrate(&url)
        .await
        .context("failed to connect to database")
}

fn argument_value<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a str> {
    args.get(index)
        .map(String::as_str)
        .filter(|value| !value.starts_with("--"))
        .with_context(|| format!("{flag} requires a value"))
}

async fn create_client(args: &[String]) -> Result<()> {
    let mut name = String::new();
    let mut redirect_uris: Vec<String> = Vec::new();
    let mut allowed_scopes: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--name" => {
                i += 1;
                name = argument_value(args, i, "--name")?.to_owned();
            }
            "--redirect-uri" => {
                i += 1;
                let uri = argument_value(args, i, "--redirect-uri")?;
                // URL parsers repair forms such as https:host/path. Stored
                // callbacks must have an explicit authority so the browser
                // cannot resolve them relative to the consent page.
                let has_authority = uri.split_once("://").is_some_and(|(scheme, rest)| {
                    (scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https"))
                        && !rest.is_empty()
                        && !rest.starts_with(['/', '\\', '?', '#'])
                });
                let parsed = url::Url::parse(uri).context("invalid redirect URI")?;
                if !has_authority
                    || !matches!(parsed.scheme(), "http" | "https")
                    || parsed.host_str().is_none()
                    || !parsed.username().is_empty()
                    || parsed.password().is_some()
                    || parsed.fragment().is_some()
                    || uri.contains('\\')
                    || uri.chars().any(|c| c.is_whitespace() || c.is_control())
                {
                    bail!("redirect URI must have an explicit http:// or https:// authority, without userinfo, whitespace, backslashes, or fragment");
                }
                redirect_uris.push(uri.to_owned());
            }
            "--scope" => {
                i += 1;
                let scope = argument_value(args, i, "--scope")?;
                match scope {
                    "sync" | "files" | "inference" | "keys" => {
                        allowed_scopes.push(scope.to_owned());
                    }
                    _ => bail!("invalid scope: {scope}"),
                }
            }
            flag => bail!("unknown flag: {flag}"),
        }
        i += 1;
    }

    if name.trim().is_empty() {
        bail!("--name is required");
    }
    if redirect_uris.is_empty() {
        bail!("at least one --redirect-uri is required");
    }

    let storage = connect().await?;

    let client_id = Uuid::new_v4();
    let client = OAuthClient {
        id: client_id,
        name: name.clone(),
        secret_hash: None, // public client
        redirect_uris: redirect_uris.clone(),
        allowed_scopes: allowed_scopes.clone(),
        created_at: chrono::Utc::now(),
    };

    storage
        .create_oauth_client(&client)
        .await
        .context("failed to create OAuth client")?;

    println!("OAuth client created successfully!\n");
    println!("Client ID:     {client_id}");
    println!("Name:          {name}");
    println!("Redirect URIs: {}", redirect_uris.join(", "));
    if allowed_scopes.is_empty() {
        println!("Allowed Scopes: (none — OIDC only)");
    } else {
        println!("Allowed Scopes: {}", allowed_scopes.join(", "));
    }
    println!("\nNote: Public client (no secret). Use PKCE for secure authorization.");

    Ok(())
}

async fn list_clients() -> Result<()> {
    let storage = connect().await?;

    // Use raw query via pool to list all clients
    let rows = sqlx::query!(
        "SELECT id, name, redirect_uris, allowed_scopes, created_at FROM oauth_clients ORDER BY created_at"
    )
    .fetch_all(storage.pool())
    .await
    .context("failed to list clients")?;

    println!("OAuth Clients:");
    println!("{}", "-".repeat(80));

    if rows.is_empty() {
        println!("No OAuth clients registered.");
        return Ok(());
    }

    for row in &rows {
        println!("ID:             {}", row.id);
        println!("Name:           {}", row.name);
        println!("Redirect URIs:  {:?}", row.redirect_uris);
        let scopes: Vec<String> = row.allowed_scopes.clone();
        if scopes.is_empty() {
            println!("Allowed Scopes: (none)");
        } else {
            println!("Allowed Scopes: {}", scopes.join(", "));
        }
        println!("Created:        {}", row.created_at);
        println!("{}", "-".repeat(80));
    }

    println!("\nTotal: {} client(s)", rows.len());
    Ok(())
}
