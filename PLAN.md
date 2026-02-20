# less-accounts-rs: Rust Port Plan

Port of `less-accounts` (Go) to Rust, following the architecture established in `less-sync-rs`.

## Ground Rules

- **Faithful port.** The Go source at `/Users/nchapman/Code/lessisbetter/less-platform/less-accounts` is the reference implementation. Always cross-check behavior, edge cases, and error handling against it. Don't invent new behavior.
- **Idiomatic Rust.** Newtypes for domain concepts, `thiserror` error enums, exhaustive pattern matching, trait-based abstractions, `From`/`Into` conversions. Leverage the type system to make invalid states unrepresentable.
- **Test-driven.** Write failing tests before implementation. Every public function and every error path should be tested. Use inline `#[cfg(test)] mod tests`.
- **Commit discipline.** Small, atomic commits. Describe what was done clearly — never reference phase numbers, milestone names, or plan sections in commit messages.

## Workspace Layout

```
less-accounts-rs/
├── Cargo.toml                  # Workspace root
├── Dockerfile                  # Multi-stage: rust:1.88 -> debian:bookworm-slim
├── Dockerfile.dev              # cargo-watch hot reload
├── justfile                    # check, test, lint, fmt, test-db
│
├── bins/
│   ├── server/                 # Main server binary
│   │   └── src/main.rs         # Init tracing, load config, run
│   ├── keygen/                 # OPAQUE ServerSetup generation
│   │   └── src/main.rs         # Generate + print hex-encoded ServerSetup
│   └── oauth-client/           # CLI: create/list OAuth clients
│       └── src/main.rs
│
├── crates/
│   ├── core/                   # Shared types, validation
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── protocol.rs     # All API request/response types (serde JSON)
│   │       ├── email.rs        # Email validation + Gmail canonicalization
│   │       ├── username.rs     # Username validation (3-32, [a-z0-9_])
│   │       └── identity.rs     # Handle (user@domain), DID key, PersonalSpaceID
│   │
│   ├── auth/                   # OPAQUE protocol + JWT creation/validation
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── opaque.rs       # OpaqueService: registration, login, fake records
│   │       ├── jwt.rs          # JwtService: create/validate all token types
│   │       ├── es256.rs        # ES256 key management, JWKS generation
│   │       └── middleware.rs   # Bearer token extraction + validation
│   │
│   ├── storage/                # Storage traits + PostgreSQL implementation
│   │   ├── migrations/         # Fresh SQL migrations for Rust server
│   │   └── src/
│   │       ├── lib.rs          # Domain types, error enum, storage traits
│   │       └── postgres/
│   │           ├── mod.rs      # PostgresStorage struct, pool, migrations
│   │           ├── accounts.rs
│   │           ├── registration.rs
│   │           ├── login.rs
│   │           ├── jwt_keys.rs
│   │           ├── user_keys.rs
│   │           ├── oauth_clients.rs
│   │           ├── oauth_codes.rs
│   │           ├── oauth_grants.rs
│   │           ├── oauth_refresh.rs
│   │           ├── oauth_signing.rs
│   │           ├── recovery.rs
│   │           ├── verification.rs
│   │           ├── rate_limit.rs
│   │           ├── cleanup.rs
│   │           └── test_support.rs
│   │
│   ├── email/                  # Email sending
│   │   └── src/
│   │       ├── lib.rs          # Mailer trait
│   │       ├── smtp.rs         # SMTP implementation (lettre)
│   │       └── dev.rs          # Dev mode: log to stdout
│   │
│   ├── cap/                    # CAP proof-of-work verification
│   │   └── src/lib.rs          # HTTP client to CAP service
│   │
│   ├── api/                    # Axum router + all HTTP handlers
│   │   └── src/
│   │       ├── lib.rs          # Router, ApiState, middleware, CORS, body limits
│   │       ├── health.rs
│   │       ├── auth.rs         # Registration (init/finalize), login (init/finalize), validate, delete
│   │       ├── oauth.rs        # authorize, consent, token, userinfo, JWKS, mailbox, user keys, thumbprint
│   │       ├── verification.rs # send/confirm verification codes
│   │       ├── recovery.rs     # Recovery blob, re-registration (init/finalize)
│   │       ├── keys.rs         # User key CRUD
│   │       ├── rootkey.rs      # Root key, grant wrapped keys, rotation
│   │       ├── password.rs     # Password change (init/verify/complete)
│   │       ├── discovery.rs    # .well-known/less-platform, webfinger
│   │       └── webui.rs        # Embedded React SPA (rust-embed)
│   │
│   └── app/                    # Application bootstrap + config
│       └── src/
│           └── lib.rs          # AppConfig::from_env(), run(), startup init, cleanup loop
│
└── docker/
    ├── entrypoint.sh           # migrate -> server
    └── dev-entrypoint.sh       # cargo-watch
```

## Crate Dependency Graph

```
bins/server  →  app  →  api  →  auth
                             →  storage
                             →  email
                             →  cap
                             →  core
```

All crates: `#![forbid(unsafe_code)]`, pure Rust crypto (no OpenSSL).

## Key Dependencies

| Category | Crate | Notes |
|----------|-------|-------|
| HTTP | `axum 0.8` | Router, middleware, state extraction |
| Async | `tokio 1` | rt-multi-thread, signal, time |
| Database | `sqlx 0.8` | runtime-tokio-rustls, postgres, migrate |
| OPAQUE | `opaque-ke 4` | facebook/opaque-ke, ristretto255 cipher suite |
| JWT | `jsonwebtoken 10` | HS256 (internal) + ES256 (OAuth) |
| JWE | `josekit` | JWE construction for extended PKCE key delivery |
| Crypto | `p256`, `sha2`, `hmac`, `hkdf` | ES256, HMAC keys, HKDF, identity hashing |
| Email | `lettre` | SMTP with STARTTLS |
| Serialization | `serde`, `serde_json` | JSON API bodies |
| UUID | `uuid` | v4 (random), v5 (namespace) |
| Error handling | `thiserror`, `anyhow` | Library errors / app errors |
| Logging | `tracing`, `tracing-subscriber` | Structured logging with env-filter |
| Embedded SPA | `rust-embed` | Embed React build output |
| HTTP client | `reqwest` | CAP verification calls |
| CORS | `tower-http` | CorsLayer (handles OPTIONS preflight automatically) + RequestBodyLimitLayer |
| Multibase | `multibase`, `bs58` | DID key encoding |

Note: `aes-kw` is **not needed** — the server stores and returns wrapped key blobs opaquely. Wrapping/unwrapping is client-side only.

## OPAQUE Integration (opaque-ke 4)

The Go server uses `bytemare/opaque`. The Rust port uses `opaque-ke` from Facebook.

### Cipher Suite

```rust
struct DefaultCipherSuite;
impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = opaque_ke::ksf::Identity; // No server-side stretching
}
```

### Key Differences from Go Library

| Aspect | Go (bytemare/opaque) | Rust (opaque-ke) |
|--------|----------------------|-------------------|
| Server setup | Separate key + OPRF seed | `ServerSetup` bundles both |
| Fake records | HKDF-derived seed per identifier | `ServerLogin::start()` with `password_file: None` |
| State serialization | Custom bytes | `serde` or `serialize()`/`deserialize()` |
| Server identity | Byte string parameter | `Identifiers { server: Some(b"less-accounts") }` |

### Critical: Wire Protocol Incompatibility

`opaque-ke` and `bytemare/opaque` use different internal representations. This means:

- **Existing OPAQUE registrations from the Go server cannot be used with the Rust server.** Users would need to re-register via the recovery flow.
- The `ServerSetup` (key material) must be generated fresh for the Rust server.
- The `keygen` binary produces a new `ServerSetup` serialized as hex.

This is fine — greenfield deployment, no production users. The Go server is decommissioned.

### Registration Flow

```rust
// 1. Client sends RegistrationRequest bytes
let server_setup: ServerSetup<DefaultCipherSuite> = /* loaded from config */;
let result = ServerRegistration::<DefaultCipherSuite>::start(
    &server_setup,
    RegistrationRequest::deserialize(&request_bytes)?,
    credential_identifier, // username bytes
)?;
// Send result.message.serialize() back to client

// 2. Client sends RegistrationUpload bytes
let password_file = ServerRegistration::<DefaultCipherSuite>::finish(
    RegistrationUpload::deserialize(&upload_bytes)?,
);
// Store password_file.serialize() in DB
```

### Login Flow

```rust
// 1. Client sends CredentialRequest bytes
let result = ServerLogin::<DefaultCipherSuite>::start(
    &mut rng,
    &server_setup,
    Some(ServerRegistration::deserialize(&stored_password_file)?),
    CredentialRequest::deserialize(&request_bytes)?,
    credential_identifier,
    ServerLoginStartParameters {
        identifiers: Identifiers {
            server: Some(b"less-accounts"),
            client: None,
        },
        context: None,
    },
)?;
// Store result.state.serialize() as login state (60s TTL)
// Send result.message.serialize() back to client

// 2. Client sends CredentialFinalization bytes
let state = ServerLogin::deserialize(&stored_state)?;
let result = state.finish(
    CredentialFinalization::deserialize(&finalization_bytes)?,
)?;
// Authentication successful — result.session_key available
```

### Fake Login (Anti-Enumeration)

```rust
// Pass None for password_file — opaque-ke generates a consistent fake response
let result = ServerLogin::<DefaultCipherSuite>::start(
    &mut rng,
    &server_setup,
    None, // No password file — fake login
    CredentialRequest::deserialize(&request_bytes)?,
    credential_identifier,
    ServerLoginStartParameters::default(),
)?;
```

No need for manual HKDF seed derivation like the Go server — `opaque-ke` handles fake records internally using the `ServerSetup`'s OPRF seed.

## Storage Traits

Split along domain boundaries, with all method signatures specified. Source of truth: Go `storage/storage.go`.

```rust
#[async_trait]
pub trait AccountStorage: Send + Sync {
    async fn get_or_create_account(&self, issuer: &str, username: &str, email: &str) -> Result<Account, StorageError>;
    async fn get_account_by_id(&self, id: Uuid) -> Result<Account, StorageError>;
    async fn get_account_by_username(&self, issuer: &str, username: &str) -> Result<Account, StorageError>;
    async fn get_account_by_email(&self, issuer: &str, email: &str) -> Result<Account, StorageError>;
    async fn finalize_registration(&self, account_id: Uuid, opaque_record: &[u8]) -> Result<(), StorageError>;
    async fn finalize_registration_with_root_key(&self, account_id: Uuid, opaque_record: &[u8], wrapped_root_key: &[u8]) -> Result<(), StorageError>;
    async fn update_registration(&self, account_id: Uuid, opaque_record: &[u8]) -> Result<(), StorageError>;
    async fn delete_account(&self, account_id: Uuid) -> Result<(), StorageError>;
}

#[async_trait]
pub trait RootKeyStorage: Send + Sync {
    async fn get_wrapped_root_key(&self, account_id: Uuid) -> Result<Vec<u8>, StorageError>;
    async fn set_wrapped_root_key(&self, account_id: Uuid, wrapped_key: &[u8]) -> Result<(), StorageError>;
}

#[async_trait]
pub trait RegistrationStateStorage: Send + Sync {
    async fn create_registration_state(&self, state: &RegistrationState) -> Result<(), StorageError>;
    async fn get_registration_state(&self, id: Uuid) -> Result<RegistrationState, StorageError>;
    async fn delete_registration_state(&self, id: Uuid) -> Result<(), StorageError>;
}

#[async_trait]
pub trait LoginStateStorage: Send + Sync {
    async fn create_login_state(&self, state: &LoginState) -> Result<(), StorageError>;
    async fn get_login_state(&self, id: Uuid) -> Result<LoginState, StorageError>;
    async fn delete_login_state(&self, id: Uuid) -> Result<(), StorageError>;
}

#[async_trait]
pub trait JwtKeyStorage: Send + Sync {
    async fn get_current_jwt_key(&self) -> Result<JwtKey, StorageError>;
    async fn get_jwt_key_by_id(&self, id: i32) -> Result<JwtKey, StorageError>;
    async fn ensure_jwt_key(&self, secret_key: &[u8]) -> Result<(), StorageError>;
}

#[async_trait]
pub trait UserKeyStorage: Send + Sync {
    async fn list_user_keys(&self, account_id: Uuid) -> Result<Vec<UserKey>, StorageError>;
    async fn get_user_key(&self, account_id: Uuid, service: &str, key_name: &str) -> Result<UserKey, StorageError>;
    async fn store_user_key(&self, account_id: Uuid, service: &str, key_name: &str, key_material: &[u8]) -> Result<(), StorageError>;
}

#[async_trait]
pub trait OAuthClientStorage: Send + Sync {
    async fn create_oauth_client(&self, client: &OAuthClient) -> Result<(), StorageError>;
    async fn get_oauth_client(&self, client_id: Uuid) -> Result<OAuthClient, StorageError>;
    async fn validate_redirect_uri(&self, client_id: Uuid, uri: &str) -> Result<bool, StorageError>;
}

#[async_trait]
pub trait OAuthCodeStorage: Send + Sync {
    async fn create_oauth_code(&self, code: &OAuthCode) -> Result<(), StorageError>;
    async fn get_oauth_code(&self, code: &str) -> Result<OAuthCode, StorageError>;
    /// Atomic get-and-delete
    async fn consume_oauth_code(&self, code: &str) -> Result<OAuthCode, StorageError>;
    async fn delete_oauth_code(&self, code: &str) -> Result<(), StorageError>;
}

#[async_trait]
pub trait OAuthGrantStorage: Send + Sync {
    async fn get_or_create_oauth_grant(&self, client_id: Uuid, account_id: Uuid, scope: &str) -> Result<OAuthGrant, StorageError>;
    async fn get_or_create_oauth_grant_with_thumbprint(&self, client_id: Uuid, account_id: Uuid, scope: &str, thumbprint: &str) -> Result<OAuthGrant, StorageError>;
    async fn get_oauth_grant(&self, grant_id: Uuid) -> Result<OAuthGrant, StorageError>;
    async fn get_oauth_grant_by_account_and_client(&self, account_id: Uuid, client_id: Uuid) -> Result<OAuthGrant, StorageError>;
    async fn get_account_by_key_thumbprint(&self, thumbprint: &str) -> Result<(Account, OAuthGrant), StorageError>;
    async fn update_grant_last_used(&self, grant_id: Uuid) -> Result<(), StorageError>;
    async fn update_grant_keypair(&self, grant_id: Uuid, public_key: &serde_json::Value, blob: &str) -> Result<(), StorageError>;
    async fn update_grant_wrapped_scoped_key(&self, grant_id: Uuid, wrapped_scoped_key: &[u8]) -> Result<(), StorageError>;
    /// First-write-wins: does nothing if already set.
    async fn update_grant_mailbox_id(&self, grant_id: Uuid, mailbox_id: &str) -> Result<(), StorageError>;
    async fn list_grants_for_account(&self, account_id: Uuid) -> Result<Vec<OAuthGrant>, StorageError>;
    async fn batch_update_grant_wrapped_keys(&self, updates: &[GrantKeyUpdate]) -> Result<(), StorageError>;
}

#[async_trait]
pub trait OAuthRefreshTokenStorage: Send + Sync {
    async fn create_refresh_token(&self, token: &OAuthRefreshToken) -> Result<(), StorageError>;
    async fn get_refresh_token_by_hash(&self, hash: &[u8]) -> Result<OAuthRefreshToken, StorageError>;
    async fn delete_refresh_token(&self, token_id: Uuid) -> Result<(), StorageError>;
    async fn delete_refresh_tokens_by_grant(&self, grant_id: Uuid) -> Result<(), StorageError>;
    /// Atomic: delete old token, record it as used, create new token
    async fn rotate_refresh_token(&self, old_token_id: Uuid, old_token_hash: &[u8], grant_id: Uuid, new_token: &OAuthRefreshToken) -> Result<(), StorageError>;
}

#[async_trait]
pub trait OAuthSigningKeyStorage: Send + Sync {
    async fn ensure_oauth_signing_key(&self, private_key: &[u8], public_key: &[u8]) -> Result<(), StorageError>;
    async fn get_current_signing_key(&self) -> Result<OAuthSigningKey, StorageError>;
    async fn get_signing_key_by_id(&self, kid: i32) -> Result<OAuthSigningKey, StorageError>;
    async fn list_signing_keys(&self) -> Result<Vec<OAuthSigningKey>, StorageError>;
}

#[async_trait]
pub trait RecoveryStorage: Send + Sync {
    async fn store_recovery_blob(&self, account_id: Uuid, blob: &[u8]) -> Result<(), StorageError>;
    async fn get_recovery_blob_by_email(&self, issuer: &str, email: &str) -> Result<Vec<u8>, StorageError>;
    async fn delete_recovery_blob(&self, account_id: Uuid) -> Result<(), StorageError>;
}

#[async_trait]
pub trait VerificationStorage: Send + Sync {
    async fn create_verification_code(&self, code: &VerificationCode) -> Result<(), StorageError>;
    async fn get_latest_verification_code_by_email(&self, email: &str, purpose: &str) -> Result<VerificationCode, StorageError>;
    async fn increment_verification_attempts(&self, id: Uuid) -> Result<(), StorageError>;
    async fn delete_verification_code(&self, id: Uuid) -> Result<(), StorageError>;
    async fn check_and_increment_send_rate(&self, email: &str, max_sends: i32, window: Duration, identity_hash_key: &[u8]) -> Result<(), StorageError>;
}

#[async_trait]
pub trait RateLimitStorage: Send + Sync {
    /// Returns Ok(()) if allowed, Err(LoginRateLimited) if locked out
    async fn check_login_allowed(&self, issuer: &str, username: &str) -> Result<(), StorageError>;
    /// Returns lockout duration if a new lockout was applied, or None
    async fn record_failed_login(&self, issuer: &str, username: &str, max_attempts: i32, window: Duration) -> Result<Option<Duration>, StorageError>;
    async fn clear_login_attempts(&self, issuer: &str, username: &str) -> Result<(), StorageError>;
    async fn check_and_increment_recovery_rate(&self, email: &str, max_requests: i32, window: Duration, identity_hash_key: &[u8]) -> Result<(), StorageError>;
    async fn record_used_refresh_token(&self, token_hash: &[u8], grant_id: Uuid) -> Result<(), StorageError>;
    /// Returns Err(RefreshTokenReused) if already used
    async fn check_refresh_token_reused(&self, token_hash: &[u8]) -> Result<(), StorageError>;
}

#[async_trait]
pub trait VerificationTokenStorage: Send + Sync {
    /// Marks a verification token JTI as used. Returns Err(VerificationTokenUsed) on reuse.
    async fn consume_verification_token(&self, jti: &str, expires_at: DateTime<Utc>) -> Result<(), StorageError>;
}

#[async_trait]
pub trait CleanupStorage: Send + Sync {
    async fn cleanup_expired_states(&self) -> Result<(), StorageError>;
    async fn cleanup_expired_oauth_codes(&self) -> Result<(), StorageError>;
    async fn cleanup_expired_refresh_tokens(&self) -> Result<(), StorageError>;
    async fn cleanup_used_refresh_tokens(&self, older_than: Duration) -> Result<(), StorageError>;
    async fn cleanup_expired_verification_codes(&self) -> Result<(), StorageError>;
    async fn cleanup_expired_verification_tokens(&self) -> Result<(), StorageError>;
}

/// Atomic composite operations
#[async_trait]
pub trait CompositeStorage: Send + Sync {
    /// Update OPAQUE registration + root key in one transaction
    async fn update_registration_and_root_key(&self, account_id: Uuid, opaque_record: &[u8], wrapped_root_key: &[u8]) -> Result<(), StorageError>;
    /// Atomic root key rotation: update root key + batch update grant keys + update recovery blob
    async fn rotate_root_key(&self, account_id: Uuid, wrapped_root_key: &[u8], grant_updates: &[GrantKeyUpdate], recovery_blob: &[u8]) -> Result<(), StorageError>;
}

// Supertrait for convenience
pub trait Storage:
    AccountStorage + RootKeyStorage + RegistrationStateStorage + LoginStateStorage +
    JwtKeyStorage + UserKeyStorage +
    OAuthClientStorage + OAuthCodeStorage + OAuthGrantStorage +
    OAuthRefreshTokenStorage + OAuthSigningKeyStorage +
    RecoveryStorage + VerificationStorage + VerificationTokenStorage +
    RateLimitStorage + CleanupStorage + CompositeStorage {}

impl<T> Storage for T where T:
    AccountStorage + RootKeyStorage + RegistrationStateStorage + LoginStateStorage +
    JwtKeyStorage + UserKeyStorage +
    OAuthClientStorage + OAuthCodeStorage + OAuthGrantStorage +
    OAuthRefreshTokenStorage + OAuthSigningKeyStorage +
    RecoveryStorage + VerificationStorage + VerificationTokenStorage +
    RateLimitStorage + CleanupStorage + CompositeStorage {}
```

## Database Schema

Fresh migrations (no Go migration numbering). Compared to Go, the `oprf_seeds` table is **removed** — `opaque-ke` bundles OPRF seeds inside `ServerSetup`. The `oprf_seed_id` FK is dropped from `accounts`, `registration_states`, and `login_states`.

**17 tables** (down from 18):

| Table | Notes |
|-------|-------|
| `accounts` | id, issuer, username, email, opaque_registration, wrapped_root_key, created_at, updated_at |
| `registration_states` | id, account_id FK CASCADE, username, state (opaque-ke bytes), created_at, expires_at |
| `login_states` | id, account_id FK CASCADE nullable, username, state (opaque-ke bytes), created_at, expires_at |
| `jwt_keys` | id SERIAL, secret_key BYTEA, created_at, updated_at |
| `user_keys` | account_id+service+key_name PK, key_material BYTEA, serial_number, created_at, updated_at |
| `oauth_clients` | id UUID, name, secret_hash (nullable), redirect_uris JSONB, allowed_scopes TEXT[], created_at, updated_at |
| `oauth_codes` | code TEXT PK, client_id, account_id, redirect_uri, scope, code_challenge, keys_jwe, keys_jwk_thumbprint, created_at, expires_at |
| `oauth_grants` | id UUID, client_id, account_id, scope, keys_jwk_thumbprint, app_public_key JSONB, app_keypair_blob, wrapped_scoped_key, mailbox_id CHAR(64) UNIQUE, created_at, updated_at, last_used_at |
| `oauth_refresh_tokens` | id UUID, grant_id FK CASCADE, token_hash BYTEA, created_at, expires_at |
| `oauth_signing_keys` | id SERIAL, private_key BYTEA (PKCS#8), public_key BYTEA (SPKI), created_at, updated_at |
| `recovery_blobs` | account_id UUID PK FK CASCADE, blob BYTEA, created_at, updated_at |
| `email_verification_codes` | id UUID, email, code_hash BYTEA, purpose, attempts, created_at, expires_at |
| `email_verification_rate_limits` | email TEXT PK, send_count, window_start |
| `used_verification_tokens` | jti TEXT PK, expires_at |
| `login_attempts` | issuer+username PK, failed_count, first_failed_at, locked_until, lockout_count |
| `recovery_requests` | email TEXT PK, request_count, window_start |
| `used_refresh_tokens` | token_hash BYTEA PK, grant_id FK CASCADE, used_at |

All tables with `updated_at` get `update_updated_at_column()` triggers.

## JWT Token Types

Replicate all 5 token types from the Go server:

| Token | Algorithm | Expiry | Purpose |
|-------|-----------|--------|---------|
| Auth | HS256 | 14 days | Internal session after OPAQUE login |
| State | HS256 | 60 seconds | Ephemeral state reference (binds OPAQUE init→finalize) |
| OAuth Access | ES256 | 15 minutes | Client app authorization |
| OAuth State | HS256 | 10 minutes | Preserve OAuth params across login redirect (not the same as auth code) |
| Verification | HS256 | 15 minutes | One-time email verification proof (JTI tracked for single-use) |

OAuth access tokens include: `sub`, `client_id`, `grant_id`, `scope`, `did`, `personal_space_id`, `mailbox_id`, `aud` (includes `"less-sync"` when `sync` or `files` scope).

## Identity Services

Implemented in `core/identity.rs`:

- **Handle**: `FormatHandle(username, domain) → "user@domain"`, `ParseHandle(handle) → (username, domain)`
- **DID key**: `ComputeDIDKey(p256_public_key_jwk) → "did:key:zDn..."` — multicodec 0x1200 + compressed P-256 point + base58btc
- **PersonalSpaceID**: `personal_space_id(issuer, user_id, client_id) → UUID5(UUID5(DNS, "less.so"), "{issuer}\0{user_id}\0{client_id}")`

These are needed by Phase 8 (OAuth) for access token claims.

## API Routes

All routes from Go, organized by handler module:

### Health
- `GET /health`

### Verification (`api/verification.rs`)
- `POST /v1/accounts/verify/send` — CAP required
- `POST /v1/accounts/verify/confirm`

### Registration (`api/auth.rs`)
- `POST /v1/accounts/password/init` — CAP + verification token
- `POST /v1/accounts/password/finalize`

### Login (`api/auth.rs`)
- `POST /v1/auth/login/init` — CAP required, rate limited
- `POST /v1/auth/login/finalize`

### Authenticated (`api/auth.rs`, `api/keys.rs`, `api/rootkey.rs`, `api/password.rs`)
- `GET /v1/auth/validate`
- `DELETE /v1/accounts`
- `GET /v1/keys`
- `PUT /v1/keys/{service}/{key_name}`
- `GET /v1/keys/{service}/{key_name}`
- `POST /v1/accounts/recovery-blob`
- `GET /v1/accounts/root-key`
- `PUT /v1/accounts/root-key`
- `GET /v1/accounts/grants/wrapped-keys`
- `PUT /v1/accounts/grants/wrapped-keys`
- `POST /v1/accounts/rotate-root-key`
- `POST /v1/accounts/password/change/init`
- `POST /v1/accounts/password/change/verify`
- `POST /v1/accounts/password/change/complete`

### Recovery (`api/recovery.rs`)
- `POST /v1/accounts/recovery-blob/fetch` — verification token
- `POST /v1/accounts/recover/init` — CAP + verification token, rate limited
- `POST /v1/accounts/recover/finalize`

### OAuth (`api/oauth.rs`)
- `GET /oauth/authorize`
- `POST /oauth/consent` — auth required
- `GET /oauth/grant-keypair` — auth required
- `POST /oauth/token` — CORS
- `GET /oauth/userinfo` — OAuth bearer, CORS
- `GET /.well-known/jwks.json` — CORS
- `POST /oauth/mailbox` — OAuth bearer
- `GET /v1/users/{username}/keys/{client_id}` — OAuth bearer
- `GET /v1/users/by-thumbprint/{thumbprint}` — auth required

### Discovery (`api/discovery.rs`)
- `GET /.well-known/less-platform`
- `GET /.well-known/webfinger`

### Web UI (`api/webui.rs`)
- `GET /*` — SPA fallback (embedded React build)

## Middleware

Following `less-sync-rs` patterns, using `tower-http` where possible:

1. **Request body limit** — `tower_http::limit::RequestBodyLimitLayer` set to 64KB (matches Go's `MaxBytesReader`)
2. **CORS** — `tower_http::cors::CorsLayer` (handles OPTIONS preflight automatically, simpler than Go's manual OPTIONS handlers). Applied selectively to CORS-enabled routes (`/oauth/token`, `/oauth/userinfo`, `/.well-known/jwks.json`)
3. **Protocol version** — adds `X-Protocol-Version: 1` header to all responses
4. **Auth middleware** — `axum::middleware::from_fn_with_state()`. Extracts `Authorization: Bearer <token>`, validates via `JwtService`, inserts `AuthContext` into request extensions. Public paths bypass auth.

## Web UI

The React frontend is **copied** from `less-accounts/web/` — it's framework-agnostic and talks to the same HTTP API. No changes needed to the frontend code itself.

Embedded via `rust-embed`:

```rust
#[derive(RustEmbed)]
#[folder = "web/dist/"]
struct WebAssets;
```

SPA fallback: serve `index.html` for paths without file extensions. Cache headers: `immutable` for hashed assets (`/assets/*`), `no-cache` for `index.html`.

**Build note**: `rust-embed` requires `web/dist/` to exist at compile time. The `justfile` should include a `build-web` target that runs `cd web && pnpm build` before `cargo build`. For dev without the frontend, use a cargo feature flag (`--features embed-web`) or create an empty `web/dist/` directory.

## Configuration

```rust
pub struct AppConfig {
    pub listen_addr: SocketAddr,            // LISTEN_ADDR (default 0.0.0.0:5377)
    pub log_format: LogFormat,              // LOG_FORMAT: "text" (default) or "json"
    pub database_url: String,               // DATABASE_URL (required)
    pub server_setup: ServerSetup<CS>,      // OPAQUE_SERVER_SETUP (hex, required)
    pub oauth_issuer: String,               // OAUTH_ISSUER (required)
    pub identity_domain: Option<String>,    // IDENTITY_DOMAIN (default: host from oauth_issuer)
    pub identity_hash_key: [u8; 32],        // IDENTITY_HASH_KEY (hex, 32 bytes, required)
    pub web_base_url: Option<String>,       // WEB_BASE_URL
    pub sync_endpoint: Option<String>,      // SYNC_ENDPOINT (for discovery metadata)
    pub federation_ws_endpoint: Option<String>, // FEDERATION_WS_ENDPOINT (for discovery metadata)
    pub sync_jwks_uri: Option<String>,      // SYNC_JWKS_URI (for discovery metadata)
    pub cap: CapConfig,                     // CAP_KEY_ID, CAP_SECRET, CAP_VERIFY_URL
    pub smtp: SmtpConfig,                   // SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, SMTP_FROM, SMTP_DEV_MODE
}
```

`opaque-ke` bundles the server keypair and OPRF seed into a single `ServerSetup`. The `keygen` binary serializes this as one hex blob (`OPAQUE_SERVER_SETUP`), replacing the Go server's separate `OPAQUE_SERVER_KEY` + `OPAQUE_PUBLIC_KEY` + DB-stored OPRF seeds. This also means the docker-compose `.env` template needs updating in Phase 10.

Config parsing follows `less-sync-rs` pattern: testable `from_values()` function that takes `Option<String>` args, with `from_env()` calling `std::env::var()` and delegating.

## Startup Initialization

Run in `app::run()` before starting the HTTP server:

1. **Run migrations** via `sqlx::migrate!()`
2. **Ensure JWT key** — generate 32-byte random HS256 key and call `storage.ensure_jwt_key()` (no-op if key exists)
3. **Ensure OAuth signing key** — generate P-256 keypair, serialize as PKCS#8/SPKI DER, call `storage.ensure_oauth_signing_key()` (no-op if key exists)
4. **Start background cleanup loop** (see below)
5. **Start HTTP server** with graceful shutdown on SIGINT/SIGTERM

## Background Tasks

Single cleanup loop (spawned in `app::run()`), every 60 seconds:
- Expired registration states (60s TTL)
- Expired login states (60s TTL)
- Expired OAuth codes (10 min)
- Expired refresh tokens (30 days)
- Used refresh tokens older than 7 days
- Expired verification codes (10 min)
- Expired verification token JTIs (15 min)

## Testing Strategy

### Unit Tests
- Inline `#[cfg(test)] mod tests` in every module
- Trait-based test doubles for storage
- `tower::ServiceExt::oneshot()` for HTTP handler tests (no server needed)
- Follow `test_support` pattern from `less-sync-rs` for database tests with `testcontainers`

### Database Tests
- `testcontainers` with postgres for `cargo test` anywhere Docker runs
- Skip gracefully if Docker unavailable
- Per-test isolation via unique schemas

### TypeScript Client Compatibility
After Phase 10, the Rust server should pass the existing integration tests at `less-platform/integration/`. Those tests call the server's HTTP API — just re-point them at the Rust server.

---

## Execution Phases

### Phase 1 — Scaffold
Workspace, Cargo.toml, all crate stubs with `lib.rs`, bins with `main.rs`, Dockerfile, justfile.

**Done when**: `cargo check --workspace` passes, `just check` runs (fmt + clippy + test with no tests).

### Phase 2 — Core + Storage
Domain types (`Account`, `OAuthGrant`, etc.), protocol request/response types, validation (email, username), storage traits (all signatures above), `StorageError` enum, PostgreSQL implementation, SQL migrations.

**Done when**: All storage traits implemented. Database tests pass via testcontainers: CRUD for every entity, error cases (not found, duplicate, expired), atomic operations (`consume_oauth_code`, `rotate_refresh_token`, `rotate_root_key`).

### Phase 3 — Auth (OPAQUE + JWT + ES256) + keygen
`OpaqueService` with opaque-ke, `JwtService` for all 5 token types, `ES256Service` for keypair management + JWKS generation, `keygen` binary, identity services (DID key, PersonalSpaceID, handle parsing).

**Exit criteria — OPAQUE round-trip test**:
1. Generate `ServerSetup` via `keygen`
2. Full registration round-trip using opaque-ke `ClientRegistration` + `ServerRegistration` in-process
3. Full login round-trip using opaque-ke `ClientLogin` + `ServerLogin` in-process
4. Verify fake login produces a valid CredentialResponse (no panic/error)
5. Verify `ServerRegistration` serialization round-trips through bytes (simulating DB storage)

**Also test**: All JWT token types create and validate correctly. ES256 JWKS output matches expected JWK format. DID key computation produces valid `did:key:zDn...`. PersonalSpaceID is deterministic.

### Phase 4 — Email + CAP
`email` crate: `Mailer` trait with `send_verification_code()` and `send_already_registered_notice()`. `SmtpMailer` (lettre) and `DevMailer` (log to stdout). `cap` crate: `CapService` with `verify_token()` — single HTTP POST to CAP server.

**Done when**: `DevMailer` logs correctly. `CapService` makes correct HTTP request (test with mock server via `axum::Router` on ephemeral port).

### Phase 5 — Minimal App Bootstrap + Health
`AppConfig::from_env()`, `run()` function: connect to DB, run migrations, ensure JWT key, ensure signing key, build `ApiState`, start server. Health endpoint. Background cleanup loop.

**Done when**: `cargo run --bin server` starts, connects to Postgres, runs migrations, responds to `GET /health`. Cleanup loop runs without error. Graceful shutdown on Ctrl-C.

### Phase 6 — API: Auth Routes + Middleware
Auth middleware, registration (init/finalize), login (init/finalize), validate, delete account. Wire CAP verification into registration/login handlers.

**Done when**: Full registration + login flow works via `curl` against running server. Rate limiting works (login lockout after N failures). Fake login responds without error. Auth middleware rejects invalid/expired tokens. `tower::oneshot` tests for all handlers.

### Phase 7 — API: Verification + Recovery
Verification send/confirm. Recovery blob store/fetch. OPAQUE re-registration (recover/init, recover/finalize). Rate limiting for verification sends and recovery requests.

**Done when**: Full verification flow (send code → confirm → get token). Full recovery flow (verify email → fetch blob → re-register). Rate limits enforced. `tower::oneshot` tests.

### Phase 8 — API: OAuth
This is the largest phase. Implement in order:

1. **JWKS endpoint** (`GET /.well-known/jwks.json`) — simple, validates ES256 key serving
2. **Authorize + Consent** — `GET /oauth/authorize` (validate client, PKCE, redirect to consent UI) + `POST /oauth/consent` (create grant, generate code)
3. **Token exchange** — `POST /oauth/token` with `grant_type=authorization_code` (validate PKCE, consume code, issue access + refresh tokens)
4. **Extended PKCE + JWE** — when `keys_jwk` is provided: compute extended code challenge as `SHA256(verifier || thumbprint)`, construct JWE with `josekit` to deliver scoped key, store on grant
5. **Refresh token** — `POST /oauth/token` with `grant_type=refresh_token` (rotate token, reuse detection, revoke grant on theft)
6. **UserInfo** — `GET /oauth/userinfo` (OIDC claims from OAuth bearer)
7. **Supporting OAuth routes** — mailbox registration, user key lookup, thumbprint lookup, grant keypair retrieval
8. **Scope validation** — OIDC scopes always allowed; `sync`, `files` require client's `allowed_scopes`; `files` requires `sync`

**Done when**: Full OAuth flow works end-to-end via curl/test. Extended PKCE returns JWE on code exchange but not on refresh. Refresh rotation works. Reuse detection revokes grant. JWKS serves valid keys. `tower::oneshot` tests for all sub-flows.

### Phase 9 — API: Supporting Routes
User keys (list/get/put), root key (get/set), grant wrapped keys (get/batch update), root key rotation, password change (init/verify/complete), discovery (`.well-known/less-platform`, `.well-known/webfinger`).

**Done when**: All endpoints respond correctly. Root key rotation is atomic (root key + grant keys + recovery blob in one transaction). Password change 3-step flow works. Discovery returns correct metadata including sync/federation endpoints. `tower::oneshot` tests.

### Phase 10 — Web UI + CLI + Docker
Copy `less-accounts/web/` into `less-accounts-rs/web/`. Add `build-web` justfile target. Wire `rust-embed` SPA handler. `oauth-client` CLI binary (create/list). Dockerfiles (prod + dev). Update parent repo's `docker-compose.yml` and `.env` template to use `OPAQUE_SERVER_SETUP` instead of `OPAQUE_SERVER_KEY`/`OPAQUE_PUBLIC_KEY`. Update parent `justfile` if needed.

**Done when**: `just dev` in parent repo starts the Rust accounts server. Web UI loads and renders. OAuth client CLI creates clients. Integration tests at `less-platform/integration/` pass against the Rust server.
