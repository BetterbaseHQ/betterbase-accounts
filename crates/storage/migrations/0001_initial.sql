-- Initial schema for less-accounts-rs.
-- Differences from Go schema:
--   - No oprf_seeds table (opaque-ke bundles them in ServerSetup)
--   - No oprf_seed_id FK on accounts, registration_states, login_states

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Accounts
CREATE TABLE accounts (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer       TEXT NOT NULL,
    username     TEXT NOT NULL,
    email        TEXT NOT NULL,
    opaque_record  BYTEA,
    wrapped_root_key     BYTEA,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_username_format CHECK (username ~ '^[a-z0-9_]{3,32}$'),
    CONSTRAINT uq_accounts_issuer_username UNIQUE (issuer, username),
    CONSTRAINT uq_accounts_issuer_email    UNIQUE (issuer, email)
);
CREATE TRIGGER trg_accounts_updated_at
    BEFORE UPDATE ON accounts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Registration states (60s TTL)
-- No server-side state is needed between OPAQUE registration rounds (stateless finish).
CREATE TABLE registration_states (
    id          UUID PRIMARY KEY,
    account_id  UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    username    TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_registration_states_expires ON registration_states(expires_at);

-- Login states (60s TTL)
CREATE TABLE login_states (
    id          UUID PRIMARY KEY,
    account_id  UUID REFERENCES accounts(id) ON DELETE CASCADE,
    username    TEXT NOT NULL,
    state       BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_login_states_expires ON login_states(expires_at);

-- JWT keys (HS256)
CREATE TABLE jwt_keys (
    id          SERIAL PRIMARY KEY,
    secret_key  BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TRIGGER trg_jwt_keys_updated_at
    BEFORE UPDATE ON jwt_keys
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- User keys (service-specific encrypted material)
CREATE TABLE user_keys (
    account_id    UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    service       TEXT NOT NULL,
    key_name      TEXT NOT NULL,
    key_material  BYTEA NOT NULL,
    serial_number BIGINT NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (account_id, service, key_name)
);
CREATE TRIGGER trg_user_keys_updated_at
    BEFORE UPDATE ON user_keys
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- OAuth clients
CREATE TABLE oauth_clients (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name           TEXT NOT NULL,
    secret_hash    TEXT,
    redirect_uris  JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_scopes TEXT[] NOT NULL DEFAULT '{}',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TRIGGER trg_oauth_clients_updated_at
    BEFORE UPDATE ON oauth_clients
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- OAuth authorization codes (10-min TTL)
CREATE TABLE oauth_codes (
    code                  TEXT PRIMARY KEY,
    client_id             UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    account_id            UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    redirect_uri          TEXT NOT NULL,
    scope                 TEXT NOT NULL,
    code_challenge        TEXT NOT NULL,
    keys_jwe              TEXT,
    keys_jwk_thumbprint   TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at            TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_oauth_codes_expires ON oauth_codes(expires_at);

-- OAuth grants (persistent user consent)
CREATE TABLE oauth_grants (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id           UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    account_id          UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    scope               TEXT NOT NULL,
    keys_jwk_thumbprint TEXT,
    app_public_key      JSONB,
    app_keypair_blob    TEXT,
    wrapped_scoped_key  BYTEA,
    mailbox_id          CHAR(64),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_oauth_grants_client_account UNIQUE (client_id, account_id)
);
CREATE UNIQUE INDEX idx_oauth_grants_mailbox_id
    ON oauth_grants(mailbox_id)
    WHERE mailbox_id IS NOT NULL;
CREATE INDEX idx_oauth_grants_keys_jwk_thumbprint
    ON oauth_grants(keys_jwk_thumbprint)
    WHERE keys_jwk_thumbprint IS NOT NULL;
CREATE TRIGGER trg_oauth_grants_updated_at
    BEFORE UPDATE ON oauth_grants
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- OAuth refresh tokens
CREATE TABLE oauth_refresh_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    grant_id    UUID NOT NULL REFERENCES oauth_grants(id) ON DELETE CASCADE,
    token_hash  BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_oauth_refresh_tokens_expires ON oauth_refresh_tokens(expires_at);
CREATE INDEX idx_oauth_refresh_tokens_hash    ON oauth_refresh_tokens(token_hash);

-- OAuth signing keys (ES256)
CREATE TABLE oauth_signing_keys (
    id          SERIAL PRIMARY KEY,
    private_key BYTEA NOT NULL,
    public_key  BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TRIGGER trg_oauth_signing_keys_updated_at
    BEFORE UPDATE ON oauth_signing_keys
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Recovery blobs (encrypted account recovery export)
CREATE TABLE recovery_blobs (
    account_id  UUID PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    blob        BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TRIGGER trg_recovery_blobs_updated_at
    BEFORE UPDATE ON recovery_blobs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Email verification codes (10-min TTL)
CREATE TABLE email_verification_codes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email       TEXT NOT NULL,
    code_hash   BYTEA NOT NULL,
    purpose     TEXT NOT NULL CHECK (purpose IN ('registration', 'recovery')),
    attempts    INT  NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_email_verification_codes_email_purpose ON email_verification_codes(email, purpose);
CREATE INDEX idx_email_verification_codes_expires       ON email_verification_codes(expires_at);

-- Email verification send-rate limits (identity_key = HMAC-hashed email)
CREATE TABLE email_verification_rate_limits (
    identity_key TEXT PRIMARY KEY,
    send_count   INT          NOT NULL DEFAULT 0,
    window_start TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_email_verification_rate_limits_window ON email_verification_rate_limits(window_start);

-- Used verification token JTIs (15-min TTL)
CREATE TABLE used_verification_tokens (
    jti        TEXT PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_used_verification_tokens_expires ON used_verification_tokens(expires_at);

-- Login rate limiting (brute-force protection)
CREATE TABLE login_attempts (
    issuer         TEXT NOT NULL,
    username       TEXT NOT NULL,
    failed_count   INT  NOT NULL DEFAULT 0,
    first_failed_at TIMESTAMPTZ,
    locked_until   TIMESTAMPTZ,
    lockout_count  INT  NOT NULL DEFAULT 0,
    PRIMARY KEY (issuer, username)
);
CREATE INDEX idx_login_attempts_locked ON login_attempts(locked_until)
    WHERE locked_until IS NOT NULL;

-- Recovery initiation rate limiting (identity_key = HMAC-hashed email)
CREATE TABLE recovery_requests (
    identity_key  TEXT PRIMARY KEY,
    request_count INT          NOT NULL DEFAULT 0,
    window_start  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_recovery_requests_window ON recovery_requests(window_start);

-- Used refresh tokens (reuse detection)
CREATE TABLE used_refresh_tokens (
    token_hash BYTEA PRIMARY KEY,
    grant_id   UUID  NOT NULL REFERENCES oauth_grants(id) ON DELETE CASCADE,
    used_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_used_refresh_tokens_used_at ON used_refresh_tokens(used_at);
CREATE INDEX idx_used_refresh_tokens_grant   ON used_refresh_tokens(grant_id);
