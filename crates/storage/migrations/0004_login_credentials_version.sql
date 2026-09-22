-- Keep the credential snapshot for an OPAQUE exchange on the server. Exposing
-- the counter in login/init JWTs would let callers monitor password changes.
ALTER TABLE login_states ADD COLUMN credentials_version BIGINT NOT NULL DEFAULT 0;
