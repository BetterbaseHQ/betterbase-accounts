-- Reject credential completion prepared before another session rotated the root.
ALTER TABLE login_states ADD COLUMN root_key_version BIGINT NOT NULL DEFAULT 0;
ALTER TABLE registration_states ADD COLUMN root_key_version BIGINT NOT NULL DEFAULT 0;
