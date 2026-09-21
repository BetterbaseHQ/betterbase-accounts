-- AUD-011: per-account credentials version for revoking prior sessions.
-- Bumped on password change and recovery completion; auth JWTs embed the
-- version they were minted under and accounts-side validation compares.
ALTER TABLE accounts ADD COLUMN credentials_version INT NOT NULL DEFAULT 0;
