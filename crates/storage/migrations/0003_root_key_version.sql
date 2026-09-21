-- AUD-009: root key generation for compare-and-swap rotation. Clients read
-- the version alongside the wrapped root and submit it with a rotation; a
-- mismatch (someone rotated first) rejects the stale rotation.
ALTER TABLE accounts ADD COLUMN root_key_version INT NOT NULL DEFAULT 0;
