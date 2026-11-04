-- Keykeeper: the server security pass (October 2026). See DESIGN.md.

-- Site fixes: the server's operator may have to approve a fix before it
-- fills for everyone (SITE_FIXES_NEED_APPROVAL).
ALTER TABLE site_fixes ADD COLUMN approved_at TIMESTAMP;
-- People who share fixes are now counted with a key derived from the
-- server's RSA key, never kept in the database, and only once they've
-- verified their email address: the old key goes, and counting starts over.
DELETE FROM keykeeper_secrets WHERE name = 'site_fix_reporters';
DELETE FROM site_fix_reporters;
UPDATE site_fixes SET reporters = 0;

-- Install command tokens are found by their SHA-256, and kept sealed with a
-- key the database doesn't have; the server seals the ones kept the old way
-- when it starts.
ALTER TABLE msp_clients ADD COLUMN enrollment_token_hash TEXT;
ALTER TABLE org_setups ADD COLUMN enrollment_token_hash TEXT;
CREATE UNIQUE INDEX msp_clients_enrollment_token_hash ON msp_clients (enrollment_token_hash);
CREATE UNIQUE INDEX org_setups_enrollment_token_hash ON org_setups (enrollment_token_hash);

-- MSP staff invitations keep only their token's SHA-256. Ones made before
-- kept the token itself, so they go: MSP admins invite again.
DELETE FROM msp_invites;
