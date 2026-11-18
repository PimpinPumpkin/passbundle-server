-- Keykeeper: an organization that already uses PassBundle joins an MSP with
-- a one-time code the MSP gives its owner (DESIGN.md, "An organization that
-- already uses PassBundle", in the meta repo).
--
-- A code is 24 characters: the first 8 find it (selector), and the server
-- keeps only a SHA-256 of the whole code (code_hash), never the code. It
-- works once (the row is deleted when it's used or revoked) and until
-- expires_at.
CREATE TABLE msp_link_codes (
    uuid             TEXT NOT NULL PRIMARY KEY,
    msp_uuid         TEXT NOT NULL REFERENCES msps (uuid) ON DELETE CASCADE,
    selector         TEXT NOT NULL,
    code_hash        TEXT NOT NULL,
    label            TEXT,
    created_by_uuid  TEXT REFERENCES users (uuid) ON DELETE SET NULL,
    created_by_email TEXT NOT NULL,
    created_at       DATETIME NOT NULL,
    expires_at       DATETIME NOT NULL
);
CREATE UNIQUE INDEX msp_link_codes_selector ON msp_link_codes (selector);
CREATE INDEX msp_link_codes_msp ON msp_link_codes (msp_uuid);

-- A client that joined its MSP with a code. Until the owner decides who
-- pays (DESIGN.md, "Plans and billing", decision 14), it keeps its own plan:
-- the MSP's pool doesn't cover it.
ALTER TABLE msp_clients ADD COLUMN joined_with_code BOOLEAN NOT NULL DEFAULT 0;

-- The organization took this person out by removing their MSP as a whole,
-- rather than removing or revoking them itself. Joining an MSP with a code
-- doesn't keep them out (DESIGN.md, "Offboarding").
ALTER TABLE removed_members ADD COLUMN with_msp BOOLEAN NOT NULL DEFAULT 0;
