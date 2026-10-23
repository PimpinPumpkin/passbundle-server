-- Keykeeper: every item's past versions (DESIGN.md, "Item history"). Each row
-- is an item as it was stored before an edit replaced it: its encrypted fields
-- exactly as they were, which the server can't read, with who saved that
-- version and who replaced it. They go with the item, and stay unnamed when
-- someone who saved or replaced one leaves.
CREATE TABLE keykeeper_cipher_versions (
    uuid             TEXT      NOT NULL PRIMARY KEY,
    cipher_uuid      TEXT      NOT NULL REFERENCES ciphers (uuid) ON DELETE CASCADE,
    atype            INTEGER   NOT NULL,
    akey             TEXT,
    name             TEXT      NOT NULL,
    notes            TEXT,
    fields           TEXT,
    data             TEXT      NOT NULL,
    password_history TEXT,
    reprompt         INTEGER,
    -- Its encrypted fields' length in bytes, for the item's history budget.
    size             INTEGER   NOT NULL,
    revision_date    TIMESTAMP NOT NULL,
    saved_by         TEXT      REFERENCES users (uuid) ON DELETE SET NULL,
    replaced_at      TIMESTAMP NOT NULL,
    replaced_by      TEXT      REFERENCES users (uuid) ON DELETE SET NULL
);

CREATE INDEX keykeeper_cipher_versions_cipher ON keykeeper_cipher_versions (cipher_uuid, replaced_at);

-- Who saved each item as it is now, so the version an edit replaces names
-- its author.
CREATE TABLE keykeeper_cipher_saves (
    cipher_uuid TEXT      NOT NULL PRIMARY KEY REFERENCES ciphers (uuid) ON DELETE CASCADE,
    saved_by    TEXT      REFERENCES users (uuid) ON DELETE SET NULL,
    saved_at    TIMESTAMP NOT NULL
);
