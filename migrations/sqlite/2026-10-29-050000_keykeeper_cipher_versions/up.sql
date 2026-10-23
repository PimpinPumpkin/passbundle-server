-- Keykeeper: every item's past versions (DESIGN.md, "Item history"). Each row
-- is an item as it was stored before a save replaced it: its encrypted fields
-- exactly as they were, which the server can't read. They go with the item,
-- and stay when the person who replaced them leaves.
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
    revision_date    TIMESTAMP NOT NULL,
    replaced_at      TIMESTAMP NOT NULL,
    replaced_by      TEXT      REFERENCES users (uuid) ON DELETE SET NULL
);

CREATE INDEX keykeeper_cipher_versions_cipher ON keykeeper_cipher_versions (cipher_uuid, replaced_at);
