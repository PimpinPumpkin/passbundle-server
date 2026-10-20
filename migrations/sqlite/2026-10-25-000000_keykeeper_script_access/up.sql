-- Keykeeper: script access. A token reads only copies of the fields it was
-- granted, encrypted with a key the server never sees. See
-- docs/script-access.md in the meta repo.
CREATE TABLE script_tokens (
    uuid         TEXT NOT NULL PRIMARY KEY,
    org_uuid     TEXT NOT NULL REFERENCES organizations (uuid) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    created_by   TEXT NOT NULL,
    created_at   TIMESTAMP NOT NULL,
    expires_at   TIMESTAMP NOT NULL,
    revoked_at   TIMESTAMP,
    -- SHA-256 of the auth secret, which is derived from the token's seed.
    auth_hash    TEXT NOT NULL,
    -- The networks it may be used from, as a JSON list; empty for anywhere.
    networks     TEXT NOT NULL,
    -- The token key, sealed with the organization key.
    sealed_key   TEXT NOT NULL,
    last_used_at TIMESTAMP,
    last_used_ip TEXT
);
CREATE INDEX script_tokens_org ON script_tokens (org_uuid);
-- A grant: the token's copy of an item's chosen fields, the item revision it
-- was made from, and which fields it copies (sealed with the organization key).
CREATE TABLE script_grants (
    token_uuid  TEXT NOT NULL REFERENCES script_tokens (uuid) ON DELETE CASCADE,
    cipher_uuid TEXT NOT NULL REFERENCES ciphers (uuid) ON DELETE CASCADE,
    copy        TEXT NOT NULL,
    revision    TEXT NOT NULL,
    sealed_spec TEXT NOT NULL,
    PRIMARY KEY (token_uuid, cipher_uuid)
);
CREATE INDEX script_grants_cipher ON script_grants (cipher_uuid);
-- Every read, allowed or refused.
CREATE TABLE script_reads (
    uuid        TEXT NOT NULL PRIMARY KEY,
    token_uuid  TEXT NOT NULL REFERENCES script_tokens (uuid) ON DELETE CASCADE,
    cipher_uuid TEXT,
    read_at     TIMESTAMP NOT NULL,
    ip          TEXT NOT NULL,
    allowed     BOOLEAN NOT NULL,
    reason      TEXT NOT NULL
);
CREATE INDEX script_reads_token ON script_reads (token_uuid, read_at);
