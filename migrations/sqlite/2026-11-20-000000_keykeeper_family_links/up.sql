-- Keykeeper: a family's invite link (DESIGN.md, "A family's invite link", in
-- the meta repo). One per family. The server keeps only the SHA-256 of the
-- link's token (token_hash, NULL while the link is off), compared in constant
-- time, never the token. The link's settings, the token and the join secret
-- among them, are kept only encrypted with the family's key by the owner's
-- or admin's browser that saved them (sealed), which the server can't read.
CREATE TABLE family_links (
    org_uuid        TEXT      NOT NULL PRIMARY KEY REFERENCES organizations (uuid) ON DELETE CASCADE,
    token_hash      TEXT,
    sealed          TEXT      NOT NULL,
    automatic       BOOLEAN   NOT NULL DEFAULT 0,
    expires_at      DATETIME,
    made_by         TEXT      REFERENCES users (uuid) ON DELETE SET NULL,
    made_at         DATETIME NOT NULL,
    collection_uuid TEXT      REFERENCES collections (uuid) ON DELETE SET NULL
);

-- Each join with a family's link: the join's proof (made with the link's
-- join secret, which the server never sees) and whether the link let people
-- in automatically when they joined.
CREATE TABLE family_link_joins (
    membership_uuid TEXT      NOT NULL PRIMARY KEY REFERENCES users_organizations (uuid) ON DELETE CASCADE,
    org_uuid        TEXT      NOT NULL REFERENCES organizations (uuid) ON DELETE CASCADE,
    proof           TEXT,
    automatic       BOOLEAN   NOT NULL DEFAULT 0,
    joined_at       DATETIME NOT NULL
);
CREATE INDEX family_link_joins_org ON family_link_joins (org_uuid);

-- When an account said "No thanks" to the suggestion to add a legacy
-- contact, which then stays away on every device.
CREATE TABLE legacy_contact_suggestions (
    user_uuid    TEXT      NOT NULL PRIMARY KEY REFERENCES users (uuid) ON DELETE CASCADE,
    dismissed_at DATETIME NOT NULL
);
