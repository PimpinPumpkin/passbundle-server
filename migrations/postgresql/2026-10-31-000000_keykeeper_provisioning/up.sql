-- Keykeeper: provisioning from Microsoft Entra ID, or any SCIM 2.0 client
-- (DESIGN.md, "Provisioning from Entra ID", in the meta repo).
--
-- One token per organization. The server makes it, shows it once, and keeps
-- only its SHA-256: a token is 32 random bytes, so there's nothing to guess.
CREATE TABLE scim_tokens (
    org_uuid     TEXT      NOT NULL PRIMARY KEY REFERENCES organizations (uuid) ON DELETE CASCADE,
    token_hash   TEXT      NOT NULL,
    -- The email of whoever made it, kept readable if their account goes.
    created_by   TEXT      NOT NULL,
    created_at   TIMESTAMP NOT NULL,
    last_used_at TIMESTAMP,
    last_used_ip TEXT
);
-- A member as the directory knows them: what it sent, as it sent it, never
-- anything about their vault. Every member the directory matched or invited
-- has one; it goes with the membership.
CREATE TABLE scim_users (
    membership_uuid TEXT      NOT NULL PRIMARY KEY REFERENCES users_organizations (uuid) ON DELETE CASCADE,
    org_uuid        TEXT      NOT NULL REFERENCES organizations (uuid) ON DELETE CASCADE,
    user_name       TEXT      NOT NULL,
    -- user_name lowercased, for matching (SCIM's userName isn't case exact).
    user_name_key   TEXT      NOT NULL,
    external_id     TEXT,
    -- The other attributes it sent (name, emails, ...), as JSON.
    attributes      TEXT      NOT NULL,
    -- Provisioning made the membership (an invitation), rather than matching
    -- someone who was already a member.
    provisioned     BOOLEAN   NOT NULL,
    -- Provisioning turned them off, so it may turn them back on. Someone an
    -- admin turned off stays off until an admin turns them on.
    turned_off      BOOLEAN   NOT NULL,
    -- The directory asked to turn off or remove someone provisioning never
    -- changes (owners, admins, custom roles, an MSP's staff), so the
    -- organization's admins can do it themselves.
    refused_off_at  TIMESTAMP,
    created_at      TIMESTAMP NOT NULL,
    updated_at      TIMESTAMP NOT NULL
);
CREATE UNIQUE INDEX scim_users_user_name ON scim_users (org_uuid, user_name_key);
-- Groups provisioning made. Only these are the directory's to change; groups
-- made in PassBundle are never touched. A group's externalId is upstream's
-- groups.external_id.
CREATE TABLE scim_groups (
    group_uuid TEXT      NOT NULL PRIMARY KEY REFERENCES groups (uuid) ON DELETE CASCADE,
    org_uuid   TEXT      NOT NULL REFERENCES organizations (uuid) ON DELETE CASCADE,
    created_at TIMESTAMP NOT NULL
);
CREATE INDEX scim_groups_org ON scim_groups (org_uuid);
-- Who acted when it wasn't a person: upstream's system users (1 is SCIM),
-- which the web vault's event log names. Not "system_user": that's a
-- keyword in PostgreSQL.
ALTER TABLE event ADD COLUMN system_actor INTEGER;
