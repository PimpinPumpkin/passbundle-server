-- Keykeeper: sign in with Microsoft Entra ID, set up per organization
-- (DESIGN.md, "Sign in with Microsoft Entra ID", in the meta repo).
--
-- One sign-in setup per organization: its Entra tenant, the app registration
-- its admins made there, and the identifier people type to find it.
CREATE TABLE keykeeper_sso (
    org_uuid      TEXT      NOT NULL PRIMARY KEY REFERENCES organizations (uuid) ON DELETE CASCADE,
    enabled       BOOLEAN   NOT NULL,
    -- What people type to sign in: lowercase letters, digits, and hyphens.
    identifier    TEXT      NOT NULL UNIQUE,
    -- The Entra tenant's id (a GUID, lowercase) and the app's client id.
    tenant_id     TEXT      NOT NULL,
    client_id     TEXT      NOT NULL,
    -- The app's client secret, sealed. Never sent back to anyone.
    client_secret TEXT,
    secret_set_at TIMESTAMP,
    -- The email of whoever last changed it, kept readable if their account goes.
    updated_by    TEXT      NOT NULL,
    created_at    TIMESTAMP NOT NULL,
    updated_at    TIMESTAMP NOT NULL
);
-- Email domains an organization proved it controls with a DNS TXT record.
-- Any organization can add a domain; only one can verify it.
CREATE TABLE keykeeper_sso_domains (
    uuid            TEXT      NOT NULL PRIMARY KEY,
    org_uuid        TEXT      NOT NULL REFERENCES organizations (uuid) ON DELETE CASCADE,
    domain          TEXT      NOT NULL,
    -- The random value the TXT record must carry.
    txt_token       TEXT      NOT NULL,
    created_by      TEXT      NOT NULL,
    created_at      TIMESTAMP NOT NULL,
    verified_at     TIMESTAMP,
    last_checked_at TIMESTAMP
);
CREATE UNIQUE INDEX keykeeper_sso_domains_org ON keykeeper_sso_domains (org_uuid, domain);
CREATE UNIQUE INDEX keykeeper_sso_domains_verified ON keykeeper_sso_domains (domain) WHERE verified_at IS NOT NULL;
-- Which account a person in the organization's tenant signs in to, by
-- Entra's immutable tenant id and object id, never by email.
CREATE TABLE keykeeper_sso_links (
    org_uuid     TEXT      NOT NULL REFERENCES organizations (uuid) ON DELETE CASCADE,
    tenant_id    TEXT      NOT NULL,
    object_id    TEXT      NOT NULL,
    user_uuid    TEXT      NOT NULL REFERENCES users (uuid) ON DELETE CASCADE,
    -- The email Entra sent when the link was made, for the settings page.
    email        TEXT      NOT NULL,
    created_at   TIMESTAMP NOT NULL,
    last_used_at TIMESTAMP,
    PRIMARY KEY (org_uuid, tenant_id, object_id)
);
CREATE UNIQUE INDEX keykeeper_sso_links_user ON keykeeper_sso_links (org_uuid, user_uuid);
-- A sign-in in progress, for ten minutes at most. Secrets that travel in
-- URLs (the state, the code) are kept only as SHA-256 hashes.
CREATE TABLE keykeeper_sso_auth (
    state_hash       TEXT      NOT NULL PRIMARY KEY,
    org_uuid         TEXT      NOT NULL REFERENCES organizations (uuid) ON DELETE CASCADE,
    -- What the app sent: its client, where to send it back, its state, and
    -- its PKCE challenge, checked when it redeems the code.
    client_id        TEXT      NOT NULL,
    redirect_uri     TEXT      NOT NULL,
    client_state     TEXT      NOT NULL,
    client_challenge TEXT      NOT NULL,
    -- This server's own nonce and PKCE verifier for Entra.
    nonce            TEXT      NOT NULL,
    code_verifier    TEXT      NOT NULL,
    -- Ties Entra's answer to the browser that started (a cookie's hash).
    binding_hash     TEXT      NOT NULL,
    -- The one-time code this server gave the app, once Entra answered.
    code_hash        TEXT      UNIQUE,
    -- For linking an account to single sign-on (upstream's Link SSO): the
    -- account and the session that asked, from its link ticket. The link
    -- waits for that session to confirm it.
    link_user_uuid   TEXT      REFERENCES users (uuid) ON DELETE CASCADE,
    link_session     TEXT,
    -- Who Entra said it was (JSON), or why it didn't work.
    identity         TEXT,
    error            TEXT,
    created_at       TIMESTAMP NOT NULL,
    returned_at      TIMESTAMP
);
CREATE INDEX keykeeper_sso_auth_created ON keykeeper_sso_auth (created_at);
-- A session's ticket to link its own account to single sign-on: five
-- minutes, once, from the browser it was issued to (a cookie's hash), kept
-- only as a SHA-256 hash.
CREATE TABLE keykeeper_sso_link_tickets (
    ticket_hash  TEXT      NOT NULL PRIMARY KEY,
    user_uuid    TEXT      NOT NULL REFERENCES users (uuid) ON DELETE CASCADE,
    -- Only this organization's single sign-on, for a linking session.
    org_uuid     TEXT      REFERENCES organizations (uuid) ON DELETE CASCADE,
    binding_hash TEXT      NOT NULL,
    -- Which session asked: "device:<id>" or "link:<hash>".
    session_ref  TEXT      NOT NULL,
    created_at   TIMESTAMP NOT NULL
);
-- A linking session: what a password sign-in gets, after two-step login, when
-- an organization requires single sign-on of someone who isn't linked yet. It
-- can only link them to that organization's single sign-on, for fifteen
-- minutes, and ends when the link is made. Kept only as a SHA-256 hash.
CREATE TABLE keykeeper_sso_link_sessions (
    session_hash TEXT      NOT NULL PRIMARY KEY,
    user_uuid    TEXT      NOT NULL REFERENCES users (uuid) ON DELETE CASCADE,
    org_uuid     TEXT      NOT NULL REFERENCES organizations (uuid) ON DELETE CASCADE,
    created_at   TIMESTAMP NOT NULL
);
-- An event's subject in words, where it has one: a domain for domain events
-- (upstream's domainName), or why a single sign-on was refused.
ALTER TABLE event ADD COLUMN keykeeper_detail TEXT;
