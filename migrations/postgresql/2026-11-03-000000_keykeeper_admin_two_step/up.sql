-- Keykeeper: two-step login for the people who run an organization. An
-- organization that turns it on requires its owners, admins, and custom roles
-- that manage members, policies, or account recovery to sign in with an
-- authenticator app, a security key or passkey, or Duo. An organization
-- without a row doesn't require it; the Business preset and an MSP's default
-- policies turn it on. See DESIGN.md, "Two-step login for admins".
CREATE TABLE org_admin_two_step (
    org_uuid TEXT    NOT NULL PRIMARY KEY REFERENCES organizations (uuid) ON DELETE CASCADE,
    required BOOLEAN NOT NULL
);
-- Whether an MSP requires two-step login of everyone on its staff. An MSP
-- without a row does: it's on by default.
CREATE TABLE msp_staff_two_step (
    msp_uuid TEXT    NOT NULL PRIMARY KEY REFERENCES msps (uuid) ON DELETE CASCADE,
    required BOOLEAN NOT NULL
);
-- A setup session: what a sign-in gets, after the password and any email
-- code, when the person's role requires two-step login and they haven't set
-- it up. Only the endpoints that set up two-step login take it, for fifteen
-- minutes, one at a time per account, and it ends when setup is done. Kept
-- only as a SHA-256 hash.
CREATE TABLE two_step_setup_sessions (
    session_hash TEXT      NOT NULL PRIMARY KEY,
    user_uuid    TEXT      NOT NULL REFERENCES users (uuid) ON DELETE CASCADE,
    device_type  INTEGER   NOT NULL,
    created_at   TIMESTAMP NOT NULL
);
-- A membership the server accepted for its person, on a server that sends no
-- email (upstream joins an existing account at once when it's invited). The
-- person never accepted it, so two-step login for admins doesn't count it
-- until they do, in the web vault: otherwise anyone could sign someone out,
-- and hold up their sign-in, by inviting them as an admin.
CREATE TABLE unaccepted_memberships (
    membership_uuid TEXT NOT NULL PRIMARY KEY REFERENCES users_organizations (uuid) ON DELETE CASCADE
);
