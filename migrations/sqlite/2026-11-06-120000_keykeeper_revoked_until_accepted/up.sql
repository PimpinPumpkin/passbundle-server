-- Keykeeper: a membership revoked until its person accepts it. On a server
-- that sends no email, a role the server accepted for its person isn't
-- counted by two-step login for admins until they accept it themselves
-- (unaccepted_memberships), so one confirmed before the organization required
-- it would keep the role without two-step login. When the rule comes to
-- cover it, it's revoked until they accept, and accepting restores it. See
-- DESIGN.md, "Two-step login for admins".
CREATE TABLE revoked_until_accepted (
    membership_uuid TEXT NOT NULL PRIMARY KEY REFERENCES users_organizations (uuid) ON DELETE CASCADE
);
