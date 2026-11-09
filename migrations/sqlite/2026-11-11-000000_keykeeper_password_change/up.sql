-- Keykeeper: whether an organization lets its people use assisted password
-- change on its items (the browser extension changes a login's password on
-- its site; DESIGN.md, "Assisted password change"). An organization without a
-- row allows it: it's on by default, and an organization or its MSP turns it
-- off. Only its owners, admins, and its MSP's admins change it.
CREATE TABLE org_password_change (
    org_uuid TEXT    NOT NULL PRIMARY KEY REFERENCES organizations (uuid) ON DELETE CASCADE,
    allowed  BOOLEAN NOT NULL
);
