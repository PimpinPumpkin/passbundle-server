-- Keykeeper: what lets an app confirm a join on its own without trusting the
-- server (DESIGN.md, "Joins a hacked server can't forge"). The server can't
-- read or make any of these; it only keeps them for the apps.
-- The install command's join secret, encrypted with the organization's key.
ALTER TABLE msp_clients ADD COLUMN enrollment_secret TEXT;
ALTER TABLE org_setups ADD COLUMN enrollment_secret TEXT;
-- The proof each install command join came with.
ALTER TABLE msp_enrollment_joins ADD COLUMN proof TEXT;
-- Seals an owner's or admin's app made over an email invitation ("invite")
-- or an MSP staff member's place in a client ("staff"), by email.
CREATE TABLE join_seals (
    org_uuid TEXT NOT NULL REFERENCES organizations (uuid) ON DELETE CASCADE,
    email    TEXT NOT NULL,
    kind     TEXT NOT NULL,
    seal     TEXT NOT NULL,
    PRIMARY KEY (org_uuid, email, kind)
);
-- The seal over an organization's joining setting and email domains.
CREATE TABLE joining_seals (
    org_uuid TEXT NOT NULL PRIMARY KEY REFERENCES organizations (uuid) ON DELETE CASCADE,
    seal     TEXT NOT NULL
);
