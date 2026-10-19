-- Keykeeper: a company's own organization, set up with a preset rather than
-- through an MSP: the preset it started with, its install command's
-- enrollment token, and the collection people who join with it get. An MSP's
-- clients keep the same in msp_clients. See DESIGN.md, "A company's own IT".
CREATE TABLE org_setups (
    org_uuid                    TEXT NOT NULL PRIMARY KEY REFERENCES organizations (uuid) ON DELETE CASCADE,
    created_at                  DATETIME NOT NULL,
    preset                      TEXT,
    enrollment_token            TEXT,
    enrollment_token_created_at DATETIME,
    everyone_collection         TEXT
);
CREATE UNIQUE INDEX org_setups_enrollment_token ON org_setups (enrollment_token);
