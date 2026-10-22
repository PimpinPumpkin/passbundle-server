-- Keykeeper: a technician's role in chosen clients, when it differs from
-- their role in the rest (msp_staff.client_access): admin there
-- (client_access empty), or a custom role (CustomRole as JSON). A row is
-- only for a client the technician reaches. See DESIGN.md, "Per MSP:
-- technician access".
CREATE TABLE msp_staff_client_roles (
    msp_uuid      TEXT NOT NULL REFERENCES msps (uuid) ON DELETE CASCADE,
    user_uuid     TEXT NOT NULL REFERENCES users (uuid) ON DELETE CASCADE,
    org_uuid      TEXT NOT NULL REFERENCES organizations (uuid) ON DELETE CASCADE,
    client_access TEXT,
    PRIMARY KEY (msp_uuid, user_uuid, org_uuid)
);
