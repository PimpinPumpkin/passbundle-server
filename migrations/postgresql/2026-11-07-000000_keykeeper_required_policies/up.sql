-- Keykeeper: an MSP can require one of its default policies for every client
-- (DESIGN.md, "Required for every client", in the meta repo). A required
-- default reaches every client, including those with their own setting, and
-- nobody can change that policy in a client's admin console until it's no
-- longer required.
ALTER TABLE msp_policies ADD COLUMN required BOOLEAN NOT NULL DEFAULT FALSE;

-- The clients that had their own setting when a requirement changed their
-- policy, so the MSP can tell which ones might want to go back once it stops
-- requiring it. Client ids only, never what their policy was. Cleared when
-- the MSP stops requiring the policy, and for a client when it leaves the MSP.
CREATE TABLE msp_required_had_own (
    msp_uuid TEXT    NOT NULL REFERENCES msps (uuid) ON DELETE CASCADE,
    atype    INTEGER NOT NULL,
    org_uuid TEXT    NOT NULL REFERENCES organizations (uuid) ON DELETE CASCADE,
    PRIMARY KEY (msp_uuid, atype, org_uuid)
);
