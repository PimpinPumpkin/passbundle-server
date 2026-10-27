-- Keykeeper: offboarding that holds (DESIGN.md, "Offboarding", in the meta
-- repo).
--
-- Someone an organization removed (its admins, its directory, or its API
-- key's import), or an MSP's person the client itself removed or revoked.
-- Their own joins with an install command wait for an admin's approval,
-- and an MSP's staff changes never add or confirm them there again. A new
-- invitation from the organization's own people clears it.
CREATE TABLE removed_members (
    org_uuid   TEXT      NOT NULL REFERENCES organizations (uuid) ON DELETE CASCADE,
    user_uuid  TEXT      NOT NULL REFERENCES users (uuid) ON DELETE CASCADE,
    removed_at TIMESTAMP NOT NULL,
    -- The MSP whose membership the client removed or revoked, if it was one.
    -- Without the MSP, they're still someone the organization removed.
    msp_uuid   TEXT      REFERENCES msps (uuid) ON DELETE SET NULL,
    -- Revoked rather than removed: restoring them clears it.
    revoked    BOOLEAN   NOT NULL,
    PRIMARY KEY (org_uuid, user_uuid)
);
-- The account that made a provisioning token: the token stops working
-- once they no longer manage the organization.
ALTER TABLE scim_tokens ADD COLUMN created_by_user TEXT;
