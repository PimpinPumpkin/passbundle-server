-- Keykeeper: whether an organization's owners and admins see how many of its
-- members' own passwords are weak, reused, or exposed (DESIGN.md, "Members'
-- own passwords"). An organization without a row doesn't, so one made the
-- upstream way (a family or a group) has it off; the Business preset and an
-- MSP's default policies write a row that turns it on. A member's apps send
-- their numbers only while an organization they've joined has it on.
CREATE TABLE org_member_health (
    org_uuid TEXT    NOT NULL PRIMARY KEY REFERENCES organizations (uuid) ON DELETE CASCADE,
    enabled  BOOLEAN NOT NULL
);
