-- Keykeeper: indexes for what every sync and sign-in looks up by: a person's
-- items, folders, organizations, collections, Sends, devices, and two-step
-- login, and an organization's items, collections, policies, and groups.
-- Upstream has none beyond primary keys, so each of these lookups read the
-- whole table, and a sync got slower as the service grew. See DESIGN.md,
-- "Capacity".
CREATE INDEX IF NOT EXISTS keykeeper_ciphers_user ON ciphers (user_uuid);
CREATE INDEX IF NOT EXISTS keykeeper_ciphers_org ON ciphers (organization_uuid);
CREATE INDEX IF NOT EXISTS keykeeper_attachments_cipher ON attachments (cipher_uuid);
CREATE INDEX IF NOT EXISTS keykeeper_folders_user ON folders (user_uuid);
CREATE INDEX IF NOT EXISTS keykeeper_folders_ciphers_folder ON folders_ciphers (folder_uuid);
CREATE INDEX IF NOT EXISTS keykeeper_ciphers_collections_collection ON ciphers_collections (collection_uuid);
CREATE INDEX IF NOT EXISTS keykeeper_collections_org ON collections (org_uuid);
CREATE INDEX IF NOT EXISTS keykeeper_users_collections_collection ON users_collections (collection_uuid);
CREATE INDEX IF NOT EXISTS keykeeper_users_organizations_user ON users_organizations (user_uuid);
CREATE INDEX IF NOT EXISTS keykeeper_users_organizations_org ON users_organizations (org_uuid);
CREATE INDEX IF NOT EXISTS keykeeper_org_policies_org ON org_policies (org_uuid);
CREATE INDEX IF NOT EXISTS keykeeper_groups_org ON groups (organizations_uuid);
CREATE INDEX IF NOT EXISTS keykeeper_groups_users_member ON groups_users (users_organizations_uuid);
CREATE INDEX IF NOT EXISTS keykeeper_collections_groups_group ON collections_groups (groups_uuid);
CREATE INDEX IF NOT EXISTS keykeeper_sends_user ON sends (user_uuid);
CREATE INDEX IF NOT EXISTS keykeeper_devices_user ON devices (user_uuid);
CREATE INDEX IF NOT EXISTS keykeeper_twofactor_user ON twofactor (user_uuid);
CREATE INDEX IF NOT EXISTS keykeeper_emergency_access_grantor ON emergency_access (grantor_uuid);
CREATE INDEX IF NOT EXISTS keykeeper_emergency_access_grantee ON emergency_access (grantee_uuid);
