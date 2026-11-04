DROP INDEX org_setups_enrollment_token_hash;
DROP INDEX msp_clients_enrollment_token_hash;
ALTER TABLE org_setups DROP COLUMN enrollment_token_hash;
ALTER TABLE msp_clients DROP COLUMN enrollment_token_hash;
ALTER TABLE site_fixes DROP COLUMN approved_at;
