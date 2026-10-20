DROP TABLE joining_seals;
DROP TABLE join_seals;
ALTER TABLE msp_enrollment_joins DROP COLUMN proof;
ALTER TABLE org_setups DROP COLUMN enrollment_secret;
ALTER TABLE msp_clients DROP COLUMN enrollment_secret;
