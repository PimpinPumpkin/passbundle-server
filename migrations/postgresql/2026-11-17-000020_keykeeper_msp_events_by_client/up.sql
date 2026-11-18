-- Keykeeper: a client's own view of what its MSP did there reads the MSP's
-- audit log by client (DESIGN.md, "The client sees its MSP's actions").
CREATE INDEX msp_events_org_created ON msp_events (org_uuid, created_at);
