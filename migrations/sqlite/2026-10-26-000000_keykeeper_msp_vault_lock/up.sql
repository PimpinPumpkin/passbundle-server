-- Keykeeper: the Business preset gains Vault lock (upstream's vault timeout
-- policy, type 9): vaults lock when the computer locks or sleeps. MSPs that
-- already exist get it as a default too, as the preset's other policies came
-- to them (keykeeper_msp_policies). Their clients keep what they have until
-- an MSP admin uses the default there. See docs/core.md, "Locking by policy".
INSERT OR IGNORE INTO msp_policies (msp_uuid, atype, enabled, data)
    SELECT uuid, 9, 1, '{"type":"onSystemLock","minutes":null,"action":"lock"}' FROM msps;
