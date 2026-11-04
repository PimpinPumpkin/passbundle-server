-- Keykeeper: the client seal (DESIGN.md, "Joins a hacked server can't forge",
-- in the meta repo). The MSP admin's browser that makes a client, or confirms
-- one by name, seals with that client's key that it is this MSP's client.
-- Apps write seals and template copies only into clients whose seal checks
-- out, so a hacked server can't point that work at another organization. The
-- server can't read or make it; it only keeps it.
ALTER TABLE msp_clients ADD COLUMN client_seal TEXT;
