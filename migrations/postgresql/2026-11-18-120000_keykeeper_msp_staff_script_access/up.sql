-- Keykeeper: whether an MSP technician has script access. With it, they make,
-- see, and revoke script tokens in the clients they reach where they're an
-- admin, and a token they made works only while that's still so. Off by
-- default (DESIGN.md, "Script access", in the meta repo).
ALTER TABLE msp_staff ADD COLUMN script_access BOOLEAN NOT NULL DEFAULT FALSE;
