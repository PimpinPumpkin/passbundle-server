-- Keykeeper: the new-device check (DESIGN.md, "New-device check"). An
-- account without two-step login that signs in on a device it has never used
-- waits until the person approves it from a device already signed in, typing
-- the number the new device shows, or with a code by email. One row per
-- waiting sign-in, gone once it ends. The token the new device asks with and
-- the emailed code are kept only as hashes. No location is kept: it's worked
-- out from the address when it's shown.
CREATE TABLE new_device_checks (
    uuid               TEXT      NOT NULL PRIMARY KEY,
    user_uuid          TEXT      NOT NULL REFERENCES users (uuid) ON DELETE CASCADE,
    device_uuid        TEXT      NOT NULL,
    device_type        INTEGER   NOT NULL,
    device_name        TEXT      NOT NULL,
    ip                 TEXT      NOT NULL,
    token_hash         TEXT      NOT NULL,
    number             INTEGER   NOT NULL,
    created_at         TIMESTAMP NOT NULL,
    expires_at         TIMESTAMP NOT NULL,
    approved_at        TIMESTAMP,
    approved_how       TEXT,
    approved_by        TEXT,
    denied_at          TIMESTAMP,
    denied_why         TEXT,
    email_after        TIMESTAMP,
    code_hash          TEXT,
    code_sends         INTEGER   NOT NULL DEFAULT 0,
    code_tries         INTEGER   NOT NULL DEFAULT 0,
    used_at            TIMESTAMP
);
CREATE INDEX new_device_checks_user ON new_device_checks (user_uuid);
-- A device that has passed the check (or wasn't asked) for an account without
-- two-step login gets a token of its own, which it sends back at its next
-- sign-in: a device identifier alone isn't a secret. Kept as its SHA-256.
CREATE TABLE known_device_tokens (
    user_uuid   TEXT      NOT NULL REFERENCES users (uuid) ON DELETE CASCADE,
    device_uuid TEXT      NOT NULL,
    token_hash  TEXT      NOT NULL,
    created_at  TIMESTAMP NOT NULL,
    PRIMARY KEY (user_uuid, device_uuid)
);
