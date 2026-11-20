-- Keykeeper: push to phones over UnifiedPush (DESIGN.md, "Push to phones").
-- One endpoint per account and device: the address the phone's distributor
-- gave it, with the phone's P-256 public key and auth secret (base64url), which
-- messages are encrypted to (RFC 8291). Gone with the device's row or the
-- account.
CREATE TABLE push_endpoints (
    user_uuid   TEXT      NOT NULL REFERENCES users (uuid) ON DELETE CASCADE,
    device_uuid TEXT      NOT NULL,
    endpoint    TEXT      NOT NULL,
    public_key  TEXT      NOT NULL,
    auth        TEXT      NOT NULL,
    created_at  TIMESTAMP NOT NULL,
    PRIMARY KEY (user_uuid, device_uuid),
    FOREIGN KEY (device_uuid, user_uuid) REFERENCES devices (uuid, user_uuid) ON DELETE CASCADE
);
