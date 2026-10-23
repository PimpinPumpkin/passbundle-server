-- Keykeeper: the places organizations and MSPs send their events (their
-- SIEM or MDR service), and the events waiting to go there. Secrets (a
-- webhook's URL and signing secret, a header's value, Sentinel's client
-- secret) are in `secrets`, encrypted with a key that isn't in the database.
-- See src/db/models/keykeeper_event_streaming.rs and DESIGN.md, "Sending
-- events to security tools".
CREATE TABLE event_destinations (
    uuid            TEXT      NOT NULL PRIMARY KEY,
    org_uuid        TEXT      REFERENCES organizations (uuid) ON DELETE CASCADE,
    msp_uuid        TEXT      REFERENCES msps (uuid) ON DELETE CASCADE,
    name            TEXT      NOT NULL,
    kind            TEXT      NOT NULL,
    settings        TEXT      NOT NULL,
    secrets         TEXT      NOT NULL,
    shown_target    TEXT      NOT NULL,
    enabled         BOOLEAN   NOT NULL,
    paused_reason   TEXT,
    failures        INTEGER   NOT NULL,
    failing_since   TIMESTAMP,
    last_success_at TIMESTAMP,
    last_error      TEXT,
    last_error_at   TIMESTAMP,
    dropped         INTEGER   NOT NULL,
    lease_until     TIMESTAMP,
    created_at      TIMESTAMP NOT NULL,
    updated_at      TIMESTAMP NOT NULL,
    -- Not tried again before then (it failed or answered slowly).
    retry_at        TIMESTAMP,
    -- When its people were last emailed that it stopped.
    notified_at     TIMESTAMP,
    -- A running count of event_deliveries rows, recounted when it looks full.
    queued          INTEGER   NOT NULL,
    -- Who set it up (users.uuid): the worker shares its time between people.
    created_by      TEXT      NOT NULL,
    -- Slow turns in a row (held back longer each time, never paused for it).
    slow_count      INTEGER   NOT NULL,
    -- When its earliest waiting event is due, so finding work is one indexed
    -- query on this table.
    next_due_at     TIMESTAMP,
    -- An organization's or an MSP's, never both.
    CHECK ((org_uuid IS NULL) <> (msp_uuid IS NULL))
);
CREATE INDEX event_destinations_org ON event_destinations (org_uuid);
CREATE INDEX event_destinations_msp ON event_destinations (msp_uuid);
CREATE INDEX event_destinations_due ON event_destinations (next_due_at);
CREATE INDEX event_destinations_creator ON event_destinations (created_by);

-- An event waiting for one destination, as every destination gets it (JSON
-- with ids and emails, never vault data). Deleted once delivered, or after
-- three days of failed attempts. A full queue drops the lowest priority
-- first (kept events, priority 3, never), from the busiest client in an
-- MSP's feed.
CREATE TABLE event_deliveries (
    destination_uuid TEXT      NOT NULL REFERENCES event_destinations (uuid) ON DELETE CASCADE,
    event_uuid       TEXT      NOT NULL,
    payload          TEXT      NOT NULL,
    created_at       TIMESTAMP NOT NULL,
    attempts         INTEGER   NOT NULL,
    next_attempt_at  TIMESTAMP NOT NULL,
    priority         INTEGER   NOT NULL,
    -- Events that merge while they wait share one row per kind, person, and minute.
    merge_key        TEXT,
    -- The organization the event came from (for an MSP's feed).
    source           TEXT,
    PRIMARY KEY (destination_uuid, event_uuid)
);
CREATE INDEX event_deliveries_due ON event_deliveries (destination_uuid, next_attempt_at);
CREATE INDEX event_deliveries_merge ON event_deliveries (destination_uuid, merge_key);
CREATE INDEX event_deliveries_source ON event_deliveries (destination_uuid, source);
CREATE INDEX event_deliveries_queue ON event_deliveries (destination_uuid, created_at);
CREATE INDEX event_deliveries_least ON event_deliveries (destination_uuid, priority, created_at);
