-- Keykeeper: site fixes people chose to share from the fill picker, problem
-- reports about sites, and MSPs' site rules. See DESIGN.md, "Site fixes
-- (opt-in)". No row here says which account sent it.
-- A fix: how to recognize a field on a site, and which kind of value goes
-- there. Missing parts of the field are empty strings, so the key is unique.
CREATE TABLE site_fixes (
    uuid        TEXT NOT NULL PRIMARY KEY,
    host        TEXT NOT NULL,
    field_id    TEXT NOT NULL,
    field_name  TEXT NOT NULL,
    field_label TEXT NOT NULL,
    fill        TEXT NOT NULL,
    reporters   INTEGER NOT NULL,
    first_seen  TIMESTAMP NOT NULL,
    last_seen   TIMESTAMP NOT NULL
);
CREATE UNIQUE INDEX site_fixes_key ON site_fixes (host, field_id, field_name, field_label, fill);
-- Each person who sent a fix, counted once by a keyed hash only this server
-- can make, so it never stores who sent what.
CREATE TABLE site_fix_reporters (
    fix_uuid      TEXT NOT NULL REFERENCES site_fixes (uuid) ON DELETE CASCADE,
    reporter_hash TEXT NOT NULL,
    PRIMARY KEY (fix_uuid, reporter_hash)
);
-- "Report a problem with this site": the host and the sign-in fields' shape.
CREATE TABLE site_problems (
    uuid       TEXT NOT NULL PRIMARY KEY,
    host       TEXT NOT NULL,
    fields     TEXT NOT NULL,
    note       TEXT,
    created_at TIMESTAMP NOT NULL
);
CREATE INDEX site_problems_host ON site_problems (host, created_at);
-- Fixes an MSP's staff shared, with who sent them, for its console.
CREATE TABLE msp_site_fix_reports (
    uuid           TEXT NOT NULL PRIMARY KEY,
    msp_uuid       TEXT NOT NULL REFERENCES msps (uuid) ON DELETE CASCADE,
    host           TEXT NOT NULL,
    field_id       TEXT NOT NULL,
    field_name     TEXT NOT NULL,
    field_label    TEXT NOT NULL,
    fill           TEXT NOT NULL,
    reporter_email TEXT NOT NULL,
    created_at     TIMESTAMP NOT NULL
);
CREATE INDEX msp_site_fix_reports_msp ON msp_site_fix_reports (msp_uuid, created_at);
-- Fixes an MSP's admin applied to every client.
CREATE TABLE msp_site_rules (
    uuid        TEXT NOT NULL PRIMARY KEY,
    msp_uuid    TEXT NOT NULL REFERENCES msps (uuid) ON DELETE CASCADE,
    host        TEXT NOT NULL,
    field_id    TEXT NOT NULL,
    field_name  TEXT NOT NULL,
    field_label TEXT NOT NULL,
    fill        TEXT NOT NULL,
    created_at  TIMESTAMP NOT NULL
);
CREATE UNIQUE INDEX msp_site_rules_key ON msp_site_rules (msp_uuid, host, field_id, field_name, field_label, fill);
-- Secrets only this server has, such as the key for reporters' hashes.
CREATE TABLE keykeeper_secrets (
    name  TEXT NOT NULL PRIMARY KEY,
    value TEXT NOT NULL
);
