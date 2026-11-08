-- Keykeeper: how healthy each person's own passwords are, in numbers only
-- (DESIGN.md, "Members' own passwords"). A member's apps count the logins in
-- their Personal items and send these four numbers; their organizations'
-- owners and admins see them. Never which items: these are counts, not vault
-- contents, so they're kept as they are. One row per account, replaced by
-- each report; `exposed` and when it was checked stay from the last report
-- that checked.
CREATE TABLE keykeeper_member_health (
    user_uuid          TEXT NOT NULL PRIMARY KEY REFERENCES users (uuid) ON DELETE CASCADE,
    logins             INTEGER NOT NULL,
    weak               INTEGER NOT NULL,
    reused             INTEGER NOT NULL,
    exposed            INTEGER,
    exposed_checked_at TIMESTAMP,
    reported_at        TIMESTAMP NOT NULL
);
