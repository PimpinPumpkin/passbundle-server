-- Keykeeper: an organization can require two-step login of everyone in it,
-- not only its admins, with the same counting (DESIGN.md, "Two-step login for
-- everyone"). One setting with three levels: off, admins (`required`), or
-- everyone (`required` and `everyone`). `everyone` counts only while
-- `required` is on.
ALTER TABLE org_admin_two_step ADD COLUMN everyone BOOLEAN NOT NULL DEFAULT 0;
-- When an account last said "Not now" to the nudge to set up two-step login,
-- which then stays hidden for 90 days on every device. Nothing else is kept.
CREATE TABLE two_step_nudge_dismissals (
    user_uuid    TEXT      NOT NULL PRIMARY KEY REFERENCES users (uuid) ON DELETE CASCADE,
    dismissed_at TIMESTAMP NOT NULL
);
