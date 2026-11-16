-- Keykeeper: what the plans' clock has already done (DESIGN.md, "Plans and
-- billing", "What happens when payment stops"), so the job that runs it never
-- does anything twice: each reminder email for a plan and the moment it's
-- about, and each sync notice for a state the clock moved a plan into.
--   plan_uuid: the plan's row (plans.uuid). There's no foreign key: the
--     operator's write replaces a row under the same uuid, which mustn't
--     forget what was sent. The job removes the notes of rows that are gone.
--   notice: 'trial_7_days', 'trial_1_day', 'grace_3_days', or 'grace_ended'
--     for an email; 'state_' and the state for a sync notice.
--   about: for an email, the moment it's about (when the free time or the
--     grace ends), so a plan given new dates gets its reminders again; for a
--     sync notice, when the row was last written.
--   sent_at: when the job sent it.
CREATE TABLE plan_notices (
    plan_uuid TEXT      NOT NULL,
    notice    TEXT      NOT NULL,
    about     TIMESTAMP NOT NULL,
    sent_at   TIMESTAMP NOT NULL,
    PRIMARY KEY (plan_uuid, notice, about)
);
