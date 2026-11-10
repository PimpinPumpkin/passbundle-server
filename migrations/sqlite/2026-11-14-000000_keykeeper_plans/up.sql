-- Keykeeper: plans (DESIGN.md, "Plans and billing"). A plan belongs to a
-- person (Premium), an organization (Families or Business), or an MSP (its
-- pool, which covers its clients), and each has at most one row. A person
-- without a row is on Free. Exactly one of the three owner columns is set,
-- and the row goes when its owner is deleted.
--   free_until, free_why: nothing has to be paid before then, and why
--     ('trial' or 'offer').
--   standing: 'none' (never paid, or over), 'until' (good through the moment
--     in "until"), or 'open' (good with no end set). "No end" is its own
--     value, so a row nobody paid for can't be read as one that never ends.
--   renews: whether a plan that's good until a date is set to renew then. One
--     that isn't was canceled, and gets no grace.
--   billed: 'prepaid', 'by_the_day', or 'by_hand'.
--   set_by: who last set it, 'server', 'provider', or 'operator'.
--   provider, provider_customer, provider_subscription: the payment
--     provider's name and its ids, which mean nothing outside the provider.
--   checked_at: when the provider was last asked.
-- No request from a signed-in person writes here. What a person gets is
-- worked out from these rows when it's asked for, never stored.
CREATE TABLE plans (
    uuid                  TEXT      NOT NULL PRIMARY KEY,
    user_uuid             TEXT      UNIQUE REFERENCES users (uuid) ON DELETE CASCADE,
    org_uuid              TEXT      UNIQUE REFERENCES organizations (uuid) ON DELETE CASCADE,
    msp_uuid              TEXT      UNIQUE REFERENCES msps (uuid) ON DELETE CASCADE,
    plan                  TEXT      NOT NULL,
    free_until            TIMESTAMP,
    free_why              TEXT,
    standing              TEXT      NOT NULL,
    until                 TIMESTAMP,
    renews                BOOLEAN   NOT NULL,
    billed                TEXT      NOT NULL,
    set_by                TEXT      NOT NULL,
    provider              TEXT,
    provider_customer     TEXT,
    provider_subscription TEXT,
    checked_at            TIMESTAMP,
    updated_at            TIMESTAMP NOT NULL,
    CHECK (
        (user_uuid IS NOT NULL AND org_uuid IS NULL AND msp_uuid IS NULL)
        OR (user_uuid IS NULL AND org_uuid IS NOT NULL AND msp_uuid IS NULL)
        OR (user_uuid IS NULL AND org_uuid IS NULL AND msp_uuid IS NOT NULL)
    )
);
