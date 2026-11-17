-- Keykeeper: invoices by the day (DESIGN.md, "Plans and billing", "Learning who
-- has paid"). Written only where PLANS_ENFORCED and BILLING_PROVIDER are both
-- set.
--
-- org_seats: once a day, with the MSP clients' readings (msp_client_seats),
-- the seats of each organization with a Business plan of its own: its members
-- who joined (accepted or confirmed) and aren't revoked. `day` is the UTC date
-- (YYYY-MM-DD). While it's an MSP's client its seats are the MSP's, so its own
-- reading that day is 0 and nothing is billed to it twice. Rows go with the
-- organization.
CREATE TABLE org_seats (
    org_uuid TEXT    NOT NULL REFERENCES organizations (uuid) ON DELETE CASCADE,
    day      TEXT    NOT NULL,
    seats    INTEGER NOT NULL,
    PRIMARY KEY (org_uuid, day)
);

-- plan_invoices: one row for each plan billed by the day and each month
-- (`YYYY-MM`, UTC), ever: unique on whose plan and the month. The server
-- writes it, with the figures it worked out, before it asks the provider for
-- the invoice, and completes it with the provider's id for the invoice after,
-- so a crash or a rerun finds the row and never makes a second invoice.
--   seat_days: the month's seat-days that are billed (days before free_until
--     aren't); free_days: how many of the month's days weren't billed.
--   prorated: seat_days over days_in_month, in hundredths, rounded half up,
--     as the seat report rounds.
--   price_cents: the price a seat for the month's tier; amount_cents: prorated
--     times price_cents, to the cent, rounded half up.
-- Exactly one owner column is set, and the row goes with its owner.
CREATE TABLE plan_invoices (
    uuid              TEXT      NOT NULL PRIMARY KEY,
    org_uuid          TEXT      REFERENCES organizations (uuid) ON DELETE CASCADE,
    msp_uuid          TEXT      REFERENCES msps (uuid) ON DELETE CASCADE,
    month             TEXT      NOT NULL,
    plan              TEXT      NOT NULL,
    seat_days         BIGINT    NOT NULL,
    free_days         INTEGER   NOT NULL,
    days_in_month     INTEGER   NOT NULL,
    prorated          BIGINT    NOT NULL,
    price_cents       BIGINT    NOT NULL,
    amount_cents      BIGINT    NOT NULL,
    currency          TEXT      NOT NULL,
    provider          TEXT      NOT NULL,
    provider_customer TEXT      NOT NULL,
    provider_invoice  TEXT,
    created_at        TIMESTAMP NOT NULL,
    sent_at           TIMESTAMP,
    UNIQUE (org_uuid, month),
    UNIQUE (msp_uuid, month),
    CHECK (
        (org_uuid IS NOT NULL AND msp_uuid IS NULL)
        OR (org_uuid IS NULL AND msp_uuid IS NOT NULL)
    )
);
