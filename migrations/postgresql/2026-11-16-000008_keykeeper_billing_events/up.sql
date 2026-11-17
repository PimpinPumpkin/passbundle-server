-- Keykeeper: learning who has paid (DESIGN.md, "Plans and billing", "Learning
-- who has paid"). Written only where PLANS_ENFORCED and BILLING_PROVIDER are
-- both set.
--
-- billing_events: each webhook the provider sent, by its id, so a repeat is
-- answered and dropped. Kept 35 days, longer than a provider resends, and
-- cleared by the billing job. A webhook only ever causes a look at the
-- provider's answer: pending_customer is the customer a look is still owed
-- for, and goes empty once the provider has answered about them. Nothing from
-- the webhook's body is kept.
CREATE TABLE billing_events (
    provider         TEXT      NOT NULL,
    event_id         TEXT      NOT NULL,
    pending_customer TEXT,
    received_at      TIMESTAMP NOT NULL,
    PRIMARY KEY (provider, event_id)
);
CREATE INDEX billing_events_received_at ON billing_events (received_at);
CREATE INDEX billing_events_pending ON billing_events (provider, pending_customer);

-- billing_customers: whose plan each of the provider's customers pays for,
-- written when the server first asks the provider for a page to pay. The
-- server's own record decides whose plan a provider's answer is written to;
-- nothing a webhook or the provider says changes it. Exactly one owner column
-- is set, each owner has at most one customer at a provider, and the row
-- goes when its owner is deleted.
CREATE TABLE billing_customers (
    provider   TEXT      NOT NULL,
    customer   TEXT      NOT NULL,
    user_uuid  TEXT      REFERENCES users (uuid) ON DELETE CASCADE,
    org_uuid   TEXT      REFERENCES organizations (uuid) ON DELETE CASCADE,
    msp_uuid   TEXT      REFERENCES msps (uuid) ON DELETE CASCADE,
    created_at TIMESTAMP NOT NULL,
    PRIMARY KEY (provider, customer),
    UNIQUE (provider, user_uuid),
    UNIQUE (provider, org_uuid),
    UNIQUE (provider, msp_uuid),
    CHECK (
        (user_uuid IS NOT NULL AND org_uuid IS NULL AND msp_uuid IS NULL)
        OR (user_uuid IS NULL AND org_uuid IS NOT NULL AND msp_uuid IS NULL)
        OR (user_uuid IS NULL AND org_uuid IS NULL AND msp_uuid IS NOT NULL)
    )
);
