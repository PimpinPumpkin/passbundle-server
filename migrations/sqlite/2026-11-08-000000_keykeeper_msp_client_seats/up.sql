-- Keykeeper: seats by client (DESIGN.md, "Seats by client", in the meta repo).
-- Once a day the server records how many seats each of an MSP's clients has:
-- its members who joined (accepted or confirmed), aren't revoked, and aren't
-- the MSP's staff. `day` is the UTC date (YYYY-MM-DD). The client's name is
-- copied in and nothing refers to the organization, so a month stays
-- readable after a client leaves, is renamed, or is deleted. Rows go with
-- their MSP.
CREATE TABLE msp_client_seats (
    msp_uuid TEXT NOT NULL REFERENCES msps (uuid) ON DELETE CASCADE,
    org_uuid TEXT NOT NULL,
    day      TEXT NOT NULL,
    seats    INTEGER NOT NULL,
    org_name TEXT NOT NULL,
    PRIMARY KEY (msp_uuid, org_uuid, day)
);

CREATE INDEX msp_client_seats_by_day ON msp_client_seats (msp_uuid, day);
