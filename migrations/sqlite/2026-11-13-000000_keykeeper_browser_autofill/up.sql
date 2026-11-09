-- Keykeeper: whether an organization turns off the browsers' own card and
-- address autofill for its people (DESIGN.md, "Addresses and cards"): 'off',
-- or 'offAndImport' (off, and each person is offered to bring their saved
-- cards and addresses into PassBundle). An organization without a row leaves
-- them as they are, the default. Only its owners, admins, and its MSP's
-- admins change it.
CREATE TABLE org_browser_autofill (
    org_uuid TEXT NOT NULL PRIMARY KEY REFERENCES organizations (uuid) ON DELETE CASCADE,
    mode     TEXT NOT NULL
);
