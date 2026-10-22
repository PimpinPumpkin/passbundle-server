-- Keykeeper: settings that follow someone to each of their devices, such as
-- the password generator's (DESIGN.md, "Generator settings"). Apps encrypt
-- them with the account's key; the server keeps only the ciphertext, and
-- forgets it when the account's key changes.
CREATE TABLE keykeeper_user_settings (
    user_uuid     TEXT NOT NULL PRIMARY KEY REFERENCES users (uuid) ON DELETE CASCADE,
    data          TEXT NOT NULL,
    revision_date TIMESTAMP NOT NULL
);
