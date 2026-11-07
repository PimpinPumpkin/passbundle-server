-- Keykeeper: a shared folder's icon and color (DESIGN.md, "Folder icons"),
-- encrypted with the organization's key by the apps, as its name is. The
-- server can't read it; it only keeps it with the folder and sends it back.
ALTER TABLE collections ADD COLUMN keykeeper_look TEXT;
