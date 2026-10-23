-- Keykeeper: the capabilities a grant to a shared folder (upstream's
-- collection) has beyond upstream's three fields, for a person
-- (users_collections) or a group (collections_groups). read_only,
-- hide_passwords, and manage are the grant's upstream values when these were
-- saved: a row counts only while the grant still has them, and otherwise the
-- grant is the preset its upstream values name. See
-- src/db/models/keykeeper_folder_permissions.rs and DESIGN.md, "Folders and
-- permissions".
CREATE TABLE keykeeper_users_collections (
    user_uuid        TEXT    NOT NULL,
    collection_uuid  TEXT    NOT NULL,
    read_only        BOOLEAN NOT NULL,
    hide_passwords   BOOLEAN NOT NULL,
    manage           BOOLEAN NOT NULL,
    can_create       BOOLEAN NOT NULL,
    can_delete       BOOLEAN NOT NULL,
    can_export       BOOLEAN NOT NULL,
    can_share        BOOLEAN NOT NULL,
    can_print        BOOLEAN NOT NULL,
    can_view_history BOOLEAN NOT NULL,
    PRIMARY KEY (user_uuid, collection_uuid),
    FOREIGN KEY (user_uuid, collection_uuid)
        REFERENCES users_collections (user_uuid, collection_uuid) ON DELETE CASCADE
);

CREATE TABLE keykeeper_collections_groups (
    collections_uuid TEXT    NOT NULL,
    groups_uuid      TEXT    NOT NULL,
    read_only        BOOLEAN NOT NULL,
    hide_passwords   BOOLEAN NOT NULL,
    manage           BOOLEAN NOT NULL,
    can_create       BOOLEAN NOT NULL,
    can_delete       BOOLEAN NOT NULL,
    can_export       BOOLEAN NOT NULL,
    can_share        BOOLEAN NOT NULL,
    can_print        BOOLEAN NOT NULL,
    can_view_history BOOLEAN NOT NULL,
    PRIMARY KEY (collections_uuid, groups_uuid),
    FOREIGN KEY (collections_uuid, groups_uuid)
        REFERENCES collections_groups (collections_uuid, groups_uuid) ON DELETE CASCADE
);

CREATE INDEX keykeeper_folder_permissions_group ON keykeeper_collections_groups (groups_uuid);
