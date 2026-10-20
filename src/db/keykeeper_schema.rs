// Keykeeper's own tables, kept apart from upstream's schema.rs so upstream
// merges stay clean. See the keykeeper_msp migrations.

table! {
    msps (uuid) {
        uuid -> Text,
        name -> Text,
        created_at -> Timestamp,
    }
}

table! {
    msp_staff (msp_uuid, user_uuid) {
        msp_uuid -> Text,
        user_uuid -> Text,
        role -> Integer,
        created_at -> Timestamp,
        all_clients -> Bool,
        client_access -> Nullable<Text>,
        install_commands -> Bool,
    }
}

table! {
    msp_clients (org_uuid) {
        org_uuid -> Text,
        msp_uuid -> Text,
        created_at -> Timestamp,
        preset -> Nullable<Text>,
        enrollment_token -> Nullable<Text>,
        enrollment_token_created_at -> Nullable<Timestamp>,
        everyone_collection -> Nullable<Text>,
        templates_collection -> Nullable<Text>,
        enrollment_secret -> Nullable<Text>,
    }
}

table! {
    msp_enrollment_joins (membership_uuid) {
        membership_uuid -> Text,
        org_uuid -> Text,
        joined_at -> Timestamp,
        proof -> Nullable<Text>,
    }
}

table! {
    msp_memberships (membership_uuid) {
        membership_uuid -> Text,
        msp_uuid -> Text,
    }
}

table! {
    msp_events (uuid) {
        uuid -> Text,
        msp_uuid -> Text,
        created_at -> Timestamp,
        event -> Text,
        actor_uuid -> Nullable<Text>,
        actor_email -> Nullable<Text>,
        org_uuid -> Nullable<Text>,
        org_name -> Nullable<Text>,
        target_email -> Nullable<Text>,
        detail -> Nullable<Text>,
        ip -> Nullable<Text>,
    }
}

table! {
    msp_invites (uuid) {
        uuid -> Text,
        msp_uuid -> Text,
        email -> Text,
        role -> Integer,
        token -> Text,
        invited_by_email -> Text,
        created_at -> Timestamp,
        access -> Nullable<Text>,
    }
}

table! {
    membership_permissions (membership_uuid) {
        membership_uuid -> Text,
        permissions -> Text,
    }
}

table! {
    msp_staff_clients (msp_uuid, user_uuid, org_uuid) {
        msp_uuid -> Text,
        user_uuid -> Text,
        org_uuid -> Text,
    }
}

table! {
    msp_policies (msp_uuid, atype) {
        msp_uuid -> Text,
        atype -> Integer,
        enabled -> Bool,
        data -> Text,
    }
}

table! {
    msp_templates (msp_uuid, template_id) {
        msp_uuid -> Text,
        template_id -> Text,
        source_cipher_uuid -> Text,
        all_clients -> Bool,
        created_at -> Timestamp,
    }
}

table! {
    msp_template_clients (msp_uuid, template_id, org_uuid) {
        msp_uuid -> Text,
        template_id -> Text,
        org_uuid -> Text,
    }
}

table! {
    msp_template_copies (org_uuid, template_id) {
        org_uuid -> Text,
        template_id -> Text,
        cipher_uuid -> Text,
        source_revision -> Text,
    }
}

table! {
    org_joining (org_uuid) {
        org_uuid -> Text,
        auto_confirm -> Bool,
        invite_hours -> Integer,
    }
}

table! {
    msp_joining (msp_uuid) {
        msp_uuid -> Text,
        auto_confirm -> Bool,
        invite_hours -> Integer,
    }
}

table! {
    enrollment_domains (org_uuid) {
        org_uuid -> Text,
        domains -> Text,
    }
}

table! {
    org_setups (org_uuid) {
        org_uuid -> Text,
        created_at -> Timestamp,
        preset -> Nullable<Text>,
        enrollment_token -> Nullable<Text>,
        enrollment_token_created_at -> Nullable<Timestamp>,
        everyone_collection -> Nullable<Text>,
        enrollment_secret -> Nullable<Text>,
    }
}

table! {
    join_seals (org_uuid, email, kind) {
        org_uuid -> Text,
        email -> Text,
        kind -> Text,
        seal -> Text,
    }
}

table! {
    joining_seals (org_uuid) {
        org_uuid -> Text,
        seal -> Text,
    }
}
