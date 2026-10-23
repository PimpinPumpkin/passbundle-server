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
    msp_staff_client_roles (msp_uuid, user_uuid, org_uuid) {
        msp_uuid -> Text,
        user_uuid -> Text,
        org_uuid -> Text,
        client_access -> Nullable<Text>,
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

table! {
    site_fixes (uuid) {
        uuid -> Text,
        host -> Text,
        field_id -> Text,
        field_name -> Text,
        field_label -> Text,
        fill -> Text,
        reporters -> Integer,
        first_seen -> Timestamp,
        last_seen -> Timestamp,
    }
}

table! {
    site_fix_reporters (fix_uuid, reporter_hash) {
        fix_uuid -> Text,
        reporter_hash -> Text,
    }
}

table! {
    site_problems (uuid) {
        uuid -> Text,
        host -> Text,
        fields -> Text,
        note -> Nullable<Text>,
        created_at -> Timestamp,
    }
}

table! {
    msp_site_fix_reports (uuid) {
        uuid -> Text,
        msp_uuid -> Text,
        host -> Text,
        field_id -> Text,
        field_name -> Text,
        field_label -> Text,
        fill -> Text,
        reporter_email -> Text,
        created_at -> Timestamp,
    }
}

table! {
    msp_site_rules (uuid) {
        uuid -> Text,
        msp_uuid -> Text,
        host -> Text,
        field_id -> Text,
        field_name -> Text,
        field_label -> Text,
        fill -> Text,
        created_at -> Timestamp,
    }
}

table! {
    keykeeper_secrets (name) {
        name -> Text,
        value -> Text,
    }
}

table! {
    script_tokens (uuid) {
        uuid -> Text,
        org_uuid -> Text,
        name -> Text,
        created_by -> Text,
        created_at -> Timestamp,
        expires_at -> Timestamp,
        revoked_at -> Nullable<Timestamp>,
        auth_hash -> Text,
        networks -> Text,
        sealed_key -> Text,
        last_used_at -> Nullable<Timestamp>,
        last_used_ip -> Nullable<Text>,
    }
}

table! {
    script_grants (token_uuid, cipher_uuid) {
        token_uuid -> Text,
        cipher_uuid -> Text,
        copy -> Text,
        revision -> Text,
        sealed_spec -> Text,
    }
}

table! {
    script_reads (uuid) {
        uuid -> Text,
        token_uuid -> Text,
        cipher_uuid -> Nullable<Text>,
        read_at -> Timestamp,
        ip -> Text,
        allowed -> Bool,
        reason -> Text,
    }
}

table! {
    keykeeper_user_settings (user_uuid) {
        user_uuid -> Text,
        data -> Text,
        revision_date -> Timestamp,
    }
}

table! {
    keykeeper_cipher_versions (uuid) {
        uuid -> Text,
        cipher_uuid -> Text,
        atype -> Integer,
        akey -> Nullable<Text>,
        name -> Text,
        notes -> Nullable<Text>,
        fields -> Nullable<Text>,
        data -> Text,
        password_history -> Nullable<Text>,
        reprompt -> Nullable<Integer>,
        size -> Integer,
        revision_date -> Timestamp,
        saved_by -> Nullable<Text>,
        replaced_at -> Timestamp,
        replaced_by -> Nullable<Text>,
    }
}

table! {
    keykeeper_cipher_saves (cipher_uuid) {
        cipher_uuid -> Text,
        saved_by -> Nullable<Text>,
        saved_at -> Timestamp,
    }
}

table! {
    keykeeper_users_collections (user_uuid, collection_uuid) {
        user_uuid -> Text,
        collection_uuid -> Text,
        read_only -> Bool,
        hide_passwords -> Bool,
        manage -> Bool,
        can_create -> Bool,
        can_delete -> Bool,
        can_export -> Bool,
        can_share -> Bool,
        can_print -> Bool,
        can_view_history -> Bool,
    }
}

table! {
    keykeeper_collections_groups (collections_uuid, groups_uuid) {
        collections_uuid -> Text,
        groups_uuid -> Text,
        read_only -> Bool,
        hide_passwords -> Bool,
        manage -> Bool,
        can_create -> Bool,
        can_delete -> Bool,
        can_export -> Bool,
        can_share -> Bool,
        can_print -> Bool,
        can_view_history -> Bool,
    }
}

table! {
    scim_tokens (org_uuid) {
        org_uuid -> Text,
        token_hash -> Text,
        created_by -> Text,
        created_at -> Timestamp,
        last_used_at -> Nullable<Timestamp>,
        last_used_ip -> Nullable<Text>,
    }
}

table! {
    scim_users (membership_uuid) {
        membership_uuid -> Text,
        org_uuid -> Text,
        user_name -> Text,
        user_name_key -> Text,
        external_id -> Nullable<Text>,
        attributes -> Text,
        provisioned -> Bool,
        turned_off -> Bool,
        refused_off_at -> Nullable<Timestamp>,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

table! {
    scim_groups (group_uuid) {
        group_uuid -> Text,
        org_uuid -> Text,
        created_at -> Timestamp,
    }
}
