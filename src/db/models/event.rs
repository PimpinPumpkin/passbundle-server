use chrono::{NaiveDateTime, TimeDelta, Utc};
use diesel::prelude::*;
use serde_json::Value;

use crate::{
    CONFIG,
    api::EmptyResult,
    db::{
        DbConn,
        schema::{event, users_organizations},
    },
    error::MapResult,
};

use super::{CipherId, CollectionId, GroupId, MembershipId, OrgPolicyId, OrganizationId, UserId};

// https://bitwarden.com/help/event-logs/

// Upstream: https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Core/AdminConsole/Services/Implementations/EventService.cs
// Upstream: https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Api/AdminConsole/Public/Models/Response/EventResponseModel.cs
// Upstream SQL: https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Sql/dbo/Tables/Event.sql
#[derive(Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = event)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(uuid))]
pub struct Event {
    pub uuid: EventId,
    pub event_type: i32, // EventType
    pub user_uuid: Option<UserId>,
    pub org_uuid: Option<OrganizationId>,
    pub cipher_uuid: Option<CipherId>,
    pub collection_uuid: Option<CollectionId>,
    pub group_uuid: Option<GroupId>,
    pub org_user_uuid: Option<MembershipId>,
    pub act_user_uuid: Option<UserId>,
    // Upstream enum: https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Core/Enums/DeviceType.cs
    pub device_type: Option<i32>,
    pub ip_address: Option<String>,
    pub event_date: NaiveDateTime,
    pub policy_uuid: Option<OrgPolicyId>,
    pub provider_uuid: Option<String>,
    pub provider_user_uuid: Option<String>,
    pub provider_org_uuid: Option<String>,
    // Keykeeper: upstream's system user that acted, when no person did (1 is
    // SCIM provisioning). The web vault's event log names it.
    pub system_actor: Option<i32>,
}

// Upstream enum: https://github.com/bitwarden/server/blob/v2026.6.2/src/Core/Dirt/Enums/EventType.cs
#[derive(Debug, Copy, Clone)]
pub enum EventType {
    // User
    UserLoggedIn = 1000,
    UserChangedPassword = 1001,
    UserUpdated2fa = 1002,
    UserDisabled2fa = 1003,
    UserRecovered2fa = 1004,
    UserFailedLogIn = 1005,
    UserFailedLogIn2fa = 1006,
    UserClientExportedVault = 1007,
    // UserUpdatedTempPassword = 1008, // Not supported
    // UserMigratedKeyToKeyConnector = 1009, // Not supported
    UserRequestedDeviceApproval = 1010,
    // UserTdeOffboardingPasswordSet = 1011, // Not supported

    // Cipher
    CipherCreated = 1100,
    CipherUpdated = 1101,
    CipherDeleted = 1102,
    CipherAttachmentCreated = 1103,
    CipherAttachmentDeleted = 1104,
    CipherShared = 1105,
    CipherUpdatedCollections = 1106,
    CipherClientViewed = 1107,
    CipherClientToggledPasswordVisible = 1108,
    CipherClientToggledHiddenFieldVisible = 1109,
    CipherClientToggledCardCodeVisible = 1110,
    CipherClientCopiedPassword = 1111,
    CipherClientCopiedHiddenField = 1112,
    CipherClientCopiedCardCode = 1113,
    CipherClientAutofilled = 1114,
    CipherSoftDeleted = 1115,
    CipherRestored = 1116,
    CipherClientToggledCardNumberVisible = 1117,
    // Keykeeper: someone cleared an item's earlier versions, or deleted one
    // (keykeeper_cipher_versions). Upstream's cipher events end at 1132.
    KeykeeperCipherHistoryCleared = 1190,
    KeykeeperCipherVersionDeleted = 1191,

    // Collection
    CollectionCreated = 1300,
    CollectionUpdated = 1301,
    CollectionDeleted = 1302,

    // Group
    GroupCreated = 1400,
    GroupUpdated = 1401,
    GroupDeleted = 1402,

    // OrganizationUser
    OrganizationUserInvited = 1500,
    OrganizationUserConfirmed = 1501,
    OrganizationUserUpdated = 1502,
    OrganizationUserRemoved = 1503, // Organization user data was deleted
    OrganizationUserUpdatedGroups = 1504,
    OrganizationUserUnlinkedSso = 1505,
    OrganizationUserResetPasswordEnroll = 1506,
    OrganizationUserResetPasswordWithdraw = 1507,
    OrganizationUserAdminResetPassword = 1508,
    // OrganizationUserResetSsoLink = 1509, // Not supported
    // OrganizationUserFirstSsoLogin = 1510, // Not supported
    OrganizationUserRevoked = 1511,
    OrganizationUserRestored = 1512,
    OrganizationUserApprovedAuthRequest = 1513,
    OrganizationUserRejectedAuthRequest = 1514,
    OrganizationUserDeleted = 1515, // Both user and organization user data were deleted
    OrganizationUserLeft = 1516,    // User voluntarily left the organization
    // OrganizationUserAutomaticallyConfirmed = 1517,
    // OrganizationUserSelfRevoked = 1518, // User self-revoked due to declining organization data ownership policy
    OrganizationUserAdminResetTwoFactor = 1519,
    // OrganizationUserRevoked_TwoFactorNonCompliance = 1520,
    // OrganizationUserRevoked_SingleOrganizationNonCompliance = 1521,
    OrganizationUserNotificationBannerActionClicked = 1522,

    // Organization
    OrganizationUpdated = 1600,
    OrganizationPurgedVault = 1601,
    OrganizationClientExportedVault = 1602,
    // Keykeeper: a place the organization's events are sent was added,
    // changed, removed, or stopped (keykeeper_event_streaming). 1690 and up
    // are ours.
    KeykeeperEventStreamAdded = 1690,
    KeykeeperEventStreamChanged = 1691,
    KeykeeperEventStreamRemoved = 1692,
    // The server turned a destination off: it kept failing, said it's gone,
    // or its settings can't be read anymore.
    KeykeeperEventStreamStopped = 1693,
    // OrganizationVaultAccessed = 1603,
    // OrganizationEnabledSso = 1604, // Not supported
    // OrganizationDisabledSso = 1605, // Not supported
    // OrganizationEnabledKeyConnector = 1606, // Not supported
    // OrganizationDisabledKeyConnector = 1607, // Not supported
    // OrganizationSponsorshipsSynced = 1608, // Not supported
    // OrganizationCollectionManagementUpdated = 1609, // Not supported

    // Policy
    PolicyUpdated = 1700,
    // Provider (Not yet supported)
    // ProviderUserInvited = 1800, // Not supported
    // ProviderUserConfirmed = 1801, // Not supported
    // ProviderUserUpdated = 1802, // Not supported
    // ProviderUserRemoved = 1803, // Not supported
    // ProviderOrganizationCreated = 1900, // Not supported
    // ProviderOrganizationAdded = 1901, // Not supported
    // ProviderOrganizationRemoved = 1902, // Not supported
    // ProviderOrganizationVaultAccessed = 1903, // Not supported

    // OrganizationDomainAdded = 2000, // Not supported
    // OrganizationDomainRemoved = 2001, // Not supported
    // OrganizationDomainVerified = 2002, // Not supported
    // OrganizationDomainNotVerified = 2003, // Not supported

    // SecretRetrieved = 2100, // Not supported
}

/// Local methods
impl Event {
    pub fn new(event_type: i32, event_date: Option<NaiveDateTime>) -> Self {
        let event_date = match event_date {
            Some(d) => d,
            None => Utc::now().naive_utc(),
        };

        Self {
            uuid: EventId(crate::util::get_uuid()),
            event_type,
            user_uuid: None,
            org_uuid: None,
            cipher_uuid: None,
            collection_uuid: None,
            group_uuid: None,
            org_user_uuid: None,
            act_user_uuid: None,
            device_type: None,
            ip_address: None,
            event_date,
            policy_uuid: None,
            provider_uuid: None,
            provider_user_uuid: None,
            provider_org_uuid: None,
            system_actor: None,
        }
    }

    /// Keykeeper: a copy, for streaming (upstream's Event isn't Clone).
    fn copy(&self) -> Self {
        Self {
            uuid: self.uuid.clone(),
            event_type: self.event_type,
            user_uuid: self.user_uuid.clone(),
            org_uuid: self.org_uuid.clone(),
            cipher_uuid: self.cipher_uuid.clone(),
            collection_uuid: self.collection_uuid.clone(),
            group_uuid: self.group_uuid.clone(),
            org_user_uuid: self.org_user_uuid.clone(),
            act_user_uuid: self.act_user_uuid.clone(),
            device_type: self.device_type,
            ip_address: self.ip_address.clone(),
            event_date: self.event_date,
            policy_uuid: self.policy_uuid.clone(),
            provider_uuid: self.provider_uuid.clone(),
            provider_user_uuid: self.provider_user_uuid.clone(),
            provider_org_uuid: self.provider_org_uuid.clone(),
            system_actor: self.system_actor,
        }
    }

    pub fn to_json(&self) -> Value {
        use crate::util::format_date;

        json!({
            "type": self.event_type,
            "userId": self.user_uuid,
            "organizationId": self.org_uuid,
            "cipherId": self.cipher_uuid,
            "collectionId": self.collection_uuid,
            "groupId": self.group_uuid,
            "organizationUserId": self.org_user_uuid,
            "actingUserId": self.act_user_uuid,
            "date": format_date(&self.event_date),
            "deviceType": self.device_type,
            "ipAddress": self.ip_address,
            "policyId": self.policy_uuid,
            "providerId": self.provider_uuid,
            "providerUserId": self.provider_user_uuid,
            "providerOrganizationId": self.provider_org_uuid,
            "systemUser": self.system_actor,
            // "installationId": null, // Not supported
        })
    }
}

/// Database methods
/// https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Core/AdminConsole/Services/Implementations/EventService.cs
impl Event {
    pub const PAGE_SIZE: i64 = 30;

    /// #############
    /// Basic Queries
    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        let saved = self.save_row(conn).await;
        // Keykeeper: and to the organization's security tools, if it sends
        // its events to any (keykeeper_event_streaming).
        if saved.is_ok() {
            super::keykeeper_event_streaming::stream(self, conn).await;
        }
        saved
    }

    async fn save_row(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn:
            mysql {
                diesel::insert_into(event::table)
                    .values(self)
                    .on_conflict(diesel::dsl::DuplicatedKeys)
                    .do_update()
                    .set(self)
                    .execute(conn)
                    .map_res("Error saving event")
            }
            postgresql, sqlite {
                diesel::insert_into(event::table)
                    .values(self)
                    .on_conflict(event::uuid)
                    .do_update()
                    .set(self)
                    .execute(conn)
                    .map_res("Error saving event")
            }
        }
    }

    pub async fn save_user_event(events: Vec<Event>, conn: &DbConn) -> EmptyResult {
        // Keykeeper: and to each organization's security tools
        // (keykeeper_event_streaming). The saves below ignore errors, so the
        // events are streamed whatever they return.
        let streamed: Vec<Event> = events.iter().filter(|e| e.org_uuid.is_some()).map(Event::copy).collect();
        let saved = Self::save_user_event_rows(events, conn).await;
        for event in &streamed {
            super::keykeeper_event_streaming::stream(event, conn).await;
        }
        saved
    }

    async fn save_user_event_rows(events: Vec<Event>, conn: &DbConn) -> EmptyResult {
        // Special save function which is able to handle multiple events.
        // SQLite doesn't support the DEFAULT argument, and does not support inserting multiple values at the same time.
        // MySQL and PostgreSQL do.
        // We also ignore duplicate if they ever will exists, else it could break the whole flow.
        db_run! { conn:
            // Unfortunately SQLite does not support inserting multiple records at the same time
            // We loop through the events here and insert them one at a time.
            sqlite {
                for event in events {
                    diesel::insert_or_ignore_into(event::table)
                    .values(&event)
                    .execute(conn)
                    .unwrap_or_default();
                }
                Ok(())
            }
            mysql {
                diesel::insert_or_ignore_into(event::table)
                .values(&events)
                .execute(conn)
                .unwrap_or_default();
                Ok(())
            }
            postgresql {
                diesel::insert_into(event::table)
                .values(&events)
                .on_conflict_do_nothing()
                .execute(conn)
                .unwrap_or_default();
                Ok(())
            }
        }
    }

    pub async fn delete(self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(event::table.filter(event::uuid.eq(self.uuid))).execute(conn).map_res("Error deleting event")
        })
        .await
    }

    /// ##############
    /// Custom Queries
    pub async fn find_by_organization_uuid(
        org_uuid: &OrganizationId,
        start: &NaiveDateTime,
        end: &NaiveDateTime,
        conn: &DbConn,
    ) -> Vec<Self> {
        conn.run(move |conn| {
            event::table
                .filter(event::org_uuid.eq(org_uuid))
                .filter(event::event_date.between(start, end))
                .order_by(event::event_date.desc())
                .limit(Self::PAGE_SIZE)
                .load::<Self>(conn)
                .expect("Error filtering events")
        })
        .await
    }

    pub async fn count_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> i64 {
        conn.run(move |conn| {
            event::table.filter(event::org_uuid.eq(org_uuid)).count().first::<i64>(conn).ok().unwrap_or(0)
        })
        .await
    }

    pub async fn find_by_org_and_member(
        org_uuid: &OrganizationId,
        member_uuid: &MembershipId,
        start: &NaiveDateTime,
        end: &NaiveDateTime,
        conn: &DbConn,
    ) -> Vec<Self> {
        conn.run(move |conn| {
            event::table
                .inner_join(
                    users_organizations::table
                        .on(users_organizations::uuid.eq(member_uuid).and(users_organizations::org_uuid.eq(org_uuid))),
                )
                .filter(event::org_uuid.eq(org_uuid))
                .filter(event::event_date.between(start, end))
                .filter(
                    event::org_user_uuid
                        .eq(member_uuid)
                        .or(event::user_uuid.eq(users_organizations::user_uuid.nullable()))
                        .or(event::act_user_uuid.eq(users_organizations::user_uuid.nullable())),
                )
                .select(event::all_columns)
                .order_by(event::event_date.desc())
                .limit(Self::PAGE_SIZE)
                .load::<Self>(conn)
                .expect("Error filtering events")
        })
        .await
    }

    pub async fn find_by_cipher_uuid(
        cipher_uuid: &CipherId,
        start: &NaiveDateTime,
        end: &NaiveDateTime,
        conn: &DbConn,
    ) -> Vec<Self> {
        conn.run(move |conn| {
            event::table
                .filter(event::cipher_uuid.eq(cipher_uuid))
                .filter(event::event_date.between(start, end))
                .order_by(event::event_date.desc())
                .limit(Self::PAGE_SIZE)
                .load::<Self>(conn)
                .expect("Error filtering events")
        })
        .await
    }

    pub async fn clean_events(conn: &DbConn) -> EmptyResult {
        if let Some(days_to_retain) = CONFIG.events_days_retain() {
            let dt = Utc::now().naive_utc() - TimeDelta::try_days(days_to_retain).unwrap();
            conn.run(move |conn| {
                diesel::delete(event::table.filter(event::event_date.lt(dt)))
                    .execute(conn)
                    .map_res("Error cleaning old events")
            })
            .await
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, DieselNewType, FromForm, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventId(String);

// Keykeeper: for event streaming's queue, which keys on it.
impl EventId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
