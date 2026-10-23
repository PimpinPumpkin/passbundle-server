// Keykeeper: how people join an organization. Whether someone who accepts an
// invitation is confirmed automatically, by an owner's or admin's unlocked
// app in the background (the server never holds the organization's key, so it
// can't do it itself), and how long an invitation lasts.
//
// An organization's own setting wins; without one it follows its MSP's
// default, and outside an MSP the server's: confirmed automatically, and
// invitations last INVITATION_EXPIRATION_HOURS. See DESIGN.md, "Joining".

use diesel::prelude::*;

use crate::{
    CONFIG,
    api::EmptyResult,
    db::{
        DbConn,
        keykeeper_schema::{msp_joining, org_joining},
    },
    error::MapResult,
};

use super::{MspClient, MspId, OrganizationId};

/// Whether someone waiting to join gets in without an owner or admin
/// approving them: the organization confirms automatically, and if they
/// joined with the install command, the command is limited to the
/// organization's email domains. A command without domains can be copied off
/// any machine it ran on and used with any account, so those joins wait for
/// approval. See DESIGN.md, "Onboarding through the RMM".
///
/// Someone only the directory invited (provisioning) waits for an owner or
/// admin to let them in, unless they joined with a command limited to email
/// domains: nothing an app can check vouches for the directory's choice. See
/// DESIGN.md, "Provisioning from Entra ID".
pub async fn confirms_automatically(org_auto_confirm: bool, member: &super::Membership, conn: &DbConn) -> bool {
    if !org_auto_confirm {
        return false;
    }
    if super::MspEnrollmentJoin::exists_for(&member.uuid, conn).await {
        return !super::EnrollmentDomains::for_org(&member.org_uuid, conn).await.is_empty();
    }
    !super::ScimUser::awaits_let_in(member, conn).await
}

/// Invitations last between an hour and 30 days.
pub const INVITE_HOURS: std::ops::RangeInclusive<i32> = 1..=720;

/// A joining setting, wherever it comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Joining {
    pub auto_confirm: bool,
    pub invite_hours: i32,
}

impl Joining {
    /// The server's: confirmed automatically, and its configured invitation lifetime.
    pub fn server_default() -> Self {
        Self {
            auto_confirm: true,
            invite_hours: i32::try_from(CONFIG.invitation_expiration_hours()).unwrap_or(120),
        }
    }
}

/// An organization's own setting, which its MSP's default doesn't change.
#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = org_joining)]
#[diesel(primary_key(org_uuid))]
pub struct OrgJoining {
    pub org_uuid: OrganizationId,
    pub auto_confirm: bool,
    pub invite_hours: i32,
}

/// An MSP's default for its clients.
#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = msp_joining)]
#[diesel(primary_key(msp_uuid))]
pub struct MspJoining {
    pub msp_uuid: MspId,
    pub auto_confirm: bool,
    pub invite_hours: i32,
}

impl OrgJoining {
    pub fn new(org_uuid: OrganizationId, joining: Joining) -> Self {
        Self {
            org_uuid,
            auto_confirm: joining.auto_confirm,
            invite_hours: joining.invite_hours,
        }
    }

    pub async fn find(org_uuid: &OrganizationId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| org_joining::table.filter(org_joining::org_uuid.eq(org_uuid)).first::<Self>(conn).ok())
            .await
    }

    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(org_joining::table.filter(org_joining::org_uuid.eq(&self.org_uuid)))
                .execute(conn)
                .map(|_| ())
                .map_res("Error saving how people join")?;
            diesel::insert_into(org_joining::table).values(self).execute(conn).map_res("Error saving how people join")
        })
        .await
    }

    /// Puts the organization back on its MSP's default, or the server's.
    pub async fn delete(org_uuid: &OrganizationId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(org_joining::table.filter(org_joining::org_uuid.eq(org_uuid)))
                .execute(conn)
                .map(|_| ())
                .map_res("Error resetting how people join")
        })
        .await
    }
}

impl MspJoining {
    pub fn new(msp_uuid: MspId, joining: Joining) -> Self {
        Self {
            msp_uuid,
            auto_confirm: joining.auto_confirm,
            invite_hours: joining.invite_hours,
        }
    }

    pub async fn find(msp_uuid: &MspId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| msp_joining::table.filter(msp_joining::msp_uuid.eq(msp_uuid)).first::<Self>(conn).ok())
            .await
    }

    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(msp_joining::table.filter(msp_joining::msp_uuid.eq(&self.msp_uuid)))
                .execute(conn)
                .map(|_| ())
                .map_res("Error saving the MSP's joining default")?;
            diesel::insert_into(msp_joining::table)
                .values(self)
                .execute(conn)
                .map_res("Error saving the MSP's joining default")
        })
        .await
    }

    pub fn joining(&self) -> Joining {
        Joining {
            auto_confirm: self.auto_confirm,
            invite_hours: self.invite_hours,
        }
    }
}

/// Where an organization's setting comes from.
pub enum JoiningSource {
    /// Its own, set in its admin console or by an MSP admin for this client.
    Own,
    /// Its MSP's default.
    Msp,
    /// The server's: the organization isn't an MSP's client.
    Server,
}

/// The MSP's default: its own, or the server's until it sets one.
pub async fn msp_default(msp_uuid: &MspId, conn: &DbConn) -> Joining {
    MspJoining::find(msp_uuid, conn).await.map_or_else(Joining::server_default, |d| d.joining())
}

/// The setting in effect for an organization, and where it comes from.
pub async fn effective_joining(org_uuid: &OrganizationId, conn: &DbConn) -> (Joining, JoiningSource) {
    if let Some(own) = OrgJoining::find(org_uuid, conn).await {
        let joining = Joining {
            auto_confirm: own.auto_confirm,
            invite_hours: own.invite_hours,
        };
        return (joining, JoiningSource::Own);
    }
    if let Some(client) = MspClient::find_by_org(org_uuid, conn).await {
        return (msp_default(&client.msp_uuid, conn).await, JoiningSource::Msp);
    }
    (Joining::server_default(), JoiningSource::Server)
}

/// How long an invitation to this organization lasts, in hours.
pub async fn invite_hours(org_uuid: &OrganizationId, conn: &DbConn) -> i64 {
    i64::from(effective_joining(org_uuid, conn).await.0.invite_hours)
}
