// Keykeeper: two-step login for the people who run an organization or an
// MSP. An organization's setting requires it of its owners, admins, and custom
// roles that manage members, policies, or account recovery; an MSP's setting
// requires it of everyone on its staff. Someone it covers who signs in
// without a second step that counts gets a setup session, which can only set
// one up. See DESIGN.md, "Two-step login for admins", in the meta repo.

use chrono::{NaiveDateTime, TimeDelta, Utc};
use diesel::prelude::*;

use crate::{
    api::{ApiResult, EmptyResult},
    db::{
        DbConn,
        keykeeper_schema::{
            msp_staff_two_step, org_admin_two_step, revoked_until_accepted, two_step_nudge_dismissals,
            two_step_setup_sessions, unaccepted_memberships,
        },
    },
    error::MapResult,
};

use super::{MembershipId, MspId, OrganizationId, TwoFactorType, UserId, sso_hash, sso_random};

/// The second steps that count for a role two-step login is required of: an
/// authenticator app, a security key or passkey, and Duo. Email codes don't:
/// a client's email admins can read a member's mailbox, the same reason a
/// link to single sign-on never trusts an email. Upstream's YubiKey OTP isn't
/// counted either. See DESIGN.md, "Two-step login for admins".
pub const QUALIFYING_TWO_STEP: [i32; 3] =
    [TwoFactorType::Authenticator as i32, TwoFactorType::Webauthn as i32, TwoFactorType::Duo as i32];

/// Whether a two-step method (upstream's type number) counts for the roles
/// two-step login is required of.
pub fn qualifying_two_step(atype: i32) -> bool {
    QUALIFYING_TWO_STEP.contains(&atype)
}

/// Whom an organization requires two-step login of: nobody, its admins (its
/// owners, admins, custom roles that manage members, policies, or account
/// recovery, and everyone its MSP brings in), or everyone who has joined it,
/// which includes the admins. One setting with three levels, so it can't
/// require it of members but not admins. See DESIGN.md, "Two-step login for
/// everyone".
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TwoStepScope {
    Off,
    Admins,
    Everyone,
}

impl TwoStepScope {
    /// The level a row says: `everyone` counts only while `required` is on.
    pub fn of(required: bool, everyone: bool) -> Self {
        match (required, everyone) {
            (false, _) => Self::Off,
            (true, false) => Self::Admins,
            (true, true) => Self::Everyone,
        }
    }

    /// Whether it requires anything: the admin level, at least.
    pub fn required(self) -> bool {
        self != Self::Off
    }

    pub fn everyone(self) -> bool {
        self == Self::Everyone
    }
}

/// An organization's setting: whether its owners, admins, and the custom roles
/// that manage members, policies, or account recovery must use two-step login,
/// and whether everyone else must too (TwoStepScope).
#[derive(Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = org_admin_two_step)]
#[diesel(primary_key(org_uuid))]
pub struct OrgAdminTwoStep {
    pub org_uuid: OrganizationId,
    pub required: bool,
    /// Everyone else too. Counts only while `required` is on.
    pub everyone: bool,
}

impl OrgAdminTwoStep {
    /// Whether the organization requires it of its admins (or of everyone).
    /// Without a row it doesn't: the Business preset and an MSP's default
    /// policies write one.
    pub async fn required(org_uuid: &OrganizationId, conn: &DbConn) -> ApiResult<bool> {
        Ok(Self::scope(org_uuid, conn).await?.required())
    }

    /// Whom the organization requires it of. Without a row, nobody.
    pub async fn scope(org_uuid: &OrganizationId, conn: &DbConn) -> ApiResult<TwoStepScope> {
        let org_uuid = org_uuid.clone();
        conn.run(move |conn| {
            org_admin_two_step::table
                .filter(org_admin_two_step::org_uuid.eq(org_uuid))
                .select((org_admin_two_step::required, org_admin_two_step::everyone))
                .first::<(bool, bool)>(conn)
                .optional()
                .map(|r| r.map_or(TwoStepScope::Off, |(required, everyone)| TwoStepScope::of(required, everyone)))
                .map_res("Error reading an organization's two-step login setting")
        })
        .await
    }

    pub async fn set(org_uuid: &OrganizationId, scope: TwoStepScope, conn: &DbConn) -> EmptyResult {
        let row = Self {
            org_uuid: org_uuid.clone(),
            required: scope.required(),
            everyone: scope.everyone(),
        };
        conn.run(move |conn| {
            diesel::delete(org_admin_two_step::table.filter(org_admin_two_step::org_uuid.eq(&row.org_uuid)))
                .execute(conn)
                .map_res("Error saving an organization's two-step login setting")
                .map(|_: usize| ())?;
            diesel::insert_into(org_admin_two_step::table)
                .values(&row)
                .execute(conn)
                .map_res("Error saving an organization's two-step login setting")
        })
        .await
    }
}

/// An MSP's setting: whether everyone on its staff must use two-step login.
#[derive(Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = msp_staff_two_step)]
#[diesel(primary_key(msp_uuid))]
pub struct MspStaffTwoStep {
    pub msp_uuid: MspId,
    pub required: bool,
}

impl MspStaffTwoStep {
    /// Whether the MSP requires it of its staff. Without a row it does.
    pub async fn required(msp_uuid: &MspId, conn: &DbConn) -> ApiResult<bool> {
        let msp_uuid = msp_uuid.clone();
        conn.run(move |conn| {
            msp_staff_two_step::table
                .filter(msp_staff_two_step::msp_uuid.eq(msp_uuid))
                .select(msp_staff_two_step::required)
                .first::<bool>(conn)
                .optional()
                .map(|r| r.unwrap_or(true))
                .map_res("Error reading an MSP's two-step login setting")
        })
        .await
    }

    pub async fn set(msp_uuid: &MspId, required: bool, conn: &DbConn) -> EmptyResult {
        let row = Self {
            msp_uuid: msp_uuid.clone(),
            required,
        };
        conn.run(move |conn| {
            diesel::delete(msp_staff_two_step::table.filter(msp_staff_two_step::msp_uuid.eq(&row.msp_uuid)))
                .execute(conn)
                .map_res("Error saving an MSP's two-step login setting")
                .map(|_: usize| ())?;
            diesel::insert_into(msp_staff_two_step::table)
                .values(&row)
                .execute(conn)
                .map_res("Error saving an MSP's two-step login setting")
        })
        .await
    }
}

/// Memberships the server accepted for their person, on a server that sends
/// no email: upstream joins an existing account at once when it's invited, so
/// the person never accepted. Two-step login for admins doesn't count one
/// until they accept it in the web vault, so nobody can sign someone out, or
/// hold up their sign-in, by inviting them as an admin.
pub struct UnacceptedMembership;

impl UnacceptedMembership {
    /// Records that the server, not the person, accepted these memberships.
    pub async fn mark(ids: Vec<MembershipId>, conn: &DbConn) -> EmptyResult {
        if ids.is_empty() {
            return Ok(());
        }
        conn.run(move |conn| {
            for id in &ids {
                diesel::delete(unaccepted_memberships::table.filter(unaccepted_memberships::membership_uuid.eq(id)))
                    .execute(conn)
                    .map_res("Error recording a membership its person hasn't accepted")
                    .map(|_: usize| ())?;
                diesel::insert_into(unaccepted_memberships::table)
                    .values(unaccepted_memberships::membership_uuid.eq(id))
                    .execute(conn)
                    .map_res("Error recording a membership its person hasn't accepted")
                    .map(|_: usize| ())?;
            }
            Ok(())
        })
        .await
    }

    /// Whether the person hasn't accepted this membership.
    pub async fn is(id: &MembershipId, conn: &DbConn) -> bool {
        let id = id.clone();
        conn.run(move |conn| {
            unaccepted_memberships::table
                .filter(unaccepted_memberships::membership_uuid.eq(id))
                .count()
                .first::<i64>(conn)
                .is_ok_and(|n| n > 0)
        })
        .await
    }

    /// The person accepted it.
    pub async fn accept(id: &MembershipId, conn: &DbConn) -> EmptyResult {
        let id = id.clone();
        conn.run(move |conn| {
            diesel::delete(unaccepted_memberships::table.filter(unaccepted_memberships::membership_uuid.eq(id)))
                .execute(conn)
                .map_res("Error accepting a membership")
                .map(|_: usize| ())
        })
        .await
    }
}

/// Memberships revoked until their person accepts them: a role the server
/// accepted for its person (UnacceptedMembership), confirmed before its
/// organization required two-step login for it. Accepting restores it; a
/// revoke by the directory, or a restore once the organization no longer
/// requires it, ends the hold. Removing the membership removes the row.
pub struct RevokedUntilAccepted;

impl RevokedUntilAccepted {
    /// Records that this membership is revoked until its person accepts it.
    pub async fn hold(id: &MembershipId, conn: &DbConn) -> EmptyResult {
        let id = id.clone();
        conn.run(move |conn| {
            diesel::delete(revoked_until_accepted::table.filter(revoked_until_accepted::membership_uuid.eq(&id)))
                .execute(conn)
                .map_res("Error recording a membership revoked until it's accepted")
                .map(|_: usize| ())?;
            diesel::insert_into(revoked_until_accepted::table)
                .values(revoked_until_accepted::membership_uuid.eq(&id))
                .execute(conn)
                .map_res("Error recording a membership revoked until it's accepted")
                .map(|_: usize| ())
        })
        .await
    }

    /// Whether this membership is revoked until its person accepts it.
    pub async fn is(id: &MembershipId, conn: &DbConn) -> bool {
        let id = id.clone();
        conn.run(move |conn| {
            revoked_until_accepted::table
                .filter(revoked_until_accepted::membership_uuid.eq(id))
                .count()
                .first::<i64>(conn)
                .is_ok_and(|n| n > 0)
        })
        .await
    }

    /// The hold is over: accepted, restored, or turned off by the directory.
    pub async fn end(id: &MembershipId, conn: &DbConn) -> EmptyResult {
        let id = id.clone();
        conn.run(move |conn| {
            diesel::delete(revoked_until_accepted::table.filter(revoked_until_accepted::membership_uuid.eq(id)))
                .execute(conn)
                .map_res("Error ending a membership's hold")
                .map(|_: usize| ())
        })
        .await
    }
}

/// How long "Not now" hides the nudge to set up two-step login.
pub const TWO_STEP_NUDGE_DAYS: i64 = 90;

/// When an account last said "Not now" to the nudge to set up two-step login
/// (DESIGN.md, "A nudge for everyone else"): one row per account, so it's the
/// same on every device. Nothing else is kept.
pub struct TwoStepNudgeDismissal;

impl TwoStepNudgeDismissal {
    /// Whether the account said "Not now" in the last 90 days.
    pub async fn hidden(user_uuid: &UserId, conn: &DbConn) -> bool {
        let user_uuid = user_uuid.clone();
        let since = Utc::now().naive_utc() - TimeDelta::days(TWO_STEP_NUDGE_DAYS);
        conn.run(move |conn| {
            two_step_nudge_dismissals::table
                .filter(two_step_nudge_dismissals::user_uuid.eq(user_uuid))
                .select(two_step_nudge_dismissals::dismissed_at)
                .first::<NaiveDateTime>(conn)
                .optional()
                .ok()
                .flatten()
                .is_some_and(|at| hides_since(at, since))
        })
        .await
    }

    /// The account said "Not now", just now.
    pub async fn dismiss(user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        let user_uuid = user_uuid.clone();
        let now = Utc::now().naive_utc();
        conn.run(move |conn| {
            diesel::delete(
                two_step_nudge_dismissals::table.filter(two_step_nudge_dismissals::user_uuid.eq(&user_uuid)),
            )
            .execute(conn)
            .map_res("Error saving a dismissed notice")
            .map(|_: usize| ())?;
            diesel::insert_into(two_step_nudge_dismissals::table)
                .values((
                    two_step_nudge_dismissals::user_uuid.eq(&user_uuid),
                    two_step_nudge_dismissals::dismissed_at.eq(now),
                ))
                .execute(conn)
                .map_res("Error saving a dismissed notice")
        })
        .await
    }
}

/// Whether a dismissal at `at` still hides the nudge: it came after `since`.
fn hides_since(at: NaiveDateTime, since: NaiveDateTime) -> bool {
    at > since
}

/// How long a setup session lasts.
pub const TWO_STEP_SETUP_MINUTES: i64 = 15;

/// A setup session: what a sign-in gets instead of a login when the person's
/// role requires two-step login and they haven't set up a method that counts.
/// It isn't a login token, so only the endpoints that set up two-step login
/// take it (keykeeper_two_step::SetupHeaders); it has no refresh token, lasts
/// fifteen minutes, and ends when a method that counts is set up. Kept only as
/// a hash, like a single sign-on linking session.
#[derive(Identifiable, Queryable, Insertable, Clone)]
#[diesel(table_name = two_step_setup_sessions)]
#[diesel(primary_key(session_hash))]
pub struct TwoStepSetupSession {
    pub session_hash: String,
    pub user_uuid: UserId,
    /// The device type the sign-in came from, for the events setup logs.
    pub device_type: i32,
    pub created_at: NaiveDateTime,
}

impl TwoStepSetupSession {
    /// A new setup session: its token, and its row.
    pub fn generate(user_uuid: UserId, device_type: i32) -> (String, Self) {
        let token = sso_random();
        let row = Self {
            session_hash: sso_hash(&token),
            user_uuid,
            device_type,
            created_at: Utc::now().naive_utc(),
        };
        (token, row)
    }

    fn oldest() -> NaiveDateTime {
        Utc::now().naive_utc() - TimeDelta::minutes(TWO_STEP_SETUP_MINUTES)
    }

    /// Keeps it, ending the account's earlier setup sessions (one at a time)
    /// and everyone's expired ones.
    pub async fn insert(&self, conn: &DbConn) -> EmptyResult {
        let oldest = Self::oldest();
        conn.run(move |conn| {
            diesel::delete(
                two_step_setup_sessions::table.filter(
                    two_step_setup_sessions::user_uuid
                        .eq(&self.user_uuid)
                        .or(two_step_setup_sessions::created_at.lt(oldest)),
                ),
            )
            .execute(conn)
            .map_res("Error starting two-step login setup")
            .map(|_: usize| ())?;
            diesel::insert_into(two_step_setup_sessions::table)
                .values(self)
                .execute(conn)
                .map_res("Error starting two-step login setup")
        })
        .await
    }

    /// A live setup session, by its token.
    pub async fn find(token: &str, conn: &DbConn) -> Option<Self> {
        let (hash, oldest) = (sso_hash(token), Self::oldest());
        conn.run(move |conn| {
            two_step_setup_sessions::table
                .filter(two_step_setup_sessions::session_hash.eq(hash))
                .filter(two_step_setup_sessions::created_at.ge(oldest))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    /// Ends every setup session the account has: setup is done.
    pub async fn end_for_user(user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        let user_uuid = user_uuid.clone();
        conn.run(move |conn| {
            diesel::delete(two_step_setup_sessions::table.filter(two_step_setup_sessions::user_uuid.eq(user_uuid)))
                .execute(conn)
                .map_res("Error ending two-step login setup")
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_codes_and_yubikey_otp_dont_count() {
        assert!(qualifying_two_step(TwoFactorType::Authenticator as i32));
        assert!(qualifying_two_step(TwoFactorType::Webauthn as i32));
        assert!(qualifying_two_step(TwoFactorType::Duo as i32));
        for t in [
            TwoFactorType::Email,
            TwoFactorType::YubiKey,
            TwoFactorType::U2f,
            TwoFactorType::Remember,
            TwoFactorType::OrganizationDuo,
            TwoFactorType::RecoveryCode,
            TwoFactorType::EmailVerificationChallenge,
            TwoFactorType::WebauthnRegisterChallenge,
            TwoFactorType::WebauthnLoginChallenge,
            TwoFactorType::U2fRegisterChallenge,
            TwoFactorType::U2fLoginChallenge,
            TwoFactorType::ProtectedActions,
        ] {
            assert!(!qualifying_two_step(t as i32));
        }
    }

    #[test]
    fn everyone_includes_the_admins_and_counts_only_with_them() {
        assert_eq!(TwoStepScope::of(false, false), TwoStepScope::Off);
        // Everyone without the admin level is off: turning off the admins
        // turns off both.
        assert_eq!(TwoStepScope::of(false, true), TwoStepScope::Off);
        assert_eq!(TwoStepScope::of(true, false), TwoStepScope::Admins);
        assert_eq!(TwoStepScope::of(true, true), TwoStepScope::Everyone);
        assert!(!TwoStepScope::Off.required());
        assert!(TwoStepScope::Admins.required() && !TwoStepScope::Admins.everyone());
        assert!(TwoStepScope::Everyone.required() && TwoStepScope::Everyone.everyone());
        assert!(TwoStepScope::Off < TwoStepScope::Admins && TwoStepScope::Admins < TwoStepScope::Everyone);
    }

    #[test]
    fn not_now_hides_the_nudge_for_ninety_days() {
        let now = Utc::now().naive_utc();
        let since = now - TimeDelta::days(TWO_STEP_NUDGE_DAYS);
        assert!(hides_since(now, since));
        assert!(hides_since(now - TimeDelta::days(89), since));
        assert!(!hides_since(now - TimeDelta::days(91), since));
    }

    #[test]
    fn a_setup_token_is_kept_only_as_its_hash() {
        let (token, row) = TwoStepSetupSession::generate(UserId::from("user".to_owned()), 9);
        assert_eq!(token.len(), 43);
        assert_ne!(row.session_hash, token);
        assert_eq!(row.session_hash, sso_hash(&token));
        let (other, _) = TwoStepSetupSession::generate(UserId::from("user".to_owned()), 9);
        assert_ne!(token, other);
    }
}
