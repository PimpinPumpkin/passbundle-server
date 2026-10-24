// Keykeeper: which PassBundle account an organization's single sign-on signs
// someone in to. A pure decision over facts the caller loads, so every rule
// has a unit test. See DESIGN.md, "Sign in with Microsoft Entra ID", "How
// accounts link".
//
// - Someone already linked (this organization, their tenant id and object id)
//   signs in to that account, whatever email Entra sends now, as long as it's
//   still within the organization's rules below.
// - Otherwise the email Entra sends is only a suggestion. It may pick an
//   account to link only when it's vouched for: its domain is one this
//   organization verified with a DNS record, or Entra says the domain's
//   owner verified it (`xms_edov`). Then the account must be in the
//   organization (invited, joined, or confirmed, and not turned off), or have
//   no organization at all and an email at one of the organization's verified
//   domains.
// - Never anyone on an MSP's staff: their account reaches every client, so
//   one client's directory could otherwise sign in to all of them. They sign
//   in with their master password.
// - Never an account already linked to another Entra person here.
//
// Nothing here creates an account. Someone with no account and no
// invitation is told to ask for one.

use crate::db::models::{MembershipId, MembershipStatus, UserId};

/// What the decision needs to know about an account.
#[derive(Clone, Debug)]
#[expect(clippy::struct_excessive_bools, reason = "independent facts about one account, each a rule's input")]
pub struct Candidate {
    pub user_id: UserId,
    pub email: String,
    pub enabled: bool,
    /// On any MSP's staff, or a member of any organization through an MSP.
    pub msp_staff: bool,
    /// Has keys: a real account, not only an invitation.
    pub has_keys: bool,
    /// Their membership in this organization: its id and status.
    pub membership: Option<(MembershipId, i32)>,
    /// How many other organizations they belong to, in any status.
    pub other_orgs: usize,
    /// Their email's domain is one this organization verified.
    pub domain_verified: bool,
    /// Linked to another Entra person in this organization.
    pub linked_elsewhere: bool,
}

/// What the caller found.
#[derive(Clone, Debug)]
pub struct Facts {
    /// The account this person is linked to here, if they are.
    pub linked: Option<Candidate>,
    /// The email Entra sent, lowercase.
    pub email: Option<String>,
    /// Entra's `xms_edov` for that email.
    pub email_vouched: bool,
    /// That email's domain is one this organization verified.
    pub email_domain_verified: bool,
    /// The account with that email, when nobody is linked.
    pub by_email: Option<Candidate>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    /// Already linked: sign in to it.
    SignIn(UserId),
    /// Link this person to the account, then sign in to it.
    Link(UserId),
    Refuse(Refusal),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    NoEmail,
    EmailNotVouched(String),
    NoAccount(String),
    NotMember(String),
    TurnedOff(String),
    Disabled(String),
    MspStaff(String),
    LinkedToAnother(String),
}

impl Refusal {
    /// What the person signing in is told. `org` is the organization's name.
    pub fn message(&self, org: &str) -> String {
        match self {
            Self::NoEmail => "Your Microsoft account has no email address to match to a PassBundle account. Ask your administrator to invite you.".to_owned(),
            Self::EmailNotVouched(email) => format!(
                "Microsoft didn't confirm that {email} is yours, so it can't be linked to a PassBundle account. Ask your administrator to verify your email's domain for single sign-on."
            ),
            Self::NoAccount(email) => format!(
                "There's no PassBundle account or invitation for {email} in {org}. Ask your administrator to invite you."
            ),
            Self::NotMember(email) => format!(
                "{email} isn't a member of {org}, so its single sign-on can't sign you in. Ask your administrator to invite you."
            ),
            Self::TurnedOff(_) => format!("Your access to {org} is turned off. Ask your administrator."),
            Self::Disabled(_) => "This account has been disabled.".to_owned(),
            Self::MspStaff(_) => "IT provider staff sign in with their email and master password, not a client's single sign-on.".to_owned(),
            Self::LinkedToAnother(email) => format!(
                "{email} is already linked to a different Microsoft account in {org}. Ask your administrator to unlink it."
            ),
        }
    }

    /// A few words for the organization's event log.
    pub fn detail(&self) -> String {
        match self {
            Self::NoEmail => "no email in the Microsoft account".to_owned(),
            Self::EmailNotVouched(email) => format!("{email} not vouched for (unverified domain, no xms_edov)"),
            Self::NoAccount(email) => format!("no account or invitation for {email}"),
            Self::NotMember(email) => format!("{email} isn't a member"),
            Self::TurnedOff(email) => format!("{email} is turned off"),
            Self::Disabled(email) => format!("{email}'s account is disabled"),
            Self::MspStaff(email) => format!("{email} is IT provider staff"),
            Self::LinkedToAnother(email) => format!("{email} is linked to another Microsoft account"),
        }
    }
}

/// Whether the organization's single sign-on may sign in to this account.
fn within_rules(c: &Candidate) -> Result<(), Refusal> {
    if !c.enabled {
        return Err(Refusal::Disabled(c.email.clone()));
    }
    if c.msp_staff {
        return Err(Refusal::MspStaff(c.email.clone()));
    }
    match c.membership {
        Some((_, status)) if status == MembershipStatus::Revoked as i32 => Err(Refusal::TurnedOff(c.email.clone())),
        Some(_) => Ok(()),
        // Not in this organization: only someone in no organization at all,
        // with a real account, at a domain this organization proved it owns.
        None if c.domain_verified && c.other_orgs == 0 && c.has_keys => Ok(()),
        None => Err(Refusal::NotMember(c.email.clone())),
    }
}

pub fn decide(facts: &Facts) -> Decision {
    if let Some(linked) = &facts.linked {
        // The link decides who it is; the email Entra sends now doesn't.
        return match within_rules(linked) {
            Ok(()) => Decision::SignIn(linked.user_id.clone()),
            Err(refusal) => Decision::Refuse(refusal),
        };
    }
    let Some(email) = &facts.email else {
        return Decision::Refuse(Refusal::NoEmail);
    };
    if !(facts.email_vouched || facts.email_domain_verified) {
        return Decision::Refuse(Refusal::EmailNotVouched(email.clone()));
    }
    let Some(candidate) = &facts.by_email else {
        return Decision::Refuse(Refusal::NoAccount(email.clone()));
    };
    // The account matched by email, or nothing: never one Entra didn't name.
    if !candidate.email.eq_ignore_ascii_case(email) {
        return Decision::Refuse(Refusal::NoAccount(email.clone()));
    }
    if candidate.linked_elsewhere {
        return Decision::Refuse(Refusal::LinkedToAnother(email.clone()));
    }
    match within_rules(candidate) {
        Ok(()) => Decision::Link(candidate.user_id.clone()),
        Err(refusal) => Decision::Refuse(refusal),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(email: &str, status: MembershipStatus) -> Candidate {
        Candidate {
            user_id: UserId::from(format!("user-{email}")),
            email: email.to_owned(),
            enabled: true,
            msp_staff: false,
            has_keys: true,
            membership: Some((MembershipId::from(format!("member-{email}")), status as i32)),
            other_orgs: 0,
            domain_verified: false,
            linked_elsewhere: false,
        }
    }

    fn outsider(email: &str) -> Candidate {
        Candidate {
            membership: None,
            ..member(email, MembershipStatus::Confirmed)
        }
    }

    fn first_sign_in(email: &str, vouched: bool, domain_verified: bool, account: Option<Candidate>) -> Facts {
        Facts {
            linked: None,
            email: Some(email.to_owned()),
            email_vouched: vouched,
            email_domain_verified: domain_verified,
            by_email: account,
        }
    }

    fn user(email: &str) -> UserId {
        UserId::from(format!("user-{email}"))
    }

    #[test]
    fn a_member_with_a_vouched_email_is_linked() {
        for status in [MembershipStatus::Invited, MembershipStatus::Accepted, MembershipStatus::Confirmed] {
            let facts = first_sign_in("ana@acme.test", true, false, Some(member("ana@acme.test", status)));
            assert_eq!(decide(&facts), Decision::Link(user("ana@acme.test")));
        }
        // Vouched for by the organization's verified domain instead.
        let facts =
            first_sign_in("ana@acme.test", false, true, Some(member("ana@acme.test", MembershipStatus::Confirmed)));
        assert_eq!(decide(&facts), Decision::Link(user("ana@acme.test")));
    }

    #[test]
    fn an_email_nobody_vouches_for_links_nothing() {
        // Entra's email claim isn't verified: an admin can set a user's mail to
        // anything. Unvouched, it never picks an account, even a member's.
        let facts =
            first_sign_in("ceo@acme.test", false, false, Some(member("ceo@acme.test", MembershipStatus::Confirmed)));
        assert_eq!(decide(&facts), Decision::Refuse(Refusal::EmailNotVouched("ceo@acme.test".into())));
    }

    #[test]
    fn a_spoofed_email_never_moves_an_existing_link() {
        // Ana is linked. Her token now claims the CEO's email, vouched for and
        // at a verified domain: she still signs in as Ana, never as the CEO.
        let facts = Facts {
            linked: Some(member("ana@acme.test", MembershipStatus::Confirmed)),
            email: Some("ceo@acme.test".into()),
            email_vouched: true,
            email_domain_verified: true,
            by_email: Some(member("ceo@acme.test", MembershipStatus::Confirmed)),
        };
        assert_eq!(decide(&facts), Decision::SignIn(user("ana@acme.test")));
    }

    #[test]
    fn a_spoofed_email_cant_take_an_account_linked_to_someone_else() {
        let mut ceo = member("ceo@acme.test", MembershipStatus::Confirmed);
        ceo.linked_elsewhere = true;
        let facts = first_sign_in("ceo@acme.test", true, true, Some(ceo));
        assert_eq!(decide(&facts), Decision::Refuse(Refusal::LinkedToAnother("ceo@acme.test".into())));
    }

    #[test]
    fn a_non_member_is_refused() {
        // A vouched email at another domain: an account elsewhere, not here.
        let facts = first_sign_in("bob@other.test", true, false, Some(outsider("bob@other.test")));
        assert_eq!(decide(&facts), Decision::Refuse(Refusal::NotMember("bob@other.test".into())));
        // At a verified domain, but a member of another organization: never
        // one organization's sign-in for another's member.
        let mut elsewhere = outsider("bob@acme.test");
        elsewhere.domain_verified = true;
        elsewhere.other_orgs = 1;
        let facts = first_sign_in("bob@acme.test", false, true, Some(elsewhere));
        assert_eq!(decide(&facts), Decision::Refuse(Refusal::NotMember("bob@acme.test".into())));
        // Only an invitation, from another organization (no keys yet).
        let mut stub = outsider("bob@acme.test");
        stub.domain_verified = true;
        stub.has_keys = false;
        let facts = first_sign_in("bob@acme.test", false, true, Some(stub));
        assert_eq!(decide(&facts), Decision::Refuse(Refusal::NotMember("bob@acme.test".into())));
    }

    #[test]
    fn an_account_in_no_organization_at_a_verified_domain_is_linked() {
        let mut solo = outsider("bob@acme.test");
        solo.domain_verified = true;
        let facts = first_sign_in("bob@acme.test", false, true, Some(solo));
        assert_eq!(decide(&facts), Decision::Link(user("bob@acme.test")));
        // xms_edov alone isn't enough for someone outside the organization.
        let facts = first_sign_in("bob@acme.test", true, false, Some(outsider("bob@acme.test")));
        assert_eq!(decide(&facts), Decision::Refuse(Refusal::NotMember("bob@acme.test".into())));
    }

    #[test]
    fn msp_staff_are_never_signed_in_by_a_client() {
        let mut tech = member("tech@msp.test", MembershipStatus::Confirmed);
        tech.msp_staff = true;
        let facts = first_sign_in("tech@msp.test", true, true, Some(tech.clone()));
        assert_eq!(decide(&facts), Decision::Refuse(Refusal::MspStaff("tech@msp.test".into())));
        // Not even through a link made before they joined the staff.
        let facts = Facts {
            linked: Some(tech),
            ..first_sign_in("tech@msp.test", true, true, None)
        };
        assert_eq!(decide(&facts), Decision::Refuse(Refusal::MspStaff("tech@msp.test".into())));
    }

    #[test]
    fn a_link_stops_working_outside_the_rules() {
        // Turned off in the organization (Entra provisioning, or an admin).
        let facts = Facts {
            linked: Some(member("ana@acme.test", MembershipStatus::Revoked)),
            ..first_sign_in("ana@acme.test", true, true, None)
        };
        assert_eq!(decide(&facts), Decision::Refuse(Refusal::TurnedOff("ana@acme.test".into())));
        // Removed from the organization, and now a member of another one.
        let mut left = outsider("ana@acme.test");
        left.domain_verified = true;
        left.other_orgs = 1;
        let facts = Facts {
            linked: Some(left),
            ..first_sign_in("ana@acme.test", true, true, None)
        };
        assert_eq!(decide(&facts), Decision::Refuse(Refusal::NotMember("ana@acme.test".into())));
        // A disabled account.
        let mut disabled = member("ana@acme.test", MembershipStatus::Confirmed);
        disabled.enabled = false;
        let facts = Facts {
            linked: Some(disabled),
            ..first_sign_in("ana@acme.test", true, true, None)
        };
        assert_eq!(decide(&facts), Decision::Refuse(Refusal::Disabled("ana@acme.test".into())));
    }

    #[test]
    fn nobody_is_made_an_account() {
        let facts = first_sign_in("new@acme.test", true, true, None);
        assert_eq!(decide(&facts), Decision::Refuse(Refusal::NoAccount("new@acme.test".into())));
        let facts = Facts {
            email: None,
            ..first_sign_in("x@acme.test", true, true, None)
        };
        assert_eq!(decide(&facts), Decision::Refuse(Refusal::NoEmail));
    }

    #[test]
    fn only_the_account_with_entras_email_is_linked() {
        // The caller found an account by another email somehow: refused.
        let facts =
            first_sign_in("ana@acme.test", true, true, Some(member("ceo@acme.test", MembershipStatus::Confirmed)));
        assert_eq!(decide(&facts), Decision::Refuse(Refusal::NoAccount("ana@acme.test".into())));
    }

    #[test]
    fn messages_name_no_secrets() {
        let all = [
            Refusal::NoEmail,
            Refusal::EmailNotVouched("a@b.test".into()),
            Refusal::NoAccount("a@b.test".into()),
            Refusal::NotMember("a@b.test".into()),
            Refusal::TurnedOff("a@b.test".into()),
            Refusal::Disabled("a@b.test".into()),
            Refusal::MspStaff("a@b.test".into()),
            Refusal::LinkedToAnother("a@b.test".into()),
        ];
        for r in all {
            assert!(!r.message("Acme").is_empty());
            assert!(!r.detail().is_empty());
            assert!(!r.message("Acme").contains('\u{2014}'), "no em dashes");
        }
    }
}
