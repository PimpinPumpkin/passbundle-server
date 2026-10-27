// Keykeeper: which PassBundle account an organization's single sign-on signs
// someone in to. Pure decisions over facts the caller loads, so every rule
// has a unit test. See DESIGN.md, "Sign in with Microsoft Entra ID", "How
// accounts link".
//
// - Someone already linked (this organization, their tenant id and object id)
//   signs in to that account, whatever email Entra sends now, as long as it's
//   still within the organization's rules below.
// - Otherwise the email Entra sends is only a suggestion, and it links only an
//   invitation that has no account yet (no keys): someone invited by email or
//   by provisioning who hasn't set a master password. The email must be
//   vouched for: Entra's `xms_edov` says its domain owner is verified, or,
//   when Entra doesn't say either way, it's at a domain this organization
//   verified with DNS and the person isn't a guest in the tenant. `xms_edov`
//   false is never vouched for.
// - An account that already has keys never links by email: anyone who can
//   write a user's mail in the tenant could otherwise claim it (an owner's,
//   say). Its person links it from a signed-in session instead (upstream's
//   Link SSO, `decide_session`), having proved both their master password
//   and their Microsoft account.
// - Within the rules: in the organization (invited, joined, or confirmed, and
//   not turned off), or, for a signed-in session, an account in no
//   organization at all with an email at one of its verified domains.
// - Never anyone on an MSP's staff: their account reaches every client, so
//   one client's directory could otherwise sign in to all of them. They sign
//   in with their master password.
// - Never an account already linked to another Entra person here, or an Entra
//   person already linked to another account.
//
// Nothing here creates an account. Someone with no account and no
// invitation is told to ask for one.

use crate::db::models::{MembershipId, MembershipStatus, UserId};

/// What the decisions need to know about an account.
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

/// What the caller found for a sign-in.
#[derive(Clone, Debug)]
pub struct Facts {
    /// The account this person is linked to here, if they are.
    pub linked: Option<Candidate>,
    /// The email Entra sent, lowercase ASCII.
    pub email: Option<String>,
    /// Entra's `xms_edov` for that email, if it said.
    pub email_edov: Option<bool>,
    /// A guest in the tenant.
    pub guest: bool,
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
    /// The account has keys: its person links it from a signed-in session.
    SignInToLink(String),
    /// Linking from a session: this Microsoft account is another account's.
    MicrosoftAccountTaken,
}

impl Refusal {
    /// What the person signing in is told. `org` is the organization's name.
    pub fn message(&self, org: &str) -> String {
        match self {
            Self::NoEmail => "Your Microsoft account has no email address to match to a PassBundle invitation. Ask your administrator to invite you.".to_owned(),
            Self::EmailNotVouched(email) => format!(
                "Microsoft didn't confirm that {email} is yours, so it can't be matched to a PassBundle invitation. Ask your administrator to verify your email's domain for single sign-on."
            ),
            Self::NoAccount(email) => format!(
                "There's no PassBundle account or invitation for {email} in {org}. Ask your administrator to invite you."
            ),
            Self::NotMember(email) => format!(
                "{email} isn't a member of {org}, so its single sign-on can't sign you in. Ask your administrator to invite you."
            ),
            Self::TurnedOff(_) => format!("Your access to {org} is turned off. Ask your administrator."),
            Self::Disabled(_) => "This account has been disabled.".to_owned(),
            Self::MspStaff(_) => "IT provider staff sign in with their email and master password, not a client's single sign-on. If an organization you belong to requires single sign-on, ask its owners to make you an owner there, or to remove you.".to_owned(),
            Self::LinkedToAnother(email) => format!(
                "{email} is already linked to a different Microsoft account in {org}. Ask your administrator to unlink it."
            ),
            Self::SignInToLink(email) => format!(
                "{email} already has a PassBundle account. Sign in with your email and master password, then link your Microsoft account: PassBundle asks you to if {org} requires single sign-on, or open {org}'s menu in your vault and choose Link SSO. After that, single sign-on works."
            ),
            Self::MicrosoftAccountTaken => format!(
                "That Microsoft account is already linked to another PassBundle account in {org}. Ask your administrator to unlink it."
            ),
        }
    }

    /// A fixed code for the reason, for security tools: refusals for
    /// different reasons are never merged into one event.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoEmail => "no_email",
            Self::EmailNotVouched(_) => "email_not_vouched",
            Self::NoAccount(_) => "no_account",
            Self::NotMember(_) => "not_member",
            Self::TurnedOff(_) => "turned_off",
            Self::Disabled(_) => "disabled",
            Self::MspStaff(_) => "msp_staff",
            Self::LinkedToAnother(_) => "linked_to_another",
            Self::SignInToLink(_) => "link_from_session",
            Self::MicrosoftAccountTaken => "microsoft_account_taken",
        }
    }

    /// A few words for the organization's event log.
    pub fn detail(&self) -> String {
        match self {
            Self::NoEmail => "no email in the Microsoft account".to_owned(),
            Self::EmailNotVouched(email) => {
                format!("{email} not vouched for (xms_edov, or a verified domain for a member of the tenant)")
            }
            Self::NoAccount(email) => format!("no account or invitation for {email}"),
            Self::NotMember(email) => format!("{email} isn't a member"),
            Self::TurnedOff(email) => format!("{email} is turned off"),
            Self::Disabled(email) => format!("{email}'s account is disabled"),
            Self::MspStaff(email) => format!("{email} is IT provider staff"),
            Self::LinkedToAnother(email) => format!("{email} is linked to another Microsoft account"),
            Self::SignInToLink(email) => {
                format!("{email} has an account: it links from a signed-in session (Link SSO)")
            }
            Self::MicrosoftAccountTaken => "the Microsoft account is linked to another account".to_owned(),
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

/// Whether Entra's email vouches for its person: `xms_edov` when Entra says,
/// otherwise a domain this organization verified, for a member of the tenant.
fn vouched(facts: &Facts) -> bool {
    match facts.email_edov {
        Some(edov) => edov,
        None => facts.email_domain_verified && !facts.guest,
    }
}

/// A sign-in with the organization's single sign-on.
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
    if !vouched(facts) {
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
    if let Err(refusal) = within_rules(candidate) {
        return Decision::Refuse(refusal);
    }
    // An account with keys links only from a signed-in session.
    if candidate.has_keys {
        return Decision::Refuse(Refusal::SignInToLink(email.clone()));
    }
    Decision::Link(candidate.user_id.clone())
}

/// What the caller found for linking from a signed-in session: the session's
/// account, and the account this Microsoft account is already linked to here.
#[derive(Clone, Debug)]
pub struct SessionFacts {
    pub account: Candidate,
    pub microsoft_account_linked_to: Option<UserId>,
}

/// Linking from a signed-in session (upstream's Link SSO): the person proved
/// their master password (the session) and their Microsoft account (this
/// sign-in), so the email doesn't matter. `SignIn` means it's linked already.
pub fn decide_session(facts: &SessionFacts) -> Decision {
    let account = &facts.account;
    match &facts.microsoft_account_linked_to {
        Some(user) if user == &account.user_id => return Decision::SignIn(user.clone()),
        Some(_) => return Decision::Refuse(Refusal::MicrosoftAccountTaken),
        None => {}
    }
    if account.linked_elsewhere {
        return Decision::Refuse(Refusal::LinkedToAnother(account.email.clone()));
    }
    match within_rules(account) {
        Ok(()) => Decision::Link(account.user_id.clone()),
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

    /// Invited, with no account yet: no keys.
    fn invited(email: &str) -> Candidate {
        Candidate {
            has_keys: false,
            ..member(email, MembershipStatus::Invited)
        }
    }

    fn outsider(email: &str) -> Candidate {
        Candidate {
            membership: None,
            ..member(email, MembershipStatus::Confirmed)
        }
    }

    fn first_sign_in(email: &str, edov: Option<bool>, domain_verified: bool, account: Option<Candidate>) -> Facts {
        Facts {
            linked: None,
            email: Some(email.to_owned()),
            email_edov: edov,
            guest: false,
            email_domain_verified: domain_verified,
            by_email: account,
        }
    }

    fn user(email: &str) -> UserId {
        UserId::from(format!("user-{email}"))
    }

    #[test]
    fn an_invitation_without_an_account_links_by_a_vouched_email() {
        let facts = first_sign_in("ana@acme.test", Some(true), false, Some(invited("ana@acme.test")));
        assert_eq!(decide(&facts), Decision::Link(user("ana@acme.test")));
        // A verified domain vouches when Entra doesn't say either way.
        let facts = first_sign_in("ana@acme.test", None, true, Some(invited("ana@acme.test")));
        assert_eq!(decide(&facts), Decision::Link(user("ana@acme.test")));
        // Joined (by provisioning, say) but no master password yet.
        let joined = Candidate {
            has_keys: false,
            ..member("ana@acme.test", MembershipStatus::Accepted)
        };
        let facts = first_sign_in("ana@acme.test", Some(true), true, Some(joined));
        assert_eq!(decide(&facts), Decision::Link(user("ana@acme.test")));
    }

    #[test]
    fn an_account_with_keys_never_links_by_email() {
        // An owner at the verified domain, with xms_edov true: whoever can
        // write the mail attribute of a user in the tenant could send this.
        for status in [MembershipStatus::Invited, MembershipStatus::Accepted, MembershipStatus::Confirmed] {
            let facts = first_sign_in("owner@acme.test", Some(true), true, Some(member("owner@acme.test", status)));
            assert_eq!(decide(&facts), Decision::Refuse(Refusal::SignInToLink("owner@acme.test".into())));
        }
        // Nor an account in no organization at the verified domain.
        let mut solo = outsider("solo@acme.test");
        solo.domain_verified = true;
        let facts = first_sign_in("solo@acme.test", Some(true), true, Some(solo));
        assert_eq!(decide(&facts), Decision::Refuse(Refusal::SignInToLink("solo@acme.test".into())));
    }

    #[test]
    fn an_email_nobody_vouches_for_links_nothing() {
        // Entra's email claim isn't verified: an admin can set a user's mail to
        // anything. Unvouched, it never picks an invitation.
        let facts = first_sign_in("ceo@acme.test", None, false, Some(invited("ceo@acme.test")));
        assert_eq!(decide(&facts), Decision::Refuse(Refusal::EmailNotVouched("ceo@acme.test".into())));
    }

    #[test]
    fn xms_edov_false_wins_over_a_verified_domain() {
        let facts = first_sign_in("ana@acme.test", Some(false), true, Some(invited("ana@acme.test")));
        assert_eq!(decide(&facts), Decision::Refuse(Refusal::EmailNotVouched("ana@acme.test".into())));
    }

    #[test]
    fn a_guest_needs_xms_edov() {
        // A guest signed in at another tenant or provider: the organization's
        // verified domain says nothing about them.
        let mut facts = first_sign_in("ana@acme.test", None, true, Some(invited("ana@acme.test")));
        facts.guest = true;
        assert_eq!(decide(&facts), Decision::Refuse(Refusal::EmailNotVouched("ana@acme.test".into())));
        facts.email_edov = Some(true);
        assert_eq!(decide(&facts), Decision::Link(user("ana@acme.test")));
    }

    #[test]
    fn a_spoofed_email_never_moves_an_existing_link() {
        // Ana is linked. Her token now claims the CEO's invitation's email,
        // vouched for and at a verified domain: she still signs in as Ana.
        let facts = Facts {
            linked: Some(member("ana@acme.test", MembershipStatus::Confirmed)),
            ..first_sign_in("ceo@acme.test", Some(true), true, Some(invited("ceo@acme.test")))
        };
        assert_eq!(decide(&facts), Decision::SignIn(user("ana@acme.test")));
    }

    #[test]
    fn a_spoofed_email_cant_take_an_invitation_linked_to_someone_else() {
        let mut ceo = invited("ceo@acme.test");
        ceo.linked_elsewhere = true;
        let facts = first_sign_in("ceo@acme.test", Some(true), true, Some(ceo));
        assert_eq!(decide(&facts), Decision::Refuse(Refusal::LinkedToAnother("ceo@acme.test".into())));
    }

    #[test]
    fn a_non_member_is_refused() {
        let facts = first_sign_in("bob@other.test", Some(true), false, Some(outsider("bob@other.test")));
        assert_eq!(decide(&facts), Decision::Refuse(Refusal::NotMember("bob@other.test".into())));
        // At a verified domain, but a member of another organization.
        let mut elsewhere = outsider("bob@acme.test");
        elsewhere.domain_verified = true;
        elsewhere.other_orgs = 1;
        let facts = first_sign_in("bob@acme.test", None, true, Some(elsewhere));
        assert_eq!(decide(&facts), Decision::Refuse(Refusal::NotMember("bob@acme.test".into())));
        // Only an invitation, from another organization (no keys yet).
        let mut stub = outsider("bob@acme.test");
        stub.domain_verified = true;
        stub.has_keys = false;
        let facts = first_sign_in("bob@acme.test", None, true, Some(stub));
        assert_eq!(decide(&facts), Decision::Refuse(Refusal::NotMember("bob@acme.test".into())));
    }

    #[test]
    fn msp_staff_are_never_signed_in_by_a_client() {
        let mut tech = member("tech@msp.test", MembershipStatus::Confirmed);
        tech.msp_staff = true;
        let facts = first_sign_in("tech@msp.test", Some(true), true, Some(tech.clone()));
        assert_eq!(decide(&facts), Decision::Refuse(Refusal::MspStaff("tech@msp.test".into())));
        // Not through a link made before they joined the staff.
        let facts = Facts {
            linked: Some(tech.clone()),
            ..first_sign_in("tech@msp.test", Some(true), true, None)
        };
        assert_eq!(decide(&facts), Decision::Refuse(Refusal::MspStaff("tech@msp.test".into())));
        // Nor from a signed-in session.
        let session = SessionFacts {
            account: tech,
            microsoft_account_linked_to: None,
        };
        assert_eq!(decide_session(&session), Decision::Refuse(Refusal::MspStaff("tech@msp.test".into())));
    }

    #[test]
    fn a_link_stops_working_outside_the_rules() {
        let facts = Facts {
            linked: Some(member("ana@acme.test", MembershipStatus::Revoked)),
            ..first_sign_in("ana@acme.test", Some(true), true, None)
        };
        assert_eq!(decide(&facts), Decision::Refuse(Refusal::TurnedOff("ana@acme.test".into())));
        let mut left = outsider("ana@acme.test");
        left.domain_verified = true;
        left.other_orgs = 1;
        let facts = Facts {
            linked: Some(left),
            ..first_sign_in("ana@acme.test", Some(true), true, None)
        };
        assert_eq!(decide(&facts), Decision::Refuse(Refusal::NotMember("ana@acme.test".into())));
        let mut disabled = member("ana@acme.test", MembershipStatus::Confirmed);
        disabled.enabled = false;
        let facts = Facts {
            linked: Some(disabled),
            ..first_sign_in("ana@acme.test", Some(true), true, None)
        };
        assert_eq!(decide(&facts), Decision::Refuse(Refusal::Disabled("ana@acme.test".into())));
    }

    #[test]
    fn nobody_is_made_an_account() {
        let facts = first_sign_in("new@acme.test", Some(true), true, None);
        assert_eq!(decide(&facts), Decision::Refuse(Refusal::NoAccount("new@acme.test".into())));
        let facts = Facts {
            email: None,
            ..first_sign_in("x@acme.test", Some(true), true, None)
        };
        assert_eq!(decide(&facts), Decision::Refuse(Refusal::NoEmail));
    }

    #[test]
    fn only_the_account_with_entras_email_is_linked() {
        let facts = first_sign_in("ana@acme.test", Some(true), true, Some(invited("ceo@acme.test")));
        assert_eq!(decide(&facts), Decision::Refuse(Refusal::NoAccount("ana@acme.test".into())));
    }

    #[test]
    fn a_signed_in_member_links_their_own_account_whatever_the_email() {
        let session = SessionFacts {
            account: member("owner@acme.test", MembershipStatus::Confirmed),
            microsoft_account_linked_to: None,
        };
        assert_eq!(decide_session(&session), Decision::Link(user("owner@acme.test")));
        // Already linked to this Microsoft account: nothing to do.
        let again = SessionFacts {
            microsoft_account_linked_to: Some(user("owner@acme.test")),
            ..session.clone()
        };
        assert_eq!(decide_session(&again), Decision::SignIn(user("owner@acme.test")));
        // An account in no organization, at a verified domain.
        let mut solo = outsider("solo@acme.test");
        solo.domain_verified = true;
        let solo = SessionFacts {
            account: solo,
            microsoft_account_linked_to: None,
        };
        assert_eq!(decide_session(&solo), Decision::Link(user("solo@acme.test")));
    }

    #[test]
    fn a_signed_in_session_cant_take_a_microsoft_account_or_leave_the_rules() {
        let taken = SessionFacts {
            account: member("ana@acme.test", MembershipStatus::Confirmed),
            microsoft_account_linked_to: Some(user("ceo@acme.test")),
        };
        assert_eq!(decide_session(&taken), Decision::Refuse(Refusal::MicrosoftAccountTaken));
        let mut relinking = member("ana@acme.test", MembershipStatus::Confirmed);
        relinking.linked_elsewhere = true;
        let relinking = SessionFacts {
            account: relinking,
            microsoft_account_linked_to: None,
        };
        assert_eq!(decide_session(&relinking), Decision::Refuse(Refusal::LinkedToAnother("ana@acme.test".into())));
        let outside = SessionFacts {
            account: outsider("bob@other.test"),
            microsoft_account_linked_to: None,
        };
        assert_eq!(decide_session(&outside), Decision::Refuse(Refusal::NotMember("bob@other.test".into())));
        let off = SessionFacts {
            account: member("ana@acme.test", MembershipStatus::Revoked),
            microsoft_account_linked_to: None,
        };
        assert_eq!(decide_session(&off), Decision::Refuse(Refusal::TurnedOff("ana@acme.test".into())));
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
            Refusal::SignInToLink("a@b.test".into()),
            Refusal::MicrosoftAccountTaken,
        ];
        let mut codes = std::collections::HashSet::new();
        for r in all {
            assert!(!r.message("Acme").is_empty());
            assert!(!r.detail().is_empty());
            assert!(!r.message("Acme").contains('\u{2014}'), "no em dashes");
            assert!(codes.insert(r.code()), "{} is one reason's code", r.code());
        }
    }
}
