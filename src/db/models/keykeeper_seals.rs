// Keykeeper: what lets an app confirm a join on its own without trusting the
// server. Owners' and admins' apps seal email invitations, MSP staff's places
// in clients, and joining settings with a key made from the organization's
// key, and the install command carries a secret the server only ever holds
// encrypted. The server can't read or make any of these; it keeps them for
// the apps and checks only that each looks like what it should be.
// Invitation and staff seals end and carry a nonce (version 2), and the
// server deletes them once the person they vouch for is confirmed, so each is
// used once. Joining seals say where the setting comes from (version 2): the
// organization's own, or a default it follows. See DESIGN.md, "Joins a hacked
// server can't forge".

use diesel::prelude::*;

use crate::{
    api::EmptyResult,
    db::{
        DbConn,
        keykeeper_schema::{join_seals, joining_seals},
    },
    error::MapResult,
};

use super::OrganizationId;

/// A seal or proof: an HMAC-SHA256, standard base64.
pub fn valid_seal(seal: &str) -> bool {
    seal.len() == 44
        && seal.ends_with('=')
        && data_encoding::BASE64.decode(seal.as_bytes()).is_ok_and(|bytes| bytes.len() == 32)
}

/// An invitation's or staff member's seal, version 2: `v2.<expires>.<nonce>.<mac>`,
/// its end in Unix seconds, a 16-byte nonce, and the HMAC-SHA256, both in
/// base64url without padding. The apps check the end and the MAC; the server
/// only checks the form, and that it hasn't already ended.
pub fn valid_expiring_seal(seal: &str, now: i64) -> bool {
    let parts: Vec<&str> = seal.split('.').collect();
    let [version, expires, nonce, mac] = parts.as_slice() else {
        return false;
    };
    let decodes_to = |text: &str, len: usize| {
        data_encoding::BASE64URL_NOPAD.decode(text.as_bytes()).is_ok_and(|bytes| bytes.len() == len)
    };
    *version == "v2"
        && (1..=12).contains(&expires.len())
        && expires.bytes().all(|b| b.is_ascii_digit())
        && expires.parse::<i64>().is_ok_and(|end| end > now)
        && nonce.len() == 22
        && decodes_to(nonce, 16)
        && mac.len() == 43
        && decodes_to(mac, 32)
}

/// Where an organization's joining setting comes from, as its joining seal
/// says: its own setting, or a default it follows (its MSP's, or the
/// server's outside an MSP).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoiningSealSource {
    Own,
    Default,
}

/// A joining seal, version 2: `v2.<source>.<mac>`, the source `own` or
/// `default` and the HMAC-SHA256 in base64url without padding, with the
/// source inside the MAC. The apps check the MAC; the server only checks the
/// form, and reads the source. Version 1, which said nothing of where the
/// setting comes from, isn't taken.
pub fn joining_seal_source(seal: &str) -> Option<JoiningSealSource> {
    let parts: Vec<&str> = seal.split('.').collect();
    let ["v2", source, mac] = parts.as_slice() else {
        return None;
    };
    let source = match *source {
        "own" => JoiningSealSource::Own,
        "default" => JoiningSealSource::Default,
        _ => return None,
    };
    (mac.len() == 43 && data_encoding::BASE64URL_NOPAD.decode(mac.as_bytes()).is_ok_and(|bytes| bytes.len() == 32))
        .then_some(source)
}

/// The install command's join secret, encrypted with the organization's key
/// as upstream encrypts with symmetric keys: `2.<iv>|<data>|<mac>`.
pub fn valid_encrypted_secret(secret: &str) -> bool {
    let Some(parts) = secret.strip_prefix("2.") else {
        return false;
    };
    let parts: Vec<&str> = parts.split('|').collect();
    secret.len() <= 512
        && parts.len() == 3
        && parts.iter().all(|p| !p.is_empty() && data_encoding::BASE64.decode(p.as_bytes()).is_ok())
}

/// What a seal vouches for: an email invitation, or an MSP staff member's
/// place in a client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealKind {
    Invite,
    Staff,
}

impl SealKind {
    fn as_str(self) -> &'static str {
        match self {
            SealKind::Invite => "invite",
            SealKind::Staff => "staff",
        }
    }
}

#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = join_seals)]
#[diesel(primary_key(org_uuid, email, kind))]
pub struct JoinSeal {
    pub org_uuid: OrganizationId,
    pub email: String,
    pub kind: String,
    pub seal: String,
}

impl JoinSeal {
    /// Keeps a seal for someone, by their lowercased email, replacing any
    /// earlier one of the same kind. Without a seal, removes the earlier one,
    /// so a change made without sealing never keeps an old seal's word.
    pub async fn set(
        org_uuid: &OrganizationId,
        email: &str,
        kind: SealKind,
        seal: Option<&str>,
        conn: &DbConn,
    ) -> EmptyResult {
        let row = seal.map(|seal| Self {
            org_uuid: org_uuid.clone(),
            email: email.to_lowercase(),
            kind: kind.as_str().to_owned(),
            seal: seal.to_owned(),
        });
        let org = org_uuid.clone();
        let email = email.to_lowercase();
        conn.run(move |conn| {
            conn.transaction(|conn| {
                diesel::delete(
                    join_seals::table
                        .filter(join_seals::org_uuid.eq(&org))
                        .filter(join_seals::email.eq(&email))
                        .filter(join_seals::kind.eq(kind.as_str())),
                )
                .execute(conn)?;
                if let Some(row) = row {
                    diesel::insert_into(join_seals::table).values(&row).execute(conn)?;
                }
                Ok::<(), diesel::result::Error>(())
            })
            .map_res("Error saving a join seal")
        })
        .await
    }

    pub async fn find(org_uuid: &OrganizationId, email: &str, kind: SealKind, conn: &DbConn) -> Option<String> {
        let org = org_uuid.clone();
        let email = email.to_lowercase();
        conn.run(move |conn| {
            join_seals::table
                .filter(join_seals::org_uuid.eq(org))
                .filter(join_seals::email.eq(email))
                .filter(join_seals::kind.eq(kind.as_str()))
                .select(join_seals::seal)
                .first::<String>(conn)
                .ok()
        })
        .await
    }

    /// Removes the seals that vouched for someone in an organization once
    /// they're confirmed there: each seal is used once. An app that let them
    /// in also remembers the seal, so a server that keeps it can't use it again.
    pub async fn used_up(org_uuid: &OrganizationId, email: &str, conn: &DbConn) -> EmptyResult {
        let org = org_uuid.clone();
        let email = email.to_lowercase();
        conn.run(move |conn| {
            diesel::delete(join_seals::table.filter(join_seals::org_uuid.eq(org)).filter(join_seals::email.eq(email)))
                .execute(conn)
                .map(|_| ())
                .map_res("Error removing used join seals")
        })
        .await
    }

    /// Removes someone's staff seals in these organizations, when they leave
    /// an MSP's staff or stop reaching some of its clients.
    pub async fn delete_staff(orgs: Vec<OrganizationId>, email: &str, conn: &DbConn) -> EmptyResult {
        let email = email.to_lowercase();
        conn.run(move |conn| {
            diesel::delete(
                join_seals::table
                    .filter(join_seals::org_uuid.eq_any(orgs))
                    .filter(join_seals::email.eq(email))
                    .filter(join_seals::kind.eq(SealKind::Staff.as_str())),
            )
            .execute(conn)
            .map(|_| ())
            .map_res("Error removing staff seals")
        })
        .await
    }

    /// Removes every seal of one kind in an organization, such as all staff
    /// seals when a client removes its MSP. Returns how many went.
    pub async fn delete_kind(org_uuid: &OrganizationId, kind: SealKind, conn: &DbConn) -> Result<usize, crate::Error> {
        let org = org_uuid.clone();
        conn.run(move |conn| {
            diesel::delete(
                join_seals::table.filter(join_seals::org_uuid.eq(org)).filter(join_seals::kind.eq(kind.as_str())),
            )
            .execute(conn)
            .map_res("Error removing seals")
        })
        .await
    }
}

#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = joining_seals)]
#[diesel(primary_key(org_uuid))]
pub struct JoiningSeal {
    pub org_uuid: OrganizationId,
    pub seal: String,
}

impl JoiningSeal {
    /// Keeps the seal over an organization's joining setting and domains, or
    /// removes it, so a setting changed without sealing means approval.
    pub async fn set(org_uuid: &OrganizationId, seal: Option<&str>, conn: &DbConn) -> EmptyResult {
        let row = seal.map(|seal| Self {
            org_uuid: org_uuid.clone(),
            seal: seal.to_owned(),
        });
        let org = org_uuid.clone();
        conn.run(move |conn| {
            conn.transaction(|conn| {
                diesel::delete(joining_seals::table.filter(joining_seals::org_uuid.eq(&org))).execute(conn)?;
                if let Some(row) = row {
                    diesel::insert_into(joining_seals::table).values(&row).execute(conn)?;
                }
                Ok::<(), diesel::result::Error>(())
            })
            .map_res("Error saving a joining seal")
        })
        .await
    }

    pub async fn find(org_uuid: &OrganizationId, conn: &DbConn) -> Option<String> {
        let org = org_uuid.clone();
        conn.run(move |conn| {
            joining_seals::table
                .filter(joining_seals::org_uuid.eq(org))
                .select(joining_seals::seal)
                .first::<String>(conn)
                .ok()
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seals_are_hmacs_in_base64() {
        assert!(valid_seal("Lzxr28jrCFbS8FDbf7uxBHX4MyVhlz+g1h1WL/9m2SE="));
        assert!(!valid_seal("Lzxr28jrCFbS8FDbf7uxBHX4MyVhlz+g1h1WL/9m2SE"));
        assert!(!valid_seal("Lzxr28jrCFbS8FDbf7uxBHX4MyVhlz-g1h1WL_9m2SE="));
        assert!(!valid_seal(""));
        // 44 characters, but 31 bytes.
        assert!(!valid_seal(&format!("{}==", "A".repeat(42))));
    }

    #[test]
    fn invitation_and_staff_seals_end_and_carry_a_nonce() {
        // docs/vectors/joins-v2.json in the meta repo.
        let seal = "v2.1794268800.MDEyMzQ1Njc4OTo7PD0-Pw.8fzOYFVJ_0dbzgLkRxUhcka895B600chQht67HG55Kk";
        let made = 1_793_059_200;
        assert!(valid_expiring_seal(seal, made));
        assert!(valid_expiring_seal(seal, 1_794_268_799));
        // Ended.
        assert!(!valid_expiring_seal(seal, 1_794_268_800));
        // Version 1 seals never end, and aren't taken for these any more.
        assert!(!valid_expiring_seal("Lzxr28jrCFbS8FDbf7uxBHX4MyVhlz+g1h1WL/9m2SE=", made));
        for bad in [
            "v1.1794268800.MDEyMzQ1Njc4OTo7PD0-Pw.8fzOYFVJ_0dbzgLkRxUhcka895B600chQht67HG55Kk",
            "v2.17942688x0.MDEyMzQ1Njc4OTo7PD0-Pw.8fzOYFVJ_0dbzgLkRxUhcka895B600chQht67HG55Kk",
            "v2.-1.MDEyMzQ1Njc4OTo7PD0-Pw.8fzOYFVJ_0dbzgLkRxUhcka895B600chQht67HG55Kk",
            "v2.1794268800.MDEyMzQ1Njc4OTo7PD0+Pw.8fzOYFVJ_0dbzgLkRxUhcka895B600chQht67HG55Kk",
            "v2.1794268800.MDEyMzQ1Njc4OTo7PD0-Pw.8fzOYFVJ_0dbzgLkRxUhcka895B600chQht67HG55K",
            "v2.1794268800.MDEyMzQ1Njc4OTo7PD0-Pw.8fzOYFVJ_0dbzgLkRxUhcka895B600chQht67HG55Kk.x",
            "v2.1794268800.MDEyMzQ1Njc4OTo7PD0-Pw",
            "",
        ] {
            assert!(!valid_expiring_seal(bad, made), "{bad}");
        }
    }

    /// docs/vectors/joining-v2.json in the meta repo (a copy is in vectors/
    /// here), made with Node's crypto: the server takes version 2 joining
    /// seals and reads their source, and the vectors' MACs hold, checked here
    /// with ring as the apps check them, so the vectors are what they say.
    #[test]
    fn joining_seals_say_where_the_setting_comes_from() {
        let v: serde_json::Value = serde_json::from_str(include_str!("vectors/joining-v2.json")).unwrap();
        let join_key = data_encoding::BASE64.decode(v["joinKey"].as_str().unwrap().as_bytes()).unwrap();
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &join_key);
        let org = v["inputs"]["organizationId"].as_str().unwrap();
        let source_of = |name: &str| match name {
            "own" => JoiningSealSource::Own,
            "default" => JoiningSealSource::Default,
            other => panic!("{other}"),
        };
        // What an app checks: the seal's form, the source it asks for (if
        // any), and the MAC over the setting, its domains, and the source.
        let vouches = |seal: &str, auto_confirm: bool, domains: &[&str], asked: Option<&str>| {
            let Some(source) = joining_seal_source(seal) else {
                return false;
            };
            if asked.is_some_and(|a| source_of(a) != source) {
                return false;
            }
            let mut sorted = domains.to_vec();
            sorted.sort_unstable();
            let source = if source == JoiningSealSource::Own {
                "own"
            } else {
                "default"
            };
            let data = [
                "passbundle joining v2",
                org,
                if auto_confirm {
                    "1"
                } else {
                    "0"
                },
                &sorted.join(","),
                source,
            ]
            .join("\0");
            let mac = data_encoding::BASE64URL_NOPAD.decode(seal.rsplit('.').next().unwrap().as_bytes()).unwrap();
            ring::hmac::verify(&key, data.as_bytes(), &mac).is_ok()
        };
        let domains_of = |c: &serde_json::Value| -> Vec<String> {
            c["domains"].as_array().unwrap().iter().map(|d| d.as_str().unwrap().to_owned()).collect()
        };
        for s in v["seals"].as_array().unwrap() {
            let seal = s["seal"].as_str().unwrap();
            assert_eq!(joining_seal_source(seal), Some(source_of(s["source"].as_str().unwrap())), "{seal}");
            let domains = domains_of(s);
            let domains: Vec<&str> = domains.iter().map(String::as_str).collect();
            assert!(vouches(seal, s["autoConfirm"].as_bool().unwrap(), &domains, None), "{seal}");
        }
        for c in v["checks"].as_array().unwrap() {
            let domains = domains_of(c);
            let domains: Vec<&str> = domains.iter().map(String::as_str).collect();
            assert_eq!(
                vouches(
                    c["seal"].as_str().unwrap(),
                    c["autoConfirm"].as_bool().unwrap(),
                    &domains,
                    c["source"].as_str()
                ),
                c["vouches"].as_bool().unwrap(),
                "{}",
                c["why"]
            );
        }
        // Version 1, and forms that aren't a seal, aren't taken.
        for bad in [
            "Lzxr28jrCFbS8FDbf7uxBHX4MyVhlz+g1h1WL/9m2SE=",
            "v1.own.OKFnhDXt8AwYQaKfXtY-rRA21dE1T4S1ysMUVa-bYfY",
            "v2.msp.OKFnhDXt8AwYQaKfXtY-rRA21dE1T4S1ysMUVa-bYfY",
            "v2.own.OKFnhDXt8AwYQaKfXtY-rRA21dE1T4S1ysMUVa-bYf",
            "v2.own.OKFnhDXt8AwYQaKfXtY+rRA21dE1T4S1ysMUVa-bYfY",
            "v2.own.OKFnhDXt8AwYQaKfXtY-rRA21dE1T4S1ysMUVa-bYfY.x",
            "v2.own",
            "",
        ] {
            assert_eq!(joining_seal_source(bad), None, "{bad}");
        }
    }

    #[test]
    fn secrets_are_encrypted_strings() {
        assert!(valid_encrypted_secret("2.AAECAw==|BAUGBw==|CAkKCw=="));
        assert!(!valid_encrypted_secret("0.AAECAw==|BAUGBw=="));
        assert!(!valid_encrypted_secret("2.AAECAw==|BAUGBw=="));
        assert!(!valid_encrypted_secret("2.AAECAw==||CAkKCw=="));
        assert!(!valid_encrypted_secret("2.not base64|BAUGBw==|CAkKCw=="));
        assert!(!valid_encrypted_secret(&format!("2.{}|BAUGBw==|CAkKCw==", "A".repeat(600))));
    }
}
