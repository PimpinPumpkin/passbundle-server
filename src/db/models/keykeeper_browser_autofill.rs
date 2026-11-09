// Keykeeper: whether an organization turns off the browsers' own card and
// address autofill for its people (DESIGN.md, "Addresses and cards", in the
// meta repo). Left as is by default: an organization without a row doesn't
// touch them. Its owners, admins, and its MSP's admins change it, and an MSP
// can turn them off for its clients as a default policy
// (keykeeper_msp_policies). The install command carries it to the browsers'
// policies, and the extension sets the same switches in work profiles.

use diesel::prelude::*;

use crate::{
    api::{ApiResult, EmptyResult},
    db::{DbConn, keykeeper_schema::org_browser_autofill},
    error::MapResult,
};

use super::OrganizationId;

/// What the organization does with the browsers' own card and address autofill.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrowserAutofillMode {
    /// PassBundle leaves them as they are.
    Unchanged,
    /// Off in Chrome, Edge, and Firefox, wherever PassBundle reaches them.
    Off,
    /// Off, and each person is offered, once, to bring their saved cards and
    /// addresses into PassBundle.
    OffAndImport,
}

impl BrowserAutofillMode {
    /// Its name in the API, in the sync, and in the database.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unchanged => "unchanged",
            Self::Off => "off",
            Self::OffAndImport => "offAndImport",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "unchanged" => Some(Self::Unchanged),
            "off" => Some(Self::Off),
            "offAndImport" => Some(Self::OffAndImport),
            _ => None,
        }
    }

    /// Whether the browsers' card and address autofill are turned off.
    pub fn is_off(self) -> bool {
        self != Self::Unchanged
    }
}

#[derive(Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = org_browser_autofill)]
#[diesel(primary_key(org_uuid))]
pub struct OrgBrowserAutofill {
    pub org_uuid: OrganizationId,
    pub mode: String,
}

impl OrgBrowserAutofill {
    /// The organization's setting. Without a row, or with a value this server
    /// doesn't know, it leaves them as they are.
    pub async fn mode(org_uuid: &OrganizationId, conn: &DbConn) -> ApiResult<BrowserAutofillMode> {
        let org_uuid = org_uuid.clone();
        conn.run(move |conn| {
            org_browser_autofill::table
                .filter(org_browser_autofill::org_uuid.eq(org_uuid))
                .select(org_browser_autofill::mode)
                .first::<String>(conn)
                .optional()
                .map(|mode| {
                    mode.as_deref().and_then(BrowserAutofillMode::parse).unwrap_or(BrowserAutofillMode::Unchanged)
                })
                .map_res("Error reading an organization's browser autofill setting")
        })
        .await
    }

    /// Saves the setting. Leaving them as they are keeps no row.
    pub async fn set(org_uuid: &OrganizationId, mode: BrowserAutofillMode, conn: &DbConn) -> EmptyResult {
        let row = Self {
            org_uuid: org_uuid.clone(),
            mode: mode.as_str().to_owned(),
        };
        conn.run(move |conn| {
            diesel::delete(org_browser_autofill::table.filter(org_browser_autofill::org_uuid.eq(&row.org_uuid)))
                .execute(conn)
                .map_res("Error saving an organization's browser autofill setting")
                .map(|_: usize| ())?;
            if mode == BrowserAutofillMode::Unchanged {
                return Ok(());
            }
            diesel::insert_into(org_browser_autofill::table)
                .values(&row)
                .execute(conn)
                .map_res("Error saving an organization's browser autofill setting")
        })
        .await
    }
}
