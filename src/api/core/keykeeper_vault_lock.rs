// Keykeeper: the "Vault lock" policy (upstream's vault timeout policy, type
// 9), which upstream leaves out of its open-source server. Its data is what
// upstream's open-source clients read, `{"type", "minutes", "action"}`, so the
// web vault and the browser extension keep to it as they are, and our apps
// keep to it through the core. "When the computer locks" may also have
// `webMinutes`: a web page can't see the computer lock, so the web vault locks
// after that many minutes without use instead (15 when it's missing). Any type
// may have `webReload: false`, which keeps members' web vaults from staying
// unlocked across a reload (keykeeper_reload_keys). This
// refuses data a client couldn't read (the extension stops on a type it
// doesn't know). See docs/core.md, "Locking by policy", in the meta repo.

use serde_json::Value;

use crate::api::EmptyResult;

use super::organizations::PolicyData;

/// The longest wait a policy can set: a day, as in the apps.
const MAX_MINUTES: u64 = 24 * 60;

/// Whether this policy's data can be kept. Off, it may have none.
pub(super) fn check(policy: &PolicyData) -> EmptyResult {
    let data = match &policy.data {
        None | Some(Value::Null) if !policy.enabled => return Ok(()),
        None | Some(Value::Null) => err!("Choose when the vault locks"),
        Some(Value::Object(data)) => data,
        Some(_) => err!("The vault lock policy's options aren't readable"),
    };
    let present = |key: &str| data.get(key).filter(|v| !v.is_null());

    // Upstream's five types. "never" and "onAppRestart" limit nothing in our
    // apps, which lock when they close, but upstream's clients read them.
    let kind = match present("type") {
        None => "custom",
        Some(Value::String(t))
            if matches!(t.as_str(), "custom" | "immediately" | "onSystemLock" | "onAppRestart" | "never") =>
        {
            t.as_str()
        }
        Some(_) => err!("The vault lock policy's type isn't one this server knows"),
    };
    let custom = kind == "custom";

    // A longest wait needs its minutes; the other types don't use them.
    match present("minutes") {
        None if custom => err!("Choose the longest wait before the vault locks"),
        None => {}
        Some(m) => match m.as_u64() {
            Some(0) if custom => err!("The longest wait before the vault locks is from 1 minute to a day"),
            Some(m) if m <= MAX_MINUTES => {}
            _ => err!("The longest wait before the vault locks is from 1 minute to a day"),
        },
    }

    // The web vault's wait, only for "when the computer locks".
    match present("webMinutes") {
        None => {}
        Some(_) if kind != "onSystemLock" => {
            err!("Only \"when the computer locks\" has a wait for the web vault")
        }
        Some(m) => match m.as_u64() {
            Some(m) if (1..=MAX_MINUTES).contains(&m) => {}
            _ => err!("The web vault's wait is from 1 minute to a day"),
        },
    }

    // Whether web vaults may stay unlocked across a reload: only a yes or no.
    match present("webReload") {
        None | Some(Value::Bool(_)) => {}
        Some(_) => err!("Staying unlocked across a reload is on or off, nothing else"),
    }

    match present("action") {
        None => {}
        Some(Value::String(a)) if a == "lock" || a == "logOut" => {}
        Some(_) => err!("The vault lock policy locks or signs out, nothing else"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn allowed(enabled: bool, data: Value) -> bool {
        check(&PolicyData {
            enabled,
            data: Some(data),
        })
        .is_ok()
    }

    #[test]
    fn keeps_what_upstreams_clients_read() {
        assert!(allowed(true, json!({ "type": "custom", "minutes": 15, "action": "lock" })));
        assert!(allowed(true, json!({ "minutes": 1 })));
        assert!(allowed(true, json!({ "type": null, "minutes": 1440, "action": "logOut" })));
        assert!(allowed(true, json!({ "type": "immediately", "action": "lock" })));
        assert!(allowed(true, json!({ "type": "onSystemLock", "minutes": null })));
        assert!(allowed(true, json!({ "type": "onSystemLock", "webMinutes": 1 })));
        assert!(allowed(true, json!({ "type": "onSystemLock", "webMinutes": 1440, "action": "logOut" })));
        assert!(allowed(true, json!({ "type": "custom", "minutes": 15, "webMinutes": null })));
        assert!(allowed(true, json!({ "type": "custom", "minutes": 15, "webReload": false })));
        assert!(allowed(true, json!({ "type": "onSystemLock", "webReload": true })));
        assert!(allowed(true, json!({ "type": "onAppRestart", "minutes": 0 })));
        assert!(allowed(true, json!({ "type": "never" })));
        // Off, it may have nothing, or whatever it had.
        assert!(allowed(false, Value::Null));
        assert!(
            check(&PolicyData {
                enabled: false,
                data: None
            })
            .is_ok()
        );
    }

    #[test]
    fn refuses_what_a_client_couldnt_read() {
        // On with nothing.
        assert!(!allowed(true, Value::Null));
        assert!(!allowed(true, json!([])));
        assert!(!allowed(true, json!("15")));
        // A type no client knows, or not a string.
        assert!(!allowed(true, json!({ "type": "onIdle", "minutes": 5 })));
        assert!(!allowed(true, json!({ "type": 1, "minutes": 5 })));
        // A longest wait without minutes, or outside a minute to a day.
        assert!(!allowed(true, json!({ "type": "custom" })));
        assert!(!allowed(true, json!({})));
        assert!(!allowed(true, json!({ "minutes": 0 })));
        assert!(!allowed(true, json!({ "minutes": 1441 })));
        assert!(!allowed(true, json!({ "minutes": -5 })));
        assert!(!allowed(true, json!({ "minutes": 2.5 })));
        assert!(!allowed(true, json!({ "minutes": "15" })));
        assert!(!allowed(true, json!({ "type": "immediately", "minutes": 100_000 })));
        // An action other than locking or signing out.
        assert!(!allowed(true, json!({ "minutes": 15, "action": "delete" })));
        assert!(!allowed(true, json!({ "minutes": 15, "action": true })));
        // The web vault's wait: whole minutes, from 1 to a day, and only
        // for "when the computer locks".
        for web in [json!(0), json!(1441), json!(-1), json!(2.5), json!("15"), json!(true)] {
            assert!(!allowed(true, json!({ "type": "onSystemLock", "webMinutes": web })), "{web}");
        }
        assert!(!allowed(true, json!({ "type": "custom", "minutes": 15, "webMinutes": 5 })));
        assert!(!allowed(true, json!({ "minutes": 15, "webMinutes": 5 })));
        assert!(!allowed(true, json!({ "type": "immediately", "webMinutes": 5 })));
        // Staying unlocked across a reload: true or false only.
        for reload in [json!("false"), json!(0), json!({})] {
            assert!(!allowed(true, json!({ "minutes": 15, "webReload": reload })), "{reload}");
        }
        // Off doesn't excuse unreadable data that's there.
        assert!(!allowed(false, json!({ "type": "onIdle" })));
    }
}
