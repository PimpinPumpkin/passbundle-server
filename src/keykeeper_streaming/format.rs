// Keykeeper: how a streamed event is written for each kind of destination.
// Every destination gets the same event (see
// db::models::keykeeper_event_streaming::event_json): webhooks as JSON,
// signed the Standard Webhooks way; syslog as RFC 5424 messages framed by
// octet counting for TLS (RFC 5425), with a JSON or CEF message; Sentinel as
// rows for its Logs Ingestion API. See docs/event-streaming.md in the meta
// repo for every field.

use std::fmt::Write as _;

use ring::hmac;
use serde_json::{Map, Value, json};

/// The header a webhook's signature goes in, and the others it signs.
pub const HEADER_ID: &str = "webhook-id";
pub const HEADER_TIMESTAMP: &str = "webhook-timestamp";
pub const HEADER_SIGNATURE: &str = "webhook-signature";

/// A new signing secret in the Standard Webhooks format: whsec_ and 32
/// random bytes in base64.
pub fn new_signing_secret() -> String {
    format!("whsec_{}", data_encoding::BASE64.encode(&super::secrets::random::<32>()))
}

/// The key bytes of a signing secret.
fn signing_key(secret: &str) -> Option<Vec<u8>> {
    data_encoding::BASE64.decode(secret.strip_prefix("whsec_")?.as_bytes()).ok()
}

/// The webhook-signature header: HMAC-SHA256 over "<id>.<timestamp>.<body>"
/// with the secret's key bytes, base64, after "v1,".
pub fn sign(secret: &str, id: &str, timestamp: i64, body: &[u8]) -> Option<String> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, &signing_key(secret)?);
    let mut signed = format!("{id}.{timestamp}.").into_bytes();
    signed.extend_from_slice(body);
    Some(format!("v1,{}", data_encoding::BASE64.encode(hmac::sign(&key, &signed).as_ref())))
}

/// Syslog message formats.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageFormat {
    Json,
    Cef,
}

impl MessageFormat {
    pub fn from_str(text: &str) -> Option<Self> {
        match text {
            "json" => Some(Self::Json),
            "cef" => Some(Self::Cef),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Cef => "cef",
        }
    }
}

fn text<'a>(event: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut v = event;
    for p in path {
        v = v.get(p)?;
    }
    v.as_str()
}

/// Syslog severity (RFC 5424) for an event's severity.
fn syslog_severity(event: &Value) -> u8 {
    match text(event, &["severity"]) {
        Some("high") => 4,   // warning
        Some("medium") => 5, // notice
        _ => 6,              // informational
    }
}

/// CEF severity, 0 to 10.
fn cef_severity(event: &Value) -> u8 {
    match text(event, &["severity"]) {
        Some("high") => 7,
        Some("medium") => 5,
        _ => 3,
    }
}

/// Facility 13, "log audit".
const FACILITY: u8 = 13;

/// One RFC 5424 message: PRI, version, time, host, app, no process id, the
/// event type as MSGID, no structured data, then the message. No BOM, so
/// receivers that parse the message as JSON can.
pub fn syslog_message(event: &Value, format: MessageFormat, hostname: &str, version: &str) -> String {
    let pri = u16::from(FACILITY) * 8 + u16::from(syslog_severity(event));
    let time = text(event, &["time"]).unwrap_or("-");
    let msgid = event.get("type").and_then(Value::as_i64).map_or_else(|| "-".to_owned(), |t| t.to_string());
    let host = printable(hostname, 255);
    let message = match format {
        MessageFormat::Json => event.to_string(),
        MessageFormat::Cef => cef(event, version),
    };
    format!("<{pri}>1 {time} {host} passbundle - {msgid} - {message}")
}

/// RFC 5425 framing: the message's length in bytes, a space, the message.
pub fn frame(message: &str) -> Vec<u8> {
    let mut out = format!("{} ", message.len()).into_bytes();
    out.extend_from_slice(message.as_bytes());
    out
}

/// A header field (RFC 5424 HOSTNAME): printable US-ASCII, no spaces.
fn printable(text: &str, max: usize) -> String {
    let s: String = text.chars().filter(char::is_ascii_graphic).take(max).collect();
    if s.is_empty() {
        "-".into()
    } else {
        s
    }
}

fn cef_header(text: &str) -> String {
    text.replace('\\', "\\\\").replace('|', "\\|").replace(['\r', '\n'], " ")
}

fn cef_value(text: &str) -> String {
    text.replace('\\', "\\\\").replace('=', "\\=").replace('\n', "\\n").replace('\r', "\\r")
}

/// A CEF (version 0) message: vendor and product PassBundle, the event type
/// as the signature id, the event's name, a severity, and an extension with
/// the standard keys where one fits and labeled custom strings for the rest.
pub fn cef(event: &Value, version: &str) -> String {
    let signature = event.get("type").and_then(Value::as_i64).unwrap_or(0);
    let name = text(event, &["name"]).unwrap_or("Event");
    let mut ext: Vec<(&str, String)> = Vec::new();
    if let Some(ms) =
        text(event, &["time"]).and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok()).map(|t| t.timestamp_millis())
    {
        ext.push(("rt", ms.to_string()));
    }
    let mut push = |key: &'static str, value: Option<&str>| {
        if let Some(v) = value.filter(|v| !v.is_empty()) {
            ext.push((key, v.to_owned()));
        }
    };
    push("externalId", text(event, &["id"]));
    push("cat", text(event, &["category"]));
    push("act", text(event, &["name"]));
    push("suid", text(event, &["actor", "id"]));
    push("suser", text(event, &["actor", "email"]));
    push("src", text(event, &["ip"]));
    push("requestClientApplication", text(event, &["device", "name"]));
    push("duid", text(event, &["target", "userId"]));
    push("duser", text(event, &["target", "email"]));
    let mut ext: Vec<(String, String)> = ext.into_iter().map(|(k, v)| (k.to_owned(), v)).collect();
    let custom = [
        ("organizationId", text(event, &["organization", "id"])),
        ("organizationName", text(event, &["organization", "name"])),
        ("targetType", text(event, &["target", "type"])),
        ("targetId", text(event, &["target", "id"])),
        ("mspId", text(event, &["msp", "id"])),
        ("mspName", text(event, &["msp", "name"])),
    ];
    for (n, (label, value)) in custom.into_iter().enumerate() {
        if let Some(value) = value.filter(|v| !v.is_empty()) {
            ext.push((format!("cs{}", n + 1), value.to_owned()));
            ext.push((format!("cs{}Label", n + 1), label.to_owned()));
        }
    }
    if let Some(device) = event.get("device").and_then(|d| d.get("type")).and_then(Value::as_i64) {
        ext.push(("cn1".into(), device.to_string()));
        ext.push(("cn1Label".into(), "deviceType".into()));
    }
    if actor_is_system(event) {
        ext.push(("suser".into(), "system".into()));
    }
    let mut out = format!(
        "CEF:0|PassBundle|PassBundle|{}|{}|{}|{}|",
        cef_header(version),
        signature,
        cef_header(name),
        cef_severity(event)
    );
    for (i, (k, v)) in ext.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let _ = write!(out, "{k}={}", cef_value(v));
    }
    out
}

fn actor_is_system(event: &Value) -> bool {
    text(event, &["actor", "type"]) == Some("system")
}

/// A row for Sentinel's Logs Ingestion API: the event's fields at the top
/// level with TimeGenerated, as a custom table expects. Nested parts become
/// flat columns so a DCR can pass them straight through.
pub fn sentinel_row(event: &Value) -> Value {
    let mut row = Map::new();
    row.insert("TimeGenerated".into(), event.get("time").cloned().unwrap_or(Value::Null));
    let flat = [
        ("EventId", &["id"][..]),
        ("EventName", &["name"]),
        ("Category", &["category"]),
        ("Severity", &["severity"]),
        ("OrganizationId", &["organization", "id"]),
        ("OrganizationName", &["organization", "name"]),
        ("ActorType", &["actor", "type"]),
        ("ActorId", &["actor", "id"]),
        ("ActorEmail", &["actor", "email"]),
        ("TargetType", &["target", "type"]),
        ("TargetId", &["target", "id"]),
        ("TargetUserId", &["target", "userId"]),
        ("TargetEmail", &["target", "email"]),
        ("IpAddress", &["ip"]),
        ("DeviceName", &["device", "name"]),
        ("MspId", &["msp", "id"]),
        ("MspName", &["msp", "name"]),
        ("Action", &["action"]),
        ("Detail", &["detail"]),
    ];
    for (column, path) in flat {
        row.insert(column.into(), text(event, path).map_or(Value::Null, |s| json!(s)));
    }
    row.insert("EventType".into(), event.get("type").cloned().unwrap_or(Value::Null));
    row.insert("DeviceType".into(), event.get("device").and_then(|d| d.get("type")).cloned().unwrap_or(Value::Null));
    Value::Object(row)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Value {
        json!({
            "id": "0f1c2e3d-0000-4000-8000-000000000001",
            "time": "2026-10-23T18:04:05.123456Z",
            "type": 1503,
            "name": "Removed a member",
            "category": "member",
            "severity": "medium",
            "organization": { "id": "org-1", "name": "Contoso | West=Coast" },
            "actor": { "type": "user", "id": "user-1", "email": "admin@contoso.example" },
            "target": { "type": "member", "id": "member-9", "userId": "user-9", "email": "left@contoso.example" },
            "device": { "type": 9, "name": "Chrome" },
            "ip": "203.0.113.7",
        })
    }

    #[test]
    fn webhook_signatures_follow_standard_webhooks() {
        // The example from the Standard Webhooks spec's reference tests.
        let secret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
        let body = br#"{"test": 2432232314}"#;
        let sig = sign(secret, "msg_p5jXN8AQM9LWM0D4loKWxJek", 1_614_265_330, body).unwrap();
        assert_eq!(sig, "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=");
        // A changed body, id, or time gives a different signature.
        assert_ne!(sign(secret, "msg_p5jXN8AQM9LWM0D4loKWxJek", 1_614_265_331, body).unwrap(), sig);
        assert_ne!(sign(secret, "msg_other", 1_614_265_330, body).unwrap(), sig);
        assert!(sign("not a secret", "id", 1, body).is_none());
        let fresh = new_signing_secret();
        assert!(fresh.starts_with("whsec_"));
        assert_eq!(signing_key(&fresh).unwrap().len(), 32);
    }

    #[test]
    fn syslog_messages_are_rfc5424_with_octet_counting() {
        let msg = syslog_message(&sample(), MessageFormat::Json, "vault.passbundle.com", "1.0");
        // Facility 13 (log audit), severity 5 (notice): 13 * 8 + 5 = 109.
        assert!(
            msg.starts_with("<109>1 2026-10-23T18:04:05.123456Z vault.passbundle.com passbundle - 1503 - {"),
            "{msg}"
        );
        let json_part = msg.split_once(" - 1503 - ").unwrap().1;
        assert_eq!(serde_json::from_str::<Value>(json_part).unwrap(), sample());
        let framed = frame(&msg);
        let (len, rest) = std::str::from_utf8(&framed).unwrap().split_once(' ').unwrap();
        assert_eq!(len.parse::<usize>().unwrap(), rest.len());
        // Length in bytes, not characters.
        assert_eq!(frame("é"), b"2 \xc3\xa9".to_vec());
        let high = syslog_message(&json!({"severity": "high", "type": 1005}), MessageFormat::Json, "h", "1");
        assert!(high.starts_with("<108>1 - h passbundle - 1005 - "), "{high}");
    }

    #[test]
    fn cef_escapes_its_separators() {
        let line = cef(&sample(), "2026.10.0");
        assert!(
            line.starts_with("CEF:0|PassBundle|PassBundle|2026.10.0|1503|Removed a member|5|rt=1792778645123 "),
            "{line}"
        );
        assert!(line.contains("externalId=0f1c2e3d-0000-4000-8000-000000000001"));
        assert!(line.contains("suser=admin@contoso.example"));
        assert!(line.contains("src=203.0.113.7"));
        assert!(line.contains("duser=left@contoso.example"));
        assert!(line.contains(r"cs2=Contoso | West\=Coast cs2Label=organizationName"), "{line}");
        assert!(line.contains("cs3=member cs3Label=targetType"));
        assert!(line.contains("cn1=9 cn1Label=deviceType"));
        let tricky = cef(&json!({"type": 1, "name": "a|b\\c", "detail": "x"}), "1|2");
        assert!(tricky.starts_with(r"CEF:0|PassBundle|PassBundle|1\|2|1|a\|b\\c|3|"), "{tricky}");
        let newline = cef(&json!({"type": 1, "name": "n", "organization": {"name": "a\nb=c"}}), "1");
        assert!(newline.contains(r"cs2=a\nb\=c"), "{newline}");
        let system = cef(&json!({"type": 1500, "name": "n", "actor": {"type": "system"}}), "1");
        assert!(system.contains("suser=system"));
    }

    #[test]
    fn sentinel_rows_are_flat_with_time_generated() {
        let row = sentinel_row(&sample());
        assert_eq!(row["TimeGenerated"], "2026-10-23T18:04:05.123456Z");
        assert_eq!(row["EventType"], 1503);
        assert_eq!(row["ActorEmail"], "admin@contoso.example");
        assert_eq!(row["TargetEmail"], "left@contoso.example");
        assert_eq!(row["DeviceType"], 9);
        assert_eq!(row["MspName"], Value::Null);
        assert!(row.as_object().unwrap().values().all(|v| !v.is_object()));
    }
}
