// Keykeeper: SCIM PATCH (RFC 7644, section 3.5.2) applied to a resource's
// JSON, in the shapes Microsoft Entra ID sends, with and without its
// `aadOptscim062020` flag: "Add", "Replace", and "Remove" in any case; paths
// such as `name.familyName`, `emails[type eq "work"].value`, and extension
// attributes (`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:
// employeeNumber`); a replace without a path whose value object has those
// paths as keys; and `active` as true or false or "True" or "False".

use serde_json::{Map, Value};

use super::filter::{self, AttrPath, ENTERPRISE_USER_SCHEMA, Filter, Literal, Op};

/// The most operations one request may carry.
pub const MAX_OPERATIONS: usize = 1000;

pub const PATCH_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

/// Why a request was refused, as a SCIM error's `scimType` and `detail`.
#[derive(Debug, PartialEq, Eq)]
pub struct Refusal {
    pub scim_type: &'static str,
    pub detail: String,
}

pub fn refusal(scim_type: &'static str, detail: impl Into<String>) -> Refusal {
    Refusal {
        scim_type,
        detail: detail.into(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Add,
    Replace,
    Remove,
}

/// `[schema:]attr[.sub]` or `attr[filter][.sub]`.
#[derive(Debug, Clone, PartialEq)]
pub struct PatchPath {
    pub attr: AttrPath,
    pub filter: Option<Filter>,
    /// After a filter: the sub-attribute of the matching values.
    pub sub: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Operation {
    pub kind: Kind,
    pub path: Option<PatchPath>,
    pub value: Option<Value>,
}

/// Parses a PATCH path.
pub fn parse_path(text: &str) -> Result<PatchPath, Refusal> {
    let invalid = |why: String| refusal("invalidPath", why);
    let text = text.trim();
    let Some(open) = text.find('[') else {
        return Ok(PatchPath {
            attr: filter::parse_attr_path(text).map_err(invalid)?,
            filter: None,
            sub: None,
        });
    };
    // The matching bracket, skipping quoted values.
    let mut close = None;
    let mut quoted = false;
    let mut escaped = false;
    for (i, c) in text[open + 1..].char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ']' if !quoted => {
                close = Some(open + 1 + i);
                break;
            }
            _ => {}
        }
    }
    let Some(close) = close else {
        return Err(invalid(format!("{text} has a bracket that isn't closed")));
    };
    let attr = filter::parse_attr_path(&text[..open]).map_err(invalid)?;
    if attr.sub.is_some() {
        return Err(invalid(format!("{text} filters a sub-attribute")));
    }
    let inner = filter::parse(&text[open + 1..close]).map_err(|e| refusal("invalidFilter", e))?;
    let rest = &text[close + 1..];
    let sub = if rest.is_empty() {
        None
    } else {
        match rest.strip_prefix('.') {
            Some(sub) if filter::parse_attr_path(sub).is_ok_and(|p| p.schema.is_none() && p.sub.is_none()) => {
                Some(sub.to_owned())
            }
            _ => return Err(invalid(format!("{text} isn't a path"))),
        }
    };
    Ok(PatchPath {
        attr,
        filter: Some(inner),
        sub,
    })
}

/// Reads a PatchOp request's operations. Keys and `op` values in any case.
pub fn parse_request(body: &Value) -> Result<Vec<Operation>, Refusal> {
    let syntax = |why: &str| refusal("invalidSyntax", why);
    if let Some(schemas) = filter::get_key(body, "schemas").and_then(Value::as_array)
        && !schemas.iter().any(|s| s.as_str().is_some_and(|s| s.eq_ignore_ascii_case(PATCH_SCHEMA)))
    {
        return Err(syntax("A PATCH request's schemas must name the PatchOp message"));
    }
    let Some(list) = filter::get_key(body, "Operations").and_then(Value::as_array) else {
        return Err(syntax("A PATCH request needs its Operations"));
    };
    if list.is_empty() || list.len() > MAX_OPERATIONS {
        return Err(syntax("A PATCH request has between 1 and 1000 operations"));
    }
    list.iter()
        .map(|op| {
            let kind = match filter::get_key(op, "op").and_then(Value::as_str).map(str::to_ascii_lowercase).as_deref() {
                Some("add") => Kind::Add,
                Some("replace") => Kind::Replace,
                Some("remove") => Kind::Remove,
                _ => return Err(syntax("Each operation's op is add, replace, or remove")),
            };
            let path = match filter::get_key(op, "path") {
                None | Some(Value::Null) => None,
                Some(Value::String(p)) if p.trim().is_empty() => None,
                Some(Value::String(p)) => Some(parse_path(p)?),
                Some(_) => return Err(syntax("An operation's path is a string")),
            };
            let value = filter::get_key(op, "value").cloned();
            if kind != Kind::Remove && value.is_none() {
                return Err(syntax("Add and replace operations need a value"));
            }
            if kind == Kind::Remove && path.is_none() {
                return Err(refusal("noTarget", "A remove operation needs a path"));
            }
            Ok(Operation {
                kind,
                path,
                value,
            })
        })
        .collect()
}

/// The names RFC 7643 gives the attributes we're most likely to be sent,
/// so a request in another case keeps one copy, spelled the standard way.
const KNOWN_NAMES: &[&str] = &[
    "id",
    "externalId",
    "meta",
    "schemas",
    "userName",
    "name",
    "displayName",
    "nickName",
    "profileUrl",
    "title",
    "userType",
    "preferredLanguage",
    "locale",
    "timezone",
    "active",
    "password",
    "emails",
    "phoneNumbers",
    "ims",
    "photos",
    "addresses",
    "groups",
    "entitlements",
    "roles",
    "x509Certificates",
    "members",
    "formatted",
    "familyName",
    "givenName",
    "middleName",
    "honorificPrefix",
    "honorificSuffix",
    "value",
    "display",
    "type",
    "primary",
    "$ref",
    "streetAddress",
    "locality",
    "region",
    "postalCode",
    "country",
    "employeeNumber",
    "costCenter",
    "organization",
    "division",
    "department",
    "manager",
    ENTERPRISE_USER_SCHEMA,
];

fn canonical(name: &str) -> String {
    KNOWN_NAMES.iter().find(|k| k.eq_ignore_ascii_case(name)).map_or_else(|| name.to_owned(), |k| (*k).to_owned())
}

/// The key an object already has for a name, in any case.
fn existing_key(object: &Map<String, Value>, name: &str) -> Option<String> {
    object.keys().find(|k| k.eq_ignore_ascii_case(name)).cloned()
}

/// Sets a key, replacing a copy of it in another case.
fn set(object: &mut Map<String, Value>, name: &str, value: Value) {
    let key = existing_key(object, name).unwrap_or_else(|| canonical(name));
    object.remove(&key);
    object.insert(key, value);
}

fn take(object: &mut Map<String, Value>, name: &str) -> Option<Value> {
    existing_key(object, name).and_then(|k| object.remove(&k))
}

fn get_mut<'a>(object: &'a mut Map<String, Value>, name: &str) -> Option<&'a mut Value> {
    let key = existing_key(object, name)?;
    object.get_mut(&key)
}

/// Merges an object's sub-attributes into another.
fn merge(into: &mut Map<String, Value>, from: &Map<String, Value>) {
    for (k, v) in from {
        set(into, k, v.clone());
    }
}

/// The attribute values a filter fixes (`type eq "work"`), for a new value
/// when nothing matches, as Entra expects of `emails[type eq "work"].value`.
fn fixed_by(filter: &Filter, into: &mut Map<String, Value>) {
    match filter {
        Filter::And(a, b) => {
            fixed_by(a, into);
            fixed_by(b, into);
        }
        Filter::Compare(path, Op::Eq, literal) if path.schema.is_none() && path.sub.is_none() => {
            let value = match literal {
                Literal::Str(s) => Value::String(s.clone()),
                Literal::Bool(b) => Value::Bool(*b),
                _ => return,
            };
            set(into, &path.attr, value);
        }
        _ => {}
    }
}

/// Whether an extension object key, like
/// "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User", names a
/// schema rather than an attribute in one.
fn names_schema(key: &str) -> bool {
    filter::names_urn(key)
        && (key.eq_ignore_ascii_case(ENTERPRISE_USER_SCHEMA)
            || key
                .rsplit(':')
                .next()
                .is_some_and(|last| last.eq_ignore_ascii_case("User") || last.eq_ignore_ascii_case("Group")))
}

/// Whether a value is in a list already: by its "value" when both have one.
fn same_item(a: &Value, b: &Value) -> bool {
    match (filter::get_key(a, "value"), filter::get_key(b, "value")) {
        (Some(x), Some(y)) => x == y,
        _ => a == b,
    }
}

/// Applies operations to a resource's attributes. `id` can't change; `meta`,
/// `schemas`, and `groups` are the server's and are ignored.
pub fn apply(resource: &mut Map<String, Value>, operations: &[Operation]) -> Result<(), Refusal> {
    for op in operations {
        if let Some(path) = &op.path {
            apply_at(resource, op.kind, path, op.value.as_ref())?;
        } else {
            let Some(Value::Object(values)) = &op.value else {
                return Err(refusal("invalidValue", "Without a path, the value is an object of attributes"));
            };
            for (key, value) in values {
                if names_schema(key) && value.is_object() {
                    let Value::Object(inner) = value else {
                        continue;
                    };
                    for (attr, v) in inner {
                        let path = PatchPath {
                            attr: AttrPath {
                                schema: Some(key.clone()),
                                attr: attr.clone(),
                                sub: None,
                            },
                            filter: None,
                            sub: None,
                        };
                        apply_at(resource, op.kind, &path, Some(v))?;
                    }
                } else {
                    apply_at(resource, op.kind, &parse_path(key)?, Some(value))?;
                }
            }
        }
    }
    Ok(())
}

fn apply_at(
    resource: &mut Map<String, Value>,
    kind: Kind,
    path: &PatchPath,
    value: Option<&Value>,
) -> Result<(), Refusal> {
    let attr = &path.attr;
    if attr.schema.is_none() {
        if attr.attr.eq_ignore_ascii_case("id") {
            return Err(refusal("mutability", "A resource's id can't change"));
        }
        if ["meta", "schemas", "groups"].iter().any(|a| attr.attr.eq_ignore_ascii_case(a)) {
            return Ok(());
        }
    }
    // The object the attribute lives in: the resource, or its extension's.
    let container = match &attr.schema {
        None => resource,
        Some(schema) => {
            if kind == Kind::Remove && existing_key(resource, schema).is_none() {
                return Ok(());
            }
            if !matches!(get_mut(resource, schema), Some(Value::Object(_))) {
                set(resource, schema, Value::Object(Map::new()));
            }
            match get_mut(resource, schema) {
                Some(Value::Object(object)) => object,
                _ => unreachable!("just made an object"),
            }
        }
    };
    let value = value.cloned().unwrap_or(Value::Null);
    match (&path.filter, &attr.sub) {
        (None, None) => match kind {
            Kind::Remove => match (get_mut(container, &attr.attr), &value) {
                // Entra's remove of chosen members: path "members" and the
                // values to take out.
                (Some(Value::Array(items)), Value::Array(gone)) => {
                    items.retain(|item| !gone.iter().any(|g| same_item(item, g)));
                    if items.is_empty() {
                        take(container, &attr.attr);
                    }
                }
                _ => {
                    take(container, &attr.attr);
                }
            },
            Kind::Add | Kind::Replace => match (get_mut(container, &attr.attr), value) {
                (Some(Value::Array(items)), Value::Array(more)) if kind == Kind::Add => {
                    for v in more {
                        if !items.iter().any(|item| same_item(item, &v)) {
                            items.push(v);
                        }
                    }
                }
                (Some(Value::Array(items)), v) if kind == Kind::Add && !v.is_null() => {
                    if !items.iter().any(|item| same_item(item, &v)) {
                        items.push(v);
                    }
                }
                (Some(Value::Object(existing)), Value::Object(more)) => merge(existing, &more),
                (_, v) => set(container, &attr.attr, v),
            },
        },
        (None, Some(sub)) => {
            if kind == Kind::Remove {
                match get_mut(container, &attr.attr) {
                    Some(Value::Object(object)) => {
                        take(object, sub);
                    }
                    Some(Value::Array(items)) => {
                        for item in items.iter_mut().filter_map(Value::as_object_mut) {
                            take(item, sub);
                        }
                    }
                    _ => {}
                }
                return Ok(());
            }
            match get_mut(container, &attr.attr) {
                Some(Value::Array(items)) => {
                    for item in items.iter_mut().filter_map(Value::as_object_mut) {
                        set(item, sub, value.clone());
                    }
                }
                Some(Value::Object(object)) => set(object, sub, value),
                _ => {
                    let mut object = Map::new();
                    set(&mut object, sub, value);
                    set(container, &attr.attr, Value::Object(object));
                }
            }
        }
        (Some(filter), _) => {
            let sub = &path.sub;
            let mut items = match take(container, &attr.attr) {
                Some(Value::Array(items)) => items,
                Some(Value::Null) | None => Vec::new(),
                Some(single) => vec![single],
            };
            let matching: Vec<usize> =
                items.iter().enumerate().filter(|(_, item)| filter::matches(filter, item)).map(|(i, _)| i).collect();
            match (kind, sub) {
                (Kind::Remove, None) => {
                    let mut i = 0;
                    items.retain(|_| {
                        let keep = !matching.contains(&i);
                        i += 1;
                        keep
                    });
                }
                (Kind::Remove, Some(sub)) => {
                    for &i in &matching {
                        if let Some(object) = items[i].as_object_mut() {
                            take(object, sub);
                        }
                    }
                }
                (_, Some(sub)) => {
                    if matching.is_empty() {
                        let mut object = Map::new();
                        fixed_by(filter, &mut object);
                        set(&mut object, sub, value);
                        items.push(Value::Object(object));
                    } else {
                        for &i in &matching {
                            if let Some(object) = items[i].as_object_mut() {
                                set(object, sub, value.clone());
                            }
                        }
                    }
                }
                (_, None) => {
                    let Value::Object(more) = value else {
                        return Err(refusal("invalidValue", "A filtered path's value is an object"));
                    };
                    if matching.is_empty() {
                        let mut object = Map::new();
                        fixed_by(filter, &mut object);
                        merge(&mut object, &more);
                        items.push(Value::Object(object));
                    } else {
                        for &i in &matching {
                            if let Some(object) = items[i].as_object_mut() {
                                merge(object, &more);
                            }
                        }
                    }
                }
            }
            if !items.is_empty() {
                set(container, &attr.attr, Value::Array(items));
            }
        }
    }
    Ok(())
}

/// `active` as SCIM says (true or false), or as Entra sends it without its
/// compliance flag ("True" or "False").
pub fn as_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(b) => Some(*b),
        Value::String(s) if s.eq_ignore_ascii_case("true") => Some(true),
        Value::String(s) if s.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    }
}

/// Drops attributes sent as null, at every depth (in extensions, complex
/// attributes, and the values of multi-valued ones): SCIM leaves out what has
/// no value.
pub fn without_nulls(resource: &mut Map<String, Value>) {
    resource.retain(|_, v| !v.is_null());
    for value in resource.values_mut() {
        drop_nulls(value);
    }
}

fn drop_nulls(value: &mut Value) {
    match value {
        Value::Object(object) => without_nulls(object),
        Value::Array(items) => {
            items.retain(|v| !v.is_null());
            for item in items {
                drop_nulls(item);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn patched(start: Value, request: Value) -> Value {
        let mut resource = start.as_object().unwrap().clone();
        apply(&mut resource, &parse_request(&request).unwrap()).unwrap();
        Value::Object(resource)
    }

    #[test]
    fn keys_and_paths_of_several_bytes_are_refused_without_a_crash() {
        assert!(!names_schema("€€x"));
        assert!(!names_schema("urn€:User"));
        assert!(parse_path("€€x").is_err());
        // A value whose object has such a key names an attribute that isn't
        // one: refused, as any other.
        let mut resource = created().as_object().unwrap().clone();
        let refused = parse_request(&json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{ "op": "add", "value": { "€€x": "1" } }]
        }))
        .and_then(|ops| apply(&mut resource, &ops));
        assert!(refused.is_err());
    }

    fn created() -> Value {
        // Microsoft's create example, as kept.
        json!({
            "externalId": "0a21f0f2-8d2a-4f8e-bf98-7363c4aed4ef",
            "userName": "Test_User_00aa00aa-bb11-cc22-dd33-44ee44ee44ee",
            "active": true,
            "emails": [{ "primary": true, "type": "work", "value": "Test_User_11bb11bb@testuser.com" }],
            "name": { "formatted": "givenName familyName", "familyName": "familyName", "givenName": "givenName" }
        })
    }

    #[test]
    fn entra_multi_valued_update() {
        let user = patched(
            created(),
            json!({
                "schemas": [PATCH_SCHEMA],
                "Operations": [
                    { "op": "Replace", "path": "emails[type eq \"work\"].value", "value": "updatedEmail@microsoft.com" },
                    { "op": "Replace", "path": "name.familyName", "value": "updatedFamilyName" }
                ]
            }),
        );
        assert_eq!(user["emails"], json!([{ "primary": true, "type": "work", "value": "updatedEmail@microsoft.com" }]));
        assert_eq!(user["name"]["familyName"], "updatedFamilyName");
        assert_eq!(user["name"]["givenName"], "givenName");
    }

    #[test]
    fn entra_single_valued_update_and_disable() {
        let user = patched(
            created(),
            json!({
                "schemas": [PATCH_SCHEMA],
                "Operations": [{ "op": "Replace", "path": "userName", "value": "5b50642d@testuser.com" }]
            }),
        );
        assert_eq!(user["userName"], "5b50642d@testuser.com");
        // Without the flag, "False" as a string; with it, false.
        for value in [json!("False"), json!(false)] {
            let user = patched(
                created(),
                json!({
                    "Operations": [{ "op": "Replace", "path": "active", "value": value }],
                    "schemas": [PATCH_SCHEMA]
                }),
            );
            assert_eq!(as_bool(&user["active"]), Some(false));
        }
    }

    #[test]
    fn entra_replace_without_a_path() {
        // With aadOptscim062020: one operation whose value has paths as keys.
        let user = patched(
            created(),
            json!({
                "schemas": [PATCH_SCHEMA],
                "Operations": [
                    { "op": "replace", "path": "emails[type eq \"work\"].value", "value": "TestMhvaes@test.microsoft.com" },
                    { "op": "replace", "value": {
                        "displayName": "Bjfe",
                        "name.givenName": "Kkom",
                        "name.familyName": "Unua",
                        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber": "Aklq"
                    } }
                ]
            }),
        );
        assert_eq!(user["displayName"], "Bjfe");
        assert_eq!(user["name"]["givenName"], "Kkom");
        assert_eq!(user["name"]["familyName"], "Unua");
        assert_eq!(user["name"]["formatted"], "givenName familyName");
        assert_eq!(user[ENTERPRISE_USER_SCHEMA]["employeeNumber"], "Aklq");
        assert_eq!(user["emails"][0]["value"], "TestMhvaes@test.microsoft.com");
    }

    #[test]
    fn entra_without_the_flag_sends_one_operation_per_attribute() {
        let user = patched(
            created(),
            json!({
                "schemas": [PATCH_SCHEMA],
                "Operations": [
                    { "op": "Replace", "path": "displayName", "value": "Pvlo" },
                    { "op": "Replace", "path": "emails[type eq \"work\"].value", "value": "TestBcwqnm@test.microsoft.com" },
                    { "op": "Replace", "path": "name.givenName", "value": "Gtfd" },
                    { "op": "Replace", "path": "name.familyName", "value": "Pkqf" },
                    { "op": "Replace", "path": "externalId", "value": "Eqpj" },
                    { "op": "Replace", "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber", "value": "Eqpj" },
                    { "op": "Add", "path": "nickName", "value": "Babs" }
                ]
            }),
        );
        assert_eq!(user["externalId"], "Eqpj");
        assert_eq!(user["nickName"], "Babs");
        assert_eq!(user[ENTERPRISE_USER_SCHEMA]["employeeNumber"], "Eqpj");
    }

    #[test]
    fn a_filter_that_matches_nothing_adds_the_value() {
        let user = patched(
            json!({ "userName": "a" }),
            json!({
                "Operations": [
                    { "op": "add", "path": "emails[type eq \"work\"].value", "value": "a@example.test" },
                    { "op": "add", "path": "phoneNumbers[type eq \"mobile\"].value", "value": "555" }
                ]
            }),
        );
        assert_eq!(user["emails"], json!([{ "type": "work", "value": "a@example.test" }]));
        assert_eq!(user["phoneNumbers"], json!([{ "type": "mobile", "value": "555" }]));
    }

    #[test]
    fn manager_as_entra_adds_it() {
        let user = patched(
            created(),
            json!({
                "schemas": [PATCH_SCHEMA],
                "Operations": [{ "op": "Add", "path": "manager", "value": [{ "$ref": "http://x/Users/m1", "value": "m1" }] }]
            }),
        );
        assert_eq!(user["manager"][0]["value"], "m1");
    }

    #[test]
    fn names_in_any_case_keep_one_copy() {
        let user = patched(
            created(),
            json!({
                "operations": [
                    { "OP": "REPLACE", "Path": "USERNAME", "Value": "new@x.test" },
                    { "op": "replace", "path": "Name.GivenName", "value": "G" },
                    { "op": "remove", "path": "EXTERNALID" }
                ]
            }),
        );
        assert_eq!(user["userName"], "new@x.test");
        assert_eq!(user["name"]["givenName"], "G");
        assert!(user.get("externalId").is_none());
        assert_eq!(user.as_object().unwrap().keys().filter(|k| k.eq_ignore_ascii_case("username")).count(), 1);
    }

    #[test]
    fn group_member_shapes() {
        let group = json!({ "displayName": "Sales", "members": [{ "value": "u1" }, { "value": "u2" }] });
        let added = patched(
            group.clone(),
            json!({ "Operations": [{ "op": "Add", "path": "members", "value": [{ "$ref": null, "value": "u3" }, { "value": "u1" }] }] }),
        );
        assert_eq!(added["members"].as_array().unwrap().len(), 3);
        // Without the flag: path "members" and the values to remove.
        let removed = patched(
            group.clone(),
            json!({ "Operations": [{ "op": "Remove", "path": "members", "value": [{ "value": "u1" }] }] }),
        );
        assert_eq!(removed["members"], json!([{ "value": "u2" }]));
        // With it: a filter in the path.
        let removed =
            patched(group.clone(), json!({ "Operations": [{ "op": "remove", "path": "members[value eq \"u2\"]" }] }));
        assert_eq!(removed["members"], json!([{ "value": "u1" }]));
        let renamed = patched(
            group,
            json!({ "Operations": [{ "op": "Replace", "path": "displayName", "value": "Sales EMEA" }] }),
        );
        assert_eq!(renamed["displayName"], "Sales EMEA");
    }

    #[test]
    fn refusals() {
        for (request, scim_type) in [
            (json!({ "Operations": [] }), "invalidSyntax"),
            (
                json!({ "schemas": ["urn:other"], "Operations": [{ "op": "add", "path": "a", "value": 1 }] }),
                "invalidSyntax",
            ),
            (json!({ "Operations": [{ "op": "move", "path": "a", "value": 1 }] }), "invalidSyntax"),
            (json!({ "Operations": [{ "op": "add", "path": "a" }] }), "invalidSyntax"),
            (json!({ "Operations": [{ "op": "remove" }] }), "noTarget"),
            (json!({ "Operations": [{ "op": "add", "path": "emails[type eq", "value": 1 }] }), "invalidPath"),
            (json!({ "Operations": [{ "op": "add", "path": "emails[type zz \"w\"]", "value": 1 }] }), "invalidFilter"),
            (json!({ "Operations": [{ "op": "add", "path": "bad name", "value": 1 }] }), "invalidPath"),
        ] {
            assert_eq!(parse_request(&request).map(|_| ()).unwrap_err().scim_type, scim_type, "{request}");
        }
        let mut resource = created().as_object().unwrap().clone();
        let ops = parse_request(&json!({ "Operations": [{ "op": "replace", "path": "id", "value": "x" }] })).unwrap();
        assert_eq!(apply(&mut resource, &ops).unwrap_err().scim_type, "mutability");
        let ops = parse_request(&json!({ "Operations": [{ "op": "replace", "value": "not an object" }] })).unwrap();
        assert_eq!(apply(&mut resource, &ops).unwrap_err().scim_type, "invalidValue");
    }

    #[test]
    fn active_as_a_bool_or_entras_string() {
        assert_eq!(as_bool(&json!(true)), Some(true));
        assert_eq!(as_bool(&json!("False")), Some(false));
        assert_eq!(as_bool(&json!("TRUE")), Some(true));
        assert_eq!(as_bool(&json!("no")), None);
        assert_eq!(as_bool(&json!(0)), None);
    }

    #[test]
    fn nulls_are_left_out() {
        let mut user = json!({
            "userName": "a",
            "title": null,
            ENTERPRISE_USER_SCHEMA: { "manager": { "value": null, "$ref": "r" }, "department": "x", "costCenter": null },
            "emails": [null, { "value": "a@x.test", "type": null, "display": { "deep": null } }],
            "name": { "givenName": "A", "middleName": null }
        })
        .as_object()
        .unwrap()
        .clone();
        without_nulls(&mut user);
        assert_eq!(
            Value::Object(user),
            json!({
                "userName": "a",
                ENTERPRISE_USER_SCHEMA: { "manager": { "$ref": "r" }, "department": "x" },
                "emails": [{ "value": "a@x.test", "display": {} }],
                "name": { "givenName": "A" }
            })
        );
    }
}
