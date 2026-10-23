// Keykeeper: SCIM filters (RFC 7644, section 3.4.2.2), parsed and checked
// against a resource's JSON. Microsoft Entra ID sends only `eq` and `and`
// (`userName eq "..."`, `externalId eq "..."`, `displayName eq "..."`, and
// `emails[type eq "work"].value eq "..."`), but the rest of the grammar costs
// little: `ne`, `co`, `sw`, `ew`, `gt`, `ge`, `lt`, `le`, `pr`, `or`, `not`,
// parentheses, and value paths in brackets. Attribute names and operators
// don't depend on case; values don't either, except `id` and `externalId`,
// which RFC 7643 makes case exact.

use serde_json::Value;

/// The longest filter accepted, in bytes, and how deeply it may nest.
pub const MAX_FILTER_LEN: usize = 2048;
const MAX_DEPTH: usize = 16;

/// The core schemas: an attribute named with one of these is a top-level one.
pub const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
pub const ENTERPRISE_USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

/// `[schema:]attr[.sub]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttrPath {
    /// An extension schema's URN; None for the core schema.
    pub schema: Option<String>,
    pub attr: String,
    pub sub: Option<String>,
}

impl AttrPath {
    /// Whether this names a core attribute, in any case: `userName`, or
    /// `urn:ietf:params:scim:schemas:core:2.0:User:userName`.
    pub fn is(&self, attr: &str) -> bool {
        self.schema.is_none() && self.sub.is_none() && self.attr.eq_ignore_ascii_case(attr)
    }
}

/// Parses `[schema:]attr[.sub]`. A core schema's URN names a top-level
/// attribute. Attribute names are ALPHA *(ALPHA / DIGIT / "-" / "_"), or
/// "$ref".
pub fn parse_attr_path(text: &str) -> Result<AttrPath, String> {
    let text = text.trim();
    let (schema, rest) = if text.len() > 4 && text[..4].eq_ignore_ascii_case("urn:") {
        match text.rfind(':') {
            Some(i) if i + 1 < text.len() => (Some(&text[..i]), &text[i + 1..]),
            _ => return Err(format!("{text} names a schema but no attribute")),
        }
    } else {
        (None, text)
    };
    let schema = schema.filter(|s| !s.eq_ignore_ascii_case(USER_SCHEMA) && !s.eq_ignore_ascii_case(GROUP_SCHEMA));
    let (attr, sub) = match rest.split_once('.') {
        Some((attr, sub)) => (attr, Some(sub)),
        None => (rest, None),
    };
    if !valid_name(attr) || sub.is_some_and(|s| !valid_name(s)) {
        return Err(format!("{text} isn't an attribute path"));
    }
    Ok(AttrPath {
        schema: schema.map(str::to_owned),
        attr: attr.to_owned(),
        sub: sub.map(str::to_owned),
    })
}

fn valid_name(name: &str) -> bool {
    name == "$ref"
        || name.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    Co,
    Sw,
    Ew,
    Gt,
    Ge,
    Lt,
    Le,
}

impl Op {
    fn parse(word: &str) -> Option<Self> {
        Some(match word.to_ascii_lowercase().as_str() {
            "eq" => Self::Eq,
            "ne" => Self::Ne,
            "co" => Self::Co,
            "sw" => Self::Sw,
            "ew" => Self::Ew,
            "gt" => Self::Gt,
            "ge" => Self::Ge,
            "lt" => Self::Lt,
            "le" => Self::Le,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Literal {
    Str(String),
    Bool(bool),
    Num(f64),
    Null,
}

/// What a value path's sub-attribute is tested for.
#[derive(Debug, Clone, PartialEq)]
pub enum Test {
    Present,
    Compare(Op, Literal),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Filter {
    And(Box<Filter>, Box<Filter>),
    Or(Box<Filter>, Box<Filter>),
    Not(Box<Filter>),
    Present(AttrPath),
    Compare(AttrPath, Op, Literal),
    /// `attr[inner]`: an element of a multi-valued attribute matches `inner`,
    /// and, with `.sub`, that element's sub-attribute passes `test`
    /// (`emails[type eq "work"].value eq "..."`, as Entra sends it).
    Within {
        path: AttrPath,
        inner: Box<Filter>,
        sub: Option<(String, Test)>,
    },
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Open,
    Close,
    OpenBracket,
    CloseBracket,
    Word(String),
    Str(String),
}

fn tokenize(text: &str) -> Result<Vec<Tok>, String> {
    let mut toks = Vec::new();
    let mut chars = text.char_indices().peekable();
    while let Some(&(start, c)) = chars.peek() {
        match c {
            c if c.is_whitespace() => {
                chars.next();
            }
            '(' | ')' | '[' | ']' => {
                chars.next();
                toks.push(match c {
                    '(' => Tok::Open,
                    ')' => Tok::Close,
                    '[' => Tok::OpenBracket,
                    _ => Tok::CloseBracket,
                });
            }
            '"' => {
                // A JSON string, escapes and all.
                chars.next();
                let mut end = None;
                let mut escaped = false;
                for (i, c) in chars.by_ref() {
                    if escaped {
                        escaped = false;
                    } else if c == '\\' {
                        escaped = true;
                    } else if c == '"' {
                        end = Some(i);
                        break;
                    }
                }
                let Some(end) = end else {
                    return Err("A quoted value isn't closed".into());
                };
                let value: String = serde_json::from_str(&text[start..=end])
                    .map_err(|_| "A quoted value isn't a JSON string".to_owned())?;
                toks.push(Tok::Str(value));
            }
            _ => {
                let mut end = text.len();
                while let Some(&(i, c)) = chars.peek() {
                    if c.is_whitespace() || matches!(c, '(' | ')' | '[' | ']' | '"') {
                        end = i;
                        break;
                    }
                    chars.next();
                }
                toks.push(Tok::Word(text[start..end].to_owned()));
            }
        }
    }
    Ok(toks)
}

struct Parser {
    toks: Vec<Tok>,
    at: usize,
    depth: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.at)
    }

    fn next(&mut self) -> Option<Tok> {
        let tok = self.toks.get(self.at).cloned();
        self.at += 1;
        tok
    }

    fn peek_word(&self, word: &str) -> bool {
        matches!(self.peek(), Some(Tok::Word(w)) if w.eq_ignore_ascii_case(word))
    }

    fn deeper(&mut self) -> Result<(), String> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err("The filter nests too deeply".into());
        }
        Ok(())
    }

    fn or(&mut self) -> Result<Filter, String> {
        let mut left = self.and()?;
        while self.peek_word("or") {
            self.next();
            let right = self.and()?;
            left = Filter::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Filter, String> {
        let mut left = self.unary()?;
        while self.peek_word("and") {
            self.next();
            let right = self.unary()?;
            left = Filter::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn unary(&mut self) -> Result<Filter, String> {
        if self.peek_word("not") {
            self.next();
            if self.next() != Some(Tok::Open) {
                return Err("\"not\" needs a filter in parentheses".into());
            }
            let inner = self.grouped()?;
            return Ok(Filter::Not(Box::new(inner)));
        }
        if self.peek() == Some(&Tok::Open) {
            self.next();
            return self.grouped();
        }
        self.attr_expr()
    }

    /// The rest of a parenthesized filter, after "(".
    fn grouped(&mut self) -> Result<Filter, String> {
        self.deeper()?;
        let inner = self.or()?;
        self.depth -= 1;
        if self.next() != Some(Tok::Close) {
            return Err("A parenthesis isn't closed".into());
        }
        Ok(inner)
    }

    fn attr_expr(&mut self) -> Result<Filter, String> {
        let Some(Tok::Word(word)) = self.next() else {
            return Err("Expected an attribute".into());
        };
        let path = parse_attr_path(&word)?;
        if self.peek() == Some(&Tok::OpenBracket) {
            self.next();
            self.deeper()?;
            let inner = self.or()?;
            self.depth -= 1;
            if self.next() != Some(Tok::CloseBracket) {
                return Err("A bracket isn't closed".into());
            }
            let sub = match self.peek() {
                Some(Tok::Word(w)) if w.starts_with('.') => {
                    let name = w[1..].to_owned();
                    if !valid_name(&name) {
                        return Err(format!("{w} isn't a sub-attribute"));
                    }
                    self.next();
                    Some((name, self.test()?))
                }
                _ => None,
            };
            return Ok(Filter::Within {
                path,
                inner: Box::new(inner),
                sub,
            });
        }
        match self.test()? {
            Test::Present => Ok(Filter::Present(path)),
            Test::Compare(op, value) => Ok(Filter::Compare(path, op, value)),
        }
    }

    fn test(&mut self) -> Result<Test, String> {
        let Some(Tok::Word(op)) = self.next() else {
            return Err("Expected an operator such as eq".into());
        };
        if op.eq_ignore_ascii_case("pr") {
            return Ok(Test::Present);
        }
        let Some(op) = Op::parse(&op) else {
            return Err(format!("{op} isn't an operator this server supports"));
        };
        let value = match self.next() {
            Some(Tok::Str(s)) => Literal::Str(s),
            Some(Tok::Word(w)) => match w.to_ascii_lowercase().as_str() {
                "true" => Literal::Bool(true),
                "false" => Literal::Bool(false),
                "null" => Literal::Null,
                _ => match w.parse::<f64>() {
                    Ok(n) => Literal::Num(n),
                    // Leniency for an unquoted value, as in some examples.
                    Err(_) => Literal::Str(w),
                },
            },
            _ => return Err("Expected a value".into()),
        };
        Ok(Test::Compare(op, value))
    }
}

/// Parses a filter.
pub fn parse(text: &str) -> Result<Filter, String> {
    if text.len() > MAX_FILTER_LEN {
        return Err("The filter is too long".into());
    }
    let mut parser = Parser {
        toks: tokenize(text)?,
        at: 0,
        depth: 0,
    };
    if parser.toks.is_empty() {
        return Err("The filter is empty".into());
    }
    let filter = parser.or()?;
    if parser.at != parser.toks.len() {
        return Err("The filter has something extra at the end".into());
    }
    Ok(filter)
}

/// A key of a JSON object, found without regard to case.
pub fn get_key<'a>(object: &'a Value, key: &str) -> Option<&'a Value> {
    object.as_object()?.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v)
}

/// The object an attribute path starts from: the resource, or an extension
/// schema's object in it.
fn base<'a>(resource: &'a Value, path: &AttrPath) -> Option<&'a Value> {
    match &path.schema {
        None => Some(resource),
        Some(schema) => get_key(resource, schema),
    }
}

/// Every value at a path, with multi-valued attributes spread out.
fn values_at<'a>(resource: &'a Value, path: &AttrPath) -> Vec<&'a Value> {
    let Some(value) = base(resource, path).and_then(|b| get_key(b, &path.attr)) else {
        return Vec::new();
    };
    let spread = |v: &'a Value| -> Vec<&'a Value> {
        match v {
            Value::Array(items) => items.iter().collect(),
            v => vec![v],
        }
    };
    match &path.sub {
        None => spread(value),
        Some(sub) => spread(value).into_iter().filter_map(|v| get_key(v, sub)).flat_map(spread).collect(),
    }
}

/// RFC 7643 makes `id` and `externalId` case exact; the attributes we filter
/// on otherwise aren't.
fn case_exact(path: &AttrPath) -> bool {
    path.sub.is_none() && (path.attr.eq_ignore_ascii_case("id") || path.attr.eq_ignore_ascii_case("externalId"))
}

fn present(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
        _ => true,
    }
}

fn compare(value: &Value, op: Op, literal: &Literal, exact: bool) -> bool {
    // A complex value compared as a whole compares by its "value".
    let value = match value {
        Value::Object(_) => match get_key(value, "value") {
            Some(v) => v,
            None => return false,
        },
        v => v,
    };
    match (literal, value) {
        (Literal::Null, v) => match op {
            Op::Eq => v.is_null(),
            Op::Ne => !v.is_null(),
            _ => false,
        },
        (Literal::Bool(b), v) => {
            let actual = match v {
                Value::Bool(actual) => Some(*actual),
                Value::String(s) if s.eq_ignore_ascii_case("true") => Some(true),
                Value::String(s) if s.eq_ignore_ascii_case("false") => Some(false),
                _ => None,
            };
            match (op, actual) {
                (Op::Eq, Some(a)) => a == *b,
                (Op::Ne, Some(a)) => a != *b,
                _ => false,
            }
        }
        (Literal::Num(n), Value::Number(actual)) => {
            let Some(a) = actual.as_f64() else {
                return false;
            };
            match op {
                Op::Eq => (a - n).abs() < f64::EPSILON,
                Op::Ne => (a - n).abs() >= f64::EPSILON,
                Op::Gt => a > *n,
                Op::Ge => a >= *n,
                Op::Lt => a < *n,
                Op::Le => a <= *n,
                _ => false,
            }
        }
        (Literal::Num(_), _) => false,
        (Literal::Str(s), v) => {
            let actual = match v {
                Value::String(a) => a.clone(),
                Value::Bool(b) => b.to_string(),
                Value::Number(n) => n.to_string(),
                _ => return false,
            };
            let (a, s) = if exact {
                (actual, s.clone())
            } else {
                (actual.to_lowercase(), s.to_lowercase())
            };
            match op {
                Op::Eq => a == s,
                Op::Ne => a != s,
                Op::Co => a.contains(&s),
                Op::Sw => a.starts_with(&s),
                Op::Ew => a.ends_with(&s),
                Op::Gt => a > s,
                Op::Ge => a >= s,
                Op::Lt => a < s,
                Op::Le => a <= s,
            }
        }
    }
}

fn passes(values: &[&Value], test: &Test, exact: bool) -> bool {
    match test {
        Test::Present => values.iter().any(|v| present(v)),
        // "ne": none of the values is equal (an absent attribute isn't equal).
        Test::Compare(Op::Ne, literal) => !values.iter().any(|v| compare(v, Op::Eq, literal, exact)),
        // "eq null": the attribute is absent or null.
        Test::Compare(Op::Eq, Literal::Null) => values.iter().all(|v| v.is_null()),
        Test::Compare(op, literal) => values.iter().any(|v| compare(v, *op, literal, exact)),
    }
}

/// Whether a resource matches a filter.
pub fn matches(filter: &Filter, resource: &Value) -> bool {
    match filter {
        Filter::And(a, b) => matches(a, resource) && matches(b, resource),
        Filter::Or(a, b) => matches(a, resource) || matches(b, resource),
        Filter::Not(f) => !matches(f, resource),
        Filter::Present(path) => passes(&values_at(resource, path), &Test::Present, false),
        Filter::Compare(path, op, literal) => {
            passes(&values_at(resource, path), &Test::Compare(*op, literal.clone()), case_exact(path))
        }
        Filter::Within {
            path,
            inner,
            sub,
        } => {
            let whole = AttrPath {
                sub: None,
                ..path.clone()
            };
            values_at(resource, &whole).into_iter().filter(|element| matches(inner, element)).any(|element| match sub {
                None => true,
                Some((name, test)) => {
                    let values: Vec<&Value> = match get_key(element, name) {
                        Some(Value::Array(items)) => items.iter().collect(),
                        Some(v) => vec![v],
                        None => Vec::new(),
                    };
                    passes(&values, test, false)
                }
            })
        }
    }
}

/// The string a filter requires a core attribute to equal, when it does so at
/// its top level (alone, or in an "and"): `userName eq "x"`. Lets a list
/// narrow its candidates before checking the whole filter.
pub fn required_equal<'a>(filter: &'a Filter, attr: &str) -> Option<&'a str> {
    match filter {
        Filter::Compare(path, Op::Eq, Literal::Str(value)) if path.is(attr) => Some(value),
        Filter::And(a, b) => required_equal(a, attr).or_else(|| required_equal(b, attr)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn user() -> Value {
        json!({
            "schemas": [USER_SCHEMA, ENTERPRISE_USER_SCHEMA],
            "id": "2441309d-8532-4e77-93ae-000000000001",
            "externalId": "7fce0092-d52e-4f76-b727-3955bd72c939",
            "userName": "Test_User_00aa00aa-bb11-cc22-dd33-44ee44ee44ee",
            "name": { "familyName": "familyName", "givenName": "givenName" },
            "active": true,
            "emails": [
                { "value": "Test_User_11bb11bb@testuser.com", "type": "work", "primary": true },
                { "value": "home@example.test", "type": "home" }
            ],
            ENTERPRISE_USER_SCHEMA: { "employeeNumber": "701984", "manager": { "value": "boss-id" } }
        })
    }

    fn check(filter: &str) -> bool {
        matches(&parse(filter).unwrap_or_else(|e| panic!("{filter}: {e}")), &user())
    }

    #[test]
    fn entra_matching_queries() {
        // Microsoft's documented queries, and Test Connection's random one.
        assert!(check(r#"userName eq "Test_User_00aa00aa-bb11-cc22-dd33-44ee44ee44ee""#));
        assert!(check(r#"userName eq "test_user_00AA00aa-bb11-cc22-dd33-44ee44ee44ee""#), "userName isn't case exact");
        assert!(!check(r#"userName eq "non-existent user""#));
        assert!(!check(r#"userName eq "4f1a2b3c-0000-4000-8000-000000000000""#));
        assert!(check(r#"externalId eq "7fce0092-d52e-4f76-b727-3955bd72c939""#));
        assert!(!check(r#"externalId eq "7FCE0092-D52E-4F76-B727-3955BD72C939""#), "externalId is case exact");
        assert!(check(r#"emails[type eq "work"].value eq "test_user_11bb11bb@testuser.com""#));
        assert!(!check(r#"emails[type eq "work"].value eq "home@example.test""#));
        assert!(!check(r#"id eq "2441309d-8532-4e77-93ae-000000000001" and manager eq "boss-id""#));
        assert!(check(
            r#"id eq "2441309d-8532-4e77-93ae-000000000001" and urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager eq "boss-id""#
        ));
    }

    #[test]
    fn names_and_operators_ignore_case() {
        assert!(check(r#"USERNAME EQ "Test_User_00aa00aa-bb11-cc22-dd33-44ee44ee44ee""#));
        assert!(check(r#"Emails[Type Eq "WORK"].Value eq "TEST_USER_11BB11BB@TESTUSER.COM""#));
        assert!(check(r#"urn:ietf:params:scim:schemas:core:2.0:User:userName sw "test_""#));
    }

    #[test]
    fn the_rest_of_the_grammar() {
        assert!(check("active eq true"));
        assert!(!check("active eq false"));
        assert!(check("name.givenName co \"VEN\""));
        assert!(check("name.familyName ew \"Name\""));
        assert!(!check("title pr"));
        assert!(check("emails pr"));
        assert!(check("emails[type eq \"home\"]"));
        assert!(!check("emails[type eq \"other\"]"));
        assert!(check("emails.value ew \"testuser.com\""));
        assert!(check("not (userName eq \"someone else\")"));
        assert!(check("userName eq \"x\" or (active eq true and name.givenName pr)"));
        assert!(check("title eq null"));
        assert!(!check("userName eq null"));
        assert!(check("userName ne \"x\""));
        assert!(check(r#"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber gt "7""#));
        // An unquoted value, as in one of Microsoft's examples.
        assert!(check("externalId eq 7fce0092-d52e-4f76-b727-3955bd72c939"));
    }

    #[test]
    fn group_member_queries() {
        let group = json!({
            "id": "g1",
            "displayName": "Sales",
            "members": [{ "value": "m1" }, { "value": "m2" }]
        });
        for (filter, expected) in [
            (r#"displayName eq "sales""#, true),
            (r#"id eq "g1" and members eq "m2""#, true),
            (r#"id eq "g1" and members[value eq "m1"]"#, true),
            (r#"id eq "g1" and members.value eq "m3""#, false),
        ] {
            assert_eq!(matches(&parse(filter).unwrap(), &group), expected, "{filter}");
        }
    }

    #[test]
    fn refuses_what_isnt_a_filter() {
        for bad in [
            "",
            "userName",
            "userName eq",
            "userName xx \"a\"",
            "userName eq \"a\" and",
            "(userName eq \"a\"",
            "emails[type eq \"work\"",
            "userName eq \"unclosed",
            "user name eq \"a\"",
            "urn:ietf:params:scim:schemas:core:2.0:User: eq \"a\"",
            "userName eq \"a\" extra",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        assert!(parse(&"(".repeat(40)).is_err());
        assert!(parse(&format!("userName eq \"{}\"", "a".repeat(MAX_FILTER_LEN))).is_err());
    }

    #[test]
    fn finds_the_equality_a_list_can_narrow_by() {
        let f = parse(r#"userName eq "A@x.test""#).unwrap();
        assert_eq!(required_equal(&f, "username"), Some("A@x.test"));
        let f = parse(r#"active eq true and externalId eq "e1""#).unwrap();
        assert_eq!(required_equal(&f, "externalId"), Some("e1"));
        assert_eq!(required_equal(&f, "userName"), None);
        let f = parse(r#"userName eq "a" or userName eq "b""#).unwrap();
        assert_eq!(required_equal(&f, "userName"), None);
    }
}
