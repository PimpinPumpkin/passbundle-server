//! PassBundle: roughly where an address is (country, and city when known),
//! from an IP-to-location database file on this server's own disk, for the
//! new-device check's prompt, its emails, and the event log (DESIGN.md,
//! "New-device check", "Where a sign-in comes from").
//!
//! Nothing is ever asked of another service: without the file
//! (`IP_LOCATION_DATABASE`) there's no location, and nothing else changes.
//! The file is in the MaxMind DB format (its published specification, version
//! 2.0), as DB-IP's "IP to City Lite" and "IP to Country Lite" are, with
//! GeoLite2's layout (`country.names.en`, `country.iso_code`,
//! `city.names.en`). This reader is our own, so the server needs no new
//! crate. A lookup reads only the few hundred bytes it needs from the file in
//! place, never the whole file into memory, and the server notices a new file
//! within a minute.
//!
//! Nothing is stored: a location is worked out when it's shown, from an
//! address the server already keeps. Private, local, and VPN addresses are
//! "unknown" without a lookup.

use std::{
    collections::HashMap,
    fs::File,
    io,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, LazyLock, Mutex},
    time::{Duration, Instant, SystemTime},
};

use serde_json::Value;

use crate::CONFIG;

/// Where an address is, as approximately as it's shown: a country, and a
/// city when the database knows it. Never a region, coordinates, or a
/// postal code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Location {
    pub country: String,
    pub city: Option<String>,
}

impl Location {
    /// "Berlin, Germany", or "Germany".
    pub fn display(&self) -> String {
        match &self.city {
            Some(city) => format!("{city}, {}", self.country),
            None => self.country.clone(),
        }
    }
}

/// Where this address is, in words, or None: no database, an address it
/// doesn't have, or one that's private, local, or a VPN's (`unknown_range`).
pub fn describe(ip: &str) -> Option<String> {
    let ip: IpAddr = ip.trim().parse().ok()?;
    locate(&ip).map(|l| l.display())
}

/// Where this address is, or None.
pub fn locate(ip: &IpAddr) -> Option<Location> {
    let ip = unmapped(ip);
    if unknown_range(&ip) {
        return None;
    }
    let mut state = STATE.lock().ok()?;
    state.refresh(Path::new(&CONFIG.ip_location_database()));
    if let Some(found) = state.cache.get(&ip) {
        return found.clone();
    }
    let found = state.db.as_ref().and_then(|db| db.lookup(&ip).ok().flatten());
    if state.cache.len() >= CACHE_SIZE {
        state.cache.clear();
    }
    state.cache.insert(ip, found.clone());
    found
}

/// Who the locations come from, to credit next to each one shown
/// (`IP_LOCATION_ATTRIBUTION` and `_URL`, DB-IP's by default, as its CC BY
/// 4.0 license asks), or None when there's no database.
pub fn attribution() -> Option<Value> {
    let mut state = STATE.lock().ok()?;
    state.refresh(Path::new(&CONFIG.ip_location_database()));
    state.db.as_ref()?;
    let name = CONFIG.ip_location_attribution();
    if name.trim().is_empty() {
        return None;
    }
    let url = CONFIG.ip_location_attribution_url();
    Some(json!({ "name": name, "url": if url.trim().is_empty() { None } else { Some(url) } }))
}

/// An IPv4-mapped IPv6 address as its IPv4 address.
fn unmapped(ip: &IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(*ip, IpAddr::V4),
        IpAddr::V4(_) => *ip,
    }
}

/// Addresses that say nothing about where someone is, so they're "unknown"
/// without a lookup: private networks, this computer, link-local, carrier-
/// grade NAT (where Tailscale puts its devices), unique local IPv6 (where
/// WireGuard and Tailscale put theirs), and the like.
pub fn unknown_range(ip: &IpAddr) -> bool {
    match unmapped(ip) {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
                || a == 0
                // 100.64.0.0/10: carrier-grade NAT, and Tailscale.
                || (a == 100 && (64..128).contains(&b))
                // 240.0.0.0/4: reserved.
                || a >= 240
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // fe80::/10, link-local.
                || (first & 0xffc0) == 0xfe80
                // fc00::/7, unique local.
                || (first & 0xfe00) == 0xfc00
        }
    }
}

/// How many addresses' answers are kept, so a page of events doesn't read the
/// file again for the same address. Forgotten all at once when full, and when
/// the file changes.
const CACHE_SIZE: usize = 4096;

/// How often the file's modified time is checked for a new database.
const RECHECK: Duration = Duration::from_secs(60);

struct State {
    db: Option<Arc<Database>>,
    path: PathBuf,
    stamp: Option<(SystemTime, u64)>,
    checked: Option<Instant>,
    cache: HashMap<IpAddr, Option<Location>>,
}

static STATE: LazyLock<Mutex<State>> = LazyLock::new(|| {
    Mutex::new(State {
        db: None,
        path: PathBuf::new(),
        stamp: None,
        checked: None,
        cache: HashMap::new(),
    })
});

impl State {
    /// Opens the database, or a new one in its place, at most once a minute.
    fn refresh(&mut self, path: &Path) {
        if self.path == path && self.checked.is_some_and(|at| at.elapsed() < RECHECK) {
            return;
        }
        self.checked = Some(Instant::now());
        let stamp = std::fs::metadata(path).ok().map(|m| (m.modified().unwrap_or(SystemTime::UNIX_EPOCH), m.len()));
        if self.path == path && stamp == self.stamp {
            return;
        }
        self.path = path.to_path_buf();
        self.stamp = stamp;
        self.cache.clear();
        self.db = match stamp {
            None => None,
            Some(_) => match Database::open(path) {
                Ok(db) => {
                    info!("IP location database loaded: {}", path.display());
                    Some(Arc::new(db))
                }
                Err(e) => {
                    warn!("IP location database {} can't be read, so no locations are shown: {e}", path.display());
                    None
                }
            },
        };
    }
}

/// Where a lookup reads from: the file in place, or bytes in a test.
trait Source: Send + Sync {
    fn size(&self) -> u64;
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()>;
}

impl Source for Vec<u8> {
    fn size(&self) -> u64 {
        self.len() as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(offset).map_err(|_| io::ErrorKind::UnexpectedEof)?;
        let end = start.checked_add(buf.len()).ok_or(io::ErrorKind::UnexpectedEof)?;
        buf.copy_from_slice(self.get(start..end).ok_or(io::ErrorKind::UnexpectedEof)?);
        Ok(())
    }
}

struct FileSource {
    file: File,
    size: u64,
}

impl Source for FileSource {
    fn size(&self) -> u64 {
        self.size
    }

    #[cfg(unix)]
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        use std::os::unix::fs::FileExt;
        self.file.read_exact_at(buf, offset)
    }

    #[cfg(windows)]
    fn read_at(&self, mut offset: u64, mut buf: &mut [u8]) -> io::Result<()> {
        use std::os::windows::fs::FileExt;
        while !buf.is_empty() {
            match self.file.seek_read(buf, offset)? {
                0 => return Err(io::ErrorKind::UnexpectedEof.into()),
                n => {
                    buf = &mut buf[n..];
                    offset += n as u64;
                }
            }
        }
        Ok(())
    }
}

/// What can go wrong reading a database: it isn't one, or it's damaged.
#[derive(Debug)]
pub struct Bad(&'static str);

impl std::fmt::Display for Bad {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl From<io::Error> for Bad {
    fn from(_: io::Error) -> Self {
        Bad("the file ends too soon")
    }
}

type Result<T> = std::result::Result<T, Bad>;

/// The metadata's start: this marker, then a map (the specification's).
const MARKER: &[u8] = b"\xAB\xCD\xEFMaxMind.com";
/// The metadata is within the file's last 128 KiB.
const METADATA_MAX: u64 = 128 * 1024;
/// A lookup reads the file a page at a time.
const PAGE: u64 = 4096;
/// The deepest a value may nest, and the most values one decode makes, so a
/// damaged file can't make a lookup run away.
const MAX_DEPTH: u32 = 32;
const MAX_VALUES: usize = 20_000;
const MAX_STRING: usize = 64 * 1024;

pub struct Database {
    source: Box<dyn Source>,
    node_count: u32,
    record_size: u16,
    ip_version: u16,
    data_start: u64,
    /// Where IPv4 addresses start in an IPv6 tree: 96 zero bits down.
    ipv4_start: u32,
}

#[derive(Debug, Clone, PartialEq)]
enum V {
    Map(Vec<(String, V)>),
    Array(Vec<V>),
    Str(String),
    Uint(u128),
    Int(i32),
    Double(f64),
    Float(f32),
    Bool(bool),
    Bytes(Vec<u8>),
}

impl V {
    fn get(&self, key: &str) -> Option<&V> {
        match self {
            V::Map(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    fn str(&self) -> Option<&str> {
        match self {
            V::Str(s) => Some(s),
            _ => None,
        }
    }

    fn uint(&self) -> Option<u128> {
        match self {
            V::Uint(n) => Some(*n),
            _ => None,
        }
    }
}

/// Reads one lookup's bytes, a page at a time, each page once.
struct Reader<'a> {
    source: &'a dyn Source,
    pages: HashMap<u64, Vec<u8>>,
    values: usize,
}

impl<'a> Reader<'a> {
    fn new(source: &'a dyn Source) -> Self {
        Self {
            source,
            pages: HashMap::new(),
            values: 0,
        }
    }

    fn bytes(&mut self, pos: u64, n: usize) -> Result<Vec<u8>> {
        let end = pos.checked_add(n as u64).ok_or(Bad("an offset past the file"))?;
        if end > self.source.size() {
            return Err(Bad("an offset past the file"));
        }
        let mut out = Vec::with_capacity(n);
        let mut at = pos;
        while at < end {
            let page = at / PAGE;
            if !self.pages.contains_key(&page) {
                let start = page * PAGE;
                let len = usize::try_from(PAGE.min(self.source.size() - start)).map_err(|_| Bad("a page too large"))?;
                let mut buf = vec![0u8; len];
                self.source.read_at(start, &mut buf)?;
                self.pages.insert(page, buf);
            }
            let buf = &self.pages[&page];
            // Both within one page, so they fit.
            let from = usize::try_from(at - page * PAGE).unwrap_or(0);
            let to = usize::try_from(end - page * PAGE).unwrap_or(usize::MAX).min(buf.len());
            out.extend_from_slice(&buf[from..to]);
            at = page * PAGE + to as u64;
        }
        Ok(out)
    }

    fn byte(&mut self, pos: u64) -> Result<u8> {
        Ok(self.bytes(pos, 1)?[0])
    }

    fn be(&mut self, pos: u64, n: usize) -> Result<u128> {
        Ok(self.bytes(pos, n)?.iter().fold(0u128, |acc, b| (acc << 8) | u128::from(*b)))
    }

    /// The value at `pos`, and where the next one starts. Pointers are
    /// offsets from `base`: the data section's start, or the metadata's.
    fn decode(&mut self, pos: u64, base: u64, depth: u32) -> Result<(V, u64)> {
        if depth > MAX_DEPTH {
            return Err(Bad("values nested too deep"));
        }
        self.values += 1;
        if self.values > MAX_VALUES {
            return Err(Bad("too many values"));
        }
        let ctrl = self.byte(pos)?;
        let mut pos = pos + 1;
        let mut kind = ctrl >> 5;
        if kind == 1 {
            let extra = usize::from((ctrl >> 3) & 3);
            let low = u128::from(ctrl & 7);
            let raw = self.be(pos, extra + 1)?;
            let target = match extra {
                0 => (low << 8) | raw,
                1 => ((low << 16) | raw) + 2048,
                2 => ((low << 24) | raw) + 526_336,
                _ => raw,
            };
            pos += extra as u64 + 1;
            let target = base.checked_add(u64::try_from(target).map_err(|_| Bad("a pointer past the file"))?);
            let (value, _) = self.decode(target.ok_or(Bad("a pointer past the file"))?, base, depth + 1)?;
            return Ok((value, pos));
        }
        if kind == 0 {
            kind = self.byte(pos)?.checked_add(7).ok_or(Bad("a type it doesn't know"))?;
            pos += 1;
            if kind < 8 {
                return Err(Bad("a type it doesn't know"));
            }
        }
        let mut size = u64::from(ctrl & 0x1f);
        if size >= 29 {
            let n = usize::from(ctrl & 0x1f) - 28;
            let raw = u64::try_from(self.be(pos, n)?).map_err(|_| Bad("a size too large"))?;
            size = match n {
                1 => 29 + raw,
                2 => 285 + raw,
                _ => 65_821 + raw,
            };
            pos += n as u64;
        }
        let size_usize = usize::try_from(size).map_err(|_| Bad("a value too large"))?;
        let value = match kind {
            2 => {
                if size_usize > MAX_STRING {
                    return Err(Bad("a string too long"));
                }
                let raw = self.bytes(pos, size_usize)?;
                pos += size;
                V::Str(String::from_utf8(raw).map_err(|_| Bad("a string that isn't UTF-8"))?)
            }
            3 => {
                if size != 8 {
                    return Err(Bad("a double that isn't 8 bytes"));
                }
                let raw = self.bytes(pos, 8)?;
                pos += 8;
                V::Double(f64::from_be_bytes(raw.try_into().map_err(|_| Bad("a short double"))?))
            }
            4 => {
                if size_usize > MAX_STRING {
                    return Err(Bad("bytes too long"));
                }
                let raw = self.bytes(pos, size_usize)?;
                pos += size;
                V::Bytes(raw)
            }
            5 | 6 | 9 | 10 => {
                let max = match kind {
                    5 => 2,
                    6 => 4,
                    9 => 8,
                    _ => 16,
                };
                if size_usize > max {
                    return Err(Bad("an unsigned number too long"));
                }
                let n = self.be(pos, size_usize)?;
                pos += size;
                V::Uint(n)
            }
            7 => {
                let mut pairs = Vec::new();
                for _ in 0..size {
                    let (key, next) = self.decode(pos, base, depth + 1)?;
                    let V::Str(key) = key else {
                        return Err(Bad("a map key that isn't a string"));
                    };
                    let (value, next) = self.decode(next, base, depth + 1)?;
                    pairs.push((key, value));
                    pos = next;
                }
                V::Map(pairs)
            }
            8 => {
                if size_usize > 4 {
                    return Err(Bad("a signed number too long"));
                }
                let n = u32::try_from(self.be(pos, size_usize)?).map_err(|_| Bad("a signed number too long"))?;
                pos += size;
                V::Int(n.cast_signed())
            }
            11 => {
                let mut items = Vec::new();
                for _ in 0..size {
                    let (item, next) = self.decode(pos, base, depth + 1)?;
                    items.push(item);
                    pos = next;
                }
                V::Array(items)
            }
            14 => match size {
                0 => V::Bool(false),
                1 => V::Bool(true),
                _ => return Err(Bad("a boolean that isn't 0 or 1")),
            },
            15 => {
                if size != 4 {
                    return Err(Bad("a float that isn't 4 bytes"));
                }
                let raw = self.bytes(pos, 4)?;
                pos += 4;
                V::Float(f32::from_be_bytes(raw.try_into().map_err(|_| Bad("a short float"))?))
            }
            _ => return Err(Bad("a type it doesn't know")),
        };
        Ok((value, pos))
    }
}

impl Database {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).map_err(|_| Bad("the file can't be opened"))?;
        let size = file.metadata().map_err(|_| Bad("the file can't be read"))?.len();
        Self::from_source(Box::new(FileSource {
            file,
            size,
        }))
    }

    fn from_source(source: Box<dyn Source>) -> Result<Self> {
        let size = source.size();
        let tail_start = size.saturating_sub(METADATA_MAX);
        let mut tail = vec![0u8; usize::try_from(size - tail_start).map_err(|_| Bad("the file can't be read"))?];
        source.read_at(tail_start, &mut tail)?;
        let at = tail.windows(MARKER.len()).rposition(|w| w == MARKER).ok_or(Bad("it isn't a MaxMind DB file"))?;
        let metadata_start = tail_start + (at + MARKER.len()) as u64;

        let mut reader = Reader::new(source.as_ref());
        let (meta, _) = reader.decode(metadata_start, metadata_start, 0)?;
        let number = |key: &str| meta.get(key).and_then(V::uint);
        if number("binary_format_major_version") != Some(2) {
            return Err(Bad("a format version it doesn't read"));
        }
        let node_count = number("node_count").and_then(|n| u32::try_from(n).ok()).ok_or(Bad("no node count"))?;
        let record_size =
            number("record_size").and_then(|n| u16::try_from(n).ok()).filter(|n| matches!(n, 24 | 28 | 32));
        let record_size = record_size.ok_or(Bad("a record size it doesn't read"))?;
        let ip_version = number("ip_version").and_then(|n| u16::try_from(n).ok()).filter(|n| matches!(n, 4 | 6));
        let ip_version = ip_version.ok_or(Bad("an IP version it doesn't read"))?;
        let tree_size = u64::from(node_count) * u64::from(record_size) * 2 / 8;
        let data_start = tree_size + 16;
        if data_start > metadata_start {
            return Err(Bad("a search tree larger than the file"));
        }
        drop(reader);

        let mut db = Self {
            source,
            node_count,
            record_size,
            ip_version,
            data_start,
            ipv4_start: 0,
        };
        if ip_version == 6 {
            let mut reader = Reader::new(db.source.as_ref());
            let mut node = 0u32;
            for _ in 0..96 {
                if node >= node_count {
                    break;
                }
                node = db.child(&mut reader, node, 0)?;
            }
            db.ipv4_start = node;
        }
        Ok(db)
    }

    /// A node's left (0) or right (1) record.
    fn child(&self, reader: &mut Reader<'_>, node: u32, bit: u8) -> Result<u32> {
        let width = u64::from(self.record_size) * 2 / 8;
        let raw = reader.bytes(u64::from(node) * width, width as usize)?;
        let u24 = |b: &[u8]| (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        Ok(match (self.record_size, bit) {
            (24, 0) => u24(&raw[0..3]),
            (24, _) => u24(&raw[3..6]),
            (28, 0) => ((u32::from(raw[3]) & 0xf0) << 20) | u24(&raw[0..3]),
            (28, _) => ((u32::from(raw[3]) & 0x0f) << 24) | u24(&raw[4..7]),
            (_, 0) => u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]),
            _ => u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]),
        })
    }

    /// The record for an address, or None when the database doesn't have it.
    fn record(&self, ip: &IpAddr) -> Result<Option<V>> {
        let (bits, count, start): (u128, u32, u32) = match unmapped(ip) {
            IpAddr::V4(v4) => (u128::from(u32::from(v4)), 32, self.ipv4_start),
            IpAddr::V6(_) if self.ip_version == 4 => return Ok(None),
            IpAddr::V6(v6) => (u128::from(v6), 128, 0),
        };
        let mut reader = Reader::new(self.source.as_ref());
        let mut node = start;
        for i in 0..count {
            if node >= self.node_count {
                break;
            }
            let bit = ((bits >> (count - 1 - i)) & 1) as u8;
            node = self.child(&mut reader, node, bit)?;
        }
        if node <= self.node_count {
            // Equal: not in the database. Less: the address ran out first,
            // which a well-made tree never does.
            return Ok(None);
        }
        let offset = u64::from(node - self.node_count) - 16;
        let (value, _) = reader.decode(self.data_start + offset, self.data_start, 0)?;
        Ok(Some(value))
    }

    /// Where an address is: the country's English name (or its code), and
    /// the city's when there is one.
    pub fn lookup(&self, ip: &IpAddr) -> Result<Option<Location>> {
        let Some(record) = self.record(ip)? else {
            return Ok(None);
        };
        let name = |v: Option<&V>| {
            v.and_then(|v| v.get("names"))
                .and_then(|n| n.get("en"))
                .and_then(V::str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        };
        let country_v = record.get("country");
        let country = name(country_v).or_else(|| {
            country_v.and_then(|c| c.get("iso_code")).and_then(V::str).filter(|s| !s.is_empty()).map(str::to_owned)
        });
        let Some(country) = country else {
            return Ok(None);
        };
        Ok(Some(Location {
            country,
            city: name(record.get("city")),
        }))
    }
}

#[cfg(test)]
pub mod tests {
    //! A tiny database made here, the way a real one is laid out, so the
    //! reader is checked against the specification rather than against
    //! itself alone: each record size, IPv4 in an IPv6 tree and in an IPv4
    //! one, pointers, and addresses it doesn't have.

    use super::*;

    /// One entry: a network, and the country and city (if any) for it.
    pub struct Entry<'a> {
        pub network: &'a str,
        pub country: &'a str,
        pub iso: &'a str,
        pub city: Option<&'a str>,
    }

    fn ctrl(out: &mut Vec<u8>, kind: u8, size: usize) {
        let (first, extra): (u8, Vec<u8>) = if size < 29 {
            (size as u8, vec![])
        } else if size < 285 {
            (29, vec![(size - 29) as u8])
        } else {
            let n = size - 285;
            (30, vec![(n >> 8) as u8, n as u8])
        };
        if kind <= 7 {
            out.push((kind << 5) | first);
        } else {
            out.push(first);
            out.push(kind - 7);
        }
        out.extend(extra);
    }

    fn string(out: &mut Vec<u8>, s: &str) {
        ctrl(out, 2, s.len());
        out.extend(s.as_bytes());
    }

    fn uint(out: &mut Vec<u8>, kind: u8, n: u64) {
        let bytes: Vec<u8> = n.to_be_bytes().into_iter().skip_while(|b| *b == 0).collect();
        ctrl(out, kind, bytes.len());
        out.extend(bytes);
    }

    /// A pointer (the shortest form) to an offset in its section.
    fn pointer(out: &mut Vec<u8>, to: usize) {
        assert!(to < 2048);
        out.push(0b0010_0000 | ((to >> 8) as u8 & 7));
        out.push(to as u8);
    }

    /// A database in the MaxMind DB format, IPv6 or IPv4, with this record size.
    pub fn build(entries: &[Entry<'_>], ip_version: u16, record_size: u16) -> Vec<u8> {
        // The data section: "en" once, pointed to from every names map.
        let mut data = Vec::new();
        let en_at = data.len();
        string(&mut data, "en");
        let mut offsets = Vec::new();
        for e in entries {
            offsets.push(data.len());
            let names = |data: &mut Vec<u8>, name: &str| {
                ctrl(data, 7, 1);
                pointer(data, en_at);
                string(data, name);
            };
            ctrl(
                &mut data,
                7,
                if e.city.is_some() {
                    3
                } else {
                    2
                },
            );
            if let Some(city) = e.city {
                string(&mut data, "city");
                ctrl(&mut data, 7, 1);
                string(&mut data, "names");
                names(&mut data, city);
            }
            string(&mut data, "country");
            ctrl(&mut data, 7, 2);
            string(&mut data, "iso_code");
            string(&mut data, e.iso);
            string(&mut data, "names");
            names(&mut data, e.country);
            // Something the reader must skip: coordinates, as a double.
            string(&mut data, "location");
            ctrl(&mut data, 7, 1);
            string(&mut data, "latitude");
            ctrl(&mut data, 3, 8);
            data.extend(52.52f64.to_be_bytes());
        }

        // The tree: nodes as [left, right], where a child is a node, "none",
        // or a record (index into `offsets`).
        #[derive(Clone, Copy)]
        enum C {
            Node(usize),
            Empty,
            Rec(usize),
        }
        let mut nodes: Vec<[C; 2]> = vec![[C::Empty, C::Empty]];
        let bits = if ip_version == 6 {
            128
        } else {
            32
        };
        for (i, e) in entries.iter().enumerate() {
            let (addr, len) = e.network.split_once('/').unwrap();
            let len: u32 = len.parse().unwrap();
            let ip: IpAddr = addr.parse().unwrap();
            let (value, len) = match ip {
                IpAddr::V4(v4) if ip_version == 6 => (u128::from(u32::from(v4)), len + 96),
                IpAddr::V4(v4) => (u128::from(u32::from(v4)) << 96, len),
                IpAddr::V6(v6) => (u128::from(v6), len),
            };
            let value = if ip_version == 4 {
                value >> 96
            } else {
                value
            };
            let mut node = 0;
            for depth in 0..len {
                let bit = ((value >> (bits - 1 - depth)) & 1) as usize;
                if depth == len - 1 {
                    nodes[node][bit] = C::Rec(i);
                } else {
                    node = match nodes[node][bit] {
                        C::Node(n) => n,
                        _ => {
                            nodes.push([C::Empty, C::Empty]);
                            let n = nodes.len() - 1;
                            nodes[node][bit] = C::Node(n);
                            n
                        }
                    };
                }
            }
        }
        let count = nodes.len() as u32;
        let value_of = |c: C| match c {
            C::Node(n) => n as u32,
            C::Empty => count,
            C::Rec(i) => count + 16 + offsets[i] as u32,
        };
        let mut out = Vec::new();
        for [l, r] in &nodes {
            let (l, r) = (value_of(*l), value_of(*r));
            match record_size {
                24 => {
                    out.extend(&l.to_be_bytes()[1..]);
                    out.extend(&r.to_be_bytes()[1..]);
                }
                28 => {
                    out.extend(&l.to_be_bytes()[1..]);
                    out.push((((l >> 24) & 0x0f) << 4) as u8 | ((r >> 24) & 0x0f) as u8);
                    out.extend(&r.to_be_bytes()[1..]);
                }
                _ => {
                    out.extend(l.to_be_bytes());
                    out.extend(r.to_be_bytes());
                }
            }
        }
        out.extend([0u8; 16]);
        out.extend(data);
        out.extend(MARKER);
        let mut meta = Vec::new();
        ctrl(&mut meta, 7, 5);
        string(&mut meta, "binary_format_major_version");
        uint(&mut meta, 5, 2);
        string(&mut meta, "node_count");
        uint(&mut meta, 6, u64::from(count));
        string(&mut meta, "record_size");
        uint(&mut meta, 5, u64::from(record_size));
        string(&mut meta, "ip_version");
        uint(&mut meta, 5, u64::from(ip_version));
        string(&mut meta, "database_type");
        string(&mut meta, "PassBundle-Test-Location");
        out.extend(meta);
        out
    }

    fn sample() -> Vec<Entry<'static>> {
        vec![
            Entry {
                network: "203.0.113.0/24",
                country: "Germany",
                iso: "DE",
                city: Some("Berlin"),
            },
            Entry {
                network: "198.51.100.0/25",
                country: "Canada",
                iso: "CA",
                city: None,
            },
            Entry {
                network: "2001:db8:5::/48",
                country: "Japan",
                iso: "JP",
                city: Some("Osaka"),
            },
        ]
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn a_tiny_database_answers_for_each_record_size() {
        for record_size in [24, 28, 32] {
            let db = Database::from_source(Box::new(build(&sample(), 6, record_size))).unwrap();
            let at = |s: &str| db.lookup(&ip(s)).unwrap().map(|l| l.display());
            assert_eq!(at("203.0.113.7").as_deref(), Some("Berlin, Germany"), "{record_size}");
            assert_eq!(at("::ffff:203.0.113.200").as_deref(), Some("Berlin, Germany"), "{record_size}");
            assert_eq!(at("198.51.100.4").as_deref(), Some("Canada"), "{record_size}");
            // The /25's other half isn't in it.
            assert_eq!(at("198.51.100.200"), None, "{record_size}");
            assert_eq!(at("2001:db8:5:1::9").as_deref(), Some("Osaka, Japan"), "{record_size}");
            assert_eq!(at("2001:db8:6::1"), None, "{record_size}");
            assert_eq!(at("192.0.2.1"), None, "{record_size}");
        }
    }

    #[test]
    fn an_ipv4_database_has_no_ipv6() {
        let entries: Vec<_> = sample().into_iter().filter(|e| !e.network.contains(':')).collect();
        let db = Database::from_source(Box::new(build(&entries, 4, 24))).unwrap();
        assert_eq!(db.lookup(&ip("203.0.113.7")).unwrap().unwrap().display(), "Berlin, Germany");
        assert_eq!(db.lookup(&ip("2001:db8:5::1")).unwrap(), None);
    }

    #[test]
    fn what_isnt_a_database_is_refused() {
        assert!(Database::from_source(Box::new(b"not a database".to_vec())).is_err());
        assert!(Database::from_source(Box::new(Vec::new())).is_err());
        // Metadata whose tree would be larger than the file.
        let mut file = MARKER.to_vec();
        ctrl(&mut file, 7, 4);
        string(&mut file, "binary_format_major_version");
        uint(&mut file, 5, 2);
        string(&mut file, "node_count");
        uint(&mut file, 6, 1_000_000);
        string(&mut file, "record_size");
        uint(&mut file, 5, 24);
        string(&mut file, "ip_version");
        uint(&mut file, 5, 6);
        assert!(Database::from_source(Box::new(file)).is_err());
        // A record size the format doesn't have.
        let mut db = build(&sample(), 6, 24);
        let at = db.windows(11).rposition(|w| w == b"record_size").unwrap();
        db[at + 12] = 20;
        assert!(Database::from_source(Box::new(db)).is_err());
    }

    #[test]
    fn a_damaged_value_is_an_error_not_a_hang() {
        let source = vec![0b0010_0000u8, 0x00];
        let mut reader = Reader::new(&source);
        // A pointer to itself: refused once it nests too deep.
        assert!(reader.decode(0, 0, 0).is_err());
    }

    #[test]
    fn private_local_and_vpn_addresses_are_unknown() {
        for s in [
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.10",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "100.127.255.254",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "::1",
            "::",
            "fe80::1",
            "fd7a:115c:a1e0::1",
            "fc00::1",
            "ff02::1",
            "::ffff:192.168.1.10",
        ] {
            assert!(unknown_range(&ip(s)), "{s}");
        }
        for s in ["203.0.113.7", "8.8.8.8", "100.128.0.1", "172.32.0.1", "2001:db8::1", "2606:4700::1111"] {
            assert!(!unknown_range(&ip(s)), "{s}");
        }
    }

    #[test]
    fn a_location_is_shown_as_city_and_country_or_country() {
        let berlin = Location {
            country: "Germany".into(),
            city: Some("Berlin".into()),
        };
        assert_eq!(berlin.display(), "Berlin, Germany");
        let canada = Location {
            country: "Canada".into(),
            city: None,
        };
        assert_eq!(canada.display(), "Canada");
    }

    /// Against a real database, by hand: KK_REAL_IP_LOCATION=<a DB-IP Lite
    /// .mmdb> cargo test real_database -- --ignored
    #[test]
    #[ignore = "needs a real database file, named by KK_REAL_IP_LOCATION"]
    fn a_real_database_reads() {
        let path = std::env::var("KK_REAL_IP_LOCATION").expect("KK_REAL_IP_LOCATION");
        let db = Database::open(Path::new(&path)).unwrap();
        for (address, country) in [
            ("8.8.8.8", "United States"),
            ("2001:4860:4860::8888", "United States"),
            ("::ffff:8.8.4.4", "United States"),
        ] {
            let found = db.lookup(&ip(address)).unwrap().unwrap();
            assert_eq!(found.country, country, "{address}: {found:?}");
        }
        assert!(db.lookup(&ip("193.0.6.139")).unwrap().is_some());
    }

    #[test]
    fn the_file_is_read_in_place() {
        let dir = std::env::temp_dir().join(format!("kk-location-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ip-location.mmdb");
        std::fs::write(&path, build(&sample(), 6, 28)).unwrap();
        let db = Database::open(&path).unwrap();
        assert_eq!(db.lookup(&ip("203.0.113.9")).unwrap().unwrap().display(), "Berlin, Germany");
        std::fs::remove_dir_all(&dir).ok();
        assert!(Database::open(&dir.join("missing.mmdb")).is_err());
    }
}
