//! Microsoft Defender, for forensics: its detection history
//! (`ProgramData\Microsoft\Windows Defender\Scans\History\Service\
//! DetectionHistory\<n>\<GUID>`), one file per detection: the threat's
//! name and category, the files, registry keys and processes it was found
//! in, the user and process involved, when, and the file's SHA-256.
//!
//! The file is a list of typed values (a size, a type, the data, padding
//! to 8 bytes), in sets separated by the string `Magic.Version:1.2`: the
//! detection's identifiers, then the threat, then one set per resource
//! (its type and location, and key/value tracking data: start time, file
//! name, SHA-256, …), as libyal's dtformats documents it.
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let detection = defender::read(&std::fs::read("DetectionHistory/02/6AFE33A0-19BA-4FFF-892F-B700539D7D63")?)?;
//! for resource in &detection.resources {
//!     println!("{:?} in {} {}", detection.threat_name, resource.kind, resource.location);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Damage is reported in `problems`, never a panic.
//!
//! [`read_mplog`] reads the protection logs (`Support\MPLog-*.log`):
//! detections, programs scanned, exclusions, blocked files, behaviour
//! monitoring telemetry.

use common::time::Ts;

mod mplog;

pub use mplog::{is_mplog_name, read_mplog, Entry, EntryKind, MpLog};

/// This crate's version, for records of what parsed them.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The value separating the sets.
const SEPARATOR: &str = "Magic.Version:1.2";
/// Where the first separator is, a file's signature (after an integer and
/// a GUID).
const SIGNATURE_AT: usize = 0x30;

// Value types.
const INTEGERS_32: [u32; 3] = [0x00, 0x05, 0x06];
const INTEGER_64: u32 = 0x08;
const FILETIME: u32 = 0x0A;
const STRING: u32 = 0x15;
const GUID: u32 = 0x1E;

/// A detection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Detection {
    /// The detection's identifier (a GUID, also the file's name).
    pub id: Option<String>,
    /// The threat's name (`Virus:DOS/EICAR_Test_File`).
    pub threat_name: Option<String>,
    /// The threat's category number (see [`Detection::category_name`]).
    pub category: Option<u64>,
    /// Where it was found.
    pub resources: Vec<Resource>,
    /// The user involved (`DOMAIN\user`).
    pub user: Option<String>,
    /// The process involved (its path, or `Unknown`).
    pub process: Option<String>,
    /// When the threat's status last changed (UTC).
    pub status_changed: Option<Ts>,
    /// When it was first detected (UTC).
    pub initial_detection: Option<Ts>,
    /// When it was remediated (UTC).
    pub remediation: Option<Ts>,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

/// Where a threat was found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Resource {
    /// Its type: `file`, `containerfile`, `webfile`, `process`, `regkey`,
    /// `CmdLine`, ….
    pub kind: String,
    /// A path, key or command line (a `webfile` adds `|<URL>|pid:…`).
    pub location: String,
    /// Its tracking data's keys and values (`ThreatTrackingStartTime`,
    /// `ThreatTrackingSha256`, `ThreatTrackingId`, …), integers in decimal.
    pub tracking: Vec<(String, String)>,
}

impl Detection {
    /// A tracking value by key (`ThreatTrackingSha256`), from the last
    /// resource tracking it, as plaso reads it.
    #[must_use]
    pub fn tracking(&self, key: &str) -> Option<&str> {
        self.resources.iter().rev().find_map(|resource| {
            resource
                .tracking
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
        })
    }

    /// The tracking data's start time (UTC), as plaso dates a detection.
    #[must_use]
    pub fn start_time(&self) -> Option<Ts> {
        let ticks: u64 = self.tracking("ThreatTrackingStartTime")?.parse().ok()?;
        filetime(ticks)
    }

    /// The SHA-256 of the file detected, if tracked.
    #[must_use]
    pub fn sha256(&self) -> Option<&str> {
        self.tracking("ThreatTrackingSha256")
    }

    /// The category's name (`VIRUS`, `TROJAN`, `RANSOM`, …), as
    /// `Get-MpThreatCatalog` lists them.
    #[must_use]
    pub fn category_name(&self) -> Option<&'static str> {
        const NAMES: [&str; 52] = [
            "INVALID",
            "ADWARE",
            "SPYWARE",
            "PASSWORDSTEALER",
            "TROJANDOWNLOADER",
            "WORM",
            "BACKDOOR",
            "REMOTEACCESSTROJAN",
            "TROJAN",
            "EMAILFLOODER",
            "KEYLOGGER",
            "DIALER",
            "MONITORINGSOFTWARE",
            "BROWSERMODIFIER",
            "COOKIE",
            "BROWSERPLUGIN",
            "AOLEXPLOIT",
            "NUKER",
            "SECURITYDISABLER",
            "JOKEPROGRAM",
            "HOSTILEACTIVEXCONTROL",
            "SOFTWAREBUNDLER",
            "STEALTHNOTIFIER",
            "SETTINGSMODIFIER",
            "TOOLBAR",
            "REMOTECONTROLSOFTWARE",
            "TROJANFTP",
            "POTENTIALUNWANTEDSOFTWARE",
            "ICQEXPLOIT",
            "TROJANTELNET",
            "EXPLOIT",
            "FILESHARINGPROGRAM",
            "MALWARE_CREATION_TOOL",
            "REMOTE_CONTROL_SOFTWARE",
            "TOOL",
            "",
            "TROJAN_DENIALOFSERVICE",
            "TROJAN_DROPPER",
            "TROJAN_MASSMAILER",
            "TROJAN_MONITORINGSOFTWARE",
            "TROJAN_PROXYSERVER",
            "",
            "VIRUS",
            "KNOWN",
            "UNKNOWN",
            "SPP",
            "BEHAVIOR",
            "VULNERABILITY",
            "POLICY",
            "EUS",
            "RANSOM",
            "ASR",
        ];
        let name = *NAMES.get(usize::try_from(self.category?).ok()?)?;
        (!name.is_empty()).then_some(name)
    }
}

/// Why a file can't be read as a detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// Whether `head` starts like a detection history file (its first
/// separator at offset 0x30).
#[must_use]
pub fn detect(head: &[u8]) -> bool {
    let signature: Vec<u8> = SEPARATOR
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    head.get(SIGNATURE_AT..SIGNATURE_AT + signature.len()) == Some(&signature[..])
}

/// A value of the file.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Item {
    Integer(u64),
    Time(u64),
    Text(String),
    Guid(String),
    Bytes(Vec<u8>),
}

impl Item {
    fn text(&self) -> String {
        match self {
            Self::Integer(n) | Self::Time(n) => n.to_string(),
            Self::Text(t) | Self::Guid(t) => t.clone(),
            Self::Bytes(b) => format!("{} bytes", b.len()),
        }
    }
}

/// Read a detection history file.
///
/// # Errors
/// When it doesn't start like one.
pub fn read(data: &[u8]) -> Result<Detection, Error> {
    if !detect(data) {
        return Err(Error(
            "no Magic.Version:1.2 at offset 0x30: not a detection history file".to_owned(),
        ));
    }
    let mut detection = Detection::default();
    let items = items(data, &mut detection.problems);
    let mut set = 0;
    let mut index = 0;
    let mut resource_type: Option<String> = None;
    for item in &items {
        if matches!(item, Item::Text(t) if t == SEPARATOR) {
            set = (set + 1).min(2);
            index = 0;
        }
        apply(&mut detection, set, index, item, &mut resource_type);
        index += 1;
    }
    Ok(detection)
}

/// Take value `index` of set `set` into the detection.
fn apply(
    detection: &mut Detection,
    set: usize,
    index: usize,
    item: &Item,
    resource_type: &mut Option<String>,
) {
    let time = || match item {
        Item::Time(ticks) => filetime(*ticks),
        _ => None,
    };
    match (set, index, item) {
        (0, 1, Item::Guid(id)) => detection.id = Some(id.clone()),
        (1, 1, Item::Text(name)) => detection.threat_name = Some(name.clone()),
        (1, 4, Item::Integer(category)) => detection.category = Some(*category),
        (2, 1, kind) => *resource_type = Some(kind.text()),
        (2, 2, location) => {
            if let Some(kind) = resource_type.take() {
                detection.resources.push(Resource {
                    kind,
                    location: location.text(),
                    tracking: Vec::new(),
                });
            }
        }
        (2, 5, Item::Bytes(data)) => {
            let Some(resource) = detection.resources.last_mut() else {
                return;
            };
            if let Err(why) = read_tracking(data, &mut resource.tracking) {
                detection.problems.push(format!("tracking data: {why}"));
            }
        }
        (2, 6, _) => detection.status_changed = time().or(detection.status_changed),
        (2, 12, Item::Text(user)) => detection.user = Some(user.clone()),
        (2, 14, Item::Text(process)) => detection.process = Some(process.clone()),
        (2, 18, _) => detection.initial_detection = time().or(detection.initial_detection),
        (2, 20, _) => detection.remediation = time().or(detection.remediation),
        _ => {}
    }
}

/// Every value of the file, up to the first that doesn't read.
fn items(data: &[u8], problems: &mut Vec<String>) -> Vec<Item> {
    let mut items = Vec::new();
    let mut at = 0;
    while at < data.len() {
        let (Some(size), Some(kind)) = (u32_at(data, at), u32_at(data, at + 4)) else {
            problems.push(format!("offset {at:#x}: a value cut short"));
            break;
        };
        let size = size as usize;
        let Some(value) = data.get(at + 8..(at + 8).saturating_add(size)) else {
            problems.push(format!(
                "offset {at:#x}: a value of {size} bytes past the end"
            ));
            break;
        };
        items.push(match kind {
            k if INTEGERS_32.contains(&k) && size == 4 => {
                Item::Integer(u64::from(u32_at(value, 0).unwrap_or(0)))
            }
            INTEGER_64 if size == 8 => Item::Integer(u64_at(value, 0).unwrap_or(0)),
            FILETIME if size == 8 => Item::Time(u64_at(value, 0).unwrap_or(0)),
            STRING => Item::Text(utf16(value)),
            GUID if size == 16 => Item::Guid(guid(value)),
            _ => Item::Bytes(value.to_vec()),
        });
        at = (at + 8 + size).next_multiple_of(8);
    }
    items
}

/// Tracking data: an optional header, then key/value pairs (a key's size
/// and UTF-16 text, a type, the value).
fn read_tracking(data: &[u8], tracking: &mut Vec<(String, String)>) -> Result<(), String> {
    let first = u32_at(data, 0).ok_or("shorter than 4 bytes")? as usize;
    let (mut at, end) = if first == 1 {
        let header = u32_at(data, 4).ok_or("a header cut short")? as usize;
        let total = u32_at(data, 12).ok_or("a header cut short")? as usize;
        (header.saturating_add(4), total)
    } else {
        (4, first)
    };
    let end = end.min(data.len());
    while at < end {
        let key_size = u32_at(data, at).ok_or("a key cut short")? as usize;
        let key = utf16(
            data.get(at + 4..(at + 4).saturating_add(key_size))
                .ok_or("a key past the end")?,
        );
        at += 4 + key_size;
        let kind = u32_at(data, at).ok_or("a type cut short")?;
        at += 4;
        let (value, size) = match kind {
            3 => (u32_at(data, at).map(|v| v.to_string()), 4),
            4 => (u64_at(data, at).map(|v| v.to_string()), 8),
            5 => (data.get(at).map(u8::to_string), 1),
            6 => {
                let size = u32_at(data, at).ok_or("a string's size cut short")? as usize;
                let text = data.get(at + 4..(at + 4).saturating_add(size)).map(utf16);
                (text, 4 + size)
            }
            7 => (data.get(at..at + 5).map(|b| format!("{b:02x?}")), 5),
            other => return Err(format!("{key}: a value of type {other}")),
        };
        tracking.push((key, value.ok_or("a value past the end")?));
        at += size;
    }
    Ok(())
}

/// A FILETIME, `None` when unset.
fn filetime(ticks: u64) -> Option<Ts> {
    let ts = Ts::from_filetime(ticks);
    ts.ticks().is_some().then_some(ts)
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(data: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(data.get(at..at + 8)?.try_into().ok()?))
}

/// UTF-16LE text up to its first NUL.
fn utf16(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// A GUID as Windows writes it, upper case.
fn guid(bytes: &[u8]) -> String {
    let data1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let data2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let data3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    let tail = common::sha256::hex(&bytes[10..16]).to_ascii_uppercase();
    format!(
        "{data1:08X}-{data2:04X}-{data3:04X}-{:02X}{:02X}-{tail}",
        bytes[8], bytes[9]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_aligned_to_eight_bytes() {
        let mut data = Vec::new();
        data.extend(4u32.to_le_bytes());
        data.extend(0u32.to_le_bytes());
        data.extend(7u32.to_le_bytes());
        data.extend([0; 4]);
        data.extend(8u32.to_le_bytes());
        data.extend(FILETIME.to_le_bytes());
        data.extend(132_000_000_000_000_000u64.to_le_bytes());
        let mut problems = Vec::new();
        let items = items(&data, &mut problems);
        assert_eq!(
            items,
            [Item::Integer(7), Item::Time(132_000_000_000_000_000)]
        );
        assert!(problems.is_empty());
    }

    #[test]
    fn tracking_values() {
        let mut data = Vec::new();
        let mut pair = |key: &str, kind: u32, value: &[u8]| {
            let key: Vec<u8> = format!("{key}\0")
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect();
            data.extend((key.len() as u32).to_le_bytes());
            data.extend(key);
            data.extend(kind.to_le_bytes());
            data.extend(value);
        };
        pair("A", 4, &5u64.to_le_bytes());
        let text: Vec<u8> = "x\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut string = (text.len() as u32).to_le_bytes().to_vec();
        string.extend(text);
        pair("B", 6, &string);
        let mut blob = ((data.len() + 4) as u32).to_le_bytes().to_vec();
        blob.extend(&data);
        let mut tracking = Vec::new();
        read_tracking(&blob, &mut tracking).unwrap();
        assert_eq!(
            tracking,
            [
                ("A".to_owned(), "5".to_owned()),
                ("B".to_owned(), "x".to_owned())
            ]
        );
    }

    #[test]
    fn other_files_are_errors() {
        assert!(read(b"not a detection").is_err());
        assert!(read(&[0; 200]).is_err());
    }
}
