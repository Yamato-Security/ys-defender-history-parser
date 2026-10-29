//! Detection history files, read section by section as Orange Cyberdefense's analysis lays them
//! out (`doc.md` of <https://github.com/cert-orangecyberdefense/wddh-parser>, sections 1 to 8,
//! positions counted within each section):
//!
//! 1. the threat's identifier, the detection's, `Magic.Version:1.2` (missing from some Windows
//!    Server 2016 files) and the threat's name;
//! 2. five integers (the threat's severity and category, three not known), the threat's status, a
//!    counted list, the number of resources;
//! 3. the resources: `Magic.Version:1.2`, the type, the location, flags, the tracking data's size
//!    and the tracking data;
//! 4. the last status change, its error code, an integer, the quarantine entry, the execution
//!    status;
//! 5. six values, present only when section 2 starts with `4`;
//! 6. the user, the detection's source, the process, the first detection, the remediation and
//!    twelve values not known, the last of them the number of resources in section 7;
//! 7. more resources, read as section 3's;
//! 8. five values not known.
//!
//! Values whose meaning isn't known are kept in [`Detection::unknown`], by section and position
//! (`2.3`, `6.13`), so nothing read is lost.

use std::fmt;

use crate::time::Time;

/// The value separating the sets.
const SEPARATOR: &str = "Magic.Version:1.2";

// Value types.
const INTEGERS_32: [u32; 2] = [0x00, 0x06];
const SIGNED_32: u32 = 0x05;
const INTEGER_64: u32 = 0x08;
const FILETIME: u32 = 0x0A;
const STRING: u32 = 0x15;
const GUID: u32 = 0x1E;
const BLOB: u32 = 0x28;

/// A value of the file, or of a resource's tracking data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// An unsigned integer.
    Integer(u64),
    /// A signed integer (an error code).
    Signed(i64),
    /// A FILETIME, as stored.
    Time(u64),
    /// A flag.
    Bool(bool),
    /// Text.
    Text(String),
    /// A GUID, upper case, without braces.
    Guid(String),
    /// Bytes not read further.
    Bytes(Vec<u8>),
}

impl Value {
    /// An integer's or a FILETIME's value.
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Integer(n) | Self::Time(n) => Some(*n),
            _ => None,
        }
    }

    /// A text's or a GUID's value.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Text(t) | Self::Guid(t) => Some(t),
            _ => None,
        }
    }
}

impl fmt::Display for Value {
    /// Integers in decimal, a FILETIME in ISO 8601 (as a number when it isn't a time), bytes in
    /// hexadecimal.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Integer(n) => write!(f, "{n}"),
            Self::Signed(n) => write!(f, "{n}"),
            Self::Time(ticks) => match Time::from_filetime(*ticks) {
                Some(time) => write!(f, "{time}"),
                None => write!(f, "{ticks}"),
            },
            Self::Bool(b) => write!(f, "{b}"),
            Self::Text(t) | Self::Guid(t) => f.write_str(t),
            Self::Bytes(bytes) => f.write_str(&hex(bytes)),
        }
    }
}

/// A detection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Detection {
    /// The threat's identifier (`ThreatID`, as `Get-MpThreatCatalog` lists it).
    pub threat_id: Option<u64>,
    /// The detection's identifier (`DetectionID`, a GUID, also the file's name).
    pub id: Option<String>,
    /// The header's `Magic.Version:1.2`, missing from some Windows Server 2016 files.
    pub version: Option<String>,
    /// The threat's name (`Virus:DOS/EICAR_Test_File`).
    pub threat_name: Option<String>,
    /// The threat's severity (see [`Detection::severity_name`]).
    pub severity_id: Option<u32>,
    /// The threat's category (see [`Detection::category_name`]).
    pub category_id: Option<u32>,
    /// The threat's status (`ThreatStatusID`, see [`Detection::threat_status_name`]).
    pub threat_status_id: Option<u32>,
    /// The counted list after the status, meaning not known (`[2, 3, 6]`, `[3, 6]`, …).
    pub list: Vec<u32>,
    /// Where it was found (section 3, then section 7's).
    pub resources: Vec<Resource>,
    /// When the threat's status last changed (`LastThreatStatusChangeTime`).
    pub status_changed: Option<Time>,
    /// The error the status change ended with (`ThreatStatusErrorCode`), 0 for none.
    pub status_error_code: Option<i64>,
    /// The quarantine entry holding what was quarantined (`Quarantine\Entries\{<GUID>}`, as DLEAPP
    /// found on its test machine); `None` when the file holds a zero GUID.
    pub quarantine_id: Option<String>,
    /// Whether the threat was running (`CurrentThreatExecutionStatusID`, see
    /// [`Detection::execution_status_name`]).
    pub execution_status_id: Option<u32>,
    /// The user involved (`DomainUser`, `DOMAIN\user`).
    pub user: Option<String>,
    /// What detected it (`DetectionSourceTypeID`, see [`Detection::source_type_name`]); section
    /// 6's fifth value (`6.4`) has held the same in every file seen.
    pub source_type_id: Option<u32>,
    /// The process involved (`ProcessName`: its path, or `Unknown`).
    pub process: Option<String>,
    /// When it was first detected (`InitialDetectionTime`).
    pub initial_detection: Option<Time>,
    /// When it was remediated (`RemediationTime`).
    pub remediation: Option<Time>,
    /// The values whose meaning isn't known, by section and position (`2.3`, `6.13`); `after.0`,
    /// … for values past the footer, `rest.0`, … for those after a count the file couldn't hold.
    pub unknown: Vec<(String, Value)>,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

/// Where a threat was found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Resource {
    /// Its type: `file`, `containerfile`, `webfile`, `process`, `regkeyvalue`, `service`,
    /// `CmdLine`, `behavior`, `amsi`, ….
    pub kind: String,
    /// A path, key or command line (a `webfile` adds `|<URL>|pid:…`).
    pub location: String,
    /// Flags, meaning not known (0, `0x10000001` or `0x10000002` in the files seen).
    pub flags: Option<u32>,
    /// Its tracking data's keys and values (`ThreatTrackingStartTime`, `ThreatTrackingSha256`,
    /// `ThreatTrackingId`, …).
    pub tracking: Vec<(String, Value)>,
}

impl Detection {
    /// A tracking value by key (`ThreatTrackingSha256`), from the last resource tracking it, as
    /// plaso reads it.
    #[must_use]
    pub fn tracking(&self, key: &str) -> Option<&Value> {
        self.resources.iter().rev().find_map(|resource| {
            resource
                .tracking
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v)
        })
    }

    /// The tracking data's start time, as plaso dates a detection.
    #[must_use]
    pub fn start_time(&self) -> Option<Time> {
        Time::from_filetime(self.tracking("ThreatTrackingStartTime")?.as_u64()?)
    }

    /// The SHA-256 of the file detected, if tracked.
    #[must_use]
    pub fn sha256(&self) -> Option<&str> {
        self.tracking("ThreatTrackingSha256")?.as_str()
    }

    /// The category's name (`VIRUS`, `TROJAN`, `TOOL`, …), as `Get-MpThreatCatalog` lists them.
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
        let name = *NAMES.get(self.category_id? as usize)?;
        (!name.is_empty()).then_some(name)
    }

    /// The severity's name, as `MSFT_MpThreat`'s `SeverityID`: `Low`, `Moderate`, `High`,
    /// `Severe`.
    #[must_use]
    pub fn severity_name(&self) -> Option<&'static str> {
        Some(match self.severity_id? {
            0 => "Unknown",
            1 => "Low",
            2 => "Moderate",
            4 => "High",
            5 => "Severe",
            _ => return None,
        })
    }

    /// The status's name, as `MSFT_MpThreatDetection` documents `ThreatStatusID`: `Detected`,
    /// `Quarantined`, `Removed`, `RemoveFailed`, ….
    #[must_use]
    pub fn threat_status_name(&self) -> Option<&'static str> {
        Some(match self.threat_status_id? {
            0 => "Unknown",
            1 => "Detected",
            2 => "Cleaned",
            3 => "Quarantined",
            4 => "Removed",
            5 => "Allowed",
            6 => "Blocked",
            102 => "QuarantineFailed",
            103 => "RemoveFailed",
            104 => "AllowFailed",
            105 => "Abandoned",
            107 => "BlockedFailed",
            _ => return None,
        })
    }

    /// The execution status's name, as `MSFT_MpThreatDetection` documents
    /// `CurrentThreatExecutionStatusID`: `Unknown`, `Blocked`, `Allowed`, `Executing`,
    /// `NotExecuting`.
    #[must_use]
    pub fn execution_status_name(&self) -> Option<&'static str> {
        Some(match self.execution_status_id? {
            0 => "Unknown",
            1 => "Blocked",
            2 => "Allowed",
            3 => "Executing",
            4 => "NotExecuting",
            _ => return None,
        })
    }

    /// The source's name, as `MSFT_MpThreatDetection` documents `DetectionSourceTypeID`
    /// (`Real-time`, `IOAV` for downloads, …), and 6, 10 and 11 (`IEPROTECT`, `AMSI`, `UAC`) in the
    /// order of the detection sources Microsoft's Defender event documentation lists, which 0 to 9
    /// follow.
    #[must_use]
    pub fn source_type_name(&self) -> Option<&'static str> {
        Some(match self.source_type_id? {
            0 => "Unknown",
            1 => "User",
            2 => "System",
            3 => "Real-time",
            4 => "IOAV",
            5 => "NRI",
            6 => "IEPROTECT",
            7 => "ELAM",
            8 => "LocalAttestation",
            9 => "RemoteAttestation",
            10 => "AMSI",
            11 => "UAC",
            _ => return None,
        })
    }
}

/// Why a file can't be read as a detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// Whether `head` starts like a detection history file: a 64-bit threat identifier, a GUID, then
/// a string (`Magic.Version:1.2`, or the threat's name in files without it).
#[must_use]
pub fn detect(head: &[u8]) -> bool {
    let typed = |at: usize, size: u32, kind: u32| {
        u32_at(head, at) == Some(size) && u32_at(head, at + 4) == Some(kind)
    };
    typed(0, 8, INTEGER_64) && typed(0x10, 16, GUID) && u32_at(head, 0x2C) == Some(STRING)
}

/// Read a detection history file.
///
/// # Errors
/// When it doesn't start like one.
pub fn read(data: &[u8]) -> Result<Detection, Error> {
    if !detect(data) {
        return Err(Error(
            "no threat identifier, GUID and string at its start: not a detection history file"
                .to_owned(),
        ));
    }
    let mut detection = Detection::default();
    let values = values(data, &mut detection.problems);
    let mut reader = Reader {
        values: &values,
        next: 0,
        ended: false,
        detection: &mut detection,
    };
    let complete = reader.read().is_some();
    let after = reader.next;
    // What is left: past the footer, or after a count that couldn't be (said so already).
    let label = if complete { "after" } else { "rest" };
    if complete && after < values.len() {
        detection.problems.push(format!(
            "offset {:#x}: {} values after the footer",
            values[after].at,
            values.len() - after
        ));
    }
    for (i, raw) in values.get(after..).unwrap_or_default().iter().enumerate() {
        detection
            .unknown
            .push((format!("{label}.{i}"), raw.value.clone()));
    }
    Ok(detection)
}

/// A value as stored: where, its type, and what it reads as.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Raw {
    at: usize,
    kind: u32,
    value: Value,
}

/// Every value of the file, up to the first that doesn't read.
fn values(data: &[u8], problems: &mut Vec<String>) -> Vec<Raw> {
    let mut values = Vec::new();
    let mut at = 0;
    while at < data.len() {
        let (Some(size), Some(kind)) = (u32_at(data, at), u32_at(data, at + 4)) else {
            problems.push(format!("offset {at:#x}: a value cut short"));
            break;
        };
        let size = size as usize;
        let Some(bytes) = data.get(at + 8..(at + 8).saturating_add(size)) else {
            problems.push(format!(
                "offset {at:#x}: a value of {size} bytes past the end"
            ));
            break;
        };
        let value = match kind {
            k if INTEGERS_32.contains(&k) && size == 4 => {
                Value::Integer(u64::from(u32_at(bytes, 0).unwrap_or(0)))
            }
            SIGNED_32 if size == 4 => {
                Value::Signed(i64::from(u32_at(bytes, 0).unwrap_or(0) as i32))
            }
            INTEGER_64 if size == 8 => Value::Integer(u64_at(bytes, 0).unwrap_or(0)),
            FILETIME if size == 8 => Value::Time(u64_at(bytes, 0).unwrap_or(0)),
            STRING => {
                let (text, damage) = utf16(bytes);
                if let Some(damage) = damage {
                    problems.push(format!("offset {at:#x}: a string with {damage}"));
                }
                Value::Text(text)
            }
            GUID if size == 16 => Value::Guid(guid(bytes)),
            _ => Value::Bytes(bytes.to_vec()),
        };
        values.push(Raw { at, kind, value });
        // Zero padding to 8 bytes follows every value, the last included.
        let (end, next) = (at + 8 + size, (at + 8 + size).next_multiple_of(8));
        match data.get(end..next) {
            None => {
                problems.push(format!(
                    "offset {at:#x}: its padding cut short ({} of {} bytes)",
                    data.len() - end,
                    next - end
                ));
                break;
            }
            Some(padding) if padding.iter().any(|&b| b != 0) => {
                problems.push(format!("offset {end:#x}: padding that isn't zero"));
            }
            Some(_) => {}
        }
        at = next;
    }
    values
}

/// What a named value must be.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Want {
    U32,
    I32,
    U64,
    Time,
    Text,
    Guid,
    Blob,
}

impl Want {
    fn fits(self, raw: &Raw) -> bool {
        match self {
            Self::U32 => INTEGERS_32.contains(&raw.kind) && matches!(raw.value, Value::Integer(_)),
            Self::I32 => raw.kind == SIGNED_32 && matches!(raw.value, Value::Signed(_)),
            Self::U64 => raw.kind == INTEGER_64 && matches!(raw.value, Value::Integer(_)),
            Self::Time => matches!(raw.value, Value::Time(_)),
            Self::Text => matches!(raw.value, Value::Text(_)),
            Self::Guid => matches!(raw.value, Value::Guid(_)),
            Self::Blob => raw.kind == BLOB,
        }
    }
}

/// Reads the values in order, section by section.
struct Reader<'a> {
    values: &'a [Raw],
    next: usize,
    ended: bool,
    detection: &'a mut Detection,
}

impl Reader<'_> {
    /// The next value, if there is one; past the end, says so once.
    fn take(&mut self, key: &str) -> Option<&Raw> {
        let raw = self.values.get(self.next);
        if raw.is_none() && !self.ended {
            self.ended = true;
            self.detection
                .problems
                .push(format!("the values end before {key}"));
        }
        self.next += usize::from(raw.is_some());
        raw
    }

    /// The next value if it is what `want` says; else it is kept as unknown, with a problem.
    fn want(&mut self, key: &str, want: Want) -> Option<Value> {
        let raw = self.take(key)?.clone();
        if want.fits(&raw) {
            return Some(raw.value);
        }
        self.detection.problems.push(format!(
            "offset {:#x}: {key} has type {:#x}, not the type expected",
            raw.at, raw.kind
        ));
        self.detection.unknown.push((key.to_owned(), raw.value));
        None
    }

    fn integer(&mut self, key: &str) -> Option<u32> {
        self.want(key, Want::U32)?.as_u64().map(|n| n as u32)
    }

    fn text(&mut self, key: &str) -> Option<String> {
        match self.want(key, Want::Text)? {
            Value::Text(text) => Some(text),
            _ => None,
        }
    }

    /// A time; one that isn't (past 9999) is kept as unknown.
    fn time(&mut self, key: &str) -> Option<Time> {
        let ticks = self.want(key, Want::Time)?.as_u64()?;
        let time = Time::from_filetime(ticks);
        if time.is_none() && ticks != 0 {
            self.detection
                .unknown
                .push((key.to_owned(), Value::Time(ticks)));
        }
        time
    }

    /// The next value, kept as unknown.
    fn keep(&mut self, key: &str) -> Option<Value> {
        let value = self.take(key)?.value.clone();
        self.detection.unknown.push((key.to_owned(), value.clone()));
        Some(value)
    }

    /// Whether the next value is the separator.
    fn at_separator(&self) -> bool {
        self.values
            .get(self.next)
            .is_some_and(|raw| matches!(&raw.value, Value::Text(t) if t == SEPARATOR))
    }

    /// A count of what follows, if no more than the values left could hold (each at least `each`
    /// values long).
    fn count(&mut self, key: &str, each: usize) -> Option<usize> {
        let count = self.integer(key)? as usize;
        let left = self.values.len() - self.next;
        if count.saturating_mul(each) > left {
            self.detection.problems.push(format!(
                "{key}: {count} said, more than the {left} values left could hold"
            ));
            self.detection
                .unknown
                .push((key.to_owned(), Value::Integer(count as u64)));
            return None;
        }
        Some(count)
    }

    fn read(&mut self) -> Option<()> {
        // Section 1, the header.
        self.detection.threat_id = self.want("1.0", Want::U64)?.as_u64();
        self.detection.id = self.want("1.1", Want::Guid)?.as_str().map(str::to_owned);
        if self.at_separator() {
            self.detection.version = self.text("1.2");
        }
        self.detection.threat_name = self.text("1.3");

        // Section 2.
        let optional = self.keep("2.0")? == Value::Integer(4);
        self.detection.severity_id = self.integer("2.1");
        self.detection.category_id = self.integer("2.2");
        self.keep("2.3")?;
        self.keep("2.4")?;
        self.detection.threat_status_id = self.integer("2.5");
        let listed = self.count("2.6", 1)?;
        for i in 0..listed {
            let item = self.integer(&format!("2.{}", 7 + i));
            self.detection.list.extend(item);
        }
        let resources = self.count(&format!("2.{}", 7 + listed), 5)?;

        // Section 3.
        for _ in 0..resources {
            self.resource("3")?;
        }

        // Section 4.
        self.detection.status_changed = self.time("4.0");
        self.detection.status_error_code = self.want("4.1", Want::I32).and_then(|v| match v {
            Value::Signed(n) => Some(n),
            _ => None,
        });
        self.keep("4.2")?;
        self.detection.quarantine_id = self
            .want("4.3", Want::Guid)
            .and_then(|v| v.as_str().map(str::to_owned))
            .filter(|guid| guid.bytes().any(|b| !matches!(b, b'0' | b'-')));
        self.detection.execution_status_id = self.integer("4.4");

        // Section 5, only when section 2 starts with 4.
        if optional {
            for i in 0..6 {
                self.keep(&format!("5.{i}"))?;
            }
        }

        // Section 6.
        self.keep("6.0")?;
        self.detection.user = self.text("6.1");
        self.detection.source_type_id = self.integer("6.2");
        self.detection.process = self.text("6.3");
        for i in 4..7 {
            self.keep(&format!("6.{i}"))?;
        }
        self.detection.initial_detection = self.time("6.7");
        self.keep("6.8")?;
        self.detection.remediation = self.time("6.9");
        for i in 10..15 {
            self.keep(&format!("6.{i}"))?;
        }
        let more = self.count("6.15", 5)?;

        // Section 7.
        for _ in 0..more {
            self.resource("7")?;
        }

        // Section 8, the footer.
        for i in 0..5 {
            self.keep(&format!("8.{i}"))?;
        }
        Some(())
    }

    /// A resource of section 3 or 7: the separator, type, location, flags, tracking data's size
    /// and tracking data.
    fn resource(&mut self, section: &str) -> Option<()> {
        if self.at_separator() {
            self.next += 1;
        }
        // text, as the other named values are checked: another type is kept as unknown
        let kind = self.text(&format!("{section}.1"));
        let location = self.text(&format!("{section}.2"));
        if self.ended {
            return None;
        }
        let flags = self.integer(&format!("{section}.3"));
        let size = self.integer(&format!("{section}.4"));
        let mut resource = Resource {
            kind: kind.unwrap_or_default(),
            location: location.unwrap_or_default(),
            flags,
            tracking: Vec::new(),
        };
        if let Some(Value::Bytes(blob)) = self.want(&format!("{section}.5"), Want::Blob) {
            if size.is_some_and(|size| size as usize != blob.len()) {
                self.detection.problems.push(format!(
                    "{section}.4: tracking data of {size:?} bytes said, {} there",
                    blob.len()
                ));
            }
            resource.tracking = read_tracking(&blob, &mut self.detection.problems);
        }
        self.detection.resources.push(resource);
        Some(())
    }
}

/// Tracking data: its size and key/value pairs (a key's size and UTF-16 text, a type, the value),
/// or before them, a header (1, the header's size, the pairs' size, the whole size, 0).
fn read_tracking(data: &[u8], problems: &mut Vec<String>) -> Vec<(String, Value)> {
    let mut tracking = Vec::new();
    if data.is_empty() {
        return tracking;
    }
    let mut notes = Vec::new();
    match read_pairs(data, &mut tracking, &mut notes) {
        Ok(end) if end < data.len() => notes.push(format!(
            "{} bytes after the {end} it declares, not read",
            data.len() - end
        )),
        Ok(_) => {}
        Err(why) => notes.push(why),
    }
    problems.extend(
        notes
            .into_iter()
            .map(|note| format!("tracking data: {note}")),
    );
    tracking
}

/// The pairs, read within the size the data declares (bytes past it are not evidence), and that
/// size. Every size declared is checked against what is there: the header's own, the whole's
/// (after the pairs, which are kept), and the pairs' (as the header gives it, and as they repeat
/// it). Damaged text, and a header's fifth value when it isn't 0, are noted in `notes`.
fn read_pairs(
    data: &[u8],
    tracking: &mut Vec<(String, Value)>,
    notes: &mut Vec<String>,
) -> Result<usize, String> {
    let first = u32_at(data, 0).ok_or("shorter than 4 bytes")? as usize;
    let (mut at, end, whole) = if first == 1 {
        let cut = || format!("a header cut short ({} bytes)", data.len());
        let header = u32_at(data, 4).ok_or_else(cut)? as usize;
        let pairs = u32_at(data, 8).ok_or_else(cut)? as usize;
        let whole = u32_at(data, 12).ok_or_else(cut)? as usize;
        // Its five fields, 20 bytes, at least.
        if header < 20 || header > data.len() {
            return Err(format!("a header of {header} bytes in {}", data.len()));
        }
        // Its fifth value, meaning not known, is 0 in every file seen: any other isn't lost.
        match u32_at(data, 16) {
            Some(0) | None => {}
            Some(fifth) => notes.push(format!("a header whose fifth value is {fifth}, not 0")),
        }
        if pairs == 0 {
            if whole != data.len() {
                return Err(format!("{whole} bytes said, {} there", data.len()));
            }
            return Ok(header);
        }
        if pairs < 4 {
            return Err(format!("pairs of {pairs} bytes, less than their size's 4"));
        }
        // The pairs start with their size again: read within the header's, any other noted.
        let own = u32_at(data, header).ok_or_else(cut)? as usize;
        if own != pairs {
            notes.push(format!(
                "pairs whose own size is {own}, the header's {pairs}"
            ));
        }
        (header + 4, header.saturating_add(pairs), Some(whole))
    } else {
        if first < 4 {
            return Err(format!("{first} bytes said, less than the size's own 4"));
        }
        (4, first, None)
    };
    if end > data.len() {
        return Err(format!("{end} bytes said, {} there", data.len()));
    }
    let all = data.len();
    let data = &data[..end];
    while at < end {
        let key_size = u32_at(data, at).ok_or("a key cut short")? as usize;
        let (key, damage) = utf16(
            data.get(at + 4..(at + 4).saturating_add(key_size))
                .ok_or("a key past the end")?,
        );
        if let Some(damage) = damage {
            notes.push(format!("{key}: a key with {damage}"));
        }
        at += 4 + key_size;
        let kind = u32_at(data, at).ok_or_else(|| format!("{key}: its type cut short"))?;
        at += 4;
        let sized = |at: usize| -> Result<&[u8], String> {
            let size = u32_at(data, at).ok_or_else(|| format!("{key}: its size cut short"))?;
            data.get(at + 4..(at + 4).saturating_add(size as usize))
                .ok_or_else(|| format!("{key}: a value past the end"))
        };
        let (value, size) = match kind {
            3 => (u32_at(data, at).map(|v| Value::Integer(u64::from(v))), 4),
            4 => (u64_at(data, at).map(Value::Integer), 8),
            5 => (data.get(at).map(|&b| Value::Bool(b != 0)), 1),
            6 | 7 => {
                let bytes = sized(at)?;
                let (text, damage) = if kind == 6 {
                    utf16(bytes)
                } else {
                    ascii(bytes)
                };
                if let Some(damage) = damage {
                    notes.push(format!("{key}: a value with {damage}"));
                }
                (Some(Value::Text(text)), 4 + bytes.len())
            }
            other => {
                let rest = data.get(at..end).unwrap_or_default().to_vec();
                tracking.push((key.clone(), Value::Bytes(rest)));
                return Err(format!("{key}: a value of type {other}, kept as bytes"));
            }
        };
        tracking.push((
            key.clone(),
            value.ok_or_else(|| format!("{key}: a value past the end"))?,
        ));
        at += size;
    }
    match whole {
        Some(whole) if whole != all => Err(format!("{whole} bytes said, {all} there")),
        _ => Ok(end),
    }
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(data: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(data.get(at..at + 8)?.try_into().ok()?))
}

/// UTF-16LE text up to its first NUL, and what was damaged: an odd byte at its end, text after
/// its NUL, or text that isn't UTF-16 (replaced).
fn utf16(bytes: &[u8]) -> (String, Option<&'static str>) {
    let pairs = bytes.chunks_exact(2);
    let odd = !pairs.remainder().is_empty();
    let units: Vec<u16> = pairs.map(|p| u16::from_le_bytes([p[0], p[1]])).collect();
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    let text = String::from_utf16(&units[..end]);
    let damage = if odd {
        Some("an odd byte at its end")
    } else if units[end..].iter().any(|&u| u != 0) {
        Some("text after its NUL")
    } else if text.is_err() {
        Some("text that isn't UTF-16, replaced")
    } else {
        None
    };
    let text = text.unwrap_or_else(|_| String::from_utf16_lossy(&units[..end]));
    (text, damage)
}

/// An ASCII string (read as UTF-8) up to its first NUL, and what was damaged: text after its
/// NUL, or text that isn't UTF-8 (replaced).
fn ascii(bytes: &[u8]) -> (String, Option<&'static str>) {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let text = String::from_utf8_lossy(&bytes[..end]);
    let damage = if bytes[end..].iter().any(|&b| b != 0) {
        Some("text after its NUL")
    } else if std::str::from_utf8(&bytes[..end]).is_err() {
        Some("text that isn't UTF-8, replaced")
    } else {
        None
    };
    (text.into_owned(), damage)
}

fn hex(bytes: &[u8]) -> String {
    use fmt::Write;
    bytes.iter().fold(String::new(), |mut text, b| {
        let _ = write!(text, "{b:02x}");
        text
    })
}

/// A GUID as Windows writes it, upper case.
fn guid(bytes: &[u8]) -> String {
    let data1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let data2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let data3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    let tail = hex(&bytes[10..16]).to_ascii_uppercase();
    format!(
        "{data1:08X}-{data2:04X}-{data3:04X}-{:02X}{:02X}-{tail}",
        bytes[8], bytes[9]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(kind: u32, data: &[u8]) -> Vec<u8> {
        let mut bytes = (data.len() as u32).to_le_bytes().to_vec();
        bytes.extend(kind.to_le_bytes());
        bytes.extend(data);
        bytes.resize(bytes.len().next_multiple_of(8), 0);
        bytes
    }

    fn text(t: &str) -> Vec<u8> {
        format!("{t}\0")
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    #[test]
    fn padding_cut_short_or_not_zero_is_reported() {
        let full = value(STRING, &text("ab"));
        let mut problems = Vec::new();
        let read = values(&full[..full.len() - 1], &mut problems);
        assert_eq!(read[0].value, Value::Text("ab".to_owned()));
        assert_eq!(
            problems,
            ["offset 0x0: its padding cut short (1 of 2 bytes)"]
        );
        let mut dirty = full.clone();
        *dirty.last_mut().unwrap() = 1;
        let mut problems = Vec::new();
        values(&dirty, &mut problems);
        assert_eq!(problems, ["offset 0xe: padding that isn't zero"]);
    }

    #[test]
    fn values_are_aligned_to_eight_bytes() {
        let mut data = value(0, &7u32.to_le_bytes());
        data.extend(value(FILETIME, &132_000_000_000_000_000u64.to_le_bytes()));
        data.extend(value(SIGNED_32, &(-2i32).to_le_bytes()));
        let mut problems = Vec::new();
        let values: Vec<Value> = values(&data, &mut problems)
            .into_iter()
            .map(|r| r.value)
            .collect();
        assert_eq!(
            values,
            [
                Value::Integer(7),
                Value::Time(132_000_000_000_000_000),
                Value::Signed(-2)
            ]
        );
        assert_eq!(problems, Vec::<String>::new());
    }

    fn pair(key: &str, kind: u32, value: &[u8]) -> Vec<u8> {
        let key = text(key);
        let mut data = (key.len() as u32).to_le_bytes().to_vec();
        data.extend(key);
        data.extend(kind.to_le_bytes());
        data.extend(value);
        data
    }

    fn sized(bytes: &[u8]) -> Vec<u8> {
        let mut data = (bytes.len() as u32).to_le_bytes().to_vec();
        data.extend(bytes);
        data
    }

    #[test]
    fn tracking_values_of_every_type() {
        let mut pairs = pair("A", 4, &5u64.to_le_bytes());
        pairs.extend(pair("B", 6, &sized(&text("x"))));
        pairs.extend(pair("C", 7, &sized(b"TTData={}\0")));
        pairs.extend(pair("D", 5, &[1]));
        pairs.extend(pair("E", 3, &9u32.to_le_bytes()));
        let expected = [
            ("A".to_owned(), Value::Integer(5)),
            ("B".to_owned(), Value::Text("x".to_owned())),
            ("C".to_owned(), Value::Text("TTData={}".to_owned())),
            ("D".to_owned(), Value::Bool(true)),
            ("E".to_owned(), Value::Integer(9)),
        ];
        let mut problems = Vec::new();

        // Sized.
        let mut plain = ((pairs.len() + 4) as u32).to_le_bytes().to_vec();
        plain.extend(&pairs);
        assert_eq!(read_tracking(&plain, &mut problems), expected);

        // Behind a header.
        let mut headed = Vec::new();
        for n in [1, 0x14, plain.len() as u32, plain.len() as u32 + 0x14, 0] {
            headed.extend(n.to_le_bytes());
        }
        headed.extend(&plain);
        assert_eq!(read_tracking(&headed, &mut problems), expected);

        // Empty, behind a header.
        let mut empty = Vec::new();
        for n in [1u32, 0x14, 0, 0x14, 0] {
            empty.extend(n.to_le_bytes());
        }
        assert_eq!(read_tracking(&empty, &mut problems), []);
        assert_eq!(problems, Vec::<String>::new());
    }

    #[test]
    fn tracking_values_must_not_cross_the_declared_end() {
        let mut pair = pair("A", 7, &sized(b"oops"));
        let declared_end = pair.len() - 4;
        let mut data = ((declared_end + 4) as u32).to_le_bytes().to_vec();
        data.append(&mut pair);
        let mut tracking = Vec::new();

        assert!(
            read_pairs(&data, &mut tracking, &mut Vec::new()).is_err(),
            "{tracking:?}"
        );
        assert!(tracking.is_empty(), "{tracking:?}");
    }

    #[test]
    fn empty_tracking_header_must_fit_in_the_blob() {
        let mut data = Vec::new();
        for n in [1u32, 0x14, 0] {
            data.extend(n.to_le_bytes());
        }
        let mut problems = Vec::new();

        assert_eq!(read_tracking(&data, &mut problems), []);
        assert!(
            !problems.is_empty(),
            "a 20-byte header in a 12-byte blob was accepted"
        );
    }

    #[test]
    fn declared_sizes_are_checked() {
        let words =
            |words: &[u32]| -> Vec<u8> { words.iter().flat_map(|w| w.to_le_bytes()).collect() };
        let read = |data: &[u8]| {
            let mut problems = Vec::new();
            (read_tracking(data, &mut problems), problems)
        };
        // A fifth header value that isn't 0: noted, the rest read.
        assert_eq!(
            read(&words(&[1, 0x14, 0, 0x14, 7])).1,
            ["tracking data: a header whose fifth value is 7, not 0"]
        );
        // A header smaller than its five fields, and a size smaller than itself.
        assert_eq!(read(&words(&[1, 8, 0, 20, 0])).1.len(), 1);
        assert_eq!(read(&words(&[1, 16, 0, 16])).1.len(), 1);
        assert_eq!(read(&words(&[2, 0])).1.len(), 1);
        // A whole size that isn't the data's: the pairs are kept, with the problem.
        let pairs = pair("A", 3, &1u32.to_le_bytes());
        let mut inner = ((pairs.len() + 4) as u32).to_le_bytes().to_vec();
        inner.extend(&pairs);
        let mut data = words(&[1, 0x14, inner.len() as u32, 999, 0]);
        data.extend(&inner);
        let (tracking, problems) = read(&data);
        assert_eq!(tracking, [("A".to_owned(), Value::Integer(1))]);
        assert_eq!(problems.len(), 1, "{problems:?}");
    }

    #[test]
    fn damaged_text_is_reported() {
        assert_eq!(utf16(&text("ok")), ("ok".to_owned(), None));
        assert_eq!(utf16(b"o\0k").1, Some("an odd byte at its end"));
        assert_eq!(
            utf16(&[b'a', 0, 0, 0, b'b', 0]).1,
            Some("text after its NUL")
        );
        assert_eq!(
            utf16(&[0x00, 0xD8, b'a', 0]).1,
            Some("text that isn't UTF-16, replaced")
        );
        assert_eq!(ascii(b"TTData={}\0"), ("TTData={}".to_owned(), None));
        assert_eq!(ascii(b"a\0b").1, Some("text after its NUL"));
        assert_eq!(
            ascii(&[b'a', 0xFF]).1,
            Some("text that isn't UTF-8, replaced")
        );

        // Through the file's values and a resource's tracking data.
        let mut problems = Vec::new();
        let read = values(&value(STRING, b"o\0k"), &mut problems);
        assert_eq!(read[0].value, Value::Text("o".to_owned()));
        assert_eq!(problems.len(), 1, "{problems:?}");
        let mut pairs = pair("A", 6, &sized(b"o\0k"));
        pairs.extend(pair("B", 7, &sized(&[b'a', 0xFF, 0])));
        let mut data = ((pairs.len() + 4) as u32).to_le_bytes().to_vec();
        data.extend(&pairs);
        let mut problems = Vec::new();
        let tracking = read_tracking(&data, &mut problems);
        assert_eq!(tracking.len(), 2);
        assert_eq!(problems.len(), 2, "{problems:?}");
    }

    #[test]
    fn tracking_header_must_include_all_five_fields() {
        let data: Vec<u8> = [1u32, 0x10, 0, 0x10]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let mut problems = Vec::new();

        assert_eq!(read_tracking(&data, &mut problems), []);
        assert_eq!(problems, ["tracking data: a header of 16 bytes in 16"]);
    }

    #[test]
    fn headed_tracking_checks_the_inner_pairs_size() {
        let pairs = pair("A", 3, &1u32.to_le_bytes());
        let declared = (pairs.len() + 4) as u32;
        let mut data: Vec<u8> = [1u32, 0x14, declared, declared + 0x14, 0]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        data.extend(4u32.to_le_bytes()); // conflicting inner values-data size
        data.extend(pairs);
        let mut problems = Vec::new();

        assert_eq!(
            read_tracking(&data, &mut problems),
            [("A".to_owned(), Value::Integer(1))]
        );
        assert_eq!(
            problems,
            [format!(
                "tracking data: pairs whose own size is 4, the header's {declared}"
            )]
        );
    }

    #[test]
    fn bytes_after_the_declared_end_are_reported() {
        let pairs = pair("A", 3, &1u32.to_le_bytes());
        let mut data = ((pairs.len() + 4) as u32).to_le_bytes().to_vec();
        data.extend(&pairs);
        data.extend(pair("B", 3, &2u32.to_le_bytes()));
        let mut problems = Vec::new();
        let tracking = read_tracking(&data, &mut problems);
        assert_eq!(tracking, [("A".to_owned(), Value::Integer(1))]);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("after the"), "{problems:?}");
    }

    #[test]
    fn an_unknown_tracking_type_is_kept_as_bytes() {
        let mut pairs = pair("A", 3, &1u32.to_le_bytes());
        pairs.extend(pair("B", 99, &[1, 2, 3]));
        let mut data = ((pairs.len() + 4) as u32).to_le_bytes().to_vec();
        data.extend(&pairs);
        let mut problems = Vec::new();
        let tracking = read_tracking(&data, &mut problems);
        assert_eq!(tracking[1], ("B".to_owned(), Value::Bytes(vec![1, 2, 3])));
        assert_eq!(problems.len(), 1);
    }

    #[test]
    fn other_files_are_errors() {
        assert!(read(b"not a detection").is_err());
        assert!(read(&[0; 200]).is_err());
    }

    /// A file of `values`, after a header without `Magic.Version:1.2`.
    fn file(rest: &[Vec<u8>]) -> Vec<u8> {
        let mut data = value(INTEGER_64, &2_147_519_003u64.to_le_bytes());
        data.extend(value(GUID, &[0x11; 16]));
        data.extend(value(STRING, &text("Virus:DOS/EICAR_Test_File")));
        for v in rest {
            data.extend(v);
        }
        data
    }

    #[test]
    fn a_header_without_its_version_and_a_file_cut_short() {
        let u32v = |n: u32| value(6, &n.to_le_bytes());
        let data = file(&[u32v(0), u32v(5), u32v(42), u32v(1), u32v(4), u32v(3)]);
        assert!(detect(&data));
        let detection = read(&data).unwrap();
        assert_eq!(detection.threat_id, Some(2_147_519_003));
        assert_eq!(detection.version, None);
        assert_eq!(
            detection.threat_name.as_deref(),
            Some("Virus:DOS/EICAR_Test_File")
        );
        assert_eq!(detection.severity_name(), Some("Severe"));
        assert_eq!(detection.category_name(), Some("VIRUS"));
        assert_eq!(detection.threat_status_name(), Some("Quarantined"));
        assert_eq!(detection.problems, ["the values end before 2.6"]);
        assert_eq!(
            detection.unknown,
            [
                ("2.0".to_owned(), Value::Integer(0)),
                ("2.3".to_owned(), Value::Integer(1)),
                ("2.4".to_owned(), Value::Integer(4))
            ]
        );
    }

    #[test]
    fn counts_past_the_values_left_stop_the_reading() {
        let u32v = |n: u32| value(6, &n.to_le_bytes());
        let data = file(&[
            u32v(0),
            u32v(5),
            u32v(42),
            u32v(1),
            u32v(4),
            u32v(3),
            u32v(1_000_000),
        ]);
        let detection = read(&data).unwrap();
        assert_eq!(detection.problems.len(), 1, "{:?}", detection.problems);
        assert!(detection.problems[0].starts_with("2.6: 1000000 said"));
    }
}
