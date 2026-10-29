//! Microsoft Defender's quarantine (`ProgramData\Microsoft\Windows Defender\Quarantine`): what
//! Defender quarantined, when, for which threat, and the quarantined content itself, only ever
//! read, never run.
//!
//! - `Entries\{<GUID>}`: one per quarantine ([`read_entry`]): the threat's identifier and name,
//!   the scan, when, and each resource quarantined (a file, registry key, service, startup item,
//!   scheduled task) with its fields: a file's size, times, attributes and path, and the
//!   identifier of the resource's content. The GUID is the detection history's `quarantine_id`.
//! - `ResourceData\<xx>\<ID>`: a resource's content ([`read_resource_data`]): for a file, what
//!   Windows' `BackupRead` gives (its security descriptor, data and alternate data streams); for
//!   a registry key or a service, a registry hive. The ID is the SHA-1 of the content.
//! - `Resources\<xx>\<ID>`: the content's size and the entries holding it
//!   ([`read_resource_record`]).
//!
//! Every part is RC4-encrypted with the key Defender holds ([`crypt`]). An entry and a resource
//! record are a 60-byte header (two magic numbers, the sizes of two sections and their CRC-32s,
//! stored without the CRC's final inversion) and the two sections, each encrypted on its own.
//! The sizes and CRCs are checked, so damage and changes there are reported. A content's SHA-1 is
//! computed as [`ResourceData::id`]; compare it with the `ResourceData` file's name to check the
//! content itself.

use std::fmt::Write;
use std::ops::Range;

use common::checksum::Crc32;
use common::{md5::Md5, sha1::Sha1, sha256::Sha256};

use crate::history::{ascii, guid, hex, u32_at, u64_at, utf16, Error, Value};
use crate::time::Time;

/// The RC4 key Defender encrypts its quarantine with, as cuckoo-modified's `quarantine.py`
/// published it and every reader since uses it.
const KEY: [u8; 256] = [
    0x1E, 0x87, 0x78, 0x1B, 0x8D, 0xBA, 0xA8, 0x44, 0xCE, 0x69, 0x70, 0x2C, 0x0C, 0x78, 0xB7, 0x86,
    0xA3, 0xF6, 0x23, 0xB7, 0x38, 0xF5, 0xED, 0xF9, 0xAF, 0x83, 0x53, 0x0F, 0xB3, 0xFC, 0x54, 0xFA,
    0xA2, 0x1E, 0xB9, 0xCF, 0x13, 0x31, 0xFD, 0x0F, 0x0D, 0xA9, 0x54, 0xF6, 0x87, 0xCB, 0x9E, 0x18,
    0x27, 0x96, 0x97, 0x90, 0x0E, 0x53, 0xFB, 0x31, 0x7C, 0x9C, 0xBC, 0xE4, 0x8E, 0x23, 0xD0, 0x53,
    0x71, 0xEC, 0xC1, 0x59, 0x51, 0xB8, 0xF3, 0x64, 0x9D, 0x7C, 0xA3, 0x3E, 0xD6, 0x8D, 0xC9, 0x04,
    0x7E, 0x82, 0xC9, 0xBA, 0xAD, 0x97, 0x99, 0xD0, 0xD4, 0x58, 0xCB, 0x84, 0x7C, 0xA9, 0xFF, 0xBE,
    0x3C, 0x8A, 0x77, 0x52, 0x33, 0x55, 0x7D, 0xDE, 0x13, 0xA8, 0xB1, 0x40, 0x87, 0xCC, 0x1B, 0xC8,
    0xF1, 0x0F, 0x6E, 0xCD, 0xD0, 0x83, 0xA9, 0x59, 0xCF, 0xF8, 0x4A, 0x9D, 0x1D, 0x50, 0x75, 0x5E,
    0x3E, 0x19, 0x18, 0x18, 0xAF, 0x23, 0xE2, 0x29, 0x35, 0x58, 0x76, 0x6D, 0x2C, 0x07, 0xE2, 0x57,
    0x12, 0xB2, 0xCA, 0x0B, 0x53, 0x5E, 0xD8, 0xF6, 0xC5, 0x6C, 0xE7, 0x3D, 0x24, 0xBD, 0xD0, 0x29,
    0x17, 0x71, 0x86, 0x1A, 0x54, 0xB4, 0xC2, 0x85, 0xA9, 0xA3, 0xDB, 0x7A, 0xCA, 0x6D, 0x22, 0x4A,
    0xEA, 0xCD, 0x62, 0x1D, 0xB9, 0xF2, 0xA2, 0x2E, 0xD1, 0xE9, 0xE1, 0x1D, 0x75, 0xBE, 0xD7, 0xDC,
    0x0E, 0xCB, 0x0A, 0x8E, 0x68, 0xA2, 0xFF, 0x12, 0x63, 0x40, 0x8D, 0xC8, 0x08, 0xDF, 0xFD, 0x16,
    0x4B, 0x11, 0x67, 0x74, 0xCD, 0x0B, 0x9B, 0x8D, 0x05, 0x41, 0x1E, 0xD6, 0x26, 0x2E, 0x42, 0x9B,
    0xA4, 0x95, 0x67, 0x6B, 0x83, 0x98, 0xDB, 0x2F, 0x35, 0xD3, 0xC1, 0xB9, 0xCE, 0xD5, 0x26, 0x36,
    0xF2, 0x76, 0x5E, 0x1A, 0x95, 0xCB, 0x7C, 0xA4, 0xC3, 0xDD, 0xAB, 0xDD, 0xBF, 0xF3, 0x82, 0x53,
];

/// The header's first and last magic numbers.
const MAGIC: [u8; 4] = [0xDB, 0xE8, 0xC5, 0x01];
const FOOTER: [u8; 4] = [0xDB, 0xE8, 0xC5, 0x02];
/// The header's size.
const HEADER: usize = 60;
/// An entry's first section: its identifier, the scan's, the time, the threat's identifier, a
/// value, then the threat's name.
const ENTRY_FIXED: usize = 52;
/// A resource record's first section: the content's size, its identifier, the entries' count.
const RECORD_FIXED: usize = 32;

/// RC4 with Defender's key: it decrypts the quarantine's parts, and encrypts them alike.
#[must_use]
pub fn crypt(data: &[u8]) -> Vec<u8> {
    let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut j = 0u8;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(KEY[i]);
        s.swap(i, usize::from(j));
    }
    let (mut i, mut j) = (0u8, 0u8);
    data.iter()
        .map(|&b| {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[usize::from(i)]);
            s.swap(usize::from(i), usize::from(j));
            b ^ s[usize::from(s[usize::from(i)].wrapping_add(s[usize::from(j)]))]
        })
        .collect()
}

/// The CRC-32 a header holds for a section: without the CRC's final inversion.
fn stored_crc(plain: &[u8]) -> u32 {
    !Crc32::of(plain)
}

/// A header and its two sections, decrypted.
#[derive(Default)]
struct Container {
    sections: [Vec<u8>; 2],
    unknown: Vec<(String, Value)>,
    problems: Vec<String>,
}

/// The header and the two sections of an entry or a resource record (`what`).
fn container(data: &[u8], what: &str) -> Result<Container, Error> {
    let head = crypt(
        data.get(..HEADER)
            .ok_or_else(|| Error(format!("shorter than a {what}'s 60-byte header")))?,
    );
    if head[..4] != MAGIC || head[56..] != FOOTER {
        return Err(Error(format!("no {what} header (its magic numbers)")));
    }
    let mut c = Container::default();
    c.unknown.push((
        "header.4".to_owned(),
        Value::Integer(u64::from(u32_at(&head, 4).unwrap_or(0))),
    ));
    if head[8..40].iter().any(|&b| b != 0) {
        c.problems.push("header padding that isn't zero".to_owned());
    }
    let mut at = HEADER;
    for n in 0..2 {
        let size = u32_at(&head, 40 + 4 * n).unwrap_or(0) as usize;
        let crc = u32_at(&head, 48 + 4 * n).unwrap_or(0);
        let end = at.saturating_add(size);
        let bytes = data.get(at..end.min(data.len())).unwrap_or_default();
        let plain = crypt(bytes);
        if bytes.len() < size {
            c.problems.push(format!(
                "section {} of {size} bytes cut short ({} there)",
                n + 1,
                bytes.len()
            ));
        } else if stored_crc(&plain) != crc {
            c.problems.push(format!(
                "section {}'s CRC-32 isn't its content's: changed or damaged",
                n + 1
            ));
        }
        c.sections[n] = plain;
        at = end.min(data.len());
    }
    if at < data.len() {
        c.problems
            .push(format!("{} bytes after the sections", data.len() - at));
    }
    Ok(c)
}

/// A quarantine entry: `Entries\{<GUID>}`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Entry {
    /// Its identifier (a GUID, upper case, without braces), also its file's name and the
    /// detection history's `quarantine_id`.
    pub id: Option<String>,
    /// The scan that found the threat (a GUID).
    pub scan_id: Option<String>,
    /// When the threat was quarantined.
    pub time: Option<Time>,
    /// The threat's identifier, as the detection history and `Get-MpThreatCatalog` give it.
    pub threat_id: Option<u64>,
    /// The threat's name (`HackTool:Win64/Mikatz!dha`).
    pub threat_name: Option<String>,
    /// What was quarantined.
    pub resources: Vec<Resource>,
    /// Values whose meaning isn't known: the header's (`header.4`) and the first section's
    /// (`1.48`, 1 in every entry seen).
    pub unknown: Vec<(String, Value)>,
    /// What couldn't be read, or doesn't match.
    pub problems: Vec<String>,
}

/// A resource quarantined: a file, registry key, service, startup item, scheduled task, ….
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Resource {
    /// Its type: `file`, `regkey`, `service`, `startup`, `taskscheduler`, ….
    pub kind: String,
    /// Its path or key as Defender wrote it (`\\?\C:\Users\…`, `HKLM\SOFTWARE\…`).
    pub path: String,
    /// Its fields, in order.
    pub fields: Vec<Field>,
}

/// A field of a resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    /// Its identifier (12 bits).
    pub id: u16,
    /// Its type (4 bits): 1 text, 2 UTF-16 text, 3 32-bit integer, 4 a content's identifier,
    /// 5 bytes, 6 64-bit integer.
    pub kind: u8,
    /// Its value.
    pub value: Value,
}

/// The field type of a content's identifier (in `ResourceData`).
const RESOURCE_ID: u8 = 4;

impl Field {
    /// Its name, where known (dissect.target's names for a file's fields): `ResourceId`,
    /// `Flags`, `PhysicalPath`, `DetectionContext`, `CreationTime`, `LastAccessTime`,
    /// `LastWriteTime`, `FileSize`.
    #[must_use]
    pub fn name(&self) -> Option<&'static str> {
        if self.kind == RESOURCE_ID {
            return Some("ResourceId");
        }
        Some(match (self.id, self.kind) {
            (0x0A, 3) => "Flags",
            (0x0C, 2) => "PhysicalPath",
            (0x0D, 5) => "DetectionContext",
            (0x0F, 6) => "CreationTime",
            (0x10, 6) => "LastAccessTime",
            (0x11, 6) => "LastWriteTime",
            (0x12, 6) => "FileSize",
            _ => return None,
        })
    }
}

impl Resource {
    /// The first field named `name` (see [`Field::name`]).
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&Value> {
        self.fields
            .iter()
            .find(|f| f.name() == Some(name))
            .map(|f| &f.value)
    }

    /// The identifier of its content: the SHA-1 of `ResourceData\<xx>\<ID>`'s content, upper
    /// case, as the file is named.
    #[must_use]
    pub fn resource_id(&self) -> Option<String> {
        match self.field("ResourceId")? {
            Value::Bytes(bytes) => Some(hex(bytes).to_ascii_uppercase()),
            _ => None,
        }
    }

    /// The file's path without `\\?\` (`PhysicalPath`).
    #[must_use]
    pub fn physical_path(&self) -> Option<&str> {
        self.field("PhysicalPath")?.as_str()
    }

    /// The file's size when quarantined.
    #[must_use]
    pub fn size(&self) -> Option<u64> {
        self.field("FileSize")?.as_u64()
    }

    /// The file's attributes (`Flags`: 0x20 archive, 0x01 read-only, …).
    #[must_use]
    pub fn flags(&self) -> Option<u64> {
        self.field("Flags")?.as_u64()
    }

    /// The file's creation, last access and last write times.
    #[must_use]
    pub fn times(&self) -> [Option<Time>; 3] {
        ["CreationTime", "LastAccessTime", "LastWriteTime"]
            .map(|name| Time::from_filetime(self.field(name)?.as_u64()?))
    }
}

/// Whether `head` starts like a quarantine entry or resource record: its header's magic
/// numbers, once decrypted.
#[must_use]
pub fn detect(head: &[u8]) -> bool {
    head.get(..HEADER)
        .map(crypt)
        .is_some_and(|h| h[..4] == MAGIC && h[56..] == FOOTER)
}

/// Read a quarantine entry (`Entries\{<GUID>}`).
///
/// # Errors
/// When it doesn't start like one.
pub fn read_entry(data: &[u8]) -> Result<Entry, Error> {
    let c = container(data, "quarantine entry")?;
    let mut entry = Entry {
        unknown: c.unknown,
        problems: c.problems,
        ..Entry::default()
    };
    let [first, second] = &c.sections;
    if first.len() < ENTRY_FIXED {
        entry
            .problems
            .push(format!("section 1 of {} bytes, too short", first.len()));
    } else {
        entry.id = Some(guid(&first[..16]));
        entry.scan_id = Some(guid(&first[16..32]));
        entry.time = u64_at(first, 32).and_then(Time::from_filetime);
        entry.threat_id = u64_at(first, 40);
        let value = u32_at(first, 48).unwrap_or(0);
        entry
            .unknown
            .push(("1.48".to_owned(), Value::Integer(u64::from(value))));
        let (name, damage) = ascii(&first[ENTRY_FIXED..]);
        if let Some(damage) = damage {
            entry.problems.push(format!("a threat name with {damage}"));
        }
        if first.get(ENTRY_FIXED..).is_some_and(|n| !n.ends_with(&[0])) {
            entry
                .problems
                .push("a threat name without its end".to_owned());
        }
        entry.threat_name = Some(name);
    }
    resources(second, &mut entry);
    Ok(entry)
}

/// The second section: a count, the resources' offsets, the resources.
fn resources(section: &[u8], entry: &mut Entry) {
    let Some(count) = u32_at(section, 0) else {
        entry
            .problems
            .push("section 2 without its count".to_owned());
        return;
    };
    let table = 4usize.saturating_add((count as usize).saturating_mul(4));
    if table > section.len() {
        entry.problems.push(format!(
            "section 2: {count} resources said, more than its {} bytes could hold",
            section.len()
        ));
        return;
    }
    let offsets: Vec<usize> = (0..count as usize)
        .map(|i| u32_at(section, 4 + 4 * i).unwrap_or(0) as usize)
        .collect();
    for (i, &start) in offsets.iter().enumerate() {
        // A resource runs to the next one, or the section's end.
        let end = offsets
            .iter()
            .copied()
            .filter(|&o| o > start)
            .min()
            .unwrap_or(section.len());
        if start < table || start >= section.len() {
            entry.problems.push(format!(
                "resource {i}: an offset ({start}) outside the resources"
            ));
            continue;
        }
        let (resource, problems) = resource(section, start..end.min(section.len()));
        entry
            .problems
            .extend(problems.into_iter().map(|p| format!("resource {i}: {p}")));
        entry.resources.extend(resource);
    }
}

/// A resource at `range` of the section: its path, its fields' count, its type, then its
/// fields, each at a multiple of 4 bytes.
fn resource(section: &[u8], range: Range<usize>) -> (Option<Resource>, Vec<String>) {
    let mut problems = Vec::new();
    let region = &section[range.clone()];
    let Some(path_end) =
        (0..region.len() / 2).find(|&k| region[2 * k] == 0 && region[2 * k + 1] == 0)
    else {
        problems.push("a path without its end".to_owned());
        return (None, problems);
    };
    let (path, damage) = utf16(&region[..2 * path_end]);
    if let Some(damage) = damage {
        problems.push(format!("a path with {damage}"));
    }
    let mut at = 2 * path_end + 2;
    let Some(count) = region
        .get(at..at + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
    else {
        problems.push("its fields' count cut short".to_owned());
        return (None, problems);
    };
    at += 2;
    let Some(kind_end) = region[at..].iter().position(|&b| b == 0) else {
        problems.push("a type without its end".to_owned());
        return (None, problems);
    };
    let (kind, damage) = ascii(&region[at..at + kind_end]);
    if let Some(damage) = damage {
        problems.push(format!("a type with {damage}"));
    }
    at += kind_end + 1;
    let mut resource = Resource {
        kind,
        path,
        fields: Vec::new(),
    };
    for n in 0..count {
        // aligned within the section
        at = (range.start + at).next_multiple_of(4) - range.start;
        let Some(head) = region.get(at..at + 4) else {
            problems.push(format!("field {n} of {count} cut short"));
            break;
        };
        let size = usize::from(u16::from_le_bytes([head[0], head[1]]));
        let word = u16::from_le_bytes([head[2], head[3]]);
        let (id, kind) = (word & 0x0FFF, (word >> 12) as u8);
        let Some(data) = region.get(at + 4..at + 4 + size) else {
            problems.push(format!("field {n} (0x{id:x}) of {size} bytes cut short"));
            break;
        };
        let value = match (kind, size) {
            (1 | 2, _) => {
                let (text, damage) = if kind == 1 { ascii(data) } else { utf16(data) };
                if let Some(damage) = damage {
                    problems.push(format!("field 0x{id:x} with {damage}"));
                }
                Value::Text(text)
            }
            (3, 4) => Value::Integer(u64::from(u32_at(data, 0).unwrap_or(0))),
            (6, 8) => Value::Integer(u64_at(data, 0).unwrap_or(0)),
            (4 | 5, _) => Value::Bytes(data.to_vec()),
            _ => {
                problems.push(format!(
                    "field 0x{id:x}: type {kind} of {size} bytes not known, kept as bytes"
                ));
                Value::Bytes(data.to_vec())
            }
        };
        resource.fields.push(Field { id, kind, value });
        at += 4 + size;
    }
    if region
        .get(at..)
        .is_some_and(|rest| rest.iter().any(|&b| b != 0))
    {
        problems.push(format!(
            "{} bytes after its fields, not read",
            region.len() - at
        ));
    }
    (Some(resource), problems)
}

/// A resource record: `Resources\<xx>\<ID>`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResourceRecord {
    /// The size of the content's file (`ResourceData\<xx>\<ID>`).
    pub data_size: Option<u64>,
    /// The content's identifier, upper case, as the file is named.
    pub resource_id: Option<String>,
    /// The entries holding the content (GUIDs).
    pub entries: Vec<String>,
    /// Values whose meaning isn't known (`header.4`).
    pub unknown: Vec<(String, Value)>,
    /// What couldn't be read, or doesn't match.
    pub problems: Vec<String>,
}

/// Read a resource record (`Resources\<xx>\<ID>`).
///
/// # Errors
/// When it doesn't start like one.
pub fn read_resource_record(data: &[u8]) -> Result<ResourceRecord, Error> {
    let c = container(data, "resource record")?;
    let mut record = ResourceRecord {
        unknown: c.unknown,
        problems: c.problems,
        ..ResourceRecord::default()
    };
    let [first, second] = &c.sections;
    if first.len() < RECORD_FIXED {
        record
            .problems
            .push(format!("section 1 of {} bytes, too short", first.len()));
    } else {
        record.data_size = u64_at(first, 0);
        record.resource_id = Some(hex(&first[8..28]).to_ascii_uppercase());
        let count = u32_at(first, 28).unwrap_or(0) as usize;
        if first.len() > RECORD_FIXED {
            record.problems.push(format!(
                "{} bytes after section 1's values",
                first.len() - RECORD_FIXED
            ));
        }
        if second.len() != count.saturating_mul(16) {
            record.problems.push(format!(
                "{count} entries said, section 2 of {} bytes",
                second.len()
            ));
        }
    }
    let ids = second.chunks_exact(16);
    if !ids.remainder().is_empty() {
        record.problems.push(format!(
            "{} bytes after section 2's entries",
            ids.remainder().len()
        ));
    }
    record.entries = ids.map(guid).collect();
    Ok(record)
}

/// A stream of a file's content, as `BackupRead` wrote it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stream {
    /// Its kind (`WIN32_STREAM_ID`'s `dwStreamId`: 1 data, 3 security, 4 alternate data, …).
    pub kind: u32,
    /// Its attributes.
    pub attributes: u32,
    /// Its name (an alternate data stream's: `:Zone.Identifier:$DATA`).
    pub name: String,
    /// Where its data is in [`ResourceData::content`].
    pub range: Range<usize>,
}

impl Stream {
    /// Its kind's name: `Data`, `EaData`, `SecurityData`, `AlternateData`, `Link`,
    /// `PropertyData`, `ObjectId`, `ReparseData`, `SparseBlock`, `TxfsData`,
    /// `GhostedFileExtents`.
    #[must_use]
    pub fn kind_name(&self) -> Option<&'static str> {
        Some(match self.kind {
            1 => "Data",
            2 => "EaData",
            3 => "SecurityData",
            4 => "AlternateData",
            5 => "Link",
            6 => "PropertyData",
            7 => "ObjectId",
            8 => "ReparseData",
            9 => "SparseBlock",
            10 => "TxfsData",
            11 => "GhostedFileExtents",
            _ => return None,
        })
    }
}

/// A resource's content: `ResourceData\<xx>\<ID>`, decrypted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResourceData {
    /// The content's SHA-1, upper case: its identifier, as its file should be named.
    pub id: String,
    /// Whether it is a registry hive (a registry key's or a service's), not a file's streams.
    pub hive: bool,
    /// A file's streams, in order.
    pub streams: Vec<Stream>,
    /// The content, decrypted.
    pub content: Vec<u8>,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

/// The size of a stream's header (kind, attributes, size, name's size).
const STREAM_HEADER: usize = 20;
/// A data or alternate-data stream is sparse; its allocated regions follow in sparse-block
/// streams.
const STREAM_SPARSE_ATTRIBUTE: u32 = 0x08;

/// Read a resource's content (`ResourceData\<xx>\<ID>`): decrypted, a file's streams found, or a
/// registry hive. Check [`ResourceData::id`] against the file's name.
#[must_use]
pub fn read_resource_data(data: &[u8]) -> ResourceData {
    let content = crypt(data);
    let mut read = ResourceData {
        id: hex(&Sha1::digest(&content)).to_ascii_uppercase(),
        hive: content.starts_with(b"regf"),
        ..ResourceData::default()
    };
    let mut at = 0;
    while !read.hive && at < content.len() {
        let Some(head) = content.get(at..at + STREAM_HEADER) else {
            read.problems.push(format!(
                "offset {at:#x}: a stream's header cut short ({} bytes)",
                content.len() - at
            ));
            break;
        };
        let kind = u32_at(head, 0).unwrap_or(0);
        let attributes = u32_at(head, 4).unwrap_or(0);
        let size = u64_at(head, 8).unwrap_or(0);
        let name_size = u32_at(head, 16).unwrap_or(0) as usize;
        if !(1..=11).contains(&kind) {
            read.problems.push(format!(
                "offset {at:#x}: a stream of kind {kind}, not known: the rest not read"
            ));
            break;
        }
        let name_at = at + STREAM_HEADER;
        let data_at = name_at.saturating_add(name_size);
        let data_end = usize::try_from(size)
            .ok()
            .and_then(|s| data_at.checked_add(s))
            .filter(|&end| end <= content.len());
        let (Some(name), Some(data_end)) = (content.get(name_at..data_at), data_end) else {
            read.problems.push(format!(
                "offset {at:#x}: a stream of {size} bytes cut short"
            ));
            break;
        };
        if kind == 4 {
            if name_size > 65_536 {
                read.problems.push(format!(
                    "offset {at:#x}: an alternate stream name of {name_size} bytes, more than 65536"
                ));
            }
        } else if name_size != 0 {
            read.problems.push(format!(
                "offset {at:#x}: a stream of kind {kind} with a name of {name_size} bytes"
            ));
        }
        let (name, damage) = utf16(name);
        if let Some(damage) = damage {
            read.problems
                .push(format!("offset {at:#x}: a stream name with {damage}"));
        }
        read.streams.push(Stream {
            kind,
            attributes,
            name,
            range: data_at..data_end,
        });
        at = data_end;
    }
    read.content = content;
    for (i, stream) in read.streams.iter().enumerate().filter(|(_, s)| s.kind == 9) {
        let data = read.stream_data(stream);
        if data.len() < 8 {
            read.problems.push(format!(
                "stream {i}: a sparse block shorter than its 8-byte file offset"
            ));
            continue;
        }
        let offset = u64_at(data, 0).unwrap_or(0);
        let length = u64::try_from(data.len() - 8).unwrap_or(u64::MAX);
        if offset.checked_add(length).is_none() {
            read.problems.push(format!(
                "stream {i}: a sparse block whose offset and size overflow"
            ));
        }
        let parent = read.streams[..i]
            .iter()
            .rev()
            .find(|s| matches!(s.kind, 1 | 4));
        if parent.map_or(true, |s| s.attributes & STREAM_SPARSE_ATTRIBUTE == 0) {
            read.problems.push(format!(
                "stream {i}: a sparse block without a preceding sparse data stream"
            ));
        }
    }
    read
}

impl ResourceData {
    /// A stream's data.
    #[must_use]
    pub fn stream_data(&self, stream: &Stream) -> &[u8] {
        self.content.get(stream.range.clone()).unwrap_or_default()
    }

    /// What was quarantined: a non-sparse file's data (its first data stream), or a hive.
    ///
    /// A sparse file is not one contiguous borrowed range: this returns `None` for it. Use
    /// [`ResourceData::reconstruct_sparse_file`] with the file size from its entry instead.
    #[must_use]
    pub fn file_data(&self) -> Option<&[u8]> {
        if self.hive {
            return Some(&self.content);
        }
        let (data_i, data) = self
            .streams
            .iter()
            .enumerate()
            .find(|(_, stream)| stream.kind == 1)?;
        if data.attributes & STREAM_SPARSE_ATTRIBUTE != 0
            || self.streams[data_i + 1..]
                .iter()
                .take_while(|stream| !matches!(stream.kind, 1 | 4))
                .any(|stream| stream.kind == 9)
        {
            return None;
        }
        Some(self.stream_data(data))
    }

    /// Reconstruct a sparse file's unnamed data stream, including its zero regions.
    ///
    /// `size` is the logical file size from the quarantine entry's `FileSize` field. A sparse
    /// block starts with its 8-byte file offset; the bytes after it are placed there. Blocks after
    /// an alternate-data stream belong to that named stream, not to the file's unnamed stream.
    ///
    /// # Errors
    /// When the content has no sparse data stream, a block is malformed or falls outside `size`,
    /// or a buffer of `size` bytes cannot be represented or reserved.
    pub fn reconstruct_sparse_file(&self, size: u64) -> Result<Vec<u8>, Error> {
        if self.hive {
            return Err(Error("a registry hive is not a sparse file".to_owned()));
        }
        let Some((data_i, data)) = self
            .streams
            .iter()
            .enumerate()
            .find(|(_, stream)| stream.kind == 1)
        else {
            return Err(Error("no data stream".to_owned()));
        };
        let has_blocks = self.streams[data_i + 1..]
            .iter()
            .take_while(|stream| !matches!(stream.kind, 1 | 4))
            .any(|stream| stream.kind == 9);
        if data.attributes & STREAM_SPARSE_ATTRIBUTE == 0 && !has_blocks {
            return Err(Error("the data stream is not sparse".to_owned()));
        }
        let size = usize::try_from(size)
            .map_err(|_| Error("the sparse file's size does not fit in memory".to_owned()))?;
        let base = self.stream_data(data);
        if base.len() > size {
            return Err(Error(format!(
                "the data stream has {} bytes, more than the file's {size}",
                base.len()
            )));
        }
        let mut file = Vec::new();
        file.try_reserve_exact(size)
            .map_err(|_| Error(format!("could not reserve the sparse file's {size} bytes")))?;
        file.resize(size, 0);
        file[..base.len()].copy_from_slice(base);

        for (i, stream) in self.streams[data_i + 1..].iter().enumerate() {
            if matches!(stream.kind, 1 | 4) {
                break;
            }
            if stream.kind != 9 {
                continue;
            }
            let n = data_i + 1 + i;
            let block = self.stream_data(stream);
            let offset = u64_at(block, 0)
                .ok_or_else(|| Error(format!("stream {n}: a sparse block without its offset")))?;
            let offset = usize::try_from(offset)
                .map_err(|_| Error(format!("stream {n}: a sparse block offset too large")))?;
            let bytes = &block[8..];
            let end = offset
                .checked_add(bytes.len())
                .filter(|&end| end <= size)
                .ok_or_else(|| {
                    Error(format!(
                        "stream {n}: a sparse block outside the file's {size} bytes"
                    ))
                })?;
            file[offset..end].copy_from_slice(bytes);
        }
        Ok(file)
    }

    /// The file's owner (a SID, `S-1-5-21-…`), from its security descriptor.
    #[must_use]
    pub fn owner(&self) -> Option<String> {
        let stream = self.streams.iter().find(|s| s.kind == 3)?;
        let descriptor = self.stream_data(stream);
        let owner = u32_at(descriptor, 4)? as usize;
        (owner != 0).then(|| sid(descriptor.get(owner..)?))?
    }

    /// The `[ZoneTransfer]` values of the file's `Zone.Identifier` stream (where it was
    /// downloaded from): `ZoneId`, `ReferrerUrl`, `HostUrl`, ….
    #[must_use]
    pub fn zone_identifier(&self) -> Vec<(String, String)> {
        let Some(stream) = self
            .streams
            .iter()
            .find(|s| s.kind == 4 && s.name.eq_ignore_ascii_case(":Zone.Identifier:$DATA"))
        else {
            return Vec::new();
        };
        let text = String::from_utf8_lossy(self.stream_data(stream));
        text.lines()
            .filter_map(|line| line.split_once('='))
            .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
            .collect()
    }
}

/// A SID (`S-1-5-21-…`), as a security descriptor holds it.
fn sid(bytes: &[u8]) -> Option<String> {
    let (&revision, &count) = (bytes.first()?, bytes.get(1)?);
    let authority = bytes.get(2..8)?;
    if revision != 1 || count > 15 {
        return None;
    }
    let authority = authority.iter().fold(0u64, |a, &b| (a << 8) | u64::from(b));
    let mut text = format!("S-1-{authority}");
    for i in 0..usize::from(count) {
        let _ = write!(text, "-{}", u32_at(bytes, 8 + 4 * i)?);
    }
    Some(text)
}

/// A file's hashes, lower case: what the detection history's tracking data holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hashes {
    /// MD5.
    pub md5: String,
    /// SHA-1.
    pub sha1: String,
    /// SHA-256.
    pub sha256: String,
}

/// The MD5, SHA-1 and SHA-256 of `data`.
#[must_use]
pub fn hashes(data: &[u8]) -> Hashes {
    Hashes {
        md5: hex(&Md5::digest(data)),
        sha1: hex(&Sha1::digest(data)),
        sha256: hex(&Sha256::digest(data)),
    }
}
