//! Microsoft Protection logs (`ProgramData\Microsoft\Windows Defender\
//! Support\MPLog-*.log`): Defender's own troubleshooting log, kept for
//! weeks, and a record of what ran and what was found long after the event
//! logs have rolled over. UTF-16 text (UTF-8 accepted), mostly noise; the
//! entries read here are the ones investigations use:
//!
//! - estimated impact (`ProcessImageName: …, EstimatedImpact: …`): a
//!   program Defender scanned files for, with its process and the slowest
//!   file;
//! - detections (`DETECTION_ADD`, `DETECTIONEVENT`), EMS memory scans and
//!   detections, `lowfi` and `threat` lines (command lines);
//! - files blocked or not scanned by the mini-filter, original file names,
//!   exclusions (`[Exclusion]`);
//! - the multi-line blocks: behaviour monitoring telemetry, resource
//!   scans, threat actions, and the real-time protection performance log
//!   with its process, path and extension exclusions.
//!
//! Each timestamped line starts `2021-07-22T15:38:04.557Z` (or with an
//! offset, `+02:00`). The format changes with Defender's versions; fields
//! are read by their labels, so a field added or missing doesn't stop the
//! rest.

use common::time::{Precision, Ts};

/// What an entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A program and the time Defender spent scanning for it.
    EstimatedImpact,
    /// A threat detected (`DETECTION_ADD`).
    DetectionAdd,
    /// A detection event (`DETECTIONEVENT MPSOURCE_REALTIME`, `…_SYSTEM`).
    DetectionEvent,
    /// A threat cleaned (`DETECTION_CLEANEVENT`): quarantined, removed.
    DetectionClean,
    /// A file Defender found suspicious enough to stop caching its verdict
    /// (`Filter caching disabled for`): `PsExec`, scanners, remote tools.
    FilterCachingDisabled,
    /// A file looked up in the cloud, with its hashes (`SDN:Issuing SDN
    /// query`).
    SdnQuery,
    /// A low-fidelity detection, with a command line (`lowfi:`).
    Lowfi,
    /// A threat's command line (`threat:`).
    Threat,
    /// A process's memory scanned (`Engine:EMS scan for process`).
    EmsScan,
    /// A detection in a process's memory (`Engine:EMS detection`).
    EmsDetection,
    /// A file's original name (its version information).
    OriginalFileName,
    /// A path excluded from scanning (`[Exclusion]`).
    Exclusion,
    /// A file the mini-filter blocked.
    BlockedFile,
    /// A file the mini-filter couldn't scan.
    UnsuccessfulScan,
    /// Behaviour monitoring telemetry (`BEGIN BM telemetry`).
    BmTelemetry,
    /// A resource scanned (`Begin Resource Scan`).
    ResourceScan,
    /// What was done about a threat (`Beginning threat actions`).
    ThreatAction,
    /// The real-time protection performance log, with the exclusions.
    RtpPerf,
}

impl EntryKind {
    /// Its name (`DetectionAdd`).
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::EstimatedImpact => "EstimatedImpact",
            Self::DetectionAdd => "DetectionAdd",
            Self::DetectionEvent => "DetectionEvent",
            Self::DetectionClean => "DetectionClean",
            Self::FilterCachingDisabled => "FilterCachingDisabled",
            Self::SdnQuery => "SdnQuery",
            Self::Lowfi => "Lowfi",
            Self::Threat => "Threat",
            Self::EmsScan => "EmsScan",
            Self::EmsDetection => "EmsDetection",
            Self::OriginalFileName => "OriginalFileName",
            Self::Exclusion => "Exclusion",
            Self::BlockedFile => "BlockedFile",
            Self::UnsuccessfulScan => "UnsuccessfulScan",
            Self::BmTelemetry => "BmTelemetry",
            Self::ResourceScan => "ResourceScan",
            Self::ThreatAction => "ThreatAction",
            Self::RtpPerf => "RtpPerf",
        }
    }
}

/// An entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Its first line (1 the first).
    pub line: usize,
    /// When: the line's time, or for a block, the time it holds (a
    /// telemetry's process creation, a scan's start).
    pub time: Option<Ts>,
    /// What it is.
    pub kind: EntryKind,
    /// Its values by label, in order (a label may repeat in a block: one
    /// per resource).
    pub fields: Vec<(String, String)>,
}

impl Entry {
    /// The first value of `label`.
    #[must_use]
    pub fn get(&self, label: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(l, _)| l == label)
            .map(|(_, v)| v.as_str())
    }

    /// Every value of `label`.
    pub fn all<'a>(&'a self, label: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.fields
            .iter()
            .filter(move |(l, _)| l == label)
            .map(|(_, v)| v.as_str())
    }
}

/// A log's entries and what couldn't be read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MpLog {
    /// The entries, in file order.
    pub entries: Vec<Entry>,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

/// Whether a file's name is a protection log's (`MPLog-<date>-<time>.log`).
#[must_use]
pub fn is_mplog_name(name: &str) -> bool {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    base.get(..6)
        .is_some_and(|p| p.eq_ignore_ascii_case("MPLog-"))
        && base.to_ascii_lowercase().ends_with(".log")
}

/// The labels of an estimated impact line.
const IMPACT: &[&str] = &[
    "ProcessImageName",
    "Pid",
    "TotalTime",
    "Count",
    "MaxTime",
    "MaxTimeFile",
    "EstimatedImpact",
];
/// The labels after a mini-filter line's path.
const MINI_FILTER: &[&str] = &[
    "Process",
    "Status",
    "State",
    "ScanRequest",
    "FileId",
    "Reason",
    "IoStatusBlockForNewFile",
    "DesiredAccess",
    "FileAttributes",
    "ScanAttributes",
    "AccessStateFlags",
    "BackingFileInfo",
];
/// The labels of an EMS scan line.
const EMS_SCAN: &[&str] = &["pid", "sigseq", "sendMemoryScanReport", "source"];

/// The multi-line blocks: kind, first line's start, last line's start.
const BLOCKS: &[(EntryKind, &str, &str)] = &[
    (
        EntryKind::BmTelemetry,
        "BEGIN BM telemetry",
        "END BM telemetry",
    ),
    (EntryKind::ResourceScan, "Begin Resource Scan", "End Scan"),
    (
        EntryKind::ThreatAction,
        "Beginning threat actions",
        "Finished threat actions",
    ),
];
/// The most lines a block spans before it is given up as unterminated.
const MAX_BLOCK: usize = 2000;

/// Read a protection log.
#[must_use]
pub fn read_mplog(data: &[u8]) -> MpLog {
    let mut log = MpLog::default();
    let text = decode(data, &mut log.problems);
    let lines: Vec<&str> = text.lines().map(|l| l.trim_end_matches('\r')).collect();
    let mut at = 0;
    while at < lines.len() {
        let line = lines[at];
        if let Some((entry, used)) = block(&lines, at) {
            log.entries.push(entry);
            at += used;
            continue;
        }
        if let Some((time, rest)) = timestamped(line) {
            if let Some((kind, fields)) = single(rest) {
                log.entries.push(Entry {
                    line: at + 1,
                    time: Some(time),
                    kind,
                    fields,
                });
            }
        }
        at += 1;
    }
    log
}

/// The text: UTF-16LE (with or without its byte order mark) or UTF-8.
fn decode(data: &[u8], problems: &mut Vec<String>) -> String {
    let utf16 = data.starts_with(&[0xFF, 0xFE])
        || (data.len() >= 4 && data[1] == 0 && data[3] == 0 && data[0] != 0);
    if utf16 {
        let body = data.strip_prefix(&[0xFF, 0xFE]).unwrap_or(data);
        let decoded = common::text::utf16le(body);
        if decoded.escaped {
            problems.push("text that isn't valid UTF-16, escaped".to_owned());
        }
        decoded.text
    } else {
        let body = data.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(data);
        String::from_utf8_lossy(body).into_owned()
    }
}

/// A line's time and the rest, if it starts with one.
fn timestamped(line: &str) -> Option<(Ts, &str)> {
    let (stamp, rest) = line.split_once(' ')?;
    if stamp.len() < 23 || !stamp.is_ascii() || !stamp.as_bytes()[0].is_ascii_digit() {
        return None;
    }
    Some((time(stamp)?, rest))
}

/// `2021-07-22T15:38:04.557Z`, or with an offset (`+02:00`) made UTC; to
/// the millisecond, as written.
fn time(stamp: &str) -> Option<Ts> {
    let (utc, shift) = if stamp.ends_with('Z') {
        (stamp.to_owned(), 0)
    } else {
        let (local, offset) = stamp.split_at(stamp.len().checked_sub(6)?);
        let sign = match offset.as_bytes()[0] {
            b'+' => 1,
            b'-' => -1,
            _ => return None,
        };
        let (hours, minutes) = offset[1..].split_once(':')?;
        let minutes = hours.parse::<i64>().ok()? * 60 + minutes.parse::<i64>().ok()?;
        (format!("{local}Z"), sign * minutes * 60 * 10_000_000)
    };
    let ticks = Ts::parse_iso8601_utc(&utc)?.ticks()?.checked_sub(shift)?;
    Some(Ts::from_ticks(ticks, Precision::Millisecond))
}

type Fields = Vec<(String, String)>;

/// A timestamped line's entry, if it is one read here.
fn single(rest: &str) -> Option<(EntryKind, Fields)> {
    if let Some(body) = rest.strip_prefix("ProcessImageName:") {
        return Some((
            EntryKind::EstimatedImpact,
            labelled(&format!("ProcessImageName:{body}"), IMPACT),
        ));
    }
    if let Some(at) = rest.find("[Mini-filter] ") {
        return mini_filter(&rest[at + 14..]);
    }
    if let Some(at) = rest.find("[Exclusion] ") {
        let (path, device) = rest[at + 12..].split_once(" -> ")?;
        return Some((
            EntryKind::Exclusion,
            pairs(&[("Path", path), ("DevicePath", device)]),
        ));
    }
    if let Some(at) = rest.find("DETECTION_ADD") {
        let (_, body) = rest[at..].split_once(' ')?;
        return Some((EntryKind::DetectionAdd, detection(&[], body)));
    }
    if let Some(at) = rest.find("DETECTIONEVENT ") {
        let (source, body) = rest[at + 15..].split_once(' ')?;
        return Some((
            EntryKind::DetectionEvent,
            detection(&[("Source", source)], body),
        ));
    }
    if let Some(at) = rest.find("DETECTION_CLEANEVENT ") {
        let mut parts = rest[at + 21..].splitn(4, ' ');
        let (source, action, hr) = (parts.next()?, parts.next()?, parts.next()?);
        let fixed = [("Source", source), ("Action", action), ("Hr", hr)];
        return Some((EntryKind::DetectionClean, detection(&fixed, parts.next()?)));
    }
    if let Some(at) = rest.find("Filter caching disabled for ") {
        let body = &rest[at + 28..];
        let path = body.rsplit_once(" (runtime").map_or(body, |(path, _)| path);
        return Some((EntryKind::FilterCachingDisabled, pairs(&[("Path", path)])));
    }
    if let Some(at) = rest.find("Issuing SDN query for ") {
        return sdn_query(&rest[at + 22..]);
    }
    if let Some(at) = rest.find("Engine:EMS scan for process: ") {
        let body = &rest[at + 29..];
        let (process, labels) = body.split_once(' ')?;
        let mut fields = pairs(&[("Process", process)]);
        fields.extend(labelled(labels, EMS_SCAN));
        return Some((EntryKind::EmsScan, fields));
    }
    if let Some(at) = rest.find("Engine:EMS detection: ") {
        let mut parts = rest[at + 22..].split(", ");
        let mut fields = pairs(&[("ThreatName", parts.next()?)]);
        for part in parts {
            let (label, value) = part.split_once('=')?;
            fields.extend(pairs(&[(label, value)]));
        }
        return Some((EntryKind::EmsDetection, fields));
    }
    if let Some(at) = rest.find("original file name \"") {
        let (original, after) = rest[at + 20..].split_once("\" for \"")?;
        let (path, hr) = after.rsplit_once("\", hr=")?;
        return Some((
            EntryKind::OriginalFileName,
            pairs(&[("OriginalFileName", original), ("Path", path), ("Hr", hr)]),
        ));
    }
    if let Some(at) = rest.find("lowfi: ") {
        return Some((EntryKind::Lowfi, pairs(&[("CommandLine", &rest[at + 7..])])));
    }
    if let Some(at) = rest.find("threat: ") {
        return Some((
            EntryKind::Threat,
            pairs(&[("CommandLine", &rest[at + 8..])]),
        ));
    }
    None
}

fn pairs(items: &[(&str, &str)]) -> Fields {
    items
        .iter()
        .map(|(l, v)| ((*l).to_owned(), v.trim().to_owned()))
        .collect()
}

/// `[Mini-filter] Blocked file[(#n)]: <path>[.] Process: …` and
/// `Unsuccessful scan status…: <path> Process: …`.
fn mini_filter(body: &str) -> Option<(EntryKind, Fields)> {
    let kind = if body.starts_with("Blocked file") {
        EntryKind::BlockedFile
    } else if body.starts_with("Unsuccessful scan status") {
        EntryKind::UnsuccessfulScan
    } else {
        return None;
    };
    let rest = body.split_once(": ")?.1;
    let at = rest.find(" Process: ")?;
    let mut fields = pairs(&[("Path", rest[..at].trim_end_matches('.'))]);
    fields.extend(labelled(&rest[at + 1..], MINI_FILTER));
    Some((kind, fields))
}

/// A detection's `<threat> <target>` (after `fixed` values): the target
/// `file:<path>` (up to `;` or ` PropBag`) or `process:pid:<pid>,
/// ProcessStart:<FILETIME>`.
fn detection(fixed: &[(&str, &str)], body: &str) -> Fields {
    let (threat, target) = body.split_once(' ').unwrap_or((body, ""));
    let target = target.split(" PropBag").next().unwrap_or(target);
    let target = target.trim_end().trim_end_matches(';');
    let mut fields = pairs(fixed);
    fields.extend(pairs(&[("ThreatName", threat), ("Target", target)]));
    if let Some(path) = target.strip_prefix("file:") {
        fields.extend(pairs(&[("Path", path)]));
    } else if let Some(process) = target.strip_prefix("process:") {
        for part in process.split(',') {
            if let Some((label, value)) = part.split_once(':') {
                let label = if label == "pid" { "Pid" } else { label };
                fields.extend(pairs(&[(label, value)]));
            }
        }
    }
    fields
}

/// `<path> (<device path>) (sha1=<hex>, sha2=<hex>)`.
fn sdn_query(body: &str) -> Option<(EntryKind, Fields)> {
    let (path, rest) = body.split_once(" (")?;
    let mut fields = pairs(&[("Path", path)]);
    let hashes = rest.rsplit_once("(sha1=")?.1.trim_end_matches(')');
    for part in format!("sha1={hashes}").split(", ") {
        let (label, value) = part.split_once('=')?;
        let label = if label == "sha1" { "Sha1" } else { "Sha256" };
        fields.extend(pairs(&[(label, value)]));
    }
    Some((EntryKind::SdnQuery, fields))
}

/// `Label: value, Label: value…` read by the labels expected, in order: a
/// value runs to where the next label found starts (so a path holding
/// `, ` is kept whole). A label may be followed by `:` or a space
/// (`ScanRequest #12`); labels not found are left out.
fn labelled(text: &str, labels: &[&str]) -> Fields {
    let mut found: Vec<(usize, usize, &str)> = Vec::new();
    let mut from = 0;
    for label in labels {
        let start_ok =
            |at: usize| at == 0 || text[..at].ends_with(", ") || text[..at].ends_with(' ');
        let hit = text[from..]
            .match_indices(label)
            .map(|(at, _)| from + at)
            .find(|&at| {
                let after = &text[at + label.len()..];
                start_ok(at) && (after.starts_with(':') || after.starts_with(' '))
            });
        if let Some(at) = hit {
            let value_at = at + label.len() + 1;
            found.push((at, value_at, label));
            from = value_at;
        }
    }
    found
        .iter()
        .enumerate()
        .map(|(i, &(_, value_at, label))| {
            let end = found.get(i + 1).map_or(text.len(), |&(next, _, _)| next);
            let value = text[value_at..end].trim().trim_end_matches(',').trim();
            ((*label).to_owned(), value.to_owned())
        })
        .collect()
}

/// A multi-line block starting at `at`, and how many lines it spans.
fn block(lines: &[&str], at: usize) -> Option<(Entry, usize)> {
    let line = lines[at].trim();
    if line.contains("RTP Perf Log") && !line.contains("END RTP Perf Log") {
        return rtp_perf(lines, at);
    }
    let &(kind, _, end) = BLOCKS.iter().find(|(_, begin, _)| line.contains(begin))?;
    let body = lines
        .iter()
        .skip(at + 1)
        .take(MAX_BLOCK)
        .position(|l| l.contains(end))?;
    let mut fields = Fields::new();
    for line in &lines[at + 1..at + 1 + body] {
        if let Some((label, value)) = line.split_once(':') {
            let label = label.trim();
            let plain = |c: char| c.is_alphanumeric() || matches!(c, ' ' | '-' | '_');
            if !label.is_empty() && label.chars().all(plain) {
                fields.push((label.to_owned(), value.trim().to_owned()));
            }
        }
    }
    let time = block_time(kind, &fields);
    let entry = Entry {
        line: at + 1,
        time,
        kind,
        fields,
    };
    Some((entry, body + 2))
}

/// A block's time: a telemetry's process creation (FILETIME), a scan's or
/// threat action's start.
fn block_time(kind: EntryKind, fields: &Fields) -> Option<Ts> {
    let get = |label: &str| {
        fields
            .iter()
            .find(|(l, _)| l == label)
            .map(|(_, v)| v.as_str())
    };
    match kind {
        EntryKind::BmTelemetry => get("ProcessCreationTime")
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&t| t != 0)
            .map(Ts::from_filetime),
        EntryKind::ResourceScan => get("Start Time").and_then(us_time),
        EntryKind::ThreatAction => get("Start time").and_then(us_time),
        _ => None,
    }
}

/// `12-15-2022 11:24:33` (month first, local time), as blocks write times.
fn us_time(text: &str) -> Option<Ts> {
    let (date, clock) = text.trim().split_once(' ')?;
    let mut date = date.split('-');
    let (month, day, year) = (date.next()?, date.next()?, date.next()?);
    let ts = Ts::parse_iso8601_utc(&format!("{year}-{month}-{day}T{clock}Z"))?;
    Some(Ts::from_local_ticks(ts.ticks()?, Precision::Second))
}

/// The real-time protection performance log: its times, plugin states, and
/// the indented lists of exclusions.
fn rtp_perf(lines: &[&str], at: usize) -> Option<(Entry, usize)> {
    let body = lines
        .iter()
        .skip(at + 1)
        .take(MAX_BLOCK)
        .position(|l| l.contains("END RTP Perf Log"))?;
    let mut fields = Fields::new();
    let mut list: Option<&str> = None;
    for line in &lines[at + 1..at + 1 + body] {
        let indented = line.starts_with([' ', '\t']);
        if let (true, Some(label)) = (indented, list) {
            fields.push((label.to_owned(), line.trim().to_owned()));
            continue;
        }
        list = None;
        let Some((label, value)) = line.split_once(':') else {
            continue;
        };
        match label.trim() {
            "Process Exclusions" => list = Some("ProcessExclusion"),
            "Path Exclusions" => list = Some("PathExclusion"),
            "Ext Exclusions" => list = Some("ExtensionExclusion"),
            label @ ("RTP Start" | "Last Perf" | "First RTP Scan" | "Plugin States") => {
                fields.push((label.replace(' ', ""), value.trim().to_owned()));
            }
            _ => {}
        }
    }
    let time = fields
        .iter()
        .find(|(l, _)| l == "RTPStart")
        .and_then(|(_, v)| time(v));
    let entry = Entry {
        line: at + 1,
        time,
        kind: EntryKind::RtpPerf,
        fields,
    };
    Some((entry, body + 2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_keep_commas_in_values() {
        let fields = labelled(
            "ProcessImageName: a.exe, TotalTime: 3, MaxTimeFile: C:\\x, y\\z.dll, EstimatedImpact: 9%",
            IMPACT,
        );
        assert_eq!(
            fields,
            pairs(&[
                ("ProcessImageName", "a.exe"),
                ("TotalTime", "3"),
                ("MaxTimeFile", "C:\\x, y\\z.dll"),
                ("EstimatedImpact", "9%"),
            ])
        );
    }

    #[test]
    fn offsets_are_made_utc() {
        let ts = time("2021-07-22T17:38:04.557+02:00").unwrap();
        assert_eq!(ts, time("2021-07-22T15:38:04.557Z").unwrap());
    }

    #[test]
    fn names() {
        assert!(is_mplog_name(
            r"C:\ProgramData\Microsoft\Windows Defender\Support\MPLog-20230101-000000.log"
        ));
        assert!(!is_mplog_name("MpCmdRun.log"));
    }
}
