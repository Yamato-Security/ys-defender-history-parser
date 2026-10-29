//! Microsoft Protection logs (`ProgramData\Microsoft\Windows Defender\
//! Support\MPLog-*.log`): Defender's own troubleshooting log, kept for
//! weeks, and a record of what ran and what was found long after the event
//! logs have rolled over; and the detection logs beside them
//! (`MPDetection-*.log`): the service's starts, stops and versions. UTF-16
//! text (UTF-8 accepted), mostly noise; the entries read here are the ones
//! investigations use:
//!
//! - the service log's header (`… Service Log`): when the service started,
//!   the OS install time, the current time and the milliseconds since boot;
//! - the service starting and stopping, and its versions (product, engine,
//!   signatures);
//! - estimated impact (`ProcessImageName: …, EstimatedImpact: …`): a
//!   program Defender scanned files for, with its process and the slowest
//!   file; and the per-process counts of a process scan;
//! - detections (`DETECTION_ADD`, `DETECTIONEVENT`), EMS memory scans and
//!   detections, `lowfi` and `threat` lines (command lines);
//! - files blocked or not scanned by the mini-filter, original file names,
//!   exclusions (`[Exclusion]`, `[ProcessExclusion]`), real-time protection
//!   configuration changes;
//! - the multi-line blocks: behaviour monitoring telemetry, resource
//!   scans, threat actions, and the real-time protection performance log
//!   with its process, path and extension exclusions.
//!
//! Each timestamped line starts `2021-07-22T15:38:04.557Z` (or with an
//! offset, `+02:00`, made UTC). Newer logs also write times without the `Z`:
//! those are read as UTC inside a service log whose header (`Current time:
//! … UTC`) is within 60 seconds of its first timed line, as DLEAPP reads
//! them (a zone other than UTC is at least 15 minutes off), and otherwise as
//! times whose zone isn't known. The format changes with Defender's versions;
//! fields are read by their labels, so a field added or missing doesn't stop
//! the rest.

use crate::time::{Precision, Time};

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
    /// A file looked up in the cloud, with its device path and, when
    /// hashed, its hashes (`SDN:Issuing SDN query`).
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
    /// The service log's header: the service, when it started (local time), the
    /// OS install time, the current time and the milliseconds since boot.
    LogHeader,
    /// The service started (`Service started - <product> (<GUID>)`).
    ServiceStarted,
    /// The service stopped, with its exit code.
    ServiceStopped,
    /// The versions running: product, service, engine, signatures
    /// (`Version: Product … Service … Engine … AS … AV …`).
    Version,
    /// A program excluded from scanning (`[ProcessExclusion]`).
    ProcessExclusion,
    /// Real-time protection's configuration changed (`[RtpConfig] Config
    /// change detected, type: <n>`).
    RtpConfigChange,
    /// A process scan's count for one program (`Per-process counts:`), an
    /// untimed line: its time is the timed line's before it, the scan's start.
    ProcessCounts,
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
            Self::LogHeader => "LogHeader",
            Self::ServiceStarted => "ServiceStarted",
            Self::ServiceStopped => "ServiceStopped",
            Self::Version => "Version",
            Self::ProcessExclusion => "ProcessExclusion",
            Self::RtpConfigChange => "RtpConfigChange",
            Self::ProcessCounts => "ProcessCounts",
        }
    }
}

/// An entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Its first line (1 the first).
    pub line: usize,
    /// When: the line's time, or for a block, the time it holds (a
    /// telemetry's process creation, a scan's start, real-time protection's
    /// start).
    pub time: Option<Time>,
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

/// Whether a file's name is a protection log's (`MPLog-<date>-<time>.log`)
/// or a detection log's (`MPDetection-<date>-<time>.log`).
#[must_use]
pub fn is_mplog_name(name: &str) -> bool {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let lower = base.to_ascii_lowercase();
    let log = std::path::Path::new(&lower)
        .extension()
        .is_some_and(|e| e == "log");
    (lower.starts_with("mplog-") || lower.starts_with("mpdetection-")) && log
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
/// The labels of a version line.
const VERSION_LABELS: &[&str] = &["Product", "Service", "Engine", "AS", "AV"];
/// How near a service log's first timed line must be to its header's UTC
/// time for its times without a zone to be UTC, in 100 ns ticks.
const HEADER_AGREEMENT: u64 = 60 * 10_000_000;
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

/// Which zone the times without one are in, as a service log's header and
/// first timed line say.
#[derive(Default)]
struct Zone {
    /// The last header's time.
    header: Option<Time>,
    /// Whether this service log's first timed line has been seen.
    checked: bool,
    /// Whether its times without a zone are UTC.
    utc: bool,
    /// The last timed line's time.
    last: Option<Time>,
}

impl Zone {
    /// A new service log, and its header's time (`None` when its header was cut short: nothing
    /// then says its times without a zone are UTC).
    fn header(&mut self, time: Option<Time>) {
        *self = Self {
            header: time,
            last: self.last,
            ..Self::default()
        };
    }

    /// A line's time, its zone settled: a service log's first timed line
    /// settles whether its times without a zone are UTC.
    fn resolve(&mut self, stamp: Stamp) -> Time {
        let (Stamp::Utc(reading) | Stamp::Unzoned(reading)) = stamp;
        if !self.checked {
            self.checked = true;
            self.utc = self.header.is_some_and(|header| {
                header.filetime().abs_diff(reading.filetime()) <= HEADER_AGREEMENT
            });
        }
        let time = self.settle(stamp);
        self.last = Some(time);
        time
    }

    /// A time in this service log, UTC if it has a zone or the log's times
    /// without one are UTC.
    fn settle(&self, stamp: Stamp) -> Time {
        match stamp {
            Stamp::Unzoned(time) if self.utc => time.as_utc(),
            Stamp::Utc(time) | Stamp::Unzoned(time) => time,
        }
    }
}

/// Read a protection log or a detection log.
#[must_use]
pub fn read_mplog(data: &[u8]) -> MpLog {
    let mut log = MpLog::default();
    let text = decode(data, &mut log.problems);
    let lines: Vec<&str> = text.lines().map(|l| l.trim_end_matches('\r')).collect();
    let mut zone = Zone::default();
    let mut at = 0;
    while at < lines.len() {
        let line = lines[at];
        if let Some(time) = current_time(line) {
            zone.header(Some(time));
        }
        let record = log_header(&lines, at)
            .inspect(|header| zone.header(header.entry.time))
            .or_else(|| block(&lines, at, &zone));
        if let Some(record) = record {
            log.problems.extend(record.cut);
            log.entries.push(record.entry);
            at += record.used;
            continue;
        }
        if let Some(body) = line.strip_prefix("Per-process counts:") {
            log.entries.push(Entry {
                line: at + 1,
                time: zone.last,
                kind: EntryKind::ProcessCounts,
                fields: labelled(body, IMPACT),
            });
        } else if let Some((stamp, rest)) = timestamped(line) {
            let time = zone.resolve(stamp);
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
        let pairs = body.chunks_exact(2);
        if !pairs.remainder().is_empty() {
            problems.push("an odd byte at the end (UTF-16 is in pairs), not read".to_owned());
        }
        let units: Vec<u16> = pairs.map(|p| u16::from_le_bytes([p[0], p[1]])).collect();
        String::from_utf16(&units).unwrap_or_else(|_| {
            problems.push("text that isn't valid UTF-16, replaced".to_owned());
            String::from_utf16_lossy(&units)
        })
    } else {
        let body = data.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(data);
        if let Ok(text) = std::str::from_utf8(body) {
            text.to_owned()
        } else {
            problems.push("text that isn't valid UTF-8, replaced".to_owned());
            String::from_utf8_lossy(body).into_owned()
        }
    }
}

/// A line's time: UTC (`Z`, or an offset made UTC), or without a zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stamp {
    Utc(Time),
    Unzoned(Time),
}

/// A line's time and the rest, if it starts with one.
fn timestamped(line: &str) -> Option<(Stamp, &str)> {
    let (stamp, rest) = line.split_once(' ')?;
    if stamp.len() < 19 || !stamp.is_ascii() || !stamp.as_bytes()[0].is_ascii_digit() {
        return None;
    }
    Some((time(stamp)?, rest))
}

/// `2021-07-22T15:38:04.557Z`, with an offset (`+02:00`) made UTC, or
/// without either; to the precision written.
fn time(stamp: &str) -> Option<Stamp> {
    if let Some(utc) = stamp.strip_suffix('Z') {
        return Some(Stamp::Utc(clock(utc)?.as_utc()));
    }
    let split = stamp.len().checked_sub(6)?;
    if let (Some(local), Some(offset)) = (stamp.get(..split), stamp.get(split..)) {
        let sign = match offset.as_bytes()[0] {
            b'+' => 1,
            b'-' => -1,
            _ => 0,
        };
        if sign != 0 && offset.as_bytes()[3] == b':' {
            // RFC 3339's range: hours 00 to 23, minutes 00 to 59.
            let hours: i64 = number(&offset[1..3]).filter(|h| *h <= 23)?;
            let minutes: i64 = number(&offset[4..]).filter(|m| *m <= 59)?;
            let shifted = clock(local)?.shifted(-sign * (hours * 60 + minutes))?;
            return Some(Stamp::Utc(shifted.as_utc()));
        }
    }
    Some(Stamp::Unzoned(clock(stamp)?))
}

/// A number written in digits only: Rust's parsing also takes a sign (`+1`), which no time
/// written here holds.
fn number<T: std::str::FromStr>(text: &str) -> Option<T> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// `YYYY-MM-DDTHH:MM:SS[.fraction]`, its zone not known.
fn clock(text: &str) -> Option<Time> {
    let (date, clock) = text.split_once('T')?;
    let mut date = date.split('-');
    let (year, month, day) = (date.next()?, date.next()?, date.next()?);
    if date.next().is_some() {
        return None;
    }
    let date = (number(year)?, number(month)?, number(day)?);
    calendar(date, clock)
}

/// A date and `HH:MM:SS[.fraction]`, its zone not known.
fn calendar(date: (i64, u32, u32), clock: &str) -> Option<Time> {
    let (whole, fraction) = clock.split_once('.').unwrap_or((clock, ""));
    let mut parts = whole.split(':');
    let (hour, minute, second) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let digits = &fraction[..fraction.len().min(7)];
    let ticks = format!("{digits:0<7}").parse().ok()?;
    let precision = match fraction.len() {
        0 => Precision::Second,
        1..=3 => Precision::Millisecond,
        _ => Precision::Tick,
    };
    let clock = (number(hour)?, number(minute)?, number(second)?);
    Time::from_parts(date, clock, ticks, false, precision)
}

/// `MM/DD/YYYY HH:MM:SS[.fraction] UTC`, as a service log's header writes
/// times.
fn header_time(text: &str) -> Option<Time> {
    let (date, rest) = text.trim().split_once(' ')?;
    let clock = rest
        .strip_suffix(" UTC")
        .or_else(|| rest.split_once(" UTC ").map(|(c, _)| c))?;
    let mut date = date.split('/');
    let (month, day, year) = (date.next()?, date.next()?, date.next()?);
    let date = (number(year)?, number(month)?, number(day)?);
    Some(calendar(date, clock)?.as_utc())
}

/// A service log header's `Current time: <UTC time> (<n> ms since boot)`.
fn current_time(line: &str) -> Option<Time> {
    header_time(line.strip_prefix("Current time: ")?)
}

/// A multi-line record read: its entry, the lines it spans, and when its end
/// wasn't found, a problem saying so.
struct Record {
    entry: Entry,
    used: usize,
    cut: Option<String>,
}

impl Record {
    /// A record of `body` lines after its first, ended by `end` or cut short.
    fn new(entry: Entry, body: usize, ended: bool, end: &str) -> Self {
        let cut = (!ended).then(|| {
            format!(
                "line {}: {} without its end ({end}), read to line {}",
                entry.line,
                entry.kind.name(),
                entry.line + body
            )
        });
        Self {
            used: 1 + body + usize::from(ended),
            entry,
            cut,
        }
    }
}

/// How many lines after `at` a record's body spans, and whether its end
/// (`is_end`) follows them. A record is cut short by a timed line or another
/// record's start (no record holds either), by `limit` lines, or by the
/// file's end.
fn extent(lines: &[&str], at: usize, limit: usize, is_end: impl Fn(&str) -> bool) -> (usize, bool) {
    for (n, line) in lines.iter().skip(at + 1).take(limit).enumerate() {
        if is_end(line) {
            return (n, true);
        }
        if starts_record(line) {
            return (n, false);
        }
    }
    (lines.len().saturating_sub(at + 1).min(limit), false)
}

/// Whether a line starts something of its own: a timed line, a service log,
/// a block.
fn starts_record(line: &str) -> bool {
    let line = line.trim();
    timestamped(line).is_some()
        || line.ends_with(" Service Log")
        || (line.contains("RTP Perf Log") && !line.contains("END RTP Perf Log"))
        || BLOCKS.iter().any(|(_, begin, _)| line.contains(begin))
}

/// The service log's header, from its `<service> (<GUID>) Service Log` line
/// to its `Current time:` line.
fn log_header(lines: &[&str], at: usize) -> Option<Record> {
    let title = lines[at].trim().strip_suffix(" Service Log")?;
    let mut fields = Fields::new();
    match title.rsplit_once(" (") {
        Some((service, id)) => fields.extend(pairs(&[
            ("Service", service),
            ("Id", id.trim_end_matches(')')),
        ])),
        None => fields.extend(pairs(&[("Service", title)])),
    }
    let (body, ended) = extent(lines, at, 8, |l| l.starts_with("Current time: "));
    for line in &lines[at + 1..at + 1 + body] {
        if let Some(started) = line.strip_prefix("Started On ") {
            fields.extend(pairs(&[("StartedOn", started)]));
        } else if let Some(installed) = line.strip_prefix("OS install time: ") {
            let installed =
                header_time(installed).map_or_else(|| installed.to_owned(), Time::to_iso8601);
            fields.push(("OsInstallTime".to_owned(), installed));
        }
    }
    let mut time = None;
    if let Some(current) = ended.then(|| &lines[at + 1 + body]["Current time: ".len()..]) {
        time = header_time(current);
        if let Some(time) = time {
            fields.push(("CurrentTime".to_owned(), time.to_iso8601()));
        }
        if let Some((_, boot)) = current.split_once(" (") {
            let ms = boot
                .trim_end_matches(')')
                .trim_end_matches(" ms since boot");
            fields.extend(pairs(&[("MsSinceBoot", ms)]));
        }
    }
    let entry = Entry {
        line: at + 1,
        time,
        kind: EntryKind::LogHeader,
        fields,
    };
    Some(Record::new(entry, body, ended, "Current time:"))
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
    if let Some(found) = service(rest) {
        return Some(found);
    }
    if let Some(at) = rest.find("[ProcessExclusion] ") {
        let (path, device) = rest[at + 19..].split_once(" -> ")?;
        return Some((
            EntryKind::ProcessExclusion,
            pairs(&[("Path", path), ("DevicePath", device)]),
        ));
    }
    if let Some(at) = rest.find("[RtpConfig] Config change detected, type: ") {
        return Some((
            EntryKind::RtpConfigChange,
            pairs(&[("Type", &rest[at + 42..])]),
        ));
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
    if let Some(at) = rest.find("EMS scan for process: ") {
        let body = &rest[at + 22..];
        // The process's name runs to its pid (a name may hold spaces).
        let (process, labels) = match body.find(" pid: ") {
            Some(pid) => (&body[..pid], &body[pid + 1..]),
            None => body.split_once(' ')?,
        };
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

/// The service's lines: started, stopped, its versions.
fn service(rest: &str) -> Option<(EntryKind, Fields)> {
    if let Some(body) = rest.strip_prefix("Service started - ") {
        let (product, id) = body.rsplit_once(" (").unwrap_or((body, ""));
        let id = id.trim_end_matches(')');
        return Some((
            EntryKind::ServiceStarted,
            pairs(&[("Product", product), ("Id", id)]),
        ));
    }
    if let Some(code) = rest.strip_prefix("Service stopped with exit code ") {
        return Some((EntryKind::ServiceStopped, pairs(&[("ExitCode", code)])));
    }
    if let Some(body) = rest.strip_prefix("Version: ") {
        return Some((EntryKind::Version, labelled(body, VERSION_LABELS)));
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

/// `<path> (<device path>)`, then `(sha1=<hex>, sha2=<hex>)` when the
/// file was hashed.
fn sdn_query(body: &str) -> Option<(EntryKind, Fields)> {
    let body = body.trim_end();
    let (paths, hashes) = match body.rsplit_once(" (sha1=") {
        Some((paths, hashes)) if hashes.ends_with(')') && !hashes.contains('(') => {
            (paths, Some(&hashes[..hashes.len() - 1]))
        }
        _ => (body, None),
    };
    let (path, device) = last_group(paths)?;
    let mut fields = pairs(&[("Path", path), ("DevicePath", device)]);
    for part in hashes
        .map(|h| format!("sha1={h}"))
        .iter()
        .flat_map(|h| h.split(", "))
    {
        let (label, value) = part.split_once('=')?;
        let label = if label == "sha1" { "Sha1" } else { "Sha256" };
        fields.extend(pairs(&[(label, value)]));
    }
    Some((EntryKind::SdnQuery, fields))
}

/// `<text> (<group>)`: what is before the group ending `text`, and the group. Paths hold
/// parentheses too (`Program Files (x86)`, `archive.zip->(member)`, a name with one alone), so of
/// the ` (` the group may start at, the one is taken whose group starts like a path (`\`, `X:`),
/// ends with the name the text before it ends with (an archive's `->member` aside), and has its
/// parentheses balanced, the most of these; the first, of several as good.
fn last_group(text: &str) -> Option<(&str, &str)> {
    let inner = text.strip_suffix(')')?;
    let balanced = |group: &str| {
        let mut depth = 0usize;
        for c in group.chars() {
            match c {
                '(' => depth += 1,
                ')' => match depth.checked_sub(1) {
                    Some(d) => depth = d,
                    None => return false,
                },
                _ => {}
            }
        }
        depth == 0
    };
    let name = |path: &str| {
        let last = path.rsplit('\\').next().unwrap_or(path);
        last.split("->").next().unwrap_or(last).to_ascii_lowercase()
    };
    let path_like = |group: &str| {
        let b = group.as_bytes();
        b.first() == Some(&b'\\') || (b.len() > 1 && b[0].is_ascii_alphabetic() && b[1] == b':')
    };
    let at = inner
        .rmatch_indices(" (")
        .map(|(at, _)| at)
        .max_by_key(|&at| {
            let (before, group) = (&inner[..at], &inner[at + 2..]);
            (
                path_like(group),
                name(before) == name(group),
                balanced(group),
            )
        })?;
    Some((&inner[..at], &inner[at + 2..]))
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
fn block(lines: &[&str], at: usize, zone: &Zone) -> Option<Record> {
    let line = lines[at].trim();
    if line.contains("RTP Perf Log") && !line.contains("END RTP Perf Log") {
        return Some(rtp_perf(lines, at, zone));
    }
    let &(kind, _, end) = BLOCKS.iter().find(|(_, begin, _)| line.contains(begin))?;
    let (body, ended) = extent(lines, at, MAX_BLOCK, |l| l.contains(end));
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
    Some(Record::new(entry, body, ended, end))
}

/// A block's time: a telemetry's process creation (FILETIME), a scan's or
/// threat action's start.
fn block_time(kind: EntryKind, fields: &Fields) -> Option<Time> {
    let get = |label: &str| {
        fields
            .iter()
            .find(|(l, _)| l == label)
            .map(|(_, v)| v.as_str())
    };
    match kind {
        EntryKind::BmTelemetry => get("ProcessCreationTime")
            .and_then(number::<u64>)
            .and_then(Time::from_filetime),
        EntryKind::ResourceScan => get("Start Time").and_then(us_time),
        EntryKind::ThreatAction => get("Start time").and_then(us_time),
        _ => None,
    }
}

/// `12-15-2022 11:24:33` (month first, local time), as blocks write times.
fn us_time(text: &str) -> Option<Time> {
    // Some logs put left-to-right marks around the date's numbers.
    let text: String = text
        .chars()
        .filter(|c| !matches!(c, '\u{200E}' | '\u{200F}'))
        .collect();
    let (date, clock) = text.trim().split_once(' ')?;
    let mut date = date.split('-');
    let (month, day, year) = (date.next()?, date.next()?, date.next()?);
    let date = (number(year)?, number(month)?, number(day)?);
    calendar(date, clock)
}

/// The real-time protection performance log: its times, plugin states, and
/// the indented lists of exclusions.
fn rtp_perf(lines: &[&str], at: usize, zone: &Zone) -> Record {
    const END: &str = "END RTP Perf Log";
    let (body, ended) = extent(lines, at, MAX_BLOCK, |l| l.contains(END));
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
        .and_then(|(_, v)| {
            time(v)
                .map(|stamp| zone.settle(stamp))
                .or_else(|| us_time(v))
        });
    let entry = Entry {
        line: at + 1,
        time,
        kind: EntryKind::RtpPerf,
        fields,
    };
    Record::new(entry, body, ended, END)
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
        let Stamp::Utc(ts) = ts else { panic!("{ts:?}") };
        assert_eq!(ts.to_iso8601(), "2021-07-22T15:38:04.557Z");
        assert!(matches!(
            time("2021-07-22T15:38:04.557"),
            Some(Stamp::Unzoned(t)) if t.to_iso8601() == "2021-07-22T15:38:04.557"
        ));
        assert_eq!(time("2021-07-22T15:38:04.557+0200"), None);
        assert_eq!(time("2021-02-30T15:38:04.557Z"), None);
        // Offsets out of RFC 3339's range, and signed numbers, aren't times.
        assert_eq!(time("2021-07-22T17:38:04.557+02:60"), None);
        assert_eq!(time("2021-07-22T17:38:04.557+24:00"), None);
        assert_eq!(time("2021-07-22T17:38:04.557+-1:00"), None);
        assert_eq!(time("2021-07-22T17:38:04.557-0+:00"), None);
        assert_eq!(time("2021-07-22T+7:38:04.557Z"), None);
        assert_eq!(time("+021-07-22T17:38:04.557Z"), None);
        assert_eq!(us_time("+7-22-2021 17:38:04"), None);
        assert_eq!(
            time("2021-07-22T17:38:04.557-23:59"),
            time("2021-07-23T17:37:04.557Z")
        );
        // Offsets taking a time out of 1601 to 9999.
        assert_eq!(time("9999-12-31T23:59:59.000-23:59"), None);
        assert_eq!(time("1601-01-01T00:00:00.000+00:01"), None);
    }

    /// The times of a log's estimated impact lines.
    fn times(text: &str) -> Vec<String> {
        read_mplog(text.as_bytes())
            .entries
            .iter()
            .filter(|e| e.kind == EntryKind::EstimatedImpact)
            .map(|e| e.time.unwrap().to_iso8601())
            .collect()
    }

    #[test]
    fn times_without_a_zone() {
        let impact = "ProcessImageName: a.exe, Pid: 1, TotalTime: 1, Count: 1, MaxTime: 1, MaxTimeFile: x, EstimatedImpact: 1%";
        let header = |time: &str| {
            format!(
                "Microsoft Defender Antivirus (77BDAF73-B396-481F-9042-AD358843EC24) Service Log\n\
                 Started On 05-06-2024 06:20:45\n\
                 ****\n\
                 Current time: {time} UTC (5000 ms since boot)\n"
            )
        };
        // Its header within a minute of its first timed line: UTC.
        let utc = format!(
            "{}2024-05-06T13:20:45.250 {impact}\n2024-05-06T18:00:00.000 {impact}\n",
            header("05/06/2024 13:20:45.123456789")
        );
        assert_eq!(
            times(&utc),
            ["2024-05-06T13:20:45.250Z", "2024-05-06T18:00:00.000Z"]
        );
        // Hours away (written in local time): zone not known; and so with no header.
        let local = format!(
            "{}2024-05-06T06:20:45.250 {impact}\n",
            header("05/06/2024 13:20:45.123456789")
        );
        assert_eq!(times(&local), ["2024-05-06T06:20:45.250"]);
        assert_eq!(
            times(&format!("2024-05-06T13:20:45.250 {impact}\n")),
            ["2024-05-06T13:20:45.250"]
        );
        // Each service log is settled anew; a time with its Z is UTC either way.
        let both = format!("{local}2024-05-06T07:00:00.000Z {impact}\n{utc}");
        assert_eq!(
            times(&both),
            [
                "2024-05-06T06:20:45.250",
                "2024-05-06T07:00:00.000Z",
                "2024-05-06T13:20:45.250Z",
                "2024-05-06T18:00:00.000Z"
            ]
        );
    }

    #[test]
    fn ems_process_names_with_spaces() {
        let (kind, fields) =
            single("EMS scan for process: My App pid: 42, sigseq: 0x0, sendMemoryScanReport: 0")
                .unwrap();
        assert_eq!(kind, EntryKind::EmsScan);
        assert_eq!(
            fields,
            pairs(&[
                ("Process", "My App"),
                ("pid", "42"),
                ("sigseq", "0x0"),
                ("sendMemoryScanReport", "0")
            ])
        );
    }

    #[test]
    fn device_paths_after_paths_with_parentheses() {
        let read = |body: &str| sdn_query(body).unwrap().1;
        let fields = |items: &[(&str, &str)]| pairs(items);
        assert_eq!(
            read(r"C:\a (x86)\b.exe (\Device\HarddiskVolume3\a (x86)\b.exe) (sha1=11, sha2=22)"),
            fields(&[
                ("Path", r"C:\a (x86)\b.exe"),
                ("DevicePath", r"\Device\HarddiskVolume3\a (x86)\b.exe"),
                ("Sha1", "11"),
                ("Sha256", "22"),
            ])
        );
        // An archive's member, and no hashes.
        assert_eq!(
            read(
                r"\Device\HarddiskVolume3\t\b.jsp->(SCRIPT0065) (\Device\HarddiskVolume3\t\b.jsp)"
            ),
            fields(&[
                ("Path", r"\Device\HarddiskVolume3\t\b.jsp->(SCRIPT0065)"),
                ("DevicePath", r"\Device\HarddiskVolume3\t\b.jsp"),
            ])
        );
        // A parenthesis alone in a name: the group starting like a path.
        assert_eq!(
            read(r"C:\x (1\b.exe (\Device\HarddiskVolume3\x (1\b.exe)"),
            fields(&[
                ("Path", r"C:\x (1\b.exe"),
                ("DevicePath", r"\Device\HarddiskVolume3\x (1\b.exe"),
            ])
        );
        assert_eq!(sdn_query(r"C:\no\device\path.exe"), None);
    }

    #[test]
    fn header_times() {
        let line = "Current time: 08/01/2020 21:48:49.717895900 UTC (12656 ms since boot)";
        assert_eq!(
            current_time(line).unwrap().to_iso8601(),
            "2020-08-01T21:48:49.7178959Z"
        );
        assert_eq!(
            header_time("08/01/2020 21:48:28.0 UTC")
                .unwrap()
                .to_iso8601(),
            "2020-08-01T21:48:28.000Z"
        );
    }

    #[test]
    fn names() {
        assert!(is_mplog_name(
            r"C:\ProgramData\Microsoft\Windows Defender\Support\MPLog-20230101-000000.log"
        ));
        assert!(is_mplog_name("MPDetection-20210213-115635.log"));
        assert!(!is_mplog_name("MpCmdRun.log"));
    }
}
