//! A protection log written as Defender writes them
//! (`tests/fixtures/written/`, by `tests/oracle/gen_mplog.py`), read as
//! Intrinsec's `mplog_parser` reads it (`tests/oracle/intrinsec-mplog.tsv`):
//! every row it gives, given the same. It knows older line shapes only, so
//! some entries are checked here alone: the numbered `Blocked file(#74)`,
//! `DETECTION_ADD#1`, `MPSOURCE_REALTIME` detection events, an EMS scan of
//! a process named with its extension, cleaning, filter caching, SDN
//! queries, EMS detections and exclusions.

use std::path::Path;

use common::time::{Semantic, Ts};
use defender::{is_mplog_name, read_mplog, Entry, EntryKind};

const NAME: &str = "MPLog-20231219-093000.log";

fn log() -> Vec<Entry> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/written")
        .join(NAME);
    let log = read_mplog(&std::fs::read(path).unwrap());
    assert_eq!(log.problems, Vec::<String>::new());
    log.entries
}

/// A line's time as written (`2023-12-19T09:33:29.026Z`).
fn stamp(ts: Option<Ts>) -> String {
    let iso = ts.unwrap().to_iso8601().unwrap();
    format!("{}Z", &iso[..23])
}

/// Which value a column takes when a block repeats its label.
#[derive(Clone, Copy)]
enum Pick {
    First,
    /// Intrinsec keeps the last.
    Last,
}

/// Intrinsec's CSV for a kind of entry, whether its rows have the line's
/// time, and its columns' labels here.
type Mapping = (
    EntryKind,
    &'static str,
    bool,
    Pick,
    &'static [(&'static str, &'static str)],
);

const MINI_FILTER: &[(&str, &str)] = &[
    ("full_path", "Path"),
    ("process_name", "Process"),
    ("status", "Status"),
    ("state", "State"),
    ("scan_request", "ScanRequest"),
    ("file_id", "FileId"),
    ("reason", "Reason"),
    ("io_status_block_for_new_file", "IoStatusBlockForNewFile"),
    ("desiredaccess", "DesiredAccess"),
    ("file_attributes", "FileAttributes"),
    ("scan_attributes", "ScanAttributes"),
    ("access_state_flags", "AccessStateFlags"),
    ("backing_file_info", "BackingFileInfo"),
];

const MAPPINGS: &[Mapping] = &[
    (
        EntryKind::EstimatedImpact,
        "ProcessImageName",
        true,
        Pick::First,
        &[
            ("process_image_name", "ProcessImageName"),
            ("pid", "Pid"),
            ("total_time", "TotalTime"),
            ("count", "Count"),
            ("max_time", "MaxTime"),
            ("full_path", "MaxTimeFile"),
            ("estimated_impact", "EstimatedImpact"),
        ],
    ),
    (
        EntryKind::BlockedFile,
        "BlockedFile",
        true,
        Pick::First,
        MINI_FILTER,
    ),
    (
        EntryKind::UnsuccessfulScan,
        "UnsuccessfulScanStatus",
        true,
        Pick::First,
        MINI_FILTER,
    ),
    (
        EntryKind::EmsScan,
        "Ems",
        true,
        Pick::First,
        &[
            ("process", "Process"),
            ("pid", "pid"),
            ("sigseq", "sigseq"),
            ("send_memory_scan_report", "sendMemoryScanReport"),
            ("source", "source"),
        ],
    ),
    (
        EntryKind::Lowfi,
        "Lowfi",
        true,
        Pick::First,
        &[("command_line", "CommandLine")],
    ),
    (
        EntryKind::Threat,
        "ThreatCommandLine",
        true,
        Pick::First,
        &[("command_line", "CommandLine")],
    ),
    (
        EntryKind::OriginalFileName,
        "OriginalFilename",
        true,
        Pick::First,
        &[
            ("original_filename", "OriginalFileName"),
            ("full_path", "Path"),
        ],
    ),
    (
        EntryKind::BmTelemetry,
        "BMTelemetry",
        false,
        Pick::First,
        &[
            ("guid", "GUID"),
            ("process_creation_time", "ProcessCreationTime"),
            ("signature_id", "SignatureID"),
            ("signature_sha1", "SigSha"),
            ("pid", "ProcessID"),
            ("session_id", "SessionID"),
            ("creation_time", "CreationTime"),
            ("image_path", "ImagePath"),
            ("taint_info", "Taint Info"),
            ("operations", "Operations"),
        ],
    ),
    (
        EntryKind::ResourceScan,
        "ResourceScan",
        false,
        Pick::Last,
        &[
            ("scan_id", "Scan ID"),
            ("scan_source", "Scan Source"),
            ("start_time", "Start Time"),
            ("end_time", "End Time"),
            ("resource_schema", "Resource Schema"),
            ("resource_path", "Resource Path"),
            ("result_count", "Result Count"),
            ("threat_name", "Threat Name"),
            ("id", "ID"),
            ("severity", "Severity"),
            ("number_of_resources", "Number of Resources"),
            ("extended_info_sigseq", "Extended Info - SigSeq"),
            ("extended_info_sigsha", "Extended Info - SigSha"),
        ],
    ),
    (
        EntryKind::ThreatAction,
        "ThreatAction",
        false,
        Pick::Last,
        &[
            ("start_time", "Start time"),
            ("threat_name", "Threat Name"),
            ("threat_id", "Threat ID"),
            ("action", "Action"),
            ("resource_action_complete", "Resource action complete"),
            ("path", "Path"),
        ],
    ),
];

/// An entry as Intrinsec's CSV row for it, if it has one: its CSV's name and
/// its columns, sorted, empty ones left out.
fn intrinsec(entry: &Entry) -> Option<(&'static str, Vec<(&'static str, String)>)> {
    let (name, mut columns) = special(entry).or_else(|| mapped(entry))?;
    columns.retain(|(_, value): &(&str, String)| !value.is_empty());
    columns.sort();
    Some((name, columns))
}

fn mapped(entry: &Entry) -> Option<(&'static str, Vec<(&'static str, String)>)> {
    let &(_, name, timed, pick, labels) = MAPPINGS.iter().find(|m| m.0 == entry.kind)?;
    let mut columns: Vec<(&str, String)> = labels
        .iter()
        .map(|&(column, label)| {
            let value = match pick {
                Pick::First => entry.get(label),
                Pick::Last => entry.all(label).last(),
            };
            (column, value.unwrap_or_default().to_owned())
        })
        .collect();
    if timed {
        columns.push(("timestamp", stamp(entry.time)));
    }
    if entry.kind == EntryKind::BmTelemetry {
        // The process creation, to the microsecond.
        let iso = entry.time.unwrap().to_iso8601().unwrap();
        columns.push(("timestamp", iso[..26].to_owned()));
    }
    Some((name, columns))
}

/// The rows not read label by label: detections (Intrinsec keeps the
/// threat and target as one, and an event's closing `;`), and the RTP log's
/// lists.
fn special(entry: &Entry) -> Option<(&'static str, Vec<(&'static str, String)>)> {
    let get = |label: &str| entry.get(label).unwrap_or_default();
    let detection = |end: &str| {
        let line = format!("{} {}{end}", get("ThreatName"), get("Target"));
        vec![("command_line", line), ("timestamp", stamp(entry.time))]
    };
    match entry.kind {
        EntryKind::DetectionAdd => Some(("DetectionAdd", detection(""))),
        EntryKind::DetectionEvent if get("Source") == "MPSOURCE_SYSTEM" => {
            Some(("DetectionEvent", detection(";")))
        }
        EntryKind::RtpPerf => {
            let list = |label: &str| entry.all(label).collect::<Vec<_>>().join("|");
            Some((
                "RTPPerf",
                vec![
                    ("rtp_start", get("RTPStart").to_owned()),
                    ("last_perf", get("LastPerf").to_owned()),
                    ("first_rtp_scan", get("FirstRTPScan").to_owned()),
                    ("plugin_states", get("PluginStates").to_owned()),
                    ("process_exclusions", list("ProcessExclusion")),
                    ("path_exclusions", list("PathExclusion")),
                    ("extension_exclusions", list("ExtensionExclusion")),
                ],
            ))
        }
        _ => None,
    }
}

#[test]
fn every_row_as_intrinsec_reads_it() {
    assert!(is_mplog_name(NAME));
    let entries = log();
    let got: Vec<String> = entries
        .iter()
        .filter_map(intrinsec)
        .map(|(name, columns)| {
            let cells: Vec<String> = columns.iter().map(|(k, v)| format!("{k}={v}")).collect();
            format!("{name}\t{}", cells.join("\t"))
        })
        .collect();
    let oracle = include_str!("oracle/intrinsec-mplog.tsv");
    for row in oracle.lines() {
        assert!(got.iter().any(|g| g == row), "not read the same: {row}");
    }
    // Rows Intrinsec would have but doesn't read: DETECTION_ADD#1, the
    // numbered blocked file, the EMS scan of `notepad.exe`.
    assert_eq!(got.len(), oracle.lines().count() + 3);
}

#[test]
fn entries_intrinsec_doesnt_read() {
    let entries = log();
    let of = |kind: EntryKind| entries.iter().filter(move |e| e.kind == kind);

    let blocked: Vec<&Entry> = of(EntryKind::BlockedFile).collect();
    assert_eq!(blocked.len(), 2);
    assert_eq!(
        blocked[1].get("Path"),
        Some(r"\Device\HarddiskVolume3\Users\alice\Videos\tool.exe")
    );
    assert_eq!(blocked[1].get("State"), Some("16"));

    let added: Vec<&Entry> = of(EntryKind::DetectionAdd).collect();
    assert_eq!(
        added[0].get("Path"),
        Some(r"C:\Users\alice\Videos\tool.exe")
    );
    assert_eq!(added[1].get("Pid"), Some("7968"));

    let clean = of(EntryKind::DetectionClean).next().unwrap();
    assert_eq!(clean.get("Action"), Some("MP_THREAT_ACTION_QUARANTINE"));
    assert_eq!(clean.get("ThreatName"), Some("HackTool:Win32/Example!MSR"));
    assert_eq!(clean.get("Path"), Some(r"C:\Users\alice\Videos\tool.exe"));

    let caching = of(EntryKind::FilterCachingDisabled).next().unwrap();
    assert_eq!(
        caching.get("Path"),
        Some(r"\Device\HarddiskVolume3\Users\alice\Documents\PsExec.exe")
    );

    let sdn = of(EntryKind::SdnQuery).next().unwrap();
    assert_eq!(
        sdn.get("Path"),
        Some(r"\Device\HarddiskVolume3\inetpub\wwwroot\shell.aspx")
    );
    assert_eq!(
        sdn.get("Sha256"),
        Some("1234567899876543215059e9780f802a2f75b432b0d87a0000000000000001")
    );

    let ems = of(EntryKind::EmsDetection).next().unwrap();
    assert_eq!(
        ems.get("ThreatName"),
        Some("HackTool:Win64/Example.A!!Example.A64")
    );
    assert_eq!(ems.get("pid"), Some("6108"));

    // The exclusion written with an offset is made UTC; the line that only
    // says an exclusion was discarded isn't one.
    let exclusions: Vec<&Entry> = of(EntryKind::Exclusion).collect();
    assert_eq!(exclusions.len(), 1);
    assert_eq!(stamp(exclusions[0].time), "2023-12-19T09:40:00.000Z");
    assert_eq!(exclusions[0].get("Path"), Some(r"C:\Tools\"));

    // Block times are local; the telemetry's is its process's creation.
    let scan = of(EntryKind::ResourceScan).next().unwrap();
    assert_eq!(scan.time.unwrap().semantic(), Semantic::LocalUnknownZone);
    let telemetry = of(EntryKind::BmTelemetry).next().unwrap();
    assert_eq!(stamp(telemetry.time), "2023-12-19T09:32:08.803Z");
}

#[test]
fn other_files_have_no_entries() {
    assert!(read_mplog(b"").entries.is_empty());
    assert!(read_mplog(b"just\nsome\ntext").entries.is_empty());
    assert!(read_mplog(&[0xFF, 0xFE, 0x41]).entries.is_empty());
}

proptest::proptest! {
    #[test]
    fn any_lines_read_without_panic(
        lines in proptest::collection::vec(
            proptest::collection::vec(
                proptest::sample::select(vec![
                    "2023-12-19T09:30:00.001Z ", "2023-12-19T11:40:00.000+02:00 ",
                    "ProcessImageName:", ", Pid: ", "[Mini-filter] ", "Blocked file",
                    "Unsuccessful scan status", ": ", " Process: ", "[Exclusion] ",
                    " -> ", "DETECTION_ADD", "DETECTIONEVENT ", "DETECTION_CLEANEVENT ",
                    "file:", "process:pid:", ",", "Filter caching disabled for ",
                    "Issuing SDN query for ", " (", "(sha1=", ")", "Engine:EMS scan for process: ",
                    "Engine:EMS detection: ", "=", "original file name \"", "\" for \"",
                    "\", hr=", "lowfi: ", "threat: ", "BEGIN BM telemetry", "END BM telemetry",
                    "Begin Resource Scan", "End Scan", "Start Time:", "12-19-2023 10:33:33",
                    "RTP Perf Log", "END RTP Perf Log", "Path Exclusions:", "  ", "x", " ",
                    "ProcessCreationTime:", "99999999999999999999", "é",
                    "2023-12-19T09:30:00.é01Z ",
                ]),
                0..12,
            ),
            0..30,
        )
    ) {
        let text: Vec<String> = lines.iter().map(|parts| parts.concat()).collect();
        let _ = read_mplog(text.join("\r\n").as_bytes());
    }
}
