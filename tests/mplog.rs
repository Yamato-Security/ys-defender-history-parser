//! A protection log written as Defender writes them
//! (`tests/fixtures/written/`, by `tests/oracle/gen_mplog.py`), read as
//! Intrinsec's `mplog_parser` reads it (`tests/oracle/intrinsec-mplog.tsv`):
//! every row it gives, given the same. It knows older line shapes only, so
//! some entries are checked here alone: the numbered `Blocked file(#74)`,
//! `DETECTION_ADD#1`, `MPSOURCE_REALTIME` detection events, an EMS scan of
//! a process named with its extension, cleaning, filter caching, SDN
//! queries, EMS detections and exclusions.

use std::path::Path;

use defender::{Entry, EntryKind, Time, is_mplog_name, read_mplog};

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
fn stamp(ts: Option<Time>) -> String {
    let iso = ts.unwrap().to_iso8601();
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
            ("telemetry_name", "TelemetryName"),
            ("image_path_hash", "ImagePathHash"),
            ("target_filename", "TargetFileName"),
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
            ("schema", "Schema"),
            ("resource_refcount", "Resource refcount"),
            ("result", "Result"),
            ("finished_threat_id", "Finished threat ID"),
            ("threat_result", "Threat result"),
            ("threat_status_flags", "Threat status flags"),
            (
                "threat_effective_removalpolicy",
                "Threat Effective RemovalPolicy",
            ),
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
        let iso = entry.time.unwrap().to_iso8601();
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

/// The entries as Intrinsec's TSV rows.
fn rows(entries: &[Entry]) -> Vec<String> {
    entries
        .iter()
        .filter_map(intrinsec)
        .map(|(name, columns)| {
            let cells: Vec<String> = columns.iter().map(|(k, v)| format!("{k}={v}")).collect();
            format!("{name}\t{}", cells.join("\t"))
        })
        .collect()
}

#[test]
fn every_row_as_intrinsec_reads_it() {
    assert!(is_mplog_name(NAME));
    let entries = log();
    let got = rows(&entries);
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
    assert!(!scan.time.unwrap().is_utc());
    let telemetry = of(EntryKind::BmTelemetry).next().unwrap();
    assert_eq!(stamp(telemetry.time), "2023-12-19T09:32:08.803Z");
}

#[test]
fn sdn_paths_with_parentheses() {
    let line = r"2023-12-19T09:36:34.869Z SDN:Issuing SDN query for C:\Program Files (x86)\Example\payload.exe (\Device\HarddiskVolume3\Program Files (x86)\Example\payload.exe) (sha1=1111, sha2=2222)";
    let log = read_mplog(line.as_bytes());
    assert_eq!(log.problems, Vec::<String>::new());
    let [entry] = &log.entries[..] else {
        panic!("{:?}", log.entries)
    };
    assert_eq!(entry.kind, EntryKind::SdnQuery);
    assert_eq!(
        entry.get("Path"),
        Some(r"C:\Program Files (x86)\Example\payload.exe")
    );
    assert_eq!(
        entry.get("DevicePath"),
        Some(r"\Device\HarddiskVolume3\Program Files (x86)\Example\payload.exe")
    );
    assert_eq!(entry.get("Sha1"), Some("1111"));
    assert_eq!(entry.get("Sha256"), Some("2222"));
}

#[test]
fn records_cut_short_are_reported_and_kept() {
    for (text, kind, fields, problem) in [
        (
            "BEGIN BM telemetry\nProcessID: 42\n",
            EntryKind::BmTelemetry,
            1,
            "line 1: BmTelemetry without its end (END BM telemetry), read to line 2",
        ),
        (
            "BEGIN RTP Perf Log\nRTP Start: 12-15-2022 11:24:33\n",
            EntryKind::RtpPerf,
            1,
            "line 1: RtpPerf without its end (END RTP Perf Log), read to line 2",
        ),
        (
            "Microsoft Defender Antivirus Service Log\nStarted On 05-06-2024 06:20:45\n",
            EntryKind::LogHeader,
            2,
            "line 1: LogHeader without its end (Current time:), read to line 2",
        ),
    ] {
        let log = read_mplog(text.as_bytes());
        assert_eq!(log.problems, [problem], "{text:?}");
        let [entry] = &log.entries[..] else {
            panic!("{text:?}: {:?}", log.entries)
        };
        assert_eq!(entry.kind, kind);
        assert_eq!(entry.fields.len(), fields, "{entry:?}");
    }

    // Cut short by the next timed line, which is still read; a service log
    // whose header is cut short has nothing saying its times are UTC.
    let impact = "ProcessImageName: a.exe, Pid: 1, TotalTime: 1, Count: 1, MaxTime: 1, MaxTimeFile: x, EstimatedImpact: 1%";
    let text = format!(
        "Microsoft Defender Antivirus Service Log\nCurrent time: 05/06/2024 13:20:45.0 UTC (9 ms since boot)\n\
         2024-05-06T13:20:46.000 {impact}\n\
         BEGIN BM telemetry\nProcessID: 42\n\
         2024-05-06T13:20:47.000 {impact}\n\
         Microsoft Defender Antivirus Service Log\n\
         2024-05-06T13:20:48.000 {impact}\n"
    );
    let log = read_mplog(text.as_bytes());
    assert_eq!(
        log.problems,
        [
            "line 4: BmTelemetry without its end (END BM telemetry), read to line 5",
            "line 7: LogHeader without its end (Current time:), read to line 7",
        ]
    );
    let times: Vec<String> = log
        .entries
        .iter()
        .filter(|e| e.kind == EntryKind::EstimatedImpact)
        .map(|e| e.time.unwrap().to_iso8601())
        .collect();
    assert_eq!(
        times,
        [
            "2024-05-06T13:20:46.000Z",
            "2024-05-06T13:20:47.000Z",
            "2024-05-06T13:20:48.000"
        ]
    );
}

#[test]
fn damaged_text_is_reported() {
    let text = "2021-07-22T15:38:04.557Z ProcessImageName:a.exe, Pid: 1, TotalTime: 1, Count: 1, MaxTime: 1, MaxTimeFile: x, EstimatedImpact: 1%\n";

    let mut utf16 = vec![0xff, 0xfe];
    utf16.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
    utf16.push(0xff); // truncated code unit
    let log = read_mplog(&utf16);
    assert_eq!(log.entries.len(), 1);
    assert_eq!(
        log.problems,
        ["an odd byte at the end (UTF-16 is in pairs), not read"]
    );

    let mut utf8 = text.as_bytes().to_vec();
    utf8.push(0xff); // invalid UTF-8
    let log = read_mplog(&utf8);
    assert_eq!(log.entries.len(), 1);
    assert_eq!(log.problems, ["text that isn't valid UTF-8, replaced"]);
}

#[test]
fn other_files_have_no_entries() {
    assert_eq!(read_mplog(b"").entries, []);
    assert_eq!(read_mplog(b"just\nsome\ntext").entries, []);
    assert_eq!(read_mplog(&[0xFF, 0xFE, 0x41]).entries, []);
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

/// A DFIRArtifactMuseum log (`tests/fixtures/museum/`, gzip-compressed).
fn museum(name: &str) -> defender::MpLog {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/museum")
        .join(name);
    let mut data = Vec::new();
    std::io::Read::read_to_end(
        &mut common::gzip::Decoder::new(&std::fs::read(path).unwrap()[..]),
        &mut data,
    )
    .unwrap();
    let log = read_mplog(&data);
    assert_eq!(log.problems, Vec::<String>::new(), "{name}");
    log
}

/// Rows Intrinsec would have but doesn't read, by its CSV: `DETECTION_ADD#1` lines (it reads
/// `DETECTION_ADD` and `#2` alone), EMS scans written without `source:`, unsuccessful scans whose
/// process is empty.
const MUSEUM: &[(&str, &[(&str, usize)])] = &[
    (
        "apt-simulator-vm/Support/MPLog-20220310-113238.log.gz",
        &[("DetectionAdd", 18)],
    ),
    (
        "belkasoft-ctf/MPLog-20200801-144809.log.gz",
        &[("Ems", 44), ("UnsuccessfulScanStatus", 10)],
    ),
    (
        "server2022-apt-simulator-vm/MPLog-20231017-224350.log.gz",
        &[("DetectionAdd", 4)],
    ),
];

#[test]
fn museum_logs_as_intrinsec_reads_them() {
    let oracle = include_str!("oracle/intrinsec-museum.tsv");
    for &(name, extra) in MUSEUM {
        let got = rows(&museum(name).entries);
        // Intrinsec keeps the full stop after a mini-filter line's path in the path.
        let expected: Vec<String> = oracle
            .lines()
            .filter_map(|line| line.strip_prefix(&format!("museum/{name}\t")))
            .map(|row| {
                let cells: Vec<&str> = row.split('\t').collect();
                let mini_filter = ["BlockedFile", "UnsuccessfulScanStatus"].contains(&cells[0]);
                let even = |cell: &&str| match cell.strip_prefix("full_path=") {
                    Some(path) if mini_filter => {
                        format!("full_path={}", path.trim_end_matches('.'))
                    }
                    _ => (*cell).to_owned(),
                };
                cells.iter().map(even).collect::<Vec<_>>().join("\t")
            })
            .collect();
        assert!(!expected.is_empty(), "{name}");
        for row in &expected {
            assert!(got.contains(row), "{name}: not read the same: {row}");
        }
        let mut more: Vec<(&str, usize)> = Vec::new();
        for row in got.iter().filter(|g| !expected.contains(g)) {
            let csv = row.split('\t').next().unwrap();
            match more.iter_mut().find(|(c, _)| *c == csv) {
                Some((_, n)) => *n += 1,
                None => more.push((csv, 1)),
            }
        }
        more.sort_unstable();
        assert_eq!(more, extra, "{name}");
    }
}

#[test]
fn museum_entries_intrinsec_doesnt_read() {
    let detection = museum("belkasoft-ctf/MPDetection-20210213-115635.log.gz");
    let of = |log: &defender::MpLog, kind: EntryKind| {
        log.entries
            .iter()
            .filter(|e| e.kind == kind)
            .cloned()
            .collect::<Vec<Entry>>()
    };
    let started = of(&detection, EntryKind::ServiceStarted);
    assert_eq!(started.len(), 8);
    assert_eq!(
        started[0].get("Product"),
        Some("Windows Defender Antivirus")
    );
    assert_eq!(
        started[0].get("Id"),
        Some("77BDAF73-B396-481F-9042-AD358843EC24")
    );
    assert_eq!(stamp(started[0].time), "2021-02-13T19:56:35.990Z");
    let stopped = of(&detection, EntryKind::ServiceStopped);
    assert_eq!(stopped.len(), 2);
    assert_eq!(stopped[0].get("ExitCode"), Some("0x0"));
    let versions = of(&detection, EntryKind::Version);
    assert_eq!(versions.len(), 8);
    assert_eq!(
        versions[0].fields,
        [
            ("Product", "4.18.1807.18075"),
            ("Service", "4.18.1807.18075"),
            ("Engine", "1.1.17700.4"),
            ("AS", "1.329.3292.0"),
            ("AV", "1.329.3292.0"),
        ]
        .map(|(l, v)| (l.to_owned(), v.to_owned()))
    );

    // The service log's headers: a local start time, UTC times, the time since boot.
    let log = museum("belkasoft-ctf/MPLog-20200801-144809.log.gz");
    let headers = of(&log, EntryKind::LogHeader);
    assert_eq!(headers.len(), 23);
    assert_eq!(headers[0].line, 3);
    assert_eq!(
        headers[0].time.unwrap().to_iso8601(),
        "2020-08-01T21:48:49.7178959Z"
    );
    assert_eq!(headers[0].get("StartedOn"), Some("08-01-2020 14:48:49"));
    assert_eq!(
        headers[0].get("OsInstallTime"),
        Some("2020-08-01T21:48:28.000Z")
    );
    assert_eq!(headers[0].get("MsSinceBoot"), Some("12656"));
    assert_eq!(of(&log, EntryKind::ProcessExclusion).len(), 178);
    // Real-time protection's start: local, its numbers between left-to-right marks.
    let rtp = of(&log, EntryKind::RtpPerf);
    assert_eq!(rtp.len(), 46);
    let timed: Vec<&Entry> = rtp.iter().filter(|e| e.time.is_some()).collect();
    assert_eq!(timed.len(), 24);
    assert!(
        rtp.iter()
            .filter(|e| e.time.is_none())
            .all(|e| e.get("RTPStart") == Some("N/A"))
    );
    assert_eq!(
        timed[0].get("RTPStart"),
        Some("\u{200e}08\u{200e}-\u{200e}01\u{200e}-\u{200e}2020 11:48:58")
    );
    let start = timed[0].time.unwrap();
    assert!(!start.is_utc());
    assert_eq!(start.to_iso8601(), "2020-08-01T11:48:58");
    let config = of(&log, EntryKind::RtpConfigChange);
    assert_eq!(config.len(), 36);
    assert_eq!(config[0].get("Type"), Some("1024"));

    // A process scan's counts: untimed lines, given the scan's start.
    let log = museum("apt-simulator-vm/Support/MPLog-20220310-113238.log.gz");
    let counts = of(&log, EntryKind::ProcessCounts);
    assert_eq!(counts.len(), 10);
    assert_eq!(counts[0].get("ProcessImageName"), Some("vmtoolsd.exe"));
    assert_eq!(
        counts[0].get("MaxTimeFile"),
        Some(r"\Device\HarddiskVolume3\Windows\System32\vcruntime140.dll")
    );
    assert!(
        counts
            .iter()
            .all(|c| stamp(c.time) == "2022-03-10T19:47:14.719Z")
    );

    let log = museum("server2022-apt-simulator-vm/MPLog-20231017-224350.log.gz");
    // Cloud queries of files not hashed, one of an archive's member.
    let queries = of(&log, EntryKind::SdnQuery);
    assert_eq!(queries.len(), 5);
    assert!(queries.iter().all(|q| q.get("Sha1").is_none()));
    assert!(queries.iter().any(|q| q.get("Path").is_some_and(|p| {
        p.ends_with(r"\toolset\b.jsp->(SCRIPT0065)")
            && q.get("DevicePath")
                .is_some_and(|d| d.ends_with(r"\toolset\b.jsp"))
    })));
    let excluded = of(&log, EntryKind::ProcessExclusion);
    assert_eq!(excluded.len(), 42);
    assert_eq!(
        excluded[0].get("DevicePath"),
        Some(r"\Device\HarddiskVolume3\Program Files\Windows Defender\MpCmdRun.exe")
    );

    // The detection log of a service that never wrote one: its byte order mark alone.
    let empty = museum("apt-simulator-vm/Support/MPDetection-20220310-113238.log.gz");
    assert_eq!(empty.entries, []);
}
