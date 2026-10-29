# ys-defender-history-parser

Yamato Security's maintained fork of Sootmark's [defender](https://github.com/Sootmark/defender)
crate (Florian Amette): Microsoft Defender's on-disk evidence, for forensics, for
[Juntei](https://github.com/Yamato-Security/juntei).

- **Detection history** (`ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\<nn>\<GUID>`),
  one file per detection, kept after the event logs have rolled over: the threat (identifier, name,
  severity, category), its status, every resource it was found in (files,
  containers, downloads with their URL, processes, command lines, registry values, services, AMSI
  buffers, behaviours) with its tracking data (hashes, size, times, parent process), the user and
  process involved, what detected it, the quarantine entry, and when.
- **Protection logs** (`Support\MPLog-*.log`) and **detection logs** (`Support\MPDetection-*.log`):
  detections, programs scanned and how long they took, exclusions, blocked and unscanned files,
  behaviour monitoring telemetry, memory scans, the service's starts, stops and versions.
- **Quarantine** (`Quarantine\Entries\{GUID}`, `ResourceData\<xx>\<ID>`, `Resources\<xx>\<ID>`,
  new in the fork): each quarantine's threat, scan and time, every resource quarantined (files
  with their path, size, times and attributes; registry keys; services; startup items; scheduled
  tasks), and the quarantined content, decrypted: a file's data, security descriptor (its owner)
  and alternate data streams (`Zone.Identifier`: where it was downloaded from), or a registry
  hive. Nothing is ever run.

Upstream's history is kept, with its MIT OR Apache-2.0 license. The crate keeps its name,
`sootmark-defender`, and its library name, `defender`; it is not published, and its versions from
0.3.0 are the fork's own. One dependency, Sootmark's `sootmark-common` (CRC-32, MD5, SHA-1,
SHA-256).

## Why this crate

DetectionHistory has no Eric Zimmerman tool. The parsers that read it, compared on the 21 public
files there are (plaso's 2, Orange Cyberdefense's 4, DFIRArtifactMuseum's 14, DHParser's 1), against
Orange Cyberdefense's [wddh](https://github.com/cert-orangecyberdefense/wddh-parser), which reads
every value of the file. Its 387 tracking values (hashes, sizes, times, process ids):

| Parser | What it reads | Tracking values equal to wddh's |
| --- | --- | --- |
| **ys-defender-history-parser** | every value wddh reads, read the same (times within the 2 µs wddh's float conversion loses), and the meanings below | **387 (100%)** |
| wddh 1.0.1 (Python, Apache-2.0) | every value, most unnamed (`flag_1` … `flag_9`); keeps strings' terminating NUL, gives a zero FILETIME as 1601-01-01 | reference |
| sootmark-defender 0.2.0 (upstream, Rust) | threat, category, resources, user, process, three times | 375: type-7 values (ASCII strings) read as 5 bytes, losing the rest of the resource's values (2 files); no threat identifier, status, severity, source or quarantine entry; files without `Magic.Version:1.2` refused |
| DLEAPP (Python, MIT, 32154fe) | threat, severity, category, resources, hashes, user, process, three times, quarantine entry; the threat, resources, user, process and times compared, all equal to wddh's on the 21 | 375, the same type-7 reading |
| DHParser 1.0.1 (Python, GPL-3.0) | scans the bytes for text: output for 20 of the 21 files; 16 users and processes right; one resource per type | 151 |
| plaso `windefender_history` (Apache-2.0) | file, time, threat, user, process, SHA-256, containers and downloads | not run here: upstream's oracle of plaso's reading of its 2 files still passes |

Velociraptor's `Windows.Applications.DefenderHistory` reads fixed offsets in the first part of the
file; dissect.target doesn't read DetectionHistory.

For the protection logs, [Intrinsec's mplog_parser](https://github.com/Intrinsec/mplog_parser) (MIT)
is the reference: on DFIRArtifactMuseum's three MPLogs, every one of its 771 rows is read the same,
and 76 more it misses (`DETECTION_ADD#1` lines, EMS scans written without `source:`, unsuccessful
scans whose process is empty).

## What a detection holds

The file is a list of typed values (a size, a type, the data, padding to 8 bytes), read section by
section as Orange Cyberdefense's analysis lays them out (its `doc.md`: sections 1 to 8, counted).
Each value is named only where Defender's own reading of it is known: Orange edited values of a
file and asked Defender through WMI (`MSFT_MpThreatDetection`) what it read
(`tests/fixtures/orange/README.md`, checked by `tests/wmi.rs`), and a value counts as known only
when WMI's change can come from it alone; or every file's value agrees with the WMI property. The
others are kept in `Detection::unknown` by section and position, so nothing read is lost.

| Field | WMI's name | Known from |
| --- | --- | --- |
| `threat_id`, `id`, `threat_name` | ThreatID, DetectionID | WMI |
| `severity_id` (`severity_name`) | MSFT_MpThreat SeverityID | its values, 1, 2, 4 and 5, are `MSFT_MpThreat`'s; in the public files Severe for trojans, backdoors, behaviours and viruses, High for hack tools, Moderate for a settings modifier, Low for a PUA |
| `category_id` (`category_name`) | MSFT_MpThreat CategoryID | `Get-MpThreatCatalog`'s numbering: in all 21 public files, the category is the threat name's type (`Trojan:` 8 TROJAN, `HackTool:` 34 TOOL, `Virus:` 42 VIRUS, `Behavior:` 46 BEHAVIOR, …) |
| `threat_status_id` (`threat_status_name`) | ThreatStatusID | WMI |
| `status_changed`, `remediation`, `initial_detection` | LastThreatStatusChangeTime, RemediationTime, InitialDetectionTime | WMI |
| `status_error_code` | ThreatStatusErrorCode | WMI |
| `quarantine_id` | – | DLEAPP found it naming a file of `Quarantine\Entries` (`{GUID}`) for each of the detections it made on a test machine; in the public files, set in 13 of the 14 whose status is Quarantined, zero in those Detected, Removed or RemoveFailed |
| `execution_status_id` (`execution_status_name`) | CurrentThreatExecutionStatusID | WMI |
| `user`, `process` | DomainUser, ProcessName | WMI |
| `source_type_id` (`source_type_name`) | DetectionSourceTypeID | WMI gave 3 (real-time) for the file holding 3; in the public files, 3 for files found on access, 4 (IOAV) for a download, 2 (system) for command lines; 6, 10 and 11 (IEPROTECT, AMSI, UAC) named in the order of Microsoft's Defender event documentation |
| `resources`: `kind`, `location`, `flags`, `tracking` | Resources | WMI |

Tracking data is read with every value type (a 32- or 64-bit integer, a flag, a UTF-16 or ASCII
string); a type not known keeps the rest of the data as bytes, with a problem.

## The logs

`read_mplog` reads a protection or detection log (UTF-16 or UTF-8) into entries, each with its line,
time and values by label: the service log's header (when the service started, the OS install time,
the current time, the milliseconds since boot); the service starting and stopping, and its
versions; estimated impact and a process scan's per-process counts; detections (`DETECTION_ADD`,
`DETECTIONEVENT`, `DETECTION_CLEANEVENT`); `lowfi` and `threat` command lines; EMS memory scans and
detections; files the mini-filter blocked or couldn't scan; original file names; path and process
exclusions; files whose caching was disabled; cloud (SDN) queries with their hashes; real-time
protection configuration changes; and the blocks: behaviour monitoring telemetry, resource scans,
threat actions, the real-time protection log with its exclusions.

Times ending in `Z` (or with an offset) are UTC. Newer logs also write times without one; those are
UTC inside a service log whose header (`Current time: … UTC`) is within 60 seconds of its first
timed line, as DLEAPP reads them (a zone other than UTC is 15 minutes off at least), and otherwise
of a zone not known (`Time::is_utc`). The detection logs have no header, so their times without a
zone stay so.

```rust
let detection = defender::read(&std::fs::read("DetectionHistory/02/6AFE33A0-19BA-4FFF-892F-B700539D7D63")?)?;
println!("{:?} {:?} {:?}", detection.threat_name, detection.threat_status_name(), detection.quarantine_id);
for resource in &detection.resources {
    println!("{} {} {:?}", resource.kind, resource.location, resource.tracking);
}

let log = defender::read_mplog(&std::fs::read("Support/MPLog-20231219-093000.log")?);
for entry in &log.entries {
    println!("{:?} {} {:?}", entry.time, entry.kind.name(), entry.fields);
}
```

Use it from Cargo by commit:

```toml
defender = { package = "sootmark-defender", git = "https://github.com/Yamato-Security/ys-defender-history-parser", rev = "<commit>" }
```

## How it's checked

- Every value wddh reads from the 20 detection history files in `tests/fixtures/` (plaso's,
  Orange's, DFIRArtifactMuseum's), 1,203 of them, read the same (`tests/wddh.rs`,
  `tests/oracle/wddh.tsv`); and those of DHParser's file (GPL-3.0, so not included).
- Orange's four files, read as Defender read them through WMI (`tests/wmi.rs`).
- plaso's reading of its 2 files (upstream's `tests/plaso.rs`).
- Every row Intrinsec's parser reads from DFIRArtifactMuseum's three MPLogs and from a log written
  in every shape documented (`tests/mplog.rs`), and the entries it doesn't read, by value.
- A quarantine folder written as Defender writes them (`tests/oracle/gen_quarantine.py`: a file
  with its streams, a service with its hive, a startup item, a content no entry holds; made-up
  names, a line of text for the file), read the same by dissect.target's quarantine reader, and
  read whole and damaged (`tests/quarantine.rs`).
- Damage gives problems, never a panic: property tests, and 3.6 million mutated copies of the 18
  detection history files (bytes overwritten, files cut, sizes and types changed).

## The quarantine

Every part is RC4-encrypted with the key Defender holds (`quarantine::crypt`; published by
cuckoo-modified's `quarantine.py`, used by every reader since). An entry and a resource record are
a 60-byte header (magic numbers `DB E8 C5 01` and `DB E8 C5 02`, the sizes of two sections and
their CRC-32s, stored without the CRC's final inversion) and the two sections, each encrypted on
its own:

- an entry's first section holds its identifier (also its file's name, and the detection
  history's `quarantine_id`), the scan's, the time, the threat's identifier and name; its second,
  the resources at the offsets it lists: a path, a type, and fields 4-byte aligned, each an
  identifier, a type and a value (named as dissect.target names a file's: `FileSize`,
  `CreationTime`, `LastAccessTime`, `LastWriteTime`, `Flags`, `PhysicalPath`,
  `DetectionContext`; the field of type 4 is the content's identifier, whatever the resource);
- a resource record's first section holds the content's size and identifier and a count, its
  second the entries holding the content;
- a content (`ResourceData`) is a file's `BackupRead` streams, or a registry hive (a registry key's
  or a service's), and its identifier is the SHA-1 of it decrypted.

The sizes, both CRCs and the SHA-1 are checked: a part cut short, changed or damaged is reported.
`read_resource_data` keeps the content in memory to read it; `file_data` is what was quarantined,
`hashes` its MD5, SHA-1 and SHA-256 (as the detection history's tracking data gives a file's).

## Credits

[Sootmark](https://github.com/Sootmark/defender) (Florian Amette) for the crate; Orange
Cyberdefense's [wddh](https://github.com/cert-orangecyberdefense/wddh-parser) for the format's
sections and its WMI experiments; Joachim Metz's
[dtformats](https://github.com/libyal/dtformats) documentation; [plaso](https://github.com/log2timeline/plaso);
Jordan Klepser's [DHParser](https://github.com/jklepsercyber/defender-detectionhistory-parser), the
first research; [DLEAPP](https://github.com/abrignoni/DLEAPP); [Intrinsec](https://github.com/Intrinsec/mplog_parser),
[CrowdStrike](https://www.crowdstrike.com/en-us/blog/how-to-use-microsoft-protection-logging-for-forensic-investigations/)
and [artefacts.help](https://artefacts.help/) for the protection logs; and
[DFIRArtifactMuseum](https://github.com/AndrewRathbun/DFIRArtifactMuseum) for test data.

## Not yet

The meaning of the values kept as unknown. WMI's `CleaningActionID` and `ActionSuccess` changed in
Orange's copies, but each time with two values edited at once: section 2's fifth value (`2.4`: 4
in the public files quarantined, removed or failing removal, 0 in those only detected) with the status, and section
6's first (`6.0`: 2, or 1 in those only detected) with the error code, which `ActionSuccess` may
follow instead. Section 6's second account (`6.13`, `NT AUTHORITY\SYSTEM` or empty) was the
Remediation User of Defender's event 1117 for the detections DLEAPP made; the counted list of
section 2 (`[2, 3, 6]`, `[3, 6]`, …) isn't known. Sections 5 and 7
(read as Orange describes them, but in no public file), files without
`Magic.Version:1.2` (Orange saw them on Windows Server 2016; tested on a built file only), and the
detection files of the newest Defender versions: a Windows 11 machine's files with
`Get-MpThreatDetection`'s output beside them would settle what the unknown values mean. Dynamic
signatures and other log lines not listed above are left out.

## Licence

MIT or Apache-2.0, at your option (`LICENSE-MIT`, `LICENSE-APACHE`). The test files keep their
licences: plaso's and Orange Cyberdefense's (Apache-2.0) and DFIRArtifactMuseum's (MIT), each with
its licence beside it. wddh, Intrinsec's parser, DLEAPP and DHParser were only run, never included.
