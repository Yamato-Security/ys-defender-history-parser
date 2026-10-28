# defender

Microsoft Defender, for forensics: its detection history (`ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\<n>\<GUID>`), one file per detection, read into the threat, where it was found, who and what was involved, and when; and its protection logs (`ProgramData\Microsoft\Windows Defender\Support\MPLog-*.log`), kept for weeks: detections, programs scanned, exclusions, blocked files, behaviour monitoring telemetry. One dependency, its sibling `sootmark-common` (times).

```toml
[dependencies]
sootmark-defender = "0.2"
```

```rust
let detection = defender::read(&std::fs::read("DetectionHistory/02/6AFE33A0-19BA-4FFF-892F-B700539D7D63")?)?;
for resource in &detection.resources {
    println!("{:?} in {} {}", detection.threat_name, resource.kind, resource.location);
}

let log = defender::read_mplog(&std::fs::read("Support/MPLog-20231219-093000.log")?);
for entry in &log.entries {
    println!("{:?} {} {:?}", entry.time, entry.kind.name(), entry.fields);
}
```

## What you get

- `detect(head)`: whether a file is a detection history file (`Magic.Version:1.2` at offset 0x30).
- `read(data)`: the detection's identifier, the threat's name and category (`category_name()`: `VIRUS`, `RANSOM`, …), the user and process involved, when it was first detected, remediated and last changed (UTC), and each resource it was found in (`file`, `containerfile`, `webfile` with its URL, `process`, `regkey`, …) with its tracking data: start time, SHA-256, SHA-1, MD5, size, threat identifier, scan source. `start_time()` and `sha256()` read them as plaso does.
- `read_mplog(data)`: a protection log's entries (UTF-16 or UTF-8), each with its line, time (UTC; a block's own time, local where it writes one) and values by label: estimated impact (a program, its process, the slowest file scanned for it), detections (`DETECTION_ADD`, `DETECTIONEVENT`, `DETECTION_CLEANEVENT`, with the file or process), `lowfi` and `threat` command lines, EMS memory scans and detections, files the mini-filter blocked or couldn't scan, original file names, exclusions, files whose caching was disabled, cloud (SDN) queries with SHA-1 and SHA-256, and the blocks: behaviour monitoring telemetry, resource scans, threat actions, and the real-time protection log's process, path and extension exclusions. Fields are read by their labels, so the format's changes across Defender versions don't stop the rest; lines of other kinds are left out.
- Damage goes to `problems`, never a panic.

## How it's checked

- plaso's detection history files (Apache-2.0, `tests/fixtures/plaso/`, see `NOTICE`): every detection plaso reads from them with its `windefender_history` parser, read the same: file, time, threat, user, process, SHA-256, container and web files (`tests/oracle/`). Beyond plaso: identifiers, categories, the three other times and every tracking value.
- A protection log written here as Defender writes them (`tests/oracle/gen_mplog.py`: every kind of entry, in the shapes CrowdStrike, Intrinsec and artefacts.help document; the names are made up): every row Intrinsec's `mplog_parser` (MIT) reads from it, read the same (`tests/oracle/intrinsec-mplog.tsv`). It knows older shapes only; the newer ones are checked by value.
- Property tests: arbitrary and damaged files give a detection, problems or an error, never a panic; arbitrary log lines, entries or nothing.

The format, as libyal's dtformats documents it: typed values (size, type, data, padded to 8 bytes) in sets separated by `Magic.Version:1.2`.

## Licence

MIT or Apache-2.0, at your option.
