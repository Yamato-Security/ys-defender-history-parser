# Changelog

## 0.3.0 (ys-defender-history-parser)

First version of Yamato Security's fork of sootmark-defender 0.2.0 (Sootmark/defender ad9ded1).
(@YamatoSecurity)

### Detection history

#### Added
- Every value of the file is read, section by section as Orange Cyberdefense's analysis lays them
  out (counted lists and resources, the optional sections 5 and 7), and named where Defender's
  own reading of it is known: `threat_id`, `severity_id`, `category_id`, `threat_status_id`,
  `status_error_code`, `quarantine_id`, `execution_status_id`, `source_type_id`, `list`, and each
  resource's `flags`. The values whose meaning isn't known are kept in `Detection::unknown` by
  section and position.
- Names for the numbers: `severity_name`, `threat_status_name`, `execution_status_name`,
  `source_type_name`.
- `Value`: tracking values keep their type (integer, flag, text); `Detection::tracking` returns
  one.
- `Time`, the crate's own time (FILETIMEs, and the logs' times with or without a zone), replaces
  sootmark-common's, so the crate has no dependencies.

#### Fixed
- Tracking values of type 7 (ASCII strings with their size: `ResearchData`,
  `CmdlineSha1Hash`) were read as 5 bytes, losing the rest of the resource's tracking data
  (`ParentPid`, `ParentCreationTime`, `ScanFlags`, …).
- Empty tracking data (a resource with none, or a header saying so) was reported as damage.
- Tracking pairs were read past the size the data declares, so a damaged value could take its
  bytes from after it; every read now stays within that size, and bytes after it are reported.
  The other sizes the tracking data declares are checked too: a header that doesn't fit or lacks
  any of its five fields (an empty one cut short was taken as whole), a whole size that isn't the
  data's, the pairs' size they repeat differing from the header's, a size smaller than itself; and
  a header's fifth value (0 in every file seen) is noted when it isn't 0.
- Damaged text in strings, tracking keys and values was read without a problem: an odd byte
  dropped, text after the NUL ignored, invalid UTF-16 or UTF-8 replaced. Each is now reported.
- A file cut inside its last value's padding read as whole; padding cut short is now reported, and
  padding that isn't zero too.
- A resource's type and location were taken as text whatever their type; another type is now
  reported and kept as unknown, as for the other named values.
- Files without `Magic.Version:1.2` (Windows Server 2016's, as Orange Cyberdefense found) were
  refused: a file is recognised by its first values (a threat identifier, a GUID, a string).

### Protection logs

#### Added
- Detection logs (`MPDetection-*.log`): the service starting (`ServiceStarted`) and stopping
  (`ServiceStopped`), and its versions (`Version`: product, service, engine, signatures).
- The service log's header (`LogHeader`): when the service started (local time), the OS install
  time, the current time and the milliseconds since boot.
- Process exclusions (`[ProcessExclusion]`), real-time protection configuration changes
  (`[RtpConfig]`), and a process scan's per-process counts (`Per-process counts:`, given the
  scan's start time).
- Times written without a zone, which newer logs drop the `Z` from: UTC inside a service log
  whose header is within 60 seconds of its first timed line, as DLEAPP reads them, else of a zone
  not known. They were left out with their lines.

#### Fixed
- EMS scans written without `Engine:` before them were left out.
- The real-time protection log had no time: its `RTP Start` is a local `MM-DD-YYYY` time (between
  left-to-right marks in some logs), not ISO 8601.
- A cloud (SDN) query's path was cut at its first ` (`, so `C:\Program Files (x86)\…` was read as
  `C:\Program Files`; the device path group is now found from the end. Queries of files not hashed
  (no `(sha1=…)`) were left out; their device path is kept too (`DevicePath`).
- An EMS scan's process name was cut at its first space; it now runs to its pid.
- A log's odd last byte (UTF-16) was dropped, and invalid UTF-8 replaced, without a problem; both
  are now reported.
- A multi-line record cut short (a block without its end line, a service log header without its
  `Current time:`) was left out without a problem. It is now read as far as it goes, up to a timed
  line or another record's start, and reported with its line; a header cut short also leaves the
  service log's times without a zone of a zone not known.
- Malformed times were read as plausible ones: an offset out of RFC 3339's range (`+02:60` was
  taken as three hours) or a number with a sign (`+7`, which Rust's parsing accepts). Every number
  in a time must now be digits, and offsets within 00:00 to 23:59. A time an offset takes past
  9999 (or before 1601) isn't one either: it rendered as a five-digit year.

### Quarantine

#### Added
- The quarantine (`quarantine` module): entries (`read_entry`: the threat, scan and time, and every
  resource with its fields), resource records (`read_resource_record`: the content's size and the
  entries holding it) and contents (`read_resource_data`: decrypted, a file's `BackupRead`
  streams or a registry hive; `owner`, `zone_identifier`, `file_data`), including sparse files
  reconstructed from their blocks and logical size, with `crypt` (RC4 with Defender's key),
  `detect` and `hashes`. Sizes and CRCs are checked; the content's SHA-1 is computed as its ID to
  compare with its file's name.
- `sootmark-common` is a dependency again, for CRC-32, MD5, SHA-1 and SHA-256.

### Tests
- Every value Orange Cyberdefense's wddh reads from 20 detection history files (plaso's, Orange's,
  DFIRArtifactMuseum's) read the same; Orange's four files read as Defender itself read them
  through WMI; every row Intrinsec's mplog_parser reads from DFIRArtifactMuseum's three protection
  logs read the same, and the entries it doesn't read checked by value.
- CI on Linux, macOS and Windows, MSRV 1.80, wasm32, cargo-deny, actions pinned by commit; the
  crates.io release workflow removed (the fork isn't published).
