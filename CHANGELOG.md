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
  The other sizes the tracking data declares are checked too: a header that doesn't fit (an empty
  one cut short was taken as whole), a whole size that isn't the data's, a size smaller than
  itself.
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

### Tests
- Every value Orange Cyberdefense's wddh reads from 20 detection history files (plaso's, Orange's,
  DFIRArtifactMuseum's) read the same; Orange's four files read as Defender itself read them
  through WMI; every row Intrinsec's mplog_parser reads from DFIRArtifactMuseum's three protection
  logs read the same, and the entries it doesn't read checked by value.
- CI on Linux, macOS and Windows, MSRV 1.80, wasm32, cargo-deny, actions pinned by commit; the
  crates.io release workflow removed (the fork isn't published).
