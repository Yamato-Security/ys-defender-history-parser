//! Microsoft Defender, for forensics: its detection history and its protection logs.
//!
//! [`read`] reads a detection history file
//! (`ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\<n>\<GUID>`),
//! one per detection: the threat (identifier, name, severity, category), its status and what was
//! done, the files, registry keys, processes and command lines it was found in with their tracking
//! data (hashes, sizes, times), the user and process involved, what detected it, the quarantine
//! entry, and when.
//!
//! The file is a list of typed values (a size, a type, the data, padding to 8 bytes), read in the
//! sections Orange Cyberdefense's analysis found, the values named as WMI's
//! `MSFT_MpThreatDetection` names them; values whose meaning isn't known are kept by section and
//! position.
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let detection = defender::read(&std::fs::read("DetectionHistory/02/6AFE33A0-19BA-4FFF-892F-B700539D7D63")?)?;
//! for resource in &detection.resources {
//!     println!("{:?} in {} {}", detection.threat_name, resource.kind, resource.location);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! [`read_mplog`] reads the protection logs (`Support\MPLog-*.log`) and the detection logs
//! (`Support\MPDetection-*.log`): detections, programs scanned, exclusions, blocked files,
//! behaviour monitoring telemetry, the service's starts and versions.
//!
//! Damage is reported in `problems`, never a panic.

mod history;
mod mplog;
mod time;

pub use history::{detect, read, Detection, Error, Resource, Value};
pub use mplog::{is_mplog_name, read_mplog, Entry, EntryKind, MpLog};
pub use time::{Precision, Time};

/// This crate's version, for records of what parsed them.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
