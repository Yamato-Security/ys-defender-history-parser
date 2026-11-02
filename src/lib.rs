// Copyright (C) 2026 Shirofune Security Co., Ltd.
// Copyright (c) 2026 Cyber Experts
//
// This file is changed from Sootmark/defender (https://github.com/Sootmark/defender), whose code is
// under the MIT License or the Apache License 2.0 (LICENSE-MIT, LICENSE-APACHE).
//
// Unless explicitly acquired and licensed from Licensor under another license, the contents of this
// file are subject to the Reciprocal Public License ("RPL") Version 1.5, or subsequent versions as
// allowed by the RPL, and You may not copy or use this file in either source code or executable
// form, except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS" basis, WITHOUT WARRANTY
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing rights
// and limitations under the RPL.

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
//! [`quarantine`] reads the quarantine (`Quarantine\Entries`, `ResourceData`, `Resources`): what
//! was quarantined, for which threat and when, and the quarantined content, decrypted, with its
//! streams, owner and download origin.
//!
//! Damage is reported in `problems`, never a panic.

mod history;
mod mplog;
pub mod quarantine;
mod time;

pub use history::{Detection, Error, Resource, Value, detect, read};
pub use mplog::{Entry, EntryKind, MpLog, is_mplog_name, read_mplog};
pub use time::{Precision, Time};

/// This crate's version, for records of what parsed them.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
