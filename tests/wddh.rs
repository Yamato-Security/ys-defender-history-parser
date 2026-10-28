//! Every detection history file in `tests/fixtures/` (plaso's, Orange Cyberdefense's samples,
//! DFIRArtifactMuseum's) read as Orange Cyberdefense's wddh reads it
//! (`tests/oracle/wddh.tsv`, written from wddh's output, see `tests/oracle/README`): each of its
//! values, named or by position, read the same; times within the 2 microseconds wddh's float
//! conversion loses.

use std::io::Read;
use std::path::{Path, PathBuf};

use defender::{Detection, Time};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// The detection history files under `folder`: named by a GUID, gzip-compressed or not.
fn files(folder: &Path, found: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(folder).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let guid = name.trim_end_matches(".gz");
        if path.is_dir() {
            files(&path, found);
        } else if guid.len() == 36 && guid.matches('-').count() == 4 {
            found.push(path);
        }
    }
}

fn read(path: &Path) -> Vec<u8> {
    let data = std::fs::read(path).unwrap();
    if path.extension().is_some_and(|e| e == "gz") {
        let mut plain = Vec::new();
        common::gzip::Decoder::new(&data[..])
            .read_to_end(&mut plain)
            .unwrap();
        return plain;
    }
    data
}

/// Microseconds since 1970.
fn micros(time: Time) -> i64 {
    let (seconds, nanos) = time.unix();
    seconds * 1_000_000 + i64::from(nanos / 1000)
}

/// A detection as the oracle's keys and values.
fn values(detection: &Detection) -> Vec<(String, String)> {
    let mut values = Vec::new();
    let mut put = |key: &str, value: Option<String>| {
        if let Some(value) = value {
            values.push((key.to_owned(), value));
        }
    };
    let string = |n: Option<u32>| n.map(|n| n.to_string());
    put("threat_id", detection.threat_id.map(|n| n.to_string()));
    put("id", detection.id.clone());
    put("version", detection.version.clone());
    put("threat_name", detection.threat_name.clone());
    put("severity_id", string(detection.severity_id));
    put("category_id", string(detection.category_id));
    put("threat_status_id", string(detection.threat_status_id));
    let list: Vec<String> = detection.list.iter().map(u32::to_string).collect();
    put("list", Some(list.join(",")));
    put("resources", Some(detection.resources.len().to_string()));
    for (i, resource) in detection.resources.iter().enumerate() {
        put(&format!("resource.{i}.kind"), Some(resource.kind.clone()));
        put(
            &format!("resource.{i}.location"),
            Some(resource.location.clone()),
        );
        put(&format!("resource.{i}.flags"), string(resource.flags));
        for (key, value) in &resource.tracking {
            put(&format!("resource.{i}.{key}"), Some(value.to_string()));
        }
    }
    let time = |t: Option<Time>| t.map(|t| micros(t).to_string());
    put("status_changed", time(detection.status_changed));
    put(
        "status_error_code",
        detection.status_error_code.map(|n| n.to_string()),
    );
    put("quarantine_id", detection.quarantine_id.clone());
    put("execution_status_id", string(detection.execution_status_id));
    put("user", detection.user.clone());
    put("source_type_id", string(detection.source_type_id));
    put("process", detection.process.clone());
    put("initial_detection", time(detection.initial_detection));
    put("remediation", time(detection.remediation));
    for (key, value) in &detection.unknown {
        put(key, Some(value.to_string()));
    }
    values
}

const TIMES: [&str; 3] = ["status_changed", "initial_detection", "remediation"];

#[test]
fn every_value_as_wddh_reads_it() {
    let mut paths = Vec::new();
    files(&fixtures(), &mut paths);
    paths.sort();
    let oracle = include_str!("oracle/wddh.tsv");
    let mut checked = 0;
    for path in &paths {
        let name = path
            .strip_prefix(fixtures())
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let detection = defender::read(&read(path)).unwrap();
        assert_eq!(detection.problems, Vec::<String>::new(), "{name}");
        let ours = values(&detection);
        let expected: Vec<(&str, &str)> = oracle
            .lines()
            .filter_map(|line| {
                let mut cells = line.splitn(3, '\t');
                let (file, key, value) = (cells.next()?, cells.next()?, cells.next()?);
                (file == name).then_some((key, value))
            })
            .collect();
        assert!(!expected.is_empty(), "{name}: not in the oracle");
        for (key, value) in &expected {
            let found = ours.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str());
            if TIMES.contains(key) {
                let ours: i64 = found
                    .unwrap_or_else(|| panic!("{name}: no {key}"))
                    .parse()
                    .unwrap();
                let theirs: i64 = value.parse().unwrap();
                assert!(
                    (ours - theirs).abs() <= 2,
                    "{name}: {key} {ours} vs {theirs}"
                );
            } else {
                assert_eq!(found, Some(*value), "{name}: {key}");
            }
            checked += 1;
        }
        // Nothing read that wddh doesn't also give, but the zero FILETIMEs and GUIDs and the
        // status it has no name for, which neither gives.
        for (key, value) in &ours {
            assert!(
                expected.iter().any(|(k, _)| k == key) || key == "threat_status_id",
                "{name}: {key} = {value} not in the oracle"
            );
        }
    }
    assert_eq!(paths.len(), 20);
    assert_eq!(checked, oracle.lines().count());
}
