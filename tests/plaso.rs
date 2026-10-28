//! plaso's detection history files (Apache-2.0, `tests/fixtures/plaso/`,
//! gzip-compressed): every detection plaso reads, read the same
//! (`tests/oracle/plaso.tsv`, written from plaso's own output, see
//! `tests/oracle/README`).

use std::io::Read;

use defender::Detection;

fn gunzip(compressed: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    common::gzip::Decoder::new(compressed)
        .read_to_end(&mut data)
        .unwrap();
    data
}

fn fixtures() -> Vec<(String, Detection)> {
    let folder = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/plaso");
    let mut found: Vec<(String, Detection)> = std::fs::read_dir(folder)
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter_map(|n| n.strip_suffix(".gz").map(str::to_owned))
        .map(|name| {
            let data = gunzip(&std::fs::read(format!("{folder}/{name}.gz")).unwrap());
            assert!(defender::detect(&data), "{name}: not detected");
            let detection = defender::read(&data).unwrap();
            (name, detection)
        })
        .collect();
    found.sort_by(|a, b| a.0.cmp(&b.0));
    found
}

/// The locations of the resources of `kinds`, joined.
fn locations(detection: &Detection, kinds: &[&str], separator: &str) -> String {
    detection
        .resources
        .iter()
        .filter(|r| kinds.contains(&r.kind.as_str()))
        .map(|r| r.location.as_str())
        .collect::<Vec<_>>()
        .join(separator)
}

/// A detection as the oracle's fields.
fn line(detection: &Detection) -> String {
    let others: Vec<&str> = detection
        .resources
        .iter()
        .filter(|r| !["file", "containerfile", "webfile"].contains(&r.kind.as_str()))
        .map(|r| r.location.as_str())
        .collect();
    let micros = detection
        .start_time()
        .and_then(|t| t.ticks())
        .map(|ticks| ticks / 10)
        .map_or_else(String::new, |m| m.to_string());
    [
        locations(detection, &["file"], ";"),
        micros,
        detection.threat_name.clone().unwrap_or_default(),
        detection.user.clone().unwrap_or_default(),
        detection.process.clone().unwrap_or_default(),
        detection.sha256().unwrap_or_default().to_owned(),
        locations(detection, &["containerfile"], "|"),
        locations(detection, &["webfile"], ";"),
        others.join(";"),
    ]
    .join("\t")
}

#[test]
fn every_detection_as_plaso_reads_it() {
    let oracle = include_str!("oracle/plaso.tsv");
    let mut expected: Vec<&str> = oracle.lines().collect();
    expected.sort_unstable();
    let mut got: Vec<String> = fixtures().iter().map(|(_, d)| line(d)).collect();
    got.sort();
    assert_eq!(got, expected);
}

#[test]
fn beyond_plaso() {
    for (name, detection) in fixtures() {
        assert_eq!(detection.problems, Vec::<String>::new(), "{name}");
        assert_eq!(detection.id.as_deref(), Some(name.as_str()));
        assert!(detection.initial_detection.is_some(), "{name}");
        // Every resource but a container is tracked.
        for resource in &detection.resources {
            let tracked = !resource.tracking.is_empty();
            assert_eq!(
                tracked,
                resource.kind != "containerfile",
                "{name}: {resource:?}"
            );
        }
    }
    let (_, eicar) = &fixtures()[0];
    assert_eq!(eicar.category_name(), Some("VIRUS"));
    assert_eq!(
        eicar.tracking("ThreatTrackingMD5"),
        Some("44d88612fea8a8f36de82e1278abb02f")
    );
    let (_, pua) = &fixtures()[1];
    assert_eq!(pua.category_name(), Some("POTENTIALUNWANTEDSOFTWARE"));
}
