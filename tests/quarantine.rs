//! A quarantine folder written as Defender writes them (`tests/fixtures/written/Quarantine/`, by
//! `tests/oracle/gen_quarantine.py`; made-up names, a line of text for the file), read whole and
//! damaged. dissect.target's quarantine reader gives the same values for it (see
//! `tests/oracle/README`).

use std::path::{Path, PathBuf};

use defender::Value;
use defender::quarantine::{
    Entry, crypt, detect, hashes, read_entry, read_resource_data, read_resource_record,
};

const FILE_ENTRY: &str = "80012345-0000-0000-1A2B-3C4D5E6F7081";
const SERVICE_ENTRY: &str = "80054321-0000-0000-9A8B-7C6D5E4F3021";
const CONTENT: &str = "AAB535B2BF6E319A41A914FDF71F7509D42E847F";
const HIVE: &str = "E2600EF2CC97428CF2377419502B3D3330483F01";
const ORPHAN: &str = "5CA5633C0E2AE818B85C5695677170EA42D55131";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/written/Quarantine")
}

fn bytes(relative: &str) -> Vec<u8> {
    std::fs::read(root().join(relative)).unwrap()
}

fn stream(kind: u32, attributes: u32, name: &str, data: &[u8]) -> Vec<u8> {
    let name: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut out = Vec::new();
    out.extend(kind.to_le_bytes());
    out.extend(attributes.to_le_bytes());
    out.extend((data.len() as u64).to_le_bytes());
    out.extend((name.len() as u32).to_le_bytes());
    out.extend(name);
    out.extend(data);
    out
}

fn entry(id: &str) -> Entry {
    let data = bytes(&format!("Entries/{{{id}}}"));
    assert!(detect(&data));
    read_entry(&data).unwrap()
}

#[test]
fn a_file_entry() {
    let e = entry(FILE_ENTRY);
    assert_eq!(e.problems, Vec::<String>::new());
    assert_eq!(e.id.as_deref(), Some(FILE_ENTRY));
    assert_eq!(
        e.scan_id.as_deref(),
        Some("6B1E0C2D-3F4A-4B5C-8D9E-0F1A2B3C4D5E")
    );
    assert_eq!(e.time.unwrap().to_iso8601(), "2023-12-19T09:36:40.1234567Z");
    assert_eq!(e.threat_id, Some(2_147_700_000));
    assert_eq!(e.threat_name.as_deref(), Some("HackTool:Win32/Example!MSR"));
    assert_eq!(
        e.unknown,
        [
            ("header.4".to_owned(), Value::Integer(0x0001_0001)),
            ("1.48".to_owned(), Value::Integer(1))
        ]
    );
    let [r] = &e.resources[..] else {
        panic!("{:?}", e.resources)
    };
    assert_eq!(r.kind, "file");
    assert_eq!(r.path, r"\\?\C:\Users\alice\Downloads\tool\tool.exe");
    assert_eq!(
        r.physical_path(),
        Some(r"C:\Users\alice\Downloads\tool\tool.exe")
    );
    assert_eq!(r.resource_id().as_deref(), Some(CONTENT));
    assert_eq!(r.size(), Some(61));
    assert_eq!(r.flags(), Some(0x20));
    let times = r.times().map(|t| t.unwrap().to_iso8601());
    assert_eq!(
        times,
        [
            "2023-12-19T09:29:59.0000000Z",
            "2023-12-19T09:36:30.5000000Z",
            "2023-12-19T09:30:00.0000000Z"
        ]
    );
    let names: Vec<Option<&str>> = r
        .fields
        .iter()
        .map(defender::quarantine::Field::name)
        .collect();
    assert_eq!(
        names,
        [
            Some("ResourceId"),
            Some("FileSize"),
            Some("LastWriteTime"),
            Some("LastAccessTime"),
            Some("CreationTime"),
            Some("Flags"),
            Some("PhysicalPath"),
            Some("DetectionContext")
        ]
    );
}

#[test]
fn a_service_and_a_startup_item() {
    let e = entry(SERVICE_ENTRY);
    assert_eq!(e.problems, Vec::<String>::new());
    let kinds: Vec<&str> = e.resources.iter().map(|r| r.kind.as_str()).collect();
    assert_eq!(kinds, ["service", "startup"]);
    // A service's content (a hive) is named by its field of type 4, whatever its identifier.
    assert_eq!(e.resources[0].resource_id().as_deref(), Some(HIVE));
    assert_eq!(e.resources[0].fields.len(), 3);
    assert_eq!(e.resources[0].fields[1].name(), None);
    assert_eq!(e.resources[1].fields, []);
}

#[test]
fn a_resource_record() {
    let record =
        read_resource_record(&bytes(&format!("Resources/{}/{CONTENT}", &CONTENT[..2]))).unwrap();
    assert_eq!(record.problems, Vec::<String>::new());
    assert_eq!(record.resource_id.as_deref(), Some(CONTENT));
    assert_eq!(record.data_size, Some(277));
    assert_eq!(record.entries, [FILE_ENTRY]);
}

#[test]
fn a_file_content() {
    let encrypted = bytes(&format!("ResourceData/{}/{CONTENT}", &CONTENT[..2]));
    assert_eq!(encrypted.len(), 277);
    let data = read_resource_data(&encrypted);
    assert_eq!(data.problems, Vec::<String>::new());
    assert_eq!(data.id, CONTENT);
    assert!(!data.hive);
    let streams: Vec<(Option<&str>, &str, usize)> = data
        .streams
        .iter()
        .map(|s| (s.kind_name(), s.name.as_str(), s.range.len()))
        .collect();
    assert_eq!(
        streams,
        [
            (Some("SecurityData"), "", 48),
            (Some("Data"), "", 61),
            (Some("AlternateData"), ":Zone.Identifier:$DATA", 64)
        ]
    );
    let file = data.file_data().unwrap();
    assert!(file.starts_with(b"A harmless line of text"));
    assert_eq!(
        hashes(file).sha256,
        "828804761c959b70327e6b05c4cab83c30aafdcc193bc29209d41b15e6d9c358"
    );
    assert_eq!(
        data.owner().as_deref(),
        Some("S-1-5-21-1111-2222-3333-1001")
    );
    assert_eq!(
        data.zone_identifier(),
        [
            ("ZoneId".to_owned(), "3".to_owned()),
            (
                "HostUrl".to_owned(),
                "https://example.com/tool.zip".to_owned()
            )
        ]
    );
}

#[test]
fn a_hive_and_an_orphan() {
    let hive = read_resource_data(&bytes(&format!("ResourceData/{}/{HIVE}", &HIVE[..2])));
    assert!(hive.hive);
    assert_eq!(hive.id, HIVE);
    assert_eq!(hive.streams, []);
    assert!(hive.file_data().unwrap().starts_with(b"regf"));
    let orphan = read_resource_data(&bytes(&format!("ResourceData/{}/{ORPHAN}", &ORPHAN[..2])));
    assert_eq!(orphan.id, ORPHAN);
    assert_eq!(orphan.file_data(), Some(&b"left behind\r\n"[..]));
}

#[test]
fn a_sparse_file_is_reconstructed_not_mistaken_for_an_empty_file() {
    let mut plain = stream(1, 8, "", &[]);
    let mut first = 4u64.to_le_bytes().to_vec();
    first.extend(b"AB");
    plain.extend(stream(9, 8, "", &first));
    let mut second = 10u64.to_le_bytes().to_vec();
    second.extend(b"XYZ");
    plain.extend(stream(9, 8, "", &second));
    // A sparse alternate stream and its block do not belong to the unnamed file stream.
    plain.extend(stream(4, 8, ":sparse:$DATA", &[]));
    let mut alternate = 0u64.to_le_bytes().to_vec();
    alternate.extend(b"not the file");
    plain.extend(stream(9, 8, "", &alternate));

    let data = read_resource_data(&crypt(&plain));
    assert_eq!(data.problems, Vec::<String>::new());
    // Returning the empty DATA stream here used to give the empty file's hash and lose both
    // allocated regions.
    assert_eq!(data.file_data(), None);
    let file = data.reconstruct_sparse_file(16).unwrap();
    assert_eq!(file, b"\0\0\0\0AB\0\0\0\0XYZ\0\0\0");
    assert_eq!(
        hashes(&file).sha256,
        "5dda0626b604ebe5cbbad0387090ce5dbe8a940de5ae0b34d1017952306a2fe3"
    );
    assert!(data.reconstruct_sparse_file(12).is_err());
}

#[test]
fn damaged_sparse_blocks_and_stream_names_are_reported() {
    let mut short = stream(1, 8, "", &[]);
    short.extend(stream(9, 8, "", b"short"));
    let short = read_resource_data(&crypt(&short));
    assert!(
        short
            .problems
            .iter()
            .any(|p| p.contains("8-byte file offset"))
    );
    assert!(short.reconstruct_sparse_file(10).is_err());

    let mut overflow = stream(1, 8, "", &[]);
    let mut block = u64::MAX.to_le_bytes().to_vec();
    block.push(1);
    overflow.extend(stream(9, 8, "", &block));
    let overflow = read_resource_data(&crypt(&overflow));
    assert!(overflow.problems.iter().any(|p| p.contains("overflow")));
    assert!(overflow.reconstruct_sparse_file(10).is_err());

    let named_data = read_resource_data(&crypt(&stream(1, 0, "not allowed", b"data")));
    assert!(
        named_data
            .problems
            .iter()
            .any(|p| p.contains("kind 1 with a name"))
    );

    // Even when the sparse attribute itself is damaged, do not present the empty base stream as
    // the complete file. The block remains recoverable, alongside the reported inconsistency.
    let mut missing_attribute = stream(1, 0, "", &[]);
    let mut block = 2u64.to_le_bytes().to_vec();
    block.extend(b"evidence");
    missing_attribute.extend(stream(9, 8, "", &block));
    let missing_attribute = read_resource_data(&crypt(&missing_attribute));
    assert!(
        missing_attribute
            .problems
            .iter()
            .any(|p| p.contains("without a preceding sparse data stream"))
    );
    assert_eq!(missing_attribute.file_data(), None);
    assert_eq!(
        missing_attribute.reconstruct_sparse_file(10).unwrap(),
        b"\0\0evidence"
    );
}

#[test]
fn changes_and_damage_are_reported() {
    let original = bytes(&format!("Entries/{{{FILE_ENTRY}}}"));
    // A byte changed in each section: its CRC no longer matches.
    for at in [61, original.len() - 3] {
        let mut changed = original.clone();
        changed[at] ^= 1;
        let e = read_entry(&changed).unwrap();
        assert_eq!(e.problems.len(), 1, "{at}: {:?}", e.problems);
        assert!(e.problems[0].contains("CRC-32"), "{:?}", e.problems);
    }
    // Cut short, or more after the sections.
    let e = read_entry(&original[..original.len() - 10]).unwrap();
    assert!(
        e.problems.iter().any(|p| p.contains("cut short")),
        "{:?}",
        e.problems
    );
    let mut longer = original.clone();
    longer.extend([0; 3]);
    assert_eq!(
        read_entry(&longer).unwrap().problems,
        ["3 bytes after the sections"]
    );
    // Not an entry: no magic numbers, or not even a header.
    assert!(read_entry(&[0; 100]).is_err());
    assert!(read_entry(&original[..59]).is_err());
    assert!(!detect(b"MZ"));

    // A content changed: its SHA-1 isn't its name any more.
    let mut content = bytes(&format!("ResourceData/{}/{CONTENT}", &CONTENT[..2]));
    content[100] ^= 1;
    assert_ne!(read_resource_data(&content).id, CONTENT);
    // A stream cut short, and one of a kind not known.
    let plain = crypt(&bytes(&format!("ResourceData/{}/{CONTENT}", &CONTENT[..2])));
    let cut = read_resource_data(&crypt(&plain[..plain.len() - 1]));
    assert_eq!(cut.streams.len(), 2);
    assert_eq!(cut.problems.len(), 1, "{:?}", cut.problems);
    let mut odd = plain.clone();
    odd[0] = 99;
    let odd = read_resource_data(&crypt(&odd));
    assert_eq!(odd.streams, []);
    assert!(odd.problems[0].contains("kind 99"), "{:?}", odd.problems);
}

#[test]
fn a_record_whose_count_does_not_match() {
    let original = bytes(&format!("Resources/{}/{CONTENT}", &CONTENT[..2]));
    // the record's two sections, decrypted, with a count of 2 for one entry, written back
    let header = crypt(&original[..60]);
    let first = crypt(&original[60..92]);
    let second = crypt(&original[92..]);
    let mut first = first.clone();
    first[28] = 2;
    let crc = |d: &[u8]| !common::checksum::Crc32::of(d);
    let mut head = header.clone();
    head[48..52].copy_from_slice(&crc(&first).to_le_bytes());
    let mut data = crypt(&head);
    data.extend(crypt(&first));
    data.extend(crypt(&second));
    let record = read_resource_record(&data).unwrap();
    assert_eq!(record.problems, ["2 entries said, section 2 of 16 bytes"]);
    assert_eq!(record.entries, [FILE_ENTRY]);
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

    #[test]
    fn any_bytes_read_without_panic(data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..400)) {
        let _ = read_entry(&data);
        let _ = read_resource_record(&data);
        let _ = read_resource_data(&data);
        // and the same bytes as decrypted parts behind a valid header
        let _ = read_entry(&crypt(&data));
    }

    #[test]
    fn damaged_entries_read_without_panic(at in 0usize..600, value in proptest::prelude::any::<u8>(), cut in 0usize..600) {
        for id in [FILE_ENTRY, SERVICE_ENTRY] {
            let mut data = bytes(&format!("Entries/{{{id}}}"));
            if let Some(slot) = data.get_mut(at) {
                *slot = value;
            }
            data.truncate(cut.max(60));
            let _ = read_entry(&data);
            // damage inside the decrypted sections, re-encrypted with a matching header
            let plain = crypt(&data);
            let _ = read_resource_data(&plain);
        }
    }
}
