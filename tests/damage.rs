//! Any input gives a detection, problems or an error, never a panic; damage is reported.

use proptest::prelude::*;

/// The start of a real file, to get past the signature.
fn real() -> Vec<u8> {
    let mut data = Vec::new();
    let compressed = include_bytes!("fixtures/plaso/6AFE33A0-19BA-4FFF-892F-B700539D7D63.gz");
    std::io::Read::read_to_end(&mut common::gzip::Decoder::new(&compressed[..]), &mut data)
        .unwrap();
    data
}

#[test]
fn resource_kind_and_location_must_be_text() {
    let original =
        include_bytes!("fixtures/orange/original/94BBE9CF-CDEB-4885-9178-CC93FB10822D").to_vec();
    // The first resource's kind (a 10-byte string, "file") and its location, made blobs.
    for (at, key) in [(0x174, "3.1"), (0x18C, "3.2")] {
        let mut data = original.clone();
        assert_eq!(&data[at..at + 4], &0x15_u32.to_le_bytes(), "{key}");
        data[at..at + 4].copy_from_slice(&0x28_u32.to_le_bytes()); // BLOB
        let detection = defender::read(&data).unwrap();
        assert_eq!(
            detection.problems.len(),
            1,
            "{key}: {:?}",
            detection.problems
        );
        assert!(
            detection.problems[0].contains(&format!("{key} has type 0x28")),
            "{:?}",
            detection.problems
        );
        assert!(
            detection
                .unknown
                .iter()
                .any(|(k, v)| k == key && matches!(v, defender::Value::Bytes(_))),
            "{key}: {:?}",
            detection.unknown
        );
        let resource = &detection.resources[0];
        let (kind, location) = (resource.kind.as_str(), resource.location.as_str());
        if key == "3.1" {
            assert_eq!(
                (kind, location),
                ("", r"C:\Users\RaptorSniper\Downloads\a.zip")
            );
        } else {
            assert_eq!((kind, location), ("file", ""));
        }
        // the rest of the file still read
        assert!(detection.remediation.is_some());
    }
}

#[test]
fn final_value_padding_cut_short_is_reported() {
    let mut data = include_bytes!(
        "fixtures/museum/apt-simulator-vm/DetectionHistory/00/\
         513F108E-C674-4D19-AE23-79C9AD68A0E6"
    )
    .to_vec();
    assert_eq!(data.len(), 10_296);
    assert_eq!(
        defender::read(&data).unwrap().problems,
        Vec::<String>::new()
    );

    data.pop(); // remove one byte from the final 64-bit alignment padding
    let detection = defender::read(&data).unwrap();
    assert_eq!(detection.problems.len(), 1, "{:?}", detection.problems);
    assert!(detection.problems[0].contains("padding cut short"));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..2000)) {
        let _ = defender::read(&data);
    }

    #[test]
    fn damaged_files(at in 0usize..4264, bytes in proptest::collection::vec(any::<u8>(), 1..64), cut in 0usize..4264) {
        let mut data = real();
        for (i, b) in bytes.iter().enumerate() {
            if let Some(slot) = data.get_mut(at + i) {
                *slot = *b;
            }
        }
        data.truncate(cut.max(0x60));
        let _ = defender::read(&data);
    }
}
