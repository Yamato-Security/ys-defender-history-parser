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
