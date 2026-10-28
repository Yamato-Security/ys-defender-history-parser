//! Any input gives a detection, problems or an error, never a panic.

use proptest::prelude::*;

/// The start of a real file, to get past the signature.
fn real() -> Vec<u8> {
    let mut data = Vec::new();
    let compressed = include_bytes!("fixtures/plaso/6AFE33A0-19BA-4FFF-892F-B700539D7D63.gz");
    std::io::Read::read_to_end(&mut common::gzip::Decoder::new(&compressed[..]), &mut data)
        .unwrap();
    data
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
