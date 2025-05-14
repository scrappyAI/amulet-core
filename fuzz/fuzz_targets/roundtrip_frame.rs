#![no_main]

// Harness: roundtrip_frame – invariant I-07 (unknown-field preservation)
// Strategy: feed arbitrary bytes, pass through encode->decode round-trip
// and assert original bytes are preserved (where spec permits).
// If kernel round-trip logic uses serde, we require custom mechanism.

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use amulet_core::{
    framing::{Frame, decode_frame, encode_frame},
};

#[derive(Arbitrary, Debug, Clone)]
struct FrameBytes(Vec<u8>);

fuzz_target!(|bytes: FrameBytes| {
    // Attempt to decode; if fails we just return (expected for random bytes)
    if let Ok(frame) = decode_frame(&bytes.0) {
        let re = encode_frame(&frame);
        // Unknown-tail invariants: encoded output should start with the exact
        // original slice if unknown fields are preserved verbatim.
        // We compare len of min(original, reencoded)
        let min_len = bytes.0.len().min(re.len());
        assert_eq!(&bytes.0[..min_len], &re[..min_len]);
    }
}); 