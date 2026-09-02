#![no_main]
use libfuzzer_sys::fuzz_target;
use reverse_engineering::binary::parse_binary_bytes;
fuzz_target!(|data: &[u8]| { let _ = parse_binary_bytes(data); });
