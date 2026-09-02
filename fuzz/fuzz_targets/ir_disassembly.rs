#![no_main]
use libfuzzer_sys::fuzz_target;
use reverse_engineering::binary::parse_binary_bytes;
fuzz_target!(|data: &[u8]| { if let Ok(binary) = parse_binary_bytes(data) { let _ = binary.sections(); } });
