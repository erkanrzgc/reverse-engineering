#[test]
fn cargo_identity_is_reverse_engineering_v0_2() {
    assert_eq!(env!("CARGO_PKG_NAME"), "reverse-engineering");
    assert_eq!(env!("CARGO_PKG_VERSION"), "0.2.0");
    assert!(option_env!("CARGO_BIN_EXE_reverse-engineering").is_some());
    assert!(option_env!("CARGO_BIN_EXE_decompiler").is_none());
}
