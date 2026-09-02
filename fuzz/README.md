# Fuzzing

Install nightly Rust and cargo-fuzz, then run bounded smoke campaigns:

```text
cargo install cargo-fuzz --version 0.12.0 --locked
cargo +nightly fuzz run parser -- -max_total_time=60
cargo +nightly fuzz run ir_disassembly -- -max_total_time=60
```

The targets accept arbitrary bytes and exercise parser/IR section boundaries.
Invalid and truncated input is expected. Keep runs bounded and do not treat a
local smoke run as proof of correctness. This standalone crate is outside the
main package/workspace; libFuzzer requires nightly and may not run on Windows.
