# Contributing

Install stable Rust 1.87 or newer, then run commands from the repository root:

```text
cargo fmt -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo build --release
cargo bench --no-run
```

Use real ELF/PE/Mach-O fixtures for parser and disassembly changes. Keep fixture
inputs small and deterministic; add or update golden output only when the intended
contract changes, and explain that change in the PR. Preserve fatal-input versus
partial-enrichment semantics and the `schema_version: "1.0"` envelope. Keep CLI
concerns out of the engine boundary. Do not commit binaries, credentials, generated
target directories, or secrets.

## Release packaging

Releases are created only after a maintainer pushes a `v*` tag (for example,
`v0.2.0`); ordinary pushes do not publish artifacts. GitHub Actions builds the
locked release binary for x86-64 Windows (MSVC), x86-64 Linux (GNU), x86-64
macOS, and Apple Silicon macOS. Each deterministic
`reverse-engineering-v<version>-<target>.tar.gz` archive contains the
executable, `README.md`, `LICENSE`, and `CHANGELOG.md`, along with a matching
`.sha256` checksum file. The workflow runs `--version` and `--help` smoke
checks before packaging and requires maintainer approval of the tag/release
operation.
