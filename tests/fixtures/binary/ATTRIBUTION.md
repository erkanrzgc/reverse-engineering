# Vendored Test Fixtures — Attribution

The binary files and the embedded Mach-O byte array in this directory are
vendored from the [`goblin`](https://github.com/m4b/goblin) project (the same
crate this decompiler already depends on for parsing). They are reused here
purely as test inputs for our own binary-parser layer.

## Source

- Project: `goblin` — cross-platform binary parsing crate
- Repository: <https://github.com/m4b/goblin>
- Version vendored from: `0.10.5`
- Copyright holder: m4b (2016 – 2024)
- License: MIT

## Files

| File | Origin in goblin repo | Format | Notes |
|---|---|---|---|
| `hello.so` | `tests/bins/elf/gnu_hash/hello.so` | ELF64 shared object | "hello world" shared lib, GNU_HASH section, 6 080 bytes |
| `hello32.so` | `tests/bins/elf/gnu_hash/hello32.so` | ELF32 shared object | 32-bit counterpart, 5 428 bytes |
| `lld_no_tls_64.exe` | `tests/bins/pe/lld_no_tls_64.exe.bin` | PE32+ executable | Minimal lld-linked binary with no TLS directory, 1 024 bytes |
| `macho64_deadbeef.rs` | excerpt of `tests/macho.rs` (`DEADBEEF_MACH_64` constant) | Mach-O x86_64 | Pre-built 8 496-byte Mach-O image embedded as a `const [u8; 8496]` |

The Mach-O fixture is embedded as a Rust source file rather than a binary file
because the upstream project itself distributes it that way — `goblin`'s own
`tests/macho.rs` keeps the bytes inline so they can be hashed and reviewed as
plain source.

## License notice (MIT)

```
The MIT License (MIT)

Copyright (c) m4b 2016-2024

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
