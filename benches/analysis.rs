use criterion::{black_box, criterion_group, criterion_main, Criterion};
use reverse_engineering::analysis::strings::StringExtractor;
use reverse_engineering::disasm::x86::X86Disassembler;

fn benchmark_string_extraction(c: &mut Criterion) {
    let data = b"prefix\0hello reverse engineering\0another stable fixture\0";
    let extractor = StringExtractor::new();

    c.bench_function("extract_strings", |b| {
        b.iter(|| black_box(extractor.extract(black_box(data), 0x1000)))
    });
}

fn benchmark_x86_disassembly(c: &mut Criterion) {
    let bytes = [0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0xc3];
    let disassembler = X86Disassembler::new_x64();

    c.bench_function("disassemble_x86_fixture", |b| {
        b.iter(|| black_box(disassembler.disassemble(black_box(&bytes), 0x1000)))
    });
}

criterion_group!(
    analysis_benches,
    benchmark_string_extraction,
    benchmark_x86_disassembly
);
criterion_main!(analysis_benches);
