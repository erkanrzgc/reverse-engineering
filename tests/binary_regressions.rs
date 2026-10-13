//! Controlled byte fixtures for parser, decoder and function discovery defects.
use reverse_engineering::analysis::functions::{FunctionDetectionInputs, FunctionDetector};
use reverse_engineering::binary::parse_binary_bytes;
use reverse_engineering::disasm::control_flow::EdgeType;
use reverse_engineering::disasm::{
    ArmDisassembler, ControlFlowGraph, Instruction, X86Disassembler,
};
use reverse_engineering::{AnalysisConfig, AnalysisEngine, DiagnosticCode, OutputSelection};

fn detect(instructions: &[Instruction], architecture: &str, entry_point: u64) -> Vec<u64> {
    FunctionDetector::new()
        .detect(FunctionDetectionInputs {
            instructions,
            architecture,
            entry_point,
            exports: &[],
            imports: &[],
        })
        .into_iter()
        .map(|function| function.address)
        .collect()
}

#[test]
fn arm32_beq_preserves_taken_and_fallthrough_edges() {
    // beq 0x100c; bx lr; nop; bx lr
    let instructions = ArmDisassembler::new_arm()
        .unwrap()
        .disassemble(
            &[
                1, 0, 0, 0x0a, 0x1e, 0xff, 0x2f, 0xe1, 0, 0xf0, 0x20, 0xe3, 0x1e, 0xff, 0x2f, 0xe1,
            ],
            0x1000,
        )
        .unwrap();
    assert!(instructions[0].is_control_flow());
    let cfg = ControlFlowGraph::from_arm(instructions);
    assert!(cfg
        .graph()
        .edge_weights()
        .any(|edge| *edge == EdgeType::BranchTrue));
    assert!(cfg
        .graph()
        .edge_weights()
        .any(|edge| *edge == EdgeType::BranchFalse));
}

#[test]
fn arm64_direct_call_discovers_unexported_helper() {
    // bl 0x1008; ret; ret
    let instructions: Vec<_> = ArmDisassembler::new_arm64()
        .unwrap()
        .disassemble(
            &[2, 0, 0, 0x94, 0xc0, 3, 0x5f, 0xd6, 0xc0, 3, 0x5f, 0xd6],
            0x1000,
        )
        .unwrap()
        .into_iter()
        .map(Instruction::Arm)
        .collect();
    assert_eq!(detect(&instructions, "ARM64", 0x1000), vec![0x1000, 0x1008]);
}

#[test]
fn x86_counter_branches_preserve_targets_and_cfg_edges() {
    for opcode in [0xe0, 0xe1, 0xe2, 0xe3] {
        let instructions = X86Disassembler::new_x64()
            .disassemble(&[opcode, 0xfe, 0xc3], 0x1000)
            .unwrap();
        assert!(instructions[0].is_conditional_jump(), "opcode {opcode:x}");
        assert!(instructions[0].is_control_flow(), "opcode {opcode:x}");
        assert_eq!(
            instructions[0].near_branch_target,
            Some(0x1000),
            "opcode {opcode:x}"
        );
        let cfg = ControlFlowGraph::from_x86(instructions);
        assert_eq!(cfg.graph().edge_count(), 2, "opcode {opcode:x}");
    }
}

#[test]
fn x86_rep_ret_ends_block_before_padding() {
    let instructions = X86Disassembler::new_x64()
        .disassemble(&[0xf3, 0xc3, 0x90], 0x1000)
        .unwrap();
    assert!(instructions[0].is_return());
    let cfg = ControlFlowGraph::from_x86(instructions);
    assert_eq!(cfg.blocks().len(), 2);
    assert_eq!(cfg.graph().edge_count(), 0);
}

#[test]
fn x86_bnd_jump_keeps_its_flow_classification() {
    let instructions = X86Disassembler::new_x64()
        .disassemble(&[0xf2, 0xe9, 0xfa, 0xff, 0xff, 0xff], 0x1000)
        .unwrap();
    assert!(instructions[0].is_unconditional_jump());
    assert_eq!(instructions[0].near_branch_target, Some(0x1000));
    assert_eq!(
        ControlFlowGraph::from_x86(instructions)
            .graph()
            .edge_count(),
        1
    );
}

#[test]
fn real_frame_prologues_span_decoder_instruction_boundaries() {
    for (architecture, bytes, decoder) in [
        (
            "x86",
            vec![0x55, 0x8b, 0xec, 0xc3],
            X86Disassembler::new_x86(),
        ),
        (
            "x64",
            vec![0x55, 0x48, 0x89, 0xe5, 0xc3],
            X86Disassembler::new_x64(),
        ),
    ] {
        let instructions: Vec<_> = decoder
            .disassemble(&bytes, 0x1000)
            .unwrap()
            .into_iter()
            .map(Instruction::X86)
            .collect();
        assert_eq!(detect(&instructions, architecture, 0), vec![0x1000]);
    }
}

#[test]
fn unsorted_duplicate_instructions_do_not_invert_function_slices() {
    let decoder = X86Disassembler::new_x64();
    let mut instructions: Vec<_> = decoder
        .disassemble(&[0x48, 0x83, 0xec, 0x20, 0xc3], 0x1010)
        .unwrap()
        .into_iter()
        .map(Instruction::X86)
        .collect();
    instructions.extend(
        decoder
            .disassemble(&[0x48, 0x83, 0xec, 0x20, 0xc3], 0x1000)
            .unwrap()
            .into_iter()
            .map(Instruction::X86),
    );
    instructions.push(instructions[0].clone());
    let functions = FunctionDetector::new().detect(FunctionDetectionInputs {
        instructions: &instructions,
        entry_point: 0x1000,
        exports: &[],
        imports: &[],
        architecture: "x64",
    });
    assert_eq!(
        functions
            .iter()
            .map(|function| function.address)
            .collect::<Vec<_>>(),
        vec![0x1000, 0x1010]
    );
    assert!(functions
        .iter()
        .all(|function| function.instructions.len() == 2));
}

fn w16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn w32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn w64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn elf_sections(overlap: bool) -> Vec<u8> {
    let mut bytes = vec![0; 292];
    bytes[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    w16(&mut bytes, 16, 2);
    w16(&mut bytes, 18, 62);
    w32(&mut bytes, 20, 1);
    w64(&mut bytes, 24, 0x1000);
    w64(&mut bytes, 40, 64);
    w16(&mut bytes, 52, 64);
    w16(&mut bytes, 58, 64);
    w16(&mut bytes, 60, 3);
    w32(&mut bytes, 132, 1);
    w64(&mut bytes, 136, 6);
    w64(&mut bytes, 144, 0x1000);
    w64(&mut bytes, 152, 256);
    w64(&mut bytes, 160, 32);
    bytes[256..288].fill(0x90);
    bytes[256..260].copy_from_slice(&[0x48, 0x83, 0xec, 0x20]);
    bytes[272..276].copy_from_slice(&[0x48, 0x83, 0xec, 0x20]);
    bytes[287] = 0xc3;
    w32(&mut bytes, 196, if overlap { 1 } else { 8 });
    w64(&mut bytes, 200, if overlap { 6 } else { 3 });
    w64(&mut bytes, 208, if overlap { 0x1008 } else { 0x2000 });
    w64(&mut bytes, 216, 288);
    w64(&mut bytes, 224, 4);
    bytes[288..292].copy_from_slice(if overlap {
        &[0x48, 0x83, 0xec, 0x20]
    } else {
        b"FAKE"
    });
    bytes
}

#[test]
fn elf_nobits_has_virtual_size_without_fake_file_bytes() {
    let binary = parse_binary_bytes(&elf_sections(false)).unwrap();
    assert_eq!(binary.sections()[2].size, 4);
    assert!(binary.sections()[2].raw_data.is_empty());
}

#[test]
fn stripped_elf_retains_defined_dynamic_function_exports() {
    let mut bytes = include_bytes!("fixtures/binary/hello.so").to_vec();
    let elf = goblin::elf::Elf::parse(&bytes).unwrap();
    let removed_headers: Vec<_> = elf
        .section_headers
        .iter()
        .enumerate()
        .filter(|(_, section)| section.sh_type == goblin::elf::section_header::SHT_SYMTAB)
        .map(|(index, _)| elf.header.e_shoff as usize + index * elf.header.e_shentsize as usize + 4)
        .collect();
    let expected: Vec<_> = elf
        .dynsyms
        .iter()
        .filter(|symbol| symbol.st_bind() == 1 && symbol.st_type() == 2 && symbol.st_shndx != 0)
        .map(|symbol| {
            (
                elf.dynstrtab.get_at(symbol.st_name).unwrap().to_string(),
                symbol.st_value,
            )
        })
        .collect();
    assert!(!expected.is_empty(), "fixture must contain dynamic exports");
    for offset in removed_headers {
        w32(&mut bytes, offset, 0);
    }
    let exports = parse_binary_bytes(&bytes).unwrap().exports();
    for (name, address) in expected {
        assert!(
            exports
                .iter()
                .any(|export| export.name == name && export.address == address),
            "missing {name} at {address:x}"
        );
    }
}

fn macho_export(flags: u8) -> Vec<u8> {
    let mut bytes = vec![0; 283];
    w32(&mut bytes, 0, 0xfeedfacf);
    w32(&mut bytes, 4, 0x01000007);
    w32(&mut bytes, 8, 3);
    w32(&mut bytes, 12, 2);
    w32(&mut bytes, 16, 3);
    w32(&mut bytes, 20, 224);
    w32(&mut bytes, 32, 0x19);
    w32(&mut bytes, 36, 152);
    bytes[40..46].copy_from_slice(b"__TEXT");
    w64(&mut bytes, 56, 0x100000000);
    w64(&mut bytes, 64, 0x1000);
    w64(&mut bytes, 80, 283);
    w32(&mut bytes, 88, 7);
    w32(&mut bytes, 92, 5);
    w32(&mut bytes, 96, 1);
    bytes[104..110].copy_from_slice(b"__text");
    bytes[120..126].copy_from_slice(b"__TEXT");
    w64(&mut bytes, 136, 0x100000100);
    w64(&mut bytes, 144, 4);
    w32(&mut bytes, 152, 256);
    w32(&mut bytes, 168, 0x80000400);
    w32(&mut bytes, 184, 0x80000022);
    w32(&mut bytes, 188, 48);
    w32(&mut bytes, 224, 272);
    w32(&mut bytes, 228, 11);
    w32(&mut bytes, 232, 0x80000028);
    w32(&mut bytes, 236, 24);
    w64(&mut bytes, 240, 256);
    bytes[256..260].copy_from_slice(&[0x90, 0x90, 0xc3, 0x90]);
    bytes[272..283].copy_from_slice(&[0, 1, b'_', b'f', 0, 6, 3, flags, 0x80, 2, 0]);
    bytes
}

#[test]
fn macho_regular_export_is_image_relative_virtual_address() {
    let binary = parse_binary_bytes(&macho_export(0)).unwrap();
    assert_eq!(binary.exports()[0].address, 0x100000100);
    assert_eq!(binary.exports()[0].name, "_f");
}

#[test]
fn macho_absolute_export_is_not_rebased() {
    assert_eq!(
        parse_binary_bytes(&macho_export(2)).unwrap().exports()[0].address,
        0x100
    );
}

fn analyze_bytes(
    bytes: &[u8],
) -> Result<reverse_engineering::AnalysisResult, reverse_engineering::AnalysisError> {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), bytes).unwrap();
    AnalysisEngine::analyze_path(
        file.path(),
        &AnalysisConfig {
            outputs: OutputSelection::none(),
            ..AnalysisConfig::default()
        },
    )
}

#[test]
fn overlapping_executable_sections_have_explicit_diagnostic() {
    let result = analyze_bytes(&elf_sections(true));
    assert!(
        !matches!(
            result.as_ref().err().map(|error| error.code()),
            Some(DiagnosticCode::InternalFailure)
        ),
        "overlap must never trigger slice panic"
    );
    // Contradictory bytes at one virtual address cannot be silently analyzed.
    assert!(
        result.is_err()
            || result
                .as_ref()
                .unwrap()
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("overlap"))
    );
}

#[test]
fn pe_armnt_requires_explicit_thumb_mode_diagnostic() {
    let mut bytes = include_bytes!("fixtures/binary/lld_no_tls_64.exe").to_vec();
    let pe_header = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    w16(&mut bytes, pe_header + 4, 0x1c4);
    let error = analyze_bytes(&bytes).expect_err("ARMNT cannot run through A32 decoder");
    assert_eq!(error.code(), DiagnosticCode::UnsupportedArchitecture);
}

fn elf32_arm(thumb: bool, big_endian: bool) -> Vec<u8> {
    let mut bytes = vec![0; 140];
    bytes[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 1, if big_endian { 2 } else { 1 }, 1]);
    let write16 = |bytes: &mut [u8], offset: usize, value: u16| {
        bytes[offset..offset + 2].copy_from_slice(&if big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        });
    };
    let write32 = |bytes: &mut [u8], offset: usize, value: u32| {
        bytes[offset..offset + 4].copy_from_slice(&if big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        });
    };
    write16(&mut bytes, 16, 2);
    write16(&mut bytes, 18, 40);
    write32(&mut bytes, 20, 1);
    write32(&mut bytes, 24, if thumb { 0x1001 } else { 0x1000 });
    write32(&mut bytes, 32, 52);
    write16(&mut bytes, 40, 52);
    write16(&mut bytes, 46, 40);
    write16(&mut bytes, 48, 2);
    write32(&mut bytes, 96, 1);
    write32(&mut bytes, 100, 6);
    write32(&mut bytes, 104, 0x1000);
    write32(&mut bytes, 108, 132);
    write32(&mut bytes, 112, 8);
    bytes[132..140].copy_from_slice(&[0, 0xf0, 0x20, 0xe3, 0x1e, 0xff, 0x2f, 0xe1]);
    bytes
}

#[test]
fn elf_thumb_entry_requires_explicit_mode_diagnostic() {
    let error = analyze_bytes(&elf32_arm(true, false)).expect_err("odd ARM entry marks Thumb mode");
    assert_eq!(error.code(), DiagnosticCode::UnsupportedArchitecture);
}

#[test]
fn big_endian_arm_requires_explicit_mode_diagnostic() {
    let error = analyze_bytes(&elf32_arm(false, true))
        .expect_err("big-endian ARM cannot use little-endian decoder");
    assert_eq!(error.code(), DiagnosticCode::UnsupportedArchitecture);
}

#[test]
fn arm32_bx_lr_ends_block_without_fallthrough() {
    let instructions = ArmDisassembler::new_arm()
        .unwrap()
        .disassemble(&[0x1e, 0xff, 0x2f, 0xe1, 0, 0xf0, 0x20, 0xe3], 0x1000)
        .unwrap();
    assert!(instructions[0].is_return());
    assert_eq!(
        ControlFlowGraph::from_arm(instructions)
            .graph()
            .edge_count(),
        0
    );
}

#[test]
fn big_endian_arm_macho_reports_unsupported_mode() {
    let mut bytes = vec![0; 32];
    for (offset, value) in [(0usize, 0xfeedface_u32), (4, 12), (12, 2)] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }
    let binary = parse_binary_bytes(&bytes).unwrap();
    assert_eq!(binary.architecture(), "ARM");
    assert!(binary.unsupported_disassembly_reason().is_some());
}

#[test]
fn arm32_predicated_direct_call_is_discovered() {
    // blne 0x1008; bx lr; bx lr
    let decoded = ArmDisassembler::new_arm()
        .unwrap()
        .disassemble(
            &[
                0, 0, 0, 0x1b, 0x1e, 0xff, 0x2f, 0xe1, 0x1e, 0xff, 0x2f, 0xe1,
            ],
            0x1000,
        )
        .unwrap();
    assert!(decoded[0].is_call());
    let instructions: Vec<_> = decoded.into_iter().map(Instruction::Arm).collect();
    assert_eq!(detect(&instructions, "ARM", 0x1000), vec![0x1000, 0x1008]);
}

#[test]
fn x86_preserves_prefixes_in_display_evidence() {
    for (bytes, prefix) in [
        (vec![0xf3, 0xa4], "rep "),
        (vec![0xf0, 0x83, 0, 1], "lock "),
    ] {
        let decoded = X86Disassembler::new_x64()
            .disassemble(&bytes, 0x1000)
            .unwrap();
        assert!(decoded[0].to_string().starts_with(prefix), "{}", decoded[0]);
    }
}

#[test]
fn arm32_macho_rejects_unresolved_arm_thumb_mode() {
    let mut bytes = vec![0; 32];
    w32(&mut bytes, 0, 0xfeedface);
    w32(&mut bytes, 4, 12);
    w32(&mut bytes, 12, 2);
    let binary = parse_binary_bytes(&bytes).unwrap();
    assert_eq!(binary.architecture(), "ARM");
    let reason = binary
        .unsupported_disassembly_reason()
        .expect("32-bit Mach-O ARM mode must be resolved before decoding");
    assert!(reason.contains("mode"));
}
