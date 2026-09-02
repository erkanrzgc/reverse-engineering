#![no_main]
use libfuzzer_sys::fuzz_target;
use reverse_engineering::disasm::{ArmDisassembler, InstructionIR, X86Disassembler};

fuzz_target!(|data: &[u8]| {
    let bytes = &data[..data.len().min(64 * 1024)];
    if let Ok(instructions) = X86Disassembler::new_x86().disassemble(bytes, 0x1000) {
        for instruction in instructions {
            if let Some(ir) = instruction.ir {
                let _typed: InstructionIR = ir;
            }
        }
    }
    if let Ok(instructions) = X86Disassembler::new_x64().disassemble(bytes, 0x1000) {
        for instruction in instructions { let _ = instruction.ir; }
    }
    if let Ok(disassembler) = ArmDisassembler::new_arm() { let _ = disassembler.disassemble(bytes, 0x1000); }
    if let Ok(disassembler) = ArmDisassembler::new_arm64() { let _ = disassembler.disassemble(bytes, 0x1000); }
});
