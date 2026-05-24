//! Function detection and analysis

use crate::binary::parser::{ExportInfo, ImportInfo};
use crate::disasm::control_flow::Instruction;
use std::collections::{BTreeSet, HashMap};

/// Function information
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub name: String,
    pub address: u64,
    pub size: usize,
    pub instructions: Vec<Instruction>,
    pub is_import: bool,
    pub is_export: bool,
}

/// Inputs to the function detection pass.
pub struct FunctionDetectionInputs<'a> {
    pub instructions: &'a [Instruction],
    pub entry_point: u64,
    pub exports: &'a [ExportInfo],
    pub imports: &'a [ImportInfo],
    pub architecture: &'a str,
}

/// Function detector.
///
/// Uses a seed-based discovery approach:
/// 1. Entry point from the binary header.
/// 2. Export table addresses.
/// 3. `call` instruction targets (every real call lands at a function start).
/// 4. Byte-pattern prologue matching as a fallback for stripped code.
///
/// Pure prologue matching alone misses most real-world binaries: modern MSVC
/// x64 functions often skip `push rbp; mov rbp, rsp` entirely, and optimized
/// code uses a wide variety of frame setups. Call-target seeding is the most
/// reliable signal in stripped binaries.
pub struct FunctionDetector {
    x86_prologues: Vec<Vec<u8>>,
    x64_prologues: Vec<Vec<u8>>,
    arm_prologues: Vec<Vec<u8>>,
    arm64_prologues: Vec<Vec<u8>>,
}

impl FunctionDetector {
    pub fn new() -> Self {
        Self {
            x86_prologues: vec![
                // push ebp; mov ebp, esp
                vec![0x55, 0x8B, 0xEC],
            ],
            x64_prologues: vec![
                // push rbp; mov rbp, rsp
                vec![0x55, 0x48, 0x89, 0xE5],
                // endbr64  (CET-enabled binaries)
                vec![0xF3, 0x0F, 0x1E, 0xFA],
                // sub rsp, imm8  — very common MSVC x64 first instruction
                vec![0x48, 0x83, 0xEC],
                // sub rsp, imm32
                vec![0x48, 0x81, 0xEC],
                // push rbx / push rbp / push rsi / push rdi (nonvolatile saves)
                // These are less specific so we intentionally avoid them to
                // reduce false positives; call-target seeding covers them.
            ],
            arm_prologues: vec![
                // push {r7, lr}
                vec![0x70, 0xB5],
            ],
            arm64_prologues: vec![
                // stp x29, x30, [sp, #-16]!
                vec![0xFD, 0x03, 0x00, 0xA9],
                // sub sp, sp, #16
                vec![0xFF, 0x43, 0x00, 0xD1],
            ],
        }
    }

    /// Primary detection entry point.
    pub fn detect(&self, inputs: FunctionDetectionInputs<'_>) -> Vec<FunctionInfo> {
        let instructions = inputs.instructions;
        if instructions.is_empty() {
            return Vec::new();
        }

        // 1. Build address -> index map for O(1) seed validation.
        let addr_to_idx: HashMap<u64, usize> = instructions
            .iter()
            .enumerate()
            .map(|(i, ins)| (ins.address(), i))
            .collect();

        // 2. Collect seeds.
        let mut seeds: BTreeSet<u64> = BTreeSet::new();
        let mut export_addrs: BTreeSet<u64> = BTreeSet::new();

        if inputs.entry_point != 0 {
            seeds.insert(inputs.entry_point);
        }

        for export in inputs.exports {
            if export.address != 0 {
                seeds.insert(export.address);
                export_addrs.insert(export.address);
            }
        }

        for (idx, instr) in instructions.iter().enumerate() {
            if instr.is_call() || looks_like_tail_jump(idx, instr, instructions, &addr_to_idx) {
                if let Some(target) = branch_target(instr) {
                    seeds.insert(target);
                }
            }
        }

        for instr in instructions {
            if self.is_function_prologue(instr, inputs.architecture) {
                seeds.insert(instr.address());
            }
        }

        // 3. Keep only seeds that actually map to a disassembled instruction.
        let mut valid_seeds: Vec<(u64, usize)> = seeds
            .iter()
            .filter_map(|&addr| addr_to_idx.get(&addr).map(|&i| (addr, i)))
            .collect();
        valid_seeds.sort_by_key(|(a, _)| *a);

        // 4. Slice instruction stream into functions. Each function runs from
        //    its seed index up to (but not including) the next seed index.
        let mut functions = Vec::with_capacity(valid_seeds.len());
        for (i, &(addr, start_idx)) in valid_seeds.iter().enumerate() {
            let end_idx = valid_seeds
                .get(i + 1)
                .map(|&(_, idx)| idx)
                .unwrap_or(instructions.len());

            let func_instrs = instructions[start_idx..end_idx].to_vec();
            let size: usize = func_instrs
                .iter()
                .map(|ins| match ins {
                    Instruction::X86(x) => x.length,
                    Instruction::Arm(a) => a.length,
                })
                .sum();

            let is_export = export_addrs.contains(&addr);
            let name = inputs
                .exports
                .iter()
                .find(|e| e.address == addr && !e.name.is_empty())
                .map(|e| e.name.clone())
                .unwrap_or_else(|| format!("sub_{:X}", addr));

            functions.push(FunctionInfo {
                name,
                address: addr,
                size,
                instructions: func_instrs,
                is_import: false,
                is_export,
            });
        }

        functions
    }

    /// Legacy prologue-only detection (kept for tests / backwards compat).
    pub fn detect_functions(
        &self,
        instructions: &[Instruction],
        architecture: &str,
    ) -> Vec<FunctionInfo> {
        self.detect(FunctionDetectionInputs {
            instructions,
            entry_point: 0,
            exports: &[],
            imports: &[],
            architecture,
        })
    }

    fn is_function_prologue(&self, instr: &Instruction, architecture: &str) -> bool {
        let bytes = match instr {
            Instruction::X86(x) => &x.bytes,
            Instruction::Arm(a) => &a.bytes,
        };

        let prologues = match architecture {
            "x86" => &self.x86_prologues,
            "x64" => &self.x64_prologues,
            "ARM" => &self.arm_prologues,
            "ARM64" => &self.arm64_prologues,
            _ => return false,
        };

        prologues.iter().any(|p| bytes.starts_with(p))
    }
}

impl Default for FunctionDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract a function-call target from an instruction, if structurally known.
fn branch_target(instr: &Instruction) -> Option<u64> {
    match instr {
        Instruction::X86(x) => x.near_branch_target,
        Instruction::Arm(_) => None, // TODO: thread capstone detail for ARM
    }
}

fn looks_like_tail_jump(
    index: usize,
    instr: &Instruction,
    instructions: &[Instruction],
    addr_to_idx: &HashMap<u64, usize>,
) -> bool {
    if !instr.is_unconditional_jump() {
        return false;
    }
    let Some(target) = branch_target(instr) else {
        return false;
    };
    let Some(target_idx) = addr_to_idx.get(&target).copied() else {
        return false;
    };
    target_idx == index + 1
        && instructions
            .get(target_idx)
            .map(|next| next.address() != instr.address().saturating_add(instruction_len(instr)))
            .unwrap_or(false)
}

fn instruction_len(instr: &Instruction) -> u64 {
    match instr {
        Instruction::X86(x) => x.length as u64,
        Instruction::Arm(a) => a.length as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::X86Instruction;

    /// Build a plain x86 instruction with the given shape. Used as a synthetic
    /// input to the detector so we can exercise seed logic without running a
    /// real decoder.
    fn x86(address: u64, mnemonic: &str, bytes: &[u8], target: Option<u64>) -> Instruction {
        Instruction::X86(X86Instruction {
            address,
            bytes: bytes.to_vec(),
            mnemonic: mnemonic.to_string(),
            operands: String::new(),
            length: bytes.len(),
            ir: None,
            near_branch_target: target,
        })
    }

    fn nop(address: u64) -> Instruction {
        x86(address, "nop", &[0x90], None)
    }

    #[test]
    fn empty_instructions_produce_no_functions() {
        let fns = FunctionDetector::new().detect(FunctionDetectionInputs {
            instructions: &[],
            entry_point: 0,
            exports: &[],
            imports: &[],
            architecture: "x64",
        });
        assert!(fns.is_empty());
    }

    #[test]
    fn entry_point_seeds_first_function() {
        // Single-function stream: entry at 0x1000.
        let instrs = vec![nop(0x1000), nop(0x1001), x86(0x1002, "ret", &[0xC3], None)];

        let fns = FunctionDetector::new().detect(FunctionDetectionInputs {
            instructions: &instrs,
            entry_point: 0x1000,
            exports: &[],
            imports: &[],
            architecture: "x64",
        });

        assert_eq!(fns.len(), 1);
        assert_eq!(fns[0].address, 0x1000);
        assert_eq!(fns[0].name, "sub_1000");
        assert_eq!(fns[0].instructions.len(), 3);
    }

    #[test]
    fn call_targets_are_seeded_as_function_starts() {
        // Caller at 0x1000 calls 0x1010. Even without an export for 0x1010,
        // the detector must recognize it as a function start.
        let instrs = vec![
            nop(0x1000),
            x86(
                0x1001,
                "call",
                &[0xE8, 0x0A, 0x00, 0x00, 0x00],
                Some(0x1010),
            ),
            x86(0x1006, "ret", &[0xC3], None),
            nop(0x1010),
            x86(0x1011, "ret", &[0xC3], None),
        ];

        let fns = FunctionDetector::new().detect(FunctionDetectionInputs {
            instructions: &instrs,
            entry_point: 0x1000,
            exports: &[],
            imports: &[],
            architecture: "x64",
        });

        let addrs: Vec<u64> = fns.iter().map(|f| f.address).collect();
        assert!(addrs.contains(&0x1000), "entry point seeded");
        assert!(addrs.contains(&0x1010), "call target seeded");
        assert_eq!(fns.len(), 2);
    }

    #[test]
    fn tail_jump_targets_are_seeded_as_function_starts() {
        let instrs = vec![
            nop(0x1000),
            x86(0x1001, "jmp", &[0xE9, 0x0A, 0x00, 0x00, 0x00], Some(0x1010)),
            nop(0x1010),
            x86(0x1011, "ret", &[0xC3], None),
        ];

        let fns = FunctionDetector::new().detect(FunctionDetectionInputs {
            instructions: &instrs,
            entry_point: 0x1000,
            exports: &[],
            imports: &[],
            architecture: "x64",
        });

        let addrs: Vec<u64> = fns.iter().map(|f| f.address).collect();
        assert!(addrs.contains(&0x1000));
        assert!(addrs.contains(&0x1010), "tail jmp target seeded");
    }

    #[test]
    fn exports_name_the_function() {
        use crate::binary::parser::ExportInfo;

        let instrs = vec![nop(0x2000), x86(0x2001, "ret", &[0xC3], None)];
        let exports = vec![ExportInfo {
            name: "MyExportedFunction".to_string(),
            address: 0x2000,
            ordinal: None,
        }];

        let fns = FunctionDetector::new().detect(FunctionDetectionInputs {
            instructions: &instrs,
            entry_point: 0,
            exports: &exports,
            imports: &[],
            architecture: "x64",
        });

        assert_eq!(fns.len(), 1);
        assert_eq!(fns[0].name, "MyExportedFunction");
        assert!(fns[0].is_export);
    }

    #[test]
    fn unresolved_call_target_outside_instructions_is_ignored() {
        // Call target 0xDEAD0000 is outside the decoded stream — should not
        // create a spurious function record.
        let instrs = vec![
            nop(0x1000),
            x86(0x1001, "call", &[0xE8, 0, 0, 0, 0], Some(0xDEAD_0000)),
            x86(0x1006, "ret", &[0xC3], None),
        ];

        let fns = FunctionDetector::new().detect(FunctionDetectionInputs {
            instructions: &instrs,
            entry_point: 0x1000,
            exports: &[],
            imports: &[],
            architecture: "x64",
        });

        assert_eq!(fns.len(), 1);
        assert_eq!(fns[0].address, 0x1000);
    }

    #[test]
    fn msvc_sub_rsp_prologue_seeds_function() {
        // MSVC x64 prologue: sub rsp, 0x20 (48 83 EC 20) followed by body.
        // Prologue pattern should flag 0x3000 as a function start even without
        // entry/export/call-target info.
        let instrs = vec![
            x86(0x3000, "sub", &[0x48, 0x83, 0xEC, 0x20], None),
            nop(0x3004),
            x86(0x3005, "ret", &[0xC3], None),
        ];

        let fns = FunctionDetector::new().detect(FunctionDetectionInputs {
            instructions: &instrs,
            entry_point: 0,
            exports: &[],
            imports: &[],
            architecture: "x64",
        });

        assert_eq!(fns.len(), 1);
        assert_eq!(fns[0].address, 0x3000);
    }

    #[test]
    fn function_boundaries_slice_instruction_stream() {
        // Two functions back-to-back: 0x1000..0x1010 and 0x1010..end, with
        // 0x1010 seeded via an export so both boundaries are resolved.
        use crate::binary::parser::ExportInfo;

        let instrs = vec![
            nop(0x1000),
            nop(0x1001),
            x86(0x1002, "ret", &[0xC3], None),
            nop(0x1010),
            x86(0x1011, "ret", &[0xC3], None),
        ];
        let exports = vec![ExportInfo {
            name: String::new(),
            address: 0x1010,
            ordinal: None,
        }];

        let fns = FunctionDetector::new().detect(FunctionDetectionInputs {
            instructions: &instrs,
            entry_point: 0x1000,
            exports: &exports,
            imports: &[],
            architecture: "x64",
        });

        assert_eq!(fns.len(), 2);
        assert_eq!(fns[0].address, 0x1000);
        assert_eq!(
            fns[0].instructions.len(),
            3,
            "first function owns 0x1000..0x1010"
        );
        assert_eq!(fns[1].address, 0x1010);
        assert_eq!(fns[1].instructions.len(), 2);
    }
}
