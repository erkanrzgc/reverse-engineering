//! ARM disassembler

use crate::utils::{Error, Result};
use capstone::prelude::*;
use capstone::Capstone;

/// ARM disassembler
pub struct ArmDisassembler {
    cs: Capstone,
}

impl ArmDisassembler {
    /// Create a new ARM disassembler (32-bit)
    pub fn new_arm() -> Result<Self> {
        let cs = Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Arm)
            .detail(true)
            .build()
            .map_err(|e| Error::Disassembly(format!("Failed to create ARM disassembler: {}", e)))?;

        Ok(Self { cs })
    }

    /// Create a new ARM64 disassembler (64-bit)
    pub fn new_arm64() -> Result<Self> {
        let cs = Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .detail(true)
            .build()
            .map_err(|e| {
                Error::Disassembly(format!("Failed to create ARM64 disassembler: {}", e))
            })?;

        Ok(Self { cs })
    }

    /// Disassemble bytes starting at the given address
    pub fn disassemble(&self, data: &[u8], address: u64) -> Result<Vec<ArmInstruction>> {
        let insns = self
            .cs
            .disasm_all(data, address)
            .map_err(|e| Error::Disassembly(format!("Failed to disassemble: {}", e)))?;

        let mut instructions = Vec::new();
        for insn in insns.iter() {
            let mnemonic = insn.mnemonic().unwrap_or("").to_string();
            let operands = insn.op_str().unwrap_or("").to_string();

            let mut instruction = ArmInstruction {
                address: insn.address(),
                bytes: insn.bytes().to_vec(),
                mnemonic,
                operands,
                length: insn.len(),
                near_branch_target: None,
            };
            if instruction.is_control_flow() {
                let detail = self.cs.insn_detail(insn).map_err(|error| {
                    Error::Disassembly(format!("Failed to decode ARM branch operands: {error}"))
                })?;
                let architecture_detail = detail.arch_detail();
                instruction.near_branch_target = if let Some(arm) = architecture_detail.arm() {
                    arm.operands()
                        .filter_map(|operand| match operand.op_type {
                            arch::arm::ArmOperandType::Imm(address) => {
                                Some(u64::from(address as u32))
                            }
                            _ => None,
                        })
                        .last()
                } else if let Some(arm64) = architecture_detail.arm64() {
                    arm64
                        .operands()
                        .filter_map(|operand| match operand.op_type {
                            arch::arm64::Arm64OperandType::Imm(address) => Some(address as u64),
                            _ => None,
                        })
                        .last()
                } else {
                    None
                };
            }
            instructions.push(instruction);
        }

        Ok(instructions)
    }
}

/// ARM instruction
#[derive(Debug, Clone)]
pub struct ArmInstruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub length: usize,
    /// Immediate target supplied by Capstone for direct branches and calls.
    /// Register branches and returns have no statically known target.
    pub near_branch_target: Option<u64>,
}

impl std::fmt::Display for ArmInstruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.operands.is_empty() {
            write!(f, "{}", self.mnemonic)
        } else {
            write!(f, "{} {}", self.mnemonic, self.operands)
        }
    }
}

impl ArmInstruction {
    /// Check if this is a control flow instruction
    pub fn is_control_flow(&self) -> bool {
        let m = self.mnemonic.to_lowercase();
        // Whitelist real branch / return mnemonics.
        // `starts_with("b")` false-positived on bic, bfi, bfc, bkpt, bl etc.
        let base = m.split('.').next().unwrap_or(&m);
        self.is_conditional_branch()
            || self.is_call()
            || self.is_return()
            || matches!(
                base,
                "b" | "bl"
                    | "blx"
                    | "bx"
                    | "bxj"
                    | "cbz"
                    | "cbnz"
                    | "tbb"
                    | "tbh"
                    | "tbz"
                    | "tbnz"
                    | "ret"
                    | "eret"
                    | "br"
                    | "braa"
                    | "brab"
                    | "blr"
                    | "blraa"
                    | "blrab"
            )
    }

    /// Check if this is a conditional branch (ARM ".cond" form or ARM32 cond suffix).
    pub fn is_conditional_branch(&self) -> bool {
        let m = self.mnemonic.to_lowercase();
        // AArch64: b.eq, b.ne, etc.  AArch32: beq, bne, etc.  Also cbz/cbnz/tbz/tbnz.
        if matches!(m.as_str(), "cbz" | "cbnz" | "tbz" | "tbnz") {
            return true;
        }
        if let Some(rest) = m.strip_prefix("b.") {
            return !rest.is_empty();
        }
        // ARM32: "b" followed by 2-char condition code (eq, ne, cs, cc, mi, pl, vs, vc, hi, ls, ge, lt, gt, le, al)
        if m.len() == 3 && m.starts_with('b') {
            let cc = &m[1..];
            return matches!(
                cc,
                "eq" | "ne"
                    | "cs"
                    | "hs"
                    | "cc"
                    | "lo"
                    | "mi"
                    | "pl"
                    | "vs"
                    | "vc"
                    | "hi"
                    | "ls"
                    | "ge"
                    | "lt"
                    | "gt"
                    | "le"
            );
        }
        false
    }

    /// Check if this is an unconditional branch
    pub fn is_unconditional_branch(&self) -> bool {
        let m = self.mnemonic.to_lowercase();
        !self.is_return() && matches!(m.as_str(), "b" | "bx" | "bxj" | "br" | "braa" | "brab")
    }

    /// Check if this is a call instruction
    pub fn is_call(&self) -> bool {
        let m = self.mnemonic.to_lowercase();
        matches!(m.as_str(), "bl" | "blx" | "blr" | "blraa" | "blrab")
            || m.strip_prefix("blx")
                .or_else(|| m.strip_prefix("bl"))
                .is_some_and(|condition| {
                    matches!(
                        condition,
                        "eq" | "ne"
                            | "cs"
                            | "hs"
                            | "cc"
                            | "lo"
                            | "mi"
                            | "pl"
                            | "vs"
                            | "vc"
                            | "hi"
                            | "ls"
                            | "ge"
                            | "lt"
                            | "gt"
                            | "le"
                            | "al"
                    )
                })
    }

    /// Check if this is a return instruction
    pub fn is_return(&self) -> bool {
        let m = self.mnemonic.to_lowercase();
        matches!(m.as_str(), "ret" | "eret")
            || (m == "bx" && self.operands.trim().eq_ignore_ascii_case("lr"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(mnemonic: &str) -> ArmInstruction {
        ArmInstruction {
            address: 0,
            bytes: vec![],
            mnemonic: mnemonic.to_string(),
            operands: String::new(),
            length: 4,
            near_branch_target: None,
        }
    }

    #[test]
    fn branches_are_classified_as_control_flow() {
        assert!(make("b").is_control_flow());
        assert!(make("bl").is_control_flow());
        assert!(make("blx").is_control_flow());
        assert!(make("bx").is_control_flow());
        assert!(make("cbz").is_control_flow());
        assert!(make("cbnz").is_control_flow());
        assert!(make("ret").is_control_flow());
        assert!(make("br").is_control_flow());
        assert!(make("blr").is_control_flow());
    }

    #[test]
    fn bitfield_and_bkpt_are_not_branches() {
        // Regression: old `starts_with("b")` misclassified these as branches,
        // which corrupted the CFG because they'd trigger basic-block splits.
        assert!(!make("bic").is_control_flow());
        assert!(!make("bics").is_control_flow());
        assert!(!make("bfi").is_control_flow());
        assert!(!make("bfc").is_control_flow());
        assert!(!make("bfxil").is_control_flow());
        assert!(!make("bkpt").is_control_flow());
    }

    #[test]
    fn aarch64_dot_cond_branches_are_conditional() {
        assert!(make("b.eq").is_conditional_branch());
        assert!(make("b.ne").is_conditional_branch());
        assert!(make("b.lt").is_conditional_branch());
        assert!(make("B.GT").is_conditional_branch()); // case-insensitive
    }

    #[test]
    fn arm32_cond_suffix_branches_are_conditional() {
        assert!(make("beq").is_conditional_branch());
        assert!(make("bne").is_conditional_branch());
        assert!(make("bge").is_conditional_branch());
        assert!(make("blt").is_conditional_branch());
    }

    #[test]
    fn compare_and_branch_are_conditional() {
        assert!(make("cbz").is_conditional_branch());
        assert!(make("cbnz").is_conditional_branch());
        assert!(make("tbz").is_conditional_branch());
        assert!(make("tbnz").is_conditional_branch());
    }

    #[test]
    fn unconditional_branch_is_not_conditional() {
        assert!(make("b").is_unconditional_branch());
        assert!(!make("b").is_conditional_branch());
        assert!(make("bx").is_unconditional_branch());
        assert!(make("br").is_unconditional_branch());
    }

    #[test]
    fn bl_is_call_not_plain_branch() {
        assert!(make("bl").is_call());
        assert!(make("blx").is_call());
        assert!(make("blr").is_call());
        assert!(!make("bl").is_unconditional_branch());
    }

    #[test]
    fn ret_and_eret_are_returns() {
        assert!(make("ret").is_return());
        assert!(make("eret").is_return());
        assert!(!make("bl").is_return());
    }

    #[test]
    fn to_string_format_with_and_without_operands() {
        let mut ins = make("mov");
        ins.operands = "x0, x1".to_string();
        assert_eq!(ins.to_string(), "mov x0, x1");

        let bare = make("ret");
        assert_eq!(bare.to_string(), "ret");
    }

    #[test]
    fn disassembles_aarch64_ret() {
        // AArch64 ret = 0xC0 0x03 0x5F 0xD6 (little-endian).
        let bytes = [0xC0, 0x03, 0x5F, 0xD6];
        let disasm = ArmDisassembler::new_arm64().expect("arm64 disasm ok");
        let out = disasm.disassemble(&bytes, 0x1000).expect("decode ok");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].address, 0x1000);
        assert_eq!(out[0].length, 4);
        assert!(out[0].is_return());
    }
}
