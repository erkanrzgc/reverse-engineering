//! Minimal semantic instruction IR for decompilation passes.
//!
//! Goal: represent operands and a few key instruction classes (cmp/test/jcc, mov/xor, calls)
//! without relying on disassembler-formatted operand strings. This makes condition recovery
//! and stack-variable naming stable across formatting differences and easier to extend to
//! additional architectures.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstructionIR {
    pub address: u64,
    pub op: String,
    pub operands: Vec<Operand>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operand {
    Reg(String),
    Imm(i64),
    Mem(MemoryOperand),
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryOperand {
    pub base: Option<String>,
    pub index: Option<String>,
    pub scale: u8,
    pub disp: i64,
    pub size_bytes: Option<u32>,
}

impl MemoryOperand {
    /// Construct a frame-relative memory reference such as `[rbp-0x10]`.
    ///
    /// Helper kept narrow so callers don't accidentally pass `scale == 0` for
    /// absolute or RIP-relative memory references that should not have an index.
    pub fn frame(base: impl Into<String>, disp: i64, size_bytes: Option<u32>) -> Self {
        Self {
            base: Some(base.into()),
            index: None,
            scale: 1,
            disp,
            size_bytes,
        }
    }

    /// Whether this memory operand looks like a stack-frame access (`rbp`/`rsp`
    /// base with no index register).
    pub fn is_stack_frame_ref(&self) -> bool {
        if self.index.is_some() {
            return false;
        }
        match self.base.as_deref() {
            Some(base) => matches!(
                base.to_ascii_lowercase().as_str(),
                "rbp" | "ebp" | "bp" | "rsp" | "esp" | "sp"
            ),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operand_variants_compare_equal_by_value() {
        assert_eq!(Operand::Reg("rax".into()), Operand::Reg("rax".into()));
        assert_ne!(Operand::Reg("rax".into()), Operand::Reg("rbx".into()));
        assert_eq!(Operand::Imm(0x1234), Operand::Imm(0x1234));
        assert_ne!(Operand::Imm(0x1234), Operand::Imm(0x1235));
    }

    #[test]
    fn instruction_ir_exposes_address_op_and_operands() {
        let ir = InstructionIR {
            address: 0x1000,
            op: "mov".into(),
            operands: vec![Operand::Reg("rax".into()), Operand::Imm(42)],
        };
        assert_eq!(ir.address, 0x1000);
        assert_eq!(ir.op, "mov");
        assert_eq!(ir.operands.len(), 2);
        assert!(matches!(&ir.operands[0], Operand::Reg(name) if name == "rax"));
        assert!(matches!(&ir.operands[1], Operand::Imm(42)));
    }

    #[test]
    fn memory_operand_frame_helper_sets_no_index_and_scale_one() {
        let mem = MemoryOperand::frame("rbp", -0x10, Some(8));
        assert_eq!(mem.base.as_deref(), Some("rbp"));
        assert_eq!(mem.index, None);
        assert_eq!(mem.scale, 1);
        assert_eq!(mem.disp, -0x10);
        assert_eq!(mem.size_bytes, Some(8));
    }

    #[test]
    fn is_stack_frame_ref_accepts_rbp_rsp_variants() {
        for base in ["rbp", "RBP", "ebp", "bp", "rsp", "ESP", "sp"] {
            assert!(
                MemoryOperand::frame(base, 0, None).is_stack_frame_ref(),
                "{} should be a stack-frame ref",
                base
            );
        }
    }

    #[test]
    fn is_stack_frame_ref_rejects_general_purpose_bases() {
        for base in ["rax", "rbx", "rcx", "rdx", "r8"] {
            assert!(
                !MemoryOperand::frame(base, 0, None).is_stack_frame_ref(),
                "{} should NOT be a stack-frame ref",
                base
            );
        }
    }

    #[test]
    fn is_stack_frame_ref_rejects_indexed_memory_even_with_rbp_base() {
        // [rbp + rax*4] is not a plain frame slot — it is array-style indexing
        // and must not be treated as a stack local by later passes.
        let mem = MemoryOperand {
            base: Some("rbp".into()),
            index: Some("rax".into()),
            scale: 4,
            disp: 0,
            size_bytes: None,
        };
        assert!(!mem.is_stack_frame_ref());
    }

    #[test]
    fn is_stack_frame_ref_rejects_baseless_memory() {
        // Absolute / RIP-relative memory references with no base register
        // (e.g. `[0x401000]`, `[rip + 0x1234]` lowered to disp-only) must not
        // be confused with stack locals.
        let mem = MemoryOperand {
            base: None,
            index: None,
            scale: 1,
            disp: 0x401000,
            size_bytes: None,
        };
        assert!(!mem.is_stack_frame_ref());
    }

    #[test]
    fn operand_other_preserves_raw_text() {
        // Until every architecture has a typed lowering, `Operand::Other`
        // carries the original disasm-formatted text so existing passes
        // (e.g. inline-asm comment emission) keep working.
        let op = Operand::Other("xmmword ptr [rsp+10h]".into());
        assert!(matches!(op, Operand::Other(ref s) if s == "xmmword ptr [rsp+10h]"));
    }
}

