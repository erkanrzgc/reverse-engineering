//! Type inference for variables and expressions

use crate::disasm::Instruction;
use std::collections::HashMap;

/// Type information
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeInfo {
    /// Void type
    Void,
    /// Boolean
    Bool,
    /// 8-bit signed integer
    I8,
    /// 8-bit unsigned integer
    U8,
    /// 16-bit signed integer
    I16,
    /// 16-bit unsigned integer
    U16,
    /// 32-bit signed integer
    I32,
    /// 32-bit unsigned integer
    U32,
    /// 64-bit signed integer
    I64,
    /// 64-bit unsigned integer
    U64,
    /// Pointer
    Pointer(Box<TypeInfo>),
    /// Array
    Array(Box<TypeInfo>, usize),
    /// Function pointer
    FunctionPointer {
        params: Vec<TypeInfo>,
        return_type: Box<TypeInfo>,
    },
    /// Unknown
    Unknown,
}

impl TypeInfo {
    /// Get the C type name
    pub fn to_c_type(&self) -> &'static str {
        match self {
            TypeInfo::Void => "void",
            TypeInfo::Bool => "bool",
            TypeInfo::I8 => "int8_t",
            TypeInfo::U8 => "uint8_t",
            TypeInfo::I16 => "int16_t",
            TypeInfo::U16 => "uint16_t",
            TypeInfo::I32 => "int32_t",
            TypeInfo::U32 => "uint32_t",
            TypeInfo::I64 => "int64_t",
            TypeInfo::U64 => "uint64_t",
            TypeInfo::Pointer(inner) => match inner.as_ref() {
                TypeInfo::Void => "void*",
                TypeInfo::I8 => "char*",
                TypeInfo::U8 => "unsigned char*",
                _ => "void*", // Conservative default
            },
            TypeInfo::Array(inner, _size) => match inner.as_ref() {
                TypeInfo::I8 => "char[]",
                TypeInfo::U8 => "unsigned char[]",
                _ => "void[]",
            },
            TypeInfo::FunctionPointer { .. } => "void(*)()",
            TypeInfo::Unknown => "void*",
        }
    }

    /// Check if this is an integer type
    pub fn is_integer(&self) -> bool {
        matches!(
            self,
            TypeInfo::I8
                | TypeInfo::U8
                | TypeInfo::I16
                | TypeInfo::U16
                | TypeInfo::I32
                | TypeInfo::U32
                | TypeInfo::I64
                | TypeInfo::U64
        )
    }

    /// Check if this is a pointer type
    pub fn is_pointer(&self) -> bool {
        matches!(self, TypeInfo::Pointer(_) | TypeInfo::Unknown)
    }

    /// Get the size in bytes
    pub fn size(&self) -> usize {
        match self {
            TypeInfo::Void => 0,
            TypeInfo::Bool => 1,
            TypeInfo::I8 | TypeInfo::U8 => 1,
            TypeInfo::I16 | TypeInfo::U16 => 2,
            TypeInfo::I32 | TypeInfo::U32 => 4,
            TypeInfo::I64 | TypeInfo::U64 => 8,
            TypeInfo::Pointer(_) => 8, // Assume 64-bit
            TypeInfo::Array(inner, size) => inner.size() * size,
            TypeInfo::FunctionPointer { .. } => 8,
            TypeInfo::Unknown => 8,
        }
    }
}

/// Type inference engine
pub struct TypeInference {
    /// Known types for registers/variables
    known_types: HashMap<String, TypeInfo>,
}

impl TypeInference {
    /// Create a new type inference engine
    pub fn new() -> Self {
        Self {
            known_types: HashMap::new(),
        }
    }

    /// Infer type from instruction
    pub fn infer_from_instruction(&mut self, instr: &Instruction) -> TypeInfo {
        match instr {
            Instruction::X86(x86_instr) => self.infer_from_x86(x86_instr),
            Instruction::Arm(arm_instr) => self.infer_from_arm(arm_instr),
        }
    }

    /// Infer type from x86 instruction
    fn infer_from_x86(&mut self, instr: &crate::disasm::X86Instruction) -> TypeInfo {
        let mnemonic = instr.mnemonic.to_lowercase();

        // MOV instructions with immediate values
        if mnemonic == "mov" {
            if let Some(value) = self.parse_immediate(&instr.operands) {
                return self.infer_from_immediate(value);
            }
        }

        // Pointer operations
        if mnemonic.contains("lea") || mnemonic.contains("ptr") {
            return TypeInfo::Pointer(Box::new(TypeInfo::Void));
        }

        TypeInfo::Unknown
    }

    /// Infer type from ARM instruction
    fn infer_from_arm(&mut self, instr: &crate::disasm::ArmInstruction) -> TypeInfo {
        let mnemonic = instr.mnemonic.to_lowercase();

        // MOV instructions with immediate values
        if mnemonic == "mov" || mnemonic == "movz" || mnemonic == "movk" {
            if let Some(value) = self.parse_immediate(&instr.operands) {
                return self.infer_from_immediate(value);
            }
        }

        // Load instructions
        if mnemonic.starts_with("ldr") {
            return TypeInfo::Pointer(Box::new(TypeInfo::Void));
        }

        TypeInfo::Unknown
    }

    /// Infer type from immediate value
    fn infer_from_immediate(&self, value: u64) -> TypeInfo {
        if value <= 0xFF {
            TypeInfo::U8
        } else if value <= 0xFFFF {
            TypeInfo::U16
        } else if value <= 0xFFFFFFFF {
            TypeInfo::U32
        } else {
            TypeInfo::U64
        }
    }

    /// Parse immediate value from operand string
    fn parse_immediate(&self, operands: &str) -> Option<u64> {
        // Look for hex addresses like 0x1234
        let re = regex::Regex::new(r"0[xX]([0-9A-Fa-f]+)").ok()?;
        if let Some(caps) = re.captures(operands) {
            let hex = caps.get(1)?.as_str();
            u64::from_str_radix(hex, 16).ok()
        } else {
            // Try to parse decimal
            operands.trim().parse().ok()
        }
    }

    /// Set a known type for a variable
    pub fn set_type(&mut self, name: String, type_info: TypeInfo) {
        self.known_types.insert(name, type_info);
    }

    /// Get the type for a variable
    pub fn get_type(&self, name: &str) -> Option<&TypeInfo> {
        self.known_types.get(name)
    }
}

impl Default for TypeInference {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::X86Instruction;

    fn x86(mnemonic: &str, operands: &str) -> Instruction {
        Instruction::X86(X86Instruction {
            address: 0,
            bytes: vec![],
            mnemonic: mnemonic.to_string(),
            operands: operands.to_string(),
            length: 0,
            ir: None,
            near_branch_target: None,
        })
    }

    // ---- TypeInfo::to_c_type ----

    #[test]
    fn primitive_types_emit_stdint_aliases() {
        assert_eq!(TypeInfo::Void.to_c_type(), "void");
        assert_eq!(TypeInfo::Bool.to_c_type(), "bool");
        assert_eq!(TypeInfo::I8.to_c_type(), "int8_t");
        assert_eq!(TypeInfo::U8.to_c_type(), "uint8_t");
        assert_eq!(TypeInfo::I16.to_c_type(), "int16_t");
        assert_eq!(TypeInfo::U16.to_c_type(), "uint16_t");
        assert_eq!(TypeInfo::I32.to_c_type(), "int32_t");
        assert_eq!(TypeInfo::U32.to_c_type(), "uint32_t");
        assert_eq!(TypeInfo::I64.to_c_type(), "int64_t");
        assert_eq!(TypeInfo::U64.to_c_type(), "uint64_t");
    }

    #[test]
    fn pointer_types_map_void_char_and_uchar_specifically() {
        assert_eq!(
            TypeInfo::Pointer(Box::new(TypeInfo::Void)).to_c_type(),
            "void*"
        );
        assert_eq!(
            TypeInfo::Pointer(Box::new(TypeInfo::I8)).to_c_type(),
            "char*"
        );
        assert_eq!(
            TypeInfo::Pointer(Box::new(TypeInfo::U8)).to_c_type(),
            "unsigned char*"
        );
    }

    #[test]
    fn pointer_to_other_types_falls_back_to_void_pointer() {
        // Conservative — we don't currently emit `uint32_t*` etc.
        assert_eq!(
            TypeInfo::Pointer(Box::new(TypeInfo::U32)).to_c_type(),
            "void*"
        );
        assert_eq!(
            TypeInfo::Pointer(Box::new(TypeInfo::I64)).to_c_type(),
            "void*"
        );
    }

    #[test]
    fn array_types_map_to_char_or_void_brackets() {
        assert_eq!(
            TypeInfo::Array(Box::new(TypeInfo::I8), 16).to_c_type(),
            "char[]"
        );
        assert_eq!(
            TypeInfo::Array(Box::new(TypeInfo::U8), 8).to_c_type(),
            "unsigned char[]"
        );
        assert_eq!(
            TypeInfo::Array(Box::new(TypeInfo::U32), 4).to_c_type(),
            "void[]"
        );
    }

    #[test]
    fn function_pointer_and_unknown_have_conservative_defaults() {
        assert_eq!(
            TypeInfo::FunctionPointer {
                params: vec![],
                return_type: Box::new(TypeInfo::Void),
            }
            .to_c_type(),
            "void(*)()"
        );
        assert_eq!(TypeInfo::Unknown.to_c_type(), "void*");
    }

    // ---- is_integer / is_pointer classification ----

    #[test]
    fn is_integer_is_true_for_all_signed_and_unsigned_integer_widths() {
        for ty in [
            TypeInfo::I8,
            TypeInfo::U8,
            TypeInfo::I16,
            TypeInfo::U16,
            TypeInfo::I32,
            TypeInfo::U32,
            TypeInfo::I64,
            TypeInfo::U64,
        ] {
            assert!(ty.is_integer(), "{:?} should be an integer type", ty);
        }
    }

    #[test]
    fn is_integer_is_false_for_non_integer_types() {
        for ty in [
            TypeInfo::Void,
            TypeInfo::Bool,
            TypeInfo::Pointer(Box::new(TypeInfo::Void)),
            TypeInfo::Array(Box::new(TypeInfo::I8), 4),
            TypeInfo::FunctionPointer {
                params: vec![],
                return_type: Box::new(TypeInfo::Void),
            },
            TypeInfo::Unknown,
        ] {
            assert!(!ty.is_integer(), "{:?} should NOT be an integer type", ty);
        }
    }

    #[test]
    fn is_pointer_is_true_for_pointer_and_unknown_but_not_array_or_fnptr() {
        // Pointer: yes. Unknown: yes (treated as void* by to_c_type).
        assert!(TypeInfo::Pointer(Box::new(TypeInfo::Void)).is_pointer());
        assert!(TypeInfo::Unknown.is_pointer());

        // Array and function pointer are NOT classified as pointer here despite
        // C semantics — this codifies the current contract; flip with care.
        assert!(!TypeInfo::Array(Box::new(TypeInfo::I8), 4).is_pointer());
        assert!(!TypeInfo::FunctionPointer {
            params: vec![],
            return_type: Box::new(TypeInfo::Void),
        }
        .is_pointer());
    }

    // ---- size ----

    #[test]
    fn size_matches_c_stdint_widths_in_bytes() {
        assert_eq!(TypeInfo::Void.size(), 0);
        assert_eq!(TypeInfo::Bool.size(), 1);
        assert_eq!(TypeInfo::I8.size(), 1);
        assert_eq!(TypeInfo::U16.size(), 2);
        assert_eq!(TypeInfo::I32.size(), 4);
        assert_eq!(TypeInfo::U64.size(), 8);
    }

    #[test]
    fn size_assumes_64_bit_targets_for_pointers_fnptrs_and_unknown() {
        assert_eq!(TypeInfo::Pointer(Box::new(TypeInfo::Void)).size(), 8);
        assert_eq!(
            TypeInfo::FunctionPointer {
                params: vec![],
                return_type: Box::new(TypeInfo::Void),
            }
            .size(),
            8
        );
        assert_eq!(TypeInfo::Unknown.size(), 8);
    }

    #[test]
    fn array_size_multiplies_element_size_by_element_count() {
        // 4 × u32 (4 bytes each) = 16 bytes.
        assert_eq!(TypeInfo::Array(Box::new(TypeInfo::U32), 4).size(), 16);
        // 0-length array → 0 bytes.
        assert_eq!(TypeInfo::Array(Box::new(TypeInfo::U64), 0).size(), 0);
    }

    // ---- TypeInference engine ----

    #[test]
    fn infer_from_immediate_picks_narrowest_unsigned_type_that_fits() {
        let infer = TypeInference::new();
        assert_eq!(infer.infer_from_immediate(0), TypeInfo::U8);
        assert_eq!(infer.infer_from_immediate(0xFF), TypeInfo::U8);
        assert_eq!(infer.infer_from_immediate(0x100), TypeInfo::U16);
        assert_eq!(infer.infer_from_immediate(0xFFFF), TypeInfo::U16);
        assert_eq!(infer.infer_from_immediate(0x10000), TypeInfo::U32);
        assert_eq!(infer.infer_from_immediate(0xFFFF_FFFF), TypeInfo::U32);
        assert_eq!(infer.infer_from_immediate(0x1_0000_0000), TypeInfo::U64);
    }

    #[test]
    fn infer_from_x86_mov_immediate_uses_immediate_width_classifier() {
        let mut infer = TypeInference::new();
        // mov rax, 0x42 → immediate fits in U8.
        assert_eq!(
            infer.infer_from_instruction(&x86("mov", "rax, 0x42")),
            TypeInfo::U8
        );
        // mov rax, 0x12345 → fits in U32 (>0xFFFF, ≤0xFFFFFFFF).
        assert_eq!(
            infer.infer_from_instruction(&x86("mov", "rax, 0x12345")),
            TypeInfo::U32
        );
    }

    #[test]
    fn infer_from_x86_lea_returns_pointer_type() {
        let mut infer = TypeInference::new();
        assert_eq!(
            infer.infer_from_instruction(&x86("lea", "rax, [rip+0x100]")),
            TypeInfo::Pointer(Box::new(TypeInfo::Void))
        );
    }

    #[test]
    fn infer_from_x86_returns_unknown_for_uncategorized_mnemonics() {
        let mut infer = TypeInference::new();
        assert_eq!(
            infer.infer_from_instruction(&x86("nop", "")),
            TypeInfo::Unknown
        );
        assert_eq!(
            infer.infer_from_instruction(&x86("ret", "")),
            TypeInfo::Unknown
        );
    }

    #[test]
    fn set_and_get_type_round_trip_through_inference_store() {
        let mut infer = TypeInference::new();
        infer.set_type("rax".to_string(), TypeInfo::I32);

        assert_eq!(infer.get_type("rax"), Some(&TypeInfo::I32));
        assert_eq!(infer.get_type("rbx"), None);
    }
}
