//! Disassembly module

pub mod arm;
pub mod control_flow;
pub mod ir;
pub mod x86;

pub use arm::{ArmDisassembler, ArmInstruction};
pub use control_flow::{BasicBlock, ControlFlowGraph, EdgeType, Instruction};
pub use ir::{InstructionIR, MemoryOperand, Operand};
pub use x86::{X86Disassembler, X86Instruction};
