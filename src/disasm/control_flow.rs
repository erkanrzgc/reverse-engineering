//! Control flow graph construction

use crate::disasm::{ArmInstruction, X86Instruction};
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::{HashMap, HashSet};

/// Control flow graph edge type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeType {
    /// Fall-through edge
    FallThrough,
    /// Conditional branch (true)
    BranchTrue,
    /// Conditional branch (false)
    BranchFalse,
    /// Unconditional jump
    Unconditional,
    /// Call edge
    Call,
    /// Return edge
    Return,
}

/// Basic block in the control flow graph
#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub address: u64,
    pub instructions: Vec<Instruction>,
    pub successors: Vec<NodeIndex>,
    pub predecessors: Vec<NodeIndex>,
}

/// Generic instruction wrapper
#[derive(Debug, Clone)]
pub enum Instruction {
    X86(X86Instruction),
    Arm(ArmInstruction),
}

impl Instruction {
    pub fn address(&self) -> u64 {
        match self {
            Instruction::X86(instr) => instr.address,
            Instruction::Arm(instr) => instr.address,
        }
    }

    pub fn is_control_flow(&self) -> bool {
        match self {
            Instruction::X86(instr) => instr.is_control_flow(),
            Instruction::Arm(instr) => instr.is_control_flow(),
        }
    }

    pub fn is_conditional_jump(&self) -> bool {
        match self {
            Instruction::X86(instr) => instr.is_conditional_jump(),
            Instruction::Arm(instr) => instr.is_conditional_branch(),
        }
    }

    pub fn is_unconditional_jump(&self) -> bool {
        match self {
            Instruction::X86(instr) => instr.is_unconditional_jump(),
            Instruction::Arm(instr) => instr.is_unconditional_branch(),
        }
    }

    pub fn is_call(&self) -> bool {
        match self {
            Instruction::X86(instr) => instr.is_call(),
            Instruction::Arm(instr) => instr.is_call(),
        }
    }

    pub fn is_return(&self) -> bool {
        match self {
            Instruction::X86(instr) => instr.is_return(),
            Instruction::Arm(instr) => instr.is_return(),
        }
    }
}

/// Control flow graph
#[derive(Debug, Clone)]
pub struct ControlFlowGraph {
    graph: DiGraph<BasicBlock, EdgeType>,
    entry: Option<NodeIndex>,
    address_to_node: HashMap<u64, NodeIndex>,
    address_to_location: HashMap<u64, (NodeIndex, usize)>,
}

impl ControlFlowGraph {
    /// Create a new empty control flow graph
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            entry: None,
            address_to_node: HashMap::new(),
            address_to_location: HashMap::new(),
        }
    }

    /// Build CFG from x86 instructions
    pub fn from_x86(instructions: Vec<X86Instruction>) -> Self {
        let mut cfg = Self::new();
        let instrs: Vec<Instruction> = instructions.into_iter().map(Instruction::X86).collect();
        cfg.build(&instrs);
        cfg
    }

    /// Build CFG from ARM instructions
    pub fn from_arm(instructions: Vec<ArmInstruction>) -> Self {
        let mut cfg = Self::new();
        let instrs: Vec<Instruction> = instructions.into_iter().map(Instruction::Arm).collect();
        cfg.build(&instrs);
        cfg
    }

    /// Build CFG from a mixed/generic instruction stream.
    pub fn from_instructions(instructions: &[Instruction]) -> Self {
        let mut cfg = Self::new();
        cfg.build(instructions);
        cfg
    }

    /// Build CFG from generic instructions
    fn build(&mut self, instructions: &[Instruction]) {
        if instructions.is_empty() {
            return;
        }

        // Find all basic block leaders
        let mut leaders: HashSet<u64> = HashSet::new();
        leaders.insert(instructions[0].address());

        let mut i = 0;
        while i < instructions.len() {
            let instr = &instructions[i];

            if instr.is_control_flow() {
                // Next instruction is a leader (if not control flow itself)
                if i + 1 < instructions.len() {
                    leaders.insert(instructions[i + 1].address());
                }

                // Extract target address from jump/call instructions
                if let Some(target) = self.extract_target(instr) {
                    leaders.insert(target);
                }
            }

            i += 1;
        }

        // Create basic blocks
        let mut blocks: Vec<(u64, Vec<Instruction>)> = Vec::new();
        let mut current_block: Vec<Instruction> = Vec::new();
        let mut current_start = instructions[0].address();

        for instr in instructions {
            if instr.address() != current_start && leaders.contains(&instr.address()) {
                if !current_block.is_empty() {
                    blocks.push((current_start, std::mem::take(&mut current_block)));
                }
                current_start = instr.address();
            }
            current_block.push(instr.clone());
        }

        if !current_block.is_empty() {
            blocks.push((current_start, current_block));
        }

        // Add nodes to graph
        for (address, instrs) in &blocks {
            let node = self.graph.add_node(BasicBlock {
                address: *address,
                instructions: instrs.clone(),
                successors: Vec::new(),
                predecessors: Vec::new(),
            });
            self.address_to_node.insert(*address, node);
            for (idx, instr) in instrs.iter().enumerate() {
                self.address_to_location.insert(instr.address(), (node, idx));
            }

            if self.entry.is_none() {
                self.entry = Some(node);
            }
        }

        // Add edges
        for (i, (address, instrs)) in blocks.iter().enumerate() {
            if let Some(&node) = self.address_to_node.get(address) {
                let last_instr = instrs.last();

                if let Some(instr) = last_instr {
                    if instr.is_conditional_jump() {
                        // Add true edge to target
                        if let Some(target) = self.extract_target(instr) {
                            if let Some(&target_node) = self.address_to_node.get(&target) {
                                self.graph.add_edge(node, target_node, EdgeType::BranchTrue);
                            }
                        }

                        // Add false edge to next block
                        if i + 1 < blocks.len() {
                            let next_address = blocks[i + 1].0;
                            if let Some(&next_node) = self.address_to_node.get(&next_address) {
                                self.graph.add_edge(node, next_node, EdgeType::BranchFalse);
                            }
                        }
                    } else if instr.is_unconditional_jump() {
                        // Add unconditional edge to target
                        if let Some(target) = self.extract_target(instr) {
                            if let Some(&target_node) = self.address_to_node.get(&target) {
                                self.graph
                                    .add_edge(node, target_node, EdgeType::Unconditional);
                            }
                        }
                    } else if instr.is_call() {
                        // Add call edge
                        if let Some(target) = self.extract_target(instr) {
                            if let Some(&target_node) = self.address_to_node.get(&target) {
                                self.graph.add_edge(node, target_node, EdgeType::Call);
                            }
                        }

                        // Fall-through after call
                        if i + 1 < blocks.len() {
                            let next_address = blocks[i + 1].0;
                            if let Some(&next_node) = self.address_to_node.get(&next_address) {
                                self.graph.add_edge(node, next_node, EdgeType::FallThrough);
                            }
                        }
                    } else if !instr.is_return() {
                        // Fall-through to next block
                        if i + 1 < blocks.len() {
                            let next_address = blocks[i + 1].0;
                            if let Some(&next_node) = self.address_to_node.get(&next_address) {
                                self.graph.add_edge(node, next_node, EdgeType::FallThrough);
                            }
                        }
                    }
                }
            }
        }

        // Update successors and predecessors
        self.update_adjacency();
    }

    /// Extract target address from instruction.
    ///
    /// For x86 we use the structured `near_branch_target` populated by iced-x86
    /// (only set for real near jmp/jcc/call). Falling back to operand-string
    /// parsing would incorrectly treat data memory references like
    /// `mov rax, [0x401000]` as branch targets and corrupt the CFG.
    fn extract_target(&self, instr: &Instruction) -> Option<u64> {
        match instr {
            Instruction::X86(x86_instr) => x86_instr.near_branch_target,
            Instruction::Arm(arm_instr) => {
                // capstone exposes target via detail operands; until we thread
                // detail info through, fall back to parsing the immediate string.
                self.parse_immediate(&arm_instr.operands)
            }
        }
    }

    /// Parse immediate value from operand string
    fn parse_immediate(&self, operands: &str) -> Option<u64> {
        // Look for hex addresses like 0x1234 or 0h1234
        let re = regex::Regex::new(r"0[xX]([0-9A-Fa-f]+)|0h([0-9A-Fa-f]+)").ok()?;
        if let Some(caps) = re.captures(operands) {
            let hex = caps.get(1).or_else(|| caps.get(2))?.as_str();
            u64::from_str_radix(hex, 16).ok()
        } else {
            // Try to parse decimal
            operands.trim().parse().ok()
        }
    }

    /// Update successor and predecessor lists
    fn update_adjacency(&mut self) {
        let nodes: Vec<_> = self.graph.node_indices().collect();

        for node in &nodes {
            let successors: Vec<NodeIndex> = self.graph.neighbors(*node).collect();
            let predecessors: Vec<NodeIndex> = self
                .graph
                .neighbors_directed(*node, petgraph::Direction::Incoming)
                .collect();

            if let Some(block) = self.graph.node_weight_mut(*node) {
                block.successors = successors;
                block.predecessors = predecessors;
            }
        }
    }

    /// Get the entry node
    pub fn entry(&self) -> Option<NodeIndex> {
        self.entry
    }

    /// Get all basic blocks
    pub fn blocks(&self) -> Vec<&BasicBlock> {
        self.graph.node_weights().collect()
    }

    /// Get basic block by address
    pub fn block_by_address(&self, address: u64) -> Option<&BasicBlock> {
        self.address_to_node
            .get(&address)
            .and_then(|&node| self.graph.node_weight(node))
    }

    /// Get the underlying graph
    pub fn graph(&self) -> &DiGraph<BasicBlock, EdgeType> {
        &self.graph
    }

    /// Fetch instruction by its address (if present in the decoded stream).
    pub fn instruction_by_address(&self, address: u64) -> Option<&Instruction> {
        let (node, idx) = self.address_to_location.get(&address).copied()?;
        self.graph.node_weight(node)?.instructions.get(idx)
    }

    /// Fetch the instruction immediately preceding `address` within the same basic block.
    pub fn previous_instruction_in_block(&self, address: u64) -> Option<&Instruction> {
        let (node, idx) = self.address_to_location.get(&address).copied()?;
        if idx == 0 {
            return None;
        }
        self.graph.node_weight(node)?.instructions.get(idx - 1)
    }
}

impl Default for ControlFlowGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::X86Instruction;

    fn x86(address: u64, mnemonic: &str, target: Option<u64>) -> X86Instruction {
        X86Instruction {
            address,
            bytes: vec![],
            mnemonic: mnemonic.to_string(),
            operands: String::new(),
            length: 1,
            ir: None,
            near_branch_target: target,
        }
    }

    #[test]
    fn empty_stream_produces_empty_graph() {
        let cfg = ControlFlowGraph::from_x86(vec![]);
        assert!(cfg.entry().is_none());
        assert_eq!(cfg.blocks().len(), 0);
    }

    #[test]
    fn linear_block_has_single_ret_terminator() {
        // nop; nop; ret — a single basic block.
        let insns = vec![
            x86(0x1000, "nop", None),
            x86(0x1001, "nop", None),
            x86(0x1002, "ret", None),
        ];
        let cfg = ControlFlowGraph::from_x86(insns);

        assert_eq!(cfg.blocks().len(), 1);
        let entry = cfg.entry().expect("entry set");
        let block = cfg.graph().node_weight(entry).unwrap();
        assert_eq!(block.address, 0x1000);
        assert_eq!(block.instructions.len(), 3);
        // ret must terminate — no fall-through successor.
        assert_eq!(cfg.graph().edge_count(), 0);
    }

    #[test]
    fn conditional_branch_creates_two_edges() {
        // 0x1000: jne 0x1010
        // 0x1001: nop
        // 0x1002: ret
        // 0x1010: ret   (branch target — separate block)
        let insns = vec![
            x86(0x1000, "jne", Some(0x1010)),
            x86(0x1001, "nop", None),
            x86(0x1002, "ret", None),
            x86(0x1010, "ret", None),
        ];
        let cfg = ControlFlowGraph::from_x86(insns);

        assert_eq!(
            cfg.blocks().len(),
            3,
            "jne, fall-through body, and branch target"
        );

        let head = cfg.block_by_address(0x1000).expect("head block exists");
        assert_eq!(
            head.successors.len(),
            2,
            "conditional branch = true + false edges"
        );

        // Edge-type distribution from the head block.
        let head_node = *cfg.address_to_node.get(&0x1000).unwrap();
        let mut edge_types: Vec<EdgeType> =
            cfg.graph().edges(head_node).map(|e| *e.weight()).collect();
        edge_types.sort_by_key(|e| format!("{:?}", e));
        assert!(edge_types.contains(&EdgeType::BranchTrue));
        assert!(edge_types.contains(&EdgeType::BranchFalse));
    }

    #[test]
    fn unconditional_jump_has_single_edge_and_no_fallthrough() {
        // 0x1000: jmp 0x1010
        // 0x1005: nop    (dead code — separate block with no predecessor)
        // 0x1010: ret
        let insns = vec![
            x86(0x1000, "jmp", Some(0x1010)),
            x86(0x1005, "nop", None),
            x86(0x1010, "ret", None),
        ];
        let cfg = ControlFlowGraph::from_x86(insns);

        let head = cfg.block_by_address(0x1000).expect("head block");
        assert_eq!(head.successors.len(), 1, "unconditional jmp = single edge");

        let head_node = *cfg.address_to_node.get(&0x1000).unwrap();
        let edge_types: Vec<EdgeType> = cfg.graph().edges(head_node).map(|e| *e.weight()).collect();
        assert_eq!(edge_types, vec![EdgeType::Unconditional]);
    }

    #[test]
    fn call_has_call_edge_and_fallthrough_when_target_in_stream() {
        // 0x1000: nop
        // 0x1001: call 0x1010
        // 0x1006: nop        (fall-through — new block after call)
        // 0x1007: ret
        // 0x1010: ret        (callee)
        let insns = vec![
            x86(0x1000, "nop", None),
            x86(0x1001, "call", Some(0x1010)),
            x86(0x1006, "nop", None),
            x86(0x1007, "ret", None),
            x86(0x1010, "ret", None),
        ];
        let cfg = ControlFlowGraph::from_x86(insns);

        let caller_node = *cfg.address_to_node.get(&0x1000).unwrap();
        let edge_types: Vec<EdgeType> = cfg
            .graph()
            .edges(caller_node)
            .map(|e| *e.weight())
            .collect();
        assert!(edge_types.contains(&EdgeType::Call));
        assert!(edge_types.contains(&EdgeType::FallThrough));
    }

    #[test]
    fn unresolved_branch_target_does_not_create_edge() {
        // Branch target outside decoded stream: no edge should be added, but
        // the block must still exist.
        let insns = vec![
            x86(0x1000, "jmp", Some(0xDEAD_0000)),
            x86(0x1005, "ret", None),
        ];
        let cfg = ControlFlowGraph::from_x86(insns);

        let head = cfg.block_by_address(0x1000).expect("head block exists");
        assert_eq!(head.successors.len(), 0, "unresolved target = no edge");
    }
}
