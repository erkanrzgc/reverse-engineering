//! Code pattern matching

use crate::disasm::Instruction;
use regex::Regex;

/// Pattern match result
#[derive(Debug, Clone)]
pub struct PatternMatch {
    pub pattern_name: String,
    pub address: u64,
    pub confidence: f32,
    pub metadata: String,
}

/// Pattern matcher
pub struct PatternMatcher {
    /// Known patterns
    patterns: Vec<Pattern>,
}

/// A code pattern
struct Pattern {
    name: String,
    regex: Regex,
    confidence: f32,
}

impl PatternMatcher {
    /// Create a new pattern matcher
    pub fn new() -> Self {
        let patterns = vec![
            // Common function prologues
            Pattern {
                name: "function_prologue_x86".to_string(),
                regex: Regex::new(r"push (ebp|rbp);\s*mov (ebp|rbp), (esp|rsp)").unwrap(),
                confidence: 0.9,
            },
            Pattern {
                name: "function_prologue_x64".to_string(),
                regex: Regex::new(r"push rbp;\s*mov rbp, rsp").unwrap(),
                confidence: 0.9,
            },
            // String operations
            Pattern {
                name: "string_copy".to_string(),
                regex: Regex::new(r"mov (eax|rax),\s*\[.*\];\s*test (eax|rax),\s*(eax|rax)")
                    .unwrap(),
                confidence: 0.7,
            },
            // Loop patterns
            Pattern {
                name: "for_loop".to_string(),
                regex: Regex::new(r"dec (eax|ecx|rcx);\s*jnz").unwrap(),
                confidence: 0.8,
            },
            Pattern {
                name: "while_loop".to_string(),
                regex: Regex::new(r"cmp.*;\s*j[ne|ge|le]").unwrap(),
                confidence: 0.7,
            },
            // Memory allocation
            Pattern {
                name: "malloc_call".to_string(),
                regex: Regex::new(r"call.*malloc").unwrap(),
                confidence: 0.95,
            },
            Pattern {
                name: "free_call".to_string(),
                regex: Regex::new(r"call.*free").unwrap(),
                confidence: 0.95,
            },
        ];

        Self { patterns }
    }

    /// Match patterns in instructions
    pub fn match_patterns(&self, instructions: &[Instruction]) -> Vec<PatternMatch> {
        let mut matches = Vec::new();

        // Build instruction string for pattern matching
        let instr_str: String = instructions
            .iter()
            .map(|instr| match instr {
                Instruction::X86(x) => x.to_string(),
                Instruction::Arm(a) => a.to_string(),
            })
            .collect::<Vec<_>>()
            .join("; ");

        for pattern in &self.patterns {
            if let Some(caps) = pattern.regex.find(&instr_str) {
                matches.push(PatternMatch {
                    pattern_name: pattern.name.clone(),
                    address: instructions.first().map(|i| i.address()).unwrap_or(0),
                    confidence: pattern.confidence,
                    metadata: caps.as_str().to_string(),
                });
            }
        }

        matches
    }

    /// Match single instruction patterns
    pub fn match_instruction(&self, instr: &Instruction) -> Vec<PatternMatch> {
        let instr_str = match instr {
            Instruction::X86(x) => x.to_string(),
            Instruction::Arm(a) => a.to_string(),
        };

        let mut matches = Vec::new();

        for pattern in &self.patterns {
            if pattern.regex.is_match(&instr_str) {
                matches.push(PatternMatch {
                    pattern_name: pattern.name.clone(),
                    address: instr.address(),
                    confidence: pattern.confidence,
                    metadata: instr_str.clone(),
                });
            }
        }

        matches
    }
}

impl Default for PatternMatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::X86Instruction;

    fn x86(address: u64, mnemonic: &str, operands: &str) -> Instruction {
        Instruction::X86(X86Instruction {
            address,
            bytes: vec![],
            mnemonic: mnemonic.to_string(),
            operands: operands.to_string(),
            length: 0,
            ir: None,
            near_branch_target: None,
        })
    }

    fn matched_names(matches: &[PatternMatch]) -> Vec<&str> {
        matches.iter().map(|m| m.pattern_name.as_str()).collect()
    }

    #[test]
    fn new_pattern_matcher_registers_built_in_pattern_set() {
        // Lock the set so accidentally dropping or duplicating a pattern is caught.
        let matcher = PatternMatcher::new();
        let names: Vec<&str> = matcher.patterns.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "function_prologue_x86",
                "function_prologue_x64",
                "string_copy",
                "for_loop",
                "while_loop",
                "malloc_call",
                "free_call",
            ]
        );
        // Confidence values should stay within [0, 1].
        for pattern in &matcher.patterns {
            assert!(
                (0.0..=1.0).contains(&pattern.confidence),
                "{} has out-of-range confidence {}",
                pattern.name,
                pattern.confidence
            );
        }
    }

    #[test]
    fn matches_x64_function_prologue_pattern() {
        let matcher = PatternMatcher::new();
        let matches = matcher.match_patterns(&[
            x86(0x1000, "push", "rbp"),
            x86(0x1001, "mov", "rbp, rsp"),
        ]);
        let names = matched_names(&matches);
        assert!(
            names.contains(&"function_prologue_x64"),
            "expected x64 prologue match, got {:?}",
            names
        );
        // The 32-bit pattern also matches because "push (ebp|rbp); mov (ebp|rbp), (esp|rsp)"
        // is a superset — this is the current contract.
        assert!(names.contains(&"function_prologue_x86"));
    }

    #[test]
    fn match_position_anchors_to_first_instruction_address() {
        let matcher = PatternMatcher::new();
        let matches = matcher.match_patterns(&[
            x86(0x401000, "push", "rbp"),
            x86(0x401001, "mov", "rbp, rsp"),
        ]);
        assert!(!matches.is_empty());
        assert!(
            matches.iter().all(|m| m.address == 0x401000),
            "all matches should report the first instruction's address"
        );
    }

    #[test]
    fn matches_malloc_and_free_call_patterns() {
        let matcher = PatternMatcher::new();

        let malloc = matcher.match_patterns(&[x86(0x1000, "call", "0x402000 <malloc@plt>")]);
        assert!(matched_names(&malloc).contains(&"malloc_call"));

        let free = matcher.match_patterns(&[x86(0x1000, "call", "0x402008 <free@plt>")]);
        assert!(matched_names(&free).contains(&"free_call"));
    }

    #[test]
    fn match_instruction_returns_empty_for_unrelated_single_instruction() {
        let matcher = PatternMatcher::new();
        let matches = matcher.match_instruction(&x86(0x1000, "nop", ""));
        assert!(matches.is_empty(), "got unexpected matches: {:?}", matches);
    }

    #[test]
    fn match_patterns_empty_input_returns_empty_result_and_uses_zero_address() {
        let matcher = PatternMatcher::new();
        let matches = matcher.match_patterns(&[]);
        assert!(matches.is_empty());
        // Sanity: even if a fake pattern matched the empty string, the address
        // fallback would be 0. Documented behaviour, not exercised here.
    }

    #[test]
    fn unrelated_instruction_sequence_produces_no_pattern_matches() {
        let matcher = PatternMatcher::new();
        let matches = matcher.match_patterns(&[
            x86(0x1000, "nop", ""),
            x86(0x1001, "xor", "rax, rax"),
            x86(0x1004, "ret", ""),
        ]);
        assert!(
            matches.is_empty(),
            "unrelated stream should not match any built-in pattern, got {:?}",
            matched_names(&matches)
        );
    }
}
