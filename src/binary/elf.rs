//! ELF format parser

use crate::binary::parser::{
    BinaryInfo, ExportInfo, ImportInfo, SectionCharacteristics, SectionInfo,
};
use crate::binary::{BinaryFormat, BinaryParser};
use crate::utils::error::{Error, Result};
use goblin::elf::section_header::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHT_NOBITS, SHT_NULL};
use goblin::elf::Elf;
use std::collections::BTreeSet;

/// ELF parser
#[derive(Default)]
pub struct ElfParser;

impl BinaryParser for ElfParser {
    fn parse(&self, data: &[u8]) -> Result<Box<dyn BinaryInfo>> {
        let elf = Elf::parse(data)
            .map_err(|e| Error::BinaryParse(format!("Failed to parse ELF: {}", e)))?;

        Ok(Box::new(ElfBinary::from_elf(&elf, data)))
    }

    fn format(&self) -> BinaryFormat {
        BinaryFormat::Elf
    }
}

/// ELF binary information (owned)
pub struct ElfBinary {
    architecture: &'static str,
    unsupported_disassembly_reason: Option<&'static str>,
    entry_point: u64,
    sections: Vec<SectionInfo>,
    imports: Vec<ImportInfo>,
    exports: Vec<ExportInfo>,
}

impl ElfBinary {
    fn from_elf(elf: &Elf<'_>, data: &[u8]) -> Self {
        let architecture = match elf.header.e_machine {
            goblin::elf::header::EM_X86_64 => "x64",
            goblin::elf::header::EM_386 => "x86",
            goblin::elf::header::EM_AARCH64 => "ARM64",
            goblin::elf::header::EM_ARM => "ARM",
            _ => "Unknown",
        };

        let entry_point = elf.header.e_entry;
        let unsupported_disassembly_reason = if matches!(architecture, "ARM" | "ARM64")
            && !elf.little_endian
        {
            Some("Big-endian ARM instruction mode is unsupported by the configured decoder")
        } else if architecture == "ARM"
            && (entry_point & 1 != 0
                || elf.syms.iter().any(|symbol| {
                    (symbol.st_type() == goblin::elf::sym::STT_FUNC && symbol.st_value & 1 != 0)
                        || elf
                            .strtab
                            .get_at(symbol.st_name)
                            .is_some_and(|name| name == "$t" || name.starts_with("$t."))
                })
                || elf.dynsyms.iter().any(|symbol| {
                    symbol.st_type() == goblin::elf::sym::STT_FUNC && symbol.st_value & 1 != 0
                }))
        {
            Some("Thumb or mixed ARM/Thumb instruction mode is unsupported by the configured A32 decoder")
        } else {
            None
        };

        // sh_flags is u64 in goblin's unified ELF view; constants are u32.
        let shf_alloc = u64::from(SHF_ALLOC);
        let shf_exec = u64::from(SHF_EXECINSTR);
        let shf_write = u64::from(SHF_WRITE);

        let sections = elf
            .section_headers
            .iter()
            .map(|section| {
                let name = elf
                    .shdr_strtab
                    .get_at(section.sh_name)
                    .unwrap_or("<invalid>")
                    .to_string();
                let virtual_address = section.sh_addr;
                let size = section.sh_size;
                let raw_data =
                    if !matches!(section.sh_type, SHT_NOBITS | SHT_NULL) && section.sh_size > 0 {
                        let start = section.sh_offset as usize;
                        let end = start.saturating_add(size as usize);
                        data.get(start..end).unwrap_or(&[]).to_vec()
                    } else {
                        vec![]
                    };

                let characteristics = SectionCharacteristics {
                    is_code: section.sh_flags & shf_exec != 0,
                    is_data: section.sh_flags & shf_alloc != 0 && section.sh_flags & shf_exec == 0,
                    is_readable: true,
                    is_writable: section.sh_flags & shf_write != 0,
                    is_executable: section.sh_flags & shf_exec != 0,
                };

                SectionInfo {
                    name,
                    virtual_address,
                    size,
                    raw_data,
                    characteristics,
                }
            })
            .collect();

        let imports = elf
            .libraries
            .iter()
            .map(|lib| ImportInfo {
                name: lib.to_string(),
                functions: vec![],
            })
            .collect();

        // Stripping .symtab must not erase definitions retained in .dynsym.
        // A defined symbol can legitimately have zero size (e.g. _init).
        let mut seen = BTreeSet::new();
        let mut exports = Vec::new();
        for (symbols, names) in [(&elf.syms, &elf.strtab), (&elf.dynsyms, &elf.dynstrtab)] {
            for symbol in symbols.iter() {
                if !matches!(
                    symbol.st_bind(),
                    goblin::elf::sym::STB_GLOBAL | goblin::elf::sym::STB_WEAK
                ) || symbol.st_shndx == goblin::elf::section_header::SHN_UNDEF as usize
                {
                    continue;
                }
                let Some(name) = names.get_at(symbol.st_name).filter(|name| !name.is_empty())
                else {
                    continue;
                };
                if seen.insert((symbol.st_value, name.to_string())) {
                    exports.push(ExportInfo {
                        name: name.to_string(),
                        address: symbol.st_value,
                        ordinal: None,
                    });
                }
            }
        }

        Self {
            architecture,
            unsupported_disassembly_reason,
            entry_point,
            sections,
            imports,
            exports,
        }
    }
}

impl BinaryInfo for ElfBinary {
    fn format(&self) -> BinaryFormat {
        BinaryFormat::Elf
    }

    fn architecture(&self) -> &'static str {
        self.architecture
    }

    fn unsupported_disassembly_reason(&self) -> Option<&'static str> {
        self.unsupported_disassembly_reason
    }

    fn entry_point(&self) -> u64 {
        self.entry_point
    }

    fn sections(&self) -> Vec<SectionInfo> {
        self.sections.clone()
    }

    fn imports(&self) -> Vec<ImportInfo> {
        self.imports.clone()
    }

    fn exports(&self) -> Vec<ExportInfo> {
        self.exports.clone()
    }
}
