//! Mach-O format parser

use crate::binary::parser::{
    BinaryInfo, ExportInfo, ImportInfo, SectionCharacteristics, SectionInfo,
};
use crate::binary::{BinaryFormat, BinaryParser};
use crate::utils::error::{Error, Result};
use goblin::mach::constants::{S_ATTR_PURE_INSTRUCTIONS, S_ATTR_SOME_INSTRUCTIONS};
use goblin::mach::Mach;

/// Mach-O parser
#[derive(Default)]
pub struct MachOParser;

impl BinaryParser for MachOParser {
    fn parse(&self, data: &[u8]) -> Result<Box<dyn BinaryInfo>> {
        let mach = Mach::parse(data)
            .map_err(|e| Error::BinaryParse(format!("Failed to parse Mach-O: {}", e)))?;

        Ok(Box::new(MachOBinary::from_mach(&mach)))
    }

    fn format(&self) -> BinaryFormat {
        BinaryFormat::MachO
    }
}

/// Mach-O binary information (owned)
pub struct MachOBinary {
    architecture: &'static str,
    unsupported_disassembly_reason: Option<&'static str>,
    entry_point: u64,
    sections: Vec<SectionInfo>,
    imports: Vec<ImportInfo>,
    exports: Vec<ExportInfo>,
}

impl MachOBinary {
    fn from_mach(mach: &Mach<'_>) -> Self {
        let macho = match mach {
            Mach::Binary(m) => m,
            Mach::Fat(_) => {
                return Self {
                    architecture: "Fat (Multi-arch)",
                    unsupported_disassembly_reason: None,
                    entry_point: 0,
                    sections: vec![],
                    imports: vec![],
                    exports: vec![],
                };
            }
        };

        let architecture = match macho.header.cputype {
            goblin::mach::constants::cputype::CPU_TYPE_X86_64 => "x64",
            goblin::mach::constants::cputype::CPU_TYPE_X86 => "x86",
            goblin::mach::constants::cputype::CPU_TYPE_ARM64 => "ARM64",
            goblin::mach::constants::cputype::CPU_TYPE_ARM => "ARM",
            _ => "Unknown",
        };

        let entry_point = macho.entry;
        let unsupported_disassembly_reason = if matches!(architecture, "ARM" | "ARM64")
            && !macho.little_endian
        {
            Some("Big-endian ARM Mach-O instruction mode is unsupported by the configured decoder")
        } else if architecture == "ARM" {
            Some("32-bit ARM Mach-O instruction mode is unresolved: ARM/Thumb mode selection is unsupported")
        } else {
            None
        };

        let mut sections: Vec<SectionInfo> = Vec::new();
        for segment in macho.segments.iter() {
            let Ok(section_list) = segment.sections() else {
                continue;
            };
            for (section, section_data) in section_list {
                let is_pure_code = section.flags & S_ATTR_PURE_INSTRUCTIONS != 0;
                let has_some_code = section.flags & S_ATTR_SOME_INSTRUCTIONS != 0;
                let is_code = is_pure_code || has_some_code;

                let characteristics = SectionCharacteristics {
                    is_code,
                    is_data: !is_code,
                    is_readable: true,
                    is_writable: false,
                    is_executable: is_code,
                };

                let name = section.name().unwrap_or("<invalid>").to_string();

                sections.push(SectionInfo {
                    name,
                    virtual_address: section.addr,
                    size: section.size,
                    raw_data: section_data.to_vec(),
                    characteristics,
                });
            }
        }

        let imports = match macho.imports() {
            Ok(imps) => {
                let mut dylib_map: std::collections::BTreeMap<String, Vec<String>> =
                    std::collections::BTreeMap::new();
                for imp in imps {
                    dylib_map
                        .entry(imp.dylib.to_string())
                        .or_default()
                        .push(imp.name.to_string());
                }
                dylib_map
                    .into_iter()
                    .map(|(name, functions)| ImportInfo { name, functions })
                    .collect()
            }
            Err(_) => vec![],
        };

        // dyld's regular export values are relative to the image's mapped
        // header segment. __PAGEZERO is not file backed and is not the base.
        let image_base = macho
            .segments
            .iter()
            .find(|segment| segment.fileoff == 0 && segment.filesize > 0)
            .map(|segment| segment.vmaddr)
            .unwrap_or(0);
        let exports = match macho.exports() {
            Ok(exps) => exps
                .into_iter()
                .map(|export| {
                    use goblin::mach::exports::{
                        ExportInfo as MachExportInfo, EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE,
                        EXPORT_SYMBOL_FLAGS_KIND_MASK,
                    };
                    let address = match export.info {
                        MachExportInfo::Regular { address, flags }
                            if flags & EXPORT_SYMBOL_FLAGS_KIND_MASK
                                == EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE =>
                        {
                            address
                        }
                        MachExportInfo::Regular { address, .. } => {
                            image_base.checked_add(address).unwrap_or(0)
                        }
                        MachExportInfo::Stub { stub_offset, .. } => {
                            image_base.checked_add(u64::from(stub_offset)).unwrap_or(0)
                        }
                        MachExportInfo::Reexport { .. } => 0,
                    };
                    ExportInfo {
                        name: export.name,
                        address,
                        ordinal: None,
                    }
                })
                .collect(),
            Err(_) => vec![],
        };

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

impl BinaryInfo for MachOBinary {
    fn format(&self) -> BinaryFormat {
        BinaryFormat::MachO
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
