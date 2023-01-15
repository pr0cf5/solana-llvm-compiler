//! This module relocates a BPF ELF

// Note: Typically ELF shared objects are loaded using the program headers and
// not the section headers.  Since we are leveraging the elfkit crate its much
// easier to use the section headers.  There are cases (reduced size, obfuscation)
// where the section headers may be removed from the ELF.  If that happens then
// this loader will need to be re-written to use the program headers instead.

use crate::{
    aligned_memory::{is_memory_aligned, AlignedMemory},
    ebpf::{self, EF_SBF_V2, HOST_ALIGN, INSN_SIZE},
    elf_parser::{
        consts::{
            ELFCLASS64, ELFDATA2LSB, ELFOSABI_NONE, EM_BPF, EM_SBF, ET_DYN, R_X86_64_32,
            R_X86_64_64, R_X86_64_NONE, R_X86_64_RELATIVE,
        },
        types::Elf64Word,
    },
    elf_parser_glue::{
        ElfParser, ElfProgramHeader, ElfRelocation, ElfSectionHeader, ElfSymbol, GoblinParser,
        NewParser,
    },
    memory_region::MemoryRegion,
    vm::{BuiltInProgram, Config, ContextObject, FunctionRegistry},
};

#[cfg(all(feature = "jit", not(target_os = "windows"), target_arch = "x86_64"))]
use crate::jit::{JitCompiler, JitProgram};
use byteorder::{ByteOrder, LittleEndian};
use std::{
    collections::{btree_map::Entry, BTreeMap},
    fmt::Debug,
    mem,
    ops::Range,
    str,
    sync::Arc,
};

/// Error definitions
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ElfError {
    /// Failed to parse ELF file
    #[error("Failed to parse ELF file: {0}")]
    FailedToParse(String),
    /// Entrypoint out of bounds
    #[error("Entrypoint out of bounds")]
    EntrypointOutOfBounds,
    /// Invaid entrypoint
    #[error("Invaid entrypoint")]
    InvalidEntrypoint,
    /// Failed to get section
    #[error("Failed to get section {0}")]
    FailedToGetSection(String),
    /// Unresolved symbol
    #[error("Unresolved symbol ({0}) at instruction #{1:?} (ELF file offset {2:#x})")]
    UnresolvedSymbol(String, usize, usize),
    /// Section not found
    #[error("Section not found: {0}")]
    SectionNotFound(String),
    /// Relative jump out of bounds
    #[error("Relative jump out of bounds at instruction #{0}")]
    RelativeJumpOutOfBounds(usize),
    /// Symbol hash collision
    #[error("Symbol hash collision {0:#x}")]
    SymbolHashCollision(u32),
    /// Incompatible ELF: wrong endianess
    #[error("Incompatible ELF: wrong endianess")]
    WrongEndianess,
    /// Incompatible ELF: wrong ABI
    #[error("Incompatible ELF: wrong ABI")]
    WrongAbi,
    /// Incompatible ELF: wrong mchine
    #[error("Incompatible ELF: wrong machine")]
    WrongMachine,
    /// Incompatible ELF: wrong class
    #[error("Incompatible ELF: wrong class")]
    WrongClass,
    /// Not one text section
    #[error("Multiple or no text sections, consider removing llc option: -function-sections")]
    NotOneTextSection,
    /// Read-write data not supported
    #[error("Found .bss section in ELF, read-write data not supported")]
    BssNotSupported,
    /// Read-write data not supported
    #[error("Found writable section ({0}) in ELF, read-write data not supported")]
    WritableSectionNotSupported(String),
    /// Relocation failed, no loadable section contains virtual address
    #[error("Relocation failed, no loadable section contains virtual address {0:#x}")]
    AddressOutsideLoadableSection(u64),
    /// Relocation failed, invalid referenced virtual address
    #[error("Relocation failed, invalid referenced virtual address {0:#x}")]
    InvalidVirtualAddress(u64),
    /// Relocation failed, unknown type
    #[error("Relocation failed, unknown type {0:?}")]
    UnknownRelocation(u32),
    /// Failed to read relocation info
    #[error("Failed to read relocation info")]
    FailedToReadRelocationInfo,
    /// Incompatible ELF: wrong type
    #[error("Incompatible ELF: wrong type")]
    WrongType,
    /// Unknown symbol
    #[error("Unknown symbol with index {0}")]
    UnknownSymbol(usize),
    /// Offset or value is out of bounds
    #[error("Offset or value is out of bounds")]
    ValueOutOfBounds,
    /// Detected capabilities required by the executable which are not enabled
    #[error("Detected capabilities required by the executable which are not enabled")]
    UnsupportedExecutableCapabilities,
    /// Invalid program header
    #[error("Invalid ELF program header")]
    InvalidProgramHeader,
}

/// Generates the hash by which a symbol can be called
pub fn hash_internal_function(pc: usize, name: &str) -> u32 {
    if name == "entrypoint" {
        ebpf::hash_symbol_name(b"entrypoint")
    } else {
        let mut key = [0u8; mem::size_of::<u64>()];
        LittleEndian::write_u64(&mut key, pc as u64);
        ebpf::hash_symbol_name(&key)
    }
}

/// Register a symbol or throw ElfError::SymbolHashCollision
pub fn register_internal_function<
    C: ContextObject,
    T: AsRef<str> + ToString + std::cmp::PartialEq<&'static str>,
>(
    function_registry: &mut FunctionRegistry,
    loader: &BuiltInProgram<C>,
    pc: usize,
    name: T,
) -> Result<u32, ElfError> {
    let config = loader.get_config();
    let key = if config.static_syscalls {
        // With static_syscalls normal function calls and syscalls are differentiated in the ISA.
        // Thus, we don't need to hash them here anymore and collisions are gone as well.
        pc as u32
    } else {
        let hash = hash_internal_function(pc, name.as_ref());
        if config.external_internal_function_hash_collision
            && loader.lookup_function(hash).is_some()
        {
            return Err(ElfError::SymbolHashCollision(hash));
        }
        hash
    };
    match function_registry.entry(key) {
        Entry::Vacant(entry) => {
            entry.insert((
                pc,
                if config.enable_symbol_and_section_labels || name == "entrypoint" {
                    name.to_string()
                } else {
                    String::default()
                },
            ));
        }
        Entry::Occupied(entry) => {
            if entry.get().0 != pc {
                return Err(ElfError::SymbolHashCollision(key));
            }
        }
    }
    Ok(key)
}

// For more information on the BPF instruction set:
// https://github.com/iovisor/bpf-docs/blob/master/eBPF.md

// msb                                                        lsb
// +------------------------+----------------+----+----+--------+
// |immediate               |offset          |src |dst |opcode  |
// +------------------------+----------------+----+----+--------+

// From least significant to most significant bit:
//   8 bit opcode
//   4 bit destination register (dst)
//   4 bit source register (src)
//   16 bit offset
//   32 bit immediate (imm)

/// Byte offset of the immediate field in the instruction
const BYTE_OFFSET_IMMEDIATE: usize = 4;
/// Byte length of the immediate field
const BYTE_LENGTH_IMMEDIATE: usize = 4;

/// BPF relocation types.
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Copy, Clone)]
enum BpfRelocationType {
    /// No relocation, placeholder
    R_Bpf_None = 0,
    /// R_BPF_64_64 relocation type is used for ld_imm64 instruction.
    /// The actual to-be-relocated data (0 or section offset) is
    /// stored at r_offset + 4 and the read/write data bitsize is 32
    /// (4 bytes). The relocation can be resolved with the symbol
    /// value plus implicit addend.
    R_Bpf_64_64 = 1,
    /// 64 bit relocation of a ldxdw instruction.  The ldxdw
    /// instruction occupies two instruction slots. The 64-bit address
    /// to load from is split into the 32-bit imm field of each
    /// slot. The first slot's pre-relocation imm field contains the
    /// virtual address (typically same as the file offset) of the
    /// location to load. Relocation involves calculating the
    /// post-load 64-bit physical address referenced by the imm field
    /// and writing that physical address back into the imm fields of
    /// the ldxdw instruction.
    R_Bpf_64_Relative = 8,
    /// Relocation of a call instruction.  The existing imm field
    /// contains either an offset of the instruction to jump to (think
    /// local function call) or a special value of "-1".  If -1 the
    /// symbol must be looked up in the symbol table.  The relocation
    /// entry contains the symbol number to call.  In order to support
    /// both local jumps and calling external symbols a 32-bit hash is
    /// computed and stored in the the call instruction's 32-bit imm
    /// field.  The hash is used later to look up the 64-bit address
    /// to jump to.  In the case of a local jump the hash is
    /// calculated using the current program counter and in the case
    /// of a symbol the hash is calculated using the name of the
    /// symbol.
    R_Bpf_64_32 = 10,
}
impl BpfRelocationType {
    fn from_x86_relocation_type(from: u32) -> Option<BpfRelocationType> {
        match from {
            R_X86_64_NONE => Some(BpfRelocationType::R_Bpf_None),
            R_X86_64_64 => Some(BpfRelocationType::R_Bpf_64_64),
            R_X86_64_RELATIVE => Some(BpfRelocationType::R_Bpf_64_Relative),
            R_X86_64_32 => Some(BpfRelocationType::R_Bpf_64_32),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq)]
struct SectionInfo {
    name: String,
    vaddr: u64,
    offset_range: Range<usize>,
}
impl SectionInfo {
    fn mem_size(&self) -> usize {
        mem::size_of::<Self>().saturating_add(self.name.capacity())
    }
}

#[derive(Debug, PartialEq)]
pub(crate) enum Section {
    /// Owned section data.
    ///
    /// The first field is the offset of the section from MM_PROGRAM_START. The
    /// second field is the actual section data.
    Owned(usize, Vec<u8>),
    /// Borrowed section data.
    ///
    /// The first field is the offset of the section from MM_PROGRAM_START. The
    /// second field an be used to index the input ELF buffer to retrieve the
    /// section data.
    Borrowed(usize, Range<usize>),
}

/// Elf loader/relocator
#[derive(Debug, PartialEq)]
pub struct Executable<C: ContextObject> {
    /// Loaded and executable elf
    elf_bytes: AlignedMemory<{ HOST_ALIGN }>,
    /// Read-only section
    ro_section: Section,
    /// Text section info
    text_section_info: SectionInfo,
    /// Address of the entry point
    entry_pc: usize,
    /// Call resolution map (hash, pc, name)
    function_registry: FunctionRegistry,
    /// Loader built-in program
    loader: Arc<BuiltInProgram<C>>,
    /// Compiled program and argument
    #[cfg(all(feature = "jit", not(target_os = "windows"), target_arch = "x86_64"))]
    compiled_program: Option<JitProgram>,
}

impl<C: ContextObject> Executable<C> {
    /// Get the configuration settings
    pub fn get_config(&self) -> &Config {
        self.loader.get_config()
    }

    /// Get the .text section virtual address and bytes
    pub fn get_text_bytes(&self) -> (u64, &[u8]) {
        let (ro_offset, ro_section) = match &self.ro_section {
            Section::Owned(offset, data) => (*offset, data.as_slice()),
            Section::Borrowed(offset, byte_range) => {
                (*offset, &self.elf_bytes.as_slice()[byte_range.clone()])
            }
        };

        let offset = self
            .text_section_info
            .vaddr
            .saturating_sub(ebpf::MM_PROGRAM_START)
            .saturating_sub(ro_offset as u64) as usize;
        (
            self.text_section_info.vaddr,
            &ro_section[offset..offset.saturating_add(self.text_section_info.offset_range.len())],
        )
    }

    /// Get the concatenated read-only sections (including the text section)
    pub fn get_ro_section(&self) -> &[u8] {
        match &self.ro_section {
            Section::Owned(_offset, data) => data.as_slice(),
            Section::Borrowed(_offset, byte_range) => {
                &self.elf_bytes.as_slice()[byte_range.clone()]
            }
        }
    }

    /// Get a memory region that can be used to access the merged readonly section
    pub fn get_ro_region(&self) -> MemoryRegion {
        get_ro_region(&self.ro_section, self.elf_bytes.as_slice())
    }

    /// Get the entry point offset into the text section
    pub fn get_entrypoint_instruction_offset(&self) -> usize {
        self.entry_pc
    }

    /// Get the text section offset
    #[cfg(feature = "debugger")]
    pub fn get_text_section_offset(&self) -> u64 {
        self.text_section_info.offset_range.start as u64
    }

    /// Get a symbol's instruction offset
    pub fn lookup_internal_function(&self, hash: u32) -> Option<usize> {
        self.function_registry.get(&hash).map(|(pc, _name)| *pc)
    }

    /// Get the loader built-in program
    pub fn get_loader(&self) -> &BuiltInProgram<C> {
        &self.loader
    }

    /// Get the JIT compiled program
    #[cfg(all(feature = "jit", not(target_os = "windows"), target_arch = "x86_64"))]
    pub fn get_compiled_program(&self) -> Option<&JitProgram> {
        self.compiled_program.as_ref()
    }

    /// JIT compile the executable
    #[cfg(all(feature = "jit", not(target_os = "windows"), target_arch = "x86_64"))]
    pub fn jit_compile(executable: &mut Self) -> Result<(), crate::error::EbpfError> {
        let jit = JitCompiler::<C>::new(executable)?;
        executable.compiled_program = Some(jit.compile()?);
        Ok(())
    }

    /// Get normal functions (if debug symbols are not stripped)
    pub fn get_function_registry(&self) -> &FunctionRegistry {
        &self.function_registry
    }

    /// Create from raw text section bytes (list of instructions)
    pub fn new_from_text_bytes(
        text_bytes: &[u8],
        loader: Arc<BuiltInProgram<C>>,
        mut function_registry: FunctionRegistry,
    ) -> Result<Self, ElfError> {
        let elf_bytes = AlignedMemory::from_slice(text_bytes);
        let config = loader.get_config();
        let enable_symbol_and_section_labels = config.enable_symbol_and_section_labels;
        let entry_pc = if let Some((pc, _name)) = function_registry
            .values()
            .find(|(_pc, name)| name == "entrypoint")
        {
            *pc
        } else {
            register_internal_function(&mut function_registry, &loader, 0, "entrypoint")?;
            0
        };
        Ok(Self {
            elf_bytes,
            ro_section: Section::Borrowed(0, 0..text_bytes.len()),
            text_section_info: SectionInfo {
                name: if enable_symbol_and_section_labels {
                    ".text".to_string()
                } else {
                    String::default()
                },
                vaddr: ebpf::MM_PROGRAM_START,
                offset_range: 0..text_bytes.len(),
            },
            entry_pc,
            function_registry,
            loader,
            #[cfg(all(feature = "jit", not(target_os = "windows"), target_arch = "x86_64"))]
            compiled_program: None,
        })
    }

    /// Fully loads an ELF, including validation and relocation
    pub fn load(bytes: &[u8], loader: Arc<BuiltInProgram<C>>) -> Result<Self, ElfError> {
        if loader.get_config().new_elf_parser {
            // The new parser creates references from the input byte slice, so
            // it must be properly aligned. We assume that HOST_ALIGN is a
            // multiple of the ELF "natural" alignment. See test_load_unaligned.
            let aligned;
            let bytes = if is_memory_aligned(bytes.as_ptr() as usize, HOST_ALIGN) {
                bytes
            } else {
                aligned = AlignedMemory::<{ HOST_ALIGN }>::from_slice(bytes);
                aligned.as_slice()
            };
            Self::load_with_parser(&NewParser::parse(bytes)?, bytes, loader)
        } else {
            Self::load_with_parser(&GoblinParser::parse(bytes)?, bytes, loader)
        }
    }

    fn load_with_parser<'a, P: ElfParser<'a>>(
        elf: &'a P,
        bytes: &[u8],
        loader: Arc<BuiltInProgram<C>>,
    ) -> Result<Self, ElfError> {
        let mut elf_bytes = AlignedMemory::from_slice(bytes);
        let config = loader.get_config();

        Self::validate(config, elf, elf_bytes.as_slice())?;

        // calculate the text section info
        let text_section = elf.section(".text")?;
        let text_section_info = SectionInfo {
            name: if config.enable_symbol_and_section_labels {
                elf.section_name(text_section.sh_name())
                    .unwrap_or(".text")
                    .to_string()
            } else {
                String::default()
            },
            vaddr: if config.enable_elf_vaddr && text_section.sh_addr() >= ebpf::MM_PROGRAM_START {
                text_section.sh_addr()
            } else {
                text_section
                    .sh_addr()
                    .saturating_add(ebpf::MM_PROGRAM_START)
            },
            offset_range: text_section.file_range().unwrap_or_default(),
        };
        let vaddr_end = if config.reject_rodata_stack_overlap {
            text_section_info
                .vaddr
                .saturating_add(text_section.sh_size())
        } else {
            text_section_info.vaddr
        };
        if (config.reject_broken_elfs
            && !config.enable_elf_vaddr
            && text_section.sh_addr() != text_section.sh_offset())
            || vaddr_end > ebpf::MM_STACK_START
        {
            return Err(ElfError::ValueOutOfBounds);
        }

        // relocate symbols
        let mut function_registry = FunctionRegistry::default();
        Self::relocate(
            &mut function_registry,
            &loader,
            elf,
            elf_bytes.as_slice_mut(),
        )?;

        // calculate entrypoint offset into the text section
        let offset = elf.header().e_entry.saturating_sub(text_section.sh_addr());
        if offset.checked_rem(ebpf::INSN_SIZE as u64) != Some(0) {
            return Err(ElfError::InvalidEntrypoint);
        }
        let entry_pc = if let Some(entry_pc) = (offset as usize).checked_div(ebpf::INSN_SIZE) {
            if !config.static_syscalls {
                function_registry.remove(&ebpf::hash_symbol_name(b"entrypoint"));
            }
            register_internal_function(&mut function_registry, &loader, entry_pc, "entrypoint")?;
            entry_pc
        } else {
            return Err(ElfError::InvalidEntrypoint);
        };

        let ro_section = Self::parse_ro_sections(
            config,
            elf.section_headers()
                .map(|s| (elf.section_name(s.sh_name()), s)),
            elf_bytes.as_slice(),
        )?;

        Ok(Self {
            elf_bytes,
            ro_section,
            text_section_info,
            entry_pc,
            function_registry,
            loader,
            #[cfg(all(feature = "jit", not(target_os = "windows"), target_arch = "x86_64"))]
            compiled_program: None,
        })
    }

    /// Calculate the total memory size of the executable
    #[rustfmt::skip]
    pub fn mem_size(&self) -> usize {
        let mut total = mem::size_of::<Self>();
        total = total
            // elf bytes
            .saturating_add(self.elf_bytes.mem_size())
            // ro section
            .saturating_add(match &self.ro_section {
                Section::Owned(_, data) => data.capacity(),
                Section::Borrowed(_, _) => 0,
            })
            // text section info
            .saturating_add(self.text_section_info.mem_size())
            // bpf functions
            .saturating_add(mem::size_of_val(&self.function_registry))
            .saturating_add(self.function_registry
            .iter()
            .fold(0, |state: usize, (_, (val, name))| state
                .saturating_add(mem::size_of_val(&val)
                .saturating_add(mem::size_of_val(&name)
                .saturating_add(name.capacity())))))
            // loader built-in program
            .saturating_add(self.loader.mem_size());

        #[cfg(all(feature = "jit", not(target_os = "windows"), target_arch = "x86_64"))]
        {
            // compiled programs
            total = total.saturating_add(self.compiled_program.as_ref().map_or(0, |program| program.mem_size()));
        }

        total
    }

    // Functions exposed for tests

    /// Fix-ups relative calls
    pub fn fixup_relative_calls(
        function_registry: &mut FunctionRegistry,
        loader: &BuiltInProgram<C>,
        elf_bytes: &mut [u8],
    ) -> Result<(), ElfError> {
        let config = loader.get_config();
        let instruction_count = elf_bytes
            .len()
            .checked_div(ebpf::INSN_SIZE)
            .ok_or(ElfError::ValueOutOfBounds)?;
        for i in 0..instruction_count {
            let mut insn = ebpf::get_insn(elf_bytes, i);
            if insn.opc == ebpf::CALL_IMM
                && insn.imm != -1
                && !(config.static_syscalls && insn.src == 0)
            {
                let target_pc = (i as isize)
                    .saturating_add(1)
                    .saturating_add(insn.imm as isize);
                if target_pc < 0 || target_pc >= instruction_count as isize {
                    return Err(ElfError::RelativeJumpOutOfBounds(
                        i.saturating_add(ebpf::ELF_INSN_DUMP_OFFSET),
                    ));
                }
                let name = if config.enable_symbol_and_section_labels {
                    format!("function_{}", target_pc)
                } else {
                    String::default()
                };

                let key = register_internal_function(
                    function_registry,
                    loader,
                    target_pc as usize,
                    name,
                )?;
                insn.imm = key as i64;
                let offset = i.saturating_mul(ebpf::INSN_SIZE);
                let checked_slice = elf_bytes
                    .get_mut(offset..offset.saturating_add(ebpf::INSN_SIZE))
                    .ok_or(ElfError::ValueOutOfBounds)?;
                checked_slice.copy_from_slice(&insn.to_array());
            }
        }
        Ok(())
    }

    /// Validates the ELF
    pub fn validate<'a, P: ElfParser<'a>>(
        config: &Config,
        elf: &'a P,
        elf_bytes: &[u8],
    ) -> Result<(), ElfError> {
        let header = elf.header();
        if header.e_ident.ei_class != ELFCLASS64 {
            return Err(ElfError::WrongClass);
        }
        if header.e_ident.ei_data != ELFDATA2LSB {
            return Err(ElfError::WrongEndianess);
        }
        if header.e_ident.ei_osabi != ELFOSABI_NONE {
            return Err(ElfError::WrongAbi);
        }
        if header.e_machine != EM_BPF && header.e_machine != EM_SBF {
            return Err(ElfError::WrongMachine);
        }
        if header.e_type != ET_DYN {
            return Err(ElfError::WrongType);
        }

        if header.e_flags == EF_SBF_V2 {
            if !config.dynamic_stack_frames {
                return Err(ElfError::UnsupportedExecutableCapabilities);
            }
        } else if config.dynamic_stack_frames
            && config.enable_elf_vaddr
            && config.reject_rodata_stack_overlap
            && config.static_syscalls
        {
            return Err(ElfError::UnsupportedExecutableCapabilities);
        }

        if config.enable_elf_vaddr {
            // This is needed to avoid an overflow error in header.vm_range() as
            // used by relocate(). See https://github.com/m4b/goblin/pull/306.
            //
            // Once we bump to a version of goblin that includes the fix, this
            // check can be removed, and relocate() will still return
            // ValueOutOfBounds on malformed program headers.
            if elf
                .program_headers()
                .any(|header| header.p_vaddr().checked_add(header.p_memsz()).is_none())
            {
                return Err(ElfError::InvalidProgramHeader);
            }
        }

        let num_text_sections = elf
            .section_headers()
            .fold(0, |count: usize, section_header| {
                if let Some(this_name) = elf.section_name(section_header.sh_name()) {
                    if this_name == ".text" {
                        return count.saturating_add(1);
                    }
                }
                count
            });
        if 1 != num_text_sections {
            return Err(ElfError::NotOneTextSection);
        }

        for section_header in elf.section_headers() {
            if let Some(name) = elf.section_name(section_header.sh_name()) {
                if name.starts_with(".bss")
                    || (section_header.is_writable()
                        && (name.starts_with(".data") && !name.starts_with(".data.rel")))
                {
                    return Err(ElfError::WritableSectionNotSupported(name.to_owned()));
                } else if name == ".bss" {
                    return Err(ElfError::BssNotSupported);
                }
            }
        }

        for section_header in elf.section_headers() {
            let start = section_header.sh_offset() as usize;
            let end = section_header
                .sh_offset()
                .checked_add(section_header.sh_size())
                .ok_or(ElfError::ValueOutOfBounds)? as usize;
            let _ = elf_bytes
                .get(start..end)
                .ok_or(ElfError::ValueOutOfBounds)?;
        }
        let text_section = elf.section(".text")?;
        if !text_section.vm_range().contains(&header.e_entry) {
            return Err(ElfError::EntrypointOutOfBounds);
        }

        Ok(())
    }

    pub(crate) fn parse_ro_sections<
        'a,
        T: ElfSectionHeader + 'a,
        S: IntoIterator<Item = (Option<&'a str>, &'a T)>,
    >(
        config: &Config,
        sections: S,
        elf_bytes: &[u8],
    ) -> Result<Section, ElfError> {
        // the lowest section address
        let mut lowest_addr = usize::MAX;
        // the highest section address
        let mut highest_addr = 0;
        // the aggregated section length, not including gaps between sections
        let mut ro_fill_length = 0usize;
        let mut invalid_offsets = false;
        // when config.enable_elf_vaddr=true, we allow section_addr != sh_offset
        // if section_addr - sh_offset is constant across all sections. That is,
        // we allow sections to be translated by a fixed virtual offset.
        let mut addr_file_offset = None;

        // keep track of where ro sections are so we can tell whether they're
        // contiguous
        let mut first_ro_section = 0;
        let mut last_ro_section = 0;
        let mut n_ro_sections = 0usize;

        let mut ro_slices = vec![];
        for (i, (name, section_header)) in sections.into_iter().enumerate() {
            match name {
                Some(name)
                    if name == ".text"
                        || name == ".rodata"
                        || name == ".data.rel.ro"
                        || name == ".eh_frame" => {}
                _ => continue,
            }

            if n_ro_sections == 0 {
                first_ro_section = i;
            }
            last_ro_section = i;
            n_ro_sections = n_ro_sections.saturating_add(1);

            let section_addr = section_header.sh_addr();

            // sh_offset handling:
            //
            // If config.enable_elf_vaddr=true, we allow section_addr >
            // sh_offset, if section_addr - sh_offset is constant across all
            // sections. That is, we allow the linker to align rodata to a
            // positive base address (MM_PROGRAM_START) as long as the mapping
            // to sh_offset(s) stays linear.
            //
            // If config.enable_elf_vaddr=false, section_addr must match
            // sh_offset for backwards compatibility
            if !invalid_offsets {
                if config.enable_elf_vaddr {
                    if section_addr < section_header.sh_offset() {
                        invalid_offsets = true;
                    } else {
                        let offset = section_addr.saturating_sub(section_header.sh_offset());
                        if *addr_file_offset.get_or_insert(offset) != offset {
                            // The sections are not all translated by the same
                            // constant. We won't be able to borrow, but unless
                            // config.reject_broken_elf=true, we're still going
                            // to accept this file for backwards compatibility.
                            invalid_offsets = true;
                        }
                    }
                } else if section_addr != section_header.sh_offset() {
                    invalid_offsets = true;
                }
            }

            let mut vaddr_end = if config.enable_elf_vaddr && section_addr >= ebpf::MM_PROGRAM_START
            {
                section_addr
            } else {
                section_addr.saturating_add(ebpf::MM_PROGRAM_START)
            };
            if config.reject_rodata_stack_overlap {
                vaddr_end = vaddr_end.saturating_add(section_header.sh_size());
            }
            if (config.reject_broken_elfs && invalid_offsets) || vaddr_end > ebpf::MM_STACK_START {
                return Err(ElfError::ValueOutOfBounds);
            }

            let section_data = elf_bytes
                .get(section_header.file_range().unwrap_or_default())
                .ok_or(ElfError::ValueOutOfBounds)?;

            let section_addr = section_addr as usize;
            lowest_addr = lowest_addr.min(section_addr);
            highest_addr = highest_addr.max(section_addr.saturating_add(section_data.len()));
            ro_fill_length = ro_fill_length.saturating_add(section_data.len());

            ro_slices.push((section_addr, section_data));
        }

        if config.reject_broken_elfs && lowest_addr.saturating_add(ro_fill_length) > highest_addr {
            return Err(ElfError::ValueOutOfBounds);
        }

        let can_borrow = !invalid_offsets
            && last_ro_section
                .saturating_add(1)
                .saturating_sub(first_ro_section)
                == n_ro_sections;
        let ro_section = if config.optimize_rodata && can_borrow {
            // Read only sections are grouped together with no intermixed non-ro
            // sections. We can borrow.

            // When config.enable_elf_vaddr=true, section addresses and their
            // corresponding buffer offsets can be translated by a constant
            // amount. Subtract the constant to get buffer positions.
            let buf_offset_start =
                lowest_addr.saturating_sub(addr_file_offset.unwrap_or(0) as usize);
            let buf_offset_end =
                highest_addr.saturating_sub(addr_file_offset.unwrap_or(0) as usize);

            let addr_offset = if lowest_addr >= ebpf::MM_PROGRAM_START as usize {
                // The first field of Section::Borrowed is an offset from
                // ebpf::MM_PROGRAM_START so if the linker has already put the
                // sections within ebpf::MM_PROGRAM_START, we need to subtract
                // it now.
                lowest_addr.saturating_sub(ebpf::MM_PROGRAM_START as usize)
            } else {
                lowest_addr
            };

            Section::Borrowed(addr_offset, buf_offset_start..buf_offset_end)
        } else {
            // Read only and other non-ro sections are mixed. Zero the non-ro
            // sections and and copy the ro ones at their intended offsets.

            if config.optimize_rodata {
                // The rodata region starts at MM_PROGRAM_START + offset,
                // [MM_PROGRAM_START, MM_PROGRAM_START + offset) is not
                // mappable. We only need to allocate highest_addr - lowest_addr
                // bytes.
                highest_addr = highest_addr.saturating_sub(lowest_addr);
            } else {
                // For backwards compatibility, the whole [MM_PROGRAM_START,
                // MM_PROGRAM_START + highest_addr) range is mappable. We need
                // to allocate the whole address range.
                lowest_addr = 0;
            };

            let buf_len = highest_addr;
            if buf_len > elf_bytes.len() {
                return Err(ElfError::ValueOutOfBounds);
            }

            let mut ro_section = vec![0; buf_len];
            for (section_addr, slice) in ro_slices.iter() {
                let buf_offset_start = section_addr.saturating_sub(lowest_addr);
                ro_section[buf_offset_start..buf_offset_start.saturating_add(slice.len())]
                    .copy_from_slice(slice);
            }

            let addr_offset = if lowest_addr >= ebpf::MM_PROGRAM_START as usize {
                lowest_addr.saturating_sub(ebpf::MM_PROGRAM_START as usize)
            } else {
                lowest_addr
            };
            Section::Owned(addr_offset, ro_section)
        };

        Ok(ro_section)
    }

    /// Relocates the ELF in-place
    fn relocate<'a, P: ElfParser<'a>>(
        function_registry: &mut FunctionRegistry,
        loader: &BuiltInProgram<C>,
        elf: &'a P,
        elf_bytes: &mut [u8],
    ) -> Result<(), ElfError> {
        let mut syscall_cache = BTreeMap::new();
        let text_section = elf.section(".text")?;

        // Fixup all program counter relative call instructions
        Self::fixup_relative_calls(
            function_registry,
            loader,
            elf_bytes
                .get_mut(text_section.file_range().unwrap_or_default())
                .ok_or(ElfError::ValueOutOfBounds)?,
        )?;

        let config = loader.get_config();
        let mut program_header: Option<&<P as ElfParser<'a>>::ProgramHeader> = None;

        // Fixup all the relocations in the relocation section if exists
        for relocation in elf.dynamic_relocations() {
            let mut r_offset = relocation.r_offset() as usize;

            // When config.enable_elf_vaddr=true, we allow section.sh_addr !=
            // section.sh_offset so we need to bring r_offset to the correct
            // byte offset.
            if config.enable_elf_vaddr {
                match program_header {
                    Some(header) if header.vm_range().contains(&(r_offset as u64)) => {}
                    _ => {
                        program_header = elf
                            .program_headers()
                            .find(|header| header.vm_range().contains(&(r_offset as u64)))
                    }
                }
                let header = program_header.as_ref().ok_or(ElfError::ValueOutOfBounds)?;
                r_offset = r_offset
                    .saturating_sub(header.p_vaddr() as usize)
                    .saturating_add(header.p_offset() as usize);
            }

            // Offset of the immediate field
            let imm_offset = r_offset.saturating_add(BYTE_OFFSET_IMMEDIATE);

            match BpfRelocationType::from_x86_relocation_type(relocation.r_type()) {
                Some(BpfRelocationType::R_Bpf_64_64) => {
                    let imm_low_offset = imm_offset;
                    let imm_high_offset = imm_low_offset.saturating_add(INSN_SIZE);

                    // Read the instruction's immediate field which contains virtual
                    // address to convert to physical
                    let checked_slice = elf_bytes
                        .get(imm_offset..imm_offset.saturating_add(BYTE_LENGTH_IMMEDIATE))
                        .ok_or(ElfError::ValueOutOfBounds)?;
                    let refd_addr = LittleEndian::read_u32(checked_slice) as u64;

                    let symbol = elf
                        .dynamic_symbol(relocation.r_sym())
                        .ok_or_else(|| ElfError::UnknownSymbol(relocation.r_sym() as usize))?;

                    // The relocated address is relative to the address of the
                    // symbol at index `r_sym`
                    let mut addr = symbol.st_value().saturating_add(refd_addr);

                    // The "physical address" from the VM's perspective is rooted
                    // at `MM_PROGRAM_START`. If the linker hasn't already put
                    // the symbol within `MM_PROGRAM_START`, we need to do so
                    // now.
                    if addr < ebpf::MM_PROGRAM_START {
                        addr = ebpf::MM_PROGRAM_START.saturating_add(addr);
                    }

                    // Write the low side of the relocate address
                    let imm_slice = elf_bytes
                        .get_mut(imm_offset..imm_offset.saturating_add(BYTE_LENGTH_IMMEDIATE))
                        .ok_or(ElfError::ValueOutOfBounds)?;
                    LittleEndian::write_u32(imm_slice, (addr & 0xFFFFFFFF) as u32);

                    // Write the high side of the relocate address
                    let imm_slice = elf_bytes
                        .get_mut(
                            imm_high_offset..imm_high_offset.saturating_add(BYTE_LENGTH_IMMEDIATE),
                        )
                        .ok_or(ElfError::ValueOutOfBounds)?;
                    LittleEndian::write_u32(
                        imm_slice,
                        addr.checked_shr(32).unwrap_or_default() as u32,
                    );
                }
                Some(BpfRelocationType::R_Bpf_64_Relative) => {
                    // Relocation between different sections, where the target
                    // memory is not associated to a symbol (eg some compiler
                    // generated rodata that doesn't have an explicit symbol).

                    if text_section
                        .file_range()
                        .unwrap_or_default()
                        .contains(&r_offset)
                    {
                        // We're relocating a lddw instruction, which spans two
                        // instruction slots. The address to be relocated is
                        // split in two halves in the two imms of the
                        // instruction slots.
                        let imm_low_offset = imm_offset;
                        let imm_high_offset = r_offset
                            .saturating_add(INSN_SIZE)
                            .saturating_add(BYTE_OFFSET_IMMEDIATE);

                        // Read the low side of the address
                        let imm_slice = elf_bytes
                            .get(
                                imm_low_offset
                                    ..imm_low_offset.saturating_add(BYTE_LENGTH_IMMEDIATE),
                            )
                            .ok_or(ElfError::ValueOutOfBounds)?;
                        let va_low = LittleEndian::read_u32(imm_slice) as u64;

                        // Read the high side of the address
                        let imm_slice = elf_bytes
                            .get(
                                imm_high_offset
                                    ..imm_high_offset.saturating_add(BYTE_LENGTH_IMMEDIATE),
                            )
                            .ok_or(ElfError::ValueOutOfBounds)?;
                        let va_high = LittleEndian::read_u32(imm_slice) as u64;

                        // Put the address back together
                        let mut refd_addr = va_high.checked_shl(32).unwrap_or_default() | va_low;

                        if refd_addr == 0 {
                            return Err(ElfError::InvalidVirtualAddress(refd_addr));
                        }

                        if refd_addr < ebpf::MM_PROGRAM_START {
                            // The linker hasn't already placed rodata within
                            // MM_PROGRAM_START, so we do so now
                            refd_addr = ebpf::MM_PROGRAM_START.saturating_add(refd_addr);
                        }

                        // Write back the low half
                        let imm_slice = elf_bytes
                            .get_mut(
                                imm_low_offset
                                    ..imm_low_offset.saturating_add(BYTE_LENGTH_IMMEDIATE),
                            )
                            .ok_or(ElfError::ValueOutOfBounds)?;
                        LittleEndian::write_u32(imm_slice, (refd_addr & 0xFFFFFFFF) as u32);

                        // Write back the high half
                        let imm_slice = elf_bytes
                            .get_mut(
                                imm_high_offset
                                    ..imm_high_offset.saturating_add(BYTE_LENGTH_IMMEDIATE),
                            )
                            .ok_or(ElfError::ValueOutOfBounds)?;
                        LittleEndian::write_u32(
                            imm_slice,
                            refd_addr.checked_shr(32).unwrap_or_default() as u32,
                        );
                    } else {
                        let refd_addr = if elf.header().e_flags == EF_SBF_V2 {
                            // We're relocating an address inside a data section (eg .rodata). The
                            // address is encoded as a simple u64.

                            let addr_slice = elf_bytes
                                .get(r_offset..r_offset.saturating_add(mem::size_of::<u64>()))
                                .ok_or(ElfError::ValueOutOfBounds)?;
                            let mut refd_addr = LittleEndian::read_u64(addr_slice);
                            if refd_addr < ebpf::MM_PROGRAM_START {
                                // Not within MM_PROGRAM_START, do it now
                                refd_addr = ebpf::MM_PROGRAM_START.saturating_add(refd_addr);
                            }
                            refd_addr
                        } else {
                            // There used to be a bug in toolchains before
                            // https://github.com/solana-labs/llvm-project/pull/35 where for 64 bit
                            // relocations we were encoding only the low 32 bits, shifted 32 bits to
                            // the left. Our relocation code used to be compatible with that, so we
                            // need to keep supporting this case for backwards compatibility.
                            let addr_slice = elf_bytes
                                .get(imm_offset..imm_offset.saturating_add(BYTE_LENGTH_IMMEDIATE))
                                .ok_or(ElfError::ValueOutOfBounds)?;
                            let refd_addr = LittleEndian::read_u32(addr_slice) as u64;
                            ebpf::MM_PROGRAM_START.saturating_add(refd_addr)
                        };

                        let addr_slice = elf_bytes
                            .get_mut(r_offset..r_offset.saturating_add(mem::size_of::<u64>()))
                            .ok_or(ElfError::ValueOutOfBounds)?;
                        LittleEndian::write_u64(addr_slice, refd_addr);
                    }
                }
                Some(BpfRelocationType::R_Bpf_64_32) => {
                    // The .text section has an unresolved call to symbol instruction
                    // Hash the symbol name and stick it into the call instruction's imm
                    // field.  Later that hash will be used to look up the function location.

                    let symbol = elf
                        .dynamic_symbol(relocation.r_sym())
                        .ok_or_else(|| ElfError::UnknownSymbol(relocation.r_sym() as usize))?;

                    let name = elf
                        .dynamic_symbol_name(symbol.st_name() as Elf64Word)
                        .ok_or_else(|| ElfError::UnknownSymbol(symbol.st_name() as usize))?;

                    // If the symbol is defined, this is a bpf-to-bpf call
                    let key = if symbol.is_function() && symbol.st_value() != 0 {
                        if !text_section.vm_range().contains(&symbol.st_value()) {
                            return Err(ElfError::ValueOutOfBounds);
                        }
                        let target_pc = (symbol.st_value().saturating_sub(text_section.sh_addr())
                            as usize)
                            .checked_div(ebpf::INSN_SIZE)
                            .unwrap_or_default();
                        register_internal_function(function_registry, loader, target_pc, name)?
                    } else {
                        // Else it's a syscall
                        let hash = *syscall_cache
                            .entry(symbol.st_name())
                            .or_insert_with(|| ebpf::hash_symbol_name(name.as_bytes()));
                        if config.reject_broken_elfs && loader.lookup_function(hash).is_none() {
                            return Err(ElfError::UnresolvedSymbol(
                                name.to_string(),
                                r_offset
                                    .checked_div(ebpf::INSN_SIZE)
                                    .and_then(|offset| {
                                        offset.checked_add(ebpf::ELF_INSN_DUMP_OFFSET)
                                    })
                                    .unwrap_or(ebpf::ELF_INSN_DUMP_OFFSET),
                                r_offset,
                            ));
                        }
                        hash
                    };

                    let checked_slice = elf_bytes
                        .get_mut(imm_offset..imm_offset.saturating_add(BYTE_LENGTH_IMMEDIATE))
                        .ok_or(ElfError::ValueOutOfBounds)?;
                    LittleEndian::write_u32(checked_slice, key);
                }
                _ => return Err(ElfError::UnknownRelocation(relocation.r_type())),
            }
        }

        if config.enable_symbol_and_section_labels {
            // Register all known function names from the symbol table
            for symbol in elf.symbols() {
                if symbol.st_info() & 0xEF != 0x02 {
                    continue;
                }
                if !text_section.vm_range().contains(&symbol.st_value()) {
                    return Err(ElfError::ValueOutOfBounds);
                }
                let target_pc = (symbol.st_value().saturating_sub(text_section.sh_addr()) as usize)
                    .checked_div(ebpf::INSN_SIZE)
                    .unwrap_or_default();
                let name = elf
                    .symbol_name(symbol.st_name() as Elf64Word)
                    .ok_or_else(|| ElfError::UnknownSymbol(symbol.st_name() as usize))?;
                register_internal_function(function_registry, loader, target_pc, name)?;
            }
        }

        Ok(())
    }

    #[allow(dead_code)]
    fn dump_data(name: &str, prog: &[u8]) {
        let mut eight_bytes: Vec<u8> = Vec::new();
        println!("{}", name);
        for i in prog.iter() {
            if eight_bytes.len() >= 7 {
                println!("{:02X?}", eight_bytes);
                eight_bytes.clear();
            } else {
                eight_bytes.push(*i);
            }
        }
    }
}

pub(crate) fn get_ro_region(ro_section: &Section, elf: &[u8]) -> MemoryRegion {
    let (offset, ro_data) = match ro_section {
        Section::Owned(offset, data) => (*offset, data.as_slice()),
        Section::Borrowed(offset, byte_range) => (*offset, &elf[byte_range.clone()]),
    };

    // If offset > 0, the region will start at MM_PROGRAM_START + the offset of
    // the first read only byte. [MM_PROGRAM_START, MM_PROGRAM_START + offset)
    // will be unmappable, see MemoryRegion::vm_to_host.
    MemoryRegion::new_readonly(
        ro_data,
        ebpf::MM_PROGRAM_START.saturating_add(offset as u64),
    )
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        ebpf,
        elf_parser::{
            // FIXME consts::{ELFCLASS32, ELFDATA2MSB, ET_REL},
            consts::{ELFCLASS32, ELFDATA2MSB, ET_REL},
            types::{Elf64Ehdr, Elf64Shdr},
        },
        error::EbpfError,
        fuzz::fuzz,
        syscalls,
        vm::{ProgramResult, TestContextObject},
    };
    use rand::{distributions::Uniform, Rng};
    use std::{fs::File, io::Read};
    type ElfExecutable = Executable<TestContextObject>;

    fn loader() -> Arc<BuiltInProgram<TestContextObject>> {
        let mut loader = BuiltInProgram::new_loader(Config::default());
        loader
            .register_function_by_name("log", syscalls::bpf_syscall_string)
            .unwrap();
        loader
            .register_function_by_name("log_64", syscalls::bpf_syscall_u64)
            .unwrap();
        Arc::new(loader)
    }

    #[test]
    fn test_validate() {
        let elf_bytes = std::fs::read("tests/elfs/noop.so").unwrap();
        let elf = NewParser::parse(&elf_bytes).unwrap();
        let mut header = elf.header().clone();

        let config = Config::default();

        let write_header = |header: Elf64Ehdr| unsafe {
            let mut bytes = elf_bytes.clone();
            std::ptr::write(bytes.as_mut_ptr() as *mut Elf64Ehdr, header);
            bytes
        };

        ElfExecutable::validate(&config, &elf, &elf_bytes).expect("validation failed");

        header.e_ident.ei_class = ELFCLASS32;
        let bytes = write_header(header.clone());
        // the new parser rejects anything other than ELFCLASS64 directly
        NewParser::parse(&bytes).expect_err("allowed bad class");
        ElfExecutable::validate(&config, &GoblinParser::parse(&bytes).unwrap(), &elf_bytes)
            .expect_err("allowed bad class");

        header.e_ident.ei_class = ELFCLASS64;
        let bytes = write_header(header.clone());
        ElfExecutable::validate(&config, &NewParser::parse(&bytes).unwrap(), &elf_bytes)
            .expect("validation failed");
        ElfExecutable::validate(&config, &GoblinParser::parse(&bytes).unwrap(), &elf_bytes)
            .expect("validation failed");

        header.e_ident.ei_data = ELFDATA2MSB;
        let bytes = write_header(header.clone());
        // the new parser only supports little endian
        NewParser::parse(&bytes).expect_err("allowed big endian");

        header.e_ident.ei_data = ELFDATA2LSB;
        let bytes = write_header(header.clone());
        ElfExecutable::validate(&config, &NewParser::parse(&bytes).unwrap(), &elf_bytes)
            .expect("validation failed");
        ElfExecutable::validate(&config, &GoblinParser::parse(&bytes).unwrap(), &elf_bytes)
            .expect("validation failed");

        header.e_ident.ei_osabi = 1;
        let bytes = write_header(header.clone());
        ElfExecutable::validate(&config, &NewParser::parse(&bytes).unwrap(), &elf_bytes)
            .expect_err("allowed wrong abi");
        ElfExecutable::validate(&config, &GoblinParser::parse(&bytes).unwrap(), &elf_bytes)
            .expect_err("allowed wrong abi");

        header.e_ident.ei_osabi = ELFOSABI_NONE;
        let bytes = write_header(header.clone());
        ElfExecutable::validate(&config, &NewParser::parse(&bytes).unwrap(), &elf_bytes)
            .expect("validation failed");
        ElfExecutable::validate(&config, &GoblinParser::parse(&bytes).unwrap(), &elf_bytes)
            .expect("validation failed");

        header.e_machine = 42;
        let bytes = write_header(header.clone());
        ElfExecutable::validate(&config, &NewParser::parse(&bytes).unwrap(), &elf_bytes)
            .expect_err("allowed wrong machine");
        ElfExecutable::validate(&config, &GoblinParser::parse(&bytes).unwrap(), &elf_bytes)
            .expect_err("allowed wrong machine");

        header.e_machine = EM_BPF;
        let bytes = write_header(header.clone());
        ElfExecutable::validate(&config, &NewParser::parse(&bytes).unwrap(), &elf_bytes)
            .expect("validation failed");
        ElfExecutable::validate(&config, &GoblinParser::parse(&bytes).unwrap(), &elf_bytes)
            .expect("validation failed");

        header.e_type = ET_REL;
        let bytes = write_header(header);
        ElfExecutable::validate(&config, &NewParser::parse(&bytes).unwrap(), &elf_bytes)
            .expect_err("allowed wrong type");
        ElfExecutable::validate(&config, &GoblinParser::parse(&bytes).unwrap(), &elf_bytes)
            .expect_err("allowed wrong type");
    }

    #[test]
    fn test_load() {
        let mut file = File::open("tests/elfs/noop.so").expect("file open failed");
        let mut elf_bytes = Vec::new();
        file.read_to_end(&mut elf_bytes)
            .expect("failed to read elf file");
        ElfExecutable::load(&elf_bytes, loader()).expect("validation failed");
    }

    #[test]
    fn test_load_unaligned() {
        let mut elf_bytes = std::fs::read("tests/elfs/noop.so").expect("failed to read elf file");
        // The default allocator allocates aligned memory. Move the ELF slice to
        // elf_bytes.as_ptr() + 1 to make it unaligned and test unaligned
        // parsing.
        elf_bytes.insert(0, 0);
        ElfExecutable::load(&elf_bytes[1..], loader()).expect("validation failed");
    }

    #[test]
    fn test_entrypoint() {
        let loader = loader();

        let mut file = File::open("tests/elfs/noop.so").expect("file open failed");
        let mut elf_bytes = Vec::new();
        file.read_to_end(&mut elf_bytes)
            .expect("failed to read elf file");
        let elf = ElfExecutable::load(&elf_bytes, loader.clone()).expect("validation failed");
        let parsed_elf = NewParser::parse(&elf_bytes).unwrap();
        let executable: &Executable<TestContextObject> = &elf;
        assert_eq!(0, executable.get_entrypoint_instruction_offset());

        let write_header = |header: Elf64Ehdr| unsafe {
            let mut bytes = elf_bytes.clone();
            std::ptr::write(bytes.as_mut_ptr() as *mut Elf64Ehdr, header);
            bytes
        };

        let mut header = parsed_elf.header().clone();
        let initial_e_entry = header.e_entry;

        header.e_entry += 8;
        let elf_bytes = write_header(header.clone());
        let elf = ElfExecutable::load(&elf_bytes, loader.clone()).expect("validation failed");
        let executable: &Executable<TestContextObject> = &elf;
        assert_eq!(1, executable.get_entrypoint_instruction_offset());

        header.e_entry = 1;
        let elf_bytes = write_header(header.clone());
        assert_eq!(
            Err(ElfError::EntrypointOutOfBounds),
            ElfExecutable::load(&elf_bytes, loader.clone())
        );

        header.e_entry = u64::MAX;
        let elf_bytes = write_header(header.clone());
        assert_eq!(
            Err(ElfError::EntrypointOutOfBounds),
            ElfExecutable::load(&elf_bytes, loader.clone())
        );

        header.e_entry = initial_e_entry + ebpf::INSN_SIZE as u64 + 1;
        let elf_bytes = write_header(header.clone());
        assert_eq!(
            Err(ElfError::InvalidEntrypoint),
            ElfExecutable::load(&elf_bytes, loader.clone())
        );

        header.e_entry = initial_e_entry;
        let elf_bytes = write_header(header);
        let elf = ElfExecutable::load(&elf_bytes, loader).expect("validation failed");
        let executable: &Executable<TestContextObject> = &elf;
        assert_eq!(0, executable.get_entrypoint_instruction_offset());
    }

    #[test]
    fn test_fixup_relative_calls_back() {
        let mut function_registry = FunctionRegistry::default();
        let loader = BuiltInProgram::new_loader(Config {
            static_syscalls: false,
            enable_symbol_and_section_labels: true,
            ..Config::default()
        });

        // call -2
        #[rustfmt::skip]
        let mut prog = vec![
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x85, 0x10, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff];

        ElfExecutable::fixup_relative_calls(&mut function_registry, &loader, &mut prog).unwrap();
        let name = "function_4".to_string();
        let hash = hash_internal_function(4, &name);
        let insn = ebpf::Insn {
            opc: 0x85,
            dst: 0,
            src: 1,
            imm: hash as i64,
            ..ebpf::Insn::default()
        };
        assert_eq!(insn.to_array(), prog[40..]);
        assert_eq!(*function_registry.get(&hash).unwrap(), (4, name));

        // call +6
        let mut function_registry = FunctionRegistry::default();
        prog.splice(44.., vec![0xfa, 0xff, 0xff, 0xff]);
        ElfExecutable::fixup_relative_calls(&mut function_registry, &loader, &mut prog).unwrap();
        let name = "function_0".to_string();
        let hash = hash_internal_function(0, &name);
        let insn = ebpf::Insn {
            opc: 0x85,
            dst: 0,
            src: 1,
            imm: hash as i64,
            ..ebpf::Insn::default()
        };
        assert_eq!(insn.to_array(), prog[40..]);
        assert_eq!(*function_registry.get(&hash).unwrap(), (0, name));
    }

    #[test]
    fn test_fixup_relative_calls_forward() {
        let mut function_registry = FunctionRegistry::default();
        let loader = BuiltInProgram::new_loader(Config {
            static_syscalls: false,
            enable_symbol_and_section_labels: true,
            ..Config::default()
        });

        // call +0
        #[rustfmt::skip]
        let mut prog = vec![
            0x85, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        ElfExecutable::fixup_relative_calls(&mut function_registry, &loader, &mut prog).unwrap();
        let name = "function_1".to_string();
        let hash = hash_internal_function(1, &name);
        let insn = ebpf::Insn {
            opc: 0x85,
            dst: 0,
            src: 1,
            imm: hash as i64,
            ..ebpf::Insn::default()
        };
        assert_eq!(insn.to_array(), prog[..8]);
        assert_eq!(*function_registry.get(&hash).unwrap(), (1, name));

        // call +4
        let mut function_registry = FunctionRegistry::default();
        prog.splice(4..8, vec![0x04, 0x00, 0x00, 0x00]);
        ElfExecutable::fixup_relative_calls(&mut function_registry, &loader, &mut prog).unwrap();
        let name = "function_5".to_string();
        let hash = hash_internal_function(5, &name);
        let insn = ebpf::Insn {
            opc: 0x85,
            dst: 0,
            src: 1,
            imm: hash as i64,
            ..ebpf::Insn::default()
        };
        assert_eq!(insn.to_array(), prog[..8]);
        assert_eq!(*function_registry.get(&hash).unwrap(), (5, name));
    }

    #[test]
    #[should_panic(
        expected = "called `Result::unwrap()` on an `Err` value: RelativeJumpOutOfBounds(29)"
    )]
    fn test_fixup_relative_calls_out_of_bounds_forward() {
        let mut function_registry = FunctionRegistry::default();
        let loader = loader();

        // call +5
        #[rustfmt::skip]
        let mut prog = vec![
            0x85, 0x10, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        ElfExecutable::fixup_relative_calls(&mut function_registry, &loader, &mut prog).unwrap();
        let name = "function_1".to_string();
        let hash = hash_internal_function(1, &name);
        let insn = ebpf::Insn {
            opc: 0x85,
            dst: 0,
            src: 1,
            imm: hash as i64,
            ..ebpf::Insn::default()
        };
        assert_eq!(insn.to_array(), prog[..8]);
        assert_eq!(*function_registry.get(&hash).unwrap(), (1, name));
    }

    #[test]
    #[should_panic(
        expected = "called `Result::unwrap()` on an `Err` value: RelativeJumpOutOfBounds(34)"
    )]
    fn test_fixup_relative_calls_out_of_bounds_back() {
        let mut function_registry = FunctionRegistry::default();
        let loader = loader();

        // call -7
        #[rustfmt::skip]
        let mut prog = vec![
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x85, 0x10, 0x00, 0x00, 0xf9, 0xff, 0xff, 0xff];

        ElfExecutable::fixup_relative_calls(&mut function_registry, &loader, &mut prog).unwrap();
        let name = "function_4".to_string();
        let hash = hash_internal_function(4, &name);
        let insn = ebpf::Insn {
            opc: 0x85,
            dst: 0,
            src: 1,
            imm: hash as i64,
            ..ebpf::Insn::default()
        };
        assert_eq!(insn.to_array(), prog[40..]);
        assert_eq!(*function_registry.get(&hash).unwrap(), (4, name));
    }

    #[test]
    #[ignore]
    fn test_fuzz_load() {
        let loader = loader();

        // Random bytes, will mostly fail due to lack of ELF header so just do a few
        let mut rng = rand::thread_rng();
        let range = Uniform::new(0, 255);
        println!("random bytes");
        for _ in 0..1_000 {
            let elf_bytes: Vec<u8> = (0..100).map(|_| rng.sample(range)).collect();
            let _ = ElfExecutable::load(&elf_bytes, loader.clone());
        }

        // Take a real elf and mangle it

        let mut file = File::open("tests/elfs/noop.so").expect("file open failed");
        let mut elf_bytes = Vec::new();
        file.read_to_end(&mut elf_bytes)
            .expect("failed to read elf file");
        let parsed_elf = NewParser::parse(&elf_bytes).unwrap();

        // focus on elf header, small typically 64 bytes
        println!("mangle elf header");
        fuzz(
            &elf_bytes,
            1_000_000,
            100,
            0..parsed_elf.header().e_ehsize as usize,
            0..255,
            |bytes: &mut [u8]| {
                let _ = ElfExecutable::load(bytes, loader.clone());
            },
        );

        // focus on section headers
        println!("mangle section headers");
        fuzz(
            &elf_bytes,
            1_000_000,
            100,
            parsed_elf.header().e_shoff as usize..elf_bytes.len(),
            0..255,
            |bytes: &mut [u8]| {
                let _ = ElfExecutable::load(bytes, loader.clone());
            },
        );

        // mangle whole elf randomly
        println!("mangle whole elf");
        fuzz(
            &elf_bytes,
            1_000_000,
            100,
            0..elf_bytes.len(),
            0..255,
            |bytes: &mut [u8]| {
                let _ = ElfExecutable::load(bytes, loader.clone());
            },
        );
    }

    fn new_section(sh_addr: u64, sh_size: u64) -> Elf64Shdr {
        Elf64Shdr {
            sh_addr,
            sh_offset: sh_addr,
            sh_size,
            sh_name: 0,
            sh_type: 0,
            sh_flags: 0,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 0,
            sh_entsize: 0,
        }
    }

    #[test]
    fn test_owned_ro_sections_not_contiguous() {
        let config = Config::default();
        let elf_bytes = [0u8; 512];

        // there's a non-rodata section between two rodata sections
        let s1 = new_section(10, 10);
        let s2 = new_section(20, 10);
        let s3 = new_section(30, 10);

        assert!(matches!(
            ElfExecutable::parse_ro_sections(
                &config,
                [(Some(".text"), &s1), (Some(".dynamic"), &s2), (Some(".rodata"), &s3)],
                &elf_bytes,
            ),
            Ok(Section::Owned(offset, data)) if offset == 10 && data.len() == 30
        ));
    }

    #[test]
    fn test_owned_ro_sections_with_sh_offset() {
        let config = Config {
            reject_broken_elfs: false,
            ..Config::default()
        };
        let elf_bytes = [0u8; 512];

        // s2 is at a custom sh_offset. We need to merge into an owned buffer so
        // s2 can be moved to the right address offset.
        let s1 = new_section(10, 10);
        let mut s2 = new_section(20, 10);
        s2.sh_offset = 30;

        assert!(matches!(
            ElfExecutable::parse_ro_sections(
                &config,
                [(Some(".text"), &s1), (Some(".rodata"), &s2)],
                &elf_bytes,
            ),
            Ok(Section::Owned(offset, data)) if offset == 10 && data.len() == 20
        ));
    }

    #[test]
    fn test_sh_offset_not_same_as_vaddr() {
        let config = Config {
            reject_broken_elfs: true,
            enable_elf_vaddr: false,
            ..Config::default()
        };
        let elf_bytes = [0u8; 512];

        let mut s1 = new_section(10, 10);

        assert!(
            ElfExecutable::parse_ro_sections(&config, [(Some(".text"), &s1)], &elf_bytes,).is_ok()
        );

        s1.sh_offset = 0;
        assert_eq!(
            ElfExecutable::parse_ro_sections(&config, [(Some(".text"), &s1)], &elf_bytes,),
            Err(ElfError::ValueOutOfBounds)
        );
    }

    #[test]
    fn test_invalid_sh_offset_larger_than_vaddr() {
        let config = Config {
            reject_broken_elfs: true,
            ..Config::default()
        };
        let elf_bytes = [0u8; 512];

        let s1 = new_section(10, 10);
        // sh_offset > sh_addr is invalid
        let mut s2 = new_section(20, 10);
        s2.sh_offset = 30;

        assert_eq!(
            ElfExecutable::parse_ro_sections(
                &config,
                [(Some(".text"), &s1), (Some(".rodata"), &s2)],
                &elf_bytes,
            ),
            Err(ElfError::ValueOutOfBounds)
        );
    }

    #[test]
    fn test_reject_non_constant_sh_offset() {
        let config = Config {
            reject_broken_elfs: true,
            ..Config::default()
        };
        let elf_bytes = [0u8; 512];

        let mut s1 = new_section(ebpf::MM_PROGRAM_START + 10, 10);
        let mut s2 = new_section(ebpf::MM_PROGRAM_START + 20, 10);
        // The sections don't have a constant offset. This is rejected since it
        // makes it impossible to efficiently map virtual addresses to byte
        // offsets
        s1.sh_offset = 100;
        s2.sh_offset = 120;

        assert_eq!(
            ElfExecutable::parse_ro_sections(
                &config,
                [(Some(".text"), &s1), (Some(".rodata"), &s2)],
                &elf_bytes,
            ),
            Err(ElfError::ValueOutOfBounds)
        );
    }

    #[test]
    fn test_borrowed_ro_sections_with_constant_sh_offset() {
        let config = Config {
            reject_broken_elfs: true,
            ..Config::default()
        };
        let elf_bytes = [0u8; 512];

        let mut s1 = new_section(ebpf::MM_PROGRAM_START + 10, 10);
        let mut s2 = new_section(ebpf::MM_PROGRAM_START + 20, 10);
        // the sections have a constant offset (100)
        s1.sh_offset = 100;
        s2.sh_offset = 110;

        assert_eq!(
            ElfExecutable::parse_ro_sections(
                &config,
                [(Some(".text"), &s1), (Some(".rodata"), &s2)],
                &elf_bytes,
            ),
            Ok(Section::Borrowed(10, 100..120))
        );
    }

    #[test]
    fn test_owned_ro_region_no_initial_gap() {
        let config = Config::default();
        let elf_bytes = [0u8; 512];

        // need an owned buffer so we can zero the address space taken by s2
        let s1 = new_section(0, 10);
        let s2 = new_section(10, 10);
        let s3 = new_section(20, 10);

        let ro_section = ElfExecutable::parse_ro_sections(
            &config,
            [
                (Some(".text"), &s1),
                (Some(".dynamic"), &s2),
                (Some(".rodata"), &s3),
            ],
            &elf_bytes,
        )
        .unwrap();
        let ro_region = get_ro_region(&ro_section, &elf_bytes);
        let owned_section = match &ro_section {
            Section::Owned(_offset, data) => data.as_slice(),
            _ => panic!(),
        };

        // [0..s3.sh_addr + s3.sh_size] is the valid ro memory area
        assert!(matches!(
            ro_region.vm_to_host(ebpf::MM_PROGRAM_START, s3.sh_addr + s3.sh_size),
            ProgramResult::Ok(ptr) if ptr == owned_section.as_ptr() as u64,
        ));

        // one byte past the ro section is not mappable
        assert!(matches!(
            ro_region.vm_to_host(ebpf::MM_PROGRAM_START + s3.sh_addr + s3.sh_size, 1),
            ProgramResult::Err(EbpfError::InvalidVirtualAddress(
                address
            )) if address == ebpf::MM_PROGRAM_START + s3.sh_addr + s3.sh_size,
        ));
    }

    #[test]
    fn test_owned_ro_region_initial_gap_mappable() {
        let config = Config {
            optimize_rodata: false,
            ..Config::default()
        };
        let elf_bytes = [0u8; 512];

        // the first section starts at a non-zero offset
        let s1 = new_section(10, 10);
        let s2 = new_section(20, 10);
        let s3 = new_section(30, 10);

        let ro_section = ElfExecutable::parse_ro_sections(
            &config,
            [
                (Some(".text"), &s1),
                (Some(".dynamic"), &s2),
                (Some(".rodata"), &s3),
            ],
            &elf_bytes,
        )
        .unwrap();
        let ro_region = get_ro_region(&ro_section, &elf_bytes);
        let owned_section = match &ro_section {
            Section::Owned(_offset, data) => data.as_slice(),
            _ => panic!(),
        };

        // [s1.sh_addr..s3.sh_addr + s3.sh_size] is where the readonly data is.
        // But for backwards compatibility (config.optimize_rodata=false)
        // [0..s1.sh_addr] is mappable too (and zeroed).
        assert!(matches!(
            ro_region.vm_to_host(ebpf::MM_PROGRAM_START, s3.sh_addr + s3.sh_size),
            ProgramResult::Ok(ptr) if ptr == owned_section.as_ptr() as u64,
        ));

        // one byte past the ro section is not mappable
        assert!(matches!(
            ro_region.vm_to_host(ebpf::MM_PROGRAM_START + s3.sh_addr + s3.sh_size, 1),
            ProgramResult::Err(EbpfError::InvalidVirtualAddress(
                address
            )) if address == ebpf::MM_PROGRAM_START + s3.sh_addr + s3.sh_size,
        ));
    }

    #[test]
    fn test_owned_ro_region_initial_gap_map_error() {
        let config = Config::default();
        let elf_bytes = [0u8; 512];

        // the first section starts at a non-zero offset
        let s1 = new_section(10, 10);
        let s2 = new_section(20, 10);
        let s3 = new_section(30, 10);

        let ro_section = ElfExecutable::parse_ro_sections(
            &config,
            [
                (Some(".text"), &s1),
                (Some(".dynamic"), &s2),
                (Some(".rodata"), &s3),
            ],
            &elf_bytes,
        )
        .unwrap();
        let owned_section = match &ro_section {
            Section::Owned(_offset, data) => data.as_slice(),
            _ => panic!(),
        };
        let ro_region = get_ro_region(&ro_section, &elf_bytes);

        // s1 starts at sh_addr=10 so [MM_PROGRAM_START..MM_PROGRAM_START + 10] is not mappable

        // the low bound of the initial gap is not mappable
        assert!(matches!(
            ro_region.vm_to_host(ebpf::MM_PROGRAM_START, 1),
            ProgramResult::Err(EbpfError::InvalidVirtualAddress(address)) if address == ebpf::MM_PROGRAM_START,
        ));

        // the hi bound of the initial gap is not mappable
        assert!(matches!(
            ro_region.vm_to_host(ebpf::MM_PROGRAM_START + s1.sh_addr - 1, 1),
            ProgramResult::Err(EbpfError::InvalidVirtualAddress(address)) if address == ebpf::MM_PROGRAM_START + 9,
        ));

        // [s1.sh_addr..s3.sh_addr + s3.sh_size] is the valid ro memory area
        assert!(matches!(
            ro_region.vm_to_host(
                ebpf::MM_PROGRAM_START + s1.sh_addr,
                s3.sh_addr + s3.sh_size - s1.sh_addr
            ),
            ProgramResult::Ok(ptr) if ptr == owned_section.as_ptr() as u64,
        ));

        // one byte past the ro section is not mappable
        assert!(matches!(
            ro_region.vm_to_host(ebpf::MM_PROGRAM_START + s3.sh_addr + s3.sh_size, 1),
            ProgramResult::Err(EbpfError::InvalidVirtualAddress(
                address
            )) if address == ebpf::MM_PROGRAM_START + s3.sh_addr + s3.sh_size,
        ));
    }

    #[test]
    fn test_borrowed_ro_sections_disabled() {
        let config = Config {
            optimize_rodata: false,
            ..Config::default()
        };
        let elf_bytes = [0u8; 512];

        // s1 and s2 are contiguous, the rodata section can be borrowed from the
        // original elf input but config.borrow_rodata=false
        let s1 = new_section(0, 10);
        let s2 = new_section(10, 10);

        assert!(matches!(
            ElfExecutable::parse_ro_sections(
                &config,
                [(Some(".text"), &s1), (Some(".rodata"), &s2)],
                &elf_bytes,
            ),
            Ok(Section::Owned(offset, data)) if offset == 0 && data.len() == 20
        ));
    }

    #[test]
    fn test_borrowed_ro_sections() {
        let config = Config::default();
        let elf_bytes = [0u8; 512];

        let s1 = new_section(0, 10);
        let s2 = new_section(20, 10);
        let s3 = new_section(40, 10);
        let s4 = new_section(50, 10);

        assert_eq!(
            ElfExecutable::parse_ro_sections(
                &config,
                [
                    (Some(".dynsym"), &s1),
                    (Some(".text"), &s2),
                    (Some(".rodata"), &s3),
                    (Some(".dynamic"), &s4)
                ],
                &elf_bytes,
            ),
            Ok(Section::Borrowed(20, 20..50))
        );
    }

    #[test]
    fn test_borrowed_ro_region_no_initial_gap() {
        let config = Config::default();
        let elf_bytes = [0u8; 512];

        let s1 = new_section(0, 10);
        let s2 = new_section(10, 10);
        let s3 = new_section(10, 10);

        let ro_section = ElfExecutable::parse_ro_sections(
            &config,
            [
                (Some(".text"), &s1),
                (Some(".rodata"), &s2),
                (Some(".dynamic"), &s3),
            ],
            &elf_bytes,
        )
        .unwrap();
        let ro_region = get_ro_region(&ro_section, &elf_bytes);

        // s1 starts at sh_addr=0 so [0..s2.sh_addr + s2.sh_size] is the valid
        // ro memory area
        assert!(matches!(
            ro_region.vm_to_host(ebpf::MM_PROGRAM_START, s2.sh_addr + s2.sh_size),
            ProgramResult::Ok(ptr) if ptr == elf_bytes.as_ptr() as u64,
        ));

        // one byte past the ro section is not mappable
        assert!(matches!(
            ro_region.vm_to_host(ebpf::MM_PROGRAM_START + s2.sh_addr + s2.sh_size, 1),
            ProgramResult::Err(EbpfError::InvalidVirtualAddress(
                address
            )) if address == ebpf::MM_PROGRAM_START + s2.sh_addr + s2.sh_size,
        ));
    }

    #[test]
    fn test_borrowed_ro_region_initial_gap() {
        let config = Config::default();
        let elf_bytes = [0u8; 512];
        let s1 = new_section(0, 10);
        let s2 = new_section(10, 10);
        let s3 = new_section(20, 10);

        let ro_section = ElfExecutable::parse_ro_sections(
            &config,
            [
                (Some(".dynamic"), &s1),
                (Some(".text"), &s2),
                (Some(".rodata"), &s3),
            ],
            &elf_bytes,
        )
        .unwrap();
        let ro_region = get_ro_region(&ro_section, &elf_bytes);

        // s2 starts at sh_addr=10 so [0..10] is not mappable

        // the low bound of the initial gap is not mappable
        assert!(matches!(
            ro_region.vm_to_host(ebpf::MM_PROGRAM_START, 1),
            ProgramResult::Err(EbpfError::InvalidVirtualAddress(address)) if address == ebpf::MM_PROGRAM_START,
        ));

        // the hi bound of the initial gap is not mappable
        assert!(matches!(
            ro_region.vm_to_host(ebpf::MM_PROGRAM_START + s2.sh_addr - 1, 1),
            ProgramResult::Err(EbpfError::InvalidVirtualAddress(address)) if address == ebpf::MM_PROGRAM_START + 9,
        ));

        // [s2.sh_addr..s3.sh_addr + s3.sh_size] is the valid ro memory area
        assert!(matches!(
            ro_region.vm_to_host(
                ebpf::MM_PROGRAM_START + s2.sh_addr,
                s3.sh_addr + s3.sh_size - s2.sh_addr
            ),
            ProgramResult::Ok(ptr) if ptr == elf_bytes[s2.sh_addr as usize..].as_ptr() as u64,
        ));

        // one byte past the ro section is not mappable
        assert!(matches!(
            ro_region.vm_to_host(ebpf::MM_PROGRAM_START + s3.sh_addr + s3.sh_size, 1),
            ProgramResult::Err(EbpfError::InvalidVirtualAddress(
                address
            )) if address == ebpf::MM_PROGRAM_START + s3.sh_addr + s3.sh_size,
        ));
    }

    #[test]
    fn test_reject_rodata_stack_overlap() {
        let config = Config {
            enable_elf_vaddr: true,
            reject_rodata_stack_overlap: true,
            ..Config::default()
        };
        let elf_bytes = [0u8; 512];

        // no overlap
        let mut s1 = new_section(ebpf::MM_STACK_START - 10, 10);
        s1.sh_offset = 0;

        assert!(
            ElfExecutable::parse_ro_sections(&config, [(Some(".text"), &s1)], &elf_bytes).is_ok()
        );

        // no overlap
        let mut s1 = new_section(ebpf::MM_STACK_START, 0);
        s1.sh_offset = 0;

        assert!(
            ElfExecutable::parse_ro_sections(&config, [(Some(".text"), &s1)], &elf_bytes).is_ok()
        );

        // overlap
        let mut s1 = new_section(ebpf::MM_STACK_START, 1);
        s1.sh_offset = 0;
        assert_eq!(
            ElfExecutable::parse_ro_sections(&config, [(Some(".text"), &s1)], &elf_bytes),
            Err(ElfError::ValueOutOfBounds)
        );

        // valid start but start + size overlap
        let mut s1 = new_section(ebpf::MM_STACK_START - 10, 11);
        s1.sh_offset = 0;

        assert_eq!(
            ElfExecutable::parse_ro_sections(&config, [(Some(".text"), &s1)], &elf_bytes),
            Err(ElfError::ValueOutOfBounds)
        );
    }

    #[test]
    #[should_panic(expected = r#"validation failed: WritableSectionNotSupported(".data")"#)]
    fn test_writable_data_section() {
        let elf_bytes =
            std::fs::read("tests/elfs/writable_data_section.so").expect("failed to read elf file");
        ElfExecutable::load(&elf_bytes, loader()).expect("validation failed");
    }

    #[test]
    #[should_panic(expected = r#"validation failed: WritableSectionNotSupported(".bss")"#)]
    fn test_bss_section() {
        let elf_bytes =
            std::fs::read("tests/elfs/bss_section.so").expect("failed to read elf file");
        ElfExecutable::load(&elf_bytes, loader()).expect("validation failed");
    }

    #[test]
    #[should_panic(expected = r#"validation failed: RelativeJumpOutOfBounds(29)"#)]
    fn test_static_syscall_disabled() {
        let loader = BuiltInProgram::new_loader(Config {
            static_syscalls: false,
            ..Config::default()
        });
        let elf_bytes =
            std::fs::read("tests/elfs/syscall_static_unknown.so").expect("failed to read elf file");

        // when config.static_syscalls=false, all CALL_IMMs are treated as relative
        // calls for backwards compatibility
        ElfExecutable::load(&elf_bytes, Arc::new(loader)).expect("validation failed");
    }

    #[test]
    #[should_panic(expected = "validation failed: InvalidProgramHeader")]
    fn test_program_headers_overflow() {
        let elf_bytes = std::fs::read("tests/elfs/program_headers_overflow.so")
            .expect("failed to read elf file");
        ElfExecutable::load(&elf_bytes, loader()).expect("validation failed");
    }

    #[cfg(all(feature = "jit", not(target_os = "windows"), target_arch = "x86_64"))]
    #[test]
    fn test_size() {
        let mut file = File::open("tests/elfs/noop.so").expect("file open failed");
        let mut elf_bytes = Vec::new();
        file.read_to_end(&mut elf_bytes)
            .expect("failed to read elf file");
        let mut executable =
            ElfExecutable::from_elf(&elf_bytes, loader()).expect("validation failed");
        {
            Executable::jit_compile(&mut executable).unwrap();
        }

        assert_eq!(10538, executable.mem_size());
    }
}
