// Readelf - tool for displaying information about ELF files.
// Copyright (C) 2025 Alexander (@alkuzin).
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! ELF sections module.

use crate::elf::{Elf32_Addr, Elf32_Off, Elf32_Word};

// ELF special section indexes enumeration.

/// This value marks an undefined, missing, irrelevant, or otherwise meaningless
/// section reference. For example, a symbol ‘‘defined’’ relative to section
/// number SHN_UNDEF is an undefined symbol.
const SHN_UNDEF: u32 = 0;
/// This value specifies the lower bound of the range of reserved indexes.
const SHN_LORESERVE: u32 = 0xff00;
/// Values in this inclusive range are reserved for processor-specific
/// semantics.
const SHN_LOPROC: u32 = 0xff00;
const SHN_HIPROC: u32 = 0xff1f;
/// This value specifies absolute values for the corresponding reference. For
/// example, symbols defined relative to section number SHN_ABS have absolute
/// values and are not affected by relocation.
const SHN_ABS: u32 = 0xfff1;
/// Symbols defined relative to this section are common symbols, such as FORTRAN
/// COMMON or unallocated C external variables.
const SHN_COMMON: u32 = 0xfff2;
/// This value specifies the upper bound of the range of reserved indexes. The
/// system reserves indexes between SHN_LORESERVE and SHN_HIRESERVE, inclusive;
/// the values do not reference the section header table. That is, the section
/// header table does not contain entries for the reserved indexes.
const SHN_HIRESERVE: u32 = 0xfff;

/// ELF section header struct.
/// Sections contain all information in an object file, except the ELF header,
/// the program header table, and the section header table. Moreover, object
/// files’ sections satisfy several conditions.
///
/// Every section in an object file has exactly one section header describing
/// it. Section headers may exist that do not have a section.
/// Each section occupies one contiguous (possibly empty) sequence of bytes
/// within a file. Sections in a file may not overlap. No byte in a file resides
/// in more than one section. An object file may have inactive space. The
/// various headers and the sections might not ‘‘cover’’ every byte in an object
/// file. The contents of the inactive data are unspecified.
#[repr(C, packed)]
pub struct Elf32_Shdr {
    /// This member specifies the name of the section. Its value is an index
    /// into the section header string table section, giving the location of a
    /// null- terminated string.
    pub sh_name: Elf32_Word,
    /// This member categorizes the section’s contents and semantics.
    pub sh_type: Elf32_Word,
    /// Sections support 1-bit flags that describe miscellaneous attributes.
    pub sh_flags: Elf32_Word,
    /// If the section will appear in the memory image of a process, this
    /// member gives the address at which the section’s first byte should
    /// reside. Otherwise, the member con- tains 0.
    pub sh_addr: Elf32_Addr,
    /// This member’s value gives the byte offset from the beginning of the
    /// file to the first byte in the section. One section type, SHT_NOBITS
    /// described below, occupies no space in the file, and its sh_offset
    /// member locates the conceptual placement in the file.
    pub sh_offset: Elf32_Off,
    /// This member gives the section’s size in bytes. Unless the section type
    /// is SHT_NOBITS, the section occupies sh_size bytes in the file. A
    /// section of type SHT_NOBITS may have a non-zero size, but it
    /// occupies no space in the file.
    pub sh_size: Elf32_Word,
    /// This member holds a section header table index link, whose
    /// interpretation depends on the section type. A table below describes
    /// the values.
    pub sh_link: Elf32_Word,
    /// This member holds extra information, whose interpretation depends on
    /// the section type.
    pub sh_info: Elf32_Word,
    /// Some sections have address alignment constraints. For example, if a
    /// section holds a doubleword, the system must ensure doubleword
    /// alignment for the entire section. That is, the value of sh_addr
    /// must be congruent to 0, modulo the value of sh_addralign.
    /// Currently, only 0 and positive integral powers of two are allowed.
    /// Values 0 and 1 mean the section has no alignment constraints.
    pub sh_addralign: Elf32_Word,
    /// Some sections hold a table of fixed-size entries, such as a symbol
    /// table. For such a sec- tion, this member gives the size in bytes of
    /// each entry. The member contains 0 if the section does not hold a
    /// table of fixed-size entries.
    pub sh_entsize: Elf32_Word,
}

// ELF section type enumeration.

/// This value marks the section header as inactive; it does not have an
/// associated section. Other members of the section header have undefined
/// values.
pub const SHT_NULL: u32 = 0;
/// The section holds information defined by the program, whose format and
/// meaning are determined solely by the program.
pub const SHT_PROGBITS: u32 = 1;
/// These sections hold a symbol table. Currently, an object file may have only
/// one section of each type, but this restriction may be relaxed in the future.
/// Typically, SHT_SYMTAB provides symbols for link editing, though it may also
/// be used for dynamic linking. As a complete symbol table, it may contain many
/// symbols unnecessary for dynamic linking. Consequently, an object file may
/// also contain a SHT_DYNSYM section, which holds a minimal set of dynamic
/// linking symbols, to save space.
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_DYNSYM: u32 = 11;
/// The section holds a string table. An object file may have multiple string
/// table sections.
pub const SHT_STRTAB: u32 = 3;
/// The section holds relocation entries with explicit addends, such as type
/// Elf32_Rela for the 32-bit class of object files. An object file may have
/// multiple relocation sections.
pub const SHT_RELA: u32 = 4;
/// The section holds a symbol hash table. All objects participating in dynamic
/// linking must contain a symbol hash table. Currently, an object file may have
/// only one hash table, but this restriction may be relaxed in the future.
pub const SHT_HASH: u32 = 5;
/// The section holds information for dynamic linking. Currently, an object file
/// may have only one dynamic section, but this restriction may be relaxed in
/// the future.
pub const SHT_DYNAMIC: u32 = 6;
/// The section holds information that marks the file in some way.
pub const SHT_NOTE: u32 = 7;
/// A section of this type occupies no space in the file but otherwise resembles
/// SHT_PROGBITS. Although this section contains no bytes, the sh_offset member
/// contains the conceptual file offset.
pub const SHT_NOBITS: u32 = 8;
/// The section holds relocation entries without explicit addends, such as type
/// Elf32_Rel for the 32-bit class of object files. An object file may have
/// multiple relocation sections.
pub const SHT_REL: u32 = 9;
/// This section type is reserved but has unspecified semantics. Programs that
/// contain a section of this type do not conform to the ABI.
pub const SHT_SHLIB: u32 = 10;
/// Values in this inclusive range are reserved for processor-specific
/// semantics.
pub const SHT_LOPROC: u32 = 0x70000000;
pub const SHT_HIPROC: u32 = 0x7fffffff;
/// This value specifies the lower bound of the range of indexes reserved for
/// application programs.
pub const SHT_LOUSER: u32 = 0x80000000;
/// This value specifies the upper bound of the range of indexes reserved for
/// application programs. Section types between SHT_LOUSER and SHT_HIUSER may be
/// used by the application, without conflicting with current or future
/// system-defined section types.
pub const SHT_HIUSER: u32 = 0xffffffff;

// ELF section flags enumeration.

/// If a flag bit is set in `sh_flags`, the attribute is "on" for the section.
/// Otherwise, the attribute is "off" or does not apply. Undefined attributes
/// are set to zero.
///
/// The section contains data that should be writable during process execution.
pub const SHF_WRITE: u32 = 0x1;
/// The section occupies memory during process execution. Some control sections
/// do not reside in the memory image of an object file; this attribute is off
/// for those sections.
pub const SHF_ALLOC: u32 = 0x2;
/// The section contains executable machine instructions.
pub const SHF_EXECINSTR: u32 = 0x4;
/// All bits included in this mask are reserved for processor-specific
/// semantics.
pub const SHF_MASKPROC: u32 = 0xf0000000;

/// Check if a section is .bss.
///
/// - `.bss` - This section holds uninitialized data that contribute to the
///   program’s memory image. By
/// definition, the system initializes the data with zeros when the program
/// begins to run. The section occupies no file space, as indicated by the
/// section type, SHT_NOBITS.
///
/// # Parameters
/// - `section` - given ELF section header struct.
/// - `section` - given section name.
///
/// # Returns
/// - `true`  - is given section is `.bss`.
/// - `false` - otherwise.
pub fn is_bss_section(section: &Elf32_Shdr, name: &str) -> bool {
    section.sh_type == SHT_NOBITS && section.sh_flags == 0 && name == ".bss"
}

/// Check if a section is .data.
///
/// - `.data` - This section holds initialized data that contribute to the
///   program’s memory image.
/// The section is allocated in memory and is writable, as indicated by the
/// presence of the SHF_ALLOC and SHF_WRITE flags.
///
/// # Parameters
/// - `section` - given ELF section header struct.
/// - `name`    - given section name.
pub fn is_data_section(section: &Elf32_Shdr, name: &str) -> bool {
    section.sh_type == SHT_PROGBITS
        && (section.sh_flags & (SHF_ALLOC | SHF_WRITE))
            == (SHF_ALLOC | SHF_WRITE)
        && name == ".data"
}

/// Check if a section is .data1.
///
/// - `.data1` - This section holds initialized data that contribute to the
///   program’s memory image.
/// Similar to `.data`, it is allocated in memory and is writable, as indicated
/// by the presence of the SHF_ALLOC and SHF_WRITE flags.
///
/// # Parameters
/// - `section` - given ELF section header struct.
/// - `name`    - given section name.
///
/// # Returns
/// - `true`  - if the given section is `.data1`.
/// - `false` - otherwise.
pub fn is_data1_section(section: &Elf32_Shdr, name: &str) -> bool {
    section.sh_type == SHT_PROGBITS
        && (section.sh_flags & (SHF_ALLOC | SHF_WRITE))
            == (SHF_ALLOC | SHF_WRITE)
        && name == ".data1"
}

/// Check if a section is .debug.
///
/// - `.debug` - This section holds information for symbolic debugging. The
///   contents are unspecified,
/// and it is typically used by debuggers to provide information about the
/// source code and its correspondence to the machine code.
///
/// # Parameters
/// - `section` - given ELF section header struct.
/// - `name`    - given section name.
///
/// # Returns
/// - `true`  - if the given section is `.debug`.
/// - `false` - otherwise.
pub fn is_debug_section(section: &Elf32_Shdr, name: &str) -> bool {
    section.sh_type == SHT_PROGBITS && section.sh_flags == 0 && name == ".debug"
}

/// Check if a section is .dynamic.
///
/// - `.dynamic` - This section holds dynamic linking information. The section’s
///   attributes will
/// include the SHF_ALLOC bit. Whether the SHF_WRITE bit is set is
/// processor-specific. It is used by the dynamic linker to manage shared
/// libraries and dynamic symbols.
///
/// # Parameters
/// - `section` - given ELF section header struct.
/// - `name`    - given section name.
///
/// # Returns
/// - `true`  - if the given section is `.dynamic`.
/// - `false` - otherwise.
pub fn is_dynamic_section(section: &Elf32_Shdr, name: &str) -> bool {
    section.sh_type == SHT_DYNAMIC && name == ".dynamic"
}

/// Check if a section is .dynstr.
///
/// - `.dynstr` - This section holds strings needed for dynamic linking, most
///   commonly the strings
/// that represent the names associated with symbol table entries. It is
/// essential for the dynamic linker to resolve symbol names at runtime.
///
/// # Parameters
/// - `section` - given ELF section header struct.
/// - `name`    - given section name.
///
/// # Returns
/// - `true`  - if the given section is `.dynstr`.
/// - `false` - otherwise.
pub fn is_dynstr_section(section: &Elf32_Shdr, name: &str) -> bool {
    section.sh_type == SHT_STRTAB
        && (section.sh_flags & SHF_ALLOC) == SHF_ALLOC
        && name == ".dynstr"
}

/// Check if a section is .dynsym.
///
/// - `.dynsym` - This section holds the dynamic linking symbol table, which
///   contains entries for
/// symbols that are used during dynamic linking. It is crucial for the dynamic
/// linker to resolve symbols at runtime.
///
/// # Parameters
/// - `section` - given ELF section header struct.
/// - `name`    - given section name.
///
/// # Returns
/// - `true`  - if the given section is `.dynsym`.
/// - `false` - otherwise.
pub fn is_dynsym_section(section: &Elf32_Shdr, name: &str) -> bool {
    section.sh_type == SHT_DYNSYM
        && (section.sh_flags & SHF_ALLOC) == SHF_ALLOC
        && name == ".dynsym"
}

/// Check if a section is .fini.
///
/// - `.fini` - This section holds executable instructions that contribute to
///   the process termination
/// code. When a program exits normally, the system arranges to execute the code
/// in this section.
///
/// # Parameters
/// - `section` - given ELF section header struct.
/// - `name`    - given section name.
///
/// # Returns
/// - `true`  - if the given section is `.fini`.
/// - `false` - otherwise.
pub fn is_fini_section(section: &Elf32_Shdr, name: &str) -> bool {
    section.sh_type == SHT_PROGBITS
        && (section.sh_flags & (SHF_ALLOC | SHF_EXECINSTR))
            == (SHF_ALLOC | SHF_EXECINSTR)
        && name == ".fini"
}

/// Check if a section is .got.
///
/// - `.got` - This section holds the global offset table, which is used for
///   dynamic linking to
/// resolve addresses of global variables and functions. It is essential for the
/// correct execution of dynamically linked programs.
///
/// # Parameters
/// - `section` - given ELF section header struct.
/// - `name`    - given section name.
///
/// # Returns
/// - `true`  - if the given section is `.got`.
/// - `false` - otherwise.
pub fn is_got_section(section: &Elf32_Shdr, name: &str) -> bool {
    section.sh_type == SHT_PROGBITS && name == ".got"
}

/// Check if a section is .hash.
///
/// - `.hash` - This section holds a symbol hash table, which is used by the
///   dynamic linker to
/// quickly resolve symbols. It provides a way to efficiently look up symbols
/// during dynamic linking.
///
/// # Parameters
/// - `section` - given ELF section header struct.
/// - `name`    - given section name.
///
/// # Returns
/// - `true`  - if the given section is `.hash`.
/// - `false` - otherwise.
pub fn is_hash_section(section: &Elf32_Shdr, name: &str) -> bool {
    section.sh_type == SHT_PROGBITS
        && (section.sh_flags & SHF_ALLOC) == SHF_ALLOC
        && name == ".hash"
}

/// Check if a section is .init.
///
/// - `.init` - This section holds executable instructions that contribute to
///   the process initialization
/// code. When a program starts to run, the system arranges to execute the code
/// in this section before calling the main program entry point (commonly `main`
/// for C programs).
///
/// # Parameters
/// - `section` - given ELF section header struct.
/// - `name`    - given section name.
///
/// # Returns
/// - `true`  - if the given section is `.init`.
/// - `false` - otherwise.
pub fn is_init_section(section: &Elf32_Shdr, name: &str) -> bool {
    section.sh_type == SHT_PROGBITS && name == ".init"
}

/// Check if a section is .line.
///
/// - `.line` - This section holds line number information for symbolic
///   debugging, which describes the
/// correspondence between the source program and the machine code. The contents
/// are unspecified.
///
/// # Parameters
/// - `section` - given ELF section header struct.
/// - `name`    - given section name.
///
/// # Returns
/// - `true`  - if the given section is `.line`.
/// - `false` - otherwise.
pub fn is_line_section(section: &Elf32_Shdr, name: &str) -> bool {
    section.sh_type == SHT_PROGBITS && section.sh_flags == 0 && name == ".line"
}

/// Check if a section is .note.
///
/// - `.note` - This section holds information in a format that is described in
///   the "Note Section"
/// in the ELF specification. It is often used for storing metadata about the
/// file.
///
/// # Parameters
/// - `section` - given ELF section header struct.
/// - `name`    - given section name.
///
/// # Returns
/// - `true`  - if the given section is `.note`.
/// - `false` - otherwise.
pub fn is_note_section(section: &Elf32_Shdr, name: &str) -> bool {
    section.sh_type == SHT_NOTE && name == ".note"
}

/// Check if a section is .plt.
///
/// - `.plt` - This section holds the procedure linkage table, which is used for
///   dynamic linking.
/// It allows for the resolution of function addresses at runtime, enabling
/// calls to shared library functions.
///
/// # Parameters
/// - `section` - given ELF section header struct.
/// - `name`    - given section name.
///
/// # Returns
/// - `true`  - if the given section is `.plt`.
/// - `false` - otherwise.
pub fn is_plt_section(section: &Elf32_Shdr, name: &str) -> bool {
    section.sh_type == SHT_PROGBITS && name == ".plt"
}

/// Check if a section is .rodata.
///
/// - `.rodata` - This section holds read-only data that typically contributes
///   to a non-writable
/// segment in the process image. It is used for constants and string literals
/// that should not be modified during execution.
///
/// # Parameters
/// - `section` - given ELF section header struct.
/// - `name`    - given section name.
///
/// # Returns
/// - `true`  - if the given section is `.rodata`.
/// - `false` - otherwise.
pub fn is_rodata_section(section: &Elf32_Shdr, name: &str) -> bool {
    section.sh_type == SHT_PROGBITS
        && (section.sh_flags & SHF_ALLOC) == SHF_ALLOC
        && name == ".rodata"
}

/// Check if a section is .rodata1.
///
/// - `.rodata1` - This section holds additional read-only data that typically
///   contributes to a
/// non-writable segment in the process image. Similar to `.rodata`, it is used
/// for constants and string literals that should not be modified during
/// execution.
///
/// # Parameters
/// - `section` - given ELF section header struct.
/// - `name`    - given section name.
///
/// # Returns
/// - `true`  - if the given section is `.rodata1`.
/// - `false` - otherwise.
pub fn is_rodata1_section(section: &Elf32_Shdr, name: &str) -> bool {
    section.sh_type == SHT_PROGBITS
        && (section.sh_flags & SHF_ALLOC) == SHF_ALLOC
        && name == ".rodata1"
}

/// Check if a section is .shstrtab.
///
/// - `.shstrtab` - This section holds section names, which are used to identify
///   the various sections
/// in the ELF file. It is essential for the proper interpretation of the
/// section headers.
///
/// # Parameters
/// - `section` - given ELF section header struct.
/// - `name`    - given section name.
///
/// # Returns
/// - `true`  - if the given section is `.shstrtab`.
/// - `false` - otherwise.
pub fn is_shstrtab_section(section: &Elf32_Shdr, name: &str) -> bool {
    section.sh_type == SHT_STRTAB && name == ".shstrtab"
}

/// Check if a section is .strtab.
///
/// - `.strtab` - This section holds strings, most commonly the strings that
///   represent the names
/// associated with symbol table entries. If the file has a loadable segment
/// that includes the symbol string table, the section’s attributes will include
/// the SHF_ALLOC bit; otherwise, that bit will be off.
///
/// # Parameters
/// - `section` - given ELF section header struct.
/// - `name`    - given section name.
///
/// # Returns
/// - `true`  - if the given section is `.strtab`.
/// - `false` - otherwise.
pub fn is_strtab_section(section: &Elf32_Shdr, name: &str) -> bool {
    section.sh_type == SHT_STRTAB && name == ".strtab"
}

/// Check if a section is .symtab.
///
/// - `.symtab` - This section holds a symbol table, which contains information
///   about the symbols
/// used in the program. It provides a mapping between symbolic names and their
/// corresponding addresses or values. If the file has a loadable segment that
/// includes the symbol table, the section’s attributes will include the
/// `SHF_ALLOC` bit; otherwise, that bit will be off.
///
/// # Parameters
/// - `section` - given ELF section header struct.
/// - `name`    - given section name.
///
/// # Returns
/// - `true`  - if the given section is `.symtab`.
/// - `false` - otherwise.
pub fn is_symtab_section(section: &Elf32_Shdr, name: &str) -> bool {
    section.sh_type == SHT_SYMTAB && name == ".symtab"
}

/// Check if a section is .text.
///
/// - `.text` - This section holds the "text," or executable instructions, of a
///   program. It
/// contains the compiled code that the CPU executes. The section is typically
/// marked as executable and may also be marked as readable, but not writable.
///
/// # Parameters
/// - `section` - given ELF section header struct.
/// - `name`    - given section name.
///
/// # Returns
/// - `true`  - if the given section is `.text`.
/// - `false` - otherwise.
pub fn is_text_section(section: &Elf32_Shdr, name: &str) -> bool {
    section.sh_type == SHT_PROGBITS
        && (section.sh_flags & (SHF_ALLOC | SHF_EXECINSTR))
            == (SHF_ALLOC | SHF_EXECINSTR)
        && name == ".text"
}
