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

//! ELF header module.

use crate::elf::{Elf32_Addr, Elf32_Half, Elf32_Off, Elf32_Word};

/// ELF header struct.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct Elf32_Ehdr {
    /// The initial bytes mark the file as an object file
    /// and provide machine-independent data with which
    /// to decode and interpret the file’s contents.
    pub e_ident: [u8; EI_NIDENT],
    /// This member identifies the object file type.
    /// Although the core file contents are unspecified,
    /// type ET_CORE is reserved to mark the
    /// file. Values from ET_LOPROC through ET_HIPROC (inclusive) are reserved
    /// for processor-specific semantics. Other values are reserved and
    /// will be assigned to new object file types as necessary.
    pub e_type: Elf32_Half,
    /// This member’s value specifies the required architecture for an
    /// individual file. Other values are reserved and will be assigned to
    /// new machines as necessary. Processor-specific ELF names use the
    /// machine name to distinguish them. For example, the flags mentioned
    /// below use the prefix EF_; a flag named WIDGET for the EM_XYZ
    /// machine would be called EF_XYZ_WIDGET.
    pub e_machine: Elf32_Half,
    /// This member identifies the object file version.
    /// The value 1 signifies the original file format; extensions will create
    /// new versions with higher numbers. The value of EV_CURRENT, though
    /// given as 1 above, will change as necessary to reflect the current
    /// version number.
    pub e_version: Elf32_Word,
    /// This member gives the virtual address to which the system first
    /// transfers control, thus starting the process. If the file has no
    /// associated entry point, this member holds zero.
    pub e_entry: Elf32_Addr,
    /// This member gives the virtual address to which the system first
    /// transfers control, thus starting the process. If the file has no
    /// associated entry point, this member holds zero.
    pub e_phoff: Elf32_Off,
    /// This member holds the section header table’s file offset in bytes.
    /// If the file has no section header table, this member holds zero.
    pub e_shoff: Elf32_Off,
    /// This member holds processor-specific flags associated with the file.
    /// Flag names take the form EF_machine_flag.
    pub e_flags: Elf32_Word,
    /// This member holds the ELF header’s size in bytes.
    pub e_ehsize: Elf32_Half,
    /// This member holds the size in bytes of one entry in the file’s program
    /// header table; all entries are the same size.
    pub e_phentsize: Elf32_Half,
    /// This member holds the number of entries in the program header table.
    /// Thus the pro- duct of e_phentsize and e_phnum gives the table’s
    /// size in bytes. If a file has no pro- gram header table, e_phnum
    /// holds the value zero.
    pub e_phnum: Elf32_Half,
    /// This member holds a section header’s size in bytes. A section header is
    /// one entry in the section header table; all entries are the same
    /// size.
    pub e_shentsize: Elf32_Half,
    /// This member holds the number of entries in the section header table.
    /// Thus the product of e_shentsize and e_shnum gives the section
    /// header table’s size in bytes. If a file has no section header
    /// table, e_shnum holds the value zero.
    pub e_shnum: Elf32_Half,
    /// This member holds the section header table index of the entry
    /// associated with the sec- tion name string table. If the file has no
    /// section name string table, this member holds the value SHN_UNDEF.
    pub e_shstrndx: Elf32_Half,
}

// ELF object file type enumeration.

/// No file type.
pub const ET_NONE: u16 = 0;
/// Relocatable file.
pub const ET_REL: u16 = 1;
/// Executable file.
pub const ET_EXEC: u16 = 2;
/// Shared object file
pub const ET_DYN: u16 = 3;
/// Core file.
pub const ET_CORE: u16 = 4;
/// Processor-specific.
pub const ET_LOPROC: u16 = 0xff00;
/// Processor-specific.
pub const ET_HIPROC: u16 = 0xffff;

// ELF machine type enumeration.

/// No machine.
pub const EM_NONE: u16 = 0;
/// AT&T WE 32100.
pub const EM_M32: u16 = 1;
/// SPARC.
pub const EM_SPARC: u16 = 2;
/// Intel 80386.
pub const EM_386: u16 = 3;
/// Motorola 68000.
pub const EM_68K: u16 = 4;
/// Motorola 88000.
pub const EM_88K: u16 = 5;
/// Intel 80860.
pub const EM_860: u16 = 7;
/// MIPS RS3000.
pub const EM_MIPS: u16 = 8;

/// File identification.
pub const EI_MAG0: usize = 0;
/// File identification.
pub const EI_MAG1: usize = 1;
/// File identification.
pub const EI_MAG2: usize = 2;
/// File identification.
pub const EI_MAG3: usize = 3;
/// ELF magic number, identifying the file as an ELF object file.
pub const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// File class.
pub const EI_CLASS: usize = 4;
/// Invalid class.
pub const ELFCLASSNONE: u8 = 0;
/// 32-bit objects.
pub const ELFCLASS32: u8 = 1;
/// 64-bit objects.
pub const ELFCLASS64: u8 = 2;

/// Data encoding.
pub const EI_DATA: usize = 5;
/// Invalid data encoding.
pub const ELFDATANONE: u8 = 0;
/// Little endian.
pub const ELFDATA2LSB: u8 = 1;
/// Big endian.
pub const ELFDATA2MSB: u8 = 2;

/// File version.
pub const EI_VERSION: usize = 6;
/// Invalid version.
pub const EV_NONE: u8 = 0;
/// Current version.
pub const EV_CURRENT: u8 = 1;

/// Start of padding bytes.
pub const EI_PAD: usize = 7;
/// Size of e_ident[].
pub const EI_NIDENT: usize = 16;
