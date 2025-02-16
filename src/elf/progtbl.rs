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

//! ELF program table module.

use crate::elf::{Elf32_Addr, Elf32_Off, Elf32_Word};

/// ELF program table entry struct.
///
/// An executable or shared object file’s program header table is an array of
/// structures, each describing a seg- ment or other information the system
/// needs to prepare the program for execution. An object file segment
/// contains one or more sections, as ‘‘Segment Contents’’ describes below.
/// Program headers are meaningful only for executable and shared object files.
/// A file specifies its own program header size with the ELF
/// header’s e_phentsize and e_phnum members.
#[repr(C, packed)]
pub struct Elf32_Phdr {
    /// This member tells what kind of segment this array element describes or
    /// how to interpret the array element’s information.
    pub p_type: Elf32_Word,
    /// This member gives the offset from the beginning of the file at which
    /// the first byte of the segment resides.
    pub p_offset: Elf32_Off,
    /// This member gives the virtual address at which the first byte of the
    /// segment resides in memory.
    pub p_vaddr: Elf32_Addr,
    /// On systems for which physical addressing is relevant, this member is
    /// reserved for the segment’s physical address. Because System V
    /// ignores physical addressing for application programs, this member
    /// has unspecified contents for executable files and shared objects.
    pub p_paddr: Elf32_Addr,
    /// This member gives the number of bytes in the file image of the segment;
    /// it may be zero.
    pub p_filesz: Elf32_Word,
    /// This member gives the number of bytes in the memory image of the
    /// segment; it may be zero.
    pub p_memsz: Elf32_Word,
    /// This member gives flags relevant to the segment.
    pub p_flags: Elf32_Word,
    /// As "Program Loading" later in this part describes, loadable process
    /// segments must have congruent values for p_vaddr and p_offset,
    /// modulo the page size. This member gives the value to which the
    /// segments are aligned in memory and in the file. Values 0 and 1 mean
    /// no alignment is required. Otherwise, p_align should be a power of two.
    pub p_align: Elf32_Word,
}

// ELF segment type enumeration.

/// The array element is unused; other members’ values are undefined. This type
/// lets the program header table have ignored entries.
pub const PT_NULL: u32 = 0;
/// The array element specifies a loadable segment, described by `p_filesz` and
/// `p_memsz`. The bytes from the file are mapped to the beginning of the memory
/// segment. If the segment’s memory size (`p_memsz`) is larger than the file
/// size (`p_filesz`), the "extra" bytes are defined to hold the value 0 and to
/// follow the segment’s initialized area. The file size may not be larger than
/// the memory size. Loadable segment entries in the program header table appear
/// in ascending order, sorted on the `p_vaddr` member.
pub const PT_LOAD: u32 = 1;
/// The array element specifies dynamic linking information.
pub const PT_DYNAMIC: u32 = 2;
/// The array element specifies the location and size of a null-terminated path
/// name to invoke as an interpreter. This segment type is meaningful only for
/// executable files (though it may occur for shared objects); it may not occur
/// more than once in a file. If it is present, it must precede any loadable
/// segment entry information.
pub const PT_INTERP: u32 = 3;
/// The array element specifies the location and size of auxiliary information.
pub const PT_NOTE: u32 = 4;
/// This segment type is reserved but has unspecified semantics. Programs that
/// contain an array element of this type do not conform to the ABI.
pub const PT_SHLIB: u32 = 5;
/// The array element, if present, specifies the location and size of the
/// program header table itself, both in the file and in the memory image of the
/// program. This segment type may not occur more than once in a file. Moreover,
/// it may occur only if the program header table is part of the memory image of
/// the program. If it is present, it must precede any loadable segment entry.
pub const PT_PHDR: u32 = 6;
/// Values in this inclusive range are reserved for processor-specific
/// semantics.
pub const PT_LOPROC: u32 = 0x70000000;
pub const PT_HIPROC: u32 = 0x7fffffff;
