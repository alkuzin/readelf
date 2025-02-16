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

//! ELF relocation module.

use crate::elf::{ Elf32_Addr, Elf32_Half, Elf32_Sword, Elf32_Word };


/// ELF relocation entry struct.
///
/// Relocation is the process of connecting symbolic references with symbolic definitions. For example, when
/// a program calls a function, the associated call instruction must transfer control to the proper destination
/// address at execution. In other words, relocatable files must have information that describes how to
/// modify their section contents, thus allowing executable and shared object files to hold the right informa-
/// tion for a process’s program image. Relocation entries are these data.
#[repr(C, packed)]
pub struct Elf32_Rel {
	/// This member gives the location at which to apply the relocation action. For a relocatable
    /// file, the value is the byte offset from the beginning of the section to the storage unit affected
    /// by the relocation. For an executable file or a shared object, the value is the virtual address of
    /// the storage unit affected by the relocation.
	pub r_offset: Elf32_Addr,
	/// This member gives both the symbol table index with respect to which the relocation must be
    /// made, and the type of relocation to apply. For example, a call instruction’s relocation entry
    /// would hold the symbol table index of the function being called. If the index is STN_UNDEF,
    /// the undefined symbol index, the relocation uses 0 as the ‘‘symbol value.’’ Relocation types
    /// are processor-specific. When the text refers to a relocation entry’s relocation type or symbol
    /// table index, it means the result of applying ELF32_R_TYPE or ELF32_R_SYM, respectively,
    /// to the entry’s r_info member.
	pub r_info: Elf32_Word
}

/// ELF relocation entry struct.
#[repr(C, packed)]
pub struct Elf32_Rela {
	/// This member gives the location at which to apply the relocation action. For a relocatable
    /// file, the value is the byte offset from the beginning of the section to the storage unit affected
    /// by the relocation. For an executable file or a shared object, the value is the virtual address of
    /// the storage unit affected by the relocation.
	pub r_offset: Elf32_Addr,
	/// This member gives both the symbol table index with respect to which the relocation must be
    /// made, and the type of relocation to apply. For example, a call instruction’s relocation entry
    /// would hold the symbol table index of the function being called. If the index is STN_UNDEF,
    /// the undefined symbol index, the relocation uses 0 as the ‘‘symbol value.’’ Relocation types
    /// are processor-specific. When the text refers to a relocation entry’s relocation type or symbol
    /// table index, it means the result of applying ELF32_R_TYPE or ELF32_R_SYM, respectively,
    /// to the entry’s r_info member.
	pub r_info: Elf32_Word,
	/// This member specifies a constant addend used to compute the value to be stored into the
    /// relocatable field.
	pub r_addend: Elf32_Sword
}

/// Extracts the symbol index from the relocation info.
///
/// # Parameters
/// - `info` - given relocation info.
///
/// # Returns
/// Symbol index.
pub fn elf32_r_sym(info: u32) -> u32 {
	info >> 8
}

/// Extracts the type from the relocation info.
///
/// # Parameters
/// - `info` - given relocation info.
///
/// # Returns
/// Relocation type.
pub fn elf32_r_type(info: u32) -> u8 {
	(info & 0xff) as u8
}

/// Combines the symbol index and type.
///
/// # Parameters
/// - `sym` - given symbol index.
/// - `type` - given relocation type.
///
/// # Returns
/// Relocation info.
pub fn elf32_r_info(sym: u32, typ: u8) -> u32 {
	(sym << 8) | (typ as u32)
}

/// ELF relocation type enumeration.
///
/// - `A` - This means the addend used to compute the value of the relocatable field.
/// - `P` - This means the place (section offset or address) of the storage unit being relocated (computed using r_offset).
/// - `S` - This means the value of the symbol whose index resides in the relocation entry.

/// No relocation is needed.
pub const R_386_NONE: u32 = 0;
/// Relocation type for a 32-bit word: S + A.
pub const R_386_32: u32 = 1;
/// Relocation type for a 32-bit word: S + A - P.
pub const R_386_PC32: u32 = 2;
/// This relocation type computes the distance from the base of the global offset table to the
/// symbol’s global offset table entry. It additionally instructs the link editor to build a
/// global offset table.
pub const R_386_GOT32: u32 = 3;
/// This relocation type computes the address of the symbol’s procedure linkage table entry and
/// additionally instructs the link editor to build a procedure linkage table.
pub const R_386_PLT32: u32 = 4;
/// No relocation is needed.
pub const R_386_COPY: u32 = 5;
/// This relocation type is used to set a global offset table entry to the address of the specified symbol.
/// It allows one to determine the correspondence between symbols and global offset table entries.
pub const R_386_GLOB_DAT: u32 = 6;
/// This relocation type is created for dynamic linking. Its offset member gives the location of a
/// procedure linkage table entry. The dynamic linker modifies the procedure linkage table entry
/// to transfer control to the designated symbol’s address.
pub const R_386_JMP_SLOT: u32 = 7;
/// The link editor creates this relocation type for dynamic linking. Its offset member gives a
/// location within a shared object that contains a value representing a relative address. The
/// dynamic linker computes the corresponding virtual address by adding the virtual address at
/// which the shared object was loaded to the relative address. Relocation entries for this type
/// must specify 0 for the symbol table index.
pub const R_386_RELATIVE: u32 = 8;
/// This relocation type computes the difference between a symbol’s value and the address of the
/// global offset table. It additionally instructs the link editor to build the global offset table.
pub const R_386_GOTOFF: u32 = 9;
/// This relocation type resembles R_386_PC32, except it uses the address of the global offset
/// table in its calculation. The symbol referenced in this relocation normally is
/// _GLOBAL_OFFSET_TABLE_, which additionally instructs the link editor to build the global
/// offset table.
pub const R_386_GOTPC: u32 = 10;