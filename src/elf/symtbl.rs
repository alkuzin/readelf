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

//! ELF symbol table module.

use crate::elf::{ Elf32_Addr, Elf32_Half, Elf32_Word };


/// ELF symbol table entry struct.
///
/// An object file’s symbol table holds information needed to locate and relocate a program’s symbolic
/// definitions and references. A symbol table index is a subscript into this array. Index 0 both designates
/// the first entry in the table and serves as the undefined symbol index. The contents of the initial entry are
/// specified later in this section.
#[repr(C, packed)]
pub struct Elf32_Sym {
	/// This member holds an index into the object file’s symbol string table, which holds the
    /// character representations of the symbol names. If the value is non-zero, it represents a
    /// string table index that gives the symbol name. Otherwise, the symbol table entry has no
    /// name.
	pub st_name: Elf32_Word,
	/// This member gives the value of the associated symbol. Depending on the context, this
    /// may be an absolute value, an address, etc.; details appear below.
	pub st_value: Elf32_Addr,
	/// Many symbols have associated sizes. For example, a data object’s size is the number of
    /// bytes contained in the object. This member holds 0 if the symbol has no size or an
    /// unknown size.
	pub st_size: Elf32_Word,
	/// This member specifies the symbol’s type and binding attributes. A list of the values and
    /// meanings appears below. The following code shows how to manipulate the values.
	pub st_info: u8,
	/// This member currently holds 0 and has no defined meaning.
	pub st_other: u8,
	/// Every symbol table entry is ‘‘defined’’ in relation to some section; this member holds the
    /// relevant section header table index.
	pub st_shndx: Elf32_Half,
}

/// Extracts the binding information from the symbol info.
///
/// # Parameters
/// - `info` - given symbol info.
///
/// # Returns
/// Binding information.
pub fn elf32_st_bind(info: u8) -> u8 {
	info >> 4
}

/// Extracts the type information from the symbol info.
///
/// # Parameters
/// - `info` - given symbol info.
///
/// # Returns
/// Type information.
pub fn elf32_st_type(info: u8) -> u8 {
	info & 0xf
}

/// Combines binding and type information.
///
/// # Parameters
/// - `bind` - given symbol bind.
/// - `info` - given symbol info.
///
/// # Returns
/// Binding and type information.
pub fn elf32_st_info(bind: u8, typ: u8) -> u8 {
	(bind << 4) | (typ & 0xf)
}

// ELF symbol table binding enumeration.

/// Local symbols are not visible outside the object file containing their definition. Local
/// symbols of the same name may exist in multiple files without interfering with each
/// other.
pub const STB_LOCAL: u8 = 0;
/// Global symbols are visible to all object files being combined. One file’s definition of a
/// global symbol will satisfy another file’s undefined reference to the same global symbol.
pub const STB_GLOBAL: u8 = 1;
/// Weak symbols resemble global symbols, but their definitions have lower precedence.
pub const STB_WEAK: u8 = 2;
/// Values in this inclusive range are reserved for processor-specific semantics.
pub const STB_LOPROC: u8 = 13;
pub const STB_HIPROC: u8 = 15;

// ELF symbol table type enumeration.

/// The symbol’s type is not specified.
pub const STT_NOTYPE: u8 = 0;
/// The symbol is associated with a data object, such as a variable, an array, etc.
pub const STT_OBJECT: u8 = 1;
/// The symbol is associated with a function or other executable code.
pub const STT_FUNC: u8 = 2;
/// The symbol is associated with a section. Symbol table entries of this type exist primarily
/// for relocation and normally have STB_LOCAL binding.
pub const STT_SECTION: u8 = 3;
/// Conventionally, the symbol’s name gives the name of the source file associated with the
/// object file. A file symbol has STB_LOCAL binding, its section index is SHN_ABS, and it
/// precedes the other STB_LOCAL symbols for the file, if it is present.
pub const STT_FILE: u8 = 4;
/// Values in this inclusive range are reserved for processor-specific semantics.
pub const STT_LOPROC: u8 = 13;
pub const STT_HIPROC: u8 = 15;
