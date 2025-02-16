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

//! ELF dynamic section module.

use crate::elf::{Elf32_Addr, Elf32_Sword, Elf32_Word};

/// ELF dynamic section struct.
///
/// If an object file participates in dynamic linking, its program header table
/// will have an element of type PT_DYNAMIC. This ‘‘segment’’ contains the
/// .dynamic section. A special symbol, _DYNAMIC, labels the section, which
/// contains an array of the following structures.
#[repr(C, packed)]
struct Elf32_Dyn {
    pub d_tag: Elf32_Sword,
    pub d_un: Dyn_Union,
}

#[repr(C, packed)]
union Dyn_Union {
    /// These Elf32_Word objects represent integer values with various
    /// interpretations.
    pub d_val: Elf32_Word,
    /// These Elf32_Addr objects represent program virtual addresses. As
    /// mentioned previously, a file’s virtual addresses might not match
    /// the memory virtual addresses during execution. When interpreting
    /// addresses contained in the dynamic structure, the dynamic linker com-
    /// putes actual addresses, based on the original file value and the memory
    /// base address. For consistency, files do not contain relocation
    /// entries to ‘‘correct’’ addresses in the dynamic structure.
    pub d_ptr: Elf32_Addr,
}

// ELF dynamic tags types enumeration.

/// An entry with a `DT_NULL` tag marks the end of the `_DYNAMIC` array.
pub const DT_NULL: u32 = 0;
/// This element holds the string table offset of a null-terminated string,
/// giving the name of a needed library. The offset is an index into the table
/// recorded in the `DT_STRTAB` entry. The dynamic array may contain multiple
/// entries with this type. These entries’ relative order is significant, though
/// their relation to entries of other types is not.
pub const DT_NEEDED: u32 = 1;
/// This element holds the total size, in bytes, of the relocation entries
/// associated with the procedure linkage table. If an entry of type `DT_JMPREL`
/// is present, a `DT_PLTRELSZ` must accompany it.
pub const DT_PLTRELSZ: u32 = 2;
/// This element holds an address associated with the procedure linkage table
/// and/or the global offset table. See this section in the processor supplement
/// for details.
pub const DT_PLTGOT: u32 = 3;
/// This element holds the address of the symbol hash table. This hash table
/// refers to the symbol table referenced by the `DT_SYMTAB` element.
pub const DT_HASH: u32 = 4;
/// This element holds the address of the string table, described in Part 1.
/// Symbol names, library names, and other strings reside in this table.
pub const DT_STRTAB: u32 = 5;
/// This element holds the address of the symbol table, described in Part 1,
/// with `Elf32_Sym` entries for the 32-bit class of files.
pub const DT_SYMTAB: u32 = 6;
/// This element holds the address of a relocation table.
/// Entries in the table have explicit addends, such as `Elf32_Rela` for the
/// 32-bit file class. An object file may have multiple relocation sections.
/// When building the relocation table for an executable or shared object file,
/// the link editor concatenates those sections to form a single table.
/// If this element is present, the dynamic structure must also have `DT_RELASZ`
/// and `DT_RELAENT` elements. When relocation is "mandatory" for a file, either
/// `DT_RELA` or `DT_REL` may occur (both are permitted but not required).
pub const DT_RELA: u32 = 7;
/// This element holds the total size, in bytes, of the `DT_RELA` relocation
/// table.
pub const DT_RELASZ: u32 = 8;
/// This element holds the size, in bytes, of the `DT_RELA` relocation entry.
pub const DT_RELAENT: u32 = 9;
/// This element holds the size, in bytes, of the string table.
pub const DT_STRSZ: u32 = 10;
/// This element holds the size, in bytes, of a symbol table entry.
pub const DT_SYMENT: u32 = 11;
/// This element holds the address of the initialization function.
pub const DT_INIT: u32 = 12;
/// This element holds the address of the termination function.
pub const DT_FINI: u32 = 13;
/// This element holds the string table offset of a null-terminated string,
/// giving the name of the shared object. The offset is an index into the table
/// recorded in the `DT_STRTAB` entry.
pub const DT_SONAME: u32 = 14;
/// This element holds the string table offset of a null-terminated search
/// library search path string. The offset is an index into the table recorded
/// in the `DT_STRTAB` entry.
pub const DT_RPATH: u32 = 15;
/// This element’s presence in a shared object library alters the dynamic
/// linker’s symbol resolution algorithm for references within the library.
/// Instead of starting a symbol search with the executable file, the dynamic
/// linker starts from the shared object itself. If the shared object fails to
/// supply the referenced symbol, the dynamic linker then searches the
/// executable file and other shared objects as usual.
pub const DT_SYMBOLIC: u32 = 16;
/// This element is similar to `DT_RELA`, except its table has implicit addends,
/// such as `Elf32_Rel` for the 32-bit file class. If this element is present,
/// the dynamic structure must also have `DT_RELSZ` and `DT_RELENT` elements.
pub const DT_REL: u32 = 17;
/// This element holds the total size, in bytes, of the `DT_REL` relocation
/// table.
pub const DT_RELSZ: u32 = 18;
/// This element holds the size, in bytes, of the `DT_REL` relocation entry.
pub const DT_RELENT: u32 = 19;
/// This member specifies the type of relocation entry to which the procedure
/// linkage table refers. The `d_val` member holds `DT_REL` or `DT_RELA`, as
/// appropriate. All relocations in a procedure linkage table must use the same
/// relocation.
pub const DT_PLTREL: u32 = 20;
/// This member is used for debugging. Its contents are not specified for the
/// ABI; programs that access this entry are not ABI-conforming.
pub const DT_DEBUG: u32 = 21;
/// This member’s absence signifies that no relocation entry should cause a
/// modification to a non-writable segment, as specified by the segment
/// permissions in the program header table. If this member is present, one or
/// more relocation entries might request modifications to a non-writable
/// segment, and the dynamic linker can prepare accordingly.
pub const DT_TEXTREL: u32 = 22;
/// If present, this entry’s `d_ptr` member holds the address of relocation
/// entries associated solely with the procedure linkage table. Separating these
/// relocation entries lets the dynamic linker ignore them during process
/// initialization, if lazy binding is enabled. If this entry is present, the
/// related entries of types `DT_PLTRELSZ` and `DT_PLTREL` must also be present.
pub const DT_JMPREL: u32 = 23;
/// Values in this inclusive range are reserved for processor-specific
/// semantics.
pub const DT_LOPROC: u32 = 0x70000000;
pub const DT_HIPROC: u32 = 0x7fffffff;
