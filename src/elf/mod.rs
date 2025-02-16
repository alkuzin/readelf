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

//! ELF module.

pub mod elfhdr;
pub mod sechdr;
pub mod symtbl;
pub mod reloc;
pub mod progtbl;
pub mod dynsec;

// ELF 32 types.
pub type Elf32_Addr  = u32;
pub type Elf32_Half  = u16;
pub type Elf32_Off   = u32;
pub type Elf32_Sword = i32;
pub type Elf32_Word  = u32;