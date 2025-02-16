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

//! Readelf entry point.

#![allow(non_camel_case_types)]
#![allow(dead_code)]

mod parser;
mod elf;

use elf::elfhdr::Elf32_Ehdr;
use parser::ElfParser;

// TODO: add command line flags handler.
static BYTES: &[u8;528] = include_bytes!("../tmp/app");


fn main() {
    let header = unsafe { *(BYTES.as_ptr() as *const Elf32_Ehdr) };

    let elf_parser = ElfParser::new(header);
    elf_parser.print_header();
}