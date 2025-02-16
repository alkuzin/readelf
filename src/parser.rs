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

//! ELF parser module.

use crate::elf::elfhdr::*;

pub struct ElfParser {
    hdr: Elf32_Ehdr,
}

impl ElfParser {
    pub fn new(hdr: Elf32_Ehdr) -> ElfParser {
        ElfParser { hdr }
    }

    /// Print ELF header content.
    pub fn print_header(&self) {
        println!("ELF Header:");
        println!("  Magic:   {}",                                   self.get_magic());
        println!("  Class:                             {}",         self.get_class());
        println!("  Date:                              {}",         self.get_data());
        println!("  Version:                           {}",         self.get_version());
        println!("  Type:                              {}",         self.get_type());
        println!("  Machine:                           {}",         self.get_machine());
        println!("  Version:                           {:#x}",      self.hdr.e_version as u32);
        println!("  Entry point address:               {:#x}",      self.hdr.e_entry as u32);
        println!("  Start of program headers:          {} (bytes)", self.hdr.e_phoff as u32);
        println!("  Start of section headers:          {} (bytes)", self.hdr.e_shoff as u32);
        println!("  Flags:                             {:#x}",      self.hdr.e_flags as u32);
        println!("  Size of this header:               {} (bytes)", self.hdr.e_ehsize as u16);
        println!("  Size of program headers:           {} (bytes)", self.hdr.e_phentsize as u16);
        println!("  Number of program headers:         {}",         self.hdr.e_phnum as u16);
        println!("  Size of section headers:           {} (bytes)", self.hdr.e_shentsize as u16);
        println!("  Number of section headers:         {}",         self.hdr.e_shnum as u16);
        println!("  Section header string table index: {}",         self.hdr.e_shstrndx as u16);
    }

    /// Get ELF header identificator string representation.
    pub fn get_magic(&self) -> String {
        let mut s = String::with_capacity(56);

        for i in self.hdr.e_ident {
            s.push_str(format!("{:02x} ", i).as_str());
        }
        s
    }

    /// Get ELF header class string representation.
    pub fn get_class(&self) -> &str {
        match self.hdr.e_ident[EI_CLASS] {
            ELFCLASS32   => "ELF32",
            ELFCLASS64   => "ELF64",
            ELFCLASSNONE => "None",
            _            => "?"
        }
    }

    /// Get ELF header data string representation.
    pub fn get_data(&self) -> &str {
        match self.hdr.e_ident[EI_DATA] {
            ELFDATA2LSB => "Little endian",
            ELFDATA2MSB => "Big endian",
            ELFDATANONE => "None",
            _           => "?"
        }
    }

    /// Get ELF header version string representation.
    pub fn get_version(&self) -> &str {
        match self.hdr.e_ident[EI_VERSION] {
            EV_CURRENT  => "1, (current)",
            EV_NONE     => "0, (invalid)",
            _           => "?, (unknown)"
        }
    }

    /// Get ELF header type string representation.
    pub fn get_type(&self) -> &str {
        match self.hdr.e_type {
            ET_REL    => "REL (Relocatable file)",
            ET_EXEC   => "EXEC (Executable file)",
            ET_DYN    => "DYN (Shared object file)",
            ET_CORE   => "CORE (Core file)",
            ET_LOPROC => "LOPROC (Processor-specific)",
            ET_HIPROC => "HIPROC (Processor-specific)",
            ET_NONE   => "NONE (No file type)",
            _         => "? (Unknown)"
        }
    }

    /// Get ELF header machine string representation.
    pub fn get_machine(&self) -> &str {
        match self.hdr.e_machine {
            EM_NONE	 => "No machine",
            EM_M32	 => "AT&T WE 32100",
            EM_SPARC => "SUN SPARC",
            EM_386	 => "Intel 80386",
            EM_68K	 => "Motorola m68k family",
            EM_88K	 => "Motorola m88k family",
            EM_860	 => "Intel 80860",
            EM_MIPS	 => "MIPS R3000 big-endian",
            _        => "?"
        }
    }
}