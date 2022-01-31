#!/usr/bin/env python3

'''Provide for disassembly of an ELF file.'''

from typing import Optional, List
from capstone import (Cs, CsInsn, CS_ARCH_X86, CS_MODE_32, CS_MODE_64) # type: ignore
## X86_REG_RIP: the integer value used in Capstone for RIP
from elftools.elf.elffile import ELFFile # type: ignore
from elftools.elf.sections import Section # type: ignore
from elftools.elf.constants import SH_FLAGS # type: ignore
from debug import debug


# This converts from the constants used in ELF tools to the constants
# used in Capstone.
constants = {
    'EM_386': CS_ARCH_X86,
    'EM_X86_64': CS_ARCH_X86,
    'ELFCLASS32': CS_MODE_32,
    'ELFCLASS64': CS_MODE_64
}


class DisassemblyException(Exception):
    '''Unable to complete disassembly.'''
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg


class SectionManager:
    '''Keep track of the sections of an ELF file.'''

    def __init__(self, elf: ELFFile):
        '''Initialize from the provided elf object.'''
        self.elf = elf

    def get_section_by_address(self, address: int) -> Optional[Section]:
        '''Find and return the first section that contains the given
        address.

        Sections can overlap!  Because of this, this method returns
        either the first executable section found that contains the
        address, or (if no executable section is found) the first
        section that contains the address.

        If no section contains the given address, None is returned.'''
        found: Optional[Section] = None
        for section in self.elf.iter_sections():
            start = section.header.sh_addr
            end = start + len(section.data())
            if start <= address < end:
                if not section:
                    found = section
                if (section.header.sh_flags & SH_FLAGS.SHF_EXECINSTR) != 0:
                    return section
        return found

    def get_entry_point(self) -> int:
        '''Get the entry point of the file.'''
        return self.elf.header.e_entry


class RAD:
    '''Provide "random access" disassembly.

    To use this, make an instance, passing an ELFFile object.  Then use
    `get_instruction` to disassemble and return an instruction at a given
    address.  The field `next_address` contains the address after the
    last decoded instruction (not necessarily the next address in the flow).
    '''

    def __init__(self, elf: ELFFile):
        '''Initialize the RAD.

        The disassembler is initialized from the provided ELF file.
        Note that this class is not "fully" initialized until
        `get_instruction` has been invoked at least once.'''

        # Make a companion object to get the sections.
        self._sections = SectionManager(elf)

        # Figure out if the bit width and architecture are supported.  This
        # check should occur as soon as it can be done, since it is better
        # for a program to fail *fast*.
        bits = constants.get(elf['e_ident']['EI_CLASS'], None)
        arch = constants.get(elf['e_machine'], None)
        if arch is None:
            raise DisassemblyException(f"Unsupported architecture: {elf['e_machine']}")
        if bits is None:
            raise DisassemblyException(f"Unsupported bit width: {elf['e_ident']['EI_CLASS']}")
        self._disassembler = Cs(arch, bits)
        self._disassembler.detail = True
        self._disassembler.skipdata = True
        self.next_address: int = -1
        self._start_address: int = -1
        self._end_address: int = -1


    def get_entry_point(self) -> int:
        '''Get the address of the entry point.'''
        return self._sections.get_entry_point()


    def in_range(self, address: int) -> bool:
        '''Determine if an address is in the program or not.
        
        This returns True iff the address is found in the program in a
        section marked as executable.'''
        section = self._sections.get_section_by_address(address)
        if section:
            # In program, but might be non-executable.
            return (section.header.sh_flags & SH_FLAGS.SHF_EXECINSTR) != 0
        return False


    def get_instruction(self, address: int) -> CsInsn:
        '''Decode and return the instruction at the address.

        If the address is in the program, then it is decoded
        and returned.  Otherwise an `IndexError` exception is
        raised.

        Linear disassembly will be a bit faster because the
        instruction generator is cached.
        '''
        
        # If we don't have a current section, or the address it outside
        # the current section, get the correct section.
        if address < self._start_address or address >= self._end_address:
            debug(f'Address {address:#x} out of range; getting section')
            section = self._sections.get_section_by_address(address)
            if not section:
                raise DisassemblyException(f'The address {address:#x} is not in the program.')
            if section.header.sh_flags & SH_FLAGS.SHF_EXECINSTR == 0:
                raise DisassemblyException(f'The address {address:#x} is not executable.')
            self._start_address = section.header.sh_addr
            self._data: List[CsInsn] = section.data()
            self._end_address = self._start_address + len(self._data)
            self.next_address = -1
            debug(f'Got section {section.name}')

        # If the next address is not known, or not the requested address,
        # make a new generator.
        if (address != self.next_address):
            debug(f'Jump to address {address:#x}; building new generator')
            offset = address - self._start_address
            self._generator = self._disassembler.disasm(self._data[offset:], address)

        # Get and return the next instruction.
        insn = next(self._generator)
        self.next_address = address + len(insn.bytes)
        return insn
