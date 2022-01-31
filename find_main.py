#!/usr/bin/env python3

'''Heuristic to find main in a compiled program.'''

from typing import List, Tuple
from capstone import CsInsn # type: ignore
from debug import debug
from assembly import OperandTests


def find_main(instructions: List[CsInsn]) -> Tuple[bool, int]:
    '''Try to find main by interpreting the given basic block as starting the
    C runtime.

    If this finds (what seems to be) main, it returns a pair consisting of
    True and the address of main.  If it does not find main, it returns a
    pair consisting of False and the value zero.
    '''

    # Bail if there aren't at least two instructions.
    if len(instructions) < 2:
        debug("Entry point too short to be C stub.")
        return (False, 0)

    # Check that the last thing is a call.
    last = instructions[-1]
    if last.mnemonic == 'hlt':
        last = instructions[-2]
    if last.mnemonic != 'call':
        # Last thing in the block must be a call.
        debug("Last effective instruction in block is not a call.")
        return (False, 0)

    # Run through this and find a setting for rdi.
    main_addr = 0
    for insn in instructions:
        # See if this is a mov or a lea.
        if insn.mnemonic != 'mov' and insn.mnemonic != 'lea':
            continue

        # See if the first operand is the rdi register.
        dest = insn.operands[0]
        sour = insn.operands[1]
        is_reg, reg_name = OperandTests.is_reg(insn, dest)
        if not is_reg or reg_name != 'rdi':
            continue

        # Find out what value is being set for rdi.
        is_imm, imm_value = OperandTests.is_imm(sour)
        if insn.mnemonic == 'mov' and is_imm:
            main_addr = imm_value
        elif insn.mnemonic == 'lea':
            is_rip, rip_value = OperandTests.is_rip_relative(sour)
            if is_rip:
                main_addr = insn.address + insn.size + rip_value

    # Either we found main or we didn't.
    if main_addr != 0:
        debug("Possible main function at " + hex(main_addr))
        return (True, main_addr)
    return (False, 0)


if __name__ == '__main__':
    print("This file contains a library; import it to use it.")
