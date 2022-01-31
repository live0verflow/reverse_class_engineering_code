#!/usr/bin/env python3

'''Support routines for working with a disassembly.'''

from typing import Union, Dict, Tuple
from capstone import CsInsn
from capstone.x86 import X86Op, X86_REG_RIP # type: ignore
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG # type: ignore


class OperandTests:
    '''Provide some common tests on operands.

    This class provides static methods to test the operand of an instruction.
    To use it, just call the appropriate method.
    '''

    @staticmethod
    def is_mem(inst: CsInsn, operand: X86Op) -> Tuple[bool, Dict[str, Union[str, int]]]:
        '''Provided with an operand, determine if it is a memory reference.

        An instruction `inst` is required to enable getting the register names.

        This method returns a pair consisting of a Boolean that is True iff
        the operand is a memory reference, and dictionary explained below.

        For a memory reference, the dictionary will have the following keys.

          segment .............. segment register name
          base ................. base register name
          index ................ index register name
          scale ................ scale factor, 1, 2, 4, or 8
          disp ................. displacement value

        If it is not a memory reference, then the dictionary is empty.
        '''
        if operand.type == X86_OP_MEM:
            return (True, {
                'segment': inst.reg_name(operand.value.mem.segment),
                'base': inst.reg_name(operand.value.mem.base),
                'index': inst.reg_name(operand.value.mem.index),
                'scale': int(operand.value.mem.scale),
                'disp': int(operand.value.mem.disp)
            })
        return (False, {})

    @staticmethod
    def is_imm(oper: X86Op) -> Tuple[bool, int]:
        '''Provided with an operand, determine if it is immediate.

        This method returns a pair consisting of a Boolean that is True iff
        the operand is immediate, and the immediate value or zero if not
        immediate.
        '''
        if oper.type == X86_OP_IMM:
            return (True, oper.value.imm)
        return (False, 0)

    @staticmethod
    def is_reg(inst: CsInsn, oper: X86Op) -> Tuple[bool, str]:
        '''Provided with an operand, determine if it is a register.

        An instruction `inst` is required to enable getting the register names.

        This method returns a pair consisting of a Boolean that is True iff
        the operand is a register, and the register name or the empty string
        if it is not a register.
        '''
        if oper.type == X86_OP_REG:
            return (True, inst.reg_name(oper.value.reg))
        return (False, '')

    @staticmethod
    def is_rip_relative(oper: X86Op) -> Tuple[bool, int]:
        '''Determine if an operand is RIP-relative.

        This method returns a pair consisting of a Boolean that is True iff
        the operand is a rip-relative address, and the displacement or the
        value zero if it is not a rip-relative address.

        N.B.: This returns the displacement, not the address!  Add the value
        of rip to obtain the correct address.
        '''
        if oper.type == X86_OP_MEM and oper.value.mem.base == X86_REG_RIP:
            return (True, oper.value.mem.disp)
        return (False, 0)
