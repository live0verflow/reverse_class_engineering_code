#!/usr/bin/env python3

'''Print disassemblies of basic blocks.'''

import sys
## This program uses type hints.  Check it with mypy --strict.
from typing import Union, Set, List, Dict
from capstone import CsInsn # type: ignore
# Note the constants are now architecture-specific, and found in a
# different place in the library.
## X86_OP_MEM: memory operand (inc [rbx+rcx*8-8])
## X86_OP_REG: register operand (inc rcx)
## X86_OP_IMM: immediate operand (jmp 0x00000000000021e4)
## X86_GRP_JUMP: jump (1)
## X86_GRP_CALL: call (2)
## X86_GRP_RET: return (3)
## X86_GRP_INT: interrupt (4)
## X86_GRP_IRET: return from interrupt (5)
## X86_GRP_PRIVILEGE: privilege (6)
## X86_GRP_BRANCH_RELATIVE: relative branch (7)
## Note the parentheses so that the instruction can extend over multiple
## lines!
from capstone.x86 import X86_REG_RIP, X86Op # type: ignore
from capstone.x86_const import (X86_OP_MEM, X86_OP_IMM,  # type: ignore
                                X86_GRP_JUMP, X86_GRP_CALL, X86_GRP_RET,
                                X86_GRP_IRET, X86_GRP_BRANCH_RELATIVE)
from elftools.elf.elffile import ELFFile, ELFError # type: ignore
from debug import error, debug, DEBUG
from find_main import find_main
from rad import RAD
from assembly import OperandTests


class Block:
    '''Base class holding a basic block.'''

    def __init__(self, instructions: List[CsInsn], address: int):
        '''Initialize the block.

        Provide the `instructions` in the block and the block leader
        `address`.'''
        self.instructions = instructions.copy()
        self.address = address

    def get_address(self) -> int:
        '''Get the block leader's address.'''
        return self.address

    def get_instructions(self) -> List[CsInsn]:
        '''Get the sequence of instructions in this block.'''
        return self.instructions.copy()

    def __str__(self) -> str:
        '''Get a string representing the disassembly of this block.'''
        result = str()
        for inst in self.instructions:
            # Print the instruction.
            result += disassemble(inst.address, inst) + '\n'
        return result


class FunctionBlock(Block):
    '''Class to hold a function (single entry, single exit) block.'''

    def __init__(self, instructions: List[CsInsn], address: int, naddr: int):
        '''Initialize the function block.

        Provide the `instructions` in the block, the `address` of the block
        leader, and the `next` address to execute after this block, if known.
        Provide -1 if unknown, and 0 for an "exit."'''
        super().__init__(instructions, address)
        self.next = naddr

    def get_next(self) -> int:
        '''Get the next address to execute after this block.

        May be negative for "unknown" and zero for "exit."'''
        return self.next

    def __str__(self) -> str:
        '''Get a string representing the disassembly of this block.'''
        result = super().__str__()
        if self.next < 0:
            return result + 'next: unknown\n'
        return result + f'next: {self.next:#x}\n'


class PredicateBlock(Block):
    '''Class to hold a predicate (single entry, true and false branches) block.'''
    def __init__(self, instructions: List[CsInsn], address: int,
                 true: int, false: int):
        '''Initialize the predicate block.

        Provide the `instructions` in the block, the `address` of the block
        leader, and the destination addresses for the `true` and `false`
        branches, where `true` is the destination when the branch is taken,
        and `false` is the "fall through" address.'''
        super().__init__(instructions, address)
        self.true = true
        self.false = false

    def get_true(self) -> int:
        '''Get the address when the branch is taken.'''
        return self.true

    def get_false(self) -> int:
        '''Get the "fall through" address.'''
        return self.false

    def __str__(self) -> str:
        '''Get a string representing the disassembly of this block.'''
        result = super().__str__()
        result += f'on true: {self.true:#x}\n'
        result += f'on false: {self.false:#x}\n'
        return result


def main():
    '''Disassemble basic blocks based on a provided set of leaders.'''

    if len(sys.argv) < 2:
        error("Missing file name (first argument).")
        sys.exit(1)

    filename = sys.argv[1]
    try:
        # Open the file.
        file = open(filename, mode='rb')
    except OSError as err:
        error(f"Unable to open input file {filename}: {err}")
        sys.exit(1)

    try:
        # Parse the file as an ELF object.
        elf = ELFFile(file)
        rad = RAD(elf)
    except ELFError as err:
        error(f"Unable to parse {filename} as an ELF file: {err}")
        sys.exit(2)

    # Figure out what leaders we need to process.  We put them in a
    # set and go ahead and convert them all to integer values.
    if len(sys.argv) < 3:
        # Try to find main, or just use the entry point.
        entry_point = rad.get_entry_point()
        leaders = {entry_point}
        if 'nomain' not in DEBUG:
            block = extract_block(rad, set(), entry_point)
            main_func = find_main(block.get_instructions())
            if main_func[0]:
                leaders = {main_func[1]}
    else:
        # Leaders given; convert them all to integers.  Note that
        # the method used here, with map, does not allow us to check
        # them all, but just terminates at the first exception.
        try:
            leaders = set(map(lambda v: int(v, base=0), sys.argv[2:]))
        except ValueError as err:
            error(f"Invalid leader specification: {err}")
            sys.exit(5)
    debug(f"initial leaders: {[f'{leader:#x}' for leader in leaders]}")

    # The primary algorithm will run in two passes.  The first pass
    # finds basic block leaders.
    leaders = do_pass_one(rad, leaders)

    # The second pass to get the collection of block leaders.
    blocks = do_pass_two(rad, leaders)

    # Now print all the blocks, in order by leader address.
    for leader in sorted(blocks.keys()):
        block = blocks[leader]
        print(block)

    # Done!
    sys.exit(0)


def compute_target(oper: X86Op, next_address: int) -> Union[None, int]:
    '''Determine the target of the operand if it is immediate or
    rip-relative.'''
    if oper.type == X86_OP_IMM:
        return int(oper.value.imm)
    if oper.type == X86_OP_MEM and oper.value.mem.base == X86_REG_RIP:
        # Get the displacement.  Explicitly make it an int so that
        # the program can be type checked.
        return int(oper.value.mem.disp) + next_address
    return None


# Handle options used by disassembly.
GROUPS = 'groups' in DEBUG
RIP = 'rip' in DEBUG
RAW = 'raw' in DEBUG
NEWSTYLE = GROUPS or RIP or RAW or 'newstyle' in DEBUG


def disassemble(address: int, inst: CsInsn) -> str:
    '''Print the disassembly of an instruction at the given address.
    
    There are debugging settings that can affect how this is done.
    It is possible to include the computed address of all rip-relative
    references (`rip`), to include the groups of the instruction (`groups`),
    and to include the raw bytes in the output (`raw`).
    '''
    if inst.id == 0:
        return f"{address:#21_x}: data byte"
    
    grp = ""
    raw = ""
    rel = ""
    if GROUPS:
        grp = f' ; Groups: {list(map(inst.group_name, inst.groups))}'
    if RIP:
        for operand in inst.operands:
            disp = OperandTests.is_rip_relative(operand)
            if disp[0]:
                rel += f'{hex(disp[1] + inst.size + address)} '
        if len(rel) > 0:
            rel = f' ; rip-refs: {rel:12}'
    if RAW:
        for byte in inst.bytes:
            raw += f'{byte:02x} '
        if len(raw) > 0:
            raw = f'{raw:20}'
    if len(grp) > 0 or len(rel) > 0 or len(raw) > 0 or NEWSTYLE:
        return f"{address:#_x}: {raw}{inst.mnemonic:8} {inst.op_str:30}{grp}{rel}"
    return "0x%x:\t%s\t%s" %(inst.address, inst.mnemonic, inst.op_str)


def do_pass_one(rad: RAD, leaders: Set[int]) -> Set[int]:
    '''Perform pass one to find basic block leaders.

    A random-access disassembler `rad` must be provided, along with
    an initial (non-empty) set of `leaders`.  The return value is
    a new set of leaders.'''

    # Sets are lists, and python lists can be treated as stacks, so
    # we can just initialize our exploration stack with the leaders
    # we are given.  Note that we need to use copy here to make a
    # (shallow) copy of leaders so we can modify explore.
    explore = leaders.copy()

    # Run until the stack is empty.
    while explore:
        debug(f'Explore stack depth: {len(explore)}')
        # Get the next leader to explore.
        address = explore.pop()
        if not rad.in_range(address):
            # This leader is out of range.  Ignore it and keep going.
            debug(f"Ignoring leader {address:#x}: out of range")
            continue

        # Now start disassembly at that location and run until we find an
        # instruction that clearly marks the end of a basic block.  Record
        # any additional leaders we find along the way by pushing them
        # onto the stack and adding them to the leaders set.

        def add_leader(address: int) -> None:
            '''Add a leader to the sets.'''
            if address not in leaders:
                debug(f"adding leader: {address:#x}")
                explore.add(address)
                leaders.add(address)

        # Note that we *could* actually use the stack to do the full range
        # of exploration, pushing every address on there instead of using
        # an inner loop here.  However, this would likely be much less
        # efficient.

        # It is also likely that the explore loop below could be extracted
        # from both the first and second pass, and made generic, with a
        # lambda or function passed in to handle the differences.

        while True:
            # If the address is out of range, then terminate the block.
            if not rad.in_range(address):
                # The address is outside of the section.
                debug("out of section stop")
                continue

            # We don't worry here about hitting a block leader.  That will
            # be handled in pass two.

            # Get the next instruction.
            try:
                inst = rad.get_instruction(address)
                next_address = rad.next_address
            except IndexError as err:
                error(f"Failed disassembly at {address:#x}: {err}")
                break

            if inst.group(X86_GRP_CALL):
                # This is the group that contains all calls.
                debug(f"found call at {address:#x}: target is leader")
                target = compute_target(inst.operands[0], next_address)
                if target:
                    add_leader(target)
                # We do not break; continue processing this block.

            # If it is in the jump group but not in the branch_relative group,
            # then it is a plain jump.  If it is in both groups, then you need
            # to check the mnemonic.

            elif inst.group(X86_GRP_JUMP):
                target = inst.operands[0]
                if not inst.group(X86_GRP_BRANCH_RELATIVE):
                    # It is a plain jump.
                    debug("jmp stop")
                    target = compute_target(target, next_address)
                    if target:
                        debug(f"found jmp at {address:#x}: target is leader")
                        add_leader(target)
                    break
                # It is in both groups.  Check the mnemonic.
                if inst.mnemonic == 'jmp':
                    debug("jmp stop")
                    target = compute_target(target, next_address)
                    if target:
                        debug(f"found jmp at {address:#x}: target is leader")
                        add_leader(target)
                    break

                # This is all conditional branches, including loop.
                debug(f"found branch at {hex(inst.address)}; true and false are leaders")
                # The operand is always immediate.
                add_leader(inst.operands[0].value.imm)
                add_leader(next_address)
                # We do not break; continue processing this block.

            elif inst.mnemonic == 'hlt' or inst.group(X86_GRP_RET) or inst.group(X86_GRP_IRET):
                # These terminate the basic block.
                debug("hlt,ret,iret stop")
                break

            # Update the address.
            address = next_address

            # Because of the way we are switching sections, it is possible that
            # we can get into an infinite loop here with next_address reset.
            # Before we could not do that, because addresses were strictly
            # increasing, but switching sections means that the address might
            # decrease.  We guard against that by checking to see if we have
            # hit a known leader and, if so, stop here.
            if address in leaders:
                break

    return leaders


def extract_block(rad: RAD, leaders: Set[int], leader: int) -> Block:
    '''Extract a basic block.

    Given a disassembler `rad`, the set of known basic block `leaders`, and
    the address of the desired basic block's `leader`, extract and return
    the basic block.'''

    # This is a list to hold the instructions.
    instructions: List[CsInsn] = []

    # Keep the leader; use address in the loop.
    address = leader

    # Watch for a leader collision.  The first time through the loop
    # the address will be a leader, so ignore that.  This flag is used
    # to prevent the check the first time through.
    check_leader = False

    # Now go to that part of the file and disassemble until we
    # find a basic block terminator or another leader.
    while True:
        # See if we are hitting a block leader.  If so, terminate this loop
        # early.
        if check_leader and address in leaders:
            # We have reached another leader.  Break the block early.
            debug("block collision stop")
            return FunctionBlock(instructions, leader, address)
        check_leader = True

        # Get the next instruction.
        try:
            inst = rad.get_instruction(address)
            next_address = rad.next_address
        except IndexError as err:
            # Write an error, but preserve the block.
            error(f"Failed disassembly at {address:#x}: {err}")
            return FunctionBlock(instructions, leader, -1)

        # Add this to the block.
        instructions.append(inst)

        # Watch for data bytes.
        if inst.id == 0:
            address = next_address
            continue

        # Basic blocks are terminated on the following conditions.

        if inst.group(X86_GRP_CALL):
            # This is a call; nothing special to do.  We keep this so
            # that calls do not get caught by the overlapping groups
            # that follow.
            pass

        # If it is in the jump group but not in the branch_relative group,
        # then it is a plain jump.  If it is in both groups, then you need
        # to check the mnemonic.

        elif inst.group(X86_GRP_JUMP):
            target = inst.operands[0]
            if not inst.group(X86_GRP_BRANCH_RELATIVE):
                # It is a plain jump.
                debug("jmp stop")
                target = compute_target(target, next_address)
                if target:
                    return FunctionBlock(instructions, leader, target)
                return FunctionBlock(instructions, leader, -1)
            # It is in both groups.  Check the mnemonic.
            if inst.mnemonic == 'jmp':
                debug("jmp stop")
                target = compute_target(target, next_address)
                if target:
                    return FunctionBlock(instructions, leader, target)
                # Return destination unknown.
                return FunctionBlock(instructions, leader, -1)
            # Return predicate block.
            debug("branch stop")
            return PredicateBlock(instructions, leader, target.value.imm, next_address)

        elif inst.mnemonic == 'hlt' or inst.group(X86_GRP_RET) or inst.group(X86_GRP_IRET):
            # Return an exit block.
            return FunctionBlock(instructions, leader, 0)

        # Update the address.
        address = next_address


def do_pass_two(rad: RAD, leaders: Set[int]) -> Dict[int, Block]:
    '''Perform pass two to print basic blocks.

    A random-access disassembler `rad` must be provided, along with
    a set of `leaders`.  The result is a dictionary from leader address
    to the basic block.'''

    # Dictionary of blocks.
    blocks = dict()

    # Now process every basic block leader we are given.  We want to write them
    # in order by address, so first sort out list of leaders.  Note that recent
    # versions of python sort sets, but we should not count on that.
    for address in sorted(leaders):

        if not rad.in_range(address):
            # This leader is out of range.  Ignore it and keep going.
            debug(f"Ignoring leader {address:#x}: out of range")
            continue

        # Get the basic block.
        block = extract_block(rad, leaders, address)
        blocks[address] = block

    return blocks


if __name__ == '__main__':
    main()
