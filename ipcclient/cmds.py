import hashlib
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64_const import ARM64_OP_IMM
from nxo64.compat import iter_range

from ipcclient.functions import find_ret, is_process_function, get_last_immediate_argument


def get_function_cmd_id_old(binstring, func_start, func_end, rostart, roend):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    counter = 0
    got_movz = False
    got_movk = False
    for i in iter_range(func_start, func_end, 4):
        try:
            instr = next(md.disasm(binstring[i:i + 4], i))
        except StopIteration:
            return None
        if instr.mnemonic == 'movz' and instr.op_str.endswith(', #0x4f43, lsl #16'):
            got_movz = True
        elif instr.mnemonic == 'movk' and instr.op_str.endswith(', #0x4653'):
            got_movk = True
        if got_movk and got_movz:
            break

    if not got_movz and got_movk:
        return None

    md.detail = True
    constants = {}
    for i in iter_range(func_start, func_end, 4):
        try:
            instr = next(md.disasm(binstring[i:i + 4], i))
        except StopIteration:
            return None

        if instr.mnemonic == 'adrp':
            reg_name = instr.reg_name(instr.operands[0].value.reg)
            constants[reg_name] = instr.operands[1].value.imm
        elif instr.mnemonic == 'add' and instr.operands[2].type == ARM64_OP_IMM:
            reg_name = instr.reg_name(instr.operands[1].value.reg)
            if reg_name in constants:
                loc = instr.operands[2].value.imm + constants[reg_name]
                if rostart <= loc <= roend - 0x10:
                    if binstring[loc:loc + 8] == 'SFCI\0\0\0\0':
                        return struct.unpack_from('<Q', binstring, loc + 8)[0]
                if instr.reg_name(instr.operands[1].value.reg) == reg_name:
                    del constants[reg_name]
        elif instr.mnemonic in ('bl', 'blr'):
            constants = {}

    return None


def get_function_cmd_id(binstring, func_start, plt_lookup, rostart, roend):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    func_end = find_ret(binstring, func_start) + 4
    # print 'func_end: 0x%X' % func_end
    calls = 0
    block_starts = set()
    block_starts.add(func_start)
    for i in iter_range(func_start, func_end, 4):
        try:
            insn = next(md.disasm(binstring[i:i + 4], i))
        except StopIteration:
            break
        if insn.mnemonic in ('bl', 'blr'):
            calls += 1
            block_starts.add(i + 4)
        elif insn.mnemonic == 'cbz':
            block_starts.add(i + 4)
            block_starts.add(insn.operands[1].value.imm)

    if calls >= 4:
        cmd_id_old = get_function_cmd_id_old(binstring, func_start, func_end, rostart, roend)
        if cmd_id_old is not None:
            return cmd_id_old, None

    # print block_starts
    if len(block_starts) < 2 or len(block_starts) > 7:
        return None

    blocks = []
    for i in iter_range(func_start, func_end, 4):
        try:
            insn = next(md.disasm(binstring[i:i + 4], i))
        except StopIteration:
            break
        if i in block_starts:
            blocks.append([])
        blocks[-1].append(insn)

    argsblock = None
    for block in blocks[::-1]:
        if block[-1].mnemonic == 'bl':
            argsblock = block
            break
    if not argsblock:
        return None
    process_function = argsblock[-1].operands[0].value.imm
    process_function = plt_lookup.get(process_function, process_function)
    if not is_process_function(binstring, process_function):
        # print 'not_process_function'
        return None

    # keep it simple by skipping all instructions that do not generate immediates
    pos = 0
    while (pos < len(argsblock) and
           argsblock[pos].mnemonic in ('stp', 'mov', 'str', 'add', 'ldr', 'and', 'ldp') and
           'wzr' not in argsblock[pos].op_str):
        pos += 1

    # noinspection PyUnboundLocalVariable
    result = get_last_immediate_argument(block[pos:])
    # if result is None:
    #	print block[pos:]

    return result, process_function


def get_cmd_id_hash(vt):
    return hashlib.sha224(','.join('%d' % i for i in vt if i is not None)).hexdigest()[:8]
