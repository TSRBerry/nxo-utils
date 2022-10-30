import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from nxo64.compat import iter_range

from common.demangling import ipcclient_demangle as demangle
from ipcclient.utils import hexify, shorten


def get_last_immediate_argument(insns):
    immregs = [None for _ in iter_range(32)]

    stores = {}
    for i in insns:
        if i.mnemonic == 'orr' and i.op_str.split(', ')[1] == 'wzr':
            immregs[int(i.op_str.split(', ')[0][1:])] = i.operands[2].value.imm
        elif i.mnemonic == 'mov':
            src = i.op_str.split(', ')[1]
            dest = int(i.op_str.split(', ')[0][1:])
            if src == 'wzr' or src == 'xzr':
                # noinspection PyTypeChecker
                immregs[dest] = 0
            elif src == 'sp':
                immregs[dest] = None
            else:
                immregs[dest] = immregs[int(src[1:])]
        elif i.mnemonic == 'movz':
            if i.op_str.endswith(', lsl #16'):
                immregs[int(i.op_str.split(', ')[0][1:])] = i.operands[1].value.imm << 16
            else:
                immregs[int(i.op_str.split(', ')[0][1:])] = i.operands[1].value.imm
        elif i.mnemonic == 'movk':
            immregs[int(i.op_str.split(', ')[0][1:])] |= i.operands[1].value.imm
        elif i.mnemonic == 'str' and i.reg_name(i.operands[1].value.mem.base) == 'sp':
            reg = i.reg_name(i.operands[0].value.mem.base)
            if reg == 'wzr':
                value = 0
            else:
                value = immregs[int(reg[1:])]
            stores[i.operands[1].value.mem.disp] = value
        elif i.mnemonic == 'stp' and i.reg_name(i.operands[2].value.mem.base) == 'sp':
            reg = i.reg_name(i.operands[0].value.mem.base)
            if reg == 'wzr':
                value = 0
            else:
                value = immregs[int(reg[1:])]
            stores[i.operands[2].value.mem.disp] = value

            reg = i.reg_name(i.operands[1].value.mem.base)
            if reg == 'wzr':
                value = 0
            else:
                value = immregs[int(reg[1:])]
            stores[i.operands[2].value.mem.disp + 8] = value

    if stores:
        last_store = None
        end = sorted(stores.keys())[-1] + 8
        for off in range(0, end, 8):
            if off not in stores:
                break
            val = stores[off]
            if val is not None:
                last_store = val
        if last_store is not None:
            return last_store

    for i in range(8, -1, -1):
        if immregs[i] is not None:
            return immregs[i]

    return None


is_process_function_cache = {}


def is_process_function(binstring, func_start):
    # print hex(func_start)
    if func_start in is_process_function_cache:
        return is_process_function_cache[func_start]
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    counter = 0
    try:
        i = func_start
        instr = md.disasm(binstring[i:i + 4], i).next()
        while instr.mnemonic not in ('ret',):
            # if instr.mnemonic in ('movz', 'movk'):
            #	print instr.mnemonic, repr(instr.op_str), instr.op_str.endswith(', #0x4653')
            # print instr.mnemonic
            if instr.mnemonic in ('movz', 'movk') and instr.op_str.endswith(', #0x4943, lsl #16'):
                counter += 1
            # print '...'
            elif instr.mnemonic in ('movz', 'movk') and instr.op_str.endswith(', #0x4f43, lsl #16'):
                # print '..'
                counter += 1
            elif instr.mnemonic in ('movz', 'movk') and instr.op_str.endswith(', #0x4653'):
                # print '.'
                counter += 1
            i += 4
            instr = md.disasm(binstring[i:i + 4], i).next()
        func_end = i + 4
    except StopIteration:
        is_process_function_cache[func_start] = False
        return False
    # print counter
    is_process_function_cache[func_start] = (counter in (2, 4))
    return counter in (2, 4)


def get_method_info_part(s):
    start = s.index('CoreMethodInfo<') + len('CoreMethodInfo<')
    p = start
    depth = 1
    while depth:
        if s[p] == '>':
            depth -= 1
        elif s[p] == '<':
            depth += 1
        p += 1
    return s[start:p - 1]


def get_display_method_info(name):
    tup, inbytes, outbytes, sendpid = hexify(shorten(get_method_info_part(demangle(name)))).rsplit(', ', 3)
    tup = tup[6:-1].strip().replace('ArgumentInfo<', '<').replace(', ', ',').replace('>,', '>, ')
    parts = [inbytes + ' bytes in', outbytes + ' bytes out']
    if sendpid == 'true':
        parts.append('takes pid')
    if tup:
        parts.append(tup)
    return ' - '.join(parts)


def get_method_data(name):
    tup, inbytes, outbytes, sendpid = hexify(shorten(get_method_info_part(demangle(name)))).rsplit(', ', 3)

    tup = tup[6:-1].strip().replace('ArgumentInfo<', '<').replace(', ', ',').replace('>,', '>, ')

    data = {"inbytes": int(inbytes, 16), "outbytes": int(outbytes, 16)}
    if sendpid == 'true':
        data["pid"] = True

    data['arginfo'] = tup
    return data


def find_ret(binstring, func_start):
    offset = func_start
    while struct.unpack_from('<I', binstring, offset)[0] != 0xd65f03c0:
        offset += 4
    return offset
