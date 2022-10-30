import os
import struct
import sys
from io import BytesIO

from capstone import *
from unicorn import *
from unicorn.arm64_const import *

from nxo64.consts import R_AArch64
from nxo64.files import load_nxo
from common.demangling import get_demangled
from nxo64.compat import iter_range

'''
TODO: try to turn into mangled symbols:

; nn::sf::cmif::server::detail::CmifProcessFunctionTableGetterImplBase<nn::mmnv::IRequest>::ProcessServerMessage(nn::sf::IServiceObject *, nn::sf::cmif::server::CmifServerMessage *, nn::sf::detail::PointerAndSize const&)
_ZN2nn2sf4cmif6server6detail38CmifProcessFunctionTableGetterImplBaseINS_4mmnv8IRequestEE20ProcessServerMessageEPNS0_14IServiceObjectEPNS2_17CmifServerMessageERKNS0_6detail14PointerAndSizeE


; nn::sf::cmif::server::detail::CmifProcessFunctionTableGetterImpl<nn::mmnv::IRequest>::DispatchServerMessage(nn::sf::cmif::CmifOutHeader **, nn::mmnv::IRequest*, nn::sf::cmif::server::CmifServerMessage *, unsigned int, nn::sf::detail::PointerAndSize &&)
_ZN2nn2sf4cmif6server6detail34CmifProcessFunctionTableGetterImplINS_4mmnv8IRequestEE21DispatchServerMessageEPPNS1_13CmifOutHeaderEPS6_PNS2_17CmifServerMessageEjONS0_6detail14PointerAndSizeE


; nn::sf::cmif::server::detail::CmifProcessFunctionTableGetterImpl<nn::mmnv::IRequest>::Process_Initialize(nn::sf::cmif::CmifOutHeader **, nn::mmnv::IRequest*, nn::sf::cmif::server::CmifServerMessage *, nn::sf::detail::PointerAndSize &&)
_ZN2nn2sf4cmif6server6detail34CmifProcessFunctionTableGetterImplINS_4mmnv8IRequestEE18Process_InitializeEPPNS1_13CmifOutHeaderEPS6_PNS2_17CmifServerMessageEONS0_6detail14PointerAndSizeE
'''


# ALL_COMMAND_IDS = set(range(30))

def load_nxo_to_capstone(mu, fn, loadbase):
    with open(fn, 'rb') as fileobj:
        f = load_nxo(fileobj)

    stables = []
    for sym in f.symbols:
        if 's_Table' in sym.name:
            stables.append((sym.name, loadbase + sym.value))
        if sym.shndx:
            sym.resolved = loadbase + sym.value
        else:
            sym.resolved = 0

    resultw = BytesIO()
    f.binfile.seek(0)
    resultw.write(f.binfile.read_to_end())

    def write_qword(ea, val):
        resultw.seek(ea - loadbase)
        resultw.write(struct.pack('<Q', val))

    for offset, r_type, sym, addend in f.relocations:
        ea = loadbase + offset

        if r_type == R_AArch64.RELATIVE:
            assert sym is None, 'R_AARCH64_RELATIVE with sym?'
            newval = (loadbase + addend)
            write_qword(ea, newval)
        elif r_type == R_AArch64.JUMP_SLOT or r_type == R_AArch64.GLOB_DAT:
            assert sym is not None
            assert addend == 0
            newval = sym.resolved
            write_qword(ea, newval)
        elif r_type == R_AArch64.ABS64:
            assert sym is not None
            newval = sym.resolved
            if addend != 0:
                # assert sym.shndx # huge mess if we do this on an extern
                newval += addend
            write_qword(ea, newval)
        else:
            print(sys.ps1, 'TODO: r_type=0x%x sym=%r ea=%X addend=%X' % (r_type, sym, ea, addend))
            continue

    binary = resultw.getvalue()
    mu.mem_map(loadbase, (len(binary) + 0xFFF) & ~0xFFF)
    mu.mem_write(loadbase, binary)
    return stables, f.symbols, f.textsize


ADDRESS = 0x7100000000

STACK = 0x1000000
STACK_SIZE = 1024 * 1024

MEM = STACK + STACK_SIZE + 0x1000
MEM_SIZE = 1024 * 1024

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)


def demangle(s):
    value = get_demangled(s)
    pre = 'nn::sf::cmif::server::detail::CmifProcessFunctionTableGetter<'
    post = ', void>::s_Table'
    if value.startswith(pre) and value.endswith(post):
        value = value[len(pre):-len(post)]
    return value


from struct import unpack as up


def parse_npdm(npdm):
    aci0_off, aci0_size, acid_off, acid_size = up('<IIII', npdm[0x70:0x80])
    aci0, acid = npdm[aci0_off:aci0_off + aci0_size], npdm[acid_off:acid_off + acid_size]
    title_name = npdm[0x20:npdm.index('\x00', 0x20)]
    title_id = up('<Q', aci0[0x10:0x18])[0]
    fs_off, fs_sz, srv_off, srv_sz, k_off, k_sz = up('<IIIIII', acid[0x220:0x238])
    return title_name


for i in sys.argv[1:]:
    print('###', i.replace('/Volumes/BOOTCAMP/switch-titles/', '').replace('../switch-builtins/', ''))
    name = i
    if os.path.exists(i + '.npdm'):
        with open(i + '.npdm', 'rb') as f:
            name = parse_npdm(f.read())
    elif i.endswith('.kip'):
        with open(i, 'rb') as f:
            f.seek(4)
            name = f.read(12)
            name = name[:name.index(b'\0')]
    else:
        name = name.split('/')[-1].split('_')[0].split('-')[0].split('.')[0].lower()
    # title_id = i.split('/')[-3]

    print('#%r: {' % (name,))

    fname = i
    mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

    stables, symbols, text_size = load_nxo_to_capstone(mu, i, ADDRESS)
    # for i in stables:
    #	print ' s_table for', demangle(i[0]), hex(i[1]), '->', hex(struct.unpack('<Q', mu.mem_read(i[1], 8))[0])

    mu.mem_map(STACK, STACK_SIZE)
    mu.mem_map(MEM, MEM_SIZE)

    # enable FP
    addr = 0x1000
    mu.reg_write(UC_ARM64_REG_X0, 3 << 20)
    mu.mem_map(addr, 0x1000)
    fpstartinstrs = b'\x41\x10\x38\xd5\x00\x00\x01\xaa\x40\x10\x18\xd5\x40\x10\x38\xd5\xc0\x03\x5f\xd6'
    mu.mem_write(addr, fpstartinstrs)
    mu.emu_start(addr, addr + len(fpstartinstrs) - 4)
    mu.mem_unmap(addr, 0x1000)

    malloc_ptr = MEM


    def malloc(sz):
        global malloc_ptr
        o = malloc_ptr
        malloc_ptr += (sz + 15) & ~15
        return o


    MAGIC = 0x49434653


    def copy_in(buf):
        pointer = malloc(len(buf))
        mu.mem_write(pointer, buf)
        return pointer


    def dump_regs():
        values = []
        for i in range(28):
            values.append(('X%d' % i, mu.reg_read(UC_ARM64_REG_X0 + i)))
        values.append(('X29', mu.reg_read(UC_ARM64_REG_X29)))
        values.append(('X30', mu.reg_read(UC_ARM64_REG_X30)))
        values.append(('SP', mu.reg_read(UC_ARM64_REG_SP)))
        values.append(('PC', mu.reg_read(UC_ARM64_REG_PC)))
        print(', '.join('%s=%X' % i for i in values))


    message_data = struct.pack('<QQ', MAGIC, 1600) + b''.join(struct.pack('<Q', 0) for i in range(512))
    message = copy_in(message_data)

    message_struct_data = struct.pack('<QQ', message, len(message_data))
    message_struct = copy_in(message_struct_data)

    RET0 = 0x25F44002A8
    ipc_vtable = copy_in(b''.join(struct.pack('<Q', 0x800000000 + i * 8) for i in range(512)))
    ipc_object = copy_in(struct.pack('<QQ', ipc_vtable, 0))

    target_vtable = copy_in(b''.join(struct.pack('<Q', 0x900000000 + i * 8) for i in range(512)))
    target_object = copy_in(struct.pack('<QQ', target_vtable, 0))

    bufbuf = malloc(0x1000)

    outbuf = malloc(0x1000)
    from collections import defaultdict

    names = defaultdict(set)


    def hook_code(uc, address, size, user_data):
        global message_buffer
        global actual_result_thing
        i = md.disasm(str(mu.mem_read(address, 4)), address).next()
        if i.mnemonic == 'cmp' and i.op_str.endswith(', x9') and len(actual_result_thing['ininterfaces']) == 1 and \
                actual_result_thing['ininterfaces'][0] is None:
            assert i.op_str == 'x8, x9'
            x9 = mu.reg_read(UC_ARM64_REG_X9)
            mu.reg_write(UC_ARM64_REG_X8, x9)
            mu.reg_write(UC_ARM64_REG_NZCV, 0b0100)
            actual_result_thing['ininterfaces'][0] = demangle([a for a, b in stables if b == x9][0])
        # print '# 0x%X: %s' % (address, i.mnemonic + ' ' + i.op_str), hex(x9), )
        if i.mnemonic == 'bl':
            if mu.reg_read(UC_ARM64_REG_X3) != current_cmd and mu.reg_read(
                    UC_ARM64_REG_X1) == target_object and mu.reg_read(UC_ARM64_REG_X2) == ipc_object:
                if 0:
                    lines.append("  %X: %s %s (%X, %X, %X, %X)" % (address, i.mnemonic, i.op_str,
                                                                   mu.reg_read(UC_ARM64_REG_X0),
                                                                   mu.reg_read(UC_ARM64_REG_X1),
                                                                   mu.reg_read(UC_ARM64_REG_X2),
                                                                   mu.reg_read(UC_ARM64_REG_X3),
                                                                   ))
                message_buffer = mu.reg_read(UC_ARM64_REG_X3)
                #				print hex(int(i.op_str[1:],16)), '%s::Process_Cmd%d' % (demangled_interface_name, current_cmd)
                pfuncname = 'CmifProcessFunctionTableGetterImpl__%s__::Process_%s' % (
                    str(demangled_interface_name), str(cmd_name))
                names[int(i.op_str[1:], 16)].add(pfuncname)


    # print(">>> Tracing instruction at 0x%x: %s %s" % (address, i.mnemonic, i.op_str))

    buffercount = None


    def PrepareForProcess():
        existing.append(current_cmd)
        global buffercount
        global actual_result_thing
        arg = mu.reg_read(UC_ARM64_REG_X1)
        desc = [dword(arg + i) for i in range(0, 0x90, 4)]
        buffercount = desc[0x18 // 4]
        bytes_in = desc[8 // 4] - 0x10
        bytes_out = desc[0x10 // 4] - 0x10
        actual_result_thing = {
            'inbytes': bytes_in,
            'outbytes': bytes_out,
            'ininterfaces': [None] * desc[0x1c // 4],
            'outinterfaces': [None] * desc[0x20 // 4],
            'inhandles': desc[0x4C / 4:0x4C / 4 + desc[0x24 // 4]],
            'outhandles': desc[0x6C / 4:0x6C / 4 + desc[0x28 // 4]],
            'buffers': desc[0x2c / 4:0x2c / 4 + desc[0x18 // 4]],
            'pid': desc[0] == 1,

            'lr': mu.reg_read(UC_ARM64_REG_LR),
        }
        # print desc
        assert desc[0] in (0, 1)
        if True:
            for i in ['outinterfaces', 'inhandles', 'outhandles', 'buffers', 'pid', 'ininterfaces']:
                if not actual_result_thing[i]:
                    del actual_result_thing[i]
        # if desc[0x20/4] != 0:
        #	print repr()
        # if True: # desc[0]:
        # print repr((INTERFACE_NAME, current_cmd, desc)) + ','
        # print 'PrepareForProcess:', repr((demangle(INTERFACE_NAME), current_cmd, desc)) + ','

        mu.reg_write(UC_ARM64_REG_X0, 0)
        mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))
        return True  # desc[0x20/4] != 0


    # return False

    def OverwriteClientProcessId():
        o = mu.reg_read(UC_ARM64_REG_X1)
        mu.mem_write(o, struct.pack('<Q', 0))
        # print' OverwriteClientProcessId', hex(struct.unpack('<Q', mu.mem_read(mu.reg_read(UC_ARM64_REG_X1), 8))[0])
        mu.reg_write(UC_ARM64_REG_X0, 0)
        mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))
        return True


    def GetBuffers():
        # print' GetBuffers'
        outptr = mu.reg_read(UC_ARM64_REG_X1)
        for i in iter_range(outptr, outptr + buffercount * 0x10, 0x10):
            # necessary for 'nn::nifm::detail::IGeneralService' cmd 26
            mu.mem_write(i, struct.pack('<QQ', bufbuf, 0x1000))
        mu.mem_write(bufbuf, struct.pack('<Q', 1))
        mu.reg_write(UC_ARM64_REG_X0, 0)
        mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))
        return True


    def GetInNativeHandles():
        # print' GetInObjects'
        mu.reg_write(UC_ARM64_REG_X0, 0)
        mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))
        return True


    def BeginPreparingForReply():
        # print' BeginPreparingForReply'
        o = mu.reg_read(UC_ARM64_REG_X1)
        mu.mem_write(o, struct.pack('<QQ', outbuf, 0x1000))
        mu.reg_write(UC_ARM64_REG_X0, 0)
        mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))
        return True


    def EndPreparingForReply():
        # print' EndPreparingForReply'
        mu.reg_write(UC_ARM64_REG_X0, 0)
        mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))
        return False


    def SetBuffers():
        # print' SetBuffers'
        mu.reg_write(UC_ARM64_REG_X0, 0)
        mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))
        return True


    def SetOutNativeHandles():
        # print' SetOutNativeHandles'
        mu.reg_write(UC_ARM64_REG_X0, 0)
        mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))
        return True


    def SetOutObjects():
        value = struct.unpack('<Q', mu.mem_read(mu.reg_read(UC_ARM64_REG_X1) + 8, 8))[0]
        actual_result_thing['outinterfaces'][0] = demangle([a for a, b in stables if b == value][0])
        #		print' SetOutObjects %d %s' % (current_cmd, demangle([a for a,b in stables if b == value][0]))
        ##printvalue,
        # exit(1)
        # , map(hex, ))
        # exit(1)
        mu.reg_write(UC_ARM64_REG_X0, 0)
        mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))
        return False


    def BeginPreparingForErrorReply():
        # actual_result_thing[-1].append(None)
        # print ' Error? %d (%X)' % (current_cmd, mu.reg_read(UC_ARM64_REG_LR))
        return False


    def GetInObjects():
        # print' GetInObjects'
        mu.reg_write(UC_ARM64_REG_X0, 0)
        mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))
        return True


    def dword(ptr):
        return struct.unpack('I', mu.mem_read(ptr, 4))[0]


    def qword(ptr):
        return struct.unpack('Q', mu.mem_read(ptr, 8))[0]


    funcs = {
        0x800000000: PrepareForProcess,  # PrepareForProcess(nn::sf::cmif::CmifMessageMetaInfo const&)
        0x800000008: OverwriteClientProcessId,  # OverwriteClientProcessId(ulong *)
        0x800000010: GetBuffers,  # GetBuffers(nn::sf::detail::PointerAndSize *)
        0x800000018: GetInNativeHandles,  # GetInNativeHandles(nn::sf::NativeHandle *)
        0x800000020: GetInObjects,  # GetInObjects(nn::sf::cmif::server::CmifServerObjectInfo *)
        0x800000028: BeginPreparingForReply,  # BeginPreparingForReply(nn::sf::detail::PointerAndSize *)
        0x800000030: SetBuffers,  # SetBuffers(nn::sf::detail::PointerAndSize *)
        0x800000038: SetOutObjects,  # SetOutObjects(nn::sf::cmif::server::CmifServerObjectInfo *)
        0x800000040: SetOutNativeHandles,  # SetOutNativeHandles(nn::sf::NativeHandle *)
        0x800000048: BeginPreparingForErrorReply,  # BeginPreparingForErrorReply(nn::sf::detail::PointerAndSize *,ulong)
        0x800000050: EndPreparingForReply,  # EndPreparingForReply(void)
    }

    mu.hook_add(UC_HOOK_CODE, hook_code)

    for INTERFACE_NAME, stable in stables:
        try:
            TABLEFUNC = qword(stable)
            qword(TABLEFUNC)
        except UcError:
            continue
        if 'CmifDomainServerObject' in INTERFACE_NAME: continue
        # if 'ICommonStateGetter' not in INTERFACE_NAME: continue

        demangled_interface_name = demangle(INTERFACE_NAME)
        if 'nn::sf::hipc::detail::IHipcManager' == demangled_interface_name: continue
        vtaddr = None
        vtcandidates = []
        for sym in symbols:
            if demangled_interface_name.split('::')[-1] not in sym.name: continue
            if demangle(sym.name).startswith((
                    'vtable for nn::sf::detail::ObjectImplFactoryWithStatelessAllocator<nn::sf::impl::detail::ImplTemplateBase<' + demangled_interface_name + ',',
                    'vtable for nn::sf::detail::ObjectImplFactoryWithStatefulAllocator<nn::sf::impl::detail::ImplTemplateBase<' + demangled_interface_name + ',',
                    'vtable for nn::sf::UnmanagedServiceObject<' + demangled_interface_name + ',',
                    'vtable for nn::sf::UnmanagedServiceObjectByPointer<' + demangled_interface_name + ',')):

                vtaddr = ADDRESS + sym.value
                while not (ADDRESS <= struct.unpack('<Q', mu.mem_read(vtaddr, 8))[0] < ADDRESS + text_size):
                    vtaddr += 8
                    assert vtaddr < ADDRESS + sym.value + 0x40

                print('#', demangle(sym.name))
                vtname = demangled_interface_name
                if 'nn::sf::detail::EmplacedImplHolder<' in demangle(sym.name):
                    vtname = demangled_interface_name + '_IpcObj_' + \
                             demangle(sym.name).split('nn::sf::detail::EmplacedImplHolder<')[1].split('>')[0]
                elif 'nn::sf::detail::StdSmartPtrHolder<std::__1::unique_ptr<' in demangle(sym.name):
                    vtname = demangled_interface_name + '_IpcPtrObj_' + \
                             demangle(sym.name).split('nn::sf::detail::StdSmartPtrHolder<std::__1::unique_ptr<')[
                                 1].split('>')[0].split(',')[0]
                elif 'nn::sf::UnmanagedServiceObject<' in demangle(sym.name):
                    vtname = demangled_interface_name + '_IpcService_' + \
                             demangle(sym.name).split('nn::sf::UnmanagedServiceObject<')[1].split('>')[0].split(', ')[1]

                # print 'vtable: %X %s (from %r)' % (vtaddr, vtname, demangle(sym.name))
                vtcandidates.append((vtaddr, vtname))
        print('##', vtcandidates)
        print('#  ' + repr(demangled_interface_name) + ': {')
        # print '    %r: {' % ('cmds')

        existing = []

        for current_cmd in ALL_COMMAND_IDS:
            if '_ZN2nn2sf4cmif6server6detail30CmifProcessFunctionTableGetterINS_5fssrv2sf11IFileSystemEvE7s_TableE' in INTERFACE_NAME and current_cmd == 7: continue

            cmd_name = None  # namesdb.get(demangle(INTERFACE_NAME), {}).get(str(current_cmd), {}).get('name')
            if cmd_name is None:
                cmd_name = 'Cmd%d' % (current_cmd,)
            else:
                cmd_name = 'Cmd%d_%s' % (current_cmd, cmd_name)
            actual_result_thing = None
            lines = []
            message_data = struct.pack('<QQ', MAGIC, current_cmd)
            mu.mem_write(message, message_data)
            mu.mem_write(message_struct, message_struct_data)

            mu.reg_write(UC_ARM64_REG_X0, target_object)
            mu.reg_write(UC_ARM64_REG_X1, ipc_object)
            mu.reg_write(UC_ARM64_REG_X2, message_struct)
            for i in range(3, 28):
                mu.reg_write(UC_ARM64_REG_X0 + i, 0)
            mu.reg_write(UC_ARM64_REG_X30, 0x700000000)
            mu.reg_write(UC_ARM64_REG_SP, STACK + STACK_SIZE)
            mu.reg_write(UC_ARM64_REG_PC, TABLEFUNC)

            message_buffer = None
            while True:
                try:
                    # help(mu.emu_start)
                    mu.emu_start(mu.reg_read(UC_ARM64_REG_PC), 0, count=1)
                except UcError as e:
                    pc = mu.reg_read(UC_ARM64_REG_PC)
                    # print '@ pc 0x%X'
                    if pc in funcs:
                        if funcs[pc]():
                            continue
                    elif 0x900000000 <= pc < 0xA00000000:
                        # print' vcall: pc=%X lr=%X' % (pc, mu.reg_read(UC_ARM64_REG_LR))
                        actual_result_thing['vt'] = pc - 0x900000000
                        if actual_result_thing.get('outinterfaces'):
                            #							break
                            mu.reg_write(UC_ARM64_REG_X0, 0)
                            mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))
                            continue

                    # for i in lines: print i
                    #						existing.append(current_cmd)
                    elif pc == 0x700000000:
                        error = mu.reg_read(UC_ARM64_REG_X0)
                        if False:
                            if error != 0:  # and error != 0x1BA0A:
                                # for i in lines: print i
                                print('#  error = 0x%X' % error)
                    else:
                        for i in lines: print('#', i)
                        print('#', e)
                        dump_regs()
                        exit(0)
                else:
                    if mu.reg_read(UC_ARM64_REG_PC) != 0:
                        continue
                if actual_result_thing:
                    line = '      ' + ('%d: ' % current_cmd).ljust(7) + '{'
                    parts = []
                    for my_vtaddr, vtname in vtcandidates:
                        if my_vtaddr is not None and 'vt' in actual_result_thing:
                            actual_result_thing['func'] = \
                                struct.unpack('<Q', mu.mem_read(my_vtaddr + actual_result_thing['vt'], 8))[0]
                            names[actual_result_thing['func']].add(vtname + '::' + cmd_name)

                    # for i in ['vt', 'lr', 'func', 'inbytes', 'outbytes', 'buffers', 'inhandles', 'outhandles', 'outinterfaces', 'pid', 'ininterfaces']:
                    for i in ['inbytes', 'outbytes', 'buffers', 'inhandles', 'outhandles', 'outinterfaces', 'pid',
                              'ininterfaces']:
                        if i not in actual_result_thing: continue
                        # if i in ('vt', 'lr'): continue
                        v = actual_result_thing[i]
                        if isinstance(v, list):
                            v = repr(v)
                        else:
                            if v >= 10:
                                v = '0x%X' % v
                            else:
                                v = str(v)
                            v = v.rjust(5)
                        parts.append('"%s": %s' % (i, v))
                    line += ', '.join(parts)
                    # print names

                    line += '},'
                    print('#', line)  # '{%r,' % (current_cmd, actual_result_thing)
                break

        # print '    },'
        print('#  },')
    print('#},')

    if True:
        for k, v in sorted(names.items()):
            if len(v) != 1:
                print('#', hex(k), v)
            else:
                print('MakeName(0x%X,%r)' % (k, str(list(v)[0])))
