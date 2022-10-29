import sys
import re
import bisect
import hashlib

from simulators import DEFAULT_LOAD_BASE, IPCServerSimulator
from known_cmd_ids import all_known_command_ids 
from nxo64.files import load_nxo
from demangling import get_demangled

from hashes import all_hashes, all_hashes_300

'''
TODO: try to turn into mangled symbols:

; nn::sf::cmif::server::detail::CmifProcessFunctionTableGetterImplBase<nn::mmnv::IRequest>::ProcessServerMessage(nn::sf::IServiceObject *, nn::sf::cmif::server::CmifServerMessage *, nn::sf::detail::PointerAndSize const&)
_ZN2nn2sf4cmif6server6detail38CmifProcessFunctionTableGetterImplBaseINS_4mmnv8IRequestEE20ProcessServerMessageEPNS0_14IServiceObjectEPNS2_17CmifServerMessageERKNS0_6detail14PointerAndSizeE


; nn::sf::cmif::server::detail::CmifProcessFunctionTableGetterImpl<nn::mmnv::IRequest>::DispatchServerMessage(nn::sf::cmif::CmifOutHeader **, nn::mmnv::IRequest*, nn::sf::cmif::server::CmifServerMessage *, unsigned int, nn::sf::detail::PointerAndSize &&)
_ZN2nn2sf4cmif6server6detail34CmifProcessFunctionTableGetterImplINS_4mmnv8IRequestEE21DispatchServerMessageEPPNS1_13CmifOutHeaderEPS6_PNS2_17CmifServerMessageEjONS0_6detail14PointerAndSizeE


; nn::sf::cmif::server::detail::CmifProcessFunctionTableGetterImpl<nn::mmnv::IRequest>::Process_Initialize(nn::sf::cmif::CmifOutHeader **, nn::mmnv::IRequest*, nn::sf::cmif::server::CmifServerMessage *, nn::sf::detail::PointerAndSize &&)
_ZN2nn2sf4cmif6server6detail34CmifProcessFunctionTableGetterImplINS_4mmnv8IRequestEE18Process_InitializeEPPNS1_13CmifOutHeaderEPS6_PNS2_17CmifServerMessageEONS0_6detail14PointerAndSizeE
'''


def demangle(s):
    value = get_demangled(s)
    pre = b'nn::sf::cmif::server::detail::CmifProcessFunctionTableGetter<'
    post = b', void>::s_Table'
    if value.startswith(pre) and value.endswith(post):
        value = value[len(pre):-len(post)]
    return value


def iter_traces(command_ids_to_try, simulator, process_function):
    cmd_id = 0
    while True:
        trace = simulator.trace_cmd(process_function, cmd_id)
        if trace.description is not None:
            yield trace
            cmd_id += 1
        else:
            if trace.branch_tracer.range_top == 0xFFFFFFFF:
                break
            assert trace.branch_tracer.range_top >= cmd_id
            cmd_id = trace.branch_tracer.range_top + 1


def get_hashes(traces):
    prior_rets = {}
    hash_code_parts = []

    for trace in traces:
        description = trace.description
        # accumulate hash code
        suffix = ''
        if 'outinterfaces' in description:
            out_obj_name = description['outinterfaces'][0]
            if out_obj_name not in prior_rets:
                prior_rets[out_obj_name] = len(prior_rets)
            suffix = ';o%d' % prior_rets[out_obj_name]

        buffers = description.get('buffers', [])
        # didn't realize this was getting counted in the client code, but easier
        # to fix it here
        c_desc_size_extr = (buffers.count(10) + buffers.count(34)) * 2
        if buffers:
            suffix += ';b' + ','.join('%d' % i for i in buffers)
        suffix += ')'

        hash_code = '%d(%d%s' % (trace.cmd_id, (trace.bytes_in + 3 + c_desc_size_extr) / 4, suffix)
        hash_code2 = '%d(%d%s' % (trace.cmd_id, (trace.bytes_in + 3) / 4, suffix)
        hash_code_parts.append((description.get('vt'), hash_code.encode(), hash_code2.encode()))

    hash_code_parts.sort()
    hash_code = b''.join(b for a, b, c in hash_code_parts)
    hash_code2 = b''.join(c for a, b, c in hash_code_parts)
    hashed = hashlib.sha224(hash_code).hexdigest()[:16]
    hashed2 = hashlib.sha224(hash_code2).hexdigest()[:16]

    return hashed, hashed2, hash_code, hash_code2


def find_hash_matches(hashed, hashed2):
    probably = None
    old_version = False
    if hashed in all_hashes:
        probably = all_hashes[hashed]
    elif hashed2 in all_hashes:
        probably = all_hashes[hashed2]
    elif hashed in all_hashes_300:
        old_version = True
        probably = all_hashes_300[hashed]
    elif hashed2 in all_hashes_300:
        old_version = True
        probably = all_hashes_300[hashed2]
    return probably, old_version


def get_bracketed(msg):
    cnt, ofs = 0, 0
    while ofs < len(msg):
        if msg[ofs] == '>':
            if cnt == 0:
                break
            else:
                cnt -= 1
        elif msg[ofs] == '<':
            cnt += 1
        ofs += 1
    msg = msg[:ofs]
    if ',' in msg:
        msg = msg[:msg.index(',')]
    return msg


def get_interface_name(intf_name):
    demangled_interface_name = demangle(intf_name)
    # print demangled_interface_name
    if demangled_interface_name.startswith(
            b'nn::sf::detail::ObjectImplFactoryWithStatelessAllocator<nn::sf::impl::detail::ImplTemplateBase<'):
        vtname = demangled_interface_name[
                 len(b'nn::sf::detail::ObjectImplFactoryWithStatelessAllocator<nn::sf::impl::detail::ImplTemplateBase<'):]
        vtname = vtname[:vtname.index(',')]
        return vtname
    elif demangled_interface_name.startswith(
            b'nn::sf::detail::ObjectImplFactoryWithStatefulAllocator<nn::sf::impl::detail::ImplTemplateBase<'):
        vtname = demangled_interface_name[
                 len(b'nn::sf::detail::ObjectImplFactoryWithStatefulAllocator<nn::sf::impl::detail::ImplTemplateBase<'):]
        vtname = vtname[:vtname.index(',')]
        return vtname
    elif demangled_interface_name.startswith(b'nn::sf::UnmanagedServiceObject<'):
        return get_bracketed(demangled_interface_name[len(b'nn::sf::UnmanagedServiceObject<'):])
    else:
        return demangled_interface_name


def get_interface_msg(intf_name):
    demangled_interface_name = demangle(intf_name)
    if b'nn::sf::detail::UnmanagedPointerHolder<' in demangled_interface_name:
        msg = demangled_interface_name[demangled_interface_name.index(b'nn::sf::detail::UnmanagedPointerHolder<') + len(
            b'nn::sf::detail::UnmanagedPointerHolder<'):]
        return b'IpcPtrObj_' + get_bracketed(msg)
    if b'nn::sf::detail::UnmanagedServiceObject<' in demangled_interface_name:
        msg = demangled_interface_name[demangled_interface_name.index(b'nn::sf::detail::UnmanagedServiceObject<') + len(
            b'nn::sf::detail::UnmanagedServiceObject<'):]
        return b'IpcService_' + get_bracketed(msg)
    if b'nn::sf::UnmanagedServiceObject<' in demangled_interface_name:
        msg = demangled_interface_name[demangled_interface_name.index(b'nn::sf::UnmanagedServiceObject<') + len(
            b'nn::sf::UnmanagedServiceObject<'):]
        return b'IpcService_' + get_bracketed(msg)
    elif b'nn::sf::detail::EmplacedImplHolder<' in demangled_interface_name:
        msg = demangled_interface_name[demangled_interface_name.index(b'nn::sf::detail::EmplacedImplHolder<') + len(
            b'nn::sf::detail::EmplacedImplHolder<'):]
        return b'IpcObj_' + get_bracketed(msg)
    elif b'nn::sf::detail::StdSmartPtrHolder<std::__1::unique_ptr<' in demangled_interface_name:
        msg = demangled_interface_name[
              demangled_interface_name.index(b'nn::sf::detail::StdSmartPtrHolder<std::__1::unique_ptr<') + len(
                  b'nn::sf::detail::StdSmartPtrHolder<std::__1::unique_ptr<'):]
        return b'IpcService' + get_bracketed(msg)
    return None


def get_vt_size(traces):
    if len(traces) == 0:
        return 0
    return max(len(traces), (max(t.description['vt'] for t in traces if 'vt' in t.description) + 8 - 0x20) / 8)


def try_match(trace_set, ipc_infos):
    ipcset = {}
    found = []
    found_any = True
    while found_any:
        found_any = False
        for i, traces in enumerate(trace_set):
            if i in ipcset:
                continue
            possibles = [x for x in ipc_infos if len(x['funcs']) == get_vt_size(traces)]
            if len(possibles) == 1:
                ipcset[i] = possibles[0]
                del ipc_infos[ipc_infos.index(possibles[0])]
                found.append(traces)
                found_any = True
                continue
            possibles = [x for x in ipc_infos if len(x['funcs']) >= get_vt_size(traces)]
            if len(possibles) == 1:
                ipcset[i] = possibles[0]
                del ipc_infos[ipc_infos.index(possibles[0])]
                found.append(traces)
                found_any = True
                continue
            for x in possibles:
                if len([t for t in trace_set if t not in found and get_vt_size(t) <= len(x['funcs'])]) == 1:
                    ipcset[i] = x
                    del ipc_infos[ipc_infos.index(x)]
                    found.append(traces)
                    found_any = True
                    break
    return ipcset, ipc_infos


PUBLIC = False


def dump_ipc_filename(fname):
    with open(fname, 'rb') as fileobj:
        f = load_nxo(fileobj)

    simulator = IPCServerSimulator(f)

    # Get .got
    data_syms = {}
    fptr_syms = {}
    got_data_syms = {}
    got = [(start, end, name, section_type) for start, end, name, section_type in f.sections if name == '.got'][0]
    for offset, r_type, sym, addend in f.relocations:
        if offset < got[0] or got[1] < offset:
            continue
        if f.dataoff <= offset < f.dataoff + f.datasize:
            if sym and sym.shndx and sym.value < f.textsize:
                fptr_syms[offset] = sym.value
            elif addend and addend < f.textsize:
                fptr_syms[offset] = addend
            elif sym and sym.shndx and sym.value:
                data_syms[offset] = sym.value
            elif addend:
                data_syms[offset] = addend
            if offset in data_syms and (got[0] <= offset or offset <= got[1]):
                got_data_syms[offset] = data_syms[offset]
    vt_infos = {}
    for offset in got_data_syms:
        vt_ofs = got_data_syms[offset]
        if f.dataoff <= vt_ofs <= f.dataoff + f.datasize:
            rtti_ofs = simulator.qword(DEFAULT_LOAD_BASE + vt_ofs + 8) - DEFAULT_LOAD_BASE
            if f.dataoff <= rtti_ofs <= f.dataoff + f.datasize:
                this_ofs = simulator.qword(DEFAULT_LOAD_BASE + rtti_ofs + 8) - DEFAULT_LOAD_BASE
                if f.rodataoff <= this_ofs <= f.rodataoff + f.rodatasize:
                    sym = f.binfile.read_from('512s', this_ofs)
                    if b'\x00' in sym:
                        sym = sym[:sym.index(b'\x00')]
                        if b'UnmanagedServiceObject' in sym or sym in [
                            b'N2nn2sf4cmif6server23CmifServerDomainManager6DomainE']:
                            vt_infos[sym] = vt_ofs
    # Locate a known IPC vtable
    known_func = None
    for sym in vt_infos:
        vt_ofs = vt_infos[sym]
        if known_func is None:
            known_func = simulator.qword(DEFAULT_LOAD_BASE + vt_ofs + 0x20)
        else:
            assert known_func == simulator.qword(DEFAULT_LOAD_BASE + vt_ofs + 0x20)
    # Find all IPC vtables
    ipc_vts = {}
    for offset in got_data_syms:
        vt_ofs = got_data_syms[offset]
        vt_base = vt_ofs + DEFAULT_LOAD_BASE
        if f.dataoff <= vt_ofs <= f.dataoff + f.datasize:
            if simulator.qword(vt_base + 0x20) == known_func:
                vt = []
                ofs = 0x30
                while simulator.qword(vt_base + ofs) != 0:
                    func = simulator.qword(vt_base + ofs)
                    func_ofs = func - DEFAULT_LOAD_BASE
                    if f.textoff <= func_ofs <= f.textoff + f.textsize:
                        vt += [func]
                        ofs += 8
                    else:
                        break
                    if vt_ofs + ofs in got_data_syms.values():
                        break
                if len(set(vt)) > 1 or len(vt) == 1:
                    ipc_vts[vt_base] = vt
    ipc_infos = []
    # Check for RTTI
    for vt_base in ipc_vts:
        ipc_info = {'base': vt_base + 0x10, 'funcs': ipc_vts[vt_base]}
        rtti_base = simulator.qword(vt_base + 8)
        if rtti_base != 0:
            rtti_ofs = rtti_base - DEFAULT_LOAD_BASE
            assert f.dataoff <= rtti_ofs <= f.dataoff + f.datasize
            this_ofs = simulator.qword(DEFAULT_LOAD_BASE + rtti_ofs + 8) - DEFAULT_LOAD_BASE
            if f.rodataoff <= this_ofs <= f.rodataoff + f.rodatasize:
                sym = f.binfile.read_from('512s', this_ofs)
                if b'\x00' in sym:
                    sym = sym[:sym.index(b'\x00')]
                    ipc_info['name'] = demangle(sym)
        ipc_infos.append(ipc_info)

    s_tables = []
    process_functions = []
    process_function_names = {}
    if True:
        stables = []
        for sym in f.symbols:
            if 's_Table' in sym.name:
                print(demangle(sym.name))
                stables.append((sym.name, DEFAULT_LOAD_BASE + sym.value))

        for stable_name, addr in stables:
            stable_name = demangle(stable_name)
            # s_Table is removed by the demangler, but only if we're looking at a real IPC interface
            if stable_name in ('nn::sf::hipc::detail::IHipcManager',
                               'nn::sf::cmif::server::CmifDomainServerObject') or 's_Table' in stable_name:
                continue
            fptr = simulator.qword(addr)
            process_functions.append(fptr)
            s_tables.append(addr)
            process_function_names[fptr] = stable_name

    if not process_functions:
        candidates = []
        for offset, r_type, sym, addend in f.relocations:
            if addend:
                candidates.append((addend, offset))
        candidates.sort()

        # there's a unique error code (0x1A60A) used to find process functions
        # by matching the pattern:
        #   MOV  W?, #0x10000
        #   MOVK W?, #0xA60A
        # this fails on empty interfaces where the error code gets interleaved
        # which could be fixed, but the interfaces are empty and we don't have
        # names for them so I didn't see the point.

        f.binfile.seek(0)
        text_string = f.binfile.read(f.textsize)
        regex = b'|'.join(
            re.escape(chr(0x20 | i).encode() + b'\x00\xA0\x52' + chr(0x40 | i).encode() + b'\xC1\x94\x72') for i in
            range(29))
        for i in re.finditer(regex, text_string):
            if i.start() & 3: continue
            idx = bisect.bisect(candidates, (i.start(), 0))
            process_function, s_table = candidates[idx - 1]
            if text_string.index(b'\xC0\x03\x5F\xD6', process_function) > i.start():
                process_functions.append(DEFAULT_LOAD_BASE + process_function)
                s_tables.append(DEFAULT_LOAD_BASE + s_table)

        # 5.x: match on the "SFCI" constant used in the template of s_Table
        #   MOV  W?, #0x4653
        #   MOVK W?, #0x4943, LSL#16
        if not s_tables:
            regex = b'|'.join(
                re.escape(chr(0x60 | i).encode() + b'\xCA\x88\x52' + chr(0x60 | i).encode() + b'\x28\xA9\x72') for i in
                range(29))
            for i in re.finditer(regex, text_string):
                if i.start() & 3: continue
                idx = bisect.bisect(candidates, (i.start(), 0))
                process_function, s_table = candidates[idx - 1]
                if text_string.index(b'\xC0\x03\x5F\xD6', process_function) > i.start():
                    process_functions.append(DEFAULT_LOAD_BASE + process_function)
                    s_tables.append(DEFAULT_LOAD_BASE + s_table)

    process_name = f.get_name()
    if process_name is None:
        process_name = fname

    print('%r: {' % (process_name.decode(),))
    # Get traces
    traceset = []
    for ind, process_function in enumerate(process_functions):
        traceset.append(list(iter_traces(all_known_command_ids, simulator, process_function)))

    ipcset, ipc_infos = try_match(traceset, ipc_infos)

    # print ipcset
    for i, traces in enumerate(traceset):
        process_function = process_functions[i]
        name = None
        msg = None
        ipc_info = None
        if i in ipcset:
            ipc_info = ipcset[i]
        if ipc_info is None:
            possibles = [x for x in ipc_infos if len(x['funcs']) == get_vt_size(traces)]
            if len(possibles) < 2:
                possibles = filter(lambda x: len(x['funcs']) >= get_vt_size(traces), ipc_infos)
        else:
            for i, trace in enumerate(traces):
                if 'vt' in trace.description:
                    traces[i].description['func'] = simulator.qword(ipc_info['base'] + trace.description['vt'])
            if 'name' in ipc_info:
                name = get_interface_name(ipc_info['name'])
                msg = get_interface_msg(ipc_info['name'])
        if name is None and msg is None:
            if process_function in process_function_names:
                name = process_function_names[process_function]
            else:
                # try to figure out name for 4.0+
                traces = list(traces)
                hashed, hashed2, hash_code, hash_code2 = get_hashes(traces)
                probably, old_version = find_hash_matches(hashed, hashed2)

                name = None
                if probably is not None:
                    if len(probably) == 1:
                        # TODO: need to figure this out earlier
                        # name = probably[0]
                        msg = 'single hash match %r' % (probably[0],)
                    else:
                        msg = repr(probably)
                    if old_version:
                        msg = '3.0.0: ' + msg
                else:
                    msg = '%s %r' % (hashed, hash_code)
                    if hash_code != hash_code2:
                        msg += ' %r' % (hash_code2,)

                if name is None:
                    name = '0x%X' % process_function

        if msg is None:
            print('  ' + repr(name) + ': {')
        else:
            if ipc_info is None:
                msg = ', vtable size %d, possible vtables [%s]' % (len(traces), ', '.join(
                    '0x%X %d' % (info['base'], len(info['funcs'])) for info in
                    sorted(possibles, key=lambda p: len(p['funcs']))))
            print('  ' + repr(name) + ': { #', msg)
        for trace in traces:
            description = trace.description
            line = '      ' + ('%d: ' % trace.cmd_id).ljust(7) + '{'
            parts = []
            for k in ('outinterfaces', 'ininterfaces'):
                if k in description:
                    description[k] = [(process_function_names.get(simulator.qword(i), '0x%X' % (
                        simulator.qword(i),)) if i is not None else None) for i in description[k]]

            for i in ['vt', 'func', 'lr', 'inbytes', 'outbytes', 'buffers', 'inhandles', 'outhandles', 'outinterfaces',
                      'pid', 'ininterfaces']:
                if i not in description: continue
                if PUBLIC and i in ('vt', 'lr'): continue
                v = description[i]
                if isinstance(v, (list, bool)):
                    v = repr(v)
                else:
                    if v >= 10:
                        v = '0x%X' % v
                    else:
                        v = str(v)
                    v = v.rjust(5)
                parts.append('"%s": %s' % (i, v))
            line += ', '.join(parts)

            line += '},'
            print(line)

        print('  },')
        # if PUBLIC:
        #    print '  },'
        # else:
        #    print '  }, # ' + msg

    print('},')


def main(fnames):
    for i in fnames:
        dump_ipc_filename(i)


if __name__ == '__main__':
    main(sys.argv[1:])
