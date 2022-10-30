import struct

from nxo64.compat import iter_range
from nxo64.files import load_nxo

from common import BASE_ADDRESS
from common.demangling import ipcclient_demangle as demangle
from ipcclient.utils import shorten
from ipcclient.cmds import get_function_cmd_id, get_cmd_id_hash
from ipcclient.functions import get_method_data
from ipcclient.manual_lookup import MANUAL_NAME_LOOKUP


class IpcClientVtableEntry(object):
    def __init__(self, cmd, process_function, funcptr):
        self.cmd = cmd
        self.process_function = process_function
        self.funcptr = funcptr


class IpcClientVtable(object):
    def __init__(self, start, end, interface, entries, is_domain):
        self.start = start
        self.end = end
        self.interface = interface
        self.entries = entries
        self.is_domain = is_domain


def iter_vtables_in_nxo(f):
    assert f.textoff == 0
    f.binfile.seek(f.textoff)
    binstring = f.binfile.read(f.dataoff + f.datasize)

    fptr_syms = {}
    data_syms = {}
    for offset, r_type, sym, addend in f.relocations:
        if f.dataoff <= offset < f.dataoff + f.datasize:
            if sym and sym.shndx and sym.value < f.textsize:
                fptr_syms[offset] = sym.value
            elif addend and addend < f.textsize:
                fptr_syms[offset] = addend
            elif sym and sym.shndx and sym.value:
                data_syms[offset] = sym.value
            elif addend:
                data_syms[offset] = addend

    # print(hex(f.dataoff), f.dataoff < 0xCE7AA8)
    # print(struct.unpack_from('<q', binstring, 0xCE7AA8)[0])
    for i in range(f.dataoff, len(binstring), 8):
        value = struct.unpack_from('<q', binstring, i)[0]
        if value in (-0x10, -0x20):
            # if i == 0xCE7AA8:
            #	print hex(i)
            end = i
            start = end
            while start - 8 in fptr_syms:
                start -= 8

            process_functions = [None] * ((end - start) // 8)

            vt = []
            funcptrs = []
            for j in iter_range(start, end, 8):
                entry = fptr_syms[j]
                cmd_id = get_function_cmd_id(binstring, entry, f.plt_lookup, f.rodataoff, f.dataoff)
                if cmd_id is not None:
                    cmd_id, process_function = cmd_id
                    process_functions[(j - start) // 8] = process_function
                vt.append(cmd_id)
                funcptrs.append(entry)

            if len(vt) > 4 and all(i is None for i in vt[:4] + vt[-1:]) and not any(i is None for i in vt[4:-1]):
                interface = ''
                raw_vtable_name = ''
                if start - 8 in data_syms:
                    rtti_string = data_syms[data_syms[start - 8] + 8]
                    raw_vtable_name = binstring[rtti_string:binstring.index(b'\0', rtti_string)].decode()
                    interface = demangle(raw_vtable_name)
                elif start - 16 in f.addr_to_name:
                    raw_vtable_name = f.addr_to_name[start - 16]
                    interface = demangle(raw_vtable_name)
                else:
                    interface = 'IUnknown_%s_0x%X' % (get_cmd_id_hash(vt), start + BASE_ADDRESS)
                    interface = MANUAL_NAME_LOOKUP.get(interface, interface)

                is_domain = False
                if 'CmifDomainProxy' in raw_vtable_name:
                    is_domain = True

                entries = []
                for cmd, process_function, funcptr in zip(vt, process_functions, funcptrs):
                    entries.append(IpcClientVtableEntry(cmd, process_function, funcptr))
                yield IpcClientVtable(start, end, interface, entries, is_domain)


def dump_vtables(fname):
    with open(fname, 'rb') as li:
        f = load_nxo(li)

    # for name in  '_nn_sf_sync_'
    for vtable in iter_vtables_in_nxo(f):
        # print '?'
        # continue
        print("  '%s': {" % vtable.interface)
        for entry in vtable.entries:
            if entry.cmd is not None:
                data = {}
                if entry.funcptr in f.addr_to_name:
                    demangled = demangle(f.addr_to_name[entry.funcptr])
                    name, args = demangled.split('>::_nn_sf_sync_')[-1].split('(', 1)
                    args = args[:-1]
                    # parts.append('%r: %r' % ('name', name))
                    # parts.append('%r: %r' % ('args', args))
                    data['name'] = name
                    data['args'] = shorten(args)

                if entry.process_function is not None and entry.process_function in f.addr_to_name:
                    # parts.append('%r: %r' % ('data', ))
                    data.update(get_method_data(f.addr_to_name[entry.process_function]))
                # s += (' | ' + )

                parts = []
                for i in ['inbytes', 'outbytes', 'name', 'pid', 'args', 'arginfo']:
                    if i not in data: continue
                    v = data[i]
                    if isinstance(v, (list, bool, str)):
                        v = repr(v).strip()
                    else:
                        if v.isnumeric():
                            v = '0x%X' % v
                        else:
                            v = str(v).strip()
                        v = v.rjust(5)
                    parts.append('"%s": %s' % (i, v))
                print('    %5d: {%s},' % (entry.cmd, ', '.join(parts)))

        print('  },')
