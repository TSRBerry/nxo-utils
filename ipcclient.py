import sys

from nxo64.files import load_nxo
from common.demangling import ipcclient_demangle as demangle
from ipcclient.vtable import iter_vtables_in_nxo, dump_vtables


def dump_structs(fname):
    with open(fname, 'rb') as li:
        f = load_nxo(li)
    # for k,v in namez.iteritems():
    #	f.

    for vtable in iter_vtables_in_nxo(f):
        interface = vtable.interface

        # if 'CmifDomainProxy' in tail:
        #	interface += '::DomainProxy'

        print()
        print('struct %s;' % interface)

        print('struct %s::vt' % interface)
        print('{')
        for i, entry in enumerate(vtable.entries):
            if entry.cmd is not None:
                funcname = 'Cmd%d' % entry.cmd
                if entry.funcptr in f.addr_to_name:
                    ipcname = demangle(f.addr_to_name[entry.funcptr]).split('>::_nn_sf_sync_')[-1].split('(')[0]
                    funcname += '_' + ipcname
            else:
                funcname = {
                    0: 'AddReference',
                    1: 'Release',
                    2: 'GetProxyInfo',
                    3: 'GetInterfaceTypeInfo',
                }.get(i)
                if funcname is None:
                    if i == len(vtable.entries) - 1:
                        funcname = 'GetCmifBaseObject'
                    else:
                        funcname = 'func%X' % (i * 8)
            print('  _DWORD (*__fastcall %s)(%s *this, ...);' % (funcname, interface))

        print('};')
        print('struct %s' % interface)
        print('{')
        print('  %s::vt *_vt;' % interface)
        print('  _BYTE byte8;')
        print('  _BYTE byte9;')
        print('  unsigned int handle;')
        print('  void *_vt10;')
        print('  _DWORD dword18;')
        print('  _QWORD qword20;')
        print('};')


def dump_unique_ids(fnames):
    all_cmds = set()
    for fname in sys.argv[1:]:
        with open(fname, 'rb') as li:
            f = load_nxo(li)
        new = False
        for vtable in iter_vtables_in_nxo(f):
            interface = vtable.interface

            for i, entry in enumerate(vtable.entries):
                if entry.cmd is not None and entry.cmd not in all_cmds:
                    print(entry.cmd)
                    new = True
                    all_cmds.add(entry.cmd)
        if new:
            print(all_cmds)


def main():
    dump_vtables(sys.argv[1])


# dump_structs(sys.argv[1])
# dump_unique_ids(sys.argv[1:])
# for fname in sys.argv[1:]:
#	dump_structs(fname)


if __name__ == '__main__':
    main()
