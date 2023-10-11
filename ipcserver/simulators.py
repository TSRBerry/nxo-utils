from __future__ import print_function

import struct
from functools import partial

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn import UcError
from unicorn.arm64_const import *

from common import BASE_ADDRESS
from .chunks import MemoryChunk, AllocatingChunk
from .tracers import IPCServerTrace
from nxo64.compat import iter_range
from common.unicornhelpers import create_unicorn_arm64, load_nxo_to_unicorn


class Nx64Simulator(object):
    def __init__(self, nxo, stack_size=0x2000, host_heap_size=0x100000, runtime_heap_size=0x2000,
                 loadbase=BASE_ADDRESS, trace_instructions=False):
        self.uc = create_unicorn_arm64()
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.loadbase = loadbase
        load_nxo_to_unicorn(self.uc, nxo, loadbase)

        self._last_chunk_base = 0
        self._chunk_step = 0x100000000
        self._chunks = []

        self.stack = self.create_chunk('stack', stack_size)
        self.host_heap = self.create_chunk('host_heap', host_heap_size, AllocatingChunk)
        self.runtime_heap = self.create_chunk('runtime_heap', runtime_heap_size, AllocatingChunk)
        self.function_pointer_chunk = self.create_chunk('function_pointers', 0)
        self.next_function_pointer = self.function_pointer_chunk.base

        self._data_for_reset = []

        self.current_trace = None

        self._hook_functions = {}

        self.return_pointer = self.create_trace_function_pointer(self.on_return_hook_function)

        self.trace_instructions = trace_instructions

        self.trace_instruction_hooks = []

    def on_return_hook_function(self, uc):
        # print('on_return_hook_function')
        return False

    def create_trace_function_pointer(self, func):
        function_pointer = self.next_function_pointer
        self.next_function_pointer += 8

        self._hook_functions[function_pointer] = func
        return function_pointer

    def create_chunk(self, name, size, cls=MemoryChunk):
        base = self._last_chunk_base + self._chunk_step
        chunk = cls(name, base, size)
        if size:
            self.uc.mem_map(base, size)
        self._last_chunk_base = base
        return chunk

    def load_host_data(self, data, reset=False):
        p = self.host_heap.alloc(len(data))
        self.uc.mem_write(p, data)
        if reset:
            self._data_for_reset.append((p, data))
        return p

    def dump_regs(self):
        values = []
        for i in iter_range(28):
            values.append(('X%d' % i, self.uc.reg_read(UC_ARM64_REG_X0 + i)))
        values.append(('X29', self.uc.reg_read(UC_ARM64_REG_X29)))
        values.append(('X30', self.uc.reg_read(UC_ARM64_REG_X30)))
        values.append(('SP', self.uc.reg_read(UC_ARM64_REG_SP)))
        values.append(('PC', self.uc.reg_read(UC_ARM64_REG_PC)))
        print(', '.join('%s=%X' % i for i in values))

    def qword(self, addr):
        return struct.unpack('<Q', self.uc.mem_read(addr, 8))[0]

    def dword(self, addr):
        return struct.unpack('<I', self.uc.mem_read(addr, 4))[0]

    def sdword(self, addr):
        return struct.unpack('<i', self.uc.mem_read(addr, 4))[0]

    def write_qword(self, addr, value):
        self.uc.mem_write(addr, struct.pack('<Q', value))

    def write_dword(self, addr, value):
        self.uc.mem_write(addr, struct.pack('<I', value))

    def reset_host_data(self):
        for addr, data in self._data_for_reset:
            self.uc.mem_write(addr, data)

    def get_instruction(self, addr):
        instructions = list(self.cs.disasm(self.uc.mem_read(addr, 4), addr))
        if instructions:
            assert len(instructions) == 1
            return instructions[0]
        return None

    def add_trace_instruction_hook(self, cb):
        self.trace_instruction_hooks.append(cb)

    def trace_call(self, funcptr, args, trace_object=None):
        if trace_object is None:
            trace_object = {}

        self.reset_host_data()

        register_args, stack_args = args[:8], args[8:]

        for i, v in enumerate(register_args):
            self.uc.reg_write(UC_ARM64_REG_X0 + i, v)

        for i in iter_range(len(register_args), 9):
            self.uc.reg_write(UC_ARM64_REG_X0 + i, 0)

        sp = self.stack.end
        if stack_args:
            stack_space = len(stack_args) * 8
            stack_space = (stack_space + 0xF) & ~0xF
            sp -= stack_space
            for i, v in enumerate(v):
                self.write_qword(sp + i * 8, v)

        self.uc.reg_write(UC_ARM64_REG_SP, sp)
        self.uc.reg_write(UC_ARM64_REG_PC, funcptr)

        self.uc.reg_write(UC_ARM64_REG_X30, self.return_pointer)

        assert self.current_trace is None
        self.current_trace = trace_object

        try:
            while True:
                try:
                    pc = self.uc.reg_read(UC_ARM64_REG_PC)
                    if self.trace_instruction_hooks:
                        instruction = self.get_instruction(pc)
                        for cb in self.trace_instruction_hooks:
                            cb(self.uc, instruction)

                    if self.trace_instructions:
                        instruction = self.get_instruction(pc)
                        if instruction is not None:
                            print('0x%08x:    %s  %s' % (instruction.address, instruction.mnemonic, instruction.op_str))
                        else:
                            print('0x%08x:    [INVALID]' % (instruction.address,))
                    self.uc.emu_start(self.uc.reg_read(UC_ARM64_REG_PC), 0, count=1)
                except UcError as e:
                    pc = self.uc.reg_read(UC_ARM64_REG_PC)
                    if pc in self._hook_functions:
                        # print('hook function for %X' % (pc,))
                        if self._hook_functions[pc](self.uc):
                            continue
                        else:
                            break

                    print('UcError @ pc 0x%X' % (pc,))
                    print('', e)
                    raise
        finally:
            self.trace_instruction_hooks = []
            self.current_trace = None

    def invoke_trace_method(self, method_name, *args, **kwargs):
        assert self.current_trace is not None
        try:
            method = getattr(self.current_trace, method_name)
        except AttributeError:
            raise NotImplementedError(
                "Class %r does not implement %r" % (self.current_trace.__class__.__name__, method_name))
        return method(*args, **kwargs)


class IPCServerSimulator(Nx64Simulator):
    def __init__(self, nxo):
        super(IPCServerSimulator, self).__init__(nxo)
        self.ipc_magic = 0x49434653
        message_data = self._make_message_data(1600) + (b'\x00' * 0x1000)
        self.message_ptr = self.load_host_data(message_data)

        message_struct_data = struct.pack('<QQ', self.message_ptr, len(message_data))
        self.message_struct_ptr = self.load_host_data(message_struct_data, reset=True)

        ipc_functions = [
            partial(self.invoke_trace_method, 'PrepareForProcess'),
            # PrepareForProcess(nn::sf::cmif::CmifMessageMetaInfo const&)
            partial(self.invoke_trace_method, 'OverwriteClientProcessId'),  # OverwriteClientProcessId(ulong *)
            partial(self.invoke_trace_method, 'GetBuffers'),  # GetBuffers(nn::sf::detail::PointerAndSize *)
            partial(self.invoke_trace_method, 'GetInNativeHandles'),  # GetInNativeHandles(nn::sf::NativeHandle *)
            partial(self.invoke_trace_method, 'GetInObjects'),
            # GetInObjects(nn::sf::cmif::server::CmifServerObjectInfo *)
            partial(self.invoke_trace_method, 'BeginPreparingForReply'),
            # BeginPreparingForReply(nn::sf::detail::PointerAndSize *)
            partial(self.invoke_trace_method, 'SetBuffers'),  # SetBuffers(nn::sf::detail::PointerAndSize *)
            partial(self.invoke_trace_method, 'SetOutObjects'),
            # SetOutObjects(nn::sf::cmif::server::CmifServerObjectInfo *)
            partial(self.invoke_trace_method, 'SetOutNativeHandles'),  # SetOutNativeHandles(nn::sf::NativeHandle *)
            partial(self.invoke_trace_method, 'BeginPreparingForErrorReply'),
            # BeginPreparingForErrorReply(nn::sf::detail::PointerAndSize *,ulong)
            partial(self.invoke_trace_method, 'EndPreparingForReply'),  # EndPreparingForReply(void)
        ]

        ipc_function_pointers = [self.create_trace_function_pointer(i) for i in ipc_functions]

        ipc_vtable_ptr = self.load_host_data(
            struct.pack('<' + 'Q' * len(ipc_function_pointers), *ipc_function_pointers))
        self.ipc_object_ptr = self.load_host_data(struct.pack('<QQ', ipc_vtable_ptr, 0))

        target_functions = [partial(self.invoke_trace_method, 'target_function', i * 8) for i in range(512)]
        target_function_pointers = [self.create_trace_function_pointer(i) for i in target_functions]

        target_vtable_ptr = self.load_host_data(
            struct.pack('<' + 'Q' * len(target_function_pointers), *target_function_pointers))
        self.target_object_ptr = self.load_host_data(struct.pack('<QQ', target_vtable_ptr, 0))

        ret_instruction_ptr = self.load_host_data(struct.pack('<I', 0xd65f03c0))
        in_object_vtable_ptr = self.load_host_data(struct.pack('<Q', ret_instruction_ptr) * 16)
        self.in_object_ptr = self.load_host_data(struct.pack('<Q', in_object_vtable_ptr) + b'\0' * (8 * 16))

        self.buffer_memory = self.load_host_data(b'\x00' * 0x1000)
        self.output_memory = self.load_host_data(b'\x00' * 0x1000)

    def _make_message_data(self, cmd_id):
        ipc_magic = 0x49434653
        return struct.pack('<QQ', ipc_magic, cmd_id)

    def trace_cmd(self, dispatch_func, cmd_id):
        trace = self.try_trace_cmd(dispatch_func, cmd_id, struct.pack('<QQQQQQ', 0, 0, 0, 0, 0, 0))
        if trace.is_correct():
            return trace
        # print('retry')
        trace = self.try_trace_cmd(dispatch_func, cmd_id, struct.pack('<QQQQQQ', 1, 1, 1, 1, 1, 1))
        if trace.is_correct():
            return trace
        for buffer_size in (128, 33):
            # print('retry')
            trace = self.try_trace_cmd(dispatch_func, cmd_id, struct.pack('<QQQQ', 0, 0, 0, 0), buffer_size=buffer_size)
            if trace.is_correct():
                return trace
        # print('retry?')
        return trace  # oh well

    def try_trace_cmd(self, dispatch_func, cmd_id, data, **kwargs):
        self.uc.mem_write(self.message_ptr, self._make_message_data(cmd_id) + data)
        trace = IPCServerTrace(self, dispatch_func, cmd_id, **kwargs)
        self.trace_call(dispatch_func, [self.target_object_ptr, self.ipc_object_ptr, self.message_struct_ptr], trace)
        return trace
