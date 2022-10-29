import struct
from functools import partial

from ipcserver.trace.ipc_server import IPCServerTrace
from ipcserver.sim.nx64 import Nx64Simulator


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
        # print 'retry'
        trace = self.try_trace_cmd(dispatch_func, cmd_id, struct.pack('<QQQQQQ', 1, 1, 1, 1, 1, 1))
        if trace.is_correct():
            return trace
        for buffer_size in (128, 33):
            # print 'retry'
            trace = self.try_trace_cmd(dispatch_func, cmd_id, struct.pack('<QQQQ', 0, 0, 0, 0), buffer_size=buffer_size)
            if trace.is_correct():
                return trace
        print('retry?')
        return trace  # oh well

    def try_trace_cmd(self, dispatch_func, cmd_id, data, **kwargs):
        self.uc.mem_write(self.message_ptr, self._make_message_data(cmd_id) + data)
        trace = IPCServerTrace(self, dispatch_func, cmd_id, **kwargs)
        self.trace_call(dispatch_func, [self.target_object_ptr, self.ipc_object_ptr, self.message_struct_ptr], trace)
        return trace
