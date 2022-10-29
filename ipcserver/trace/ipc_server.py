import struct

from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_PC, UC_ARM64_REG_LR, UC_ARM64_REG_X1, UC_ARM64_REG_X9, \
    UC_ARM64_REG_X8, UC_ARM64_REG_NZCV

from ipcserver.trace.branch_tracer import BranchTracer


class IPCServerTrace(object):
    def __init__(self, simulator, dispatch_func, cmd_id, buffer_size=0x1000):
        self.dispatch_func = dispatch_func
        self.cmd_id = cmd_id
        self._simulator = simulator
        self.description = None
        self.buffer_size = buffer_size

        self.branch_tracer = BranchTracer(simulator, cmd_id)
        self._simulator.add_trace_instruction_hook(self.branch_tracer.trace_instruction)

    def is_correct(self):
        if self.description is None:
            return True
        if 'vt' not in self.description:
            return False
        # TODO: detect missing out-interfaces / in-interfaces
        return True

    def ret(self, uc, value):
        uc.reg_write(UC_ARM64_REG_X0, value)
        uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))

    def PrepareForProcess(self, uc):
        arg = uc.reg_read(UC_ARM64_REG_X1)
        metainfo_size = 0x90
        metainfo_bytes = uc.mem_read(arg, metainfo_size)
        metainfo = list(struct.unpack('<' + 'I' * (metainfo_size // 4), metainfo_bytes))

        self.bytes_in = metainfo[8 // 4] - 0x10
        assert 0 <= self.bytes_in <= 0x1000
        self.bytes_out = metainfo[0x10 // 4] - 0x10
        assert 0 <= self.bytes_out <= 0x1000
        self.buffer_count = metainfo[0x18 // 4]
        assert self.buffer_count < 20

        self.in_interface_count = metainfo[0x1c // 4]
        self.out_interface_count = metainfo[0x20 // 4]
        self.in_handles_count = metainfo[0x24 // 4]
        self.out_handles_count = metainfo[0x28 // 4]

        assert self.in_interface_count < 20
        assert self.out_interface_count < 20
        assert self.in_handles_count < 20
        assert self.out_handles_count < 20

        self.description = {'inbytes': self.bytes_in, 'outbytes': self.bytes_out,
                            'ininterfaces': [None] * self.in_interface_count,
                            'outinterfaces': [None] * self.out_interface_count,
                            'inhandles': metainfo[0x4C // 4:0x4C // 4 + self.in_handles_count],
                            'outhandles': metainfo[0x6C // 4:0x6C // 4 + self.out_handles_count],
                            'buffers': metainfo[0x2c // 4:0x2c // 4 + self.buffer_count], 'pid': metainfo[0] == 1,
                            'lr': uc.reg_read(UC_ARM64_REG_LR)}

        for i in ['outinterfaces', 'inhandles', 'outhandles', 'buffers', 'pid', 'ininterfaces']:
            if not self.description[i]:
                del self.description[i]

        if self.in_interface_count:
            self._simulator.add_trace_instruction_hook(self.trace_instruction)

        self.ret(uc, 0)
        return True

    def trace_instruction(self, uc, instruction):
        i = instruction
        # print '0x%08x:    %s  %s' % (instruction.address, instruction.mnemonic, instruction.op_str)
        if i.mnemonic == 'cmp' and i.op_str.endswith(', x9') and len(self.description['ininterfaces']) == 1 and \
                self.description['ininterfaces'][0] is None:
            assert i.op_str == 'x8, x9'  # oddly specific
            x9 = uc.reg_read(UC_ARM64_REG_X9)
            uc.reg_write(UC_ARM64_REG_X8, x9)
            uc.reg_write(UC_ARM64_REG_NZCV, 0b0100)
            self.description['ininterfaces'][0] = x9

    def OverwriteClientProcessId(self, uc):
        o = uc.reg_read(UC_ARM64_REG_X1)
        uc.mem_write(o, struct.pack('<Q', 0))
        # print' OverwriteClientProcessId', hex(struct.unpack('<Q', uc.mem_read(uc.reg_read(UC_ARM64_REG_X1), 8))[0])
        self.ret(uc, 0)
        return True

    def GetBuffers(self, uc):
        outptr = uc.reg_read(UC_ARM64_REG_X1)
        i = outptr
        while i < outptr + self.buffer_count * 0x10:
            uc.mem_write(i, struct.pack('<QQ', self._simulator.buffer_memory, self.buffer_size))
            i += 0x10
        uc.mem_write(self._simulator.buffer_memory, struct.pack('<Q', 1))
        self.ret(uc, 0)
        return True

    def GetInNativeHandles(self, uc):
        self.ret(uc, 0)
        return True

    def GetInObjects(self, uc):
        outptr = uc.reg_read(UC_ARM64_REG_X1)
        assert self.in_interface_count == 1
        uc.mem_write(outptr, struct.pack('<Q', self._simulator.in_object_ptr))
        self.ret(uc, 0)
        return True

    def BeginPreparingForReply(self, uc):
        o = uc.reg_read(UC_ARM64_REG_X1)
        uc.mem_write(o, struct.pack('<QQ', self._simulator.output_memory, 0x1000))
        self.ret(uc, 0)
        return True

    def SetBuffers(self, uc):
        self.ret(uc, 0)
        return True

    def SetOutObjects(self, uc):
        value = struct.unpack('<Q', uc.mem_read(uc.reg_read(UC_ARM64_REG_X1) + 8, 8))[0]
        self.description['outinterfaces'][0] = value
        self.ret(uc, 0)
        return False

    def SetOutNativeHandles(self, uc):
        self.ret(uc, 0)
        return True

    def BeginPreparingForErrorReply(self, uc):
        return False

    def EndPreparingForReply(self, uc):
        self.ret(uc, 0)
        return False

    def target_function(self, offset, uc):
        if self.description is None:
            return False
        self.description['vt'] = offset
        self.ret(uc, 0)
        return True
