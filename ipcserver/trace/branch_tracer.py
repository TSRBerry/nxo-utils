from __future__ import print_function

from ipcserver.ipcserver_modern import VERBOSE_COMMAND, UC_REG_BY_NAME


class BranchTracer(object):
    def __init__(self, simulator, cmd_id):
        self.loaded_cmd_id = False
        self.stopped = False
        self._simulator = simulator
        self.taints = set()
        self.cmp_with = None
        self.cmd_id = cmd_id
        self.range_top = 0xFFFFFFFF
        self.switch_top = None
        self.taint_offsets = {}
        # print 'TRACING %d' % cmd_id

    def trace_instruction(self, uc, instruction):
        verbose = (VERBOSE_COMMAND is not None and self.cmd_id == VERBOSE_COMMAND)
        # verbose = False
        if self.stopped: return
        if not self.loaded_cmd_id:
            if instruction.mnemonic != 'ldr' or not instruction.op_str.endswith(', #8]'):
                return
            # TODO: is the offset always in the instruction?
            tainted, base = instruction.op_str[:-len(', #8]')].split(', [')
            if not base.startswith('x') or not tainted.startswith('w'):
                return
            if uc.reg_read(UC_REG_BY_NAME[base]) != self._simulator.message_ptr:
                return
            if verbose: print('BranchTracer start')
            if verbose: print('0x%08x:    %s  %s' % (instruction.address, instruction.mnemonic, instruction.op_str))
            # print '\t%X\t%X' % (uc.reg_read(UC_REG_BY_NAME[base]), self._simulator.message_ptr)

            self.loaded_cmd_id = True
            self.taints.add(int(tainted[1:]))
            self.taint_offsets[int(tainted[1:])] = 0
            # print self.taints
            return

        parts = instruction.op_str.replace(',', ' ').replace('[', ' ').replace(']', ' ').split()

        if any(('w%d' % i) in parts for i in self.taints) or any(('x%d' % i) in parts for i in self.taints):
            if verbose: print('*', end=' ')
        else:
            if verbose: print(' ', end=' ')
        if verbose: print('0x%08x:    %s  %s' % (instruction.address, instruction.mnemonic, instruction.op_str))

        if instruction.mnemonic == 'mov' and parts[0].startswith('w') and parts[1].startswith('w') and parts[
            1] != 'wzr' and int(parts[1][1:]) in self.taints:
            new_taint = int(parts[0][1:])
            self.taints.add(new_taint)
            self.taint_offsets[new_taint] = self.taint_offsets[int(parts[1][1:])]
            if verbose: print('\ttainted x%d' % new_taint)

        if instruction.mnemonic == 'sub' and parts[0].startswith('w') and parts[1].startswith('w') and parts[
            1] != 'wzr' and int(parts[1][1:]) in self.taints:
            if parts[2].startswith('#'):
                new_taint = int(parts[0][1:])
                self.taints.add(new_taint)
                self.taint_offsets[new_taint] = self.taint_offsets[int(parts[1][1:])] - int(parts[2][1:], 16)
                if verbose: print('\ttainted (sub) x%d' % new_taint)

        if instruction.mnemonic == 'add' and parts[0].startswith('w') and parts[1].startswith('w') and int(
                parts[1][1:]) in self.taints:
            if parts[2].startswith('w'):
                new_taint = int(parts[0][1:])
                value = uc.reg_read(UC_REG_BY_NAME['x' + parts[2][1:]])
                value &= 0xFFFFFFFF
                value -= (value & 0x80000000) * 2
                if verbose: print('\tvalue:', value)
                self.taints.add(new_taint)
                self.taint_offsets[new_taint] = self.taint_offsets[int(parts[1][1:])] + value
                if verbose: print('\ttainted (add) x%d' % new_taint)

        if instruction.mnemonic == 'cmp':
            self.cmp_with = None
            if parts[0].startswith(('w', 'x')) and int(parts[0][1:]) in self.taints:
                if parts[1].startswith('#'):
                    if verbose: print('\tcmp_with %r' % instruction.op_str)
                    self.cmp_with = int(parts[1][1:], 16)
                    self.cmp_delta = self.taint_offsets[int(parts[0][1:])]
                elif parts[1].startswith(('w', 'x')):
                    # TODO: safe to assume reg value is constant?
                    if verbose: print('\tcmp_with (2) %r' % instruction.op_str)
                    self.cmp_with = uc.reg_read(UC_REG_BY_NAME['x' + parts[1][1:]])  # int(parts[1][1:], 16)
                    self.cmp_delta = self.taint_offsets[int(parts[0][1:])]

        if instruction.mnemonic in ('b.gt', 'b.le') and self.cmp_with is not None:
            if self.cmp_with - self.cmp_delta >= self.cmd_id:
                self.range_top = min(self.range_top, self.cmp_with - self.cmp_delta)
                if verbose: print('\trange top: %d' % self.range_top)

        if instruction.mnemonic in ('b.eq', 'b.ne',) and self.cmp_with is not None:
            if self.cmp_with - self.cmp_delta > self.cmd_id:
                self.range_top = min(self.range_top, self.cmp_with - self.cmp_delta - 1)
                if verbose: print('\trange top: %d' % self.range_top)

        if instruction.mnemonic in ('b.hi', 'b.ls') and self.cmp_with is not None:
            if self.cmp_delta < 0 and self.cmd_id < -self.cmp_delta:
                self.range_top = min(self.range_top, -self.cmp_delta - 1)
                if verbose: print('\trange top: %d' % self.range_top)
            if self.cmd_id + self.cmp_delta <= self.cmp_with:
                self.range_top = min(self.range_top, self.cmp_with - self.cmp_delta)
                self.switch_top = self.cmp_with
                if verbose: print('\trange top: 0x%X' % self.range_top)

        if instruction.mnemonic == 'ldrsw' and instruction.op_str.endswith(', lsl #2]') and int(
                parts[2][1:]) in self.taints:
            switch_base = uc.reg_read(UC_REG_BY_NAME[parts[1]])
            current_index = uc.reg_read(UC_REG_BY_NAME[parts[2]])
            current = switch_base + self._simulator.sdword(switch_base + current_index * 4)
            same_count = 0
            for i in range(current_index + 1, self.switch_top + 1):
                if switch_base + self._simulator.sdword(switch_base + i * 4) != current:
                    break
                same_count += 1

            self.range_top = min(self.range_top, self.cmd_id + same_count)
            if verbose: print('\tswitchy (%d)' % self.range_top)

            spoiled = int(parts[0][1:])
            if spoiled in self.taints:
                self.taints.remove(spoiled)
                del self.taint_offsets[spoiled]
        if instruction.mnemonic == 'ldrh' and instruction.op_str.endswith(', lsl #1]') and int(
                parts[2][1:]) in self.taints:
            self.range_top = min(self.range_top, self.cmd_id)  # TODO
        if instruction.mnemonic == 'ldrb' and int(parts[2][1:]) in self.taints:
            self.range_top = min(self.range_top, self.cmd_id)  # TODO

        # TODO: is this sound?
        if instruction.mnemonic in ('ret', 'blr'):
            self.stopped = True
            return
