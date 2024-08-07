class MemoryChunk(object):
    def __init__(self, name, base, size):
        self.name = name
        self.base = base
        self.size = size

    @property
    def end(self):
        return self.base + self.size

    def __repr__(self):
        return 'MemoryChunk(name=%r, base=0x%X, size=0x%X)' % (self.name, self.base, self.size)


class AllocatingChunk(MemoryChunk):
    bytes_allocated = 0

    def __init__(self, name, base, size):
        super(AllocatingChunk, self).__init__(name, base, size)
        self._next_ptr = self.base

    def reset(self):
        self._next_ptr = self.base
        self.bytes_allocated = 0

    def alloc(self, size):
        available = self.end - self._next_ptr
        assert available > 0
        allocation_size = (size + 0xF) & ~0xF
        if allocation_size > available:
            raise Exception('Could not allocate 0x%X bytes from AllocatingChunk %r' % size, self.name)
        result = self._next_ptr
        self._next_ptr += allocation_size
        self.bytes_allocated += size
        return result
