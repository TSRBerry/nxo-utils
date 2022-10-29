class MemoryChunk(object):
    def __init__(self, name, base, size):
        self.base = base
        self.size = size

    @property
    def end(self):
        return self.base + self.size

    def __repr__(self):
        return 'MemoryChunk(name=%r, base=0x%X, size=0x%X)' % (self.name, self.base, self.size)
