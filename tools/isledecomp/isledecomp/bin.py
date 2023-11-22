import struct


# Declare a class that can automatically convert virtual executable addresses
# to file addresses
class Bin:
    def __init__(self, filename, logger):
        self.logger = logger
        self.logger.debug('Parsing headers of "%s"... ', filename)
        self.filename = filename
        self.file = None
        self.imagebase = None
        self.textvirt = None
        self.textraw = None

    def __enter__(self):
        self.logger.debug(f"Bin {self.filename} Enter")
        self.file = open(self.filename, "rb")

        # HACK: Strictly, we should be parsing the header, but we know where
        #      everything is in these two files so we just jump straight there

        # Read ImageBase
        self.file.seek(0xB4)
        (self.imagebase,) = struct.unpack("<i", self.file.read(4))

        # Read .text VirtualAddress
        self.file.seek(0x184)
        (self.textvirt,) = struct.unpack("<i", self.file.read(4))

        # Read .text PointerToRawData
        self.file.seek(0x18C)
        (self.textraw,) = struct.unpack("<i", self.file.read(4))
        self.logger.debug("... Parsing finished")
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.logger.debug(f"Bin {self.filename} Exit")
        if self.file:
            self.file.close()

    def get_addr(self, virt):
        return virt - self.imagebase - self.textvirt + self.textraw

    def read(self, offset, size):
        self.file.seek(self.get_addr(offset))
        return self.file.read(size)
