import struct
from collections import namedtuple


class MZHeaderNotFoundError(Exception):
    """MZ magic string not found at the start of the binary."""


class PEHeaderNotFoundError(Exception):
    """PE magic string not found at the offset given in 0x3c."""


class SectionNotFoundError(KeyError):
    """The specified section was not found in the file."""


class InvalidVirtualAddressError(IndexError):
    """The given virtual address is too high or low
    to point to something in the binary file."""


PEHeader = namedtuple(
    "PEHeader",
    [
        "Signature",
        "Machine",
        "NumberOfSections",
        "TimeDateStamp",
        "PointerToSymbolTable",  # deprecated
        "NumberOfSymbols",  # deprecated
        "SizeOfOptionalHeader",
        "Characteristics",
    ],
)

ImageSectionHeader = namedtuple(
    "ImageSectionHeader",
    [
        "Name",
        "Misc",
        "VirtualAddress",
        "SizeOfRawData",
        "PointerToRawData",
        "PointerToRelocations",
        "PointerToLineNumbers",
        "NumberOfRelocations",
        "NumberOfLineNumbers",
        "Characteristics",
    ],
)


def section_name_match(section, name):
    return section.Name == struct.pack("8s", name.encode("ascii"))


def section_contains_vaddr(section, imagebase, vaddr) -> bool:
    debased = vaddr - imagebase
    ofs = debased - section.VirtualAddress
    return 0 <= ofs < section.SizeOfRawData


class Bin:
    """Parses a PE format EXE and allows reading data from a virtual address.
    Reference: ohttps://learn.microsoft.com/en-us/windows/win32/debug/pe-format"""

    # pylint: disable=too-many-instance-attributes
    # Could remove textvirt and textraw in an upcoming refactor

    def __init__(self, filename, logger=None):
        self.logger = logger
        self._debuglog(f'Parsing headers of "{filename}"... ')
        self.filename = filename
        self.file = None
        self.imagebase = None
        self.textvirt = None
        self.textraw = None
        self.sections = []
        self.last_section = None

    def __enter__(self):
        self._debuglog(f"Bin {self.filename} Enter")
        self.file = open(self.filename, "rb")

        (mz_str,) = struct.unpack("2s", self.file.read(2))
        if mz_str != b"MZ":
            raise MZHeaderNotFoundError

        # Skip to PE header offset in MZ header.
        self.file.seek(0x3C)
        (pe_header_start,) = struct.unpack("<I", self.file.read(4))

        # PE header offset is absolute, so seek there
        self.file.seek(pe_header_start)
        pe_hdr = PEHeader(*struct.unpack("<2s2x2H3I2H", self.file.read(0x18)))

        if pe_hdr.Signature != b"PE":
            raise PEHeaderNotFoundError

        optional_hdr = self.file.read(pe_hdr.SizeOfOptionalHeader)
        (self.imagebase,) = struct.unpack("<i", optional_hdr[0x1C:0x20])

        self.sections = [
            ImageSectionHeader(*struct.unpack("<8s6I2HI", self.file.read(0x28)))
            for i in range(pe_hdr.NumberOfSections)
        ]

        text_section = self._get_section_by_name(".text")
        self.last_section = text_section

        # These are used by reccmp
        self.textvirt = text_section.VirtualAddress
        self.textraw = text_section.PointerToRawData

        self._debuglog("... Parsing finished")
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self._debuglog(f"Bin {self.filename} Exit")
        if self.file:
            self.file.close()

    def _debuglog(self, msg):
        """Write to the logger, if present"""
        if self.logger is not None:
            self.logger.debug(msg)

    def _set_section_for_vaddr(self, vaddr):
        if self.last_section is not None and section_contains_vaddr(
            self.last_section, self.imagebase, vaddr
        ):
            return

        # TODO: assumes no potential for section overlap. reasonable?
        self.last_section = next(
            filter(
                lambda section: section_contains_vaddr(section, self.imagebase, vaddr),
                self.sections,
            ),
            None,
        )

        if self.last_section is None:
            raise InvalidVirtualAddressError

    def _get_section_by_name(self, name):
        section = next(
            filter(lambda section: section_name_match(section, name), self.sections),
            None,
        )

        if section is None:
            raise SectionNotFoundError

        return section

    def get_section_offset_by_index(self, index) -> int:
        """The symbols output from cvdump gives addresses in this format: AAAA.BBBBBBBB
        where A is the index (1-based) into the section table and B is the local offset.
        This will return the virtual address for the start of the section at the given index
        so you can get the virtual address for whatever symbol you are looking at.
        """

        section = self.sections[index - 1]
        return self.imagebase + section.VirtualAddress

    def get_section_offset_by_name(self, name) -> int:
        """Same as above, but use the section name as the lookup"""

        section = self._get_section_by_name(name)
        return self.imagebase + section.VirtualAddress

    def get_raw_addr(self, vaddr) -> int:
        """Returns the raw offset in the PE binary for the given virtual address."""
        self._set_section_for_vaddr(vaddr)
        return (
            vaddr
            - self.imagebase
            - self.last_section.VirtualAddress
            + self.last_section.PointerToRawData
        )

    def is_valid_vaddr(self, vaddr) -> bool:
        """Does this virtual address point to anything in the exe?"""
        section = next(
            filter(
                lambda section: section_contains_vaddr(section, self.imagebase, vaddr),
                self.sections,
            ),
            None,
        )

        return section is not None

    def read(self, offset, size):
        self._set_section_for_vaddr(offset)

        raw_addr = self.get_raw_addr(offset)
        self.file.seek(raw_addr)

        # Clamp the read within the extent of the current section.
        # Reading off the end will most likely misrepresent the virtual addressing.
        _size = min(
            size,
            self.last_section.PointerToRawData
            + self.last_section.SizeOfRawData
            - raw_addr,
        )
        return self.file.read(_size)
