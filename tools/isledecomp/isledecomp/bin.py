import logging
import struct
from typing import List, Optional
from dataclasses import dataclass
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


@dataclass
class ImageSectionHeader:
    # pylint: disable=too-many-instance-attributes
    # Most attributes are unused, but this is the struct format
    name: bytes
    virtual_size: int
    virtual_address: int
    size_of_raw_data: int
    pointer_to_raw_data: int
    pointer_to_relocations: int
    pointer_to_line_numbers: int
    number_of_relocations: int
    number_of_line_numbers: int
    characteristics: int

    @property
    def extent(self):
        """Get the highest possible offset of this section"""
        return max(self.size_of_raw_data, self.virtual_size)

    def match_name(self, name: str) -> bool:
        return self.name == struct.pack("8s", name.encode("ascii"))

    def contains_vaddr(self, vaddr: int) -> bool:
        ofs = vaddr - self.virtual_address
        return 0 <= ofs < self.extent

    def addr_is_uninitialized(self, vaddr: int) -> bool:
        """We cannot rely on the IMAGE_SCN_CNT_UNINITIALIZED_DATA flag (0x80) in
        the characteristics field so instead we determine it this way."""
        if not self.contains_vaddr(vaddr):
            return False

        # Should include the case where size_of_raw_data == 0,
        # meaning the entire section is uninitialized
        return (self.virtual_size > self.size_of_raw_data) and (
            vaddr - self.virtual_address >= self.size_of_raw_data
        )


logger = logging.getLogger(__name__)


class Bin:
    """Parses a PE format EXE and allows reading data from a virtual address.
    Reference: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format"""

    # pylint: disable=too-many-instance-attributes

    def __init__(self, filename: str, find_str: bool = False) -> None:
        logger.debug('Parsing headers of "%s"... ', filename)
        self.filename = filename
        self.file = None
        self.imagebase = None
        self.entry = None
        self.sections: List[ImageSectionHeader] = []
        self.last_section = None
        self.find_str = find_str
        self._potential_strings = {}
        self._relocated_addrs = set()

    def __enter__(self):
        logger.debug("Bin %s Enter", self.filename)
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
        (entry,) = struct.unpack("<i", optional_hdr[0x10:0x14])
        self.entry = entry + self.imagebase

        self.sections = [
            ImageSectionHeader(*struct.unpack("<8s6I2HI", self.file.read(0x28)))
            for i in range(pe_hdr.NumberOfSections)
        ]

        # Add the imagebase here because we almost never need the base vaddr without it
        for sect in self.sections:
            sect.virtual_address += self.imagebase

        self._populate_relocations()

        # This is a (semi) expensive lookup that is not necesssary in every case.
        # We can find strings in the original if we have coverage using STRING markers.
        # For the recomp, we can find strings using the PDB.
        if self.find_str:
            self._prepare_string_search()

        text_section = self._get_section_by_name(".text")
        self.last_section = text_section

        logger.debug("... Parsing finished")
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        logger.debug("Bin %s Exit", self.filename)
        if self.file:
            self.file.close()

    def get_relocated_addresses(self) -> List[int]:
        return sorted(self._relocated_addrs)

    def find_string(self, target: str) -> Optional[int]:
        # Pad with null terminator to make sure we don't
        # match on a subset of the full string
        if not target.endswith(b"\x00"):
            target += b"\x00"

        c = target[0]
        if c not in self._potential_strings:
            return None

        for addr in self._potential_strings[c]:
            if target == self.read(addr, len(target)):
                return addr

        return None

    def is_relocated_addr(self, vaddr) -> bool:
        return vaddr in self._relocated_addrs

    def _prepare_string_search(self):
        """We are intersted in deduplicated string constants found in the
        .rdata and .data sections. For each relocated address in these sections,
        read the first byte and save the address if that byte is an ASCII character.
        When we search for an arbitrary string later, we can narrow down the list
        of potential locations by a lot."""

        def is_ascii(b):
            return b" " <= b < b"\x7f"

        sect_data = self._get_section_by_name(".data")
        sect_rdata = self._get_section_by_name(".rdata")
        potentials = filter(
            lambda a: sect_data.contains_vaddr(a) or sect_rdata.contains_vaddr(a),
            self.get_relocated_addresses(),
        )

        for addr in potentials:
            c = self.read(addr, 1)
            if c is not None and is_ascii(c):
                k = ord(c)
                if k not in self._potential_strings:
                    self._potential_strings[k] = set()

                self._potential_strings[k].add(addr)

    def _populate_relocations(self):
        """The relocation table in .reloc gives each virtual address where the next four
        bytes are, itself, another virtual address. During loading, these values will be
        patched according to the virtual address space for the image, as provided by Windows.
        We can use this information to get a list of where each significant "thing"
        in the file is located. Anything that is referenced absolutely (i.e. excluding
        jump destinations given by local offset) will be here.
        One use case is to tell whether an immediate value in an operand represents
        a virtual address or just a big number."""

        ofs = self.get_section_offset_by_name(".reloc")
        reloc_addrs = []

        # Parse the structure in .reloc to get the list locations to check.
        # The first 8 bytes are 2 dwords that give the base page address
        # and the total block size (including this header).
        # The page address is used to compact the list; each entry is only
        # 2 bytes, and these are added to the base to get the full location.
        # If the entry read in is zero, we are at the end of this section and
        # these are padding bytes.
        while True:
            (page_base, block_size) = struct.unpack("<2I", self.read(ofs, 8))
            if block_size == 0:
                break

            # HACK: ignore the relocation type for now (the top 4 bits of the value).
            values = list(struct.iter_unpack("<H", self.read(ofs + 8, block_size - 8)))
            reloc_addrs += [
                self.imagebase + page_base + (v[0] & 0xFFF) for v in values if v[0] != 0
            ]

            ofs += block_size

        # We are now interested in the relocated addresses themselves. Seek to the
        # address where there is a relocation, then read the four bytes into our set.
        reloc_addrs.sort()
        for addr in reloc_addrs:
            (relocated_addr,) = struct.unpack("<I", self.read(addr, 4))
            self._relocated_addrs.add(relocated_addr)

    def _set_section_for_vaddr(self, vaddr: int):
        if self.last_section is not None and self.last_section.contains_vaddr(vaddr):
            return

        # TODO: assumes no potential for section overlap. reasonable?
        self.last_section = next(
            filter(
                lambda section: section.contains_vaddr(vaddr),
                self.sections,
            ),
            None,
        )

        if self.last_section is None:
            raise InvalidVirtualAddressError(f"0x{vaddr:08x}")

    def _get_section_by_name(self, name: str):
        section = next(
            filter(lambda section: section.match_name(name), self.sections),
            None,
        )

        if section is None:
            raise SectionNotFoundError

        return section

    def get_section_extent_by_index(self, index: int) -> int:
        return self.sections[index - 1].extent

    def get_section_offset_by_index(self, index: int) -> int:
        """The symbols output from cvdump gives addresses in this format: AAAA.BBBBBBBB
        where A is the index (1-based) into the section table and B is the local offset.
        This will return the virtual address for the start of the section at the given index
        so you can get the virtual address for whatever symbol you are looking at.
        """

        section = self.sections[index - 1]
        return section.virtual_address

    def get_section_offset_by_name(self, name: str) -> int:
        """Same as above, but use the section name as the lookup"""

        section = self._get_section_by_name(name)
        return section.virtual_address

    def get_abs_addr(self, section: int, offset: int) -> int:
        """Convenience function for converting section:offset pairs from cvdump
        into an absolute vaddr."""
        return self.get_section_offset_by_index(section) + offset

    def get_raw_addr(self, vaddr: int) -> int:
        """Returns the raw offset in the PE binary for the given virtual address."""
        self._set_section_for_vaddr(vaddr)
        return (
            vaddr
            - self.last_section.virtual_address
            + self.last_section.pointer_to_raw_data
        )

    def is_valid_section(self, section: int) -> bool:
        """The PDB will refer to sections that are not listed in the headers
        and so should ignore these references."""
        try:
            _ = self.sections[section - 1]
            return True
        except IndexError:
            return False

    def is_valid_vaddr(self, vaddr: int) -> bool:
        """Does this virtual address point to anything in the exe?"""
        section = next(
            filter(
                lambda section: section.contains_vaddr(vaddr),
                self.sections,
            ),
            None,
        )

        return section is not None

    def read(self, offset: int, size: int) -> Optional[bytes]:
        """Read (at most) the given number of bytes at the given virtual address.
        If we return None, the given address points to uninitialized data."""
        self._set_section_for_vaddr(offset)

        if self.last_section.addr_is_uninitialized(offset):
            return None

        raw_addr = self.get_raw_addr(offset)
        self.file.seek(raw_addr)

        # Clamp the read within the extent of the current section.
        # Reading off the end will most likely misrepresent the virtual addressing.
        _size = min(
            size,
            self.last_section.pointer_to_raw_data
            + self.last_section.size_of_raw_data
            - raw_addr,
        )
        return self.file.read(_size)
