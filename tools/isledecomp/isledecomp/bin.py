import logging
import struct
import bisect
from functools import cached_property
from typing import List, Optional, Tuple
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

ImageSectionHeader = namedtuple(
    "ImageSectionHeader",
    [
        "name",
        "virtual_size",
        "virtual_address",
        "size_of_raw_data",
        "pointer_to_raw_data",
        "pointer_to_relocations",
        "pointer_to_line_numbers",
        "number_of_relocations",
        "number_of_line_numbers",
        "characteristics",
    ],
)


@dataclass
class Section:
    name: str
    virtual_size: int
    virtual_address: int
    view: memoryview

    @cached_property
    def size_of_raw_data(self) -> int:
        return len(self.view)

    @cached_property
    def extent(self):
        """Get the highest possible offset of this section"""
        return max(self.size_of_raw_data, self.virtual_size)

    def match_name(self, name: str) -> bool:
        return self.name == name

    def contains_vaddr(self, vaddr: int) -> bool:
        return self.virtual_address <= vaddr < self.virtual_address + self.extent

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
        self.view: memoryview = None
        self.imagebase = None
        self.entry = None
        self.sections: List[Section] = []
        self._section_vaddr: List[int] = []
        self.find_str = find_str
        self._potential_strings = {}
        self._relocated_addrs = set()
        self.imports = []
        self.thunks = []

    def __enter__(self):
        logger.debug("Bin %s Enter", self.filename)
        with open(self.filename, "rb") as f:
            self.view = memoryview(f.read())

        (mz_str,) = struct.unpack("2s", self.view[0:2])
        if mz_str != b"MZ":
            raise MZHeaderNotFoundError

        # Skip to PE header offset in MZ header.
        (pe_header_start,) = struct.unpack("<I", self.view[0x3C:0x40])

        # PE header offset is absolute, so seek there
        pe_header_view = self.view[pe_header_start:]
        pe_hdr = PEHeader(*struct.unpack("<2s2x2H3I2H", pe_header_view[:0x18]))

        if pe_hdr.Signature != b"PE":
            raise PEHeaderNotFoundError

        optional_hdr = pe_header_view[0x18:]
        (self.imagebase,) = struct.unpack("<i", optional_hdr[0x1C:0x20])
        (entry,) = struct.unpack("<i", optional_hdr[0x10:0x14])
        self.entry = entry + self.imagebase

        headers_view = optional_hdr[
            pe_hdr.SizeOfOptionalHeader : pe_hdr.SizeOfOptionalHeader
            + 0x28 * pe_hdr.NumberOfSections
        ]
        section_headers = [
            ImageSectionHeader(*h) for h in struct.iter_unpack("<8s6I2HI", headers_view)
        ]

        self.sections = [
            Section(
                name=hdr.name.decode("ascii").rstrip("\x00"),
                virtual_address=self.imagebase + hdr.virtual_address,
                virtual_size=hdr.virtual_size,
                view=self.view[
                    hdr.pointer_to_raw_data : hdr.pointer_to_raw_data
                    + hdr.size_of_raw_data
                ],
            )
            for hdr in section_headers
        ]

        # bisect does not support key on the github CI version of python
        self._section_vaddr = [section.virtual_address for section in self.sections]

        self._populate_relocations()
        self._populate_imports()
        self._populate_thunks()

        # This is a (semi) expensive lookup that is not necesssary in every case.
        # We can find strings in the original if we have coverage using STRING markers.
        # For the recomp, we can find strings using the PDB.
        if self.find_str:
            self._prepare_string_search()

        logger.debug("... Parsing finished")
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        logger.debug("Bin %s Exit", self.filename)
        self.view.release()

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

        sect_data = self.get_section_by_name(".data")
        sect_rdata = self.get_section_by_name(".rdata")
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

        reloc = self.get_section_by_name(".reloc").view
        ofs = 0
        reloc_addrs = []

        # Parse the structure in .reloc to get the list locations to check.
        # The first 8 bytes are 2 dwords that give the base page address
        # and the total block size (including this header).
        # The page address is used to compact the list; each entry is only
        # 2 bytes, and these are added to the base to get the full location.
        # If the entry read in is zero, we are at the end of this section and
        # these are padding bytes.
        while True:
            (page_base, block_size) = struct.unpack("<2I", reloc[ofs : ofs + 8])
            if block_size == 0:
                break

            # HACK: ignore the relocation type for now (the top 4 bits of the value).
            values = list(struct.iter_unpack("<H", reloc[ofs + 8 : ofs + block_size]))
            reloc_addrs += [
                self.imagebase + page_base + (v[0] & 0xFFF) for v in values if v[0] != 0
            ]

            ofs += block_size

        # We are now interested in the relocated addresses themselves. Seek to the
        # address where there is a relocation, then read the four bytes into our set.
        reloc_addrs.sort()
        for section_id, offset in map(self.get_relative_addr, reloc_addrs):
            section = self.get_section_by_index(section_id)
            (relocated_addr,) = struct.unpack("<I", section.view[offset : offset + 4])
            self._relocated_addrs.add(relocated_addr)

    def _populate_imports(self):
        """Parse .idata to find imported DLLs and their functions."""
        idata_ofs = self.get_section_offset_by_name(".idata")

        def iter_image_import():
            ofs = idata_ofs
            while True:
                # Read 5 dwords until all are zero.
                image_import_descriptor = struct.unpack("<5I", self.read(ofs, 20))
                ofs += 20
                if all(x == 0 for x in image_import_descriptor):
                    break

                (rva_ilt, _, __, dll_name, rva_iat) = image_import_descriptor
                # Convert relative virtual addresses into absolute
                yield (
                    self.imagebase + rva_ilt,
                    self.imagebase + dll_name,
                    self.imagebase + rva_iat,
                )

        image_import_descriptors = list(iter_image_import())

        def iter_imports():
            # ILT = Import Lookup Table
            # IAT = Import Address Table
            # ILT gives us the symbol name of the import.
            # IAT gives the address. The compiler generated a thunk function
            # that jumps to the value of this address.
            for start_ilt, dll_addr, start_iat in image_import_descriptors:
                dll_name = self.read_string(dll_addr).decode("ascii")
                ofs_ilt = start_ilt
                # Address of "__imp__*" symbols.
                ofs_iat = start_iat
                while True:
                    (lookup_addr,) = struct.unpack("<L", self.read(ofs_ilt, 4))
                    (import_addr,) = struct.unpack("<L", self.read(ofs_iat, 4))
                    if lookup_addr == 0 or import_addr == 0:
                        break

                    # MSB set if this is an ordinal import
                    if lookup_addr & 0x80000000 != 0:
                        ordinal_num = lookup_addr & 0x7FFF
                        symbol_name = f"Ordinal_{ordinal_num}"
                    else:
                        # Skip the "Hint" field, 2 bytes
                        name_ofs = lookup_addr + self.imagebase + 2
                        symbol_name = self.read_string(name_ofs).decode("ascii")

                    yield (dll_name, symbol_name, ofs_iat)
                    ofs_ilt += 4
                    ofs_iat += 4

        self.imports = list(iter_imports())

    def _populate_thunks(self):
        """For each imported function, we generate a thunk function. The only
        instruction in the function is a jmp to the address in .idata.
        Search .text to find these functions."""

        text_sect = self.get_section_by_name(".text")
        idata_sect = self.get_section_by_name(".idata")
        start = text_sect.virtual_address
        ofs = start

        for shift in (0, 2, 4):
            window = text_sect.view[shift:]
            win_end = 6 * (len(window) // 6)
            for i, (b0, b1, jmp_ofs) in enumerate(
                struct.iter_unpack("<2BL", window[:win_end])
            ):
                if (b0, b1) == (0xFF, 0x25) and idata_sect.contains_vaddr(jmp_ofs):
                    # Record the address of the jmp instruction and the destination in .idata
                    thunk_ofs = ofs + shift + i * 6
                    self.thunks.append((thunk_ofs, jmp_ofs))

    def get_section_by_name(self, name: str) -> Section:
        section = next(
            filter(lambda section: section.match_name(name), self.sections),
            None,
        )

        if section is None:
            raise SectionNotFoundError

        return section

    def get_section_by_index(self, index: int) -> Section:
        """Convert 1-based index into 0-based."""
        return self.sections[index - 1]

    def get_section_extent_by_index(self, index: int) -> int:
        return self.get_section_by_index(index).extent

    def get_section_offset_by_index(self, index: int) -> int:
        """The symbols output from cvdump gives addresses in this format: AAAA.BBBBBBBB
        where A is the index (1-based) into the section table and B is the local offset.
        This will return the virtual address for the start of the section at the given index
        so you can get the virtual address for whatever symbol you are looking at.
        """
        return self.get_section_by_index(index).virtual_address

    def get_section_offset_by_name(self, name: str) -> int:
        """Same as above, but use the section name as the lookup"""

        section = self.get_section_by_name(name)
        return section.virtual_address

    def get_abs_addr(self, section: int, offset: int) -> int:
        """Convenience function for converting section:offset pairs from cvdump
        into an absolute vaddr."""
        return self.get_section_offset_by_index(section) + offset

    def get_relative_addr(self, addr: int) -> Tuple[int, int]:
        """Convert an absolute address back into a (section, offset) pair."""
        i = bisect.bisect_right(self._section_vaddr, addr) - 1
        i = max(0, i)

        section = self.sections[i]
        if section.contains_vaddr(addr):
            return (i + 1, addr - section.virtual_address)

        raise InvalidVirtualAddressError(f"{self.filename} : {hex(addr)}")

    def is_valid_section(self, section_id: int) -> bool:
        """The PDB will refer to sections that are not listed in the headers
        and so should ignore these references."""
        try:
            _ = self.get_section_by_index(section_id)
            return True
        except IndexError:
            return False

    def is_valid_vaddr(self, vaddr: int) -> bool:
        """Does this virtual address point to anything in the exe?"""
        try:
            (_, __) = self.get_relative_addr(vaddr)
        except InvalidVirtualAddressError:
            return False

        return True

    def read_string(self, offset: int, chunk_size: int = 1000) -> Optional[bytes]:
        """Read until we find a zero byte."""
        b = self.read(offset, chunk_size)
        if b is None:
            return None

        try:
            return b[: b.index(b"\x00")]
        except ValueError:
            # No terminator found, just return what we have
            return b

    def read(self, vaddr: int, size: int) -> Optional[bytes]:
        """Read (at most) the given number of bytes at the given virtual address.
        If we return None, the given address points to uninitialized data."""
        (section_id, offset) = self.get_relative_addr(vaddr)
        section = self.sections[section_id - 1]

        if section.addr_is_uninitialized(vaddr):
            return None

        # Clamp the read within the extent of the current section.
        # Reading off the end will most likely misrepresent the virtual addressing.
        _size = min(size, section.size_of_raw_data - offset)
        return bytes(section.view[offset : offset + _size])
