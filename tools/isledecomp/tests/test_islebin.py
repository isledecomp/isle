"""Tests for the Bin (or IsleBin) module that:
1. Parses relevant data from the PE header and other structures.
2. Provides an interface to read from the DLL or EXE using a virtual address.
These are some basic smoke tests."""

import hashlib
from typing import Tuple
import pytest
from isledecomp.bin import (
    Bin as IsleBin,
    SectionNotFoundError,
    InvalidVirtualAddressError,
)


# LEGO1.DLL: v1.1 English, September
LEGO1_SHA256 = "14645225bbe81212e9bc1919cd8a692b81b8622abb6561280d99b0fc4151ce17"


@pytest.fixture(name="binfile", scope="session")
def fixture_binfile(pytestconfig) -> IsleBin:
    filename = pytestconfig.getoption("--lego1")

    # Skip this if we have not provided the path to LEGO1.dll.
    if filename is None:
        pytest.skip(allow_module_level=True, reason="No path to LEGO1")

    with open(filename, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
        if digest != LEGO1_SHA256:
            pytest.fail(reason="Did not match expected LEGO1.DLL")

    with IsleBin(filename, find_str=True) as islebin:
        yield islebin


def test_basic(binfile: IsleBin):
    assert binfile.entry == 0x1008C860
    assert len(binfile.sections) == 6

    with pytest.raises(SectionNotFoundError):
        binfile.get_section_by_name(".hello")


SECTION_INFO = (
    (".text", 0x10001000, 0xD2A66, 0xD2C00),
    (".rdata", 0x100D4000, 0x1B5B6, 0x1B600),
    (".data", 0x100F0000, 0x1A734, 0x12C00),
    (".idata", 0x1010B000, 0x1006, 0x1200),
    (".rsrc", 0x1010D000, 0x21D8, 0x2200),
    (".reloc", 0x10110000, 0x10C58, 0x10E00),
)


@pytest.mark.parametrize("name, v_addr, v_size, raw_size", SECTION_INFO)
def test_sections(name: str, v_addr: int, v_size: int, raw_size: int, binfile: IsleBin):
    section = binfile.get_section_by_name(name)
    assert section.virtual_address == v_addr
    assert section.virtual_size == v_size
    assert section.size_of_raw_data == raw_size


DOUBLE_PI_BYTES = b"\x18\x2d\x44\x54\xfb\x21\x09\x40"

# Now that's a lot of pi
PI_ADDRESSES = (
    0x100D4000,
    0x100D4700,
    0x100D7180,
    0x100DB8F0,
    0x100DC030,
)


@pytest.mark.parametrize("addr", PI_ADDRESSES)
def test_read_pi(addr: int, binfile: IsleBin):
    assert binfile.read(addr, 8) == DOUBLE_PI_BYTES


def test_unusual_reads(binfile: IsleBin):
    """Reads that return an error or some specific value based on context"""
    # Reading an address earlier than the imagebase
    with pytest.raises(InvalidVirtualAddressError):
        binfile.read(0, 1)

    # Really big address
    with pytest.raises(InvalidVirtualAddressError):
        binfile.read(0xFFFFFFFF, 1)

    # Uninitialized part of .data
    assert binfile.read(0x1010A600, 4) is None

    # Past the end of virtual size in .text
    assert binfile.read(0x100D3A70, 4) == b"\x00\x00\x00\x00"


STRING_ADDRESSES = (
    (0x100DB588, b"November"),
    (0x100F0130, b"Helicopter"),
    (0x100F0144, b"HelicopterState"),
    (0x100F0BE4, b"valerie"),
    (0x100F4080, b"TARGET"),
)


@pytest.mark.parametrize("addr, string", STRING_ADDRESSES)
def test_strings(addr: int, string: bytes, binfile: IsleBin):
    """Test string read utility function and the string search feature"""
    assert binfile.read_string(addr) == string
    assert binfile.find_string(string) == addr


def test_relocation(binfile: IsleBin):
    # n.b. This is not the number of *relocations* read from .reloc.
    # It is the set of unique addresses in the binary that get relocated.
    assert len(binfile.get_relocated_addresses()) == 14066

    # Score::Score is referenced only by CALL instructions. No need to relocate.
    assert binfile.is_relocated_addr(0x10001000) is False

    # MxEntity::SetEntityId is in the vtable and must be relocated.
    assert binfile.is_relocated_addr(0x10001070) is True


# Not sanitizing dll name case. Do we care?
IMPORT_REFS = (
    ("KERNEL32.dll", "CreateMutexA", 0x1010B3D0),
    ("WINMM.dll", "midiOutPrepareHeader", 0x1010B550),
)


@pytest.mark.parametrize("import_ref", IMPORT_REFS)
def test_imports(import_ref: Tuple[str, str, int], binfile: IsleBin):
    assert import_ref in binfile.imports


# Location of the JMP instruction and the import address.
THUNKS = (
    (0x100D3728, 0x1010B32C),  # DirectDrawCreate
    (0x10098F9E, 0x1010B3D4),  # RtlUnwind
)


@pytest.mark.parametrize("thunk_ref", THUNKS)
def test_thunks(thunk_ref: Tuple[int, int], binfile: IsleBin):
    assert thunk_ref in binfile.thunks
