from typing import Optional
import pytest
from isledecomp.compare.asm.parse import DisasmLiteInst, ParseAsm


def mock_inst(mnemonic: str, op_str: str) -> DisasmLiteInst:
    """Mock up the named tuple DisasmLite from just a mnemonic and op_str.
    To be used for tests on sanitize that do not require the instruction address
    or size. i.e. any non-jump instruction."""
    return DisasmLiteInst(0, 0, mnemonic, op_str)


identity_cases = [
    ("", ""),
    ("sti", ""),
    ("push", "ebx"),
    ("ret", ""),
    ("ret", "4"),
    ("mov", "eax, 0x1234"),
]


@pytest.mark.parametrize("mnemonic, op_str", identity_cases)
def test_identity(mnemonic, op_str):
    """Confirm that nothing is substituted."""
    p = ParseAsm()
    inst = mock_inst(mnemonic, op_str)
    result = p.sanitize(inst)
    assert result == (mnemonic, op_str)


ptr_replace_cases = [
    ("byte ptr [0x5555]", "byte ptr [<OFFSET1>]"),
    ("word ptr [0x5555]", "word ptr [<OFFSET1>]"),
    ("dword ptr [0x5555]", "dword ptr [<OFFSET1>]"),
    ("qword ptr [0x5555]", "qword ptr [<OFFSET1>]"),
    ("eax, dword ptr [0x5555]", "eax, dword ptr [<OFFSET1>]"),
    ("dword ptr [0x5555], eax", "dword ptr [<OFFSET1>], eax"),
    ("dword ptr [0x5555], 0", "dword ptr [<OFFSET1>], 0"),
    ("dword ptr [0x5555], 8", "dword ptr [<OFFSET1>], 8"),
    # Same value, assumed to be an addr in the first appearance
    # because it is designated as 'ptr', but we have not provided the
    # relocation table lookup method so we do not replace the second appearance.
    ("dword ptr [0x5555], 0x5555", "dword ptr [<OFFSET1>], 0x5555"),
]


@pytest.mark.parametrize("start, end", ptr_replace_cases)
def test_ptr_replace(start, end):
    """Anything in square brackets (with the 'ptr' prefix) will always be replaced."""
    p = ParseAsm()
    inst = mock_inst("", start)
    (_, op_str) = p.sanitize(inst)
    assert op_str == end


call_replace_cases = [
    ("ebx", "ebx"),
    ("0x1234", "<OFFSET1>"),
    ("dword ptr [0x1234]", "dword ptr [<OFFSET1>]"),
    ("dword ptr [ecx + 0x10]", "dword ptr [ecx + 0x10]"),
]


@pytest.mark.parametrize("start, end", call_replace_cases)
def test_call_replace(start, end):
    """Call with hex operand is always replaced.
    Otherwise, ptr replacement rules apply, but skip `this` calls."""
    p = ParseAsm()
    inst = mock_inst("call", start)
    (_, op_str) = p.sanitize(inst)
    assert op_str == end


def test_jump_displacement():
    """Display jump displacement (offset from end of jump instruction)
    instead of destination address."""
    p = ParseAsm()
    inst = DisasmLiteInst(0x1000, 2, "je", "0x1000")
    (_, op_str) = p.sanitize(inst)
    assert op_str == "-0x2"


def test_jmp_table():
    """To ignore cases where it would be inappropriate to replace pointer
    displacement (i.e. the vast majority of them) we require the address
    to be relocated. This excludes any address less than the imagebase."""
    p = ParseAsm()
    inst = mock_inst("jmp", "dword ptr [eax*4 + 0x5555]")
    (_, op_str) = p.sanitize(inst)
    # i.e. no change
    assert op_str == "dword ptr [eax*4 + 0x5555]"

    def relocate_lookup(addr: int) -> bool:
        return addr == 0x5555

    # Now add the relocation lookup
    p = ParseAsm(relocate_lookup=relocate_lookup)
    (_, op_str) = p.sanitize(inst)
    # Should replace it now
    assert op_str == "dword ptr [eax*4 + <OFFSET1>]"


name_replace_cases = [
    ("byte ptr [0x5555]", "byte ptr [_substitute_]"),
    ("word ptr [0x5555]", "word ptr [_substitute_]"),
    ("dword ptr [0x5555]", "dword ptr [_substitute_]"),
    ("qword ptr [0x5555]", "qword ptr [_substitute_]"),
]


@pytest.mark.parametrize("start, end", name_replace_cases)
def test_name_replace(start, end):
    """Make sure the name lookup function is called if present"""

    def substitute(_: int) -> str:
        return "_substitute_"

    p = ParseAsm(name_lookup=substitute)
    inst = mock_inst("mov", start)
    (_, op_str) = p.sanitize(inst)
    assert op_str == end


def test_replacement_cache():
    p = ParseAsm()
    inst = mock_inst("inc", "dword ptr [0x1234]")

    (_, op_str) = p.sanitize(inst)
    assert op_str == "dword ptr [<OFFSET1>]"

    (_, op_str) = p.sanitize(inst)
    assert op_str == "dword ptr [<OFFSET1>]"


def test_replacement_numbering():
    """If we can use the name lookup for the first address but not the second,
    the second replacement should be <OFFSET2> not <OFFSET1>."""

    def substitute_1234(addr: int) -> Optional[str]:
        return "_substitute_" if addr == 0x1234 else None

    p = ParseAsm(name_lookup=substitute_1234)

    (_, op_str) = p.sanitize(mock_inst("inc", "dword ptr [0x1234]"))
    assert op_str == "dword ptr [_substitute_]"

    (_, op_str) = p.sanitize(mock_inst("inc", "dword ptr [0x5555]"))
    assert op_str == "dword ptr [<OFFSET2>]"


def test_relocate_lookup():
    """Immediate values would be relocated if they are actually addresses.
    So we can use the relocation table to check whether a given value is an
    address or just some number."""

    def relocate_lookup(addr: int) -> bool:
        return addr == 0x1234

    p = ParseAsm(relocate_lookup=relocate_lookup)
    (_, op_str) = p.sanitize(mock_inst("mov", "eax, 0x1234"))
    assert op_str == "eax, <OFFSET1>"

    (_, op_str) = p.sanitize(mock_inst("mov", "eax, 0x5555"))
    assert op_str == "eax, 0x5555"


def test_jump_to_function():
    """A jmp instruction can lead us directly to a function. This can be found
    in the unwind section at the end of a function. However: we do not want to
    assume this is the case for all jumps. Only replace the jump with a name
    if we can find it using our lookup."""

    def substitute_1234(addr: int) -> Optional[str]:
        return "_substitute_" if addr == 0x1234 else None

    p = ParseAsm(name_lookup=substitute_1234)
    inst = DisasmLiteInst(0x1000, 2, "jmp", "0x1234")
    (_, op_str) = p.sanitize(inst)
    assert op_str == "_substitute_"

    # Should not replace this jump.
    # 0x1000 (start addr)
    # + 2 (size of jump instruction)
    # + 0x5555 (displacement, the value we want)
    # = 0x6557
    inst = DisasmLiteInst(0x1000, 2, "jmp", "0x6557")
    (_, op_str) = p.sanitize(inst)
    assert op_str == "0x5555"


def test_float_replacement():
    """Floating point constants often appear as pointers to data.
    A good example is ViewROI::IntrinsicImportance and the subclass override
    LegoROI::IntrinsicImportance. Both return 0.5, but this is done via the
    FLD instruction and a dword value at 0x100dbdec. In this case it is more
    valuable to just read the constant value rather than use a placeholder.
    The float constants don't appear to be deduplicated (like strings are)
    because there is another 0.5 at 0x100d40b0."""

    def bin_lookup(addr: int, _: int) -> Optional[bytes]:
        return b"\xdb\x0f\x49\x40" if addr == 0x1234 else None

    p = ParseAsm(bin_lookup=bin_lookup)
    inst = DisasmLiteInst(0x1000, 6, "fld", "dword ptr [0x1234]")
    (_, op_str) = p.sanitize(inst)
    # Single-precision float. struct.unpack("<f", struct.pack("<f", math.pi))
    assert op_str == "dword ptr [3.1415927410125732 (FLOAT)]"


def test_float_variable():
    """If there is a variable at the address referenced by a float instruction,
    use the name instead of calling into the float replacement handler."""

    def name_lookup(addr: int) -> Optional[str]:
        return "g_myFloatVariable" if addr == 0x1234 else None

    p = ParseAsm(name_lookup=name_lookup)
    inst = DisasmLiteInst(0x1000, 6, "fld", "dword ptr [0x1234]")
    (_, op_str) = p.sanitize(inst)
    assert op_str == "dword ptr [g_myFloatVariable]"


def test_pointer_compare():
    """A loop on an array could get optimized into comparing on the address
    that immediately follows the array. This may or may not be a valid address
    and it may or may not be annotated. To avoid a situation where an
    erroneous address value would get replaced with a placeholder and silently
    pass the comparison check, we will only replace an immediate value on the
    CMP instruction if it is a known address."""

    # 0x1234 and 0x5555 are relocated and so are considered to be addresses.
    def relocate_lookup(addr: int) -> bool:
        return addr in (0x1234, 0x5555)

    # Only 0x5555 is a "known" address
    def name_lookup(addr: int) -> Optional[str]:
        return "hello" if addr == 0x5555 else None

    p = ParseAsm(relocate_lookup=relocate_lookup, name_lookup=name_lookup)

    # Will always replace on MOV instruction
    (_, op_str) = p.sanitize(mock_inst("mov", "eax, 0x1234"))
    assert op_str == "eax, <OFFSET1>"
    (_, op_str) = p.sanitize(mock_inst("mov", "eax, 0x5555"))
    assert op_str == "eax, hello"

    # n.b. We have already cached the replacement for 0x1234, but the
    # special handling for CMP should skip the cache and not use it.

    # Do not replace here
    (_, op_str) = p.sanitize(mock_inst("cmp", "eax, 0x1234"))
    assert op_str == "eax, 0x1234"
    # Should replace here
    (_, op_str) = p.sanitize(mock_inst("cmp", "eax, 0x5555"))
    assert op_str == "eax, hello"


def test_absolute_indirect():
    """The instruction `call dword ptr [0x1234]` means we call the function
    whose address is at 0x1234. (i.e. absolute indirect addressing mode)
    It is probably more useful to show the name of the function itself if
    we have it, but there are some circumstances where we want to replace
    with the pointer's name (i.e. an import function)."""

    def name_lookup(addr: int) -> Optional[str]:
        return {
            0x1234: "Hello",
            0x4321: "xyz",
            0x5555: "Test",
        }.get(addr)

    def bin_lookup(addr: int, _: int) -> Optional[bytes]:
        return (
            {
                0x1234: b"\x55\x55\x00\x00",
                0x4321: b"\x99\x99\x00\x00",
            }
        ).get(addr)

    p = ParseAsm(name_lookup=name_lookup, bin_lookup=bin_lookup)

    # If we know the indirect address (0x5555)
    # Arrow to indicate this is an indirect replacement
    (_, op_str) = p.sanitize(mock_inst("call", "dword ptr [0x1234]"))
    assert op_str == "dword ptr [->Test]"

    # If we do not know the indirect address (0x9999)
    (_, op_str) = p.sanitize(mock_inst("call", "dword ptr [0x4321]"))
    assert op_str == "dword ptr [xyz]"

    # If we can't read the indirect address
    (_, op_str) = p.sanitize(mock_inst("call", "dword ptr [0x5555]"))
    assert op_str == "dword ptr [Test]"
