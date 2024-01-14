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


@pytest.mark.xfail(reason="Not implemented yet")
def test_jmp_table():
    """Should detect the characteristic jump table instruction
    (for a switch statement) and use placeholder."""
    p = ParseAsm()
    inst = mock_inst("jmp", "dword ptr [eax*4 + 0x5555]")
    (_, op_str) = p.sanitize(inst)
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
