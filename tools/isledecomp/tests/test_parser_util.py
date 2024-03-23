import pytest
from isledecomp.parser.parser import MarkerDict
from isledecomp.parser.marker import (
    DecompMarker,
    MarkerType,
    match_marker,
    is_marker_exact,
)
from isledecomp.parser.util import (
    is_blank_or_comment,
    get_class_name,
    get_variable_name,
    get_string_contents,
)


blank_or_comment_param = [
    (True, ""),
    (True, "\t"),
    (True, "    "),
    (False, "\tint abc=123;"),
    (True, "// OFFSET: LEGO1 0xdeadbeef"),
    (True, "   /* Block comment beginning"),
    (True, "Block comment ending */   "),
    # TODO: does clang-format have anything to say about these cases?
    (False, "x++; // Comment folows"),
    (False, "x++; /* Block comment begins"),
]


@pytest.mark.parametrize("expected, line", blank_or_comment_param)
def test_is_blank_or_comment(line: str, expected: bool):
    assert is_blank_or_comment(line) is expected


marker_samples = [
    # (can_parse: bool, exact_match: bool, line: str)
    (True, True, "// FUNCTION: LEGO1 0xdeadbeef"),
    (True, True, "// FUNCTION: ISLE 0x12345678"),
    # No trailing spaces allowed
    (True, False, "// FUNCTION: LEGO1 0xdeadbeef  "),
    # Must have exactly one space between elements
    (True, False, "//FUNCTION: ISLE 0xdeadbeef"),
    (True, False, "// FUNCTION:ISLE 0xdeadbeef"),
    (True, False, "//  FUNCTION: ISLE 0xdeadbeef"),
    (True, False, "// FUNCTION:  ISLE 0xdeadbeef"),
    (True, False, "// FUNCTION: ISLE  0xdeadbeef"),
    # Must have 0x prefix for hex number to match at all
    (False, False, "// FUNCTION: ISLE deadbeef"),
    # Offset, module name, and STUB must be uppercase
    (True, False, "// function: ISLE 0xdeadbeef"),
    (True, False, "// function: isle 0xdeadbeef"),
    # Hex string must be lowercase
    (True, False, "// FUNCTION: ISLE 0xDEADBEEF"),
    # TODO: How flexible should we be with matching the module name?
    (True, True, "// FUNCTION: OMNI 0x12345678"),
    (True, True, "// FUNCTION: LEG01 0x12345678"),
    (True, False, "// FUNCTION: hello 0x12345678"),
    # Not close enough to match
    (False, False, "// FUNCTION: ISLE0x12345678"),
    (False, False, "// FUNCTION: 0x12345678"),
    (False, False, "// LEGO1: 0x12345678"),
    # Hex string shorter than 8 characters
    (True, True, "// FUNCTION: LEGO1 0x1234"),
    # TODO: These match but shouldn't.
    # (False, False, '// FUNCTION: LEGO1 0'),
    # (False, False, '// FUNCTION: LEGO1 0x'),
    # Extra field
    (True, True, "// VTABLE: HELLO 0x1234 Extra"),
    # Extra with spaces
    (True, True, "// VTABLE: HELLO 0x1234 Whatever<SubClass *>"),
    # Extra, no space (if the first non-hex character is not in [a-f])
    (True, False, "// VTABLE: HELLO 0x1234Hello"),
    # Extra, many spaces
    (True, False, "// VTABLE: HELLO 0x1234    Hello"),
]


@pytest.mark.parametrize("match, _, line", marker_samples)
def test_marker_match(line: str, match: bool, _):
    did_match = match_marker(line) is not None
    assert did_match is match


@pytest.mark.parametrize("_, exact, line", marker_samples)
def test_marker_exact(line: str, exact: bool, _):
    assert is_marker_exact(line) is exact


def test_marker_dict_simple():
    d = MarkerDict()
    d.insert(DecompMarker("FUNCTION", "TEST", 0x1234))
    markers = list(d.iter())
    assert len(markers) == 1


def test_marker_dict_ofs_replace():
    d = MarkerDict()
    d.insert(DecompMarker("FUNCTION", "TEST", 0x1234))
    d.insert(DecompMarker("FUNCTION", "TEST", 0x555))
    markers = list(d.iter())
    assert len(markers) == 1
    assert markers[0].offset == 0x1234


def test_marker_dict_type_replace():
    d = MarkerDict()
    d.insert(DecompMarker("FUNCTION", "TEST", 0x1234))
    d.insert(DecompMarker("STUB", "TEST", 0x1234))
    markers = list(d.iter())
    assert len(markers) == 1
    assert markers[0].type == MarkerType.FUNCTION


class_name_match_cases = [
    ("struct MxString {", "MxString"),
    ("class MxString {", "MxString"),
    ("// class MxString", "MxString"),
    ("class MxString : public MxCore {", "MxString"),
    ("class MxPtrList<MxPresenter>", "MxPtrList<MxPresenter>"),
    # If it is possible to match the symbol MxList<LegoPathController *>::`vftable'
    # we should get the correct class name if possible. If the template type is a pointer,
    # the asterisk and class name are separated by one space.
    ("// class MxList<LegoPathController *>", "MxList<LegoPathController *>"),
    ("// class MxList<LegoPathController*>", "MxList<LegoPathController *>"),
    ("// class MxList<LegoPathController* >", "MxList<LegoPathController *>"),
    # I don't know if this would ever come up, but sure, why not?
    ("// class MxList<LegoPathController**>", "MxList<LegoPathController **>"),
]


@pytest.mark.parametrize("line, class_name", class_name_match_cases)
def test_get_class_name(line: str, class_name: str):
    assert get_class_name(line) == class_name


class_name_no_match_cases = [
    "MxString { ",
    "clas MxString",
    "// MxPtrList<MxPresenter>::`scalar deleting destructor'",
]


@pytest.mark.parametrize("line", class_name_no_match_cases)
def test_get_class_name_none(line: str):
    assert get_class_name(line) is None


variable_name_cases = [
    # with prefix for easy access
    ("char* g_test;", "g_test"),
    ("g_test;", "g_test"),
    ("void (*g_test)(int);", "g_test"),
    ("char g_test[50];", "g_test"),
    ("char g_test[50] = {1234,", "g_test"),
    ("int g_test = 500;", "g_test"),
    # no prefix
    ("char* hello;", "hello"),
    ("hello;", "hello"),
    ("void (*hello)(int);", "hello"),
    ("char hello[50];", "hello"),
    ("char hello[50] = {1234,", "hello"),
    ("int hello = 500;", "hello"),
]


@pytest.mark.parametrize("line,name", variable_name_cases)
def test_get_variable_name(line: str, name: str):
    assert get_variable_name(line) == name


string_match_cases = [
    ('return "hello world";', "hello world"),
    ('"hello\\\\"', "hello\\"),
    ('"hello \\"world\\""', 'hello "world"'),
    ('"hello\\nworld"', "hello\nworld"),
    # Only match first string if there are multiple options
    ('Method("hello", "world");', "hello"),
]


@pytest.mark.parametrize("line, string", string_match_cases)
def test_get_string_contents(line: str, string: str):
    assert get_string_contents(line) == string


def test_marker_extra_spaces():
    """The extra field can contain spaces"""
    marker = match_marker("// VTABLE: TEST 0x1234 S p a c e s")
    assert marker.extra == "S p a c e s"

    # Trailing spaces removed
    marker = match_marker("// VTABLE: TEST 0x8888 spaces    ")
    assert marker.extra == "spaces"

    # Trailing newline removed if present
    marker = match_marker("// VTABLE: TEST 0x5555 newline\n")
    assert marker.extra == "newline"


def test_marker_trailing_spaces():
    """Should ignore trailing spaces. (Invalid extra field)
    Offset field not truncated, extra field set to None."""

    marker = match_marker("// VTABLE: TEST 0x1234     ")
    assert marker is not None
    assert marker.offset == 0x1234
    assert marker.extra is None
