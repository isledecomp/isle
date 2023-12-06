import pytest
from isledecomp.parser.parser import MarkerDict
from isledecomp.parser.util import (
    DecompMarker,
    is_blank_or_comment,
    match_marker,
    is_marker_exact,
    get_class_name,
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
    assert markers[0].type == "FUNCTION"


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
