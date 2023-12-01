import pytest
from isledecomp.parser.parser import (
    ReaderState as _rs,
    DecompParser,
)
from isledecomp.parser.util import DecompMarker
from isledecomp.parser.error import ParserError as _pe

# fmt: off
state_change_marker_cases = [
    (_rs.SEARCH,          "FUNCTION",   _rs.WANT_SIG,        None),
    (_rs.SEARCH,          "GLOBAL",     _rs.IN_GLOBAL,       None),
    (_rs.SEARCH,          "STUB",       _rs.WANT_SIG,        None),
    (_rs.SEARCH,          "SYNTHETIC",  _rs.IN_TEMPLATE,     None),
    (_rs.SEARCH,          "TEMPLATE",   _rs.IN_TEMPLATE,     None),
    (_rs.SEARCH,          "VTABLE",     _rs.IN_VTABLE,       None),

    (_rs.WANT_SIG,        "FUNCTION",   _rs.WANT_SIG,        None),
    (_rs.WANT_SIG,        "GLOBAL",     _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.WANT_SIG,        "STUB",       _rs.WANT_SIG,        None),
    (_rs.WANT_SIG,        "SYNTHETIC",  _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.WANT_SIG,        "TEMPLATE",   _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.WANT_SIG,        "VTABLE",     _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),

    (_rs.IN_FUNC,         "FUNCTION",   _rs.WANT_SIG,        _pe.MISSED_END_OF_FUNCTION),
    (_rs.IN_FUNC,         "GLOBAL",     _rs.IN_FUNC_GLOBAL,  None),
    (_rs.IN_FUNC,         "STUB",       _rs.WANT_SIG,        _pe.MISSED_END_OF_FUNCTION),
    (_rs.IN_FUNC,         "SYNTHETIC",  _rs.IN_TEMPLATE,     _pe.MISSED_END_OF_FUNCTION),
    (_rs.IN_FUNC,         "TEMPLATE",   _rs.IN_TEMPLATE,     _pe.MISSED_END_OF_FUNCTION),
    (_rs.IN_FUNC,         "VTABLE",     _rs.IN_VTABLE,       _pe.MISSED_END_OF_FUNCTION),

    (_rs.IN_TEMPLATE,     "FUNCTION",   _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_TEMPLATE,     "GLOBAL",     _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_TEMPLATE,     "STUB",       _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_TEMPLATE,     "SYNTHETIC",  _rs.IN_TEMPLATE,     None),
    (_rs.IN_TEMPLATE,     "TEMPLATE",   _rs.IN_TEMPLATE,     None),
    (_rs.IN_TEMPLATE,     "VTABLE",     _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    
    (_rs.WANT_CURLY,      "FUNCTION",   _rs.SEARCH,          _pe.UNEXPECTED_MARKER),
    (_rs.WANT_CURLY,      "GLOBAL",     _rs.SEARCH,          _pe.UNEXPECTED_MARKER),
    (_rs.WANT_CURLY,      "STUB",       _rs.SEARCH,          _pe.UNEXPECTED_MARKER),
    (_rs.WANT_CURLY,      "SYNTHETIC",  _rs.SEARCH,          _pe.UNEXPECTED_MARKER),
    (_rs.WANT_CURLY,      "TEMPLATE",   _rs.SEARCH,          _pe.UNEXPECTED_MARKER),
    (_rs.WANT_CURLY,      "VTABLE",     _rs.SEARCH,          _pe.UNEXPECTED_MARKER),
    
    (_rs.IN_GLOBAL,       "FUNCTION",   _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_GLOBAL,       "GLOBAL",     _rs.IN_GLOBAL,       None),
    (_rs.IN_GLOBAL,       "STUB",       _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_GLOBAL,       "SYNTHETIC",  _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_GLOBAL,       "TEMPLATE",   _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_GLOBAL,       "VTABLE",     _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    
    (_rs.IN_FUNC_GLOBAL,  "FUNCTION",   _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_FUNC_GLOBAL,  "GLOBAL",     _rs.IN_FUNC_GLOBAL,  None),
    (_rs.IN_FUNC_GLOBAL,  "STUB",       _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_FUNC_GLOBAL,  "SYNTHETIC",  _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_FUNC_GLOBAL,  "TEMPLATE",   _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_FUNC_GLOBAL,  "VTABLE",     _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    
    (_rs.IN_VTABLE,       "FUNCTION",   _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_VTABLE,       "GLOBAL",     _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_VTABLE,       "STUB",       _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_VTABLE,       "SYNTHETIC",  _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_VTABLE,       "TEMPLATE",   _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_VTABLE,       "VTABLE",     _rs.IN_VTABLE,       None),
]
# fmt: on


@pytest.mark.parametrize(
    "state, marker_type, new_state, expected_error", state_change_marker_cases
)
def test_state_change_by_marker(
    state: _rs, marker_type: str, new_state: _rs, expected_error: None | _pe
):
    p = DecompParser()
    p.state = state
    p._handle_marker(DecompMarker(marker_type, "TEST", 0x1234))
    assert p.state == new_state

    if expected_error is not None:
        assert len(p.alerts) > 0
        assert p.alerts[0].code == expected_error


# Reading any of these lines should have no effect in ReaderState.SEARCH
search_lines_no_effect = [
    "",
    "\t",
    "    ",
    "int x = 0;",
    "// Comment",
    "/*",
    "*/",
    "/* Block comment */",
    "{",
    "}",
]


@pytest.mark.parametrize("line", search_lines_no_effect)
def test_state_search_line(line: str):
    p = DecompParser()
    p.read_line(line)
    assert p.state == _rs.SEARCH
    assert len(p.alerts) == 0


global_lines = [
    ("// A comment", _rs.IN_GLOBAL),
    ("", _rs.IN_GLOBAL),
    ("\t", _rs.IN_GLOBAL),
    ("    ", _rs.IN_GLOBAL),
    # TODO: no check for "likely" variable declaration so these all count
    ("void function()", _rs.SEARCH),
    ("int x = 123;", _rs.SEARCH),
    ("just some text", _rs.SEARCH),
]


@pytest.mark.parametrize("line, new_state", global_lines)
def test_state_global_line(line: str, new_state: _rs):
    p = DecompParser()
    p.read_line("// GLOBAL: TEST 0x1234")
    assert p.state == _rs.IN_GLOBAL
    p.read_line(line)
    assert p.state == new_state


# mostly same as above
in_func_global_lines = [
    ("// A comment", _rs.IN_FUNC_GLOBAL),
    ("", _rs.IN_FUNC_GLOBAL),
    ("\t", _rs.IN_FUNC_GLOBAL),
    ("    ", _rs.IN_FUNC_GLOBAL),
    # TODO: no check for "likely" variable declaration so these all count
    ("void function()", _rs.IN_FUNC),
    ("int x = 123;", _rs.IN_FUNC),
    ("just some text", _rs.IN_FUNC),
]


@pytest.mark.parametrize("line, new_state", in_func_global_lines)
def test_state_in_func_global_line(line: str, new_state: _rs):
    p = DecompParser()
    p.state = _rs.IN_FUNC
    p.read_line("// GLOBAL: TEST 0x1234")
    assert p.state == _rs.IN_FUNC_GLOBAL
    p.read_line(line)
    assert p.state == new_state
