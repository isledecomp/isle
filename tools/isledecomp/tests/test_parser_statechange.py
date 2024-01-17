from typing import Optional
import pytest
from isledecomp.parser.parser import (
    ReaderState as _rs,
    DecompParser,
)
from isledecomp.parser.error import ParserError as _pe

# fmt: off
state_change_marker_cases = [
    (_rs.SEARCH,          "FUNCTION",   _rs.WANT_SIG,        None),
    (_rs.SEARCH,          "GLOBAL",     _rs.IN_GLOBAL,       None),
    (_rs.SEARCH,          "STUB",       _rs.WANT_SIG,        None),
    (_rs.SEARCH,          "SYNTHETIC",  _rs.IN_SYNTHETIC,    None),
    (_rs.SEARCH,          "TEMPLATE",   _rs.IN_TEMPLATE,     None),
    (_rs.SEARCH,          "VTABLE",     _rs.IN_VTABLE,       None),
    (_rs.SEARCH,          "LIBRARY",    _rs.IN_LIBRARY,      None),
    (_rs.SEARCH,          "STRING",     _rs.IN_GLOBAL,       None),

    (_rs.WANT_SIG,        "FUNCTION",   _rs.WANT_SIG,        None),
    (_rs.WANT_SIG,        "GLOBAL",     _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.WANT_SIG,        "STUB",       _rs.WANT_SIG,        None),
    (_rs.WANT_SIG,        "SYNTHETIC",  _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.WANT_SIG,        "TEMPLATE",   _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.WANT_SIG,        "VTABLE",     _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.WANT_SIG,        "LIBRARY",    _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.WANT_SIG,        "STRING",     _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),

    (_rs.IN_FUNC,         "FUNCTION",   _rs.WANT_SIG,        _pe.MISSED_END_OF_FUNCTION),
    (_rs.IN_FUNC,         "GLOBAL",     _rs.IN_FUNC_GLOBAL,  None),
    (_rs.IN_FUNC,         "STUB",       _rs.WANT_SIG,        _pe.MISSED_END_OF_FUNCTION),
    (_rs.IN_FUNC,         "SYNTHETIC",  _rs.IN_SYNTHETIC,    _pe.MISSED_END_OF_FUNCTION),
    (_rs.IN_FUNC,         "TEMPLATE",   _rs.IN_TEMPLATE,     _pe.MISSED_END_OF_FUNCTION),
    (_rs.IN_FUNC,         "VTABLE",     _rs.IN_VTABLE,       _pe.MISSED_END_OF_FUNCTION),
    (_rs.IN_FUNC,         "LIBRARY",    _rs.IN_LIBRARY,      _pe.MISSED_END_OF_FUNCTION),
    (_rs.IN_FUNC,         "STRING",     _rs.IN_FUNC_GLOBAL,  None),

    (_rs.IN_TEMPLATE,     "FUNCTION",   _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_TEMPLATE,     "GLOBAL",     _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_TEMPLATE,     "STUB",       _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_TEMPLATE,     "SYNTHETIC",  _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_TEMPLATE,     "TEMPLATE",   _rs.IN_TEMPLATE,     None),
    (_rs.IN_TEMPLATE,     "VTABLE",     _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_TEMPLATE,     "LIBRARY",    _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_TEMPLATE,     "STRING",     _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),

    (_rs.WANT_CURLY,      "FUNCTION",   _rs.SEARCH,          _pe.UNEXPECTED_MARKER),
    (_rs.WANT_CURLY,      "GLOBAL",     _rs.SEARCH,          _pe.UNEXPECTED_MARKER),
    (_rs.WANT_CURLY,      "STUB",       _rs.SEARCH,          _pe.UNEXPECTED_MARKER),
    (_rs.WANT_CURLY,      "SYNTHETIC",  _rs.SEARCH,          _pe.UNEXPECTED_MARKER),
    (_rs.WANT_CURLY,      "TEMPLATE",   _rs.SEARCH,          _pe.UNEXPECTED_MARKER),
    (_rs.WANT_CURLY,      "VTABLE",     _rs.SEARCH,          _pe.UNEXPECTED_MARKER),
    (_rs.WANT_CURLY,      "LIBRARY",    _rs.SEARCH,          _pe.UNEXPECTED_MARKER),
    (_rs.WANT_CURLY,      "STRING",     _rs.SEARCH,          _pe.UNEXPECTED_MARKER),

    (_rs.IN_GLOBAL,       "FUNCTION",   _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_GLOBAL,       "GLOBAL",     _rs.IN_GLOBAL,       None),
    (_rs.IN_GLOBAL,       "STUB",       _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_GLOBAL,       "SYNTHETIC",  _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_GLOBAL,       "TEMPLATE",   _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_GLOBAL,       "VTABLE",     _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_GLOBAL,       "LIBRARY",    _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_GLOBAL,       "STRING",     _rs.IN_GLOBAL,       None),

    (_rs.IN_FUNC_GLOBAL,  "FUNCTION",   _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_FUNC_GLOBAL,  "GLOBAL",     _rs.IN_FUNC_GLOBAL,  None),
    (_rs.IN_FUNC_GLOBAL,  "STUB",       _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_FUNC_GLOBAL,  "SYNTHETIC",  _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_FUNC_GLOBAL,  "TEMPLATE",   _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_FUNC_GLOBAL,  "VTABLE",     _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_FUNC_GLOBAL,  "LIBRARY",    _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_FUNC_GLOBAL,  "STRING",     _rs.IN_FUNC_GLOBAL,  None),

    (_rs.IN_VTABLE,       "FUNCTION",   _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_VTABLE,       "GLOBAL",     _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_VTABLE,       "STUB",       _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_VTABLE,       "SYNTHETIC",  _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_VTABLE,       "TEMPLATE",   _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_VTABLE,       "VTABLE",     _rs.IN_VTABLE,       None),
    (_rs.IN_VTABLE,       "LIBRARY",    _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_VTABLE,       "STRING",     _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),

    (_rs.IN_SYNTHETIC,    "FUNCTION",   _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_SYNTHETIC,    "GLOBAL",     _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_SYNTHETIC,    "STUB",       _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_SYNTHETIC,    "SYNTHETIC",  _rs.IN_SYNTHETIC,    None),
    (_rs.IN_SYNTHETIC,    "TEMPLATE",   _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_SYNTHETIC,    "VTABLE",     _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_SYNTHETIC,    "LIBRARY",    _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_SYNTHETIC,    "STRING",     _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),

    (_rs.IN_LIBRARY,      "FUNCTION",   _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_LIBRARY,      "GLOBAL",     _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_LIBRARY,      "STUB",       _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_LIBRARY,      "SYNTHETIC",  _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_LIBRARY,      "TEMPLATE",   _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_LIBRARY,      "VTABLE",     _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
    (_rs.IN_LIBRARY,      "LIBRARY",    _rs.IN_LIBRARY,      None),
    (_rs.IN_LIBRARY,      "STRING",     _rs.SEARCH,          _pe.INCOMPATIBLE_MARKER),
]
# fmt: on


@pytest.mark.parametrize(
    "state, marker_type, new_state, expected_error", state_change_marker_cases
)
def test_state_change_by_marker(
    state: _rs, marker_type: str, new_state: _rs, expected_error: Optional[_pe]
):
    p = DecompParser()
    p.state = state
    mock_line = f"// {marker_type}: TEST 0x1234"
    p.read_line(mock_line)
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
