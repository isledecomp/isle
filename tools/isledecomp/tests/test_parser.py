import pytest
from isledecomp.parser.parser import (
    ReaderState,
    DecompParser,
)
from isledecomp.parser.util import DecompMarker
from isledecomp.parser.error import ParserError


@pytest.fixture
def parser():
    return DecompParser()


@pytest.mark.skip(reason="todo")
def test_missing_sig(parser):
    """Bad syntax: function signature is missing"""
    parser.read_lines(["// FUNCTION: TEST 0x1234", "{"])
    assert parser.state == ReaderState.IN_FUNC
    assert len(parser.alerts) == 1
    parser.read_line("}")
    assert len(parser.functions) == 1
    assert parser.functions[0] != "{"


def test_not_exact_syntax(parser):
    """Alert to inexact syntax right here in the parser instead of kicking it downstream.
    Doing this means we don't have to save the actual text."""
    parser.read_line("// function: test 0x1234")
    assert len(parser.alerts) == 1
    assert parser.alerts[0].code == ParserError.BAD_DECOMP_MARKER


def test_invalid_marker(parser):
    """We matched a decomp marker, but it's not one we care about"""
    parser.read_line("// BANANA: TEST 0x1234")
    assert parser.state == ReaderState.SEARCH

    assert len(parser.alerts) == 1
    assert parser.alerts[0].code == ParserError.BOGUS_MARKER


def test_unexpected_marker(parser):
    parser.read_lines(
        [
            "// FUNCTION: TEST 0x1234",
            "// GLOBAL: TEST 0x5000",
        ]
    )
    assert parser.state == ReaderState.SEARCH
    assert len(parser.alerts) == 1
    assert parser.alerts[0].code == ParserError.INCOMPATIBLE_MARKER


def test_variable(parser):
    parser.read_lines(
        [
            "// GLOBAL: HELLO 0x1234",
            "int g_value = 5;",
        ]
    )
    assert len(parser.variables) == 1


def test_synthetic_plus_marker(parser):
    """Should fail with error and not log the synthetic"""
    parser.read_lines(
        [
            "// SYNTHETIC: HEY 0x555",
            "// FUNCTION: HOWDY 0x1234",
        ]
    )
    assert len(parser.functions) == 0
    assert len(parser.alerts) == 1
    assert parser.alerts[0].code == ParserError.INCOMPATIBLE_MARKER


def test_different_markers_different_module(parser):
    """Does it make any sense for a function to be a stub in one module,
    but not in another? I don't know. But it's no problem for us."""
    parser.read_lines(
        [
            "// FUNCTION: HOWDY 0x1234",
            "// STUB: SUP 0x5555",
            "void interesting_function() {",
            "}",
        ]
    )

    assert len(parser.alerts) == 0
    assert len(parser.functions) == 2


def test_different_markers_same_module(parser):
    """Now, if something is a regular function but then a stub,
    what do we say about that?"""
    parser.read_lines(
        [
            "// FUNCTION: HOWDY 0x1234",
            "// STUB: HOWDY 0x5555",
            "void interesting_function() {",
            "}",
        ]
    )

    # Use first marker declaration, don't replace
    assert len(parser.functions) == 1
    assert parser.functions[0].is_stub is False

    # Should alert to this
    assert len(parser.alerts) == 1
    assert parser.alerts[0].code == ParserError.DUPLICATE_MODULE


def test_unexpected_synthetic(parser):
    """FUNCTION then SYNTHETIC should fail to report either one"""
    parser.read_lines(
        [
            "// FUNCTION: HOWDY 0x1234",
            "// SYNTHETIC: HOWDY 0x5555",
            "void interesting_function() {",
            "}",
        ]
    )

    assert parser.state == ReaderState.SEARCH
    assert len(parser.functions) == 0
    assert len(parser.alerts) == 1
    assert parser.alerts[0].code == ParserError.INCOMPATIBLE_MARKER


@pytest.mark.skip(reason="not implemented yet")
def test_duplicate_offset(parser):
    """Repeating the same module/offset in the same file is probably a typo"""
    parser.read_lines(
        [
            "// GLOBAL: HELLO 0x1234",
            "int x = 1;",
            "// GLOBAL: HELLO 0x1234",
            "int y = 2;",
        ]
    )

    assert len(parser.alerts) == 1
    assert parser.alerts[0].code == ParserError.DUPLICATE_OFFSET


def test_multiple_variables(parser):
    """Theoretically the same global variable can appear in multiple modules"""
    parser.read_lines(
        [
            "// GLOBAL: HELLO 0x1234",
            "// GLOBAL: WUZZUP 0x555",
            "const char *g_greeting;",
        ]
    )
    assert len(parser.alerts) == 0
    assert len(parser.variables) == 2


def test_multiple_vtables(parser):
    parser.read_lines(
        [
            "// VTABLE: HELLO 0x1234",
            "// VTABLE: TEST 0x5432",
            "class MxString : public MxCore {",
        ]
    )
    assert len(parser.alerts) == 0
    assert len(parser.vtables) == 2
