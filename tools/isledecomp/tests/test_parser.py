import pytest
from isledecomp.parser.parser import (
    ReaderState,
    DecompParser,
)
from isledecomp.parser.error import ParserError


@pytest.fixture(name="parser")
def fixture_parser():
    return DecompParser()


def test_missing_sig(parser):
    """In the hopefully rare scenario that the function signature and marker
    are swapped, we still have enough to match witch reccmp"""
    parser.read_lines(
        [
            "void my_function()",
            "// FUNCTION: TEST 0x1234",
            "{",
            "}",
        ]
    )
    assert parser.state == ReaderState.SEARCH
    assert len(parser.functions) == 1
    assert parser.functions[0].line_number == 3

    assert len(parser.alerts) == 1
    assert parser.alerts[0].code == ParserError.MISSED_START_OF_FUNCTION


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


def test_incompatible_marker(parser):
    """The marker we just read cannot be handled in the current parser state"""
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
    """Should identify a global variable"""
    parser.read_lines(
        [
            "// GLOBAL: HELLO 0x1234",
            "int g_value = 5;",
        ]
    )
    assert len(parser.variables) == 1


def test_synthetic_plus_marker(parser):
    """Marker tracking preempts synthetic name detection.
    Should fail with error and not log the synthetic"""
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
    assert parser.functions[0].should_skip() is False

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


def test_multiple_variables_same_module(parser):
    """Should not overwrite offset"""
    parser.read_lines(
        [
            "// GLOBAL: HELLO 0x1234",
            "// GLOBAL: HELLO 0x555",
            "const char *g_greeting;",
        ]
    )
    assert len(parser.alerts) == 1
    assert parser.alerts[0].code == ParserError.DUPLICATE_MODULE
    assert len(parser.variables) == 1
    assert parser.variables[0].offset == 0x1234


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
    assert parser.vtables[0].name == "MxString"


def test_multiple_vtables_same_module(parser):
    """Should not overwrite offset"""
    parser.read_lines(
        [
            "// VTABLE: HELLO 0x1234",
            "// VTABLE: HELLO 0x5432",
            "class MxString : public MxCore {",
        ]
    )
    assert len(parser.alerts) == 1
    assert parser.alerts[0].code == ParserError.DUPLICATE_MODULE
    assert len(parser.vtables) == 1
    assert parser.vtables[0].offset == 0x1234


def test_synthetic(parser):
    parser.read_lines(
        [
            "// SYNTHETIC: TEST 0x1234",
            "// TestClass::TestMethod",
        ]
    )
    assert len(parser.functions) == 1
    assert parser.functions[0].lookup_by_name is True
    assert parser.functions[0].name == "TestClass::TestMethod"


def test_synthetic_same_module(parser):
    parser.read_lines(
        [
            "// SYNTHETIC: TEST 0x1234",
            "// SYNTHETIC: TEST 0x555",
            "// TestClass::TestMethod",
        ]
    )
    assert len(parser.alerts) == 1
    assert parser.alerts[0].code == ParserError.DUPLICATE_MODULE
    assert len(parser.functions) == 1
    assert parser.functions[0].offset == 0x1234


def test_synthetic_no_comment(parser):
    """Synthetic marker followed by a code line (i.e. non-comment)"""
    parser.read_lines(
        [
            "// SYNTHETIC: TEST 0x1234",
            "int x = 123;",
        ]
    )
    assert len(parser.functions) == 0
    assert len(parser.alerts) == 1
    assert parser.alerts[0].code == ParserError.BAD_NAMEREF
    assert parser.state == ReaderState.SEARCH


def test_single_line_function(parser):
    parser.read_lines(
        [
            "// FUNCTION: TEST 0x1234",
            "int hello() { return 1234; }",
        ]
    )
    assert len(parser.functions) == 1
    assert parser.functions[0].line_number == 2
    assert parser.functions[0].end_line == 2


def test_indented_function(parser):
    """Track the number of whitespace characters when we begin the function
    and check that against each closing curly brace we read.
    Should not report a syntax warning if the function is indented"""
    parser.read_lines(
        [
            "    // FUNCTION: TEST 0x1234",
            "    void indented()",
            "    {",
            "        // TODO",
            "    }",
            "    // FUNCTION: NEXT 0x555",
        ]
    )
    assert len(parser.alerts) == 0


@pytest.mark.xfail(reason="todo")
def test_indented_no_curly_hint(parser):
    """Same as above, but opening curly brace is on the same line.
    Without the hint of how many whitespace characters to check, can we
    still identify the end of the function?"""
    parser.read_lines(
        [
            "    // FUNCTION: TEST 0x1234",
            "    void indented() {",
            "    }",
            "    // FUNCTION: NEXT 0x555",
        ]
    )
    assert len(parser.alerts) == 0


def test_implicit_lookup_by_name(parser):
    """FUNCTION (or STUB) offsets must directly precede the function signature.
    If we detect a comment instead, we assume that this is a lookup-by-name
    function and end here."""
    parser.read_lines(
        [
            "// FUNCTION: TEST 0x1234",
            "// TestClass::TestMethod()",
        ]
    )
    assert parser.state == ReaderState.SEARCH
    assert len(parser.functions) == 1
    assert parser.functions[0].lookup_by_name is True
    assert parser.functions[0].name == "TestClass::TestMethod()"


def test_function_with_spaces(parser):
    """There should not be any spaces between the end of FUNCTION markers
    and the start or name of the function. If it's a blank line, we can safely
    ignore but should alert to this."""
    parser.read_lines(
        [
            "// FUNCTION: TEST 0x1234",
            "   ",
            "inline void test_function() { };",
        ]
    )
    assert len(parser.functions) == 1
    assert len(parser.alerts) == 1
    assert parser.alerts[0].code == ParserError.UNEXPECTED_BLANK_LINE


def test_function_with_spaces_implicit(parser):
    """Same as above, but for implicit lookup-by-name"""
    parser.read_lines(
        [
            "// FUNCTION: TEST 0x1234",
            "   ",
            "// Implicit::Method",
        ]
    )
    assert len(parser.functions) == 1
    assert len(parser.alerts) == 1
    assert parser.alerts[0].code == ParserError.UNEXPECTED_BLANK_LINE


@pytest.mark.xfail(reason="will assume implicit lookup-by-name function")
def test_function_is_commented(parser):
    """In an ideal world, we would recognize that there is no code here.
    Some editors (or users) might comment the function on each line like this
    but hopefully it is rare."""
    parser.read_lines(
        [
            "// FUNCTION: TEST 0x1234",
            "// int my_function()",
            "// {",
            "//     return 5;",
            "// }",
        ]
    )

    assert len(parser.functions) == 0


def test_unexpected_eof(parser):
    """If a decomp marker finds its way to the last line of the file,
    report that we could not get anything from it."""
    parser.read_lines(
        [
            "// FUNCTION: TEST 0x1234",
            "// Cls::Method",
            "// FUNCTION: TEST 0x5555",
        ]
    )
    parser.finish()

    assert len(parser.functions) == 1
    assert len(parser.alerts) == 1
    assert parser.alerts[0].code == ParserError.UNEXPECTED_END_OF_FILE


def test_global_variable_prefix(parser):
    """Global and static variables should have the g_ prefix."""
    parser.read_lines(
        [
            "// GLOBAL: TEST 0x1234",
            'const char* g_msg = "hello";',
        ]
    )
    assert len(parser.variables) == 1
    assert len(parser.alerts) == 0

    parser.read_lines(
        [
            "// GLOBAL: TEXT 0x5555",
            "int test = 5;",
        ]
    )
    assert len(parser.alerts) == 1
    assert parser.alerts[0].code == ParserError.GLOBAL_MISSING_PREFIX
    # In spite of that, we should still grab the variable name.
    assert parser.variables[1].name == "test"


def test_global_nomatch(parser):
    """We do our best to grab the variable name, even without the g_ prefix
    but this (by design) will not match everything."""

    parser.read_lines(
        [
            "// GLOBAL: TEST 0x1234",
            "FunctionCall();",
        ]
    )
    assert len(parser.variables) == 0
    assert len(parser.alerts) == 1
    assert parser.alerts[0].code == ParserError.NO_SUITABLE_NAME


def test_static_variable(parser):
    """We can detect whether a variable is a static function variable
    based on the parser's state when we detect it.
    Checking for the word `static` alone is not a good test.
    Static class variables are filed as S_GDATA32, same as regular globals.
    Only function statics are filed as S_LDATA32."""

    parser.read_lines(
        [
            "// GLOBAL: TEST 0x1234",
            "int g_test = 1234;",
        ]
    )
    assert len(parser.variables) == 1
    assert parser.variables[0].is_static is False

    parser.read_lines(
        [
            "// FUNCTION: TEST 0x5555",
            "void test_function() {",
            "// GLOBAL: TEST 0x8888",
            "int g_internal = 0;",
            "}",
        ]
    )
    assert len(parser.variables) == 2
    assert parser.variables[1].is_static is True
