import os
from typing import List, TextIO
import pytest
from isledecomp.parser import DecompParser
from isledecomp.parser.node import ParserSymbol

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "samples")


def sample_file(filename: str) -> TextIO:
    """Wrapper for opening the samples from the directory that does not
    depend on the cwd where we run the test"""
    full_path = os.path.join(SAMPLE_DIR, filename)
    return open(full_path, "r", encoding="utf-8")


def code_blocks_are_sorted(blocks: List[ParserSymbol]) -> bool:
    """Helper to make this more idiomatic"""
    just_offsets = [block.offset for block in blocks]
    return just_offsets == sorted(just_offsets)


@pytest.fixture(name="parser")
def fixture_parser():
    return DecompParser()


# Tests are below #


def test_sanity(parser):
    """Read a very basic file"""
    with sample_file("basic_file.cpp") as f:
        parser.read_lines(f)

    assert len(parser.functions) == 3
    assert code_blocks_are_sorted(parser.functions) is True
    # n.b. The parser returns line numbers as 1-based
    # Function starts when we see the opening curly brace
    assert parser.functions[0].line_number == 8
    assert parser.functions[0].end_line == 10


def test_oneline(parser):
    """(Assuming clang-format permits this) This sample has a function
    on a single line. This will test the end-of-function detection"""
    with sample_file("oneline_function.cpp") as f:
        parser.read_lines(f)

    assert len(parser.functions) == 2
    assert parser.functions[0].line_number == 5
    assert parser.functions[0].end_line == 5


def test_missing_offset(parser):
    """What if the function doesn't have an offset comment?"""
    with sample_file("missing_offset.cpp") as f:
        parser.read_lines(f)

    # TODO: For now, the function without the offset will just be ignored.
    # Would be the same outcome if the comment was present but mangled and
    # we failed to match it. We should detect these cases in the future.
    assert len(parser.functions) == 1


def test_jumbled_case(parser):
    """The parser just reports what it sees. It is the responsibility of
    the downstream tools to do something about a jumbled file.
    Just verify that we are reading it correctly."""
    with sample_file("out_of_order.cpp") as f:
        parser.read_lines(f)

    assert len(parser.functions) == 3
    assert code_blocks_are_sorted(parser.functions) is False


def test_bad_file(parser):
    with sample_file("poorly_formatted.cpp") as f:
        parser.read_lines(f)

    assert len(parser.functions) == 3


def test_indented(parser):
    """Offsets for functions inside of a class will probably be indented."""
    with sample_file("basic_class.cpp") as f:
        parser.read_lines(f)

    # TODO: We don't properly detect the end of these functions
    # because the closing brace is indented. However... knowing where each
    # function ends is less important (for now) than capturing
    # all the functions that are there.

    assert len(parser.functions) == 2
    assert parser.functions[0].offset == int("0x12345678", 16)
    assert parser.functions[0].line_number == 16
    # assert parser.functions[0].end_line == 19

    assert parser.functions[1].offset == int("0xdeadbeef", 16)
    assert parser.functions[1].line_number == 23
    # assert parser.functions[1].end_line == 25


def test_inline(parser):
    with sample_file("inline.cpp") as f:
        parser.read_lines(f)

    assert len(parser.functions) == 2
    for fun in parser.functions:
        assert fun.line_number is not None
        assert fun.line_number == fun.end_line


def test_multiple_offsets(parser):
    """If multiple offset marks appear before for a code block, take them
    all but ensure module name (case-insensitive) is distinct.
    Use first module occurrence in case of duplicates."""
    with sample_file("multiple_offsets.cpp") as f:
        parser.read_lines(f)

    assert len(parser.functions) == 4
    assert parser.functions[0].module == "TEST"
    assert parser.functions[0].line_number == 9

    assert parser.functions[1].module == "HELLO"
    assert parser.functions[1].line_number == 9

    # Duplicate modules are ignored
    assert parser.functions[2].line_number == 16
    assert parser.functions[2].offset == 0x2345

    assert parser.functions[3].module == "TEST"
    assert parser.functions[3].offset == 0x2002


def test_variables(parser):
    with sample_file("global_variables.cpp") as f:
        parser.read_lines(f)

    assert len(parser.functions) == 1
    assert len(parser.variables) == 2
