import os
import pytest
from typing import List, TextIO
from isledecomp.parser import find_code_blocks
from isledecomp.parser.util import CodeBlock

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), 'samples')


def sample_file(filename: str) -> TextIO:
    """Wrapper for opening the samples from the directory that does not
       depend on the cwd where we run the test"""
    full_path = os.path.join(SAMPLE_DIR, filename)
    return open(full_path, 'r')


def code_blocks_are_sorted(blocks: List[CodeBlock]) -> bool:
    """Helper to make this more idiomatic"""
    just_offsets = [block.offset for block in blocks]
    return just_offsets == sorted(just_offsets)


# Tests are below #


def test_sanity():
    """Read a very basic file"""
    with sample_file('basic_file.cpp') as f:
        blocks = find_code_blocks(f)

    assert len(blocks) == 3
    assert code_blocks_are_sorted(blocks) is True
    # n.b. The parser returns line numbers as 1-based
    # Function starts when we see the opening curly brace
    assert blocks[0].start_line == 8
    assert blocks[0].end_line == 10


def test_oneline():
    """(Assuming clang-format permits this) This sample has a function
    on a single line. This will test the end-of-function detection"""
    with sample_file('oneline_function.cpp') as f:
        blocks = find_code_blocks(f)

    assert len(blocks) == 2
    assert blocks[0].start_line == 5
    assert blocks[0].end_line == 5


def test_missing_offset():
    """What if the function doesn't have an offset comment?"""
    with sample_file('missing_offset.cpp') as f:
        blocks = find_code_blocks(f)

    # TODO: For now, the function without the offset will just be ignored.
    # Would be the same outcome if the comment was present but mangled and
    # we failed to match it. We should detect these cases in the future.
    assert len(blocks) == 1


def test_jumbled_case():
    """The parser just reports what it sees. It is the responsibility of
       the downstream tools to do something about a jumbled file.
       Just verify that we are reading it correctly."""
    with sample_file('out_of_order.cpp') as f:
        blocks = find_code_blocks(f)

    assert len(blocks) == 3
    assert code_blocks_are_sorted(blocks) is False


def test_bad_file():
    with sample_file('poorly_formatted.cpp') as f:
        blocks = find_code_blocks(f)

    assert len(blocks) == 3


def test_indented():
    """Offsets for functions inside of a class will probably be indented."""
    with sample_file('basic_class.cpp') as f:
        blocks = find_code_blocks(f)

    # TODO: We don't properly detect the end of these functions
    # because the closing brace is indented. However... knowing where each
    # function ends is less important (for now) than capturing
    # all the functions that are there.

    assert len(blocks) == 2
    assert blocks[0].offset == int('0x12345678', 16)
    assert blocks[0].start_line == 15
    # assert blocks[0].end_line == 18

    assert blocks[1].offset == int('0xdeadbeef', 16)
    assert blocks[1].start_line == 22
    # assert blocks[1].end_line == 24


def test_inline():
    with sample_file('inline.cpp') as f:
        blocks = find_code_blocks(f)

    assert len(blocks) == 2
    for block in blocks:
        assert block.start_line is not None
        assert block.start_line == block.end_line


def test_multiple_offsets():
    """If multiple offset marks appear before for a code block, take them
       all but ensure module name (case-insensitive) is distinct.
       Use first module occurrence in case of duplicates."""
    with sample_file('multiple_offsets.cpp') as f:
        blocks = find_code_blocks(f)

    assert len(blocks) == 4
    assert blocks[0].module == 'TEST'
    assert blocks[0].start_line == 9

    assert blocks[1].module == 'HELLO'
    assert blocks[1].start_line == 9

    # Duplicate modules are ignored
    assert blocks[2].start_line == 16
    assert blocks[2].offset == 0x2345

    assert blocks[3].module == 'TEST'
    assert blocks[3].offset == 0x2002
