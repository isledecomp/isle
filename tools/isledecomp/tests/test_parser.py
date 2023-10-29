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
    # n.b. The parser returns line numbers as 0-based
    assert blocks[0].start_line == 5
    assert blocks[0].end_line == 9


def test_oneline():
    """(Assuming clang-format permits this) This sample has a function
    on a single line. This will test the end-of-function detection"""
    with sample_file('oneline_function.cpp') as f:
        blocks = find_code_blocks(f)

    assert len(blocks) == 2
    assert blocks[0].start_line == 3
    # TODO: Because of the way it works now, this captures the blank line
    # as part of the function. That's not *incorrect* per se, but
    # this needs to be more consistent if we want the tool to sort the
    # code blocks in the file.
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
