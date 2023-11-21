import pytest
from collections import namedtuple
from typing import List
from isledecomp.parser.util import (
    is_blank_or_comment,
    match_offset_comment,
    is_exact_offset_comment,
    distinct_by_module,
)


blank_or_comment_param = [
    (True,  ''),
    (True,  '\t'),
    (True,  '    '),
    (False, '\tint abc=123;'),
    (True,  '// OFFSET: LEGO1 0xdeadbeef'),
    (True,  '   /* Block comment beginning'),
    (True,  'Block comment ending */   '),

    # TODO: does clang-format have anything to say about these cases?
    (False, 'x++; // Comment folows'),
    (False, 'x++; /* Block comment begins'),
]


@pytest.mark.parametrize('expected, line', blank_or_comment_param)
def test_is_blank_or_comment(line: str, expected: bool):
    assert is_blank_or_comment(line) is expected


offset_comment_samples = [
    # (can_parse: bool, exact_match: bool, line: str)
    # Should match both expected modules with optional STUB marker
    (True,  True,  '// OFFSET: LEGO1 0xdeadbeef'),
    (True,  True,  '// OFFSET: LEGO1 0xdeadbeef STUB'),
    (True,  True,  '// OFFSET: ISLE 0x12345678'),
    (True,  True,  '// OFFSET: ISLE 0x12345678 STUB'),

    # No trailing spaces allowed
    (True,  False, '// OFFSET: LEGO1 0xdeadbeef  '),
    (True,  False, '// OFFSET: LEGO1 0xdeadbeef STUB '),

    # Must have exactly one space between elements
    (True,  False, '//OFFSET: ISLE 0xdeadbeef'),
    (True,  False, '// OFFSET:ISLE 0xdeadbeef'),
    (True,  False, '//  OFFSET: ISLE 0xdeadbeef'),
    (True,  False, '// OFFSET:  ISLE 0xdeadbeef'),
    (True,  False, '// OFFSET: ISLE  0xdeadbeef'),
    (True,  False, '// OFFSET: ISLE 0xdeadbeef  STUB'),

    # Must have 0x prefix for hex number
    (True,  False, '// OFFSET: ISLE deadbeef'),

    # Offset, module name, and STUB must be uppercase
    (True,  False, '// offset: ISLE 0xdeadbeef'),
    (True,  False, '// offset: isle 0xdeadbeef'),
    (True,  False, '// OFFSET: LEGO1 0xdeadbeef stub'),

    # Hex string must be lowercase
    (True,  False, '// OFFSET: ISLE 0xDEADBEEF'),

    # TODO: How flexible should we be with matching the module name?
    (True,  True,  '// OFFSET: OMNI 0x12345678'),
    (True,  True,  '// OFFSET: LEG01 0x12345678'),
    (True,  False,  '// OFFSET: hello 0x12345678'),

    # Not close enough to match
    (False, False, '// OFFSET: ISLE0x12345678'),
    (False, False, '// OFFSET: 0x12345678'),
    (False, False, '// LEGO1: 0x12345678'),

    # Hex string shorter than 8 characters
    (True,  True,  '// OFFSET: LEGO1 0x1234'),

    # TODO: These match but shouldn't.
    # (False, False, '// OFFSET: LEGO1 0'),
    # (False, False, '// OFFSET: LEGO1 0x'),
]


@pytest.mark.parametrize('match, exact, line', offset_comment_samples)
def test_offset_match(line: str, match: bool, exact):
    did_match = match_offset_comment(line) is not None
    assert did_match is match


@pytest.mark.parametrize('match, exact, line', offset_comment_samples)
def test_exact_offset_comment(line: str, exact: bool, match):
    assert is_exact_offset_comment(line) is exact


# Helper for the next test: cut down version of OffsetMatch
MiniOfs = namedtuple('MiniOfs', ['module', 'value'])

distinct_by_module_samples = [
    # empty set
    ([], []),
    # same module name
    ([MiniOfs('TEST', 123), MiniOfs('TEST', 555)],
     [MiniOfs('TEST', 123)]),
    # same module name, case-insensitive
    ([MiniOfs('test', 123), MiniOfs('TEST', 555)],
     [MiniOfs('test', 123)]),
    # duplicates, non-consecutive
    ([MiniOfs('test', 123), MiniOfs('abc', 111), MiniOfs('TEST', 555)],
     [MiniOfs('test', 123), MiniOfs('abc', 111)]),
]


@pytest.mark.parametrize('sample, expected', distinct_by_module_samples)
def test_distinct_by_module(sample: List[MiniOfs], expected: List[MiniOfs]):
    assert distinct_by_module(sample) == expected
