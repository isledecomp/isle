# C++ Parser utility functions and data structures
from __future__ import annotations # python <3.10 compatibility
import re
from collections import namedtuple


CodeBlock = namedtuple('CodeBlock',
                       ['offset', 'signature', 'start_line', 'end_line',
                        'offset_comment', 'module', 'is_template', 'is_stub'])

OffsetMatch = namedtuple('OffsetMatch', ['module', 'address',
                                         'is_template', 'is_stub'])

# This has not been formally established, but considering that "STUB"
# is a temporary state for a function, we assume it will appear last,
# after any other modifiers (i.e. TEMPLATE)

# To match a reasonable variance of formatting for the offset comment
offsetCommentRegex = re.compile(r'\s*//\s*OFFSET:\s*(\w+)\s+(?:0x)?([a-f0-9]+)(\s+TEMPLATE)?(\s+STUB)?',  # nopep8
                                flags=re.I)

# To match the exact syntax (text upper case, hex lower case, with spaces)
# that is used in most places
offsetCommentExactRegex = re.compile(r'^// OFFSET: [A-Z0-9]+ (0x[a-f0-9]+)( TEMPLATE)?( STUB)?$')  # nopep8


# The goal here is to just read whatever is on the next line, so some
# flexibility in the formatting seems OK
templateCommentRegex = re.compile(r'\s*//\s+(.*)')


# To remove any comment (//) or block comment (/*) and its leading spaces
# from the end of a code line
trailingCommentRegex = re.compile(r'(\s*(?://|/\*).*)$')


def template_function_name(line: str) -> str:
    """Parse function signature for special TEMPLATE functions"""
    template_match = templateCommentRegex.match(line)

    # If we don't match, you get whatever is on the line as the signature
    if template_match is not None:
        return template_match.group(1)
    else:
        return line


def remove_trailing_comment(line: str) -> str:
    return trailingCommentRegex.sub('', line)


def is_blank_or_comment(line: str) -> bool:
    """Helper to read ahead after the offset comment is matched.
       There could be blank lines or other comments before the
       function signature, and we want to skip those."""
    line_strip = line.strip()
    return (len(line_strip) == 0
            or line_strip.startswith('//')
            or line_strip.startswith('/*')
            or line_strip.endswith('*/'))


def is_exact_offset_comment(line: str) -> bool:
    """If the offset comment does not match our (unofficial) syntax
       we may want to alert the user to fix it for style points."""
    return offsetCommentExactRegex.match(line) is not None


def match_offset_comment(line: str) -> OffsetMatch | None:
    match = offsetCommentRegex.match(line)
    if match is None:
        return None

    return OffsetMatch(module=match.group(1),
                       address=int(match.group(2), 16),
                       is_template=match.group(3) is not None,
                       is_stub=match.group(4) is not None)
