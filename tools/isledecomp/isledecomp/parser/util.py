# C++ Parser utility functions and data structures
import re
from collections import namedtuple


CodeBlock = namedtuple('CodeBlock',
                       ['offset', 'signature', 'start_line', 'end_line'])


FunctionOffset = namedtuple('FunctionOffset',
                            ['raw', 'address', 'is_stub'])


# To match a reasonable variance of formatting for the offset comment
offsetCommentRegex = re.compile(r'//\s*OFFSET:\s*\w+\s+(?:0x)?([a-f0-9]+)',
                                flags=re.I)

# To match the exact syntax (text upper case, hex lower case, with spaces)
# that is used in most places
offsetCommentExactRegex = re.compile(r'^// OFFSET: [A-Z0-9]+ (0x[a-f0-9]+)(?: STUB)?$')


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


def match_offset_comment(line: str) -> str | None:
    # TODO: intended to skip the expensive regex match, but is it necessary?
    # TODO: this will skip indented offsets
    if not line.startswith('//'):
        return None

    match = offsetCommentRegex.match(line)
    return match.group(1) if match is not None else None
