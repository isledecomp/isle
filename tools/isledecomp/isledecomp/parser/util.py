# C++ Parser utility functions and data structures
from __future__ import annotations  # python <3.10 compatibility
import re
from typing import List
from collections import namedtuple


CodeBlock = namedtuple(
    "CodeBlock",
    [
        "offset",
        "signature",
        "start_line",
        "end_line",
        "offset_comment",
        "module",
        "is_synthetic",
        "is_stub",
    ],
)

OffsetMatch = namedtuple(
    "OffsetMatch", ["module", "address", "is_synthetic", "is_stub", "comment"]
)

# This has not been formally established, but considering that "STUB"
# is a temporary state for a function, we assume it will appear last,
# after any other modifiers (i.e. SYNTHETIC)

# To match a reasonable variance of formatting for the offset comment
offsetCommentRegex = re.compile(
    r"\s*//\s*FUNCTION:\s*(\w+)\s+(?:0x)?([a-f0-9]+)(\s+SYNTHETIC)?(\s+STUB)?",  # nopep8
    flags=re.I,
)

# To match the exact syntax (text upper case, hex lower case, with spaces)
# that is used in most places
offsetCommentExactRegex = re.compile(
    r"^// FUNCTION: [A-Z0-9]+ (0x[a-f0-9]+)( SYNTHETIC)?( STUB)?$"
)  # nopep8


# The goal here is to just read whatever is on the next line, so some
# flexibility in the formatting seems OK
templateCommentRegex = re.compile(r"\s*//\s+(.*)")


# To remove any comment (//) or block comment (/*) and its leading spaces
# from the end of a code line
trailingCommentRegex = re.compile(r"(\s*(?://|/\*).*)$")


def get_template_function_name(line: str) -> str:
    """Parse function signature for special SYNTHETIC functions"""
    template_match = templateCommentRegex.match(line)

    # If we don't match, you get whatever is on the line as the signature
    if template_match is not None:
        return template_match.group(1)

    return line


def remove_trailing_comment(line: str) -> str:
    return trailingCommentRegex.sub("", line)


def is_blank_or_comment(line: str) -> bool:
    """Helper to read ahead after the offset comment is matched.
    There could be blank lines or other comments before the
    function signature, and we want to skip those."""
    line_strip = line.strip()
    return (
        len(line_strip) == 0
        or line_strip.startswith("//")
        or line_strip.startswith("/*")
        or line_strip.endswith("*/")
    )


def is_exact_offset_comment(line: str) -> bool:
    """If the offset comment does not match our (unofficial) syntax
    we may want to alert the user to fix it for style points."""
    return offsetCommentExactRegex.match(line) is not None


def match_offset_comment(line: str) -> OffsetMatch | None:
    match = offsetCommentRegex.match(line)
    if match is None:
        return None

    return OffsetMatch(
        module=match.group(1),
        address=int(match.group(2), 16),
        is_synthetic=match.group(3) is not None,
        is_stub=match.group(4) is not None,
        comment=line.strip(),
    )


def distinct_by_module(offsets: List) -> List:
    """Given a list of offset markers, return a list with distinct
    module names. If module names (case-insensitive) are repeated,
    choose the offset that appears first."""

    if len(offsets) < 2:
        return offsets

    # Dict maintains insertion order in python >=3.7
    offsets_dict = {}
    for offset in offsets:
        module_upper = offset.module.upper()
        if module_upper not in offsets_dict:
            offsets_dict[module_upper] = offset

    return list(offsets_dict.values())
