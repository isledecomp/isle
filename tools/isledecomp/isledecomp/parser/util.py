# C++ Parser utility functions and data structures
from __future__ import annotations  # python <3.10 compatibility
import re
from typing import List
from collections import namedtuple

DecompMarker = namedtuple("DecompMarker", ["type", "module", "offset"])


markerRegex = re.compile(
    r"\s*//\s*(\w+):\s*(\w+)\s+((?:0x)?[a-f0-9]+)",
    flags=re.I,
)

markerExactRegex = re.compile(r"\s*// ([A-Z]+): ([A-Z0-9]+) (0x[a-f0-9]+)$")

# The goal here is to just read whatever is on the next line, so some
# flexibility in the formatting seems OK
templateCommentRegex = re.compile(r"\s*//\s+(.*)")


# To remove any comment (//) or block comment (/*) and its leading spaces
# from the end of a code line
trailingCommentRegex = re.compile(r"(\s*(?://|/\*).*)$")


def get_template_function_name(line: str) -> str:
    """Parse function signature for special TEMPLATE functions"""
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


def match_marker(line: str) -> DecompMarker | None:
    match = markerRegex.match(line)
    if match is None:
        return None

    return DecompMarker(
        type=match.group(1), module=match.group(2), offset=int(match.group(3), 16)
    )


def is_marker_exact(line: str) -> bool:
    return markerExactRegex.match(line) is not None
