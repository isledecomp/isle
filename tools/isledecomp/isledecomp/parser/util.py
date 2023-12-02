# C++ Parser utility functions and data structures
from __future__ import annotations  # python <3.10 compatibility
import re
from collections import namedtuple

DecompMarker = namedtuple("DecompMarker", ["type", "module", "offset"])


markerRegex = re.compile(
    r"\s*//\s*(\w+):\s*(\w+)\s+(0x[a-f0-9]+)",
    flags=re.I,
)

markerExactRegex = re.compile(r"\s*// ([A-Z]+): ([A-Z0-9]+) (0x[a-f0-9]+)$")

# The goal here is to just read whatever is on the next line, so some
# flexibility in the formatting seems OK
templateCommentRegex = re.compile(r"\s*//\s+(.*)")


# To remove any comment (//) or block comment (/*) and its leading spaces
# from the end of a code line
trailingCommentRegex = re.compile(r"(\s*(?://|/\*).*)$")


def get_synthetic_name(line: str) -> str | None:
    """Synthetic names appear on a single line comment on the line after the marker.
    If that's not what we have, return None"""
    template_match = templateCommentRegex.match(line)

    if template_match is not None:
        return template_match.group(1)

    return None


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


template_class_decl_regex = re.compile(
    r"\s*(?:\/\/)?\s*class (\w+)<([\w]+)\s*(\*+)?\s*>"
)


class_decl_regex = re.compile(r"\s*(?:\/\/)?\s*class (\w+)")


def get_class_name(line: str) -> str | None:
    """For VTABLE markers, extract the class name from the code line or comment
    where it appears."""

    match = template_class_decl_regex.match(line)
    if match is not None:
        # For template classes, we should reformat the class name so it matches
        # the output from cvdump: one space between the template type and any asterisks
        # if it is a pointer type.
        (class_name, template_type, asterisks) = match.groups()
        if asterisks is not None:
            return f"{class_name}<{template_type} {asterisks}>"

        return f"{class_name}<{template_type}>"

    match = class_decl_regex.match(line)
    if match is not None:
        return match.group(1)

    return None
