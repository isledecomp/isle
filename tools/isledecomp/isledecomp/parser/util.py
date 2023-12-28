# C++ Parser utility functions and data structures
import re
from typing import Optional

# The goal here is to just read whatever is on the next line, so some
# flexibility in the formatting seems OK
templateCommentRegex = re.compile(r"\s*//\s+(.*)")


# To remove any comment (//) or block comment (/*) and its leading spaces
# from the end of a code line
trailingCommentRegex = re.compile(r"(\s*(?://|/\*).*)$")


def get_synthetic_name(line: str) -> Optional[str]:
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


template_class_decl_regex = re.compile(
    r"\s*(?:\/\/)?\s*(?:class|struct) (\w+)<([\w]+)\s*(\*+)?\s*>"
)


class_decl_regex = re.compile(r"\s*(?:\/\/)?\s*(?:class|struct) (\w+)")


def get_class_name(line: str) -> Optional[str]:
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


global_regex = re.compile(r"(?P<name>g_\w+)")
less_strict_global_regex = re.compile(r"(?P<name>\w+)(?:\)\(|\[.*|\s*=.*|;)")


def get_variable_name(line: str) -> Optional[str]:
    """Grab the name of the variable annotated with the GLOBAL marker.
    Correct syntax would have the variable start with the prefix "g_"
    but we will try to match regardless."""

    if (match := global_regex.search(line)) is not None:
        return match.group("name")

    if (match := less_strict_global_regex.search(line)) is not None:
        return match.group("name")

    return None
