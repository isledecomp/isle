"""For demangling a subset of MSVC mangled symbols.
Some unofficial information about the mangling scheme is here:
https://en.wikiversity.org/wiki/Visual_C%2B%2B_name_mangling
"""
import re
from collections import namedtuple
from typing import Optional


class InvalidEncodedNumberError(Exception):
    pass


_encoded_number_translate = str.maketrans("ABCDEFGHIJKLMNOP", "0123456789ABCDEF")


def parse_encoded_number(string: str) -> int:
    # TODO: assert string ends in "@"?
    if string.endswith("@"):
        string = string[:-1]

    try:
        return int(string.translate(_encoded_number_translate), 16)
    except ValueError as e:
        raise InvalidEncodedNumberError(string) from e


string_const_regex = re.compile(
    r"\?\?_C@\_(?P<is_utf16>[0-1])(?P<len>\d|[A-P]+@)(?P<hash>\w+)@(?P<value>.+)@"
)
StringConstInfo = namedtuple("StringConstInfo", "len is_utf16")


def demangle_string_const(symbol: str) -> Optional[StringConstInfo]:
    """Don't bother to decode the string text from the symbol.
    We can just read it from the binary once we have the length."""
    match = string_const_regex.match(symbol)
    if match is None:
        return None

    try:
        strlen = (
            parse_encoded_number(match.group("len"))
            if "@" in match.group("len")
            else int(match.group("len"))
        )
    except (ValueError, InvalidEncodedNumberError):
        return None

    is_utf16 = match.group("is_utf16") == "1"
    return StringConstInfo(len=strlen, is_utf16=is_utf16)


def demangle_vtable(symbol: str) -> str:
    """Get the class name referenced in the vtable symbol."""

    # Seek ahead 4 chars to strip off "??_7" prefix
    t = symbol[4:].split("@")
    # "?$" indicates a template class
    if t[0].startswith("?$"):
        class_name = t[0][2:]
        # PA = Pointer/reference
        # V or U = class or struct
        if t[1].startswith("PA"):
            generic = f"{t[1][3:]} *"
        else:
            generic = t[1][1:]

        return f"{class_name}<{generic}>"

    return t[0]
