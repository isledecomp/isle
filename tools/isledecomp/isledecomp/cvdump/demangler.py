"""For demangling a subset of MSVC mangled symbols.
Some unofficial information about the mangling scheme is here:
https://en.wikiversity.org/wiki/Visual_C%2B%2B_name_mangling
"""
import re
from collections import namedtuple
from typing import Optional
import pydemangler


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


def get_vtordisp_name(symbol: str) -> Optional[str]:
    # pylint: disable=c-extension-no-member
    """For adjuster thunk functions, the PDB will sometimes use a name
    that contains "vtordisp" but often will just reuse the name of the
    function being thunked. We want to use the vtordisp name if possible."""
    name = pydemangler.demangle(symbol)
    if name is None:
        return None

    if "`vtordisp" not in name:
        return None

    # Now we remove the parts of the friendly name that we don't need
    try:
        # Assuming this is the last of the function prefixes
        thiscall_idx = name.index("__thiscall")
        # To match the end of the `vtordisp{x,y}' string
        end_idx = name.index("}'")
        return name[thiscall_idx + 11 : end_idx + 2]
    except ValueError:
        return name


def demangle_vtable(symbol: str) -> str:
    # pylint: disable=c-extension-no-member
    """Get the class name referenced in the vtable symbol."""
    raw = pydemangler.demangle(symbol)

    if raw is None:
        pass  # TODO: This shouldn't happen if MSVC behaves

    # Remove storage class and other stuff we don't care about
    return (
        raw.replace("<class ", "<")
        .replace("<struct ", "<")
        .replace("const ", "")
        .replace("volatile ", "")
    )


def demangle_vtable_ourselves(symbol: str) -> str:
    """Parked implementation of MSVC symbol demangling.
    We only use this for vtables and it works okay with the simple cases or
    templates that refer to other classes/structs. Some namespace support.
    Does not support backrefs, primitive types, or vtables with
    virtual inheritance."""

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

        return f"{class_name}<{generic}>::`vftable'"

    # If we have two classes listed, it is a namespace hierarchy.
    # @@6B@ is a common generic suffix for these vtable symbols.
    if t[1] != "" and t[1] != "6B":
        return t[1] + "::" + t[0] + "::`vftable'"

    return t[0] + "::`vftable'"
