import re
from typing import Optional
from enum import Enum


class MarkerType(Enum):
    UNKNOWN = -100
    FUNCTION = 1
    STUB = 2
    SYNTHETIC = 3
    TEMPLATE = 4
    GLOBAL = 5
    VTABLE = 6
    STRING = 7
    LIBRARY = 8


markerRegex = re.compile(
    r"\s*//\s*(?P<type>\w+):\s*(?P<module>\w+)\s+(?P<offset>0x[a-f0-9]+)",
    flags=re.I,
)


markerExactRegex = re.compile(
    r"\s*// (?P<type>[A-Z]+): (?P<module>[A-Z0-9]+) (?P<offset>0x[a-f0-9]+)$"
)


class DecompMarker:
    def __init__(self, marker_type: str, module: str, offset: int) -> None:
        try:
            self._type = MarkerType[marker_type.upper()]
        except KeyError:
            self._type = MarkerType.UNKNOWN

        # Convert to upper here. A lot of other analysis depends on this name
        # being consistent and predictable. If the name is _not_ capitalized
        # we will emit a syntax error.
        self._module: str = module.upper()
        self._offset: int = offset

    @property
    def type(self) -> MarkerType:
        return self._type

    @property
    def module(self) -> str:
        return self._module

    @property
    def offset(self) -> int:
        return self._offset

    def is_regular_function(self) -> bool:
        """Regular function, meaning: not an explicit byname lookup. FUNCTION
        markers can be _implicit_ byname.
        FUNCTION and STUB markers are (currently) the only heterogenous marker types that
        can be lumped together, although the reasons for doing so are a little vague."""
        return self._type in (MarkerType.FUNCTION, MarkerType.STUB)

    def is_explicit_byname(self) -> bool:
        return self._type in (
            MarkerType.SYNTHETIC,
            MarkerType.TEMPLATE,
            MarkerType.LIBRARY,
        )

    def is_variable(self) -> bool:
        return self._type == MarkerType.GLOBAL

    def is_synthetic(self) -> bool:
        return self._type == MarkerType.SYNTHETIC

    def is_template(self) -> bool:
        return self._type == MarkerType.TEMPLATE

    def is_vtable(self) -> bool:
        return self._type == MarkerType.VTABLE

    def is_library(self) -> bool:
        return self._type == MarkerType.LIBRARY

    def is_string(self) -> bool:
        return self._type == MarkerType.STRING

    def allowed_in_func(self) -> bool:
        return self._type in (MarkerType.GLOBAL, MarkerType.STRING)


def match_marker(line: str) -> Optional[DecompMarker]:
    match = markerRegex.match(line)
    if match is None:
        return None

    return DecompMarker(
        marker_type=match.group("type"),
        module=match.group("module"),
        offset=int(match.group("offset"), 16),
    )


def is_marker_exact(line: str) -> bool:
    return markerExactRegex.match(line) is not None
