import re
from typing import Optional, Tuple
from enum import Enum


class MarkerCategory(Enum):
    """For the purposes of grouping multiple different DecompMarkers together,
    assign a rough "category" for the MarkerType values below.
    It's really only the function types that have to get folded down, but
    we'll do that in a structured way to permit future expansion."""

    FUNCTION = 1
    VARIABLE = 2
    STRING = 3
    VTABLE = 4
    ADDRESS = 100  # i.e. no comparison required or possible


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
    r"\s*//\s*(?P<type>\w+):\s*(?P<module>\w+)\s+(?P<offset>0x[a-f0-9]+) *(?P<extra>\S.+\S)?",
    flags=re.I,
)


markerExactRegex = re.compile(
    r"\s*// (?P<type>[A-Z]+): (?P<module>[A-Z0-9]+) (?P<offset>0x[a-f0-9]+)(?: (?P<extra>\S.+\S))?\n?$"
)


class DecompMarker:
    def __init__(
        self, marker_type: str, module: str, offset: int, extra: Optional[str] = None
    ) -> None:
        try:
            self._type = MarkerType[marker_type.upper()]
        except KeyError:
            self._type = MarkerType.UNKNOWN

        # Convert to upper here. A lot of other analysis depends on this name
        # being consistent and predictable. If the name is _not_ capitalized
        # we will emit a syntax error.
        self._module: str = module.upper()
        self._offset: int = offset
        self._extra: Optional[str] = extra

    @property
    def type(self) -> MarkerType:
        return self._type

    @property
    def module(self) -> str:
        return self._module

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def extra(self) -> Optional[str]:
        return self._extra

    @property
    def category(self) -> MarkerCategory:
        if self.is_vtable():
            return MarkerCategory.VTABLE

        if self.is_variable():
            return MarkerCategory.VARIABLE

        if self.is_string():
            return MarkerCategory.STRING

        # TODO: worth another look if we add more types, but this covers it
        if self.is_regular_function() or self.is_explicit_byname():
            return MarkerCategory.FUNCTION

        return MarkerCategory.ADDRESS

    @property
    def key(self) -> Tuple[str, str, Optional[str]]:
        """For use with the MarkerDict. To detect/avoid marker collision."""
        return (self.category, self.module, self.extra)

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
        extra=match.group("extra"),
    )


def is_marker_exact(line: str) -> bool:
    return markerExactRegex.match(line) is not None
