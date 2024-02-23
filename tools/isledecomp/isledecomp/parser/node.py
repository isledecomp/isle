from typing import Optional
from dataclasses import dataclass
from .marker import MarkerType


@dataclass
class ParserSymbol:
    """Exported decomp marker with all information (except the code filename) required to
    cross-reference with cvdump data."""

    type: MarkerType
    line_number: int
    module: str
    offset: int
    name: str

    # The parser doesn't (currently) know about the code filename, but if you
    # wanted to set it here after the fact, here's the spot.
    filename: Optional[str] = None

    def should_skip(self) -> bool:
        """The default is to compare any symbols we have"""
        return False

    def is_nameref(self) -> bool:
        """All symbols default to name lookup"""
        return True


@dataclass
class ParserFunction(ParserSymbol):
    # We are able to detect the closing line of a function with some reliability.
    # This isn't used for anything right now, but perhaps later it will be.
    end_line: Optional[int] = None

    # All marker types are referenced by name except FUNCTION/STUB. These can also be
    # referenced by name, but only if this flag is true.
    lookup_by_name: bool = False

    def should_skip(self) -> bool:
        return self.type == MarkerType.STUB

    def is_nameref(self) -> bool:
        return (
            self.type in (MarkerType.SYNTHETIC, MarkerType.TEMPLATE, MarkerType.LIBRARY)
            or self.lookup_by_name
        )


@dataclass
class ParserVariable(ParserSymbol):
    is_static: bool = False
    parent_function: Optional[int] = None


@dataclass
class ParserVtable(ParserSymbol):
    pass


@dataclass
class ParserString(ParserSymbol):
    pass
