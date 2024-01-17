"""For aggregating decomp markers read from an entire directory and for a single module."""
from typing import Iterable, Iterator, List
from .parser import DecompParser
from .node import (
    ParserSymbol,
    ParserFunction,
    ParserVtable,
    ParserVariable,
    ParserString,
)


class DecompCodebase:
    def __init__(self, filenames: Iterable[str], module: str) -> None:
        self._symbols: List[ParserSymbol] = []

        parser = DecompParser()
        for filename in filenames:
            parser.reset()
            with open(filename, "r", encoding="utf-8") as f:
                parser.read_lines(f)

            for sym in parser.iter_symbols(module):
                sym.filename = filename
                self._symbols.append(sym)

    def iter_line_functions(self) -> Iterator[ParserFunction]:
        """Return lineref functions separately from nameref. Assuming the PDB matches
        the state of the source code, a line reference is a guaranteed match, even if
        multiple functions share the same name. (i.e. polymorphism)"""
        return filter(
            lambda s: isinstance(s, ParserFunction) and not s.is_nameref(),
            self._symbols,
        )

    def iter_name_functions(self) -> Iterator[ParserFunction]:
        return filter(
            lambda s: isinstance(s, ParserFunction) and s.is_nameref(), self._symbols
        )

    def iter_vtables(self) -> Iterator[ParserVtable]:
        return filter(lambda s: isinstance(s, ParserVtable), self._symbols)

    def iter_variables(self) -> Iterator[ParserVariable]:
        return filter(lambda s: isinstance(s, ParserVariable), self._symbols)

    def iter_strings(self) -> Iterator[ParserString]:
        return filter(lambda s: isinstance(s, ParserString), self._symbols)
