"""For aggregating decomp markers read from an entire directory and for a single module."""
from typing import Callable, Iterable, Iterator, List
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

    def prune_invalid_addrs(self, is_valid: Callable[int, bool]) -> List[ParserSymbol]:
        """Some decomp annotations might have an invalid address.
        Return the list of addresses where we fail the is_valid check,
        and remove those from our list of symbols."""
        invalid_symbols = [sym for sym in self._symbols if not is_valid(sym.offset)]
        self._symbols = [sym for sym in self._symbols if is_valid(sym.offset)]

        return invalid_symbols

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
