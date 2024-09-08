from dataclasses import dataclass, field
import logging
import re
from re import Match
from typing import NamedTuple, Optional


logger = logging.getLogger(__name__)


class StackOrRegisterSymbol(NamedTuple):
    symbol_type: str
    location: str
    """Should always be set/converted to lowercase."""
    data_type: str
    name: str


# S_GPROC32 = functions
@dataclass
class SymbolsEntry:
    # pylint: disable=too-many-instance-attributes
    type: str
    section: int
    offset: int
    size: int
    func_type: str
    name: str
    stack_symbols: list[StackOrRegisterSymbol] = field(default_factory=list)
    frame_pointer_present: bool = False
    addr: Optional[int] = None  # Absolute address. Will be set later, if at all


class CvdumpSymbolsParser:
    _symbol_line_generic_regex = re.compile(
        r"\(\w+\)\s+(?P<symbol_type>[^\s:]+)(?::\s+(?P<second_part>\S.*))?|(?::)$"
    )
    """
    Parses the first part, e.g. `(00008C) S_GPROC32`, and splits off the second part after the colon (if it exists).
    There are three cases:
    - no colon, e.g. `(000350) S_END`
    - colon but no data, e.g. `(000370) S_COMPILE:`
    - colon and data, e.g. `(000304)  S_REGISTER: esi, Type:             0x1E14, this``
    """

    _symbol_line_function_regex = re.compile(
        r"\[(?P<section>\w{4}):(?P<offset>\w{8})\], Cb: (?P<size>\w+), Type:\s+(?P<func_type>[^\s,]+), (?P<name>.+)"
    )
    """
    Parses the second part of a function symbol, e.g.
    `[0001:00034E90], Cb: 00000007, Type:             0x1024, ViewROI::IntrinsicImportance`
    """

    # the second part of e.g.
    _stack_register_symbol_regex = re.compile(
        r"(?P<location>\S+), Type:\s+(?P<data_type>[\w()]+), (?P<name>.+)$"
    )
    """
    Parses the second part of a stack or register symbol, e.g.
    `esi, Type:             0x1E14, this`
    """

    _debug_start_end_regex = re.compile(
        r"^\s*Debug start: (?P<debug_start>\w+), Debug end: (?P<debug_end>\w+)$"
    )

    _parent_end_next_regex = re.compile(
        r"\s*Parent: (?P<parent_addr>\w+), End: (?P<end_addr>\w+), Next: (?P<next_addr>\w+)$"
    )

    _flags_frame_pointer_regex = re.compile(r"\s*Flags: Frame Ptr Present$")

    _register_stack_symbols = ["S_BPREL32", "S_REGISTER"]

    # List the unhandled types so we can check exhaustiveness
    _unhandled_symbols = [
        "S_COMPILE",
        "S_OBJNAME",
        "S_THUNK32",
        "S_LABEL32",
        "S_LDATA32",
        "S_UDT",
    ]

    """Parser for cvdump output, SYMBOLS section."""

    def __init__(self):
        self.symbols: list[SymbolsEntry] = []
        self.current_function: Optional[SymbolsEntry] = None
        # If we read an S_BLOCK32 node, increment this level.
        # This is so we do not end the proc early by reading an S_END
        # that indicates the end of the block.
        self.block_level: int = 0

    def read_line(self, line: str):
        if (match := self._symbol_line_generic_regex.match(line)) is not None:
            self._parse_generic_case(line, match)
        elif (match := self._parent_end_next_regex.match(line)) is not None:
            # We do not need this info at the moment, might be useful in the future
            pass
        elif (match := self._debug_start_end_regex.match(line)) is not None:
            # We do not need this info at the moment, might be useful in the future
            pass
        elif (match := self._flags_frame_pointer_regex.match(line)) is not None:
            if self.current_function is None:
                logger.error(
                    "Found a `Flags: Frame Ptr Present` but self.current_function is None"
                )
                return
            self.current_function.frame_pointer_present = True
        else:
            # Most of these are either `** Module: [...]` or data we do not care about
            logger.debug("Unhandled line: %s", line[:-1])

    def _parse_generic_case(self, line, line_match: Match[str]):
        symbol_type: str = line_match.group("symbol_type")
        second_part: Optional[str] = line_match.group("second_part")

        if symbol_type in ["S_GPROC32", "S_LPROC32"]:
            assert second_part is not None
            if (match := self._symbol_line_function_regex.match(second_part)) is None:
                logger.error("Invalid function symbol: %s", line[:-1])
                return
            self.current_function = SymbolsEntry(
                type=symbol_type,
                section=int(match.group("section"), 16),
                offset=int(match.group("offset"), 16),
                size=int(match.group("size"), 16),
                func_type=match.group("func_type"),
                name=match.group("name"),
            )
            self.symbols.append(self.current_function)

        elif symbol_type in self._register_stack_symbols:
            assert second_part is not None
            if self.current_function is None:
                logger.error("Found stack/register outside of function: %s", line[:-1])
                return
            if (match := self._stack_register_symbol_regex.match(second_part)) is None:
                logger.error("Invalid stack/register symbol: %s", line[:-1])
                return

            new_symbol = StackOrRegisterSymbol(
                symbol_type=symbol_type,
                location=match.group("location").lower(),
                data_type=match.group("data_type"),
                name=match.group("name"),
            )
            self.current_function.stack_symbols.append(new_symbol)

        elif symbol_type == "S_BLOCK32":
            self.block_level += 1
        elif symbol_type == "S_END":
            if self.block_level > 0:
                self.block_level -= 1
                assert self.block_level >= 0
            else:
                self.current_function = None
        elif symbol_type in self._unhandled_symbols:
            return
        else:
            logger.error("Unhandled symbol type: %s", line)
