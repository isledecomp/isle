from dataclasses import dataclass
import re
from typing import Any, Optional
import logging

from isledecomp.cvdump.symbols import SymbolsEntry
from isledecomp.compare import Compare as IsleCompare
from isledecomp.compare.db import MatchInfo

logger = logging.getLogger(__file__)


@dataclass
class CppStackOrRegisterSymbol:
    name: str
    data_type: str


@dataclass
class CppStackSymbol(CppStackOrRegisterSymbol):
    stack_offset: int
    """Should have a value iff `symbol_type=='S_BPREL32'."""


@dataclass
class CppRegisterSymbol(CppStackOrRegisterSymbol):
    register: str
    """Should have a value iff `symbol_type=='S_REGISTER'.` Should always be set/converted to lowercase."""


@dataclass
class FunctionSignature:
    original_function_symbol: SymbolsEntry
    call_type: str
    arglist: list[str]
    return_type: str
    class_type: Optional[str]
    stack_symbols: list[CppStackOrRegisterSymbol]
    # if non-zero: an offset to the `this` parameter in a __thiscall
    this_adjust: int


@dataclass
class PdbFunction:
    match_info: MatchInfo
    signature: FunctionSignature
    is_stub: bool


class PdbFunctionExtractor:
    """
    Extracts all information on a given function from the parsed PDB
    and prepares the data for the import in Ghidra.
    """

    def __init__(self, compare: IsleCompare):
        self.compare = compare

    scalar_type_regex = re.compile(r"t_(?P<typename>\w+)(?:\((?P<type_id>\d+)\))?")

    _call_type_map = {
        "ThisCall": "__thiscall",
        "C Near": "__thiscall",
        "STD Near": "__stdcall",
    }

    def _get_cvdump_type(self, type_name: Optional[str]) -> Optional[dict[str, Any]]:
        return (
            None
            if type_name is None
            else self.compare.cv.types.keys.get(type_name.lower())
        )

    def get_func_signature(self, fn: SymbolsEntry) -> Optional[FunctionSignature]:
        function_type_str = fn.func_type
        if function_type_str == "T_NOTYPE(0000)":
            logger.debug(
                "Skipping a NOTYPE (synthetic or template + synthetic): %s", fn.name
            )
            return None

        # get corresponding function type

        function_type = self.compare.cv.types.keys.get(function_type_str.lower())
        if function_type is None:
            logger.error(
                "Could not find function type %s for function %s", fn.func_type, fn.name
            )
            return None

        class_type = function_type.get("class_type")

        arg_list_type = self._get_cvdump_type(function_type.get("arg_list_type"))
        assert arg_list_type is not None
        arg_list_pdb_types = arg_list_type.get("args", [])
        assert arg_list_type["argcount"] == len(arg_list_pdb_types)

        stack_symbols: list[CppStackOrRegisterSymbol] = []

        # for some unexplained reason, the reported stack is offset by 4 when this flag is set
        stack_offset_delta = -4 if fn.frame_pointer_present else 0

        for symbol in fn.stack_symbols:
            if symbol.symbol_type == "S_REGISTER":
                stack_symbols.append(
                    CppRegisterSymbol(
                        symbol.name,
                        symbol.data_type,
                        symbol.location,
                    )
                )
            elif symbol.symbol_type == "S_BPREL32":
                stack_offset = int(symbol.location[1:-1], 16)
                stack_symbols.append(
                    CppStackSymbol(
                        symbol.name,
                        symbol.data_type,
                        stack_offset + stack_offset_delta,
                    )
                )

        call_type = self._call_type_map[function_type["call_type"]]

        # parse as hex number, default to 0
        this_adjust = int(function_type.get("this_adjust", "0"), 16)

        return FunctionSignature(
            original_function_symbol=fn,
            call_type=call_type,
            arglist=arg_list_pdb_types,
            return_type=function_type["return_type"],
            class_type=class_type,
            stack_symbols=stack_symbols,
            this_adjust=this_adjust,
        )

    def get_function_list(self) -> list[PdbFunction]:
        handled = (
            self.handle_matched_function(match)
            for match in self.compare.get_functions()
        )
        return [signature for signature in handled if signature is not None]

    def handle_matched_function(self, match_info: MatchInfo) -> Optional[PdbFunction]:
        assert match_info.orig_addr is not None
        match_options = self.compare.get_match_options(match_info.orig_addr)
        assert match_options is not None
        if match_options.get("skip", False):
            return None

        function_data = next(
            (
                y
                for y in self.compare.cvdump_analysis.nodes
                if y.addr == match_info.recomp_addr
            ),
            None,
        )
        if not function_data:
            logger.error(
                "Did not find function in nodes, skipping: %s", match_info.name
            )
            return None

        function_symbol = function_data.symbol_entry
        if function_symbol is None:
            logger.debug(
                "Could not find function symbol (likely a PUBLICS entry): %s",
                match_info.name,
            )
            return None

        function_signature = self.get_func_signature(function_symbol)
        if function_signature is None:
            return None

        is_stub = match_options.get("stub", False)

        return PdbFunction(match_info, function_signature, is_stub)
