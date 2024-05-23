from dataclasses import dataclass
import re
from typing import Any, Optional
import logging

from isledecomp.cvdump.symbols import SymbolsEntry
from isledecomp.types import SymbolType
from isledecomp.compare import Compare as IsleCompare
from isledecomp.compare.db import MatchInfo

logger = logging.getLogger(__file__)


class TypeNotFoundError(Exception):
    pass


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
    call_type: str
    arglist: list[str]
    return_type: str
    class_type: Optional[dict[str, Any]]
    stack_symbols: list[CppStackOrRegisterSymbol]


class PdbExtractionForGhidraMigration:
    def __init__(self, compare: IsleCompare):
        self.compare = compare

    _scalar_type_regex = re.compile(r"t_(?P<typename>\w+)(?:\((?P<type_id>\d+)\))?")

    _scalar_type_map = {
        "rchar": "char",
        "int4": "int",
        "uint4": "uint",
        "real32": "float",
        "real64": "double",
    }

    _call_type_map = {
        "ThisCall": "__thiscall",
        "C Near": "__thiscall",  # TODO: Not actually sure about this one, needs verification
        "STD Near": "__stdcall",
    }

    def scalar_type_to_cpp(self, scalar_type: str) -> str:
        if scalar_type.startswith("32p"):
            return f"{self.scalar_type_to_cpp(scalar_type[3:])} *"
        return self._scalar_type_map.get(scalar_type, scalar_type)

    def lookup_type(self, type_name: Optional[str]) -> Optional[dict[str, Any]]:
        return (
            None
            if type_name is None
            else self.compare.cv.types.keys.get(type_name.lower())
        )

    def type_to_cpp_type_name(self, type_name: str) -> str:
        # pylint: disable=too-many-return-statements
        type_lower = type_name.lower()
        if type_lower.startswith("t_"):
            if (match := self._scalar_type_regex.match(type_lower)) is None:
                raise TypeNotFoundError(f"Type has unexpected format: {type_name}")

            return self.scalar_type_to_cpp(match.group("typename"))

        dereferenced = self.lookup_type(type_lower)
        if dereferenced is None:
            raise TypeNotFoundError(f"Failed to find referenced type {type_name}")

        deref_type = dereferenced["type"]
        if deref_type == "LF_POINTER":
            return f"{self.type_to_cpp_type_name(dereferenced['element_type'])} *"
        if deref_type in ["LF_CLASS", "LF_STRUCTURE"]:
            class_name = dereferenced.get("name")
            if class_name is not None:
                return class_name
            logger.error("Parsing error in class")
            return "<<parsing error>>"
        if deref_type == "LF_ARRAY":
            # We treat arrays like pointers because we don't distinguish them in Ghidra
            return f"{self.type_to_cpp_type_name(dereferenced['array_type'])} *"
        if deref_type == "LF_ENUM":
            return dereferenced["name"]
        if deref_type == "LF_MODIFIER":
            # not sure what this actually is
            return self.type_to_cpp_type_name(dereferenced["modifies"])
        if deref_type == "LF_PROCEDURE":
            logger.info(
                "Function-valued argument or return type will be replaced by void pointer: %s",
                dereferenced,
            )
            return "void"

        logger.error("Unknown type: %s", dereferenced)
        return "<<parsing error>>"

    def get_func_signature(self, fn: SymbolsEntry) -> Optional[FunctionSignature]:
        function_type_str = fn.func_type
        if function_type_str == "T_NOTYPE(0000)":
            logger.debug(
                "Got a NOTYPE (synthetic or template + synthetic): %s", fn.name
            )
            return None

        # get corresponding function type

        function_type = self.compare.cv.types.keys.get(function_type_str.lower())
        if function_type is None:
            logger.error(
                "Could not find function type %s for function %s", fn.func_type, fn.name
            )
            return None

        return_type = self.type_to_cpp_type_name(function_type["return_type"])
        class_type = self.lookup_type(function_type.get("class_type"))

        arg_list_type = self.lookup_type(function_type.get("arg_list_type"))
        assert arg_list_type is not None
        arg_list_pdb_types = arg_list_type.get("args", [])
        assert arg_list_type["argcount"] == len(arg_list_pdb_types)
        arglist = [
            self.type_to_cpp_type_name(argtype) for argtype in arg_list_pdb_types
        ]

        stack_symbols: list[CppStackOrRegisterSymbol] = []
        for symbol in fn.stack_symbols:
            if symbol.symbol_type == "S_REGISTER":
                stack_symbols.append(
                    CppRegisterSymbol(
                        symbol.name,
                        self.type_to_cpp_type_name(symbol.data_type),
                        symbol.location,
                    )
                )
            elif symbol.symbol_type == "S_BPREL32":
                stack_offset = int(symbol.location[1:-1], 16)
                stack_symbols.append(
                    CppStackSymbol(
                        symbol.name,
                        self.type_to_cpp_type_name(symbol.data_type),
                        stack_offset,
                    )
                )

        call_type = self._call_type_map[function_type["call_type"]]

        return FunctionSignature(
            call_type=call_type,
            arglist=arglist,
            return_type=return_type,
            class_type=class_type,
            stack_symbols=stack_symbols,
        )

    def get_function_list(self) -> list[tuple[MatchInfo, FunctionSignature]]:
        handled = (
            self.handle_matched_function(match)
            for match in self.compare._db.get_matches_by_type(SymbolType.FUNCTION)
        )
        return [signature for signature in handled if signature is not None]

    def handle_matched_function(
        self, match_info: MatchInfo
    ) -> Optional[tuple[MatchInfo, FunctionSignature]]:
        assert match_info.orig_addr is not None
        match_options = self.compare._db.get_match_options(match_info.orig_addr)
        assert match_options is not None
        if match_options.get("skip", False) or match_options.get("stub", False):
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

        return match_info, function_signature
