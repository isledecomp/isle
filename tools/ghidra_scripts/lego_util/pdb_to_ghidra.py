# This file can only be imported successfully when run from Ghidra using Ghidrathon.

# Disable spurious warnings in vscode / pylance
# pyright: reportMissingModuleSource=false

import logging
from typing import Optional

from ghidra.program.model.listing import Function, Parameter
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.listing import ParameterImpl
from ghidra.program.model.symbol import SourceType

from isledecomp.compare.db import MatchInfo

from lego_util.pdb_extraction import (
    FunctionSignature,
    CppRegisterSymbol,
    CppStackSymbol,
)
from lego_util.ghidra_helper import (
    get_ghidra_namespace,
    get_ghidra_type,
)
from lego_util.exceptions import StackOffsetMismatchError



logger = logging.getLogger(__name__)


class PdbFunctionWithGhidraObjects:
    """A representation of a function from the PDB with each type replaced by a Ghidra type instance."""

    def __init__(
        self,
        fpapi: FlatProgramAPI,
        match_info: MatchInfo,
        signature: FunctionSignature,
    ):
        self.api = fpapi
        self.match_info = match_info
        self.signature = signature

        assert match_info.name is not None
        colon_split = match_info.name.split("::")
        self.name = colon_split.pop()
        namespace_hierachy = colon_split
        self.namespace = get_ghidra_namespace(fpapi, namespace_hierachy)

        self.return_type = get_ghidra_type(fpapi, signature.return_type)
        self.arguments = [
            ParameterImpl(
                f"param{index}",
                get_ghidra_type(fpapi, type_name),
                fpapi.getCurrentProgram(),
            )
            for (index, type_name) in enumerate(signature.arglist)
        ]

    @property
    def call_type(self):
        return self.signature.call_type

    @property
    def stack_symbols(self):
        return self.signature.stack_symbols

    def get_full_name(self) -> str:
        return f"{self.namespace.getName()}::{self.name}"

    def format_proposed_change(self) -> str:
        return (
            f"{self.return_type} {self.call_type} {self.get_full_name()}"
            + f"({', '.join(self.signature.arglist)})"
        )

    def matches_ghidra_function(self, ghidra_function: Function) -> bool:
        """Checks whether this function declaration already matches the description in Ghidra"""
        name_match = self.name == ghidra_function.getName(False)
        namespace_match = self.namespace == ghidra_function.getParentNamespace()
        return_type_match = self.return_type == ghidra_function.getReturnType()
        # match arguments: decide if thiscall or not
        thiscall_matches = (
            self.signature.call_type == ghidra_function.getCallingConventionName()
        )

        if thiscall_matches:
            if self.signature.call_type == "__thiscall":
                args_match = self._matches_thiscall_parameters(ghidra_function)
            else:
                args_match = self._matches_non_thiscall_parameters(ghidra_function)
        else:
            args_match = False

        logger.debug(
            "Matches: namespace=%s name=%s return_type=%s thiscall=%s args=%s",
            namespace_match,
            name_match,
            return_type_match,
            thiscall_matches,
            args_match,
        )

        return (
            name_match
            and namespace_match
            and return_type_match
            and thiscall_matches
            and args_match
        )

    def _matches_non_thiscall_parameters(self, ghidra_function: Function) -> bool:
        return self._parameter_lists_match(ghidra_function.getParameters())

    def _matches_thiscall_parameters(self, ghidra_function: Function) -> bool:
        ghidra_params = list(ghidra_function.getParameters())

        # remove the `this` argument which we don't generate ourselves
        ghidra_params.pop(0)

        return self._parameter_lists_match(ghidra_params)

    def _parameter_lists_match(self, ghidra_params: "list[Parameter]") -> bool:
        if len(self.arguments) != len(ghidra_params):
            logger.info("Mismatching argument count")
            return False

        for this_arg, ghidra_arg in zip(self.arguments, ghidra_params):
            # compare argument types
            if this_arg.getDataType() != ghidra_arg.getDataType():
                logger.debug(
                    "Mismatching arg type: expected %s, found %s",
                    this_arg.getDataType(),
                    ghidra_arg.getDataType(),
                )
                return False
            # compare argument names
            stack_match = self.get_matching_stack_symbol(ghidra_arg.getStackOffset())
            if stack_match is None:
                logger.debug("Not found on stack: %s", ghidra_arg)
                return False
            # "__formal" is the placeholder for arguments without a name
            if stack_match.name not in ["__formal", ghidra_arg.getName()]:
                logger.debug(
                    "Argument name mismatch: expected %s, found %s",
                    stack_match.name,
                    ghidra_arg.getName(),
                )
                return False
        return True

    def overwrite_ghidra_function(self, ghidra_function: Function):
        """Replace the function declaration in Ghidra by the one derived from C++."""
        ghidra_function.setName(self.name, SourceType.USER_DEFINED)
        ghidra_function.setParentNamespace(self.namespace)
        ghidra_function.setReturnType(self.return_type, SourceType.USER_DEFINED)
        ghidra_function.setCallingConvention(self.call_type)

        ghidra_function.replaceParameters(
            Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
            True,
            SourceType.USER_DEFINED,
            self.arguments,
        )

        # When we set the parameters, Ghidra will generate the layout.
        # Now we read them again and match them against the stack layout in the PDB,
        # both to verify and to set the parameter names.
        ghidra_parameters: list[Parameter] = ghidra_function.getParameters()

        # Try to add Ghidra function names
        for param in ghidra_parameters:
            if param.isStackVariable():
                self._rename_stack_parameter(param)
            else:
                if param.getName() == "this":
                    # 'this' parameters are auto-generated and cannot be changed
                    continue

                # TODO: Does this ever happen?
                logger.warning("Unhandled register variable in %s", self.get_full_name)
                continue

                # Old code for reference:
                #
                # register = param.getRegister().getName().lower()
                # match = self.get_matching_register_symbol(register)
                # if match is None:
                #     logger.error(
                #         "Could not match register parameter %s to known symbols %s",
                #         param,
                #         self.stack_symbols,
                #     )
                #     continue

    def _rename_stack_parameter(self, param: Parameter):
        match = self.get_matching_stack_symbol(param.getStackOffset())
        if match is None:
            raise StackOffsetMismatchError(
                f"Could not find a matching symbol at offset {param.getStackOffset()} in {self.get_full_name()}"
            )

        if param.getDataType() != get_ghidra_type(self.api, match.data_type):
            logger.error(
                "Type mismatch for parameter: %s in Ghidra, %s in PDB", param, match
            )
            return

        param.setName(match.name, SourceType.USER_DEFINED)

    def get_matching_stack_symbol(self, stack_offset: int) -> Optional[CppStackSymbol]:
        return next(
            (
                symbol
                for symbol in self.stack_symbols
                if isinstance(symbol, CppStackSymbol)
                and symbol.stack_offset == stack_offset
            ),
            None,
        )

    def get_matching_register_symbol(self, register: str) -> Optional[CppRegisterSymbol]:
        return next(
            (
                symbol
                for symbol in self.stack_symbols
                if isinstance(symbol, CppRegisterSymbol) and symbol.register == register
            ),
            None,
        )
