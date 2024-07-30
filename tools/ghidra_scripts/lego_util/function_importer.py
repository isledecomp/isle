# This file can only be imported successfully when run from Ghidra using Ghidrathon.

# Disable spurious warnings in vscode / pylance
# pyright: reportMissingModuleSource=false

import logging
from typing import Optional

from ghidra.program.model.listing import Function, Parameter
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.listing import ParameterImpl
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import (
    TypeDef,
    TypedefDataType,
    Pointer,
    ComponentOffsetSettingsDefinition,
)

from lego_util.pdb_extraction import (
    PdbFunction,
    CppRegisterSymbol,
    CppStackSymbol,
)
from lego_util.ghidra_helper import (
    add_data_type_or_reuse_existing,
    get_or_add_pointer_type,
    get_ghidra_namespace,
    sanitize_name,
)

from lego_util.exceptions import StackOffsetMismatchError, Lego1Exception
from lego_util.type_importer import PdbTypeImporter


logger = logging.getLogger(__name__)


# pylint: disable=too-many-instance-attributes
class PdbFunctionImporter:
    """A representation of a function from the PDB with each type replaced by a Ghidra type instance."""

    def __init__(
        self,
        api: FlatProgramAPI,
        func: PdbFunction,
        type_importer: "PdbTypeImporter",
    ):
        self.api = api
        self.match_info = func.match_info
        self.signature = func.signature
        self.is_stub = func.is_stub
        self.type_importer = type_importer

        if self.signature.class_type is not None:
            # Import the base class so the namespace exists
            self.type_importer.import_pdb_type_into_ghidra(self.signature.class_type)

        assert self.match_info.name is not None

        colon_split = sanitize_name(self.match_info.name).split("::")
        self.name = colon_split.pop()
        namespace_hierachy = colon_split
        self.namespace = get_ghidra_namespace(api, namespace_hierachy)

        self.return_type = type_importer.import_pdb_type_into_ghidra(
            self.signature.return_type
        )
        self.arguments = [
            ParameterImpl(
                f"param{index}",
                type_importer.import_pdb_type_into_ghidra(type_name),
                api.getCurrentProgram(),
            )
            for (index, type_name) in enumerate(self.signature.arglist)
        ]

    @property
    def call_type(self):
        return self.signature.call_type

    @property
    def stack_symbols(self):
        return self.signature.stack_symbols

    def get_full_name(self) -> str:
        return f"{self.namespace.getName()}::{self.name}"

    def matches_ghidra_function(self, ghidra_function: Function) -> bool:
        """Checks whether this function declaration already matches the description in Ghidra"""
        name_match = self.name == ghidra_function.getName(False)
        namespace_match = self.namespace == ghidra_function.getParentNamespace()
        ghidra_return_type = ghidra_function.getReturnType()
        return_type_match = self.return_type == ghidra_return_type

        # Handle edge case: Return type X that is larger than the return register.
        # In that case, the function returns `X*` and has another argument `X* __return_storage_ptr`.
        if (
            (not return_type_match)
            and (self.return_type.getLength() > 4)
            and (
                get_or_add_pointer_type(self.api, self.return_type)
                == ghidra_return_type
            )
            and any(
                param
                for param in ghidra_function.getParameters()
                if param.getName() == "__return_storage_ptr__"
            )
        ):
            logger.debug(
                "%s has a return type larger than 4 bytes", self.get_full_name()
            )
            return_type_match = True

        # match arguments: decide if thiscall or not, and whether the `this` type matches
        thiscall_matches = (
            self.signature.call_type == ghidra_function.getCallingConventionName()
        )

        ghidra_params_without_this = list(ghidra_function.getParameters())

        if thiscall_matches and self.signature.call_type == "__thiscall":
            this_argument = ghidra_params_without_this.pop(0)
            thiscall_matches = self._this_type_match(this_argument)

        if self.is_stub:
            # We do not import the argument list for stubs, so it should be excluded in matches
            args_match = True
        elif thiscall_matches:
            args_match = self._parameter_lists_match(ghidra_params_without_this)
        else:
            args_match = False

        logger.debug(
            "Matches: namespace=%s name=%s return_type=%s thiscall=%s args=%s",
            namespace_match,
            name_match,
            return_type_match,
            thiscall_matches,
            "ignored" if self.is_stub else args_match,
        )

        return (
            name_match
            and namespace_match
            and return_type_match
            and thiscall_matches
            and args_match
        )

    def _this_type_match(self, this_parameter: Parameter) -> bool:
        if this_parameter.getName() != "this":
            logger.info("Expected first argument to be `this` in __thiscall")
            return False

        if self.signature.this_adjust != 0:
            # In this case, the `this` argument should be custom defined
            if not isinstance(this_parameter.getDataType(), TypeDef):
                logger.info(
                    "`this` argument is not a typedef while `this adjust` = %d",
                    self.signature.this_adjust,
                )
                return False
            # We are not checking for the _correct_ `this` type here, which we could do in the future

        return True

    def _parameter_lists_match(self, ghidra_params: "list[Parameter]") -> bool:
        # Remove return storage pointer from comparison if present.
        # This is relevant to returning values larger than 4 bytes, and is not mentioned in the PDB
        ghidra_params = [
            param
            for param in ghidra_params
            if param.getName() != "__return_storage_ptr__"
        ]

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

            if stack_match.name.startswith("__formal"):
                # "__formal" is the placeholder for arguments without a name
                continue

            if stack_match.name == "__$ReturnUdt":
                # These appear in templates and cannot be set automatically, as they are a NOTYPE
                continue

            if stack_match.name != ghidra_arg.getName():
                logger.debug(
                    "Argument name mismatch: expected %s, found %s",
                    stack_match.name,
                    ghidra_arg.getName(),
                )
                return False
        return True

    def overwrite_ghidra_function(self, ghidra_function: Function):
        """Replace the function declaration in Ghidra by the one derived from C++."""

        if ghidra_function.hasCustomVariableStorage():
            # Unfortunately, calling `ghidra_function.setCustomVariableStorage(False)`
            # leads to two `this` parameters. Therefore, we first need to remove all `this` parameters
            # and then re-generate a new one
            ghidra_function.replaceParameters(
                Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,  # this implicitly sets custom variable storage to False
                True,
                SourceType.USER_DEFINED,
                [
                    param
                    for param in ghidra_function.getParameters()
                    if param.getName() != "this"
                ],
            )

        if ghidra_function.hasCustomVariableStorage():
            raise Lego1Exception("Failed to disable custom variable storage.")

        ghidra_function.setName(self.name, SourceType.USER_DEFINED)
        ghidra_function.setParentNamespace(self.namespace)
        ghidra_function.setReturnType(self.return_type, SourceType.USER_DEFINED)
        ghidra_function.setCallingConvention(self.call_type)

        if self.is_stub:
            logger.debug(
                "%s is a stub, skipping parameter import", self.get_full_name()
            )
        else:
            ghidra_function.replaceParameters(
                Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                True,  # force
                SourceType.USER_DEFINED,
                self.arguments,
            )
            self._import_parameter_names(ghidra_function)

        # Special handling for `this adjust` and virtual inheritance
        if self.signature.this_adjust != 0:
            self._set_this_adjust(ghidra_function)

    def _import_parameter_names(self, ghidra_function: Function):
        # When we call `ghidra_function.replaceParameters`, Ghidra will generate the layout.
        # Now we read the parameters again and match them against the stack layout in the PDB,
        # both to verify the layout and to set the parameter names.
        ghidra_parameters: list[Parameter] = ghidra_function.getParameters()

        # Try to add Ghidra function names
        for index, param in enumerate(ghidra_parameters):
            if param.isStackVariable():
                self._rename_stack_parameter(index, param)
            else:
                if param.getName() == "this":
                    # 'this' parameters are auto-generated and cannot be changed
                    continue

                # Appears to never happen - could in theory be relevant to __fastcall__ functions,
                # which we haven't seen yet
                logger.warning(
                    "Unhandled register variable in %s", self.get_full_name()
                )
                continue

    def _rename_stack_parameter(self, index: int, param: Parameter):
        match = self.get_matching_stack_symbol(param.getStackOffset())
        if match is None:
            raise StackOffsetMismatchError(
                f"Could not find a matching symbol at offset {param.getStackOffset()} in {self.get_full_name()}"
            )

        if match.data_type == "T_NOTYPE(0000)":
            logger.warning("Skipping stack parameter of type NOTYPE")
            return

        if param.getDataType() != self.type_importer.import_pdb_type_into_ghidra(
            match.data_type
        ):
            logger.error(
                "Type mismatch for parameter: %s in Ghidra, %s in PDB", param, match
            )
            return

        name = match.name
        if name == "__formal":
            # these can cause name collisions if multiple ones are present
            name = f"__formal_{index}"

        param.setName(name, SourceType.USER_DEFINED)

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

    def get_matching_register_symbol(
        self, register: str
    ) -> Optional[CppRegisterSymbol]:
        return next(
            (
                symbol
                for symbol in self.stack_symbols
                if isinstance(symbol, CppRegisterSymbol) and symbol.register == register
            ),
            None,
        )

    def _set_this_adjust(
        self,
        ghidra_function: Function,
    ):
        """
        When `this adjust` is non-zero, the pointer type of `this` needs to be replaced by an offset version.
        The offset can only be set on a typedef on the pointer. We also must enable custom storage so we can modify
        the auto-generated `this` parameter.
        """

        # Necessary in order to overwite the auto-generated `this`
        ghidra_function.setCustomVariableStorage(True)

        this_parameter = next(
            (
                param
                for param in ghidra_function.getParameters()
                if param.isRegisterVariable() and param.getName() == "this"
            ),
            None,
        )

        if this_parameter is None:
            logger.error(
                "Failed to find `this` parameter in a function with `this adjust = %d`",
                self.signature.this_adjust,
            )
        else:
            current_ghidra_type = this_parameter.getDataType()
            assert isinstance(current_ghidra_type, Pointer)
            class_name = current_ghidra_type.getDataType().getName()
            typedef_name = f"{class_name}PtrOffset0x{self.signature.this_adjust:x}"

            typedef_ghidra_type = TypedefDataType(
                current_ghidra_type.getCategoryPath(),
                typedef_name,
                current_ghidra_type,
            )
            ComponentOffsetSettingsDefinition.DEF.setValue(
                typedef_ghidra_type.getDefaultSettings(), self.signature.this_adjust
            )
            typedef_ghidra_type = add_data_type_or_reuse_existing(
                self.api, typedef_ghidra_type
            )

            this_parameter.setDataType(typedef_ghidra_type, SourceType.USER_DEFINED)
