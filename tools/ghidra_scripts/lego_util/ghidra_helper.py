import logging
import sys
import re

from lego_util.exceptions import (
    NamespaceNotFoundInGhidraError,
    TypeNotFoundInGhidraError,
    MultipleTypesFoundInGhidraError,
)
from lego_util.cpp_parser import CppFunctionDeclaration

# Disable spurious warnings in vscode / pylance
# pyright: reportMissingModuleSource=false

from ghidra.program.model.data import PointerDataType
from ghidra.program.model.data import DataTypeConflictHandler
from ghidra.program.model.listing import ParameterImpl
from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SourceType

# Type annotations are only available in Python 3.5 or later
if sys.version_info.major > 2:
    from typing import TYPE_CHECKING

    if TYPE_CHECKING:
        from ghidra.program.flatapi import FlatProgramAPI
        from ghidra.program.model.data import DataType
        from ghidra.program.model.symbol import Namespace
        from ghidra.program.model.listing import Parameter


def get_ghidra_type(api, type_name):  # type: (FlatProgramAPI, str) -> DataType
    """
    Searches for the type named `typeName` in Ghidra.

    Raises:
        NotFoundInGhidraError:
    """

    # references to pointers
    type_name = type_name.replace("&", " *")
    # handle reference spacing (void* -> void *)
    type_name = re.sub(r"(?<!\s)\*", " *", type_name)

    result = api.getDataTypes(type_name)
    if len(result) == 0:
        if type_name.endswith("*"):
            # Create a new pointer type if the dereferenced type exists
            dereferenced_type = get_ghidra_type(api, type_name[0:-2])
            return add_pointer_type(api, dereferenced_type)

        raise TypeNotFoundInGhidraError(type_name)
    if len(result) == 1:
        return result[0]

    raise MultipleTypesFoundInGhidraError(type_name, result)


def add_pointer_type(api, pointee):  # type: (FlatProgramAPI, DataType) -> DataType
    data_type = PointerDataType(pointee)
    data_type.setCategoryPath(pointee.categoryPath)
    api.getCurrentProgram().getDataTypeManager().addDataType(
        data_type, DataTypeConflictHandler.KEEP_HANDLER
    )
    logging.info("Created new pointer type %s", data_type)
    return data_type


def get_ghidra_namespace(
    api, namespace_hierachy
):  # type: (FlatProgramAPI, list[str]) -> Namespace
    namespace = api.getCurrentProgram().getGlobalNamespace()
    for part in namespace_hierachy:
        namespace = api.getNamespace(namespace, part)
        if namespace is None:
            raise NamespaceNotFoundInGhidraError(namespace_hierachy)
    return namespace


class CppFunctionWithGhidraTypes(object):
    """Collects the matching Ghidra entities for a C++ function declaration."""

    def __init__(
        self, fpapi, cpp_fn_decl
    ):  # type: (FlatProgramAPI, CppFunctionDeclaration) -> None
        self.name = cpp_fn_decl.name
        self.class_name = cpp_fn_decl.class_name
        self.return_type = get_ghidra_type(fpapi, cpp_fn_decl.return_type)
        self.arguments = [
            ParameterImpl(
                name, get_ghidra_type(fpapi, type_name), fpapi.getCurrentProgram()
            )
            for (type_name, name) in cpp_fn_decl.arguments
        ]
        self.namespace = get_ghidra_namespace(fpapi, cpp_fn_decl.namespace_hierachy)

    def matches_ghidra_function(self, ghidra_function):  # type: (Function) -> bool
        """Checks whether this function declaration already matches the description in Ghidra"""
        name_match = self.name == ghidra_function.getName(False)
        namespace_match = self.namespace == ghidra_function.getParentNamespace()
        return_type_match = self.return_type == ghidra_function.getReturnType()
        # match arguments: decide if thiscall or not
        thiscall_matches = (self.class_name is not None) == (
            ghidra_function.getCallingConventionName() == "__thiscall"
        )

        if thiscall_matches:
            if self.class_name is not None:
                args_match = self._matches_thiscall_parameters(ghidra_function)
            else:
                args_match = self._matches_non_thiscall_parameters(ghidra_function)
        else:
            args_match = False

        logging.debug(
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

    def _matches_non_thiscall_parameters(
        self, ghidra_function
    ):  # type: (Function) -> bool
        return self._parameter_lists_match(ghidra_function.getParameters())

    def _matches_thiscall_parameters(self, ghidra_function):  # type: (Function) -> bool
        ghidra_params = ghidra_function.getParameters()  # type: list[Parameter]

        # remove the `this` argument which we don't generate ourselves
        ghidra_params.pop(0)

        return self._parameter_lists_match(ghidra_params)

    def _parameter_lists_match(self, ghidra_params):  # type: (list[Parameter]) -> bool
        if len(self.arguments) != len(ghidra_params):
            return False

        for this_arg, ghidra_arg in zip(self.arguments, ghidra_params):
            if (
                this_arg.getName() != ghidra_arg.getName()
                or this_arg.getDataType() != ghidra_arg.getDataType()
            ):
                return False

        return True

    def overwrite_ghidra_function(self, ghidra_function):  # type: (Function) -> None
        """Replace the function declaration in Ghidra by the one derived from C++."""
        ghidra_function.setName(self.name, SourceType.USER_DEFINED)
        ghidra_function.setParentNamespace(self.namespace)
        ghidra_function.setReturnType(self.return_type, SourceType.USER_DEFINED)
        # not sure what calling convention to choose when it's not a __thiscall,
        # so we play it safe and keep whatever Ghidra has
        if self.class_name:
            ghidra_function.setCallingConvention("__thiscall")

        ghidra_function.replaceParameters(
            Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
            True,
            SourceType.USER_DEFINED,
            self.arguments,
        )
