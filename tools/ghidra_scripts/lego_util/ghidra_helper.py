import logging
import re

from lego_util.exceptions import (
    ClassOrNamespaceNotFoundInGhidraError,
    TypeNotFoundInGhidraError,
    MultipleTypesFoundInGhidraError,
)

# Disable spurious warnings in vscode / pylance
# pyright: reportMissingModuleSource=false

from ghidra.program.model.data import PointerDataType
from ghidra.program.model.data import DataTypeConflictHandler
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.data import DataType
from ghidra.program.model.symbol import Namespace


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
    data_type.setCategoryPath(pointee.getCategoryPath())
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
            raise ClassOrNamespaceNotFoundInGhidraError(namespace_hierachy)
    return namespace
