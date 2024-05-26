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

logger = logging.getLogger(__name__)


def get_ghidra_type(api: FlatProgramAPI, type_name: str):
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


def add_pointer_type(api: FlatProgramAPI, pointee: DataType) -> DataType:
    new_data_type = PointerDataType(pointee)
    new_data_type.setCategoryPath(pointee.getCategoryPath())
    result_data_type = (
        api.getCurrentProgram()
        .getDataTypeManager()
        .addDataType(new_data_type, DataTypeConflictHandler.KEEP_HANDLER)
    )
    if result_data_type is not new_data_type:
        logger.debug(
            "New pointer replaced by existing one. Fresh pointer: %s (class: %s)",
            result_data_type,
            result_data_type.__class__,
        )
    return result_data_type


def get_ghidra_namespace(
    api: FlatProgramAPI, namespace_hierachy: list[str]
) -> Namespace:
    namespace = api.getCurrentProgram().getGlobalNamespace()
    for part in namespace_hierachy:
        namespace = api.getNamespace(namespace, part)
        if namespace is None:
            raise ClassOrNamespaceNotFoundInGhidraError(namespace_hierachy)
    return namespace


def create_ghidra_namespace(
    api: FlatProgramAPI, namespace_hierachy: list[str]
) -> Namespace:
    namespace = api.getCurrentProgram().getGlobalNamespace()
    for part in namespace_hierachy:
        namespace = api.getNamespace(namespace, part)
        if namespace is None:
            namespace = api.createNamespace(namespace, part)
    return namespace


def sanitize_class_name(name: str) -> str:
    """
    Takes a full class or function name and replaces characters not accepted by Ghidra.
    Applies mostly to templates.
    """
    if "<" in name:
        new_class_name = (
            "_template_" +
            name
                .replace("<", "[")
                .replace(">", "]")
                .replace("*", "#")
                .replace(" ", "")
        )
        logger.warning(
            "Changing possible template class name from '%s' to '%s'",
            name,
            new_class_name,
        )
        return new_class_name

    return name
