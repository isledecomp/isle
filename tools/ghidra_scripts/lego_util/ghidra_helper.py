"""A collection of helper functions for the interaction with Ghidra."""

import logging

from lego_util.exceptions import (
    ClassOrNamespaceNotFoundInGhidraError,
    TypeNotFoundInGhidraError,
    MultipleTypesFoundInGhidraError,
)

# Disable spurious warnings in vscode / pylance
# pyright: reportMissingModuleSource=false

from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.data import DataType, DataTypeConflictHandler, PointerDataType
from ghidra.program.model.symbol import Namespace

logger = logging.getLogger(__name__)


def get_ghidra_type(api: FlatProgramAPI, type_name: str):
    """
    Searches for the type named `typeName` in Ghidra.

    Raises:
    - NotFoundInGhidraError
    - MultipleTypesFoundInGhidraError
    """
    result = api.getDataTypes(type_name)
    if len(result) == 0:
        raise TypeNotFoundInGhidraError(type_name)
    if len(result) == 1:
        return result[0]

    raise MultipleTypesFoundInGhidraError(type_name, result)


def get_or_add_pointer_type(api: FlatProgramAPI, pointee: DataType) -> DataType:
    new_pointer_data_type = PointerDataType(pointee)
    new_pointer_data_type.setCategoryPath(pointee.getCategoryPath())
    return add_data_type_or_reuse_existing(api, new_pointer_data_type)


def add_data_type_or_reuse_existing(
    api: FlatProgramAPI, new_data_type: DataType
) -> DataType:
    result_data_type = (
        api.getCurrentProgram()
        .getDataTypeManager()
        .addDataType(new_data_type, DataTypeConflictHandler.KEEP_HANDLER)
    )
    if result_data_type is not new_data_type:
        logger.debug(
            "Reusing existing data type instead of new one: %s (class: %s)",
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


def sanitize_name(name: str) -> str:
    """
    Takes a full class or function name and replaces characters not accepted by Ghidra.
    Applies mostly to templates and names like `vbase destructor`.
    """
    new_class_name = (
        name.replace("<", "[")
        .replace(">", "]")
        .replace("*", "#")
        .replace(" ", "_")
        .replace("`", "'")
    )
    if "<" in name:
        new_class_name = "_template_" + new_class_name

    if new_class_name != name:
        logger.warning(
            "Class or function name contains characters forbidden by Ghidra, changing from '%s' to '%s'",
            name,
            new_class_name,
        )
    return new_class_name
