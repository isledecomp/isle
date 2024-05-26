from typing import Any

# Disable spurious warnings in vscode / pylance
# pyright: reportMissingModuleSource=false

from lego_util.exceptions import (
    ClassOrNamespaceNotFoundInGhidraError,
    TypeNotFoundError,
    TypeNotFoundInGhidraError,
    TypeNotImplementedError,
)
from lego_util.ghidra_helper import (
    add_pointer_type,
    create_ghidra_namespace,
    get_ghidra_namespace,
    get_ghidra_type,
    sanitize_class_name,
)
from lego_util.pdb_extraction import PdbExtractionForGhidraMigration
from lego_util.function_importer import logger


from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.data import (
    ArrayDataType,
    CategoryPath,
    DataType,
    DataTypeConflictHandler,
    StructureDataType,
    StructureInternal,
)
from ghidra.util.task import ConsoleTaskMonitor


class PdbTypeImporter:
    def __init__(
        self, api: FlatProgramAPI, extraction: PdbExtractionForGhidraMigration
    ):
        self.api = api
        self.extraction = extraction
        self.handled_structs: set[str] = (
            set()
        )  # tracks the types we have already imported, otherwise we keep overwriting finished work

    @property
    def types(self):
        return self.extraction.compare.cv.types

    def _import_class_or_struct(self, type_in_pdb: dict[str, Any]) -> DataType:
        field_list_type = type_in_pdb.get("field_list_type")
        if field_list_type is None:
            raise TypeNotFoundError(
                f"Found a referenced missing type that is not a class or lacks a field_list_type: {type_in_pdb}"
            )

        field_list = self.types.keys[field_list_type.lower()]
        logger.debug("Found class: %s", type_in_pdb)

        class_size: int = type_in_pdb["size"]
        class_name_with_namespace: str = sanitize_class_name(type_in_pdb["name"])

        if class_name_with_namespace in self.handled_structs:
            logger.debug(
                "Class has been handled or is being handled: %s",
                class_name_with_namespace,
            )
            return get_ghidra_type(self.api, class_name_with_namespace)

        # Add as soon as we start to avoid infinite recursion
        self.handled_structs.add(class_name_with_namespace)

        # Create class / namespace if it does not exist
        colon_split = class_name_with_namespace.split("::")
        class_name = colon_split[-1]
        try:
            get_ghidra_namespace(self.api, colon_split)
            logger.debug("Found existing class/namespace %s", class_name_with_namespace)
        except ClassOrNamespaceNotFoundInGhidraError:
            logger.info("Creating class/namespace %s", class_name_with_namespace)
            class_name = colon_split.pop()
            parent_namespace = create_ghidra_namespace(self.api, colon_split)
            self.api.createClass(parent_namespace, class_name)

        # Create type if it does not exist
        try:
            data_type = get_ghidra_type(self.api, class_name_with_namespace)
            logger.debug(
                "Found existing data type %s under category path %s",
                class_name_with_namespace,
                data_type.getCategoryPath(),
            )
        except TypeNotFoundInGhidraError:
            # Create a new struct data type
            data_type = StructureDataType(
                CategoryPath("/imported"), class_name_with_namespace, class_size
            )
            data_type = (
                self.api.getCurrentProgram()
                .getDataTypeManager()
                .addDataType(data_type, DataTypeConflictHandler.KEEP_HANDLER)
            )
            logger.info("Created new data type %s", class_name_with_namespace)

        assert isinstance(
            data_type, StructureInternal
        ), f"Found type sharing its name with a class/struct, but is not a struct: {class_name_with_namespace}"

        if (old_size := data_type.getLength()) != class_size:
            logger.warning(
                "Existing class %s had incorrect size %d. Setting to %d...",
                class_name_with_namespace,
                old_size,
                class_size,
            )
            # TODO: Implement comparison to expected layout
            # We might not need that, but it helps to not break stuff if we run into an error

        logger.info("Adding class data type %s", class_name_with_namespace)
        logger.debug("Class information: %s", type_in_pdb)

        data_type.deleteAll()
        data_type.growStructure(class_size)

        # this case happened for IUnknown, which linked to an (incorrect) existing library, and some other types as well.
        # Unfortunately, we don't get proper error handling for read-only types
        if data_type.getLength() != class_size:
            logger.warning(
                "Failed to modify data type %s. Please remove the existing one by hand and try again.",
                class_name_with_namespace,
            )

            assert (
                self.api.getCurrentProgram()
                .getDataTypeManager()
                .remove(data_type, ConsoleTaskMonitor())
            ), f"Failed to delete and re-create data type {class_name_with_namespace}"
            data_type = StructureDataType(
                CategoryPath("/imported"), class_name_with_namespace, class_size
            )
            data_type = (
                self.api.getCurrentProgram()
                .getDataTypeManager()
                .addDataType(data_type, DataTypeConflictHandler.KEEP_HANDLER)
            )
            assert isinstance(data_type, StructureInternal)  # for type checking

        # Delete existing components - likely not needed when using replaceAtOffset exhaustively
        # for component in data_type.getComponents():
        #     data_type.deleteAtOffset(component.getOffset())

        # can be missing when no new fields are declared
        components: list[dict[str, Any]] = field_list.get("members") or []

        super_type = field_list.get("super")
        if super_type is not None:
            components.insert(0, {"type": super_type, "offset": 0, "name": "base"})

        for component in components:
            ghidra_type = self.pdb_to_ghidra_type(component["type"])
            logger.debug("Adding component to class: %s", component)
            # XXX: temporary exception handling to get better logs
            try:
                data_type.replaceAtOffset(
                    component["offset"], ghidra_type, -1, component["name"], None
                )
            except Exception as e:
                raise Exception(f"Error importing {type_in_pdb}") from e

        logger.info("Finished importing class %s", class_name_with_namespace)

        return data_type

    def pdb_to_ghidra_type(self, type_index: str) -> DataType:
        """
        Experimental new type converter to get rid of the intermediate step PDB -> C++ -> Ghidra

        @param type_index Either a scalar type like `T_INT4(...)` or a PDB reference like `0x10ba`
        """
        # scalar type
        type_index_lower = type_index.lower()
        if type_index_lower.startswith("t_"):
            if (
                match := self.extraction.scalar_type_regex.match(type_index_lower)
            ) is None:
                raise TypeNotFoundError(f"Type has unexpected format: {type_index}")

            scalar_cpp_type = self.extraction.scalar_type_to_cpp(
                match.group("typename")
            )
            return get_ghidra_type(self.api, scalar_cpp_type)

        try:
            type_pdb = self.extraction.compare.cv.types.keys[type_index_lower]
        except KeyError as e:
            raise TypeNotFoundError(
                f"Failed to find referenced type {type_index_lower}"
            ) from e

        type_category = type_pdb["type"]

        if type_category == "LF_POINTER":
            return add_pointer_type(
                self.api, self.pdb_to_ghidra_type(type_pdb["element_type"])
            )

        if type_category in ["LF_CLASS", "LF_STRUCTURE"]:
            if type_pdb.get("is_forward_ref", False):
                logger.debug(
                    "Following forward reference from %s to %s",
                    type_index,
                    type_pdb["udt"],
                )
                return self.pdb_to_ghidra_type(type_pdb["udt"])

            return self._import_class_or_struct(type_pdb)

        if type_category == "LF_ARRAY":
            # TODO: See how well this interacts with arrays in functions
            # We treat arrays like pointers because we don't distinguish them in Ghidra
            logger.debug("Encountered array: %s", type_pdb)
            inner_type = self.pdb_to_ghidra_type(type_pdb["array_type"])

            # TODO: Insert size / consider switching to pointer if not applicable
            return ArrayDataType(inner_type, 0, 0)

        if type_category == "LF_ENUM":
            logger.warning(
                "Replacing enum by underlying type (not implemented yet): %s", type_pdb
            )
            return self.pdb_to_ghidra_type(type_pdb["underlying_type"])

        if type_category == "LF_MODIFIER":
            logger.warning("Not sure what a modifier is: %s", type_pdb)
            # not sure what this actually is, take what it references
            return self.pdb_to_ghidra_type(type_pdb["modifies"])

        if type_category == "LF_PROCEDURE":
            logger.info(
                "Function-valued argument or return type will be replaced by void pointer: %s",
                type_pdb,
            )
            return get_ghidra_type(self.api, "void")

        if type_category == "LF_UNION":
            if type_pdb.get("is_forward_ref", False):
                return self.pdb_to_ghidra_type(type_pdb["udt"])

            try:
                logger.debug("Dereferencing union %s", type_pdb)
                union_type = get_ghidra_type(self.api, type_pdb["name"])
                assert (
                    union_type.getLength() == type_pdb["size"]
                ), f"Wrong size of existing union type '{type_pdb['name']}': expected {type_pdb["size"]}, got {union_type.getLength()}"
                return union_type
            except TypeNotFoundInGhidraError as e:
                raise TypeNotImplementedError(
                    f"Writing union types is not supported. Please add by hand: {type_pdb}"
                ) from e

        raise TypeNotImplementedError(type_pdb)
