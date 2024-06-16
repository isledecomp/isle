import logging
from typing import Any, Callable, TypeVar

# Disable spurious warnings in vscode / pylance
# pyright: reportMissingModuleSource=false

# pylint: disable=too-many-return-statements # a `match` would be better, but for now we are stuck with Python 3.9
# pylint: disable=no-else-return # Not sure why this rule even is a thing, this is great for checking exhaustiveness

from lego_util.exceptions import (
    ClassOrNamespaceNotFoundInGhidraError,
    TypeNotFoundError,
    TypeNotFoundInGhidraError,
    TypeNotImplementedError,
    StructModificationError,
)
from lego_util.ghidra_helper import (
    add_pointer_type,
    create_ghidra_namespace,
    get_ghidra_namespace,
    get_ghidra_type,
    sanitize_name,
)
from lego_util.pdb_extraction import PdbFunctionExtractor

from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.data import (
    ArrayDataType,
    CategoryPath,
    DataType,
    DataTypeConflictHandler,
    Enum,
    EnumDataType,
    StructureDataType,
    StructureInternal,
)
from ghidra.util.task import ConsoleTaskMonitor


logger = logging.getLogger(__name__)


class PdbTypeImporter:
    """Allows PDB types to be imported into Ghidra."""

    def __init__(self, api: FlatProgramAPI, extraction: PdbFunctionExtractor):
        self.api = api
        self.extraction = extraction
        # tracks the structs/classes we have already started to import, otherwise we run into infinite recursion
        self.handled_structs: set[str] = set()

        # tracks the enums we have already handled for the sake of efficiency
        self.handled_enums: dict[str, Enum] = {}

    @property
    def types(self):
        return self.extraction.compare.cv.types

    def import_pdb_type_into_ghidra(self, type_index: str) -> DataType:
        """
        Recursively imports a type from the PDB into Ghidra.
        @param type_index Either a scalar type like `T_INT4(...)` or a PDB reference like `0x10ba`
        """
        type_index_lower = type_index.lower()
        if type_index_lower.startswith("t_"):
            return self._import_scalar_type(type_index_lower)

        try:
            type_pdb = self.extraction.compare.cv.types.keys[type_index_lower]
        except KeyError as e:
            raise TypeNotFoundError(
                f"Failed to find referenced type '{type_index_lower}'"
            ) from e

        type_category = type_pdb["type"]

        # follow forward reference (class, struct, union)
        if type_pdb.get("is_forward_ref", False):
            return self._import_forward_ref_type(type_index_lower, type_pdb)

        if type_category == "LF_POINTER":
            return add_pointer_type(
                self.api, self.import_pdb_type_into_ghidra(type_pdb["element_type"])
            )
        elif type_category in ["LF_CLASS", "LF_STRUCTURE"]:
            return self._import_class_or_struct(type_pdb)
        elif type_category == "LF_ARRAY":
            return self._import_array(type_pdb)
        elif type_category == "LF_ENUM":
            return self._import_enum(type_pdb)
        elif type_category == "LF_PROCEDURE":
            logger.warning(
                "Not implemented: Function-valued argument or return type will be replaced by void pointer: %s",
                type_pdb,
            )
            return get_ghidra_type(self.api, "void")
        elif type_category == "LF_UNION":
            return self._import_union(type_pdb)
        else:
            raise TypeNotImplementedError(type_pdb)

    _scalar_type_map = {
        "rchar": "char",
        "int4": "int",
        "uint4": "uint",
        "real32": "float",
        "real64": "double",
    }

    def _scalar_type_to_cpp(self, scalar_type: str) -> str:
        if scalar_type.startswith("32p"):
            return f"{self._scalar_type_to_cpp(scalar_type[3:])} *"
        return self._scalar_type_map.get(scalar_type, scalar_type)

    def _import_scalar_type(self, type_index_lower: str) -> DataType:
        if (match := self.extraction.scalar_type_regex.match(type_index_lower)) is None:
            raise TypeNotFoundError(f"Type has unexpected format: {type_index_lower}")

        scalar_cpp_type = self._scalar_type_to_cpp(match.group("typename"))
        return get_ghidra_type(self.api, scalar_cpp_type)

    def _import_forward_ref_type(
        self, type_index, type_pdb: dict[str, Any]
    ) -> DataType:
        referenced_type = type_pdb.get("udt") or type_pdb.get("modifies")
        if referenced_type is None:
            try:
                # Example: HWND__, needs to be created manually
                return get_ghidra_type(self.api, type_pdb["name"])
            except TypeNotFoundInGhidraError as e:
                raise TypeNotImplementedError(
                    f"{type_index}: forward ref without target, needs to be created manually: {type_pdb}"
                ) from e
        logger.debug(
            "Following forward reference from %s to %s",
            type_index,
            referenced_type,
        )
        return self.import_pdb_type_into_ghidra(referenced_type)

    def _import_array(self, type_pdb: dict[str, Any]) -> DataType:
        inner_type = self.import_pdb_type_into_ghidra(type_pdb["array_type"])

        array_total_bytes: int = type_pdb["size"]
        data_type_size = inner_type.getLength()
        array_length, modulus = divmod(array_total_bytes, data_type_size)
        assert (
            modulus == 0
        ), f"Data type size {data_type_size} does not divide array size {array_total_bytes}"

        return ArrayDataType(inner_type, array_length, 0)

    def _import_union(self, type_pdb: dict[str, Any]) -> DataType:
        try:
            logger.debug("Dereferencing union %s", type_pdb)
            union_type = get_ghidra_type(self.api, type_pdb["name"])
            assert (
                union_type.getLength() == type_pdb["size"]
            ), f"Wrong size of existing union type '{type_pdb['name']}': expected {type_pdb['size']}, got {union_type.getLength()}"
            return union_type
        except TypeNotFoundInGhidraError as e:
            # We have so few instances, it is not worth implementing this
            raise TypeNotImplementedError(
                f"Writing union types is not supported. Please add by hand: {type_pdb}"
            ) from e

    def _import_enum(self, type_pdb: dict[str, Any]) -> DataType:
        underlying_type = self.import_pdb_type_into_ghidra(type_pdb["underlying_type"])
        field_list = self.extraction.compare.cv.types.keys.get(type_pdb["field_type"])
        assert field_list is not None, f"Failed to find field list for enum {type_pdb}"

        result = self._get_or_create_enum_data_type(
            type_pdb["name"], underlying_type.getLength()
        )
        # clear existing variant if there are any
        for existing_variant in result.getNames():
            result.remove(existing_variant)

        variants: list[dict[str, Any]] = field_list["variants"]
        for variant in variants:
            result.add(variant["name"], variant["value"])

        return result

    def _import_class_or_struct(self, type_in_pdb: dict[str, Any]) -> DataType:
        field_list_type: str = type_in_pdb["field_list_type"]
        field_list = self.types.keys[field_list_type.lower()]

        class_size: int = type_in_pdb["size"]
        class_name_with_namespace: str = sanitize_name(type_in_pdb["name"])

        if class_name_with_namespace in self.handled_structs:
            logger.debug(
                "Class has been handled or is being handled: %s",
                class_name_with_namespace,
            )
            return get_ghidra_type(self.api, class_name_with_namespace)

        logger.debug(
            "--- Beginning to import class/struct '%s'", class_name_with_namespace
        )

        # Add as soon as we start to avoid infinite recursion
        self.handled_structs.add(class_name_with_namespace)

        self._get_or_create_namespace(class_name_with_namespace)

        data_type = self._get_or_create_struct_data_type(
            class_name_with_namespace, class_size
        )

        if (old_size := data_type.getLength()) != class_size:
            logger.warning(
                "Existing class %s had incorrect size %d. Setting to %d...",
                class_name_with_namespace,
                old_size,
                class_size,
            )

        logger.info("Adding class data type %s", class_name_with_namespace)
        logger.debug("Class information: %s", type_in_pdb)

        data_type.deleteAll()
        data_type.growStructure(class_size)

        # this case happened e.g. for IUnknown, which linked to an (incorrect) existing library, and some other types as well.
        # Unfortunately, we don't get proper error handling for read-only types.
        # However, we really do NOT want to do this every time because the type might be self-referential and partially imported.
        if data_type.getLength() != class_size:
            data_type = self._delete_and_recreate_struct_data_type(
                class_name_with_namespace, class_size, data_type
            )

        # can be missing when no new fields are declared
        components: list[dict[str, Any]] = field_list.get("members") or []

        super_type = field_list.get("super")
        if super_type is not None:
            components.insert(0, {"type": super_type, "offset": 0, "name": "base"})

        for component in components:
            ghidra_type = self.import_pdb_type_into_ghidra(component["type"])
            logger.debug("Adding component to class: %s", component)

            try:
                # for better logs
                data_type.replaceAtOffset(
                    component["offset"], ghidra_type, -1, component["name"], None
                )
            except Exception as e:
                raise StructModificationError(type_in_pdb) from e

        logger.info("Finished importing class %s", class_name_with_namespace)

        return data_type

    def _get_or_create_namespace(self, class_name_with_namespace: str):
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

    def _get_or_create_enum_data_type(
        self, enum_type_name: str, enum_type_size: int
    ) -> Enum:

        if (known_enum := self.handled_enums.get(enum_type_name, None)) is not None:
            return known_enum

        result = self._get_or_create_data_type(
            enum_type_name,
            "enum",
            Enum,
            lambda: EnumDataType(
                CategoryPath("/imported"), enum_type_name, enum_type_size
            ),
        )
        self.handled_enums[enum_type_name] = result
        return result

    def _get_or_create_struct_data_type(
        self, class_name_with_namespace: str, class_size: int
    ) -> StructureInternal:
        return self._get_or_create_data_type(
            class_name_with_namespace,
            "class/struct",
            StructureInternal,
            lambda: StructureDataType(
                CategoryPath("/imported"), class_name_with_namespace, class_size
            ),
        )

    T = TypeVar("T", bound=DataType)

    def _get_or_create_data_type(
        self,
        type_name: str,
        readable_name_of_type_category: str,
        expected_type: type[T],
        new_instance_callback: Callable[[], T],
    ) -> T:
        """
        Checks if a data type provided under the given name exists in Ghidra.
        Creates one using `new_instance_callback` if there is not.
        Also verifies the data type.

        Note that the return value of `addDataType()` is not the same instance as the input
        even if there is no name collision.
        """
        try:
            data_type = get_ghidra_type(self.api, type_name)
            logger.debug(
                "Found existing %s type %s under category path %s",
                readable_name_of_type_category,
                type_name,
                data_type.getCategoryPath(),
            )
        except TypeNotFoundInGhidraError:
            data_type = (
                self.api.getCurrentProgram()
                .getDataTypeManager()
                .addDataType(new_instance_callback(), DataTypeConflictHandler.KEEP_HANDLER)
            )
            logger.info(
                "Created new %s data type %s", readable_name_of_type_category, type_name
            )
        assert isinstance(
            data_type, expected_type
        ), f"Found existing type named {type_name} that is not a {readable_name_of_type_category}"
        return data_type

    def _delete_and_recreate_struct_data_type(
        self,
        class_name_with_namespace: str,
        class_size: int,
        existing_data_type: DataType,
    ) -> StructureInternal:
        logger.warning(
            "Failed to modify data type %s. Will try to delete the existing one and re-create the imported one.",
            class_name_with_namespace,
        )

        assert (
            self.api.getCurrentProgram()
            .getDataTypeManager()
            .remove(existing_data_type, ConsoleTaskMonitor())
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
        return data_type
