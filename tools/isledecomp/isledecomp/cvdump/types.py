from dataclasses import dataclass
import re
import logging
from typing import Any, Dict, List, NamedTuple, Optional


logger = logging.getLogger(__name__)


class CvdumpTypeError(Exception):
    pass


class CvdumpKeyError(KeyError):
    pass


class CvdumpIntegrityError(Exception):
    pass


class FieldListItem(NamedTuple):
    """Member of a class or structure"""

    offset: int
    name: str
    type: str


@dataclass
class VirtualBaseClass:
    type: str
    index: int
    direct: bool


@dataclass
class VirtualBasePointer:
    vboffset: int
    bases: list[VirtualBaseClass]


class ScalarType(NamedTuple):
    offset: int
    name: Optional[str]
    type: str

    @property
    def size(self) -> int:
        return scalar_type_size(self.type)

    @property
    def format_char(self) -> str:
        return scalar_type_format_char(self.type)

    @property
    def is_pointer(self) -> bool:
        return scalar_type_pointer(self.type)


class TypeInfo(NamedTuple):
    key: str
    size: Optional[int]
    name: Optional[str] = None
    members: Optional[List[FieldListItem]] = None

    def is_scalar(self) -> bool:
        # TODO: distinction between a class with zero members and no vtable?
        return self.members is None


def normalize_type_id(key: str) -> str:
    """Helper for TYPES parsing to ensure a consistent format.
    If key begins with "T_" it is a built-in type.
    Else it is a hex string. We prefer lower case letters and
    no leading zeroes. (UDT identifier pads to 8 characters.)"""
    if key[0] == "0":
        return f"0x{key[-4:].lower()}"

    # Remove numeric value for "T_" type. We don't use this.
    return key.partition("(")[0]


def scalar_type_pointer(type_name: str) -> bool:
    return type_name.startswith("T_32P")


def scalar_type_size(type_name: str) -> int:
    if scalar_type_pointer(type_name):
        return 4

    if "CHAR" in type_name:
        return 2 if "WCHAR" in type_name else 1

    if "SHORT" in type_name:
        return 2

    if "QUAD" in type_name or "64" in type_name:
        return 8

    return 4


def scalar_type_signed(type_name: str) -> bool:
    if scalar_type_pointer(type_name):
        return False

    # According to cvinfo.h, T_WCHAR is unsigned
    return not type_name.startswith("T_U") and not type_name.startswith("T_W")


def scalar_type_format_char(type_name: str) -> str:
    if scalar_type_pointer(type_name):
        return "L"

    # "Really a char"
    if type_name.startswith("T_RCHAR"):
        return "c"

    # floats
    if type_name.startswith("T_REAL"):
        return "d" if "64" in type_name else "f"

    size = scalar_type_size(type_name)
    char = ({1: "b", 2: "h", 4: "l", 8: "q"}).get(size, "l")

    return char if scalar_type_signed(type_name) else char.upper()


def member_list_to_struct_string(members: List[ScalarType]) -> str:
    """Create a string for use with struct.unpack"""

    format_string = "".join(m.format_char for m in members)
    if len(format_string) > 0:
        return "<" + format_string

    return ""


def join_member_names(parent: str, child: Optional[str]) -> str:
    """Helper method to combine parent/child member names.
    Child member name is None if the child is a scalar type."""

    if child is None:
        return parent

    # If the child is an array index, join without the dot
    if child.startswith("["):
        return f"{parent}{child}"

    return f"{parent}.{child}"


class CvdumpTypesParser:
    """Parser for cvdump output, TYPES section.
    Tricky enough that it demands its own parser."""

    # Marks the start of a new type
    INDEX_RE = re.compile(r"(?P<key>0x\w+) : .* (?P<type>LF_\w+)")

    # LF_FIELDLIST class/struct member (1/2)
    LIST_RE = re.compile(
        r"\s+list\[\d+\] = LF_MEMBER, (?P<scope>\w+), type = (?P<type>.*), offset = (?P<offset>\d+)"
    )

    # LF_FIELDLIST vtable indicator
    VTABLE_RE = re.compile(r"^\s+list\[\d+\] = LF_VFUNCTAB")

    # LF_FIELDLIST superclass indicator
    SUPERCLASS_RE = re.compile(
        r"^\s+list\[\d+\] = LF_BCLASS, (?P<scope>\w+), type = (?P<type>.*), offset = (?P<offset>\d+)"
    )

    # LF_FIELDLIST virtual direct/indirect base pointer, line 1/2
    VBCLASS_RE = re.compile(
        r"^\s+list\[\d+\] = LF_(?P<indirect>I?)VBCLASS, .* base type = (?P<type>.*)$"
    )

    # LF_FIELDLIST virtual direct/indirect base pointer, line 2/2
    VBCLASS_LINE_2_RE = re.compile(
        r"^\s+virtual base ptr = .+, vbpoff = (?P<vboffset>\d+), vbind = (?P<vbindex>\d+)$"
    )

    # LF_FIELDLIST member name (2/2)
    MEMBER_RE = re.compile(r"^\s+member name = '(?P<name>.*)'$")

    LF_FIELDLIST_ENUMERATE = re.compile(
        r"^\s+list\[\d+\] = LF_ENUMERATE,.*value = (?P<value>\d+), name = '(?P<name>[^']+)'$"
    )

    # LF_ARRAY element type
    ARRAY_ELEMENT_RE = re.compile(r"^\s+Element type = (?P<type>.*)")

    # LF_ARRAY total array size
    ARRAY_LENGTH_RE = re.compile(r"^\s+length = (?P<length>\d+)")

    # LF_CLASS/LF_STRUCTURE field list reference
    CLASS_FIELD_RE = re.compile(
        r"^\s+# members = \d+,  field list type (?P<field_type>0x\w+),"
    )

    # LF_CLASS/LF_STRUCTURE name and other info
    CLASS_NAME_RE = re.compile(
        r"^\s+Size = (?P<size>\d+), class name = (?P<name>(?:[^,]|,\S)+)(?:, UDT\((?P<udt>0x\w+)\))?"
    )

    # LF_MODIFIER, type being modified
    MODIFIES_RE = re.compile(r".*modifies type (?P<type>.*)$")

    # LF_ARGLIST number of entries
    LF_ARGLIST_ARGCOUNT = re.compile(r".*argument count = (?P<argcount>\d+)$")

    # LF_ARGLIST list entry
    LF_ARGLIST_ENTRY = re.compile(
        r"^\s+list\[(?P<index>\d+)\] = (?P<arg_type>[\w()]+)$"
    )

    # LF_POINTER element
    LF_POINTER_ELEMENT = re.compile(r"^\s+Element type : (?P<element_type>.+)$")

    # LF_MFUNCTION attribute key-value pairs
    LF_MFUNCTION_ATTRIBUTES = [
        re.compile(r"\s*Return type = (?P<return_type>[\w()]+)$"),
        re.compile(r"\s*Class type = (?P<class_type>[\w()]+)$"),
        re.compile(r"\s*This type = (?P<this_type>[\w()]+)$"),
        # Call type may contain whitespace
        re.compile(r"\s*Call type = (?P<call_type>[\w()\s]+)$"),
        re.compile(r"\s*Parms = (?P<num_params>[\w()]+)$"),  # LF_MFUNCTION only
        re.compile(r"\s*# Parms = (?P<num_params>[\w()]+)$"),  # LF_PROCEDURE only
        re.compile(r"\s*Arg list type = (?P<arg_list_type>[\w()]+)$"),
        re.compile(
            r"\s*This adjust = (?P<this_adjust>[\w()]+)$"
        ),  # TODO: figure out the meaning
        re.compile(
            r"\s*Func attr = (?P<func_attr>[\w()]+)$"
        ),  # Only for completeness, is always `none`
    ]

    LF_ENUM_ATTRIBUTES = [
        re.compile(r"^\s*# members = (?P<num_members>\d+)$"),
        re.compile(r"^\s*enum name = (?P<name>.+)$"),
    ]
    LF_ENUM_TYPES = re.compile(
        r"^\s*type = (?P<underlying_type>\S+) field list type (?P<field_type>0x\w{4})$"
    )
    LF_ENUM_UDT = re.compile(r"^\s*UDT\((?P<udt>0x\w+)\)$")
    LF_UNION_LINE = re.compile(
        r"^.*field list type (?P<field_type>0x\w+),.*Size = (?P<size>\d+)\s*,class name = (?P<name>(?:[^,]|,\S)+)(?:,\s.*UDT\((?P<udt>0x\w+)\))?$"
    )

    MODES_OF_INTEREST = {
        "LF_ARRAY",
        "LF_CLASS",
        "LF_ENUM",
        "LF_FIELDLIST",
        "LF_MODIFIER",
        "LF_POINTER",
        "LF_STRUCTURE",
        "LF_ARGLIST",
        "LF_MFUNCTION",
        "LF_PROCEDURE",
        "LF_UNION",
    }

    def __init__(self) -> None:
        self.mode: Optional[str] = None
        self.last_key = ""
        self.keys: Dict[str, Dict[str, Any]] = {}

    def _new_type(self):
        """Prepare a new dict for the type we just parsed.
        The id is self.last_key and the "type" of type is self.mode.
        e.g. LF_CLASS"""
        self.keys[self.last_key] = {"type": self.mode}

    def _set(self, key: str, value):
        self.keys[self.last_key][key] = value

    def _add_member(self, offset: int, type_: str):
        obj = self.keys[self.last_key]
        if "members" not in obj:
            obj["members"] = []

        obj["members"].append({"offset": offset, "type": type_})

    def _set_member_name(self, name: str):
        """Set name for most recently added member."""
        obj = self.keys[self.last_key]
        obj["members"][-1]["name"] = name

    def _add_variant(self, name: str, value: int):
        obj = self.keys[self.last_key]
        if "variants" not in obj:
            obj["variants"] = []
        variants: list[dict[str, Any]] = obj["variants"]
        variants.append({"name": name, "value": value})

    def _get_field_list(self, type_obj: Dict[str, Any]) -> List[FieldListItem]:
        """Return the field list for the given LF_CLASS/LF_STRUCTURE reference"""

        if type_obj.get("type") == "LF_FIELDLIST":
            field_obj = type_obj
        else:
            field_list_type = type_obj["field_list_type"]
            field_obj = self.keys[field_list_type]

        members: List[FieldListItem] = []

        super_ids = field_obj.get("super", [])
        for super_id in super_ids:
            # May need to resolve forward ref.
            superclass = self.get(super_id)
            if superclass.members is not None:
                members += superclass.members

        raw_members = field_obj.get("members", [])
        members += [
            FieldListItem(
                offset=m["offset"],
                type=m["type"],
                name=m["name"],
            )
            for m in raw_members
        ]

        return sorted(members, key=lambda m: m.offset)

    def _mock_array_members(self, type_obj: Dict) -> List[FieldListItem]:
        """LF_ARRAY elements provide the element type and the total size.
        We want the list of "members" as if this was a struct."""

        if type_obj.get("type") != "LF_ARRAY":
            raise CvdumpTypeError("Type is not an LF_ARRAY")

        array_type = type_obj.get("array_type")
        if array_type is None:
            raise CvdumpIntegrityError("No array element type")

        array_element_size = self.get(array_type).size
        assert (
            array_element_size is not None
        ), "Encountered an array whose type has no size"

        n_elements = type_obj["size"] // array_element_size

        return [
            FieldListItem(
                offset=i * array_element_size,
                type=array_type,
                name=f"[{i}]",
            )
            for i in range(n_elements)
        ]

    def get(self, type_key: str) -> TypeInfo:
        """Convert our dictionary values read from the cvdump output
        into a consistent format for the given type."""

        # Scalar type. Handled here because it makes the recursive steps
        # much simpler.
        if type_key.startswith("T_"):
            size = scalar_type_size(type_key)
            return TypeInfo(
                key=type_key,
                size=size,
            )

        # Go to our dictionary to find it.
        obj = self.keys.get(type_key.lower())
        if obj is None:
            raise CvdumpKeyError(type_key)

        # These type references are just a wrapper around a scalar
        if obj.get("type") == "LF_ENUM":
            underlying_type = obj.get("underlying_type")
            if underlying_type is None:
                raise CvdumpKeyError(f"Missing 'underlying_type' in {obj}")
            return self.get(underlying_type)

        if obj.get("type") == "LF_POINTER":
            return self.get("T_32PVOID")

        if obj.get("is_forward_ref", False):
            # Get the forward reference to follow.
            # If this is LF_CLASS/LF_STRUCTURE, it is the UDT value.
            # For LF_MODIFIER, it is the type being modified.
            forward_ref = obj.get("udt", None) or obj.get("modifies", None)
            if forward_ref is None:
                raise CvdumpIntegrityError(f"Null forward ref for type {type_key}")

            return self.get(forward_ref)

        # Else it is not a forward reference, so build out the object here.
        if obj.get("type") == "LF_ARRAY":
            members = self._mock_array_members(obj)
        else:
            members = self._get_field_list(obj)

        return TypeInfo(
            key=type_key,
            size=obj.get("size"),
            name=obj.get("name"),
            members=members,
        )

    def get_by_name(self, name: str) -> TypeInfo:
        """Find the complex type with the given name."""
        # TODO
        raise NotImplementedError

    def get_scalars(self, type_key: str) -> List[ScalarType]:
        """Reduce the given type to a list of scalars so we can
        compare each component value."""

        obj = self.get(type_key)
        if obj.is_scalar():
            # Use obj.key here for alias types like LF_POINTER
            return [ScalarType(offset=0, type=obj.key, name=None)]

        # mypy?
        assert obj.members is not None

        # Dedupe repeated offsets if this is a union type
        unique_offsets = {m.offset: m for m in obj.members}
        unique_members = [m for _, m in unique_offsets.items()]

        return [
            ScalarType(
                offset=m.offset + cm.offset,
                type=cm.type,
                name=join_member_names(m.name, cm.name),
            )
            for m in unique_members
            for cm in self.get_scalars(m.type)
        ]

    def get_scalars_gapless(self, type_key: str) -> List[ScalarType]:
        """Reduce the given type to a list of scalars so we can
        compare each component value."""

        obj = self.get(type_key)
        total_size = obj.size
        assert (
            total_size is not None
        ), "Called get_scalar_gapless() on a type without size"

        scalars = self.get_scalars(type_key)

        output = []
        last_extent = total_size

        # Walk the scalar list in reverse; we assume a gap could not
        # come at the start of the struct.
        for scalar in scalars[::-1]:
            this_extent = scalar.offset + scalar_type_size(scalar.type)
            size_diff = last_extent - this_extent
            # We need to add the gap fillers in reverse here
            for i in range(size_diff - 1, -1, -1):
                # Push to front
                output.insert(
                    0,
                    ScalarType(
                        offset=this_extent + i,
                        name="(padding)",
                        type="T_UCHAR",
                    ),
                )

            output.insert(0, scalar)
            last_extent = scalar.offset

        return output

    def get_format_string(self, type_key: str) -> str:
        members = self.get_scalars_gapless(type_key)
        return member_list_to_struct_string(members)

    def read_line(self, line: str):
        if line.endswith("\n"):
            line = line[:-1]
        if len(line) == 0:
            return

        if (match := self.INDEX_RE.match(line)) is not None:
            type_ = match.group(2)
            if type_ not in self.MODES_OF_INTEREST:
                self.mode = None
                return

            # Don't need to normalize, it's already in the format we want
            self.last_key = match.group(1)
            self.mode = type_
            self._new_type()

            if type_ == "LF_ARGLIST":
                submatch = self.LF_ARGLIST_ARGCOUNT.match(line)
                assert submatch is not None
                self.keys[self.last_key]["argcount"] = int(submatch.group("argcount"))
                # TODO: This should be validated in another pass
            return

        if self.mode is None:
            return

        if self.mode == "LF_MODIFIER":
            if (match := self.MODIFIES_RE.match(line)) is not None:
                # For convenience, because this is essentially the same thing
                # as an LF_CLASS forward ref.
                self._set("is_forward_ref", True)
                self._set("modifies", normalize_type_id(match.group("type")))

        elif self.mode == "LF_ARRAY":
            if (match := self.ARRAY_ELEMENT_RE.match(line)) is not None:
                self._set("array_type", normalize_type_id(match.group("type")))

            elif (match := self.ARRAY_LENGTH_RE.match(line)) is not None:
                self._set("size", int(match.group("length")))

        elif self.mode == "LF_FIELDLIST":
            self.read_fieldlist_line(line)

        elif self.mode == "LF_ARGLIST":
            self.read_arglist_line(line)

        elif self.mode in ["LF_MFUNCTION", "LF_PROCEDURE"]:
            self.read_mfunction_line(line)

        elif self.mode in ["LF_CLASS", "LF_STRUCTURE"]:
            self.read_class_or_struct_line(line)

        elif self.mode == "LF_POINTER":
            self.read_pointer_line(line)

        elif self.mode == "LF_ENUM":
            self.read_enum_line(line)

        elif self.mode == "LF_UNION":
            self.read_union_line(line)

        else:
            # Check for exhaustiveness
            logger.error("Unhandled data in mode: %s", self.mode)

    def read_fieldlist_line(self, line: str):
        # If this class has a vtable, create a mock member at offset 0
        if (match := self.VTABLE_RE.match(line)) is not None:
            # For our purposes, any pointer type will do
            self._add_member(0, "T_32PVOID")
            self._set_member_name("vftable")

        # Superclass is set here in the fieldlist rather than in LF_CLASS
        elif (match := self.SUPERCLASS_RE.match(line)) is not None:
            superclass_list: dict[str, int] = self.keys[self.last_key].setdefault(
                "super", {}
            )
            superclass_list[normalize_type_id(match.group("type"))] = int(
                match.group("offset")
            )

        # virtual base class (direct or indirect)
        elif (match := self.VBCLASS_RE.match(line)) is not None:

            virtual_base_pointer = self.keys[self.last_key].setdefault(
                "vbase",
                VirtualBasePointer(
                    vboffset=-1,  # default to -1 until we parse the correct value
                    bases=[],
                ),
            )
            assert isinstance(
                virtual_base_pointer, VirtualBasePointer
            )  # type checker only

            virtual_base_pointer.bases.append(
                VirtualBaseClass(
                    type=match.group("type"),
                    index=-1,  # default to -1 until we parse the correct value
                    direct=match.group("indirect") != "I",
                )
            )

        elif (match := self.VBCLASS_LINE_2_RE.match(line)) is not None:
            virtual_base_pointer = self.keys[self.last_key].get("vbase", None)
            assert isinstance(
                virtual_base_pointer, VirtualBasePointer
            ), "Parsed the second line of an (I)VBCLASS without the first one"
            vboffset = int(match.group("vboffset"))

            if virtual_base_pointer.vboffset == -1:
                # default value
                virtual_base_pointer.vboffset = vboffset
            elif virtual_base_pointer.vboffset != vboffset:
                # vboffset is always equal to 4 in our examples. We are not sure if there can be multiple
                # virtual base pointers, and if so, how the layout is supposed to look.
                # We therefore assume that there is always only one virtual base pointer.
                logger.error(
                    "Unhandled: Found multiple virtual base pointers at offsets %d and %d",
                    virtual_base_pointer.vboffset,
                    vboffset,
                )

            virtual_base_pointer.bases[-1].index = int(match.group("vbindex"))
            # these come out of order, and the lists are so short that it's fine to sort them every time
            virtual_base_pointer.bases.sort(key=lambda x: x.index)

        # Member offset and type given on the first of two lines.
        elif (match := self.LIST_RE.match(line)) is not None:
            self._add_member(
                int(match.group("offset")), normalize_type_id(match.group("type"))
            )

        # Name of the member read on the second of two lines.
        elif (match := self.MEMBER_RE.match(line)) is not None:
            self._set_member_name(match.group("name"))

        elif (match := self.LF_FIELDLIST_ENUMERATE.match(line)) is not None:
            self._add_variant(match.group("name"), int(match.group("value")))

    def read_class_or_struct_line(self, line: str):
        # Match the reference to the associated LF_FIELDLIST
        if (match := self.CLASS_FIELD_RE.match(line)) is not None:
            if match.group("field_type") == "0x0000":
                # Not redundant. UDT might not match the key.
                # These cases get reported as UDT mismatch.
                self._set("is_forward_ref", True)
            else:
                field_list_type = normalize_type_id(match.group("field_type"))
                self._set("field_list_type", field_list_type)

        elif line.lstrip().startswith("Derivation list type"):
            # We do not care about the second line, but we still match it so we see an error
            # when another line fails to match
            pass
        elif (match := self.CLASS_NAME_RE.match(line)) is not None:
            # Last line has the vital information.
            # If this is a FORWARD REF, we need to follow the UDT pointer
            # to get the actual class details.
            self._set("name", match.group("name"))
            udt = match.group("udt")
            if udt is not None:
                self._set("udt", normalize_type_id(udt))
            self._set("size", int(match.group("size")))
        else:
            logger.error("Unmatched line in class: %s", line[:-1])

    def read_arglist_line(self, line: str):
        if (match := self.LF_ARGLIST_ENTRY.match(line)) is not None:
            obj = self.keys[self.last_key]
            arglist: list = obj.setdefault("args", [])
            assert int(match.group("index")) == len(
                arglist
            ), "Argument list out of sync"
            arglist.append(match.group("arg_type"))
        else:
            logger.error("Unmatched line in arglist: %s", line[:-1])

    def read_pointer_line(self, line: str):
        if (match := self.LF_POINTER_ELEMENT.match(line)) is not None:
            self._set("element_type", match.group("element_type"))
        else:
            stripped_line = line.strip()
            # We don't parse these lines, but we still want to check for exhaustiveness
            # in case we missed some relevant data
            if not any(
                stripped_line.startswith(prefix)
                for prefix in ["Pointer", "const Pointer", "L-value", "volatile"]
            ):
                logger.error("Unrecognized pointer attribute: %s", line[:-1])

    def read_mfunction_line(self, line: str):
        """
        The layout is not consistent, so we want to be as robust as possible here.
        - Example 1:
            Return type = T_LONG(0012), Call type = C Near
            Func attr = none
        - Example 2:
                Return type = T_CHAR(0010), Class type = 0x101A, This type = 0x101B,
            Call type = ThisCall, Func attr = none
        """

        obj = self.keys[self.last_key]

        key_value_pairs = line.split(",")
        for pair in key_value_pairs:
            if pair.isspace():
                continue
            obj |= self.parse_function_attribute(pair)

    def parse_function_attribute(self, pair: str) -> dict[str, str]:
        for attribute_regex in self.LF_MFUNCTION_ATTRIBUTES:
            if (match := attribute_regex.match(pair)) is not None:
                return match.groupdict()
        logger.error("Unknown attribute in function: %s", pair)
        return {}

    def read_enum_line(self, line: str):
        obj = self.keys[self.last_key]

        # We need special comma handling because commas may appear in the name.
        # Splitting by "," yields the wrong result.
        enum_attributes = line.split(", ")
        for pair in enum_attributes:
            if pair.endswith(","):
                pair = pair[:-1]
            if pair.isspace():
                continue
            obj |= self.parse_enum_attribute(pair)

    def parse_enum_attribute(self, attribute: str) -> dict[str, Any]:
        for attribute_regex in self.LF_ENUM_ATTRIBUTES:
            if (match := attribute_regex.match(attribute)) is not None:
                return match.groupdict()
        if attribute == "NESTED":
            return {"is_nested": True}
        if attribute == "FORWARD REF":
            return {"is_forward_ref": True}
        if attribute.startswith("UDT"):
            match = self.LF_ENUM_UDT.match(attribute)
            assert match is not None
            return {"udt": normalize_type_id(match.group("udt"))}
        if (match := self.LF_ENUM_TYPES.match(attribute)) is not None:
            result = match.groupdict()
            result["underlying_type"] = normalize_type_id(result["underlying_type"])
            return result
        logger.error("Unknown attribute in enum: %s", attribute)
        return {}

    def read_union_line(self, line: str):
        """This is a rather barebones handler, only parsing the size"""
        if (match := self.LF_UNION_LINE.match(line)) is None:
            raise AssertionError(f"Unhandled in union: {line}")
        self._set("name", match.group("name"))
        if match.group("field_type") == "0x0000":
            self._set("is_forward_ref", True)

        self._set("size", int(match.group("size")))
        if match.group("udt") is not None:
            self._set("udt", normalize_type_id(match.group("udt")))
