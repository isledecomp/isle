"""For collating the results from parsing cvdump.exe into a more directly useful format."""
from typing import List, Optional, Tuple
from isledecomp.types import SymbolType
from .parser import CvdumpParser
from .demangler import demangle_string_const, demangle_vtable


def data_type_info(type_name: str) -> Optional[Tuple[int, bool]]:
    """cvdump type aliases are listed here:
    https://github.com/microsoft/microsoft-pdb/blob/master/include/cvinfo.h
    For the given type, return tuple(size, is_pointer) if possible."""
    # pylint: disable=too-many-return-statements
    # TODO: refactor to be as simple as possble

    # Ignore complex types. We can get the size of those from the TYPES section.
    if not type_name.startswith("T"):
        return None

    # if 32-bit pointer
    if type_name.startswith("T_32P"):
        return (4, True)

    if type_name.endswith("QUAD") or type_name.endswith("64"):
        return (8, False)

    if (
        type_name.endswith("LONG")
        or type_name.endswith("INT4")
        or type_name.endswith("32")
    ):
        return (4, False)

    if type_name.endswith("SHORT") or type_name.endswith("WCHAR"):
        return (2, False)

    if "CHAR" in type_name:
        return (1, False)

    if type_name in ("T_NOTYPE", "T_VOID"):
        return (0, False)

    return None


class CvdumpNode:
    # pylint: disable=too-many-instance-attributes
    # These two are required and allow us to identify the symbol
    section: int
    offset: int
    # aka the mangled name from the PUBLICS section
    decorated_name: Optional[str] = None
    # optional "nicer" name (e.g. of a function from SYMBOLS section)
    friendly_name: Optional[str] = None
    # To be determined by context after inserting data, unless the decorated
    # name makes this obvious. (i.e. string constants or vtables)
    # We choose not to assume that section 1 (probably ".text") contains only
    # functions. Smacker functions are linked to their own section "_UNSTEXT"
    node_type: Optional[SymbolType] = None
    # Function size can be read from the LINES section so use this over any
    # other value if we have it.
    # TYPES section can tell us the size of structs and other complex types.
    confirmed_size: Optional[int] = None
    # Estimated by reading the distance between this symbol and the one that
    # follows in the same section.
    # If this is the last symbol in the section, we cannot estimate a size.
    estimated_size: Optional[int] = None
    # Size as reported by SECTION CONTRIBUTIONS section. Not guaranteed to be
    # accurate.
    section_contribution: Optional[int] = None

    def __init__(self, section: int, offset: int) -> None:
        self.section = section
        self.offset = offset

    def set_decorated(self, name: str):
        self.decorated_name = name

        if self.decorated_name.startswith("??_7"):
            self.node_type = SymbolType.VTABLE
            self.friendly_name = demangle_vtable(self.decorated_name)

        elif self.decorated_name.startswith("??_C@"):
            self.node_type = SymbolType.STRING
            (strlen, _) = demangle_string_const(self.decorated_name)
            self.confirmed_size = strlen

        elif not self.decorated_name.startswith("?") and "@" in self.decorated_name:
            # C mangled symbol. The trailing at-sign with number tells the number of bytes
            # in the parameter list for __stdcall, __fastcall, or __vectorcall
            # For __cdecl it is more ambiguous and we would have to know which section we are in.
            # https://learn.microsoft.com/en-us/cpp/build/reference/decorated-names?view=msvc-170#FormatC
            self.node_type = SymbolType.FUNCTION

    def name(self) -> Optional[str]:
        """Prefer "friendly" name if we have it.
        This is what we have been using to match functions."""
        return (
            self.friendly_name
            if self.friendly_name is not None
            else self.decorated_name
        )

    def size(self) -> Optional[int]:
        if self.confirmed_size is not None:
            return self.confirmed_size

        # Better to undershoot the size because we can identify a comparison gap easily
        if self.estimated_size is not None and self.section_contribution is not None:
            return min(self.estimated_size, self.section_contribution)

        # Return whichever one we have, or neither
        return self.estimated_size or self.section_contribution


class CvdumpAnalysis:
    """Collects the results from CvdumpParser into a list of nodes (i.e. symbols).
    These can then be analyzed by a downstream tool."""

    nodes = List[CvdumpNode]

    def __init__(self, parser: CvdumpParser):
        """Read in as much information as we have from the parser.
        The more sections we have, the better our information will be."""
        node_dict = {}

        # PUBLICS is our roadmap for everything that follows.
        for pub in parser.publics:
            key = (pub.section, pub.offset)
            if key not in node_dict:
                node_dict[key] = CvdumpNode(*key)

            node_dict[key].set_decorated(pub.name)

        for sizeref in parser.sizerefs:
            key = (sizeref.section, sizeref.offset)
            if key not in node_dict:
                node_dict[key] = CvdumpNode(*key)

            node_dict[key].section_contribution = sizeref.size

        for glo in parser.globals:
            key = (glo.section, glo.offset)
            if key not in node_dict:
                node_dict[key] = CvdumpNode(*key)

            node_dict[key].node_type = SymbolType.DATA
            node_dict[key].friendly_name = glo.name

            if (g_info := data_type_info(glo.type)) is not None:
                (size, is_pointer) = g_info
                node_dict[key].confirmed_size = size
                if is_pointer:
                    node_dict[key].node_type = SymbolType.POINTER

        for lin in parser.lines:
            key = (lin.section, lin.offset)
            # Here we only set if the section:offset already exists
            # because our values include offsets inside of the function.
            if key in node_dict:
                node_dict[key].node_type = SymbolType.FUNCTION

        for sym in parser.symbols:
            key = (sym.section, sym.offset)
            if key not in node_dict:
                node_dict[key] = CvdumpNode(*key)

            if sym.type == "S_GPROC32":
                node_dict[key].friendly_name = sym.name
                node_dict[key].confirmed_size = sym.size
                node_dict[key].node_type = SymbolType.FUNCTION

        self.nodes = [v for _, v in dict(sorted(node_dict.items())).items()]
        self._estimate_size()

    def _estimate_size(self):
        """Get the distance between one section:offset value and the next one
        in the same section. This gives a rough estimate of the size of the symbol.
        If we have information from SECTION CONTRIBUTIONS, take whichever one is
        less to get the best approximate size."""
        for i in range(len(self.nodes) - 1):
            this_node = self.nodes[i]
            next_node = self.nodes[i + 1]

            # If they are in different sections, we can't compare them
            if this_node.section != next_node.section:
                continue

            this_node.estimated_size = next_node.offset - this_node.offset
