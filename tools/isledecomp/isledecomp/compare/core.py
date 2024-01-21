import os
import logging
import difflib
import struct
from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional
from isledecomp.bin import Bin as IsleBin
from isledecomp.cvdump.demangler import demangle_string_const
from isledecomp.cvdump import Cvdump, CvdumpAnalysis
from isledecomp.parser import DecompCodebase
from isledecomp.dir import walk_source_dir
from isledecomp.types import SymbolType
from isledecomp.compare.asm import ParseAsm, can_resolve_register_differences
from .db import CompareDb, MatchInfo
from .lines import LinesDb


logger = logging.getLogger(__name__)


@dataclass
class DiffReport:
    match_type: SymbolType
    orig_addr: int
    recomp_addr: int
    name: str
    udiff: Optional[List[str]] = None
    ratio: float = 0.0
    is_effective_match: bool = False

    @property
    def effective_ratio(self) -> float:
        return 1.0 if self.is_effective_match else self.ratio

    def __str__(self) -> str:
        """For debug purposes. Proper diff printing (with coloring) is in another module."""
        return f"{self.name} (0x{self.orig_addr:x}) {self.ratio*100:.02f}%{'*' if self.is_effective_match else ''}"


def create_reloc_lookup(bin_file: IsleBin) -> Callable[[int], bool]:
    """Function generator for relocation table lookup"""

    def lookup(addr: int) -> bool:
        return addr > bin_file.imagebase and bin_file.is_relocated_addr(addr)

    return lookup


def create_float_lookup(bin_file: IsleBin) -> Callable[[int, int], Optional[str]]:
    """Function generator for floating point lookup"""

    def lookup(addr: int, size: int) -> Optional[str]:
        data = bin_file.read(addr, size)
        # If this is a float constant, it should be initialized data.
        if data is None:
            return None

        struct_str = "<f" if size == 4 else "<d"
        try:
            (float_value,) = struct.unpack(struct_str, data)
            return str(float_value)
        except struct.error:
            return None

    return lookup


class Compare:
    # pylint: disable=too-many-instance-attributes
    def __init__(
        self, orig_bin: IsleBin, recomp_bin: IsleBin, pdb_file: str, code_dir: str
    ):
        self.orig_bin = orig_bin
        self.recomp_bin = recomp_bin
        self.pdb_file = pdb_file
        self.code_dir = code_dir

        self._lines_db = LinesDb(code_dir)
        self._db = CompareDb()

        self._load_cvdump()
        self._load_markers()
        self._find_original_strings()
        self._match_thunks()

    def _load_cvdump(self):
        logger.info("Parsing %s ...", self.pdb_file)
        cv = (
            Cvdump(self.pdb_file)
            .lines()
            .globals()
            .publics()
            .symbols()
            .section_contributions()
            .run()
        )
        res = CvdumpAnalysis(cv)

        for sym in res.nodes:
            # The PDB might contain sections that do not line up with the
            # actual binary. The symbol "__except_list" is one example.
            # In these cases, just skip this symbol and move on because
            # we can't do much with it.
            if not self.recomp_bin.is_valid_section(sym.section):
                continue

            addr = self.recomp_bin.get_abs_addr(sym.section, sym.offset)

            # If this symbol is the final one in its section, we were not able to
            # estimate its size because we didn't have the total size of that section.
            # We can get this estimate now and assume that the final symbol occupies
            # the remainder of the section.
            if sym.estimated_size is None:
                sym.estimated_size = (
                    self.recomp_bin.get_section_extent_by_index(sym.section)
                    - sym.offset
                )

            if sym.node_type == SymbolType.STRING:
                string_info = demangle_string_const(sym.decorated_name)
                if string_info is None:
                    logger.debug(
                        "Could not demangle string symbol: %s", sym.decorated_name
                    )
                    continue

                # TODO: skip unicode for now. will need to handle these differently.
                if string_info.is_utf16:
                    continue

                raw = self.recomp_bin.read(addr, sym.size())
                try:
                    sym.friendly_name = raw.decode("latin1").rstrip("\x00")
                except UnicodeDecodeError:
                    pass

            self._db.set_recomp_symbol(addr, sym.node_type, sym.name(), sym.size())

        for lineref in cv.lines:
            addr = self.recomp_bin.get_abs_addr(lineref.section, lineref.offset)
            self._lines_db.add_line(lineref.filename, lineref.line_no, addr)

        # The _entry symbol is referenced in the PE header so we get this match for free.
        self._db.set_function_pair(self.orig_bin.entry, self.recomp_bin.entry)

    def _load_markers(self):
        # Guess at module name from PDB file name
        # reccmp checks the original binary filename; we could use this too
        (module, _) = os.path.splitext(os.path.basename(self.pdb_file))

        codefiles = list(walk_source_dir(self.code_dir))
        codebase = DecompCodebase(codefiles, module)

        # Match lineref functions first because this is a guaranteed match.
        # If we have two functions that share the same name, and one is
        # a lineref, we can match the nameref correctly because the lineref
        # was already removed from consideration.
        for fun in codebase.iter_line_functions():
            recomp_addr = self._lines_db.search_line(fun.filename, fun.line_number)
            if recomp_addr is not None:
                self._db.set_function_pair(fun.offset, recomp_addr)
                if fun.should_skip():
                    self._db.skip_compare(fun.offset)

        for fun in codebase.iter_name_functions():
            self._db.match_function(fun.offset, fun.name)
            if fun.should_skip():
                self._db.skip_compare(fun.offset)

        for var in codebase.iter_variables():
            self._db.match_variable(var.offset, var.name)

        for tbl in codebase.iter_vtables():
            self._db.match_vtable(tbl.offset, tbl.name)

        for string in codebase.iter_strings():
            # Not that we don't trust you, but we're checking the string
            # annotation to make sure it is accurate.
            try:
                # TODO: would presumably fail for wchar_t strings
                orig = self.orig_bin.read_string(string.offset).decode("latin1")
                string_correct = string.name == orig
            except UnicodeDecodeError:
                string_correct = False

            if not string_correct:
                logger.error(
                    "Data at 0x%x does not match string %s",
                    string.offset,
                    repr(string.name),
                )
                continue

            self._db.match_string(string.offset, string.name)

    def _find_original_strings(self):
        """Go to the original binary and look for the specified string constants
        to find a match. This is a (relatively) expensive operation so we only
        look at strings that we have not already matched via a STRING annotation."""

        for string in self._db.get_unmatched_strings():
            addr = self.orig_bin.find_string(string.encode("latin1"))
            if addr is None:
                escaped = repr(string)
                logger.debug("Failed to find this string in the original: %s", escaped)
                continue

            self._db.match_string(addr, string)

    def _match_thunks(self):
        orig_byaddr = {
            addr: (dll.upper(), name) for (dll, name, addr) in self.orig_bin.imports
        }
        recomp_byname = {
            (dll.upper(), name): addr for (dll, name, addr) in self.recomp_bin.imports
        }
        # Combine these two dictionaries. We don't care about imports from recomp
        # not found in orig because:
        # 1. They shouldn't be there
        # 2. They are already identified via cvdump
        orig_to_recomp = {
            addr: recomp_byname.get(pair, None) for addr, pair in orig_byaddr.items()
        }

        # Now: we have the IAT offset in each matched up, so we need to make
        # the connection between the thunk functions.
        # We already have the symbol name we need from the PDB.
        orig_thunks = {
            iat_ofs: func_ofs for (func_ofs, iat_ofs) in self.orig_bin.thunks
        }
        recomp_thunks = {
            iat_ofs: func_ofs for (func_ofs, iat_ofs) in self.recomp_bin.thunks
        }

        for orig, recomp in orig_to_recomp.items():
            self._db.set_pair(orig, recomp, SymbolType.POINTER)
            thunk_from_orig = orig_thunks.get(orig, None)
            thunk_from_recomp = recomp_thunks.get(recomp, None)

            if thunk_from_orig is not None and thunk_from_recomp is not None:
                self._db.set_function_pair(thunk_from_orig, thunk_from_recomp)
                # Don't compare thunk functions for now. The comparison isn't
                # "useful" in the usual sense. We are only looking at the 6
                # bytes of the jmp instruction and not the larger context of
                # where this function is. Also: these will always match 100%
                # because we are searching for a match to register this as a
                # function in the first place.
                self._db.skip_compare(thunk_from_orig)

    def _compare_function(self, match: MatchInfo) -> DiffReport:
        if match.size == 0:
            # Report a failed match to make the user aware of the empty function.
            return DiffReport(
                match_type=SymbolType.FUNCTION,
                orig_addr=match.orig_addr,
                recomp_addr=match.recomp_addr,
                name=match.name,
            )

        orig_raw = self.orig_bin.read(match.orig_addr, match.size)
        recomp_raw = self.recomp_bin.read(match.recomp_addr, match.size)

        def orig_lookup(addr: int) -> Optional[str]:
            m = self._db.get_by_orig(addr)
            if m is None:
                return None

            return m.match_name()

        def recomp_lookup(addr: int) -> Optional[str]:
            m = self._db.get_by_recomp(addr)
            if m is None:
                return None

            return m.match_name()

        orig_should_replace = create_reloc_lookup(self.orig_bin)
        recomp_should_replace = create_reloc_lookup(self.recomp_bin)

        orig_float = create_float_lookup(self.orig_bin)
        recomp_float = create_float_lookup(self.recomp_bin)

        orig_parse = ParseAsm(
            relocate_lookup=orig_should_replace,
            name_lookup=orig_lookup,
            float_lookup=orig_float,
        )
        recomp_parse = ParseAsm(
            relocate_lookup=recomp_should_replace,
            name_lookup=recomp_lookup,
            float_lookup=recomp_float,
        )

        orig_asm = orig_parse.parse_asm(orig_raw, match.orig_addr)
        recomp_asm = recomp_parse.parse_asm(recomp_raw, match.recomp_addr)

        diff = difflib.SequenceMatcher(None, orig_asm, recomp_asm)
        ratio = diff.ratio()

        if ratio != 1.0:
            # Check whether we can resolve register swaps which are actually
            # perfect matches modulo compiler entropy.
            is_effective_match = can_resolve_register_differences(orig_asm, recomp_asm)
            unified_diff = difflib.unified_diff(orig_asm, recomp_asm, n=10)
        else:
            is_effective_match = False
            unified_diff = []

        return DiffReport(
            match_type=SymbolType.FUNCTION,
            orig_addr=match.orig_addr,
            recomp_addr=match.recomp_addr,
            name=match.name,
            udiff=unified_diff,
            ratio=ratio,
            is_effective_match=is_effective_match,
        )

    def _compare_vtable(self, match: MatchInfo) -> DiffReport:
        vtable_size = match.size

        # The vtable size should always be a multiple of 4 because that
        # is the pointer size. If it is not (for whatever reason)
        # it would cause iter_unpack to blow up so let's just fix it.
        if vtable_size % 4 != 0:
            logger.warning(
                "Vtable for class %s has irregular size %d", match.name, vtable_size
            )
            vtable_size = 4 * (vtable_size // 4)

        orig_table = self.orig_bin.read(match.orig_addr, vtable_size)
        recomp_table = self.recomp_bin.read(match.recomp_addr, vtable_size)

        raw_addrs = zip(
            [t for (t,) in struct.iter_unpack("<L", orig_table)],
            [t for (t,) in struct.iter_unpack("<L", recomp_table)],
        )

        def match_text(
            i: int, m: Optional[MatchInfo], raw_addr: Optional[int] = None
        ) -> str:
            """Format the function reference at this vtable index as text.
            If we have not identified this function, we have the option to
            display the raw address. This is only worth doing for the original addr
            because we should always be able to identify the recomp function.
            If the original function is missing then this probably means that the class
            should override the given function from the superclass, but we have not
            implemented this yet.
            """
            index = f"vtable0x{i*4:02x}"

            if m is not None:
                orig = hex(m.orig_addr) if m.orig_addr is not None else "no orig"
                recomp = (
                    hex(m.recomp_addr) if m.recomp_addr is not None else "no recomp"
                )
                return f"{index:>12}  :  ({orig:10} / {recomp:10})  :  {m.name}"

            if raw_addr is not None:
                return f"{index:>12}  :  0x{raw_addr:x} from orig not annotated."

            return f"{index:>12}  :  (no match)"

        orig_text = []
        recomp_text = []
        ratio = 0
        n_entries = 0

        # Now compare each pointer from the two vtables.
        for i, (raw_orig, raw_recomp) in enumerate(raw_addrs):
            orig = self._db.get_by_orig(raw_orig)
            recomp = self._db.get_by_recomp(raw_recomp)

            if (
                orig is not None
                and recomp is not None
                and orig.recomp_addr == recomp.recomp_addr
            ):
                ratio += 1

            n_entries += 1
            orig_text.append(match_text(i, orig, raw_orig))
            recomp_text.append(match_text(i, recomp))

        ratio = ratio / float(n_entries) if n_entries > 0 else 0

        # n=100: Show the entire table if there is a diff to display.
        # Otherwise it would be confusing if the table got cut off.
        unified_diff = difflib.unified_diff(orig_text, recomp_text, n=100)

        return DiffReport(
            match_type=SymbolType.VTABLE,
            orig_addr=match.orig_addr,
            recomp_addr=match.recomp_addr,
            name=f"{match.name}::`vftable'",
            udiff=unified_diff,
            ratio=ratio,
        )

    def _compare_match(self, match: MatchInfo) -> Optional[DiffReport]:
        """Router for comparison type"""
        if match.compare_type == SymbolType.FUNCTION:
            return self._compare_function(match)

        if match.compare_type == SymbolType.VTABLE:
            return self._compare_vtable(match)

        return None

    ## Public API

    def get_functions(self) -> List[MatchInfo]:
        return self._db.get_matches_by_type(SymbolType.FUNCTION)

    def get_vtables(self) -> List[MatchInfo]:
        return self._db.get_matches_by_type(SymbolType.VTABLE)

    def compare_address(self, addr: int) -> Optional[DiffReport]:
        match = self._db.get_one_match(addr)
        if match is None:
            return None

        return self._compare_match(match)

    def compare_all(self) -> Iterable[DiffReport]:
        for match in self._db.get_matches():
            diff = self._compare_match(match)
            if diff is not None:
                yield diff

    def compare_functions(self) -> Iterable[DiffReport]:
        for match in self.get_functions():
            yield self._compare_match(match)

    def compare_variables(self):
        pass

    def compare_pointers(self):
        pass

    def compare_strings(self):
        pass

    def compare_vtables(self) -> Iterable[DiffReport]:
        for match in self.get_vtables():
            yield self._compare_match(match)
