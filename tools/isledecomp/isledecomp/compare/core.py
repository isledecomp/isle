import os
import logging
import difflib
from dataclasses import dataclass
from typing import Iterable, List, Optional
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


class Compare:
    # pylint: disable=too-many-instance-attributes
    def __init__(self, orig_bin, recomp_bin, pdb_file, code_dir):
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
                # TODO: skip unicode for now. will need to handle these differently.
                if string_info.is_utf16:
                    continue

                raw = self.recomp_bin.read(addr, sym.size())
                try:
                    sym.friendly_name = raw.decode("latin1")
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

    def get_one_function(self, addr: int) -> Optional[MatchInfo]:
        """i.e. verbose mode for reccmp"""
        return self._db.get_one_function(addr)

    def get_functions(self) -> List[MatchInfo]:
        return self._db.get_matches(SymbolType.FUNCTION)

    def _compare_function(self, match: MatchInfo) -> DiffReport:
        if match.size == 0:
            # Report a failed match to make the user aware of the empty function.
            return DiffReport(
                orig_addr=match.orig_addr,
                recomp_addr=match.recomp_addr,
                name=match.name,
            )

        orig_raw = self.orig_bin.read(match.orig_addr, match.size)
        recomp_raw = self.recomp_bin.read(match.recomp_addr, match.size)

        def orig_should_replace(addr: int) -> bool:
            return addr > self.orig_bin.imagebase and self.orig_bin.is_relocated_addr(
                addr
            )

        def recomp_should_replace(addr: int) -> bool:
            return (
                addr > self.recomp_bin.imagebase
                and self.recomp_bin.is_relocated_addr(addr)
            )

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

        orig_parse = ParseAsm(
            relocate_lookup=orig_should_replace, name_lookup=orig_lookup
        )
        recomp_parse = ParseAsm(
            relocate_lookup=recomp_should_replace, name_lookup=recomp_lookup
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
            orig_addr=match.orig_addr,
            recomp_addr=match.recomp_addr,
            name=match.name,
            udiff=unified_diff,
            ratio=ratio,
            is_effective_match=is_effective_match,
        )

    def compare_function(self, addr: int) -> Optional[DiffReport]:
        match = self.get_one_function(addr)
        if match is None:
            return None

        return self._compare_function(match)

    def compare_functions(self) -> Iterable[DiffReport]:
        for match in self.get_functions():
            yield self._compare_function(match)

    def compare_variables(self):
        pass

    def compare_pointers(self):
        pass

    def compare_strings(self):
        pass

    def compare_vtables(self):
        pass
