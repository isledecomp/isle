import os
import logging
from typing import List, Optional
from isledecomp.cvdump.demangler import demangle_string_const
from isledecomp.cvdump import Cvdump, CvdumpAnalysis
from isledecomp.parser import DecompCodebase
from isledecomp.dir import walk_source_dir
from isledecomp.types import SymbolType
from .db import CompareDb, MatchInfo
from .lines import LinesDb


logger = logging.getLogger(__name__)


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

    def get_one_function(self, addr: int) -> Optional[MatchInfo]:
        """i.e. verbose mode for reccmp"""
        return self._db.get_one_function(addr)

    def get_functions(self) -> List[MatchInfo]:
        return self._db.get_matches(SymbolType.FUNCTION)

    def compare_functions(self):
        pass

    def compare_variables(self):
        pass

    def compare_pointers(self):
        pass

    def compare_strings(self):
        pass

    def compare_vtables(self):
        pass
