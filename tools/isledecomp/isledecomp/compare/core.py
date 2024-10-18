import os
import logging
import difflib
import struct
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Iterable, List, Optional
from isledecomp.bin import Bin as IsleBin, InvalidVirtualAddressError
from isledecomp.cvdump.demangler import demangle_string_const
from isledecomp.cvdump import Cvdump, CvdumpAnalysis
from isledecomp.cvdump.types import scalar_type_pointer
from isledecomp.parser import DecompCodebase
from isledecomp.dir import walk_source_dir
from isledecomp.types import SymbolType
from isledecomp.compare.asm import ParseAsm
from isledecomp.compare.asm.fixes import assert_fixup, find_effective_match
from .db import CompareDb, MatchInfo
from .diff import combined_diff, CombinedDiffOutput
from .lines import LinesDb


logger = logging.getLogger(__name__)


@dataclass
class DiffReport:
    # pylint: disable=too-many-instance-attributes
    match_type: SymbolType
    orig_addr: int
    recomp_addr: int
    name: str
    udiff: Optional[CombinedDiffOutput] = None
    ratio: float = 0.0
    is_effective_match: bool = False
    is_stub: bool = False

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


def create_bin_lookup(bin_file: IsleBin) -> Callable[[int, int], Optional[str]]:
    """Function generator for reading from the bin file"""

    def lookup(addr: int, size: int) -> Optional[bytes]:
        try:
            return bin_file.read(addr, size)
        except InvalidVirtualAddressError:
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
        # Controls whether we dump the asm output to a file
        self.debug: bool = False
        self.runid: str = uuid.uuid4().hex[:8]

        self._lines_db = LinesDb(code_dir)
        self._db = CompareDb()

        self._load_cvdump()
        self._load_markers()
        # Detect floats first to eliminate potential overlap with string data
        self._find_float_const()
        self._find_original_strings()
        self._match_imports()
        self._match_exports()
        self._match_thunks()
        self._find_vtordisp()

    def _load_cvdump(self):
        logger.info("Parsing %s ...", self.pdb_file)
        self.cv = (
            Cvdump(self.pdb_file)
            .lines()
            .globals()
            .publics()
            .symbols()
            .section_contributions()
            .types()
            .run()
        )
        self.cvdump_analysis = CvdumpAnalysis(self.cv)

        for sym in self.cvdump_analysis.nodes:
            # Skip nodes where we have almost no information.
            # These probably came from SECTION CONTRIBUTIONS.
            if sym.name() is None and sym.node_type is None:
                continue

            # The PDB might contain sections that do not line up with the
            # actual binary. The symbol "__except_list" is one example.
            # In these cases, just skip this symbol and move on because
            # we can't do much with it.
            if not self.recomp_bin.is_valid_section(sym.section):
                continue

            addr = self.recomp_bin.get_abs_addr(sym.section, sym.offset)
            sym.addr = addr

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
                    # We use the string length reported in the mangled symbol as the
                    # data size, but this is not always accurate with respect to the
                    # null terminator.
                    # e.g. ??_C@_0BA@EFDM@MxObjectFactory?$AA@
                    # reported length: 16 (includes null terminator)
                    # c.f. ??_C@_03DPKJ@enz?$AA@
                    # reported length: 3 (does NOT include terminator)
                    # This will handle the case where the entire string contains "\x00"
                    # because those are distinct from the empty string of length 0.
                    decoded_string = raw.decode("latin1")
                    rstrip_string = decoded_string.rstrip("\x00")

                    if decoded_string != "" and rstrip_string != "":
                        sym.friendly_name = rstrip_string
                    else:
                        sym.friendly_name = decoded_string

                except UnicodeDecodeError:
                    pass

            self._db.set_recomp_symbol(
                addr, sym.node_type, sym.name(), sym.decorated_name, sym.size()
            )

        for (section, offset), (
            filename,
            line_no,
        ) in self.cvdump_analysis.verified_lines.items():
            addr = self.recomp_bin.get_abs_addr(section, offset)
            self._lines_db.add_line(filename, line_no, addr)

        # The _entry symbol is referenced in the PE header so we get this match for free.
        self._db.set_function_pair(self.orig_bin.entry, self.recomp_bin.entry)

    def _load_markers(self):
        # Assume module name is the base filename of the original binary.
        (module, _) = os.path.splitext(os.path.basename(self.orig_bin.filename))

        codefiles = list(walk_source_dir(self.code_dir))
        codebase = DecompCodebase(codefiles, module.upper())

        def orig_bin_checker(addr: int) -> bool:
            return self.orig_bin.is_valid_vaddr(addr)

        # If the address of any annotation would cause an exception,
        # remove it and report an error.
        bad_annotations = codebase.prune_invalid_addrs(orig_bin_checker)

        for sym in bad_annotations:
            logger.error(
                "Invalid address 0x%x on %s annotation in file: %s",
                sym.offset,
                sym.type.name,
                sym.filename,
            )

        # Match lineref functions first because this is a guaranteed match.
        # If we have two functions that share the same name, and one is
        # a lineref, we can match the nameref correctly because the lineref
        # was already removed from consideration.
        for fun in codebase.iter_line_functions():
            recomp_addr = self._lines_db.search_line(fun.filename, fun.line_number)
            if recomp_addr is not None:
                self._db.set_function_pair(fun.offset, recomp_addr)
                if fun.should_skip():
                    self._db.mark_stub(fun.offset)

        for fun in codebase.iter_name_functions():
            self._db.match_function(fun.offset, fun.name)
            if fun.should_skip():
                self._db.mark_stub(fun.offset)

        for var in codebase.iter_variables():
            if var.is_static and var.parent_function is not None:
                self._db.match_static_variable(
                    var.offset, var.name, var.parent_function
                )
            else:
                if self._db.match_variable(var.offset, var.name):
                    self._check_if_array_and_match_elements(var.offset, var.name)

        for tbl in codebase.iter_vtables():
            self._db.match_vtable(tbl.offset, tbl.name, tbl.base_class)

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

    def _check_if_array_and_match_elements(self, orig_addr: int, name: str):
        """
        Checks if the global variable at `orig_addr` is an array.
        If yes, adds a match for all its elements. If it is an array of structs, all fields in that struct are also matched.
        Note that there is no recursion, so an array of arrays would not be handled entirely.
        This step is necessary e.g. for `0x100f0a20` (LegoRacers.cpp).
        """

        def _add_match_in_array(
            name: str, type_id: str, orig_addr: int, recomp_addr: int
        ):
            self._db.set_recomp_symbol(
                recomp_addr,
                SymbolType.POINTER if scalar_type_pointer(type_id) else SymbolType.DATA,
                name,
                name,
                # we only need the matches when they are referenced elsewhere, hence we don't need the size
                size=None,
            )
            self._db.set_pair(orig_addr, recomp_addr)

        matchinfo = self._db.get_by_orig(orig_addr)
        if matchinfo is None or matchinfo.recomp_addr is None:
            return
        recomp_addr = matchinfo.recomp_addr

        node = next(
            (x for x in self.cvdump_analysis.nodes if x.addr == recomp_addr),
            None,
        )
        if node is None or node.data_type is None:
            return

        if not node.data_type.key.startswith("0x"):
            # scalar type, so clearly not an array
            return

        data_type = self.cv.types.keys[node.data_type.key.lower()]

        if data_type["type"] == "LF_ARRAY":
            array_element_type = self.cv.types.get(data_type["array_type"])

            assert node.data_type.members is not None

            for array_element in node.data_type.members:
                orig_element_base_addr = orig_addr + array_element.offset
                recomp_element_base_addr = recomp_addr + array_element.offset
                if array_element_type.members is None:
                    _add_match_in_array(
                        f"{name}{array_element.name}",
                        array_element_type.key,
                        orig_element_base_addr,
                        recomp_element_base_addr,
                    )
                else:
                    for member in array_element_type.members:
                        _add_match_in_array(
                            f"{name}{array_element.name}.{member.name}",
                            array_element_type.key,
                            orig_element_base_addr + member.offset,
                            recomp_element_base_addr + member.offset,
                        )

    def _find_original_strings(self):
        """Go to the original binary and look for the specified string constants
        to find a match. This is a (relatively) expensive operation so we only
        look at strings that we have not already matched via a STRING annotation."""
        # Release builds give each de-duped string a symbol so they are easy to find and match.
        for string in self._db.get_unmatched_strings():
            addr = self.orig_bin.find_string(string.encode("latin1"))
            if addr is None:
                escaped = repr(string)
                logger.debug("Failed to find this string in the original: %s", escaped)
                continue

            self._db.match_string(addr, string)

        def is_real_string(s: str) -> bool:
            """Heuristic to ignore values that only look like strings.
            This is mostly about short strings (len <= 4) that could be byte or word values.
            """
            # 0x10 is the MSB of the address space for DLLs (LEGO1), so this is a pointer
            if len(s) == 0 or "\x10" in s:
                return False

            # assert(0) is common
            if len(s) == 1 and s[0] != "0":
                return False

            # Hack because str.isprintable() will fail on strings with newlines or tabs
            if len(s) <= 4 and "\\x" in repr(s):
                return False

            return True

        # Debug builds do not de-dupe the strings, so we need to find them via brute force scan.
        # We could try to match the string addrs if there is only one in orig and recomp.
        # When we sanitize the asm, the result is the same regardless.
        if self.orig_bin.is_debug:
            for addr, string in self.orig_bin.iter_string("latin1"):
                if is_real_string(string):
                    self._db.set_orig_symbol(
                        addr, SymbolType.STRING, string, len(string)
                    )

            for addr, string in self.recomp_bin.iter_string("latin1"):
                if is_real_string(string):
                    self._db.set_recomp_symbol(
                        addr, SymbolType.STRING, string, None, len(string)
                    )

    def _find_float_const(self):
        """Add floating point constants in each binary to the database.
        We are not matching anything right now because these values are not
        deduped like strings."""
        for addr, size, float_value in self.orig_bin.find_float_consts():
            self._db.set_orig_symbol(addr, SymbolType.FLOAT, str(float_value), size)

        for addr, size, float_value in self.recomp_bin.find_float_consts():
            self._db.set_recomp_symbol(
                addr, SymbolType.FLOAT, str(float_value), None, size
            )

    def _match_imports(self):
        """We can match imported functions based on the DLL name and
        function symbol name."""
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
        for orig, recomp in orig_to_recomp.items():
            if orig is None or recomp is None:
                continue

            # Match the __imp__ symbol
            self._db.set_pair(orig, recomp, SymbolType.POINTER)

            # Read the relative address from .idata
            try:
                (recomp_rva,) = struct.unpack("<L", self.recomp_bin.read(recomp, 4))
                (orig_rva,) = struct.unpack("<L", self.orig_bin.read(orig, 4))
            except ValueError:
                # Bail out if there's a problem with struct.unpack
                continue

            # Strictly speaking, this is a hack to support asm sanitize.
            # When calling an import, we will recognize that the address for the
            # CALL instruction is a pointer to the actual address, but this is
            # not only not the address of a function, it is not an address at all.
            # To make the asm display work correctly (i.e. to match what you see
            # in ghidra) create a function match on the RVA. This is not a valid
            # virtual address because it is before the imagebase, but it will
            # do what we need it to do in the sanitize function.

            (dll_name, func_name) = orig_byaddr[orig]
            fullname = dll_name + ":" + func_name
            self._db.set_recomp_symbol(
                recomp_rva, SymbolType.FUNCTION, fullname, None, 4
            )
            self._db.set_pair(orig_rva, recomp_rva, SymbolType.FUNCTION)
            self._db.skip_compare(orig_rva)

    def _match_thunks(self):
        """Thunks are (by nature) matched by indirection. If a thunk from orig
        points at a function we have already matched, we can find the matching
        thunk in recomp because it points to the same place."""

        # Mark all recomp thunks first. This allows us to use their name
        # when we sanitize the asm.
        for recomp_thunk, recomp_addr in self.recomp_bin.thunks:
            recomp_func = self._db.get_by_recomp(recomp_addr)
            if recomp_func is None:
                continue

            self._db.create_recomp_thunk(recomp_thunk, recomp_func.name)

        # Thunks may be non-unique, so use a list as dict value when
        # inverting the list of tuples from self.recomp_bin.
        recomp_thunks = {}
        for thunk_addr, func_addr in self.recomp_bin.thunks:
            recomp_thunks.setdefault(func_addr, []).append(thunk_addr)

        # Now match the thunks from orig where we can.
        for orig_thunk, orig_addr in self.orig_bin.thunks:
            orig_func = self._db.get_by_orig(orig_addr)
            if orig_func is None:
                continue

            # Check whether the thunk destination is a matched symbol
            if orig_func.recomp_addr not in recomp_thunks:
                self._db.create_orig_thunk(orig_thunk, orig_func.name)
                continue

            # If there are multiple thunks, they are already in v.addr order.
            # Pop the earliest one and match it.
            recomp_thunk = recomp_thunks[orig_func.recomp_addr].pop(0)
            if len(recomp_thunks[orig_func.recomp_addr]) == 0:
                del recomp_thunks[orig_func.recomp_addr]

            self._db.set_function_pair(orig_thunk, recomp_thunk)

            # Don't compare thunk functions for now. The comparison isn't
            # "useful" in the usual sense. We are only looking at the
            # bytes of the jmp instruction and not the larger context of
            # where this function is. Also: these will always match 100%
            # because we are searching for a match to register this as a
            # function in the first place.
            self._db.skip_compare(orig_thunk)

    def _match_exports(self):
        # invert for name lookup
        orig_exports = {y: x for (x, y) in self.orig_bin.exports}

        for recomp_addr, export_name in self.recomp_bin.exports:
            orig_addr = orig_exports.get(export_name)
            if orig_addr is None:
                continue

            try:
                # Check whether either of the addresses is actually a thunk.
                # This is a quirk of the debug builds. Technically the export
                # *is* the thunk, but it's more helpful to mark the actual function.
                # It could be the case that only one side is a thunk, but we can
                # deal with that.
                (opcode, rel_addr) = struct.unpack(
                    "<Bl", self.recomp_bin.read(recomp_addr, 5)
                )
                if opcode == 0xE9:
                    recomp_addr += 5 + rel_addr

                (opcode, rel_addr) = struct.unpack(
                    "<Bl", self.orig_bin.read(orig_addr, 5)
                )
                if opcode == 0xE9:
                    orig_addr += 5 + rel_addr
            except ValueError:
                # Bail out if there's a problem with struct.unpack
                continue

            if self._db.set_pair_tentative(orig_addr, recomp_addr):
                logger.debug("Matched export %s", repr(export_name))

    def _find_vtordisp(self):
        """If there are any cases of virtual inheritance, we can read
        through the vtables for those classes and find the vtable thunk
        functions (vtordisp).

        Our approach is this: walk both vtables and check where we have a
        vtordisp in the recomp table. Inspect the function at that vtable
        position (in both) and check whether we jump to the same function.

        One potential pitfall here is that the virtual displacement could
        differ between the thunks. We are not (yet) checking for this, so the
        result is that the vtable will appear to match but we will have a diff
        on the thunk in our regular function comparison.

        We could do this differently and check only the original vtable,
        construct the name of the vtordisp function and match based on that."""

        for match in self._db.get_matches_by_type(SymbolType.VTABLE):
            assert (
                match.name is not None
                and match.orig_addr is not None
                and match.recomp_addr is not None
                and match.size is not None
            )
            # We need some method of identifying vtables that
            # might have thunks, and this ought to work okay.
            if "{for" not in match.name:
                continue

            next_orig = self._db.get_next_orig_addr(match.orig_addr)
            assert next_orig is not None
            orig_upper_size_limit = next_orig - match.orig_addr
            if orig_upper_size_limit < match.size:
                # This could happen in debug builds due to code changes between BETA10 and LEGO1,
                # but we have not seen it yet as of 2024-08-28.
                logger.warning(
                    "Recomp vtable is larger than orig vtable for %s",
                    match.name,
                )

            # TODO: We might want to fix this at the source (cvdump) instead.
            # Any problem will be logged later when we compare the vtable.
            vtable_size = 4 * (min(match.size, orig_upper_size_limit) // 4)
            orig_table = self.orig_bin.read(match.orig_addr, vtable_size)
            recomp_table = self.recomp_bin.read(match.recomp_addr, vtable_size)

            raw_addrs = zip(
                [t for (t,) in struct.iter_unpack("<L", orig_table)],
                [t for (t,) in struct.iter_unpack("<L", recomp_table)],
            )

            # Now walk both vtables looking for thunks.
            for orig_addr, recomp_addr in raw_addrs:
                if orig_addr == 0:
                    # This happens in debug builds due to code changes between BETA10 and LEGO1.
                    # Note that there is a risk of running into the next vtable if there is no gap in between,
                    # which we cannot protect against at the moment.
                    logger.warning(
                        "Recomp vtable is larger than orig vtable for %s", match.name
                    )
                    break

                if self._db.is_vtordisp(recomp_addr):
                    self._match_vtordisp_in_vtable(orig_addr, recomp_addr)

    def _match_vtordisp_in_vtable(self, orig_addr, recomp_addr):
        thunk_fn = self.get_by_recomp(recomp_addr)
        assert thunk_fn is not None
        assert thunk_fn.size is not None

        # Read the function bytes here.
        # In practice, the adjuster thunk will be under 16 bytes.
        # If we have thunks of unequal size, we can still tell whether they are thunking
        # the same function by grabbing the JMP instruction at the end.
        thunk_presumed_size = max(thunk_fn.size, 16)

        # Strip off MSVC padding 0xcc bytes.
        # This should be safe to do; it is highly unlikely that
        # the MSB of the jump displacement would be 0xcc. (huge jump)
        orig_thunk_bin = self.orig_bin.read(orig_addr, thunk_presumed_size).rstrip(
            b"\xcc"
        )

        recomp_thunk_bin = self.recomp_bin.read(
            recomp_addr, thunk_presumed_size
        ).rstrip(b"\xcc")

        # Read jump opcode and displacement (last 5 bytes)
        (orig_jmp, orig_disp) = struct.unpack("<Bi", orig_thunk_bin[-5:])
        (recomp_jmp, recomp_disp) = struct.unpack("<Bi", recomp_thunk_bin[-5:])

        # Make sure it's a JMP
        if orig_jmp != 0xE9 or recomp_jmp != 0xE9:
            logger.warning(
                "Not a jump in vtordisp at (0x%x, 0x%x)", orig_addr, recomp_addr
            )
            return

        # Calculate jump destination from the end of the JMP instruction
        # i.e. the end of the function
        orig_actual = orig_addr + len(orig_thunk_bin) + orig_disp
        recomp_actual = recomp_addr + len(recomp_thunk_bin) + recomp_disp

        # If they are thunking the same function, then this must be a match.
        if self.is_pointer_match(orig_actual, recomp_actual):
            if len(orig_thunk_bin) != len(recomp_thunk_bin):
                logger.warning(
                    "Adjuster thunk %s (0x%x) is not exact",
                    thunk_fn.name,
                    orig_addr,
                )
            self._db.set_function_pair(orig_addr, recomp_addr)

    def _dump_asm(self, orig_combined, recomp_combined):
        """Append the provided assembly output to the debug files"""
        with open(f"orig-{self.runid}.txt", "a", encoding="utf-8") as f:
            for addr, line in orig_combined:
                f.write(f"{addr}: {line}\n")

        with open(f"recomp-{self.runid}.txt", "a", encoding="utf-8") as f:
            for addr, line in recomp_combined:
                f.write(f"{addr}: {line}\n")

    def _compare_function(self, match: MatchInfo) -> DiffReport:
        # Detect when the recomp function size would cause us to read
        # enough bytes from the original function that we cross into
        # the next annotated function.
        next_orig = self._db.get_next_orig_addr(match.orig_addr)
        if next_orig is not None:
            orig_size = min(next_orig - match.orig_addr, match.size)
        else:
            orig_size = match.size

        orig_raw = self.orig_bin.read(match.orig_addr, orig_size)
        recomp_raw = self.recomp_bin.read(match.recomp_addr, match.size)

        # It's unlikely that a function other than an adjuster thunk would
        # start with a SUB instruction, so alert to a possible wrong
        # annotation here.
        # There's probably a better place to do this, but we're reading
        # the function bytes here already.
        try:
            if orig_raw[0] == 0x2B and recomp_raw[0] != 0x2B:
                logger.warning(
                    "Possible thunk at 0x%x (%s)", match.orig_addr, match.name
                )
        except IndexError:
            pass

        def orig_lookup(addr: int, exact: bool) -> Optional[str]:
            m = self._db.get_by_orig(addr, exact)
            if m is None:
                return None

            if m.orig_addr == addr:
                return m.match_name()

            offset = addr - m.orig_addr
            if m.compare_type != SymbolType.DATA or offset >= m.size:
                return None

            return m.offset_name(offset)

        def recomp_lookup(addr: int, exact: bool) -> Optional[str]:
            m = self._db.get_by_recomp(addr, exact)
            if m is None:
                return None

            if m.recomp_addr == addr:
                return m.match_name()

            offset = addr - m.recomp_addr
            if m.compare_type != SymbolType.DATA or offset >= m.size:
                return None

            return m.offset_name(offset)

        orig_should_replace = create_reloc_lookup(self.orig_bin)
        recomp_should_replace = create_reloc_lookup(self.recomp_bin)

        orig_bin_lookup = create_bin_lookup(self.orig_bin)
        recomp_bin_lookup = create_bin_lookup(self.recomp_bin)

        orig_parse = ParseAsm(
            relocate_lookup=orig_should_replace,
            name_lookup=orig_lookup,
            bin_lookup=orig_bin_lookup,
        )
        recomp_parse = ParseAsm(
            relocate_lookup=recomp_should_replace,
            name_lookup=recomp_lookup,
            bin_lookup=recomp_bin_lookup,
        )

        orig_combined = orig_parse.parse_asm(orig_raw, match.orig_addr)
        recomp_combined = recomp_parse.parse_asm(recomp_raw, match.recomp_addr)

        if self.debug:
            self._dump_asm(orig_combined, recomp_combined)

        # Check for assert calls only if we expect to find them
        if self.orig_bin.is_debug or self.recomp_bin.is_debug:
            assert_fixup(orig_combined)
            assert_fixup(recomp_combined)

        # Detach addresses from asm lines for the text diff.
        orig_asm = [x[1] for x in orig_combined]
        recomp_asm = [x[1] for x in recomp_combined]

        diff = difflib.SequenceMatcher(None, orig_asm, recomp_asm, autojunk=False)
        ratio = diff.ratio()

        if ratio != 1.0:
            # Check whether we can resolve register swaps which are actually
            # perfect matches modulo compiler entropy.
            codes = diff.get_opcodes()
            is_effective_match = find_effective_match(codes, orig_asm, recomp_asm)
            unified_diff = combined_diff(
                diff, orig_combined, recomp_combined, context_size=10
            )
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

        def match_text(m: Optional[MatchInfo], raw_addr: Optional[int] = None) -> str:
            """Format the function reference at this vtable index as text.
            If we have not identified this function, we have the option to
            display the raw address. This is only worth doing for the original addr
            because we should always be able to identify the recomp function.
            If the original function is missing then this probably means that the class
            should override the given function from the superclass, but we have not
            implemented this yet.
            """

            if m is not None:
                orig = hex(m.orig_addr) if m.orig_addr is not None else "no orig"
                recomp = (
                    hex(m.recomp_addr) if m.recomp_addr is not None else "no recomp"
                )
                return f"({orig} / {recomp})  :  {m.name}"

            if raw_addr is not None:
                return f"0x{raw_addr:x} from orig not annotated."

            return "(no match)"

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
            index = f"vtable0x{i*4:02x}"
            orig_text.append((index, match_text(orig, raw_orig)))
            recomp_text.append((index, match_text(recomp)))

        ratio = ratio / float(n_entries) if n_entries > 0 else 0

        # n=100: Show the entire table if there is a diff to display.
        # Otherwise it would be confusing if the table got cut off.

        sm = difflib.SequenceMatcher(
            None,
            [x[1] for x in orig_text],
            [x[1] for x in recomp_text],
        )

        unified_diff = combined_diff(sm, orig_text, recomp_text, context_size=100)

        return DiffReport(
            match_type=SymbolType.VTABLE,
            orig_addr=match.orig_addr,
            recomp_addr=match.recomp_addr,
            name=match.name,
            udiff=unified_diff,
            ratio=ratio,
        )

    def _compare_match(self, match: MatchInfo) -> Optional[DiffReport]:
        """Router for comparison type"""

        if match.size is None or match.size == 0:
            return None

        options = self._db.get_match_options(match.orig_addr)
        if options.get("skip", False):
            return None

        if options.get("stub", False):
            return DiffReport(
                match_type=match.compare_type,
                orig_addr=match.orig_addr,
                recomp_addr=match.recomp_addr,
                name=match.name,
                is_stub=True,
            )

        if match.compare_type == SymbolType.FUNCTION:
            return self._compare_function(match)

        if match.compare_type == SymbolType.VTABLE:
            return self._compare_vtable(match)

        return None

    ## Public API

    def is_pointer_match(self, orig_addr, recomp_addr) -> bool:
        """Check whether these pointers point at the same thing"""

        # Null pointers considered matching
        if orig_addr == 0 and recomp_addr == 0:
            return True

        match = self._db.get_by_orig(orig_addr)
        if match is None:
            return False

        return match.recomp_addr == recomp_addr

    def get_by_orig(self, addr: int) -> Optional[MatchInfo]:
        return self._db.get_by_orig(addr)

    def get_by_recomp(self, addr: int) -> Optional[MatchInfo]:
        return self._db.get_by_recomp(addr)

    def get_all(self) -> List[MatchInfo]:
        return self._db.get_all()

    def get_functions(self) -> List[MatchInfo]:
        return self._db.get_matches_by_type(SymbolType.FUNCTION)

    def get_vtables(self) -> List[MatchInfo]:
        return self._db.get_matches_by_type(SymbolType.VTABLE)

    def get_variables(self) -> List[MatchInfo]:
        return self._db.get_matches_by_type(SymbolType.DATA)

    def get_match_options(self, addr: int) -> Optional[dict[str, Any]]:
        return self._db.get_match_options(addr)

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
            diff = self._compare_match(match)
            if diff is not None:
                yield diff

    def compare_variables(self):
        pass

    def compare_pointers(self):
        pass

    def compare_strings(self):
        pass

    def compare_vtables(self) -> Iterable[DiffReport]:
        for match in self.get_vtables():
            diff = self._compare_match(match)
            if diff is not None:
                yield self._compare_match(match)
