"""For all addresses matched by code annotations or recomp pdb,
report how "far off" the recomp symbol is from its proper place
in the original binary."""

import os
import argparse
import logging
from typing import List, Optional
from collections import namedtuple
from isledecomp import Bin as IsleBin
from isledecomp.cvdump import Cvdump
from isledecomp.compare import Compare as IsleCompare
from isledecomp.types import SymbolType

# Ignore all compare-db messages.
logging.getLogger("isledecomp.compare").addHandler(logging.NullHandler())


def or_blank(value) -> str:
    """Helper for dealing with potential None values in text output."""
    return "" if value is None else str(value)


class ModuleMap:
    """Load a subset of sections from the pdb to allow you to look up the
    module number based on the recomp address."""

    def __init__(self, pdb, binfile) -> None:
        cvdump = Cvdump(pdb).section_contributions().modules().run()
        self.module_lookup = {m.id: (m.lib, m.obj) for m in cvdump.modules}
        self.section_contrib = [
            (
                binfile.get_abs_addr(sizeref.section, sizeref.offset),
                sizeref.size,
                sizeref.module,
            )
            for sizeref in cvdump.sizerefs
            if binfile.is_valid_section(sizeref.section)
        ]

    def get_all_cmake_modules(self) -> List[str]:
        return [
            obj
            for (_, (__, obj)) in self.module_lookup.items()
            if obj.startswith("CMakeFiles")
        ]

    def get_module(self, addr: int) -> Optional[str]:
        for start, size, module_id in self.section_contrib:
            if start <= addr < start + size:
                if (module := self.module_lookup.get(module_id)) is not None:
                    return module

        return None


def print_sections(sections):
    print("    name |    start |   v.size | raw size")
    print("---------|----------|----------|----------")
    for sect in sections:
        name = sect.name.decode("ascii").rstrip("\x00")
        print(
            f"{name:>8} | {sect.virtual_address:8x} | {sect.virtual_size:8x} | {sect.size_of_raw_data:8x}"
        )
    print()


ALLOWED_TYPE_ABBREVIATIONS = ["fun", "dat", "poi", "str", "vta"]


def match_type_abbreviation(mtype: Optional[SymbolType]) -> str:
    """Return abbreviation of the given SymbolType name"""
    if mtype is None:
        return ""

    return mtype.name.lower()[:3]


def truncate_module_name(prefix: str, module: str) -> str:
    """Remove the CMakeFiles prefix and the .obj suffix for the given module.
    Input: CMakeFiles/lego1.dir/, CMakeFiles/lego1.dir/LEGO1/define.cpp.obj
    Output: LEGO1/define.cpp"""

    if module.startswith(prefix):
        module = module[len(prefix) :]

    if module.endswith(".obj"):
        module = module[:-4]

    return module


RoadmapRow = namedtuple(
    "RoadmapRow",
    [
        "orig_sect_ofs",
        "recomp_sect_ofs",
        "orig_addr",
        "recomp_addr",
        "displacement",
        "sym_type",
        "size",
        "name",
        "module",
    ],
)


class DeltaCollector:
    """Reads each row of the results and aggregates information about the
    placement of each module."""

    def __init__(self, match_type: str = "fun"):
        self.disp_map = {}
        self.earliest = {}
        self.seen = set()
        self.match_type = "fun"

        match_type = str(match_type).strip().lower()[:3]
        if match_type in ALLOWED_TYPE_ABBREVIATIONS:
            self.match_type = match_type

    def read_row(self, row: RoadmapRow):
        if row.module is None:
            return

        self.seen.add(row.module)
        if row.sym_type != self.match_type:
            return

        if row.orig_addr is not None:
            if row.orig_addr < self.earliest.get(row.module, 0xFFFFFFFFF):
                self.earliest[row.module] = row.orig_addr

        if row.displacement is not None:
            if row.module not in self.disp_map:
                self.disp_map[row.module] = []

            self.disp_map[row.module].append(row.displacement)


def suggest_order(results: List[RoadmapRow], cmake_modules: List[str], match_type: str):
    """Suggest the order of modules for CMakeLists.txt"""

    dc = DeltaCollector(match_type)
    for row in results:
        dc.read_row(row)

    leftover_modules = set(cmake_modules)

    # A little convoluted, but we want to take the first two tokens
    # of the string with '/' as the delimiter.
    # i.e. CMakeFiles/isle.dir/
    # The idea is to print exactly what appears in CMakeLists.txt.
    cmake_prefixes = sorted(
        set("/".join(mod.split("/", 2)[:2]) + "/" for mod in leftover_modules)
    )

    # These may already be sorted by earliest, but make sure
    first_function = [(earliest, module) for (module, earliest) in dc.earliest.items()]
    first_function.sort()

    for prefix in cmake_prefixes:
        print(prefix)
        # Show modules ordered by the first appearance of whichever symbol type.
        for start, module in first_function:
            if not module.startswith(prefix):
                continue

            leftover_modules.remove(module)

            avg_displacement = None
            displacements = dc.disp_map.get(module)
            if displacements is not None and len(displacements) > 0:
                avg_displacement = int(sum(displacements) / len(displacements))

            code_file = truncate_module_name(prefix, module)
            print(f"0x{start:08x}  {or_blank(avg_displacement):10}  {code_file}")

        # These modules are included in the final binary (in some form) but
        # they are not represented by whichever type of symbol we were checking.
        # n.b. There could still be other modules that are part of CMakeLists.txt
        # but are not included in the pdb for whatever reason.
        # In other words: don't take the list we provide as the final word on what
        # should or should not be included. This is merely a suggestion of the order.
        for module in leftover_modules:
            if not module.startswith(prefix):
                continue

            # aligned with previous print
            code_file = truncate_module_name(prefix, module)
            print(f"      no suggestion     {code_file}")

        print()


def print_text_report(results: List[RoadmapRow]):
    """Print the result with original and recomp addresses."""
    for row in results:
        print(
            "  ".join(
                [
                    f"{or_blank(row.orig_sect_ofs):14}",
                    f"{or_blank(row.recomp_sect_ofs):14}",
                    f"{or_blank(row.displacement):>8}",
                    f"{row.sym_type:3}",
                    f"{or_blank(row.size):6}",
                    or_blank(row.name),
                ]
            )
        )


def print_diff_report(results: List[RoadmapRow]):
    """Print only entries where we have the recomp address.
    This is intended for generating a file to diff against.
    The recomp addresses are always changing so we hide those."""
    for row in results:
        if row.orig_addr is None or row.recomp_addr is None:
            continue

        print(
            "  ".join(
                [
                    f"{or_blank(row.orig_sect_ofs):14}",
                    f"{or_blank(row.displacement):>8}",
                    f"{row.sym_type:3}",
                    f"{or_blank(row.size):6}",
                    or_blank(row.name),
                ]
            )
        )


def export_to_csv(csv_file: str, results: List[RoadmapRow]):
    with open(csv_file, "w+", encoding="utf-8") as f:
        f.write(
            "orig_sect_ofs,recomp_sect_ofs,orig_addr,recomp_addr,displacement,row_type,size,name,module\n"
        )
        for row in results:
            f.write(",".join(map(or_blank, row)))
            f.write("\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Show all addresses from original and recomp."
    )
    parser.add_argument(
        "original", metavar="original-binary", help="The original binary"
    )
    parser.add_argument(
        "recompiled", metavar="recompiled-binary", help="The recompiled binary"
    )
    parser.add_argument(
        "pdb", metavar="recompiled-pdb", help="The PDB of the recompiled binary"
    )
    parser.add_argument(
        "decomp_dir", metavar="decomp-dir", help="The decompiled source tree"
    )
    parser.add_argument("--csv", metavar="<file>", help="If set, export to CSV")
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show recomp addresses in output"
    )
    parser.add_argument(
        "--order",
        const="fun",
        nargs="?",
        type=str,
        help="Show suggested order of modules (using the specified symbol type)",
    )

    (args, _) = parser.parse_known_args()

    if not os.path.isfile(args.original):
        parser.error(f"Original binary {args.original} does not exist")

    if not os.path.isfile(args.recompiled):
        parser.error(f"Recompiled binary {args.recompiled} does not exist")

    if not os.path.isfile(args.pdb):
        parser.error(f"Symbols PDB {args.pdb} does not exist")

    if not os.path.isdir(args.decomp_dir):
        parser.error(f"Source directory {args.decomp_dir} does not exist")

    return args


def main():
    args = parse_args()

    with IsleBin(args.original, find_str=True) as orig_bin, IsleBin(
        args.recompiled
    ) as recomp_bin:
        engine = IsleCompare(orig_bin, recomp_bin, args.pdb, args.decomp_dir)

        module_map = ModuleMap(args.pdb, recomp_bin)

        def is_same_section(orig: int, recomp: int) -> bool:
            """Compare the section name instead of the index.
            LEGO1.dll adds extra sections for some reason. (Smacker library?)"""

            try:
                orig_name = orig_bin.sections[orig - 1].name
                recomp_name = recomp_bin.sections[recomp - 1].name
                return orig_name == recomp_name
            except IndexError:
                return False

        def to_roadmap_row(match):
            orig_sect = None
            orig_ofs = None
            orig_sect_ofs = None
            recomp_sect = None
            recomp_ofs = None
            recomp_sect_ofs = None
            orig_addr = None
            recomp_addr = None
            displacement = None
            module_name = None

            if match.recomp_addr is not None:
                if (module_ref := module_map.get_module(match.recomp_addr)) is not None:
                    (_, module_name) = module_ref

            row_type = match_type_abbreviation(match.compare_type)
            name = (
                repr(match.name)
                if match.compare_type == SymbolType.STRING
                else match.name
            )

            if match.orig_addr is not None:
                orig_addr = match.orig_addr
                (orig_sect, orig_ofs) = orig_bin.get_relative_addr(match.orig_addr)
                orig_sect_ofs = f"{orig_sect:04}:{orig_ofs:08x}"

            if match.recomp_addr is not None:
                recomp_addr = match.recomp_addr
                (recomp_sect, recomp_ofs) = recomp_bin.get_relative_addr(
                    match.recomp_addr
                )
                recomp_sect_ofs = f"{recomp_sect:04}:{recomp_ofs:08x}"

            if (
                orig_sect is not None
                and recomp_sect is not None
                and is_same_section(orig_sect, recomp_sect)
            ):
                displacement = recomp_ofs - orig_ofs

            return RoadmapRow(
                orig_sect_ofs,
                recomp_sect_ofs,
                orig_addr,
                recomp_addr,
                displacement,
                row_type,
                match.size,
                name,
                module_name,
            )

        results = list(map(to_roadmap_row, engine.get_all()))

        if args.order is not None:
            suggest_order(results, module_map.get_all_cmake_modules(), args.order)
            return

        if args.csv is None:
            if args.verbose:
                print("ORIG sections:")
                print_sections(orig_bin.sections)

                print("RECOMP sections:")
                print_sections(recomp_bin.sections)

                print_text_report(results)
            else:
                print_diff_report(results)

        if args.csv is not None:
            export_to_csv(args.csv, results)


if __name__ == "__main__":
    main()
