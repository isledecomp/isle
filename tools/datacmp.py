# (New) Data comparison.

import os
import argparse
import logging
from enum import Enum
from typing import Iterable, List, NamedTuple, Optional, Tuple
from struct import unpack
from isledecomp.compare import Compare as IsleCompare
from isledecomp.compare.db import MatchInfo
from isledecomp.cvdump import Cvdump
from isledecomp.cvdump.types import (
    CvdumpKeyError,
    CvdumpIntegrityError,
)
from isledecomp.bin import Bin as IsleBin
import colorama

colorama.init()


# Ignore all compare-db messages.
logging.getLogger("isledecomp.compare").addHandler(logging.NullHandler())


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Comparing data values.")
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
    parser.add_argument(
        "-v",
        "--verbose",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="",
    )
    parser.add_argument(
        "--no-color", "-n", action="store_true", help="Do not color the output"
    )
    parser.add_argument(
        "--print-rec-addr",
        action="store_true",
        help="Print addresses of recompiled functions too",
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


class CompareResult(Enum):
    MATCH = 1
    DIFF = 2
    ERROR = 3
    WARN = 4


class ComparedOffset(NamedTuple):
    offset: int
    # name is None for scalar types
    name: Optional[str]
    match: bool
    values: Tuple[str, str]


class ComparisonItem(NamedTuple):
    """Each variable that was compared"""

    orig_addr: int
    recomp_addr: int
    name: str

    # The list of items that were compared.
    # For a complex type, these are the members.
    # For a scalar type, this is a list of size one.
    # If we could not retrieve type information, this is
    # a list of size one but without any specific type.
    compared: List[ComparedOffset]

    # If present, the error message from the types parser.
    error: Optional[str] = None

    # If true, there is no type specified for this variable. (i.e. non-public)
    # In this case, we can only compare the raw bytes.
    # This is different from the situation where a type id _is_ given, but
    # we could not retrieve it for some reason. (This is an error.)
    raw_only: bool = False

    @property
    def result(self) -> CompareResult:
        if self.error is not None:
            return CompareResult.ERROR

        if all(c.match for c in self.compared):
            return CompareResult.MATCH

        # Prefer WARN for a diff without complete type information.
        return CompareResult.WARN if self.raw_only else CompareResult.DIFF


def create_comparison_item(
    var: MatchInfo,
    compared: Optional[List[ComparedOffset]] = None,
    error: Optional[str] = None,
    raw_only: bool = False,
) -> ComparisonItem:
    """Helper to create the ComparisonItem from the fields in MatchInfo."""
    if compared is None:
        compared = []

    return ComparisonItem(
        orig_addr=var.orig_addr,
        recomp_addr=var.recomp_addr,
        name=var.name,
        compared=compared,
        error=error,
        raw_only=raw_only,
    )


def do_the_comparison(args: argparse.Namespace) -> Iterable[ComparisonItem]:
    """Run through each variable in our compare DB, then do the comparison
    according to the variable's type. Emit the result."""
    with IsleBin(args.original, find_str=True) as origfile, IsleBin(
        args.recompiled
    ) as recompfile:
        isle_compare = IsleCompare(origfile, recompfile, args.pdb, args.decomp_dir)

        # TODO: We don't currently retain the type information of each variable
        # in our compare DB. To get those, we build this mini-lookup table that
        # maps recomp addresses to their type.
        # We still need to build the full compare DB though, because we may
        # need the matched symbols to compare pointers (e.g. on strings)
        mini_cvdump = Cvdump(args.pdb).globals().types().run()

        recomp_type_reference = {
            recompfile.get_abs_addr(g.section, g.offset): g.type
            for g in mini_cvdump.globals
            if recompfile.is_valid_section(g.section)
        }

        for var in isle_compare.get_variables():
            type_name = recomp_type_reference.get(var.recomp_addr)

            # Start by assuming we can only compare the raw bytes
            data_size = var.size
            is_type_aware = type_name is not None

            if is_type_aware:
                try:
                    # If we are type-aware, we can get the precise
                    # data size for the variable.
                    data_type = mini_cvdump.types.get(type_name)
                    data_size = data_type.size
                except (CvdumpKeyError, CvdumpIntegrityError) as ex:
                    yield create_comparison_item(var, error=repr(ex))
                    continue

            orig_raw = origfile.read(var.orig_addr, data_size)
            recomp_raw = recompfile.read(var.recomp_addr, data_size)

            # If either read exceeded the raw data size for the section,
            # assume the entire variable is uninitialized.
            # TODO: This is not correct, strictly speaking. However,
            # it is probably impossible for a variable to exceed
            # the virtual size of the section, so all that is left is
            # the uninitialized data.
            # If the variable falls at the end of the section like this,
            # it is highly likely to be uninitialized.
            if orig_raw is not None and len(orig_raw) < data_size:
                orig_raw = None

            if recomp_raw is not None and len(recomp_raw) < data_size:
                recomp_raw = None

            # If both variables are uninitialized, we consider them equal.
            # Otherwise, this is a diff but there is nothing to compare.
            if orig_raw is None or recomp_raw is None:
                match = orig_raw is None and recomp_raw is None
                orig_value = "(uninitialized)" if orig_raw is None else "(initialized)"
                recomp_value = (
                    "(uninitialized)" if recomp_raw is None else "(initialized)"
                )
                yield create_comparison_item(
                    var,
                    compared=[
                        ComparedOffset(
                            offset=0,
                            name=None,
                            match=match,
                            values=(orig_value, recomp_value),
                        )
                    ],
                )
                continue

            if not is_type_aware:
                # If there is no specific type information available
                # (i.e. if this is a static or non-public variable)
                # then we can only compare the raw bytes.
                yield create_comparison_item(
                    var,
                    compared=[
                        ComparedOffset(
                            offset=0,
                            name="(raw)",
                            match=orig_raw == recomp_raw,
                            values=(orig_raw, recomp_raw),
                        )
                    ],
                    raw_only=True,
                )
                continue

            # If we are here, we can do the type-aware comparison.
            compared = []
            compare_items = mini_cvdump.types.get_scalars(type_name)
            format_str = mini_cvdump.types.get_format_string(type_name)

            orig_data = unpack(format_str, orig_raw)
            recomp_data = unpack(format_str, recomp_raw)

            def pointer_display(addr: int, is_orig: bool) -> str:
                """Helper to streamline pointer textual display."""
                if addr == 0:
                    return "nullptr"

                ptr_match = (
                    isle_compare.get_by_orig(addr)
                    if is_orig
                    else isle_compare.get_by_recomp(addr)
                )

                if ptr_match is not None:
                    return f"Pointer to {ptr_match.match_name()}"

                # This variable did not match if we do not have
                # the pointer target in our DB.
                return f"Unknown pointer 0x{addr:x}"

            # Could zip here
            for i, member in enumerate(compare_items):
                if member.is_pointer:
                    match = isle_compare.is_pointer_match(orig_data[i], recomp_data[i])

                    value_a = pointer_display(orig_data[i], True)
                    value_b = pointer_display(recomp_data[i], False)

                    values = (value_a, value_b)
                else:
                    match = orig_data[i] == recomp_data[i]
                    values = (orig_data[i], recomp_data[i])

                compared.append(
                    ComparedOffset(
                        offset=member.offset,
                        name=member.name,
                        match=match,
                        values=values,
                    )
                )

            yield create_comparison_item(var, compared=compared)


def value_get(value: Optional[str], default: str):
    return value if value is not None else default


def main():
    args = parse_args()

    def display_match(result: CompareResult) -> str:
        """Helper to return color string or not, depending on user preference"""
        if args.no_color:
            return result.name

        match_color = (
            colorama.Fore.GREEN
            if result == CompareResult.MATCH
            else (
                colorama.Fore.YELLOW
                if result == CompareResult.WARN
                else colorama.Fore.RED
            )
        )
        return f"{match_color}{result.name}{colorama.Style.RESET_ALL}"

    for item in do_the_comparison(args):
        if not args.verbose and item.result == CompareResult.MATCH:
            continue

        address_display = (
            f"0x{item.orig_addr:x} / 0x{item.recomp_addr:x}"
            if args.print_rec_addr
            else f"0x{item.orig_addr:x}"
        )

        print(f"{item.name[:80]} ({address_display}) ... {display_match(item.result)} ")
        if item.error is not None:
            print(f"  {item.error}")

        for c in item.compared:
            if not args.verbose and c.match:
                continue

            (value_a, value_b) = c.values
            if c.match:
                print(f"  {c.offset:5} {value_get(c.name, '(value)'):30} {value_a}")
            else:
                print(
                    f"  {c.offset:5} {value_get(c.name, '(value)'):30} {value_a} : {value_b}"
                )

        print()


if __name__ == "__main__":
    main()
