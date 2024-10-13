from dataclasses import dataclass
import re
import logging
import os
import argparse
import struct
from typing import Dict, List, NamedTuple, Optional, Set, Tuple

from isledecomp import Bin
from isledecomp.compare import Compare as IsleCompare
from isledecomp.compare.diff import CombinedDiffOutput
from isledecomp.cvdump.symbols import SymbolsEntry
import colorama

# pylint: disable=duplicate-code # misdetects a code duplication with reccmp

colorama.just_fix_windows_console()

CHECK_ICON = f"{colorama.Fore.GREEN}✓{colorama.Style.RESET_ALL}"
SWAP_ICON = f"{colorama.Fore.YELLOW}⇄{colorama.Style.RESET_ALL}"
ERROR_ICON = f"{colorama.Fore.RED}✗{colorama.Style.RESET_ALL}"
UNCLEAR_ICON = f"{colorama.Fore.BLUE}?{colorama.Style.RESET_ALL}"


STACK_ENTRY_REGEX = re.compile(
    r"(?P<register>e[sb]p)\s(?P<sign>[+-])\s(?P<offset>(0x)?[0-9a-f]+)(?![0-9a-f])"
)


@dataclass
class StackSymbol:
    name: str
    data_type: str


@dataclass
class StackRegisterOffset:
    register: str
    offset: int
    symbol: Optional[StackSymbol] = None

    def __str__(self) -> str:
        first_part = (
            f"{self.register} + {self.offset:#04x}"
            if self.offset > 0
            else f"{self.register} - {-self.offset:#04x}"
        )
        second_part = f"  {self.symbol.name}" if self.symbol else ""
        return first_part + second_part

    def __hash__(self) -> int:
        return hash(self.register) + self.offset

    def copy(self) -> "StackRegisterOffset":
        return StackRegisterOffset(self.register, self.offset, self.symbol)

    def __eq__(self, other: "StackRegisterOffset"):
        return self.register == other.register and self.offset == other.offset


class StackPair(NamedTuple):
    orig: StackRegisterOffset
    recomp: StackRegisterOffset


StackPairs = Set[StackPair]


@dataclass
class Warnings:
    structural_mismatches_present: bool = False
    error_map_not_bijective: bool = False


def extract_stack_offset_from_instruction(
    instruction: str,
) -> StackRegisterOffset | None:
    match = STACK_ENTRY_REGEX.search(instruction)
    if not match:
        return None
    offset = int(match.group("sign") + match.group("offset"), 16)
    return StackRegisterOffset(match.group("register"), offset)


def analyze_diff(
    diff: Dict[str, List[Tuple[str, ...]]], warnings: Warnings
) -> StackPairs:
    stack_pairs: StackPairs = set()
    if "both" in diff:
        # get the matching stack entries
        for line in diff["both"]:
            # 0 = orig addr, 1 = instruction, 2 = reccmp addr
            instruction = line[1]

            if match := extract_stack_offset_from_instruction(instruction):
                logging.debug("stack match: %s", match)
                # need a copy for recomp because we might add a debug symbol to it
                stack_pairs.add(StackPair(match, match.copy()))
            elif any(x in instruction for x in ["ebp", "esp"]):
                logging.debug("not a stack offset: %s", instruction)

    else:
        orig = diff["orig"]
        recomp = diff["recomp"]
        if len(orig) != len(recomp):
            if orig:
                mismatch_location = f"orig={orig[0][0]}"
            else:
                mismatch_location = f"recomp={recomp[0][0]}"
            logging.error(
                "Structural mismatch at %s:\n%s",
                mismatch_location,
                print_structural_mismatch(orig, recomp),
            )
            warnings.structural_mismatches_present = True
            return set()

        for orig_line, recomp_line in zip(orig, recomp):
            if orig_match := extract_stack_offset_from_instruction(orig_line[1]):
                recomp_match = extract_stack_offset_from_instruction(recomp_line[1])

                if not recomp_match:
                    logging.error(
                        "Mismatching line structure at orig=%s:\n%s",
                        orig_line[0],
                        print_structural_mismatch(orig, recomp),
                    )
                    # not recoverable, whole block has a structural mismatch
                    warnings.structural_mismatches_present = True
                    return set()

                stack_pair = StackPair(orig_match, recomp_match)

                logging.debug(
                    "stack match, wrong order: %s vs %s", stack_pair[0], stack_pair[1]
                )
                stack_pairs.add(stack_pair)

            elif any(x in orig_line[1] for x in ["ebp", "esp"]):
                logging.debug("not a stack offset: %s", orig_line[1])

    return stack_pairs


def print_bijective_match(left: str, right: str, exact: bool):
    icon = CHECK_ICON if exact else SWAP_ICON
    print(f"{icon}{colorama.Style.RESET_ALL}  {left}: {right}")


def print_non_bijective_match(left: str, right: str):
    print(f"{ERROR_ICON}  {left}: {right}")


def print_structural_mismatch(
    orig: List[Tuple[str, ...]], recomp: List[Tuple[str, ...]]
) -> str:
    orig_str = "\n".join(f"-{x[1]}" for x in orig) if orig else "-"
    recomp_str = "\n".join(f"+{x[1]}" for x in recomp) if recomp else "+"
    return f"{colorama.Fore.RED}{orig_str}\n{colorama.Fore.GREEN}{recomp_str}\n{colorama.Style.RESET_ALL}"


def format_list_of_offsets(offsets: List[StackRegisterOffset]) -> str:
    return str([str(x) for x in offsets])


def compare_function_stacks(udiff: CombinedDiffOutput, fn_symbol: SymbolsEntry):
    warnings = Warnings()

    # consists of pairs (orig, recomp)
    # don't use a dict because we can have m:n relations
    stack_pairs: StackPairs = set()

    for block in udiff:
        # block[0] is e.g. "@@ -0x10071662,60 +0x10031368,60 @@"
        for diff in block[1]:
            stack_pairs = stack_pairs.union(analyze_diff(diff, warnings))

    # Note that the 'Frame Ptr Present' property is not relevant to the stack below `ebp`,
    # but only to entries above (i.e. the function arguments on the stack).
    # See also pdb_extraction.py.

    stack_symbols: Dict[int, StackSymbol] = {}

    for symbol in fn_symbol.stack_symbols:
        if symbol.symbol_type == "S_BPREL32":
            # convert hex to signed 32 bit integer
            hex_bytes = bytes.fromhex(symbol.location[1:-1])
            stack_offset = struct.unpack(">l", hex_bytes)[0]

            stack_symbols[stack_offset] = StackSymbol(
                symbol.name,
                symbol.data_type,
            )

    for _, recomp in stack_pairs:
        if recomp.register == "ebp":
            recomp.symbol = stack_symbols.get(recomp.offset)
        elif recomp.register == "esp":
            logging.debug(
                "Matching esp offsets to debug symbols is not implemented right now"
            )

    print("\nOrdered by original stack (left=orig, right=recomp):")

    all_orig_offsets = set(x.orig.offset for x in stack_pairs)

    for orig_offset in sorted(all_orig_offsets):
        orig = next(x.orig for x in stack_pairs if x.orig.offset == orig_offset)
        recomps = [x.recomp for x in stack_pairs if x.orig == orig]

        if len(recomps) == 1:
            recomp = recomps[0]
            print_bijective_match(str(orig), str(recomp), exact=orig == recomp)
        else:
            print_non_bijective_match(str(orig), format_list_of_offsets(recomps))
            warnings.error_map_not_bijective = True

    # Show offsets from the debug symbols that we have not encountered in the diff
    all_recomp_offsets = set(x.orig.offset for x in stack_pairs).union(
        stack_symbols.keys()
    )

    print("\nOrdered by recomp stack (left=orig, right=recomp):")
    for recomp_offset in sorted(all_recomp_offsets):
        recomp = next(
            (x.recomp for x in stack_pairs if x.recomp.offset == recomp_offset), None
        )

        if recomp is None:
            # The offset only appears in the debug symbols.
            # The legend below explains why this can happen.
            stack_offset = StackRegisterOffset(
                "ebp", recomp_offset, stack_symbols[recomp_offset]
            )
            print(f"{UNCLEAR_ICON}  not seen:   {stack_offset}")
            continue

        origs = [x.orig for x in stack_pairs if x.recomp == recomp]

        if len(origs) == 1:
            # 1:1 clean match
            print_bijective_match(str(origs[0]), str(recomp), origs[0] == recomp)
        else:
            print_non_bijective_match(format_list_of_offsets(origs), str(recomp))
            warnings.error_map_not_bijective = True

    print(
        "\nLegend:\n"
        + f"{SWAP_ICON} : This stack variable matches 1:1, but the order of variables is not correct.\n"
        + f"{ERROR_ICON} : This stack variable matches multiple variables in the other binary.\n"
        + f"{UNCLEAR_ICON} : This stack variable did not appear in the diff. It either matches or only appears in structural mismatches.\n"
    )

    if warnings.error_map_not_bijective:
        print(
            "ERROR: The stack variables of original and recomp are not in a 1:1 correspondence, "
            + "suggesting that the logic in the recomp is incorrect."
        )
    elif warnings.structural_mismatches_present:
        print(
            "WARNING: Original and recomp have at least one structural discrepancy, "
            + "so the comparison of stack variables might be incomplete. "
            + "The structural mismatches above need to be checked manually."
        )


def parse_args() -> argparse.Namespace:
    def virtual_address(value) -> int:
        """Helper method for argparse, verbose parameter"""
        return int(value, 16)

    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Recompilation Compare: compare an original EXE with a recompiled EXE + PDB.",
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

    parser.add_argument(
        "address",
        metavar="<offset>",
        type=virtual_address,
        help="The original file's offset of the function to be analyzed",
    )

    parser.set_defaults(loglevel=logging.INFO)
    parser.add_argument(
        "--debug",
        action="store_const",
        const=logging.DEBUG,
        dest="loglevel",
        help="Print script debug information",
    )

    args = parser.parse_args()

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
    logging.basicConfig(level=args.loglevel, format="[%(levelname)s] %(message)s")

    with Bin(args.original, find_str=True) as origfile, Bin(
        args.recompiled
    ) as recompfile:
        if args.loglevel != logging.DEBUG:
            # Mute logger events from compare engine
            logging.getLogger("isledecomp.compare.core").setLevel(logging.CRITICAL)
            logging.getLogger("isledecomp.compare.db").setLevel(logging.CRITICAL)
            logging.getLogger("isledecomp.compare.lines").setLevel(logging.CRITICAL)

        isle_compare = IsleCompare(origfile, recompfile, args.pdb, args.decomp_dir)

        if args.loglevel == logging.DEBUG:
            isle_compare.debug = True

        print()

        match = isle_compare.compare_address(args.address)
        if match is None:
            print(f"Failed to find a match at address 0x{args.address:x}")
            return

        assert match.udiff is not None

        function_data = next(
            (
                y
                for y in isle_compare.cvdump_analysis.nodes
                if y.addr == match.recomp_addr
            ),
            None,
        )
        assert function_data is not None
        assert function_data.symbol_entry is not None

        compare_function_stacks(match.udiff, function_data.symbol_entry)


if __name__ == "__main__":
    raise SystemExit(main())
