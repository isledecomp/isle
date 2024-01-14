#!/usr/bin/env python3

import argparse
import base64
import json
import logging
import os

from isledecomp import (
    Bin,
    get_file_in_script_dir,
    print_diff,
)
from isledecomp.compare import Compare as IsleCompare
from pystache import Renderer
import colorama

colorama.init()


def gen_html(html_file, data):
    output_data = Renderer().render_path(
        get_file_in_script_dir("template.html"), {"data": data}
    )

    with open(html_file, "w", encoding="utf-8") as htmlfile:
        htmlfile.write(output_data)


def gen_svg(svg_file, name_svg, icon, svg_implemented_funcs, total_funcs, raw_accuracy):
    icon_data = None
    if icon:
        with open(icon, "rb") as iconfile:
            icon_data = base64.b64encode(iconfile.read()).decode("utf-8")

    total_statistic = raw_accuracy / total_funcs
    full_percentbar_width = 127.18422
    output_data = Renderer().render_path(
        get_file_in_script_dir("template.svg"),
        {
            "name": name_svg,
            "icon": icon_data,
            "implemented": f"{(svg_implemented_funcs / total_funcs * 100):.2f}% ({svg_implemented_funcs}/{total_funcs})",
            "accuracy": f"{(raw_accuracy / svg_implemented_funcs * 100):.2f}%",
            "progbar": total_statistic * full_percentbar_width,
            "percent": f"{(total_statistic * 100):.2f}%",
        },
    )
    with open(svg_file, "w", encoding="utf-8") as svgfile:
        svgfile.write(output_data)


def get_percent_color(value: float) -> str:
    """Return colorama ANSI escape character for the given decimal value."""
    if value == 1.0:
        return colorama.Fore.GREEN
    if value > 0.8:
        return colorama.Fore.YELLOW

    return colorama.Fore.RED


def percent_string(
    ratio: float, is_effective: bool = False, is_plain: bool = False
) -> str:
    """Helper to construct a percentage string from the given ratio.
    If is_effective (i.e. effective match), indicate that with the asterisk.
    If is_plain, don't use colorama ANSI codes."""

    percenttext = f"{(ratio * 100):.2f}%"
    effective_star = "*" if is_effective else ""

    if is_plain:
        return percenttext + effective_star

    return "".join(
        [
            get_percent_color(ratio),
            percenttext,
            colorama.Fore.RED if is_effective else "",
            effective_star,
            colorama.Style.RESET_ALL,
        ]
    )


def print_match_verbose(match, show_both_addrs: bool = False, is_plain: bool = False):
    percenttext = percent_string(
        match.effective_ratio, match.is_effective_match, is_plain
    )

    if show_both_addrs:
        addrs = f"0x{match.orig_addr:x} / 0x{match.recomp_addr:x}"
    else:
        addrs = hex(match.orig_addr)

    if match.effective_ratio == 1.0:
        ok_text = (
            "OK!"
            if is_plain
            else (colorama.Fore.GREEN + "✨ OK! ✨" + colorama.Style.RESET_ALL)
        )
        if match.ratio == 1.0:
            print(f"{addrs}: {match.name} 100% match.\n\n{ok_text}\n\n")
        else:
            print(
                f"{addrs}: {match.name} Effective 100%% match. (Differs in register allocation only)\n\n{ok_text} (still differs in register allocation)\n\n"
            )
    else:
        print_diff(match.udiff, is_plain)

        print(
            f"\n{match.name} is only {percenttext} similar to the original, diff above"
        )


def print_match_oneline(match, show_both_addrs: bool = False, is_plain: bool = False):
    percenttext = percent_string(
        match.effective_ratio, match.is_effective_match, is_plain
    )

    if show_both_addrs:
        addrs = f"0x{match.orig_addr:x} / 0x{match.recomp_addr:x}"
    else:
        addrs = hex(match.orig_addr)

    print(f"  {match.name} ({addrs}) is {percenttext} similar to the original")


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
        "--total",
        "-T",
        metavar="<count>",
        help="Total number of expected functions (improves total accuracy statistic)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        metavar="<offset>",
        type=virtual_address,
        help="Print assembly diff for specific function (original file's offset)",
    )
    parser.add_argument(
        "--html",
        "-H",
        metavar="<file>",
        help="Generate searchable HTML summary of status and diffs",
    )
    parser.add_argument(
        "--no-color", "-n", action="store_true", help="Do not color the output"
    )
    parser.add_argument(
        "--svg", "-S", metavar="<file>", help="Generate SVG graphic of progress"
    )
    parser.add_argument("--svg-icon", metavar="icon", help="Icon to use in SVG (PNG)")
    parser.add_argument(
        "--print-rec-addr",
        action="store_true",
        help="Print addresses of recompiled functions too",
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
        if args.verbose is not None:
            # Mute logger events from compare engine
            logging.getLogger("isledecomp.compare.db").setLevel(logging.CRITICAL)
            logging.getLogger("isledecomp.compare.lines").setLevel(logging.CRITICAL)

        isle_compare = IsleCompare(origfile, recompfile, args.pdb, args.decomp_dir)

        print()

        ### Compare one or none.

        if args.verbose is not None:
            match = isle_compare.compare_function(args.verbose)
            if match is None:
                print(f"Failed to find the function with address 0x{args.verbose:x}")
                return

            print_match_verbose(
                match, show_both_addrs=args.print_rec_addr, is_plain=args.no_color
            )
            return

        ### Compare everything.

        function_count = 0
        total_accuracy = 0
        total_effective_accuracy = 0
        htmlinsert = []

        for match in isle_compare.compare_functions():
            print_match_oneline(
                match, show_both_addrs=args.print_rec_addr, is_plain=args.no_color
            )

            function_count += 1
            total_accuracy += match.ratio
            total_effective_accuracy += match.effective_ratio

            # If html, record the diffs to an HTML file
            if args.html is not None:
                htmlinsert.append(
                    {
                        "address": f"0x{match.orig_addr:x}",
                        "name": match.name,
                        "matching": match.effective_ratio,
                        "diff": "\n".join(match.udiff),
                    }
                )

        ## Generate files and show summary.

        if args.html is not None:
            gen_html(args.html, json.dumps(htmlinsert))

        implemented_funcs = function_count

        if args.total:
            function_count = int(args.total)

        if function_count > 0:
            effective_accuracy = total_effective_accuracy / function_count * 100
            actual_accuracy = total_accuracy / function_count * 100
            print(
                f"\nTotal effective accuracy {effective_accuracy:.2f}% across {function_count} functions ({actual_accuracy:.2f}% actual accuracy)"
            )

            if args.svg is not None:
                gen_svg(
                    args.svg,
                    os.path.basename(args.original),
                    args.svg_icon,
                    implemented_funcs,
                    function_count,
                    total_effective_accuracy,
                )


if __name__ == "__main__":
    raise SystemExit(main())
