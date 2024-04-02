#!/usr/bin/env python3

import argparse
import base64
import json
import logging
import os
from datetime import datetime

from isledecomp import (
    Bin,
    get_file_in_script_dir,
    print_combined_diff,
    diff_json,
    percent_string,
)
from isledecomp.compare import Compare as IsleCompare
from isledecomp.types import SymbolType
from pystache import Renderer
import colorama

colorama.just_fix_windows_console()


def gen_json(json_file: str, orig_file: str, data):
    """Create a JSON file that contains the comparison summary"""

    # If the structure of the JSON file ever changes, we would run into a problem
    # reading an older format file in the CI action. Mark which version we are
    # generating so we could potentially address this down the road.
    json_format_version = 1

    # Remove the diff field
    reduced_data = [
        {key: value for (key, value) in obj.items() if key != "diff"} for obj in data
    ]

    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(
            {
                "file": os.path.basename(orig_file).lower(),
                "format": json_format_version,
                "timestamp": datetime.now().timestamp(),
                "data": reduced_data,
            },
            f,
        )


def gen_html(html_file, data):
    js_path = get_file_in_script_dir("reccmp.js")
    with open(js_path, "r", encoding="utf-8") as f:
        reccmp_js = f.read()

    output_data = Renderer().render_path(
        get_file_in_script_dir("template.html"), {"data": data, "reccmp_js": reccmp_js}
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


def print_match_verbose(match, show_both_addrs: bool = False, is_plain: bool = False):
    percenttext = percent_string(
        match.effective_ratio, match.is_effective_match, is_plain
    )

    if show_both_addrs:
        addrs = f"0x{match.orig_addr:x} / 0x{match.recomp_addr:x}"
    else:
        addrs = hex(match.orig_addr)

    if match.is_stub:
        print(f"{addrs}: {match.name} is a stub. No diff.")
        return

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
                f"{addrs}: {match.name} Effective 100% match. (Differs in register allocation only)\n\n{ok_text} (still differs in register allocation)\n\n"
            )
    else:
        print_combined_diff(match.udiff, is_plain, show_both_addrs)

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

    if match.is_stub:
        print(f"  {match.name} ({addrs}) is a stub.")
    else:
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
        "--json",
        metavar="<file>",
        help="Generate JSON file with match summary",
    )
    parser.add_argument(
        "--diff",
        metavar="<file>",
        help="Diff against summary in JSON file",
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
    parser.add_argument(
        "--silent",
        action="store_true",
        help="Don't display text summary of matches",
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
            match = isle_compare.compare_address(args.verbose)
            if match is None:
                print(f"Failed to find a match at address 0x{args.verbose:x}")
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

        for match in isle_compare.compare_all():
            if not args.silent and args.diff is None:
                print_match_oneline(
                    match, show_both_addrs=args.print_rec_addr, is_plain=args.no_color
                )

            if match.match_type == SymbolType.FUNCTION and not match.is_stub:
                function_count += 1
                total_accuracy += match.ratio
                total_effective_accuracy += match.effective_ratio

            # If html, record the diffs to an HTML file
            html_obj = {
                "address": f"0x{match.orig_addr:x}",
                "recomp": f"0x{match.recomp_addr:x}",
                "name": match.name,
                "matching": match.effective_ratio,
            }

            if match.is_effective_match:
                html_obj["effective"] = True

            if match.udiff is not None:
                html_obj["diff"] = match.udiff

            if match.is_stub:
                html_obj["stub"] = True

            htmlinsert.append(html_obj)

        # Compare with saved diff report.
        if args.diff is not None:
            with open(args.diff, "r", encoding="utf-8") as f:
                saved_data = json.load(f)

                diff_json(
                    saved_data,
                    htmlinsert,
                    args.original,
                    show_both_addrs=args.print_rec_addr,
                    is_plain=args.no_color,
                )

        ## Generate files and show summary.

        if args.json is not None:
            gen_json(args.json, args.original, htmlinsert)

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
