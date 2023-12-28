#!/usr/bin/env python3

import argparse
import base64
import difflib
import json
import logging
import os
import re

from isledecomp import (
    Bin,
    DecompParser,
    get_file_in_script_dir,
    OffsetPlaceholderGenerator,
    print_diff,
    SymInfo,
    walk_source_dir,
)

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import colorama
from pystache import Renderer


REGISTER_LIST = set(
    [
        "ax",
        "bp",
        "bx",
        "cx",
        "di",
        "dx",
        "eax",
        "ebp",
        "ebx",
        "ecx",
        "edi",
        "edx",
        "esi",
        "esp",
        "si",
        "sp",
    ]
)
WORDS = re.compile(r"\w+")


def sanitize(file, placeholder_generator, mnemonic, op_str):
    op_str_is_number = False
    try:
        int(op_str, 16)
        op_str_is_number = True
    except ValueError:
        pass

    if (mnemonic in ["call", "jmp"]) and op_str_is_number:
        # Filter out "calls" because the offsets we're not currently trying to
        # match offsets. As long as there's a call in the right place, it's
        # probably accurate.
        op_str = placeholder_generator.get(int(op_str, 16))
    else:

        def filter_out_ptr(ptype, op_str):
            try:
                ptrstr = ptype + " ptr ["
                start = op_str.index(ptrstr) + len(ptrstr)
                end = op_str.index("]", start)

                # This will throw ValueError if not hex
                inttest = int(op_str[start:end], 16)

                return (
                    op_str[0:start] + placeholder_generator.get(inttest) + op_str[end:]
                )
            except ValueError:
                return op_str

        # Filter out dword ptrs where the pointer is to an offset
        op_str = filter_out_ptr("dword", op_str)
        op_str = filter_out_ptr("word", op_str)
        op_str = filter_out_ptr("byte", op_str)

        # Use heuristics to filter out any args that look like offsets
        words = op_str.split(" ")
        for i, word in enumerate(words):
            try:
                inttest = int(word, 16)
                if file.is_relocated_addr(inttest):
                    words[i] = placeholder_generator.get(inttest)
            except ValueError:
                pass
        op_str = " ".join(words)

    return mnemonic, op_str


def parse_asm(disassembler, file, asm_addr, size):
    asm = []
    data = file.read(asm_addr, size)
    placeholder_generator = OffsetPlaceholderGenerator()
    for i in disassembler.disasm(data, 0):
        # Use heuristics to disregard some differences that aren't representative
        # of the accuracy of a function (e.g. global offsets)
        mnemonic, op_str = sanitize(file, placeholder_generator, i.mnemonic, i.op_str)
        if op_str is None:
            asm.append(mnemonic)
        else:
            asm.append(f"{mnemonic} {op_str}")
    return asm


def get_registers(line: str):
    to_replace = []
    # use words regex to find all matching positions:
    for match in WORDS.finditer(line):
        reg = match.group(0)
        if reg in REGISTER_LIST:
            to_replace.append((reg, match.start()))
    return to_replace


def replace_register(
    lines: list[str], start_line: int, reg: str, replacement: str
) -> list[str]:
    return [
        line.replace(reg, replacement) if i >= start_line else line
        for i, line in enumerate(lines)
    ]


# Is it possible to make new_asm the same as original_asm by swapping registers?
def can_resolve_register_differences(original_asm, new_asm):
    # Split the ASM on spaces to get more granularity, and so
    # that we don't modify the original arrays passed in.
    original_asm = [part for line in original_asm for part in line.split()]
    new_asm = [part for line in new_asm for part in line.split()]

    # Swapping ain't gonna help if the lengths are different
    if len(original_asm) != len(new_asm):
        return False

    # Look for the mismatching lines
    for i, original_line in enumerate(original_asm):
        new_line = new_asm[i]
        if new_line != original_line:
            # Find all the registers to replace
            to_replace = get_registers(original_line)

            for replace in to_replace:
                (reg, reg_index) = replace
                replacing_reg = new_line[reg_index : reg_index + len(reg)]
                if replacing_reg in REGISTER_LIST:
                    if replacing_reg != reg:
                        # Do a three-way swap replacing in all the subsequent lines
                        temp_reg = "&" * len(reg)
                        new_asm = replace_register(new_asm, i, replacing_reg, temp_reg)
                        new_asm = replace_register(new_asm, i, reg, replacing_reg)
                        new_asm = replace_register(new_asm, i, temp_reg, reg)
                else:
                    # No replacement to do, different code, bail out
                    return False
    # Check if the lines are now the same
    for i, original_line in enumerate(original_asm):
        if new_asm[i] != original_line:
            return False
    return True


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


# Do the actual work
def main():
    # pylint: disable=too-many-locals, too-many-nested-blocks, too-many-branches, too-many-statements
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

    logging.basicConfig(level=args.loglevel, format="[%(levelname)s] %(message)s")
    logger = logging.getLogger(__name__)

    colorama.init()

    verbose = None
    found_verbose_target = False
    if args.verbose:
        try:
            verbose = int(args.verbose, 16)
        except ValueError:
            parser.error("invalid verbose argument")
    html_path = args.html

    plain = args.no_color

    original = args.original
    if not os.path.isfile(original):
        parser.error(f"Original binary {original} does not exist")

    recomp = args.recompiled
    if not os.path.isfile(recomp):
        parser.error(f"Recompiled binary {recomp} does not exist")

    syms = args.pdb
    if not os.path.isfile(syms):
        parser.error(f"Symbols PDB {syms} does not exist")

    source = args.decomp_dir
    if not os.path.isdir(source):
        parser.error(f"Source directory {source} does not exist")

    svg = args.svg

    with Bin(original, logger) as origfile, Bin(recomp, logger) as recompfile:
        syminfo = SymInfo(syms, recompfile, logger, source)

        print()

        capstone_disassembler = Cs(CS_ARCH_X86, CS_MODE_32)

        function_count = 0
        total_accuracy = 0
        total_effective_accuracy = 0
        htmlinsert = []

        # Generate basename of original file, used in locating OFFSET lines
        basename = os.path.basename(os.path.splitext(original)[0])

        parser = DecompParser()
        for srcfilename in walk_source_dir(source):
            parser.reset()
            with open(srcfilename, "r", encoding="utf-8") as srcfile:
                parser.read_lines(srcfile)

            for fun in parser.functions:
                if fun.should_skip():
                    continue

                if fun.module != basename:
                    continue

                addr = fun.offset
                # Verbose flag handling
                if verbose:
                    if addr == verbose:
                        found_verbose_target = True
                    else:
                        continue

                if fun.is_nameref():
                    recinfo = syminfo.get_recompiled_address_from_name(fun.name)
                    if not recinfo:
                        continue
                else:
                    recinfo = syminfo.get_recompiled_address(
                        srcfilename, fun.line_number
                    )
                    if not recinfo:
                        continue

                # The effective_ratio is the ratio when ignoring differing register
                # allocation vs the ratio is the true ratio.
                ratio = 0.0
                effective_ratio = 0.0
                if recinfo.size:
                    origasm = parse_asm(
                        capstone_disassembler,
                        origfile,
                        addr + recinfo.start,
                        recinfo.size,
                    )
                    recompasm = parse_asm(
                        capstone_disassembler,
                        recompfile,
                        recinfo.addr + recinfo.start,
                        recinfo.size,
                    )

                    diff = difflib.SequenceMatcher(None, origasm, recompasm)
                    ratio = diff.ratio()
                    effective_ratio = ratio

                    if ratio != 1.0:
                        # Check whether we can resolve register swaps which are actually
                        # perfect matches modulo compiler entropy.
                        if can_resolve_register_differences(origasm, recompasm):
                            effective_ratio = 1.0
                else:
                    ratio = 0

                percenttext = f"{(effective_ratio * 100):.2f}%"
                if not plain:
                    if effective_ratio == 1.0:
                        percenttext = (
                            colorama.Fore.GREEN + percenttext + colorama.Style.RESET_ALL
                        )
                    elif effective_ratio > 0.8:
                        percenttext = (
                            colorama.Fore.YELLOW
                            + percenttext
                            + colorama.Style.RESET_ALL
                        )
                    else:
                        percenttext = (
                            colorama.Fore.RED + percenttext + colorama.Style.RESET_ALL
                        )

                if effective_ratio == 1.0 and ratio != 1.0:
                    if plain:
                        percenttext += "*"
                    else:
                        percenttext += (
                            colorama.Fore.RED + "*" + colorama.Style.RESET_ALL
                        )

                if args.print_rec_addr:
                    addrs = f"0x{addr:x} / 0x{recinfo.addr:x}"
                else:
                    addrs = hex(addr)

                if not verbose:
                    print(
                        f"  {recinfo.name} ({addrs}) is {percenttext} similar to the original"
                    )

                function_count += 1
                total_accuracy += ratio
                total_effective_accuracy += effective_ratio

                if recinfo.size:
                    udiff = difflib.unified_diff(origasm, recompasm, n=10)

                    # If verbose, print the diff for that function to the output
                    if verbose:
                        if effective_ratio == 1.0:
                            ok_text = (
                                "OK!"
                                if plain
                                else (
                                    colorama.Fore.GREEN
                                    + "✨ OK! ✨"
                                    + colorama.Style.RESET_ALL
                                )
                            )
                            if ratio == 1.0:
                                print(
                                    f"{addrs}: {recinfo.name} 100% match.\n\n{ok_text}\n\n"
                                )
                            else:
                                print(
                                    f"{addrs}: {recinfo.name} Effective 100%% match. (Differs in register allocation only)\n\n{ok_text} (still differs in register allocation)\n\n"
                                )
                        else:
                            print_diff(udiff, plain)

                            print(
                                f"\n{recinfo.name} is only {percenttext} similar to the original, diff above"
                            )

                    # If html, record the diffs to an HTML file
                    if html_path:
                        htmlinsert.append(
                            {
                                "address": f"0x{addr:x}",
                                "name": recinfo.name,
                                "matching": effective_ratio,
                                "diff": "\n".join(udiff),
                            }
                        )

        if html_path:
            gen_html(html_path, json.dumps(htmlinsert))

        if verbose:
            if not found_verbose_target:
                print(f"Failed to find the function with address 0x{verbose:x}")
        else:
            implemented_funcs = function_count

            if args.total:
                function_count = int(args.total)

            if function_count > 0:
                effective_accuracy = total_effective_accuracy / function_count * 100
                actual_accuracy = total_accuracy / function_count * 100
                print(
                    f"\nTotal effective accuracy {effective_accuracy:.2f}% across {function_count} functions ({actual_accuracy:.2f}% actual accuracy)"
                )

                if svg:
                    gen_svg(
                        svg,
                        os.path.basename(original),
                        args.svg_icon,
                        implemented_funcs,
                        function_count,
                        total_effective_accuracy,
                    )


if __name__ == "__main__":
    raise SystemExit(main())
