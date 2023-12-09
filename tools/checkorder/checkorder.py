import os
import sys
import argparse
from isledecomp.dir import walk_source_dir, is_file_cpp
from isledecomp.parser import DecompParser


def sig_truncate(sig: str) -> str:
    """Helper to truncate function names to 50 chars and append ellipsis
    if needed. Goal is to stay under 80 columns for tool output."""
    return f"{sig[:47]}{'...' if len(sig) >= 50 else ''}"


def check_file(filename: str, verbose: bool = False) -> bool:
    """Open and read the given file, then check whether the code blocks
    are in order. If verbose, print each block."""

    parser = DecompParser()
    with open(filename, "r", encoding="utf-8") as f:
        parser.read_lines(f)

    just_offsets = [block.offset for block in parser.functions]
    sorted_offsets = sorted(just_offsets)
    file_out_of_order = just_offsets != sorted_offsets

    # TODO: When we add parser error severity, actual errors that obstruct
    # parsing should probably be shown here regardless of verbose mode

    # If we detect inexact comments, don't print anything unless we are
    # in verbose mode. If the file is out of order, we always print the
    # file name.
    should_report = (len(parser.alerts) > 0 and verbose) or file_out_of_order

    if not should_report and not file_out_of_order:
        return False

    # Else: we are alerting to some problem in this file
    print(filename)
    if verbose:
        if file_out_of_order:
            order_lookup = {k: i for i, k in enumerate(sorted_offsets)}
            prev_offset = 0

            for fun in parser.functions:
                msg = " ".join(
                    [
                        " " if fun.offset > prev_offset else "!",
                        f"{fun.offset:08x}",
                        f"{fun.end_line - fun.line_number:4} lines",
                        f"{order_lookup[fun.offset]:3}",
                        "    ",
                        sig_truncate(fun.name),
                    ]
                )
                print(msg)
                prev_offset = fun.offset

        for alert in parser.alerts:
            print(f"* line {alert.line_number:4} {alert.code} ({alert.line})")

        print()

    return file_out_of_order


def parse_args(test_args: list | None = None) -> dict:
    p = argparse.ArgumentParser(
        description="Checks the source files to make sure the function offset comments are in order",
    )
    p.add_argument("target", help="The file or directory to check.")
    p.add_argument(
        "--enforce",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Fail with error code if target is out of order.",
    )
    p.add_argument(
        "--verbose",
        action=argparse.BooleanOptionalAction,
        default=False,
        help=(
            "Display each code block in the file and show "
            "where each consecutive run of blocks is broken."
        ),
    )

    if test_args is None:
        args = p.parse_args()
    else:
        args = p.parse_args(test_args)

    return vars(args)


def main():
    args = parse_args()

    if os.path.isdir(args["target"]):
        files_to_check = list(walk_source_dir(args["target"]))
    elif os.path.isfile(args["target"]) and is_file_cpp(args["target"]):
        files_to_check = [args["target"]]
    else:
        sys.exit("Invalid target")

    files_out_of_order = 0

    for file in files_to_check:
        is_jumbled = check_file(file, args["verbose"])
        if is_jumbled:
            files_out_of_order += 1

    if files_out_of_order > 0:
        error_message = " ".join(
            [
                str(files_out_of_order),
                "files are" if files_out_of_order > 1 else "file is",
                "out of order",
            ]
        )
        print(error_message)

    if files_out_of_order > 0 and args["enforce"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
