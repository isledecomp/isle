#!/usr/bin/env python3

import os
import sys
import argparse
import colorama
from isledecomp.dir import walk_source_dir, is_file_cpp
from isledecomp.parser import DecompLinter

colorama.just_fix_windows_console()


def display_errors(alerts, filename):
    sorted_alerts = sorted(alerts, key=lambda a: a.line_number)

    for alert in sorted_alerts:
        error_type = (
            f"{colorama.Fore.RED}error: "
            if alert.is_error()
            else f"{colorama.Fore.YELLOW}warning: "
        )
        components = [
            colorama.Fore.LIGHTWHITE_EX,
            filename,
            ":",
            str(alert.line_number),
            " : ",
            error_type,
            colorama.Fore.LIGHTWHITE_EX,
            alert.code.name.lower(),
        ]
        print("".join(components))

        if alert.line is not None:
            print(f"{colorama.Fore.WHITE}  {alert.line}")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Syntax checking and linting for decomp annotation markers."
    )
    p.add_argument("target", help="The file or directory to check.")
    p.add_argument(
        "--module",
        required=False,
        type=str,
        help="If present, run targeted checks for markers from the given module.",
    )
    p.add_argument(
        "--warnfail",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Fail if syntax warnings are found.",
    )

    (args, _) = p.parse_known_args()
    return args


def process_files(files, module=None):
    warning_count = 0
    error_count = 0

    linter = DecompLinter()
    for filename in files:
        success = linter.check_file(filename, module)

        warnings = [a for a in linter.alerts if a.is_warning()]
        errors = [a for a in linter.alerts if a.is_error()]

        error_count += len(errors)
        warning_count += len(warnings)

        if not success:
            display_errors(linter.alerts, filename)
            print()

    return (warning_count, error_count)


def main():
    args = parse_args()

    if os.path.isdir(args.target):
        files_to_check = list(walk_source_dir(args.target))
    elif os.path.isfile(args.target) and is_file_cpp(args.target):
        files_to_check = [args.target]
    else:
        sys.exit("Invalid target")

    (warning_count, error_count) = process_files(files_to_check, module=args.module)

    print(colorama.Style.RESET_ALL, end="")

    would_fail = error_count > 0 or (warning_count > 0 and args.warnfail)
    if would_fail:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
