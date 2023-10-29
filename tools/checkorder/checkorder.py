import os
import sys
import argparse
from typing import TextIO
from isledecomp.dir import walk_source_dir
from isledecomp.parser import find_code_blocks
from isledecomp.parser.util import (
    is_exact_offset_comment
)


def sig_truncate(sig: str) -> str:
    """Helper to truncate function names to 50 chars and append ellipsis
       if needed. Goal is to stay under 80 columns for tool output."""
    return f"{sig[:47]}{'...' if len(sig) >= 50 else ''}"


def check_file(filename: str, verbose: bool = False) -> bool:
    """Open and read the given file, then check whether the code blocks
       are in order. If verbose, print each block."""

    with open(filename, 'r') as f:
        code_blocks = find_code_blocks(f)
        # TODO: Should combine these checks if/when we refactor.
        # This is just for simplicity / proof of concept.
        f.seek(os.SEEK_SET, 0)

    bad_comments = [(block.start_line, block.offset_comment)
                    for block in code_blocks
                    if not is_exact_offset_comment(block.offset_comment)]

    just_offsets = [block.offset for block in code_blocks]
    sorted_offsets = sorted(just_offsets)
    file_out_of_order = just_offsets != sorted_offsets

    # If we detect inexact comments, don't print anything unless we are
    # in verbose mode. If the file is out of order, we always print the
    # file name.
    should_report = ((len(bad_comments) > 0 and verbose)
                     or file_out_of_order)

    if not should_report and not file_out_of_order:
        return False

    # Else: we are alerting to some problem in this file
    print(filename)
    if verbose:
        if file_out_of_order:
            order_lookup = {k: i for i, k in enumerate(sorted_offsets)}
            prev_offset = 0

            for block in code_blocks:
                msg = ' '.join([
                    ' ' if block.offset > prev_offset else '!',
                    f'{block.offset:08x}',
                    f'{block.end_line - block.start_line:4} lines',
                    f'{order_lookup[block.offset]:3}',
                    '    ',
                    sig_truncate(block.signature),
                ])
                print(msg)
                prev_offset = block.offset

        for (line_no, line) in bad_comments:
            print(f'* line {line_no:3} bad offset comment ({line})')

        print()

    return file_out_of_order


def parse_args(test_args: list | None = None) -> dict:
    p = argparse.ArgumentParser()
    p.add_argument('target', help='The file or directory to check.')
    p.add_argument('--enforce', action=argparse.BooleanOptionalAction,
                   default=False,
                   help='Fail with error code if target is out of order.')
    p.add_argument('--verbose', action=argparse.BooleanOptionalAction,
                   default=False,
                   help=('Display each code block in the file and show '
                         'where each consecutive run of blocks is broken.'))

    if test_args is None:
        args = p.parse_args()
    else:
        args = p.parse_args(test_args)

    return vars(args)


def main():
    args = parse_args()

    if os.path.isdir(args['target']):
        files_to_check = list(walk_source_dir(args['target']))
    elif os.path.isfile(args['target']) and file_is_cpp(args['target']):
        files_to_check = [args['target']]
    else:
        sys.exit('Invalid target')

    files_out_of_order = 0

    for file in files_to_check:
        is_jumbled = check_file(file, args['verbose'])
        if is_jumbled:
            files_out_of_order += 1

    if files_out_of_order > 0:
        error_message = ' '.join([
            str(files_out_of_order),
            'files are' if files_out_of_order > 1 else 'file is',
            'out of order'
        ])
        print(error_message)

    if files_out_of_order > 0 and args['enforce']:
        sys.exit(1)


if __name__ == '__main__':
    main()
