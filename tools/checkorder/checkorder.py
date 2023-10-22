import os
import re
import sys
import argparse
from typing import List, Iterator, TextIO
from collections import namedtuple
from enum import Enum


class ReaderState(Enum):
    WANT_OFFSET = 0
    WANT_SIG = 1
    IN_FUNC = 2


CodeBlock = namedtuple('CodeBlock',
                       ['offset', 'signature', 'start_line', 'end_line'])

# To match a reasonable variance of formatting for the offset comment
offsetCommentRegex = re.compile(r'//\s?OFFSET:\s?\w+ (?:0x)?([a-f0-9]+)',
                                flags=re.I)

# To match the exact syntax (text upper case, hex lower case, with spaces)
# that is used in most places
offsetCommentExactRegex = re.compile(r'// OFFSET: [A-Z0-9]+ (0x[a-f0-9]+)')


def is_blank_or_comment(line: str) -> bool:
    """Helper to read ahead adter the offset comment is matched.
       There could be blank lines or other comments before the
       function signature, and we want to skip those."""
    line_strip = line.strip()
    return (len(line_strip) == 0
            or line_strip.startswith('//')
            or line_strip.startswith('/*')
            or line_strip.endswith('*/'))


def is_exact_offset_comment(line: str) -> bool:
    """If the offset comment does not match our (unofficial) syntax
       we may want to alert the user to fix it for style points."""
    return offsetCommentExactRegex.match(line) is not None


def match_offset_comment(line: str) -> str | None:
    # TODO: intended to skip the expensive regex match, but is it necessary?
    if not line.startswith('//'):
        return None

    match = offsetCommentRegex.match(line)
    return match.group(1) if match is not None else None


def find_code_blocks(stream: TextIO) -> List[CodeBlock]:
    """Read the IO stream (file) line-by-line and give the following report:
       Foreach code block (function) in the file, what are its starting and
       ending line numbers, and what is the given offset in the original
       binary. We expect the result to be ordered by line number because we
       are reading the file from start to finish."""

    blocks = []

    offset = None
    function_sig = None
    start_line = None
    state = ReaderState.WANT_OFFSET

    for line_no, line in enumerate(stream):
        if state in (ReaderState.WANT_SIG, ReaderState.IN_FUNC):
            # Naive but reasonable assumption that functions will end with
            # a curly brace on its own line with no prepended spaces.
            if line.startswith('}'):
                # TODO: could streamline this and the next case
                block = CodeBlock(offset=offset,
                                  signature=function_sig,
                                  start_line=start_line,
                                  end_line=line_no)

                blocks.append(block)
                state = ReaderState.WANT_OFFSET
            elif match_offset_comment(line) is not None:
                # We hit another offset unexpectedly before detecting the
                # end of the function. We can recover easily by just
                # ending the function here.
                block = CodeBlock(offset=offset,
                                  signature=function_sig,
                                  start_line=start_line,
                                  end_line=line_no - 1)

                blocks.append(block)
                state = ReaderState.WANT_OFFSET

            # We want to grab the function signature so we can identify
            # the code block. Skip any blank lines or comments
            # that follow the offset comment.
            elif (not is_blank_or_comment(line)
                  and state == ReaderState.WANT_SIG):
                function_sig = line.strip()
                state = ReaderState.IN_FUNC

        if state == ReaderState.WANT_OFFSET:
            match = match_offset_comment(line)
            if match is not None:
                offset = int(match, 16)
                start_line = line_no
                state = ReaderState.WANT_SIG

    return blocks


def file_is_cpp(filename: str) -> bool:
    # TODO: expand to check header files also?
    (basefile, ext) = os.path.splitext(filename)
    return ext.lower() == '.cpp'


def walk_source_dir(source: str) -> Iterator[tuple]:
    """Generator to walk the given directory recursively and return
       any .cpp files found."""

    for subdir, dirs, files in os.walk(source):
        for file in files:
            if not file_is_cpp(file):
                continue

            yield os.path.join(subdir, file)


def sig_truncate(sig: str) -> str:
    """Helper to truncate function names to 50 chars and append ellipsis
       if needed. Goal is to stay under 80 columns for tool output."""
    return f"{sig[:47]}{'...' if len(sig) >= 50 else ''}"


def get_inexact_offset_comments(stream: TextIO) -> [tuple]:
    """Read the file stream and return the line number and string
       for any offset comments that don't exactly match the template."""
    return ([
        (line_no, line.strip())
        for line_no, line in enumerate(stream)
        if match_offset_comment(line) and not is_exact_offset_comment(line)
    ])


def check_file(filename: str, verbose: bool = False) -> bool:
    """Open and read the given file, then check whether the code blocks
       are in order. If verbose, print each block."""

    with open(filename, 'r') as f:
        code_blocks = find_code_blocks(f)
        # TODO: Should combine these checks if/when we refactor.
        # This is just for simplicity / proof of concept.
        f.seek(os.SEEK_SET, 0)
        bad_comments = get_inexact_offset_comments(f)

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
