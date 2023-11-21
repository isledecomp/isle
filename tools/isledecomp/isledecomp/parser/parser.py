# C++ file parser

from typing import List, TextIO
from enum import Enum
from .util import (
    CodeBlock,
    OffsetMatch,
    is_blank_or_comment,
    match_offset_comment,
    is_exact_offset_comment,
    get_template_function_name,
    remove_trailing_comment,
    distinct_by_module,
)


class ReaderState(Enum):
    WANT_OFFSET = 0
    WANT_SIG = 1
    IN_FUNC = 2
    IN_TEMPLATE = 3
    WANT_CURLY = 4
    FUNCTION_DONE = 5


def find_code_blocks(stream: TextIO) -> List[CodeBlock]:
    """Read the IO stream (file) line-by-line and give the following report:
       Foreach code block (function) in the file, what are its starting and
       ending line numbers, and what is the given offset in the original
       binary. We expect the result to be ordered by line number because we
       are reading the file from start to finish."""

    blocks: List[CodeBlock] = []

    offset_matches: List[OffsetMatch] = []

    function_sig = None
    start_line = None
    end_line = None
    state = ReaderState.WANT_OFFSET

    # 1-based to match cvdump and your text editor
    # I know it says 0, but we will increment before each readline()
    line_no = 0
    can_seek = True

    while True:
        # Do this before reading again so that an EOF will not
        # cause us to miss the last function of the file.
        if state == ReaderState.FUNCTION_DONE:
            # Our list of offset marks could have duplicates on
            # module name, so we'll eliminate those now.
            for offset_match in distinct_by_module(offset_matches):
                block = CodeBlock(offset=offset_match.address,
                                  signature=function_sig,
                                  start_line=start_line,
                                  end_line=end_line,
                                  offset_comment=offset_match.comment,
                                  module=offset_match.module,
                                  is_template=offset_match.is_template,
                                  is_stub=offset_match.is_stub)
                blocks.append(block)
            offset_matches = []
            state = ReaderState.WANT_OFFSET

        if can_seek:
            line_no += 1
            line = stream.readline()
            if line == '':
                break

        new_match = match_offset_comment(line)
        if new_match is not None:
            # We will allow multiple offsets if we have just begun
            # the code block, but not after we hit the curly brace.
            if state in (ReaderState.WANT_OFFSET, ReaderState.IN_TEMPLATE,
                         ReaderState.WANT_SIG):
                # If we detected an offset marker unexpectedly,
                # we are handling it here so we can continue seeking.
                can_seek = True

                offset_matches.append(new_match)

                if new_match.is_template:
                    state = ReaderState.IN_TEMPLATE
                else:
                    state = ReaderState.WANT_SIG
            else:
                # We hit another offset unexpectedly.
                # We can recover easily by just ending the function here.
                end_line = line_no - 1
                state = ReaderState.FUNCTION_DONE

                # Pause reading here so we handle the offset marker
                # on the next loop iteration
                can_seek = False

        elif state == ReaderState.IN_TEMPLATE:
            # TEMPLATE functions are a special case. The signature is
            # given on the next line (in a // comment)
            function_sig = get_template_function_name(line)
            start_line = line_no
            end_line = line_no
            state = ReaderState.FUNCTION_DONE

        elif state == ReaderState.WANT_SIG:
            # Skip blank lines or comments that come after the offset
            # marker. There is not a formal procedure for this, so just
            # assume the next "code line" is the function signature
            if not is_blank_or_comment(line):
                # Inline functions may end with a comment. Strip that out
                # to help parsing.
                function_sig = remove_trailing_comment(line.strip())

                # Now check to see if the opening curly bracket is on the
                # same line. clang-format should prevent this (BraceWrapping)
                # but it is easy to detect.
                # If the entire function is on one line, handle that too.
                if function_sig.endswith('{'):
                    start_line = line_no
                    state = ReaderState.IN_FUNC
                elif (function_sig.endswith('}') or
                        function_sig.endswith('};')):
                    start_line = line_no
                    end_line = line_no
                    state = ReaderState.FUNCTION_DONE
                else:
                    state = ReaderState.WANT_CURLY

        elif state == ReaderState.WANT_CURLY:
            if line.strip() == '{':
                start_line = line_no
                state = ReaderState.IN_FUNC

        elif state == ReaderState.IN_FUNC:
            # Naive but reasonable assumption that functions will end with
            # a curly brace on its own line with no prepended spaces.
            if line.startswith('}'):
                end_line = line_no
                state = ReaderState.FUNCTION_DONE

    return blocks
