# C++ file parser

from typing import List, TextIO
from enum import Enum
from .util import (
    CodeBlock,
    OffsetMatch,
    is_blank_or_comment,
    match_offset_comment,
    is_exact_offset_comment,
    template_function_name,
    remove_trailing_comment,
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

    blocks = []

    offset_match = OffsetMatch(module=None,
                               address=None,
                               is_template=None,
                               is_stub=None)
    offset_comment = None
    function_sig = None
    start_line = None
    end_line = None
    state = ReaderState.WANT_OFFSET

    # 1-based to match cvdump and your text-editor
    # I know it says 0, but we will increment before each readline()
    line_no = 0
    can_seek = True

    while True:
        # Do this before reading again so that an EOF will not
        # cause us to miss the last function of the file.
        if state == ReaderState.FUNCTION_DONE:
            block = CodeBlock(offset=offset_match.address,
                              signature=function_sig,
                              start_line=start_line,
                              end_line=end_line,
                              offset_comment=offset_comment,
                              module=offset_match.module,
                              is_template=offset_match.is_template,
                              is_stub=offset_match.is_stub)
            blocks.append(block)
            state = ReaderState.WANT_OFFSET

        if can_seek:
            line_no += 1
            line = stream.readline()
            if line == '':
                break

        if (state != ReaderState.WANT_OFFSET and
                match_offset_comment(line) is not None):
            # We hit another offset unexpectedly.
            # We can recover easily by just ending the function here.
            end_line = line_no - 1
            state = ReaderState.FUNCTION_DONE

            # Pause reading here so we handle the offset marker
            # on the next loop iteration
            can_seek = False

        # Regular state machine handling begins now
        if state == ReaderState.IN_TEMPLATE:
            # TEMPLATE functions are a special case. The signature is
            # given on the next line (in a // comment)
            function_sig = template_function_name(line)
            start_line = line_no
            end_line = line_no
            state = ReaderState.FUNCTION_DONE

        elif state == ReaderState.WANT_SIG:
            # Skip blank lines or comments that come after the offset
            # marker. There is not a formal procedure for this, so just
            # assume the next "code line" is the function signature
            if not is_blank_or_comment(line):
                function_sig = remove_trailing_comment(line.strip())

                # Now check to see if the opening curly bracket is on the
                # same line. clang-format should prevent this (BraceWrapping)
                # but it is easy to detect.
                # If the entire function is on one line, we can handle that
                # too, although this should be limited to inlines.
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

        elif state == ReaderState.WANT_OFFSET:
            # If we detected an offset marker unexpectedly, we are handling
            # it here so we can continue seeking.
            can_seek = True
            match = match_offset_comment(line)
            if match is not None:
                offset_match = match
                offset_comment = line.strip()

                if match.is_template:
                    state = ReaderState.IN_TEMPLATE
                else:
                    state = ReaderState.WANT_SIG

    return blocks
