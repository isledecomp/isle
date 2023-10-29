# C++ file parser

from typing import List, TextIO
from enum import Enum
from .util import (
    CodeBlock,
    is_blank_or_comment,
    match_offset_comment,
    is_exact_offset_comment,
)


class ReaderState(Enum):
    WANT_OFFSET = 0
    WANT_SIG = 1
    IN_FUNC = 2


def find_code_blocks(stream: TextIO) -> List[CodeBlock]:
    """Read the IO stream (file) line-by-line and give the following report:
       Foreach code block (function) in the file, what are its starting and
       ending line numbers, and what is the given offset in the original
       binary. We expect the result to be ordered by line number because we
       are reading the file from start to finish."""

    blocks = []

    offset = None
    offset_comment = None
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
                                  end_line=line_no,
                                  offset_comment=offset_comment)

                blocks.append(block)
                state = ReaderState.WANT_OFFSET
            elif match_offset_comment(line) is not None:
                # We hit another offset unexpectedly before detecting the
                # end of the function. We can recover easily by just
                # ending the function here.
                block = CodeBlock(offset=offset,
                                  signature=function_sig,
                                  start_line=start_line,
                                  end_line=line_no - 1,
                                  offset_comment=offset_comment)

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
                offset_comment = line.strip()
                start_line = line_no
                state = ReaderState.WANT_SIG

    return blocks
