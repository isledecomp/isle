from enum import Enum


class ParserError(Enum):
    # WARN: Stub function exceeds some line number threshold
    UNLIKELY_STUB = 100

    # WARN: Decomp marker is close enough to be recognized, but does not follow syntax exactly
    BAD_DECOMP_MARKER = 101

    # WARN: Multiple markers in sequence do not have distinct modules
    DUPLICATE_MODULE = 102

    # WARN: Detected a dupcliate module/offset pair in the current file
    DUPLICATE_OFFSET = 103

    # WARN: We read a line that matches the decomp marker pattern, but we are not set up
    # to handle it
    BOGUS_MARKER = 104

    # WARN: New function marker appeared while we were inside a function
    MISSED_END_OF_FUNCTION = 105

    # WARN: If we find a curly brace right after the function declaration
    # this is wrong but we still have enough to make a match with reccmp
    MISSED_START_OF_FUNCTION = 106

    # WARN: A blank line appeared between the end of FUNCTION markers
    # and the start of the function. We can ignore it, but the line shouldn't be there
    UNEXPECTED_BLANK_LINE = 107

    # ERROR: We found a marker unexpectedly
    UNEXPECTED_MARKER = 200

    # ERROR: We found a marker where we expected to find one, but it is incompatible
    # with the preceding markers.
    # For example, a GLOBAL cannot follow FUNCTION/STUB
    INCOMPATIBLE_MARKER = 201

    # ERROR: The line following a synthetic marker was not a comment
    BAD_SYNTHETIC = 202
