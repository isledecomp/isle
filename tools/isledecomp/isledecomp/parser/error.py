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

    # WARN: Under a synthetic marker we expected a comment but found a code line instead
    SYNTHETIC_NOT_COMMENT = 110

    # WARN: New function marker appeared while we were inside a function
    MISSED_END_OF_FUNCTION = 117

    # ERROR: We found a marker unexpectedly
    UNEXPECTED_MARKER = 200

    # ERROR: We found a marker where we expected to find one, but it is incompatible
    # with the preceding markers.
    # For example, a GLOBAL cannot follow FUNCTION/STUB
    INCOMPATIBLE_MARKER = 201
