from enum import Enum
from typing import Optional
from dataclasses import dataclass


# TODO: poorly chosen name, should be AlertType or AlertCode or something
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

    # WARN: We called the finish() method for the parser but had not reached the starting
    # state of SEARCH
    UNEXPECTED_END_OF_FILE = 108

    # WARN: We found a marker to be referenced by name outside of a header file.
    BYNAME_FUNCTION_IN_CPP = 109

    # WARN: A GLOBAL marker appeared over a variable without the g_ prefix
    GLOBAL_MISSING_PREFIX = 110

    # WARN: GLOBAL marker points at something other than variable declaration.
    # We can't match global variables based on position, but the goal here is
    # to ignore things like string literal that are not variables.
    GLOBAL_NOT_VARIABLE = 111

    # This code or higher is an error, not a warning
    DECOMP_ERROR_START = 200

    # ERROR: We found a marker unexpectedly
    UNEXPECTED_MARKER = 200

    # ERROR: We found a marker where we expected to find one, but it is incompatible
    # with the preceding markers.
    # For example, a GLOBAL cannot follow FUNCTION/STUB
    INCOMPATIBLE_MARKER = 201

    # ERROR: The line following an explicit by-name marker was not a comment
    # We assume a syntax error here rather than try to use the next line
    BAD_NAMEREF = 202

    # ERROR: This function offset comes before the previous offset from the same module
    # This hopefully gives some hint about which functions need to be rearranged.
    FUNCTION_OUT_OF_ORDER = 203

    # ERROR: The line following an explicit by-name marker that does _not_ expect
    # a comment -- i.e. VTABLE or GLOBAL -- could not extract the name
    NO_SUITABLE_NAME = 204

    # ERROR: Two STRING markers have the same module and offset, but the strings
    # they annotate are different.
    WRONG_STRING = 205


@dataclass
class ParserAlert:
    code: ParserError
    line_number: int
    line: Optional[str] = None

    def is_warning(self) -> bool:
        return self.code.value < ParserError.DECOMP_ERROR_START.value

    def is_error(self) -> bool:
        return self.code.value >= ParserError.DECOMP_ERROR_START.value
