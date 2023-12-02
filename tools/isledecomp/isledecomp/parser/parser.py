# C++ file parser

from typing import List, Iterable, Iterator
from enum import Enum
from .util import (
    DecompMarker,
    is_blank_or_comment,
    match_marker,
    is_marker_exact,
    get_synthetic_name,
    remove_trailing_comment,
)
from .node import (
    ParserAlert,
    ParserFunction,
    ParserVariable,
    ParserVtable,
)
from .error import ParserError


class ReaderState(Enum):
    SEARCH = 0
    WANT_SIG = 1
    IN_FUNC = 2
    IN_TEMPLATE = 3
    WANT_CURLY = 4
    IN_GLOBAL = 5
    IN_FUNC_GLOBAL = 6
    IN_VTABLE = 7


def marker_is_stub(marker: DecompMarker) -> bool:
    return marker.type.upper() == "STUB"


def marker_is_variable(marker: DecompMarker) -> bool:
    return marker.type.upper() == "GLOBAL"


def marker_is_synthetic(marker: DecompMarker) -> bool:
    return marker.type.upper() in ("SYNTHETIC", "TEMPLATE")


def marker_is_template(marker: DecompMarker) -> bool:
    return marker.type.upper() == "TEMPLATE"


def marker_is_function(marker: DecompMarker) -> bool:
    return marker.type.upper() in ("FUNCTION", "STUB")


def marker_is_vtable(marker: DecompMarker) -> bool:
    return marker.type.upper() == "VTABLE"


class MarkerDict:
    def __init__(self):
        self.markers: dict = {}

    def insert(self, marker: DecompMarker) -> bool:
        """Return True if this insert would overwrite"""
        module = marker.module.upper()
        if module in self.markers:
            return True

        self.markers[module] = (marker.type, marker.offset)
        return False

    def iter(self) -> Iterator[DecompMarker]:
        for module, (marker_type, offset) in self.markers.items():
            yield DecompMarker(marker_type, module, offset)

    def empty(self):
        self.markers = {}


class DecompParser:
    # pylint: disable=too-many-instance-attributes
    # Could combine output lists into a single list to get under the limit,
    # but not right now
    def __init__(self):
        # The lists to be populated as we parse
        self.functions: List[ParserFunction] = []
        self.vtables: List[ParserVtable] = []
        self.variables: List[ParserVariable] = []
        self.alerts: List[ParserAlert] = []

        self.line_number: int = 0
        self.state: ReaderState = ReaderState.SEARCH

        self.last_line: str = ""

        # To allow for multiple markers where code is shared across different
        # modules, save lists of compatible markers that appear in sequence
        self.fun_markers = MarkerDict()
        self.var_markers = MarkerDict()
        self.tbl_markers = MarkerDict()

        # To handle functions that are entirely indented (i.e. those defined
        # in class declarations), remember how many whitespace characters
        # came before the opening curly brace and match that up at the end.
        # This should give us the same or better accuracy for a well-formed file.
        # The alternative is counting the curly braces on each line
        # but that's probably too cumbersome.
        self.curly_indent_stops: int = 0

        # For non-synthetic functions, save the line number where the function begins
        # (i.e. where we see the curly brace) along with the function signature.
        # We will need both when we reach the end of the function.
        self.function_start: int = 0
        self.function_sig: str = ""

    def reset(self):
        self.functions = []
        self.vtables = []
        self.variables = []
        self.alerts = []

        self.line_number = 0
        self.state = ReaderState.SEARCH

        self.last_line = ""

        self.fun_markers.empty()
        self.var_markers.empty()
        self.tbl_markers.empty()

        self.curly_indent_stops = 0
        self.function_start = 0
        self.function_sig = ""

    def _recover(self):
        """We hit a syntax error and need to reset temp structures"""
        self.state = ReaderState.SEARCH
        self.fun_markers.empty()
        self.var_markers.empty()
        self.tbl_markers.empty()

    def _syntax_warning(self, code):
        self.alerts.append(
            ParserAlert(
                line_number=self.line_number,
                code=code,
                line=self.last_line.strip(),
            )
        )

    def _syntax_error(self, code):
        self._syntax_warning(code)
        self._recover()

    def _function_starts_here(self):
        self.function_start = self.line_number

    def _function_marker(self, marker: DecompMarker):
        if self.fun_markers.insert(marker):
            self._syntax_warning(ParserError.DUPLICATE_MODULE)
        self.state = ReaderState.WANT_SIG

    def _synthetic_marker(self, marker: DecompMarker):
        if self.fun_markers.insert(marker):
            self._syntax_warning(ParserError.DUPLICATE_MODULE)
        self.state = ReaderState.IN_TEMPLATE

    def _function_done(self, lookup_by_name: bool = False, unexpected: bool = False):
        end_line = self.line_number
        if unexpected:
            # If we missed the end of the previous function, assume it ended
            # on the previous line and that whatever we are tracking next
            # begins on the current line.
            end_line -= 1

        for marker in self.fun_markers.iter():
            self.functions.append(
                ParserFunction(
                    line_number=self.function_start,
                    module=marker.module,
                    offset=marker.offset,
                    lookup_by_name=lookup_by_name,
                    is_stub=marker_is_stub(marker),
                    is_synthetic=marker_is_synthetic(marker),
                    is_template=marker_is_template(marker),
                    name=self.function_sig,
                    end_line=end_line,
                )
            )

        self.fun_markers.empty()
        self.curly_indent_stops = 0
        self.state = ReaderState.SEARCH

    def _vtable_marker(self, marker: DecompMarker):
        if self.tbl_markers.insert(marker):
            self._syntax_warning(ParserError.DUPLICATE_MODULE)
        self.state = ReaderState.IN_VTABLE

    def _vtable_done(self):
        for marker in self.tbl_markers.iter():
            self.vtables.append(
                ParserVtable(
                    line_number=self.line_number,
                    module=marker.module,
                    offset=marker.offset,
                    class_name=self.last_line.strip(),
                )
            )

        self.tbl_markers.empty()
        self.state = ReaderState.SEARCH

    def _variable_marker(self, marker: DecompMarker):
        if self.var_markers.insert(marker):
            self._syntax_warning(ParserError.DUPLICATE_MODULE)

        if self.state in (ReaderState.IN_FUNC, ReaderState.IN_FUNC_GLOBAL):
            self.state = ReaderState.IN_FUNC_GLOBAL
        else:
            self.state = ReaderState.IN_GLOBAL

    def _variable_done(self):
        for marker in self.var_markers.iter():
            self.variables.append(
                ParserVariable(
                    line_number=self.line_number,
                    module=marker.module,
                    offset=marker.offset,
                    name=self.last_line.strip(),
                )
            )

        self.var_markers.empty()
        if self.state == ReaderState.IN_FUNC_GLOBAL:
            self.state = ReaderState.IN_FUNC
        else:
            self.state = ReaderState.SEARCH

    def _handle_marker(self, marker: DecompMarker):
        # Cannot handle any markers between function sig and opening curly brace
        if self.state == ReaderState.WANT_CURLY:
            self._syntax_error(ParserError.UNEXPECTED_MARKER)
            return

        # TODO: How uncertain are we of detecting the end of a function
        # in a clang-formatted file? For now we assume we have missed the
        # end if we detect a non-GLOBAL marker while state is IN_FUNC.
        # Maybe these cases should be syntax errors instead

        if marker_is_function(marker):
            if self.state in (
                ReaderState.SEARCH,
                ReaderState.WANT_SIG,
            ):
                # We will allow multiple offsets if we have just begun
                # the code block, but not after we hit the curly brace.
                self._function_marker(marker)
            elif self.state == ReaderState.IN_FUNC:
                # We hit another offset unexpectedly.
                # We can recover easily by just ending the function here.
                self._syntax_warning(ParserError.MISSED_END_OF_FUNCTION)
                self._function_done(unexpected=True)

                # Start the next function right after so we can
                # read the next line.
                self._function_marker(marker)
            else:
                self._syntax_error(ParserError.INCOMPATIBLE_MARKER)

        elif marker_is_synthetic(marker):
            if self.state in (ReaderState.SEARCH, ReaderState.IN_TEMPLATE):
                self._synthetic_marker(marker)
            elif self.state == ReaderState.IN_FUNC:
                self._syntax_warning(ParserError.MISSED_END_OF_FUNCTION)
                self._function_done(lookup_by_name=True, unexpected=True)
                self._synthetic_marker(marker)
            else:
                self._syntax_error(ParserError.INCOMPATIBLE_MARKER)

        elif marker_is_variable(marker):
            if self.state in (
                ReaderState.SEARCH,
                ReaderState.IN_GLOBAL,
                ReaderState.IN_FUNC,
                ReaderState.IN_FUNC_GLOBAL,
            ):
                self._variable_marker(marker)
            else:
                self._syntax_error(ParserError.INCOMPATIBLE_MARKER)

        elif marker_is_vtable(marker):
            if self.state in (ReaderState.SEARCH, ReaderState.IN_VTABLE):
                self._vtable_marker(marker)
            elif self.state == ReaderState.IN_FUNC:
                self._syntax_warning(ParserError.MISSED_END_OF_FUNCTION)
                self._function_done(unexpected=True)
                self._vtable_marker(marker)
            else:
                self._syntax_error(ParserError.INCOMPATIBLE_MARKER)

        else:
            self._syntax_warning(ParserError.BOGUS_MARKER)

    def read_line(self, line: str):
        self.last_line = line  # TODO: Useful or hack for error reporting?
        self.line_number += 1

        marker = match_marker(line)
        if marker is not None:
            # TODO: what's the best place for this?
            # Does it belong with reading or marker handling?
            if not is_marker_exact(self.last_line):
                self._syntax_warning(ParserError.BAD_DECOMP_MARKER)
            self._handle_marker(marker)
            return

        line_strip = line.strip()
        if self.state == ReaderState.IN_TEMPLATE:
            # TEMPLATE functions are a special case. The signature is
            # given on the next line (in a // comment)
            name = get_synthetic_name(line)
            if name is None:
                self._syntax_error(ParserError.BAD_SYNTHETIC)
            else:
                self.function_sig = name
                self._function_starts_here()
                self._function_done(lookup_by_name=True)

        elif self.state == ReaderState.WANT_SIG:
            # Ignore blanks on the way to function start or function name
            if len(line_strip) == 0:
                self._syntax_warning(ParserError.UNEXPECTED_BLANK_LINE)

            elif line_strip.startswith("//"):
                # If we found a comment, assume implicit lookup-by-name
                # function and end here. We know this is not a decomp marker
                # because it would have been handled already.
                self.function_sig = get_synthetic_name(line)
                self._function_starts_here()
                self._function_done(lookup_by_name=True)

            elif line_strip == "{":
                # We missed the function signature but we can recover from this
                self.function_sig = "(unknown)"
                self._function_starts_here()
                self._syntax_warning(ParserError.MISSED_START_OF_FUNCTION)
                self.state = ReaderState.IN_FUNC

            else:
                # Inline functions may end with a comment. Strip that out
                # to help parsing.
                self.function_sig = remove_trailing_comment(line_strip)

                # Now check to see if the opening curly bracket is on the
                # same line. clang-format should prevent this (BraceWrapping)
                # but it is easy to detect.
                # If the entire function is on one line, handle that too.
                if self.function_sig.endswith("{"):
                    self._function_starts_here()
                    self.state = ReaderState.IN_FUNC
                elif self.function_sig.endswith("}") or self.function_sig.endswith(
                    "};"
                ):
                    self._function_starts_here()
                    self._function_done()
                else:
                    self.state = ReaderState.WANT_CURLY

        elif self.state == ReaderState.WANT_CURLY:
            if line_strip == "{":
                self.curly_indent_stops = line.index("{")
                self._function_starts_here()
                self.state = ReaderState.IN_FUNC

        elif self.state == ReaderState.IN_FUNC:
            if line_strip.startswith("}") and line[self.curly_indent_stops] == "}":
                self._function_done()

        elif self.state in (ReaderState.IN_GLOBAL, ReaderState.IN_FUNC_GLOBAL):
            if not is_blank_or_comment(line):
                self._variable_done()

        elif self.state == ReaderState.IN_VTABLE:
            if not is_blank_or_comment(line):
                self._vtable_done()

    def read_lines(self, lines: Iterable):
        for line in lines:
            self.read_line(line)
