# C++ file parser

from typing import List, Iterable, Iterator, Optional
from enum import Enum
from .util import (
    get_class_name,
    get_variable_name,
    get_synthetic_name,
    remove_trailing_comment,
    get_string_contents,
    sanitize_code_line,
    scopeDetectRegex,
)
from .marker import (
    DecompMarker,
    MarkerCategory,
    match_marker,
    is_marker_exact,
)
from .node import (
    ParserSymbol,
    ParserFunction,
    ParserVariable,
    ParserVtable,
    ParserString,
)
from .error import ParserAlert, ParserError


class ReaderState(Enum):
    SEARCH = 0
    WANT_SIG = 1
    IN_FUNC = 2
    IN_TEMPLATE = 3
    WANT_CURLY = 4
    IN_GLOBAL = 5
    IN_FUNC_GLOBAL = 6
    IN_VTABLE = 7
    IN_SYNTHETIC = 8
    IN_LIBRARY = 9
    DONE = 100


class MarkerDict:
    def __init__(self) -> None:
        self.markers: dict = {}

    def insert(self, marker: DecompMarker) -> bool:
        """Return True if this insert would overwrite"""
        key = (marker.category, marker.module)
        if key in self.markers:
            return True

        self.markers[key] = marker
        return False

    def query(self, category: MarkerCategory, module: str) -> Optional[DecompMarker]:
        return self.markers.get((category, module))

    def iter(self) -> Iterator[DecompMarker]:
        for _, marker in self.markers.items():
            yield marker

    def empty(self):
        self.markers = {}


class CurlyManager:
    """Overly simplified scope manager"""

    def __init__(self):
        self._stack = []

    def reset(self):
        self._stack = []

    def _pop(self):
        """Pop stack safely"""
        try:
            self._stack.pop()
        except IndexError:
            pass

    def get_prefix(self, name: Optional[str] = None) -> str:
        """Return the prefix for where we are."""

        scopes = [t for t in self._stack if t != "{"]
        if len(scopes) == 0:
            return name if name is not None else ""

        if name is not None and name not in scopes:
            scopes.append(name)

        return "::".join(scopes)

    def read_line(self, raw_line: str):
        """Read a line of code and update the stack."""
        line = sanitize_code_line(raw_line)
        if (match := scopeDetectRegex.match(line)) is not None:
            if not line.endswith(";"):
                self._stack.append(match.group("name"))

        change = line.count("{") - line.count("}")
        if change > 0:
            for _ in range(change):
                self._stack.append("{")
        elif change < 0:
            for _ in range(-change):
                self._pop()

            if len(self._stack) == 0:
                return

            last = self._stack[-1]
            if last != "{":
                self._pop()


class DecompParser:
    # pylint: disable=too-many-instance-attributes
    # Could combine output lists into a single list to get under the limit,
    # but not right now
    def __init__(self) -> None:
        # The lists to be populated as we parse
        self._symbols: List[ParserSymbol] = []
        self.alerts: List[ParserAlert] = []

        self.line_number: int = 0
        self.state: ReaderState = ReaderState.SEARCH

        self.last_line: str = ""

        self.curly = CurlyManager()

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
        self._symbols = []
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

        self.curly.reset()

    @property
    def functions(self) -> List[ParserFunction]:
        return [s for s in self._symbols if isinstance(s, ParserFunction)]

    @property
    def vtables(self) -> List[ParserVtable]:
        return [s for s in self._symbols if isinstance(s, ParserVtable)]

    @property
    def variables(self) -> List[ParserVariable]:
        return [s for s in self._symbols if isinstance(s, ParserVariable)]

    @property
    def strings(self) -> List[ParserString]:
        return [s for s in self._symbols if isinstance(s, ParserString)]

    def iter_symbols(self, module: Optional[str] = None) -> Iterator[ParserSymbol]:
        for s in self._symbols:
            if module is None or s.module == module:
                yield s

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

    def _nameref_marker(self, marker: DecompMarker):
        """Functions explicitly referenced by name are set here"""
        if self.fun_markers.insert(marker):
            self._syntax_warning(ParserError.DUPLICATE_MODULE)

        if marker.is_template():
            self.state = ReaderState.IN_TEMPLATE
        elif marker.is_synthetic():
            self.state = ReaderState.IN_SYNTHETIC
        else:
            self.state = ReaderState.IN_LIBRARY

    def _function_done(self, lookup_by_name: bool = False, unexpected: bool = False):
        end_line = self.line_number
        if unexpected:
            # If we missed the end of the previous function, assume it ended
            # on the previous line and that whatever we are tracking next
            # begins on the current line.
            end_line -= 1

        for marker in self.fun_markers.iter():
            self._symbols.append(
                ParserFunction(
                    type=marker.type,
                    line_number=self.function_start,
                    module=marker.module,
                    offset=marker.offset,
                    name=self.function_sig,
                    lookup_by_name=lookup_by_name,
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

    def _vtable_done(self, class_name: str = None):
        if class_name is None:
            # Best we can do
            class_name = self.last_line.strip()

        for marker in self.tbl_markers.iter():
            self._symbols.append(
                ParserVtable(
                    type=marker.type,
                    line_number=self.line_number,
                    module=marker.module,
                    offset=marker.offset,
                    name=self.curly.get_prefix(class_name),
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

    def _variable_done(
        self, variable_name: Optional[str] = None, string_value: Optional[str] = None
    ):
        if variable_name is None and string_value is None:
            self._syntax_error(ParserError.NO_SUITABLE_NAME)
            return

        for marker in self.var_markers.iter():
            if marker.is_string():
                self._symbols.append(
                    ParserString(
                        type=marker.type,
                        line_number=self.line_number,
                        module=marker.module,
                        offset=marker.offset,
                        name=string_value,
                    )
                )
            else:
                parent_function = None
                is_static = self.state == ReaderState.IN_FUNC_GLOBAL

                # If this is a static variable, we need to get the function
                # where it resides so that we can match it up later with the
                # mangled names of both variable and function from cvdump.
                if is_static:
                    fun_marker = self.fun_markers.query(
                        MarkerCategory.FUNCTION, marker.module
                    )

                    if fun_marker is None:
                        self._syntax_warning(ParserError.ORPHANED_STATIC_VARIABLE)
                        continue

                    parent_function = fun_marker.offset

                self._symbols.append(
                    ParserVariable(
                        type=marker.type,
                        line_number=self.line_number,
                        module=marker.module,
                        offset=marker.offset,
                        name=self.curly.get_prefix(variable_name),
                        is_static=is_static,
                        parent_function=parent_function,
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

        # If we are inside a function, the only markers we accept are:
        # GLOBAL, indicating a static variable
        # STRING, indicating a literal string.
        # Otherwise we assume that the parser missed the end of the function
        # and we have moved on to something else.
        # This is unlikely to occur with well-formed code, but
        # we can recover easily by just ending the function here.
        if self.state == ReaderState.IN_FUNC and not marker.allowed_in_func():
            self._syntax_warning(ParserError.MISSED_END_OF_FUNCTION)
            self._function_done(unexpected=True)

        # TODO: How uncertain are we of detecting the end of a function
        # in a clang-formatted file? For now we assume we have missed the
        # end if we detect a non-GLOBAL marker while state is IN_FUNC.
        # Maybe these cases should be syntax errors instead

        if marker.is_regular_function():
            if self.state in (
                ReaderState.SEARCH,
                ReaderState.WANT_SIG,
            ):
                # We will allow multiple offsets if we have just begun
                # the code block, but not after we hit the curly brace.
                self._function_marker(marker)
            else:
                self._syntax_error(ParserError.INCOMPATIBLE_MARKER)

        elif marker.is_template():
            if self.state in (ReaderState.SEARCH, ReaderState.IN_TEMPLATE):
                self._nameref_marker(marker)
            else:
                self._syntax_error(ParserError.INCOMPATIBLE_MARKER)

        elif marker.is_synthetic():
            if self.state in (ReaderState.SEARCH, ReaderState.IN_SYNTHETIC):
                self._nameref_marker(marker)
            else:
                self._syntax_error(ParserError.INCOMPATIBLE_MARKER)

        elif marker.is_library():
            if self.state in (ReaderState.SEARCH, ReaderState.IN_LIBRARY):
                self._nameref_marker(marker)
            else:
                self._syntax_error(ParserError.INCOMPATIBLE_MARKER)

        # Strings and variables are almost the same thing
        elif marker.is_string() or marker.is_variable():
            if self.state in (
                ReaderState.SEARCH,
                ReaderState.IN_GLOBAL,
                ReaderState.IN_FUNC,
                ReaderState.IN_FUNC_GLOBAL,
            ):
                self._variable_marker(marker)
            else:
                self._syntax_error(ParserError.INCOMPATIBLE_MARKER)

        elif marker.is_vtable():
            if self.state in (ReaderState.SEARCH, ReaderState.IN_VTABLE):
                self._vtable_marker(marker)
            else:
                self._syntax_error(ParserError.INCOMPATIBLE_MARKER)

        else:
            self._syntax_warning(ParserError.BOGUS_MARKER)

    def read_line(self, line: str):
        if self.state == ReaderState.DONE:
            return

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

        self.curly.read_line(line)

        line_strip = line.strip()
        if self.state in (
            ReaderState.IN_SYNTHETIC,
            ReaderState.IN_TEMPLATE,
            ReaderState.IN_LIBRARY,
        ):
            # Explicit nameref functions provide the function name
            # on the next line (in a // comment)
            name = get_synthetic_name(line)
            if name is None:
                self._syntax_error(ParserError.BAD_NAMEREF)
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
                elif self.function_sig.endswith(");"):
                    # Detect forward reference or declaration
                    self._syntax_error(ParserError.NO_IMPLEMENTATION)
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
            # TODO: Known problem that an error here will cause us to abandon a
            # function we have already parsed if state == IN_FUNC_GLOBAL.
            # However, we are not tolerant of _any_ syntax problems in our
            # CI actions, so the solution is to just fix the invalid marker.
            variable_name = None

            global_markers_queued = any(
                m.is_variable() for m in self.var_markers.iter()
            )

            if len(line_strip) == 0:
                self._syntax_warning(ParserError.UNEXPECTED_BLANK_LINE)
                return

            if global_markers_queued:
                # Not the greatest solution, but a consequence of combining GLOBAL and
                # STRING markers together. If the marker precedes a return statement, it is
                # valid for a STRING marker to be here, but not a GLOBAL. We need to look
                # ahead and tell whether this *would* fail.
                if line_strip.startswith("return"):
                    self._syntax_error(ParserError.GLOBAL_NOT_VARIABLE)
                    return
                if line_strip.startswith("//"):
                    # If we found a comment, assume implicit lookup-by-name
                    # function and end here. We know this is not a decomp marker
                    # because it would have been handled already.
                    variable_name = get_synthetic_name(line)
                else:
                    variable_name = get_variable_name(line)
                    # This is out of our control for library variables, but all of our
                    # variables should start with "g_".
                    if variable_name is not None:
                        # Before checking for the prefix, remove the
                        # namespace chain if there is one.
                        if not variable_name.split("::")[-1].startswith("g_"):
                            self._syntax_warning(ParserError.GLOBAL_MISSING_PREFIX)

            string_name = get_string_contents(line)

            self._variable_done(variable_name, string_name)

        elif self.state == ReaderState.IN_VTABLE:
            vtable_class = get_class_name(line)
            if vtable_class is not None:
                self._vtable_done(class_name=vtable_class)

    def read_lines(self, lines: Iterable):
        for line in lines:
            self.read_line(line)

    def finish(self):
        if self.state != ReaderState.SEARCH:
            self._syntax_warning(ParserError.UNEXPECTED_END_OF_FILE)

        self.state = ReaderState.DONE
