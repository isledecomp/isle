from .parser import DecompParser
from .error import ParserAlert, ParserError


def get_checkorder_filter(module):
    """Return a filter function on implemented functions in the given module"""
    return lambda fun: fun.module == module and not fun.lookup_by_name


class DecompLinter:
    def __init__(self):
        self.alerts = []
        self._parser = DecompParser()
        self._filename = ""
        self._module = None

    def reset(self):
        self.alerts = []
        self._parser.reset()
        self._filename = ""
        self._module = None

    def file_is_header(self):
        return self._filename.lower().endswith(".h")

    def _check_function_order(self):
        """Rules:
        1. Only markers that are implemented in the file are considered. This means we
        only look at markers that are cross-referenced with cvdump output by their line
        number. Markers with the lookup_by_name flag set are ignored because we cannot
        directly influence their order.

        2. Order should be considered for a single module only. If we have multiple
        markers for a single function (i.e. for LEGO1 functions linked statically to
        ISLE) then the virtual address space will be very different. If we don't check
        for one module only, we would incorrectly report that the file is out of order.
        """

        if self._module is None:
            return

        checkorder_filter = get_checkorder_filter(self._module)
        last_offset = None
        for fun in filter(checkorder_filter, self._parser.functions):
            if last_offset is not None:
                if fun.offset < last_offset:
                    self.alerts.append(
                        ParserAlert(
                            code=ParserError.FUNCTION_OUT_OF_ORDER,
                            line_number=fun.line_number,
                        )
                    )

            last_offset = fun.offset

    def _check_symbol_uniqueness(self):
        # TODO
        pass

    def _check_byname_allowed(self):
        if self.file_is_header():
            return

        for fun in self._parser.functions:
            if fun.lookup_by_name:
                self.alerts.append(
                    ParserAlert(
                        code=ParserError.BYNAME_FUNCTION_IN_CPP,
                        line_number=fun.line_number,
                    )
                )

    def check_lines(self, lines, filename, module=None):
        """`lines` is a generic iterable to allow for testing with a list of strings.
        We assume lines has the entire contents of the compilation unit."""

        self.reset()
        self._filename = filename
        self._module = module

        self._parser.read_lines(lines)

        self._parser.finish()
        self.alerts = self._parser.alerts[::]

        if self._module is not None:
            self._check_byname_allowed()
            self._check_symbol_uniqueness()

            if not self.file_is_header():
                self._check_function_order()

        return len(self.alerts) == 0

    def check_file(self, filename, module=None):
        """Convenience method for decomplint cli tool"""
        with open(filename, "r", encoding="utf-8") as f:
            return self.check_lines(f, filename, module)
