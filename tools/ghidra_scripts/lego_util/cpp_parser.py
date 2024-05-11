import re

from lego_util.exceptions import (
    UnsupportedCppSyntaxError,
    CppUnknownClassOrNamespaceError,
)

function_regex = re.compile(r"\s*// FUNCTION: LEGO1 0x(\w{8})")

class_regex = re.compile(r"\n\s*class\s(\w+)")

struct_regex = re.compile(r"\n\s*struct\s(\w+)")

namespace_regex = re.compile(r"\n\s*namespace\s(\w+)")


class CppFunctionDeclaration:
    """
    A rudimentary parser for C++ function signatures in LEGO1.
    Assumes that the C++ code has been formatted to some degree.
    """

    def __init__(
        self, fn, start_index, classes_and_structs
    ):  # type: (CppFunctionDeclaration, str, int, set[str]) -> None
        first_part_str, second_part = self._split_off_declaration_and_arguments(
            fn[start_index:]
        )

        try:
            first_part = first_part_str.split(" ")
            full_function_name = first_part.pop()
            colon_split = full_function_name.split("::")
            self.name = colon_split.pop()
            self.namespace_hierachy = colon_split

            if first_part:
                while True:
                    # desired failure if we only get keywords and no return type
                    self.return_type = first_part.pop(0)
                    if self.return_type not in ["const", "inline"]:
                        break
            else:
                # most likely a constructor or destructor
                assert self.namespace_hierachy is not None, (
                    "Unhandled function without return type or namespace: " + fn
                )
                if self.name.startswith("~"):
                    self.return_type = "void"
                else:
                    self.return_type = self.name + "*"

            # evaluate if we belong to a class, assume __thiscall
            self.class_name = None
            if self.namespace_hierachy:
                bottom_level_namespace = self.namespace_hierachy[-1]
                if bottom_level_namespace in classes_and_structs:
                    self.class_name = bottom_level_namespace
                else:
                    raise CppUnknownClassOrNamespaceError(bottom_level_namespace)

            # don't add a `this` argument, let Ghidra handle that
            self.flags = first_part
            if second_part.strip():
                self.arguments = [
                    self._parse_argument(i, x)
                    for i, x in enumerate(second_part.split(","))
                ]
            else:
                self.arguments = []

        except UnsupportedCppSyntaxError as e:
            raise UnsupportedCppSyntaxError(
                "%s. In: '%s(%s)'" % (e.args[0], first_part_str, second_part)
            )

    def __str__(self):
        flags = " ".join(self.flags)
        full_name = self.full_name()
        args = ["%s %s" % pair for pair in self.arguments]
        if self.class_name:
            # add the "this" argument to the output
            args = [("%s* this" % self.class_name)] + args
            return "%s __thiscall %s%s(%s)" % (
                self.return_type,
                flags,
                full_name,
                ", ".join(args),
            )

        return "%s %s%s(%s)" % (self.return_type, flags, full_name, ", ".join(args))

    def full_name(self):
        return "::".join(self.namespace_hierachy + [self.name])

    def _parse_argument(
        self, index, argument_str
    ):  # type: (int, str) -> tuple[str, str]
        """Returns: (type, name)"""
        # Cleanup, handle `const`
        split = (x.strip() for x in argument_str.split(" "))
        filtered = [x for x in split if len(x) > 0 and x.lower() != "const"]

        if len(filtered) == 0:
            raise UnsupportedCppSyntaxError(
                "Expected more arguments: '%s'" % argument_str.strip()
            )
        if len(filtered) == 1:
            # unnamed argument
            return (filtered[0], "param%d" % (index + 1))
        if len(filtered) == 2:
            return (filtered[0], filtered[1])

        raise UnsupportedCppSyntaxError(
            "Unsupported argument syntax: '%s'" % argument_str.strip()
        )

    def _split_off_declaration_and_arguments(
        self, fn
    ):  # type: (str) -> tuple[str, str]
        # handle `unsigned` in arguments and result
        fn = fn.replace("unsigned ", "u")
        first_paren = fn.find("(")
        assert first_paren >= 0, "No opening parenthesis found in function '%s'" % fn

        paren_stack = 1
        close_paren = first_paren
        while paren_stack > 0:
            # In case of unmatched parentheses we run into an IndexError,
            # which is expected behaviour
            close_paren += 1
            if fn[close_paren] == "(":
                paren_stack += 1
            elif fn[close_paren] == ")":
                paren_stack -= 1

        return (
            fn[:first_paren].replace("\n", ""),
            fn[first_paren + 1 : close_paren].replace("\n", ""),
        )
