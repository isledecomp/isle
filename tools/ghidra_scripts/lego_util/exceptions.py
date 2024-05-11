class Lego1Exception(Exception):
    pass


class TypeNotFoundInGhidraError(Lego1Exception):
    def __str__(self):
        return "Type not found in Ghidra: %s" % self.args[0]


class NamespaceNotFoundInGhidraError(Lego1Exception):
    def __init__(self, namespaceHierachy):  # type: (list[str]) -> None
        super(NamespaceNotFoundInGhidraError, self).__init__(namespaceHierachy)

    def get_namespace_str(self):  # type: () -> str
        return "::".join(self.args[0])

    def __str__(self):
        return "Class or namespace not found in Ghidra: %s" % self.get_namespace_str()


class FunctionNotFoundInGhidraError(Lego1Exception):
    def __str__(self):
        return "Function not found in Ghidra at %s" % self.args[0]


class MultipleTypesFoundInGhidraError(Lego1Exception):
    def __str__(self):
        return "Found multiple types matching '%s' in Ghidra: %s" % self.args


class UnsupportedCppSyntaxError(Lego1Exception):
    def __str__(self):
        return "C++ syntax currently not supported in the parser: %s" % self.args[0]


class CppUnknownClassOrNamespaceError(Lego1Exception):
    def __str__(self):
        return "'%s' is neither a known class nor namespace" % self.args[0]
