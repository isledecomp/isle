class Lego1Exception(Exception):
    pass


class TypeNotFoundInGhidraError(Lego1Exception):
    def __str__(self):
        return f"Type not found in Ghidra: {self.args[0]}"


class ClassOrNamespaceNotFoundInGhidraError(Lego1Exception):
    def __init__(self, namespaceHierachy: list[str]):
        super().__init__(namespaceHierachy)

    def get_namespace_str(self) -> str:
        return "::".join(self.args[0])

    def __str__(self):
        return f"Class or namespace not found in Ghidra: {self.get_namespace_str()}"


class FunctionNotFoundInGhidraError(Lego1Exception):
    def __str__(self):
        return f"Function not found in Ghidra at {self.args[0]}"


class MultipleTypesFoundInGhidraError(Lego1Exception):
    def __str__(self):
        return (
            f"Found multiple types matching '{self.args[0]}' in Ghidra: {self.args[1]}"
        )


class StackOffsetMismatchError(Lego1Exception):
    pass


class UnsupportedCppSyntaxError(Lego1Exception):
    def __str__(self):
        return f"C++ syntax currently not supported in the parser: {self.args[0]}"


class CppUnknownClassOrNamespaceError(Lego1Exception):
    def __str__(self):
        return f"'{self.args[0]}' is neither a known class nor namespace"
