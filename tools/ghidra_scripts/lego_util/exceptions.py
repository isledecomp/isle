class Lego1Exception(Exception):
    """
    Our own base class for exceptions.
    Makes it easier to distinguish expected and unexpected errors.
    """


class TypeNotFoundError(Lego1Exception):
    def __str__(self):
        return f"Type not found in PDB: {self.args[0]}"


class TypeNotFoundInGhidraError(Lego1Exception):
    def __str__(self):
        return f"Type not found in Ghidra: {self.args[0]}"


class TypeNotImplementedError(Lego1Exception):
    def __str__(self):
        return f"Import not implemented for type: {self.args[0]}"


class ClassOrNamespaceNotFoundInGhidraError(Lego1Exception):
    def __init__(self, namespaceHierachy: list[str]):
        super().__init__(namespaceHierachy)

    def get_namespace_str(self) -> str:
        return "::".join(self.args[0])

    def __str__(self):
        return f"Class or namespace not found in Ghidra: {self.get_namespace_str()}"


class MultipleTypesFoundInGhidraError(Lego1Exception):
    def __str__(self):
        return (
            f"Found multiple types matching '{self.args[0]}' in Ghidra: {self.args[1]}"
        )


class StackOffsetMismatchError(Lego1Exception):
    pass


class StructModificationError(Lego1Exception):
    def __str__(self):
        return f"Failed to modify struct in Ghidra: '{self.args[0]}'\nDetailed error: {self.__cause__}"
