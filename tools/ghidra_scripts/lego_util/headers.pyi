from typing import TypeVar, Any
import ghidra

# pylint: disable=invalid-name,unused-argument

T = TypeVar("T")

# from ghidra.app.script.GhidraScript
def currentProgram() -> "ghidra.program.model.listing.Program": ...
def getAddressFactory() -> " ghidra.program.model.address.AddressFactory": ...
def state() -> "ghidra.app.script.GhidraState": ...
def askChoice(title: str, message: str, choices: list[T], defaultValue: T) -> T: ...
def askYesNo(title: str, question: str) -> bool: ...
def getFunctionAt(
    entryPoint: ghidra.program.model.address.Address,
) -> ghidra.program.model.listing.Function: ...
def createFunction(
    entryPoint: ghidra.program.model.address.Address, name: str
) -> ghidra.program.model.listing.Function: ...
def getProgramFile() -> Any: ... # actually java.io.File
