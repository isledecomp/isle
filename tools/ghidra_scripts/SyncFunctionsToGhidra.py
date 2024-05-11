# Synchronised the function signatures of LEGO1.dll to Ghidra.
# At startup there will be several prompts for different modes,
# including a read-only / dry run mode.

# @author J. Schulz
# @category LEGO1
# @keybinding
# @menupath
# @toolbar


# Disable spurious warnings in vscode / pylance
# pyright: reportMissingModuleSource=false

import sys
import os
import re
import traceback
import logging

from lego_util.cpp_parser import (
    CppFunctionDeclaration,
    function_regex,
    class_regex,
    struct_regex,
    namespace_regex,
)
from lego_util.file_helper import iterate_dir
from lego_util.exceptions import (
    Lego1Exception,
    NamespaceNotFoundInGhidraError,
    TypeNotFoundInGhidraError,
    FunctionNotFoundInGhidraError,
)

# # no effect when no Ghidra is used
# READ_ONLY = False
# # READ_ONLY = True


# Type annotations are only available in Python 3.5 or later
if sys.version_info.major > 2:
    from typing import TYPE_CHECKING, TypeVar

    if TYPE_CHECKING:
        from ghidra.program.model.address import Address, AddressFactory
        from ghidra.program.model.listing import Program
        from ghidra.program.model.data import DataType
        from ghidra.program.model.symbol import Namespace
        from ghidra.app.script import GhidraScript
        from ghidra.app.script import GhidraState

        # Global stubs, Python 2 and 3 compatible

        def _get_state():  # type: () -> GhidraState
            return None  # type: ignore

        state = _get_state()

        def getDataTypes(name):  # type: (str) -> list[DataType]
            return  # type: ignore

        def getCurrentProgram():  # type: () -> Program
            return  # type: ignore

        def getFunctionAt(entryPoint):  # type: (Address) -> Function
            return  # type: ignore

        def getAddressFactory():  # type: () -> AddressFactory
            return  # type: ignore

        def getNamespace(parent, namespaceName):  # type: (Namespace, str) -> Namespace
            return  # type: ignore

        def askYesNo(title, message):  # type: (str, str) -> bool
            return  # type: ignore

        T = TypeVar("T")

        def askChoice(
            title, message, choices, defaultValue
        ):  # type: (str, str, list[T], T) -> T
            return  # type: ignore


# This script can be run both from Ghidra and as a standalone.
# In the latter case, only the C++ parser can be used.
try:
    from ghidra.program.model.listing import Function
    from ghidra.program.flatapi import FlatProgramAPI

    from lego_util.ghidra_helper import CppFunctionWithGhidraTypes

    # This is needed for Ghidra API calls in submodules
    API = FlatProgramAPI(state.getCurrentProgram())

    MAKE_CHANGES = askYesNo(
        "Make changes?", "Select 'Yes' to apply changes, select 'No' to do a dry run."
    )

    if MAKE_CHANGES:
        PROMPT_BEFORE_CHANGE = askYesNo(
            "Prompt before changes?", "Should each change be confirmed by a prompt?"
        )
    else:
        # for the linter, has no effect anyway
        PROMPT_BEFORE_CHANGE = True

    RUNNING_FROM_GHIDRA = True
except ImportError:
    RUNNING_FROM_GHIDRA = False
    MAKE_CHANGES = False


CLASSES_AND_STRUCTS = set()  # type: set[str]
NAMESPACES = set()  # type: set[str]

SUCCESSES = 0
FAILURES = {}  # type: dict[str, int]
KNOWN_MISSING_TYPES = {}  # type: dict[str, int]
KNOWN_MISSING_NAMESPACES = set()  # type: set[str]

FUNCTIONS_CHANGED = 0


def main():
    logging.basicConfig(
        format="%(levelname)-8s %(message)s", stream=sys.stdout, level=logging.INFO
    )
    if not RUNNING_FROM_GHIDRA:
        logging.error(
            "Failed to import Ghidra functions, doing a dry run for the source code parser. "
            "Has this script been launched from Ghidra?"
        )
    # navigate to this repository's root and then down to the LEGO1 source
    root_dir = os.path.join(os.path.dirname(__file__), "..", "..", "LEGO1")

    try:
        # Collect classes and structs first
        iterate_dir(root_dir, search_for_classes_and_structs)

        # Now do the real work
        iterate_dir(root_dir, search_and_process_functions)
    finally:
        # output statistics even when aborting
        missing_type_list = [
            "%s (%d)" % entry
            for entry in sorted(
                KNOWN_MISSING_TYPES.items(), key=lambda x: x[1], reverse=True
            )
        ]

        logging.info(
            "Missing types: (with number of occurences): %s",
            ", ".join(missing_type_list),
        )
        logging.info("Successes: %d", SUCCESSES)
        logging.info("Failures: %s", FAILURES)
        logging.info("Functions changed: %d", FUNCTIONS_CHANGED)


def log_and_track_failure(
    file_path, error, unexpected=False
):  # type: (str, Exception, bool) -> None
    error_type_name = error.__class__.__name__
    FAILURES[error_type_name] = FAILURES.setdefault(error_type_name, 0) + 1

    if isinstance(error, TypeNotFoundInGhidraError):
        missing_type = error.args[0]
        current_count = KNOWN_MISSING_TYPES.setdefault(missing_type, 0)
        KNOWN_MISSING_TYPES[missing_type] = current_count + 1
        if current_count > 0:
            # Log each missing type only once to reduce log noise
            return

    if isinstance(error, NamespaceNotFoundInGhidraError):
        namespace = error.get_namespace_str()
        if namespace in KNOWN_MISSING_NAMESPACES:
            # Log each missing namespace only once to reduce log noise
            return

        KNOWN_MISSING_NAMESPACES.add(namespace)

    logging.error(
        "%s%s: %s",
        "Unexpected error in " if unexpected else "",
        os.path.basename(file_path),
        error,
    )


def handle_function(lines, startIndex, address):  # type: (str, int, str) -> None
    global FUNCTIONS_CHANGED

    # Parse the C++ function
    while re.match(r"\s*//", lines[startIndex:]):
        startIndex = lines.find("\n", startIndex + 1)
    cpp_function = CppFunctionDeclaration(lines, startIndex, CLASSES_AND_STRUCTS)

    if cpp_function.return_type in CLASSES_AND_STRUCTS:
        # edge case handling - Ghidra does not understand what happens under the hood.
        # These must be set manually
        logging.error(
            "Unimplemented edge case at 0x%s: Return value is a non-referenced struct or class: %s",
            address,
            cpp_function,
        )
        return

    if not RUNNING_FROM_GHIDRA:
        return

    # Find the Ghidra function at that address
    ghidra_address = getAddressFactory().getAddress(address)
    ghidra_function = getFunctionAt(ghidra_address)
    if ghidra_function is None:
        raise FunctionNotFoundInGhidraError(address)

    # Convert the C++ data types to Ghidra data types
    typed_cpp_function = CppFunctionWithGhidraTypes(API, cpp_function)

    if typed_cpp_function.matches_ghidra_function(ghidra_function):
        logging.debug(
            "Skipping function '%s', matches already", cpp_function.full_name()
        )
        return

    if not MAKE_CHANGES:
        return

    # Navigate Ghidra to the current function
    state.setCurrentAddress(ghidra_address)

    if PROMPT_BEFORE_CHANGE:
        choice = askChoice(
            "Change function?",
            "Change to %s" % cpp_function,
            ["Yes", "No", "Abort"],
            "Yes",
        )
        if choice == "No":
            return
        if choice != "Yes":
            logging.critical("User quit, terminating")
            raise SystemExit(1)

    logging.info("Modifying function %s at 0x%s", cpp_function.full_name(), address)

    typed_cpp_function.overwrite_ghidra_function(ghidra_function)

    FUNCTIONS_CHANGED += 1

    if PROMPT_BEFORE_CHANGE:
        # Add a prompt so we can verify the result immediately
        askChoice("", "Click 'OK' to continue", ["OK"], "OK")


def search_for_classes_and_structs(header_file):  # type: (str) -> None
    global CLASSES_AND_STRUCTS, NAMESPACES

    if not (header_file.endswith(".h") or header_file.endswith(".cpp")):
        return
    try:
        with open(header_file) as infile:
            headers = infile.read()
    except Exception:
        logging.error(
            "Error handling header file: %s\n%s", header_file, traceback.format_exc()
        )
        return

    CLASSES_AND_STRUCTS = CLASSES_AND_STRUCTS.union(class_regex.findall(headers))
    CLASSES_AND_STRUCTS = CLASSES_AND_STRUCTS.union(struct_regex.findall(headers))
    NAMESPACES = NAMESPACES.union(namespace_regex.findall(headers))


def search_and_process_functions(path):  # type: (str) -> None
    global SUCCESSES
    if not path.endswith(".cpp"):
        return

    with open(path, "r") as file:
        lines = file.read()

    # search for '// FUNCTION: LEGO1 0x[...]'
    for match in function_regex.finditer(lines):
        next_line_index = lines.find("\n", match.end()) + 1
        try:
            handle_function(lines, next_line_index, match.groups()[0])
            SUCCESSES += 1
        except Lego1Exception as e:
            log_and_track_failure(path, e)

        except Exception as e:
            log_and_track_failure(path, e, unexpected=True)
            logging.error(traceback.format_exc())


if __name__ == "__main__":
    main()
