# Experiments for PDB imports.
#
# Note that the virtual environment must be set up beforehand, and all packages must be installed.
# Also, the Python version of the virtual environment must probably match the Python version used for Ghidrathon.

# @author J. Schulz
# @category LEGO1
# @keybinding
# @menupath
# @toolbar

from dataclasses import dataclass, field
import sys
import logging
from pathlib import Path
import traceback
from typing import TYPE_CHECKING

from lego_util.exceptions import Lego1Exception
from lego_util.statistics import Statistics

# pylint: disable=undefined-variable # need to disable this one globally because pylint does not understand e.g. askYesNo()
if TYPE_CHECKING:
    import ghidra
    from lego_util.headers import *  # pylint: disable=wildcard-import

logger = logging.getLogger(__name__)


def setup_logging():
    logging.basicConfig(
        format="%(levelname)-8s %(message)s",
        stream=sys.stdout,
        level=logging.INFO,
        force=True,
    )
    logger.info("Starting...")


@dataclass
class Globals:
    verbose: bool
    running_from_ghidra: bool = False
    make_changes: bool = False
    prompt_before_changes: bool = True
    # statistics
    statistics: Statistics = field(default_factory=Statistics)


# hard-coded settings that we don't want to prompt in Ghidra every time
GLOBALS = Globals(verbose=False)


# Disable spurious warnings in vscode / pylance
# pyright: reportMissingModuleSource=false

# This script can be run both from Ghidra and as a standalone.
# In the latter case, only the C++ parser can be used.
setup_logging()
try:

    # this one contains actual code
    from lego_util.ghidra_helper import (
        get_ghidra_namespace,
        get_ghidra_type,
    )

    from ghidra.program.model.listing import Function, Parameter
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.listing import ParameterImpl
    from ghidra.program.model.listing import Function
    from ghidra.program.model.symbol import SourceType
    from ghidra.util.exception import CancelledException

    GLOBALS.make_changes = askYesNo(
        "Make changes?", "Select 'Yes' to apply changes, select 'No' to do a dry run."
    )

    if GLOBALS.make_changes:
        GLOBALS.prompt_before_changes = askYesNo(
            "Prompt before changes?", "Should each change be confirmed by a prompt?"
        )

    GLOBALS.running_from_ghidra = True
except ImportError:
    logger.error(
        "Failed to import Ghidra functions, doing a dry run for the source code parser. "
        "Has this script been launched from Ghidra?"
    )
    GLOBALS.running_from_ghidra = False
    CancelledException = None


def get_repository_root():
    return Path(__file__).absolute().parent.parent.parent


def add_python_path(path: str):
    venv_path = get_repository_root().joinpath(path)
    logger.info("Adding %s to Python Path", venv_path)
    assert venv_path.exists()
    sys.path.insert(1, str(venv_path))


class PdbFunctionWithGhidraObjects:
    """A representation of a function from the PDB with each type replaced by a Ghidra type instance."""

    def __init__(
        self,
        fpapi: "FlatProgramAPI",
        match_info: "MatchInfo",
        signature: "FunctionSignature",
    ):
        self.api = fpapi
        self.match_info = match_info
        self.signature = signature

        assert match_info.name is not None
        colon_split = match_info.name.split("::")
        self.name = colon_split.pop()
        namespace_hierachy = colon_split
        self.namespace = get_ghidra_namespace(fpapi, namespace_hierachy)

        self.return_type = get_ghidra_type(fpapi, signature.return_type)
        self.arguments = [
            ParameterImpl(
                f"param{index}",
                get_ghidra_type(fpapi, type_name),
                fpapi.getCurrentProgram(),
            )
            for (index, type_name) in enumerate(signature.arglist)
        ]

    @property
    def call_type(self):
        return self.signature.call_type

    @property
    def stack_symbols(self):
        return self.signature.stack_symbols

    def get_full_name(self) -> str:
        return f"{self.namespace.getName()}::{self.name}"

    def format_proposed_change(self) -> str:
        return (
            f"{self.return_type} {self.call_type} {self.get_full_name()}"
            + f"({', '.join(self.signature.arglist)})"
        )

    def matches_ghidra_function(self, ghidra_function):  # type: (Function) -> bool
        """Checks whether this function declaration already matches the description in Ghidra"""
        name_match = self.name == ghidra_function.getName(False)
        namespace_match = self.namespace == ghidra_function.getParentNamespace()
        return_type_match = self.return_type == ghidra_function.getReturnType()
        # match arguments: decide if thiscall or not
        thiscall_matches = (
            self.signature.call_type == ghidra_function.getCallingConventionName()
        )

        if thiscall_matches:
            if self.signature.call_type == "__thiscall":
                args_match = self._matches_thiscall_parameters(ghidra_function)
            else:
                args_match = self._matches_non_thiscall_parameters(ghidra_function)
        else:
            args_match = False

        logger.debug(
            "Matches: namespace=%s name=%s return_type=%s thiscall=%s args=%s",
            namespace_match,
            name_match,
            return_type_match,
            thiscall_matches,
            args_match,
        )

        return (
            name_match
            and namespace_match
            and return_type_match
            and thiscall_matches
            and args_match
        )

    def _matches_non_thiscall_parameters(
        self, ghidra_function
    ):  # type: (Function) -> bool
        return self._parameter_lists_match(ghidra_function.getParameters())

    def _matches_thiscall_parameters(self, ghidra_function: "Function") -> bool:
        ghidra_params = list(ghidra_function.getParameters())

        # remove the `this` argument which we don't generate ourselves
        ghidra_params.pop(0)

        return self._parameter_lists_match(ghidra_params)

    def _parameter_lists_match(self, ghidra_params: "list[Parameter]") -> bool:
        if len(self.arguments) != len(ghidra_params):
            logger.info("Mismatching argument count")
            return False

        for this_arg, ghidra_arg in zip(self.arguments, ghidra_params):
            # compare argument types
            if this_arg.getDataType() != ghidra_arg.getDataType():
                logger.debug(
                    "Mismatching arg type: expected %s, found %s",
                    this_arg.getDataType(),
                    ghidra_arg.getDataType(),
                )
                return False
            # compare argument names
            stack_match = self.get_matching_stack_symbol(ghidra_arg.getStackOffset())
            if stack_match is None:
                logger.debug("Not found on stack: %s", ghidra_arg)
                return False
            # "__formal" is the placeholder for arguments without a name
            if stack_match.name not in ["__formal", ghidra_arg.getName()]:
                logger.debug(
                    "Argument name mismatch: expected %s, found %s",
                    stack_match.name,
                    ghidra_arg.getName(),
                )
                return False
        return True

    def overwrite_ghidra_function(self, ghidra_function):  # type: (Function) -> None
        """Replace the function declaration in Ghidra by the one derived from C++."""
        ghidra_function.setName(self.name, SourceType.USER_DEFINED)
        ghidra_function.setParentNamespace(self.namespace)
        ghidra_function.setReturnType(self.return_type, SourceType.USER_DEFINED)
        ghidra_function.setCallingConvention(self.call_type)

        ghidra_function.replaceParameters(
            Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
            True,
            SourceType.USER_DEFINED,
            self.arguments,
        )

        # When we set the parameters, Ghidra will generate the layout.
        # Now we read them again and match them against the stack layout in the PDB,
        # both to verify and to set the parameter names.
        ghidra_parameters: "list[ghidra.program.model.listing.Parameter]" = ghidra_function.getParameters()  # type: ignore

        # Try to add Ghidra function names
        for param in ghidra_parameters:
            if param.isStackVariable():
                self._rename_stack_parameter(param)
            else:
                if param.getName() == "this":
                    # 'this' parameters are auto-generated and cannot be changed
                    continue

                # TODO: Does this ever happen?
                logger.warning("Unhandled register variable in %s", self.get_full_name)
                continue

                # Old code for reference:
                #
                # register = param.getRegister().getName().lower()
                # match = self.get_matching_register_symbol(register)
                # if match is None:
                #     logger.error(
                #         "Could not match register parameter %s to known symbols %s",
                #         param,
                #         self.stack_symbols,
                #     )
                #     continue

    def _rename_stack_parameter(self, param: "Parameter"):
        match = self.get_matching_stack_symbol(param.getStackOffset())
        if match is None:
            raise StackOffsetMismatchError(
                f"Could not find a matching symbol at offset {param.getStackOffset()} in {self.get_full_name()}"
            )

        if param.getDataType() != get_ghidra_type(self.api, match.data_type):
            logger.error(
                "Type mismatch for parameter: %s in Ghidra, %s in PDB", param, match
            )
            return

        param.setName(match.name, SourceType.USER_DEFINED)

    def get_matching_stack_symbol(self, stack_offset: int) -> "CppStackSymbol | None":
        return next(
            (
                symbol
                for symbol in self.stack_symbols
                if isinstance(symbol, CppStackSymbol)
                and symbol.stack_offset == stack_offset
            ),
            None,
        )

    def get_matching_register_symbol(self, register: str) -> "CppRegisterSymbol | None":
        return next(
            (
                symbol
                for symbol in self.stack_symbols
                if isinstance(symbol, CppRegisterSymbol) and symbol.register == register
            ),
            None,
        )


def handle_function_in_ghidra(match_info: "MatchInfo", signature: "FunctionSignature"):

    if not GLOBALS.running_from_ghidra:
        return
    hex_original_address = f"{match_info.orig_addr:x}"

    # Find the Ghidra function at that address
    ghidra_address = getAddressFactory().getAddress(hex_original_address)  # type: ignore

    fpapi = FlatProgramAPI(currentProgram())  # type: ignore

    typed_pdb_function = PdbFunctionWithGhidraObjects(fpapi, match_info, signature)

    if not GLOBALS.make_changes:
        return

    ghidra_function = getFunctionAt(ghidra_address)
    if ghidra_function is None:
        ghidra_function = createFunction(ghidra_address, "temp")
        assert (
            ghidra_function is not None
        ), f"Failed to create function at {ghidra_address}"
        logger.info("Created new function at %s", ghidra_address)

    if typed_pdb_function.matches_ghidra_function(ghidra_function):
        logger.info(
            "Skipping function '%s', matches already",
            typed_pdb_function.get_full_name(),
        )
        return

    # Navigate Ghidra to the current function
    state().setCurrentAddress(ghidra_address)

    if GLOBALS.prompt_before_changes:
        choice = askChoice(
            "Change function?",
            f"Change to: {typed_pdb_function.format_proposed_change()}",
            # "Change to %s" % cpp_function,
            ["Yes", "No", "Abort"],
            "Yes",
        )
        if choice == "No":
            return
        if choice != "Yes":
            logger.critical("User quit, terminating")
            raise SystemExit(1)

    # logger.info("Modifying function %s at 0x%s", cpp_function.full_name(), address)

    typed_pdb_function.overwrite_ghidra_function(ghidra_function)

    GLOBALS.statistics.functions_changed += 1

    if GLOBALS.prompt_before_changes:
        # Add a prompt so we can verify the result immediately
        askChoice("", "Click 'OK' to continue", ["OK"], "OK")


def handle_function_list(isle_compare: "IsleCompare"):
    # try to acquire matched functions
    migration = PdbExtractionForGhidraMigration(isle_compare)
    func_signatures = migration.get_function_list()
    for match_info, signature in func_signatures:
        try:
            handle_function_in_ghidra(match_info, signature)
            GLOBALS.statistics.successes += 1
        except Lego1Exception as e:
            log_and_track_failure(e)
        except RuntimeError as e:
            cause = e.args[0]
            if CancelledException is not None and isinstance(cause, CancelledException):
                # let Ghidra's CancelledException pass through
                raise
            log_and_track_failure(cause, unexpected=True)
        except Exception as e:  # pylint: disable=broad-exception-caught
            log_and_track_failure(e, unexpected=True)
            logger.error(traceback.format_exc())


def log_and_track_failure(error: Exception, unexpected: bool = False):
    if GLOBALS.statistics.track_failure_and_tell_if_new(error):
        logger.error(
            "%s%s",
            "Unexpected error: " if unexpected else "",
            error,
        )


def main():
    repo_root = get_repository_root()
    origfile_path = repo_root.joinpath("LEGO1.DLL")
    build_path = repo_root.joinpath("build")
    recompiledfile_path = build_path.joinpath("LEGO1.DLL")
    pdb_path = build_path.joinpath("LEGO1.pdb")

    if not GLOBALS.verbose:
        logging.getLogger("isledecomp.compare.db").setLevel(logging.CRITICAL)
        logging.getLogger("isledecomp.compare.lines").setLevel(logging.CRITICAL)

    logger.info("Starting comparison")
    with Bin(str(origfile_path), find_str=True) as origfile, Bin(
        str(recompiledfile_path)
    ) as recompfile:
        isle_compare = IsleCompare(origfile, recompfile, str(pdb_path), str(repo_root))

    logger.info("Comparison complete.")

    try:
        handle_function_list(isle_compare)
    finally:
        GLOBALS.statistics.log()

        logger.info("Done")


# sys.path is not reset after running the script, so we should restore it
sys_path_backup = sys.path.copy()
try:
    add_python_path(
        ".venv/Lib/site-packages"
    )  # make modules installed in the venv available in Ghidra
    add_python_path(
        "tools/isledecomp"
    )  # needed when isledecomp is installed in editable mode in the venv

    import setuptools  # pylint: disable=unused-import # required to fix a distutils issue in Python 3.12
    from isledecomp import Bin
    from isledecomp.compare import Compare as IsleCompare
    from isledecomp.compare.db import MatchInfo
    from lego_util.pdb_extraction import (  # pylint: disable=ungrouped-imports # these must be imported
        PdbExtractionForGhidraMigration,
        FunctionSignature,
        CppRegisterSymbol,
        CppStackSymbol,
    )
    from lego_util.exceptions import StackOffsetMismatchError

    if __name__ == "__main__":
        main()
finally:
    sys.path = sys_path_backup
