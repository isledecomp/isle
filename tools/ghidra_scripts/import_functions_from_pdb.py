# Experiments for PDB imports.
#
# Note that the virtual environment must be set up beforehand, and all packages must be installed.
# Also, the Python version of the virtual environment must probably match the Python version used for Ghidrathon.

# @author J. Schulz
# @category LEGO1
# @keybinding
# @menupath
# @toolbar


# pylint: disable=wrong-import-position,ungrouped-imports
# pylint: disable=undefined-variable # need to disable this one globally because pylint does not understand e.g. `askYesNo()``

import importlib
from dataclasses import dataclass, field
import sys
import logging
from pathlib import Path
import traceback
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    import ghidra
    from lego_util.headers import *  # pylint: disable=wildcard-import # these are just for headers


def reload_module(module: str):
    """
    Due to a a quirk in Jep (used by Ghidrathon), imported modules persist for the lifetime of the Ghidra process
    and are not reloaded when relaunching the script. Therefore, in order to facilitate development
    we force reload all our own modules at startup.
    """
    importlib.reload(importlib.import_module(module))


reload_module("lego_util.statistics")
from lego_util.statistics import Statistics


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
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.util.exception import CancelledException

    GLOBALS.make_changes = askYesNo(
        "Make changes?", "Select 'Yes' to apply changes, select 'No' to do a dry run."
    )

    if GLOBALS.make_changes:
        GLOBALS.prompt_before_changes = askYesNo(
            "Prompt before changes?", "Should each change be confirmed by a prompt?"
        )

    GLOBALS.running_from_ghidra = True
except ImportError as importError:
    logger.error(
        "Failed to import Ghidra functions, doing a dry run for the source code parser. "
        "Has this script been launched from Ghidra?"
    )
    logger.debug("Precise import error:", exc_info=importError)

    GLOBALS.running_from_ghidra = False
    CancelledException = None


def get_repository_root():
    return Path(__file__).absolute().parent.parent.parent


def add_python_path(path: str):
    venv_path = get_repository_root().joinpath(path)
    logger.info("Adding %s to Python Path", venv_path)
    assert venv_path.exists()
    sys.path.insert(1, str(venv_path))


# We need to quote the types here because they might not exist when running without Ghidra
def migrate_function_to_ghidra(
    api: "FlatProgramAPI", match_info: "MatchInfo", signature: "FunctionSignature"
):
    hex_original_address = f"{match_info.orig_addr:x}"

    # Find the Ghidra function at that address
    ghidra_address = getAddressFactory().getAddress(hex_original_address)

    typed_pdb_function = PdbFunctionWithGhidraObjects(api, match_info, signature)

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

    logger.debug(
        "Modifying function %s at 0x%s",
        typed_pdb_function.get_full_name(),
        hex_original_address,
    )

    typed_pdb_function.overwrite_ghidra_function(ghidra_function)

    GLOBALS.statistics.functions_changed += 1

    if GLOBALS.prompt_before_changes:
        # Add a prompt so we can verify the result immediately
        askChoice("Continue", "Click 'OK' to continue", ["OK"], "OK")


def process_functions(isle_compare: "IsleCompare"):
    # try to acquire matched functions
    migration = PdbExtractionForGhidraMigration(isle_compare)
    func_signatures = migration.get_function_list()

    if not GLOBALS.running_from_ghidra:
        logger.info("Completed the dry run outside Ghidra.")
        return

    fpapi = FlatProgramAPI(currentProgram())
    for match_info, signature in func_signatures:
        try:
            migrate_function_to_ghidra(fpapi, match_info, signature)
            GLOBALS.statistics.successes += 1
        except Lego1Exception as e:
            log_and_track_failure(e)
        except RuntimeError as e:
            cause = e.args[0]
            if CancelledException is not None and isinstance(cause, CancelledException):
                # let Ghidra's CancelledException pass through
                logging.critical("Import aborted by the user.")
                return

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
        process_functions(isle_compare)
    finally:
        if GLOBALS.running_from_ghidra:
            GLOBALS.statistics.log()

        logger.info("Done")


# sys.path is not reset after running the script, so we should restore it
sys_path_backup = sys.path.copy()
try:
    # make modules installed in the venv available in Ghidra
    add_python_path(".venv/Lib/site-packages")
    # This one is needed when isledecomp is installed in editable mode in the venv
    add_python_path("tools/isledecomp")

    import setuptools  # pylint: disable=unused-import # required to fix a distutils issue in Python 3.12

    reload_module("isledecomp")
    from isledecomp import Bin

    reload_module("isledecomp.compare")
    from isledecomp.compare import Compare as IsleCompare

    reload_module("isledecomp.compare.db")
    from isledecomp.compare.db import MatchInfo

    reload_module("lego_util.exceptions")
    from lego_util.exceptions import Lego1Exception

    reload_module("lego_util.pdb_extraction")
    from lego_util.pdb_extraction import (
        PdbExtractionForGhidraMigration,
        FunctionSignature,
    )

    if GLOBALS.running_from_ghidra:
        reload_module("lego_util.pdb_to_ghidra")
        from lego_util.pdb_to_ghidra import PdbFunctionWithGhidraObjects

    if __name__ == "__main__":
        main()
finally:
    sys.path = sys_path_backup
