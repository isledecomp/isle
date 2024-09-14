# Imports types and function signatures from debug symbols (PDB file) of the recompilation.
#
# This script uses Python 3 and therefore requires Ghidrathon to be installed in Ghidra (see https://github.com/mandiant/Ghidrathon).
# Furthermore, the virtual environment must be set up beforehand under $REPOSITORY_ROOT/.venv, and all required packages must be installed
# (see $REPOSITORY_ROOT/tools/README.md).
# Also, the Python version of the virtual environment must probably match the Python version used for Ghidrathon.

# @author J. Schulz
# @category LEGO1
# @keybinding
# @menupath
# @toolbar


# In order to make this code run both within and outside of Ghidra, the import order is rather unorthodox in this file.
# That is why some of the lints below are disabled.

# pylint: disable=wrong-import-position,ungrouped-imports
# pylint: disable=undefined-variable # need to disable this one globally because pylint does not understand e.g. `askYesNo()``

# Disable spurious warnings in vscode / pylance
# pyright: reportMissingModuleSource=false

import importlib
import logging.handlers
import sys
import logging
from pathlib import Path
import traceback
from typing import TYPE_CHECKING, Optional


if TYPE_CHECKING:
    import ghidra
    from lego_util.headers import *  # pylint: disable=wildcard-import # these are just for headers


logger = logging.getLogger(__name__)


def reload_module(module: str):
    """
    Due to a a quirk in Jep (used by Ghidrathon), imported modules persist for the lifetime of the Ghidra process
    and are not reloaded when relaunching the script. Therefore, in order to facilitate development
    we force reload all our own modules at startup. See also https://github.com/mandiant/Ghidrathon/issues/103.

    Note that as of 2024-05-30, this remedy does not work perfectly (yet): Some changes in isledecomp are
    still not detected correctly and require a Ghidra restart to be applied.
    """
    importlib.reload(importlib.import_module(module))


reload_module("lego_util.statistics")
reload_module("lego_util.globals")
from lego_util.globals import GLOBALS, SupportedModules


def setup_logging():
    logging.root.handlers.clear()
    formatter = logging.Formatter("%(levelname)-8s %(message)s")
    # formatter = logging.Formatter("%(name)s %(levelname)-8s %(message)s") # use this to identify loggers
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(formatter)
    file_handler = logging.FileHandler(
        Path(__file__).absolute().parent.joinpath("import.log"), mode="w"
    )
    file_handler.setFormatter(formatter)
    logging.root.setLevel(GLOBALS.loglevel)
    logging.root.addHandler(stdout_handler)
    logging.root.addHandler(file_handler)
    logger.info("Starting import...")


# This script can be run both from Ghidra and as a standalone.
# In the latter case, only the PDB parser will be used.
setup_logging()
try:
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.util.exception import CancelledException

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
    """
    Scripts in Ghidra are executed from the tools/ghidra_scripts directory. We need to add
    a few more paths to the Python path so we can import the other libraries.
    """
    venv_path = get_repository_root().joinpath(path)
    logger.info("Adding %s to Python Path", venv_path)
    assert venv_path.exists()
    sys.path.insert(1, str(venv_path))


# We need to quote the types here because they might not exist when running without Ghidra
def import_function_into_ghidra(
    api: "FlatProgramAPI",
    pdb_function: "PdbFunction",
    type_importer: "PdbTypeImporter",
):
    hex_original_address = f"{pdb_function.match_info.orig_addr:x}"

    # Find the Ghidra function at that address
    ghidra_address = getAddressFactory().getAddress(hex_original_address)
    # pylint: disable=possibly-used-before-assignment
    function_importer = PdbFunctionImporter.build(api, pdb_function, type_importer)

    ghidra_function = getFunctionAt(ghidra_address)
    if ghidra_function is None:
        ghidra_function = createFunction(ghidra_address, "temp")
        assert (
            ghidra_function is not None
        ), f"Failed to create function at {ghidra_address}"
        logger.info("Created new function at %s", ghidra_address)

    logger.debug("Start handling function '%s'", function_importer.get_full_name())

    if function_importer.matches_ghidra_function(ghidra_function):
        logger.info(
            "Skipping function '%s', matches already",
            function_importer.get_full_name(),
        )
        return

    logger.debug(
        "Modifying function %s at 0x%s",
        function_importer.get_full_name(),
        hex_original_address,
    )

    function_importer.overwrite_ghidra_function(ghidra_function)

    GLOBALS.statistics.functions_changed += 1


def process_functions(extraction: "PdbFunctionExtractor"):
    pdb_functions = extraction.get_function_list()

    if not GLOBALS.running_from_ghidra:
        logger.info("Completed the dry run outside Ghidra.")
        return

    api = FlatProgramAPI(currentProgram())
    # pylint: disable=possibly-used-before-assignment
    type_importer = PdbTypeImporter(api, extraction)

    for pdb_func in pdb_functions:
        func_name = pdb_func.match_info.name
        try:
            import_function_into_ghidra(api, pdb_func, type_importer)
            GLOBALS.statistics.successes += 1
        except Lego1Exception as e:
            log_and_track_failure(func_name, e)
        except RuntimeError as e:
            cause = e.args[0]
            if CancelledException is not None and isinstance(cause, CancelledException):
                # let Ghidra's CancelledException pass through
                logging.critical("Import aborted by the user.")
                return

            log_and_track_failure(func_name, cause, unexpected=True)
            logger.error(traceback.format_exc())
        except Exception as e:  # pylint: disable=broad-exception-caught
            log_and_track_failure(func_name, e, unexpected=True)
            logger.error(traceback.format_exc())


def log_and_track_failure(
    function_name: Optional[str], error: Exception, unexpected: bool = False
):
    if GLOBALS.statistics.track_failure_and_tell_if_new(error):
        logger.error(
            "%s(): %s%s",
            function_name,
            "Unexpected error: " if unexpected else "",
            error,
        )


def main():
    if GLOBALS.running_from_ghidra:
        origfile_name = getProgramFile().getName()

        if origfile_name == "LEGO1.DLL":
            GLOBALS.module = SupportedModules.LEGO1
        elif origfile_name in ["LEGO1D.DLL", "BETA10.DLL"]:
            GLOBALS.module = SupportedModules.BETA10
        else:
            raise Lego1Exception(
                f"Unsupported file name in import script: {origfile_name}"
            )

    logger.info("Importing file: %s", GLOBALS.module.orig_filename())

    repo_root = get_repository_root()
    origfile_path = repo_root.joinpath("legobin").joinpath(
        GLOBALS.module.orig_filename()
    )
    build_directory = repo_root.joinpath(GLOBALS.module.build_dir_name())
    recompiledfile_name = f"{GLOBALS.module.recomp_filename_without_extension()}.DLL"
    recompiledfile_path = build_directory.joinpath(recompiledfile_name)
    pdbfile_name = f"{GLOBALS.module.recomp_filename_without_extension()}.PDB"
    pdbfile_path = build_directory.joinpath(pdbfile_name)

    if not GLOBALS.verbose:
        logging.getLogger("isledecomp.bin").setLevel(logging.WARNING)
        logging.getLogger("isledecomp.compare.core").setLevel(logging.WARNING)
        logging.getLogger("isledecomp.compare.db").setLevel(logging.WARNING)
        logging.getLogger("isledecomp.compare.lines").setLevel(logging.WARNING)
        logging.getLogger("isledecomp.cvdump.symbols").setLevel(logging.WARNING)

    logger.info("Starting comparison")
    with Bin(str(origfile_path), find_str=True) as origfile, Bin(
        str(recompiledfile_path)
    ) as recompfile:
        isle_compare = IsleCompare(
            origfile, recompfile, str(pdbfile_path), str(repo_root)
        )

    logger.info("Comparison complete.")

    # try to acquire matched functions
    migration = PdbFunctionExtractor(isle_compare)
    try:
        process_functions(migration)
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

    reload_module("lego_util.exceptions")
    from lego_util.exceptions import Lego1Exception

    reload_module("lego_util.pdb_extraction")
    from lego_util.pdb_extraction import (
        PdbFunctionExtractor,
        PdbFunction,
    )

    if GLOBALS.running_from_ghidra:
        reload_module("lego_util.ghidra_helper")

        reload_module("lego_util.function_importer")
        from lego_util.function_importer import PdbFunctionImporter

        reload_module("lego_util.type_importer")
        from lego_util.type_importer import PdbTypeImporter

    if __name__ == "__main__":
        main()
finally:
    sys.path = sys_path_backup
