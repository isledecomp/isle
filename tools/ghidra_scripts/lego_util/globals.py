import logging
from enum import Enum
from dataclasses import dataclass, field
from lego_util.statistics import Statistics


class SupportedModules(Enum):
    LEGO1 = 1
    BETA10 = 2

    def orig_filename(self):
        if self == self.LEGO1:
            return "LEGO1.DLL"
        return "BETA10.DLL"

    def recomp_filename_without_extension(self):
        # in case we want to support more functions
        return "LEGO1"

    def build_dir_name(self):
        if self == self.BETA10:
            return "build_debug"
        return "build"


@dataclass
class Globals:
    verbose: bool
    loglevel: int
    module: SupportedModules
    running_from_ghidra: bool = False
    # statistics
    statistics: Statistics = field(default_factory=Statistics)


# hard-coded settings that we don't want to prompt in Ghidra every time
GLOBALS = Globals(
    verbose=False,
    # loglevel=logging.INFO,
    loglevel=logging.DEBUG,
    module=SupportedModules.LEGO1,  # this default value will be used when run outside of Ghidra
)
