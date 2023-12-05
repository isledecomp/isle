import os
import subprocess
from .utils import get_file_in_script_dir


class RecompiledInfo:
    addr = None
    size = None
    name = None
    start = None


# Declare a class that parses the output of cvdump for fast access later
class SymInfo:
    funcs = {}
    lines = {}
    names = {}

    def __init__(self, pdb, sym_recompfile, sym_logger, sym_wine_path_converter=None):
        self.logger = sym_logger
        call = [get_file_in_script_dir("cvdump.exe"), "-l", "-s"]

        if sym_wine_path_converter:
            # Run cvdump through wine and convert path to Windows-friendly wine path
            call.insert(0, "wine")
            call.append(sym_wine_path_converter.get_wine_path(pdb))
        else:
            call.append(pdb)

        self.logger.info("Parsing %s ...", pdb)
        self.logger.debug("Command = %s", call)
        line_dump = subprocess.check_output(call).decode("utf-8").split("\r\n")

        current_section = None

        self.logger.debug("Parsing output of cvdump.exe ...")

        for i, line in enumerate(line_dump):
            if line.startswith("***"):
                current_section = line[4:]

            if current_section == "SYMBOLS" and "S_GPROC32" in line:
                sym_section = int(line[21:25], 16)
                sym_addr = int(line[26:34], 16)

                info = RecompiledInfo()
                info.addr = sym_addr + sym_recompfile.get_section_offset_by_index(
                    sym_section
                )

                use_dbg_offs = False
                if use_dbg_offs:
                    debug_offs = line_dump[i + 2]
                    debug_start = int(debug_offs[22:30], 16)
                    debug_end = int(debug_offs[43:], 16)

                    info.start = debug_start
                    info.size = debug_end - debug_start
                else:
                    info.start = 0
                    info.size = int(line[41:49], 16)

                info.name = line[77:]

                self.names[info.name] = info
                self.funcs[sym_addr] = info
            elif (
                current_section == "LINES"
                and line.startswith("  ")
                and not line.startswith("   ")
            ):
                sourcepath = line.split()[0]

                if sym_wine_path_converter:
                    # Convert filename to Unix path for file compare
                    sourcepath = sym_wine_path_converter.get_unix_path(sourcepath)

                if sourcepath not in self.lines:
                    self.lines[sourcepath] = {}

                j = i + 2
                while True:
                    ll = line_dump[j].split()
                    if len(ll) == 0:
                        break

                    k = 0
                    while k < len(ll):
                        linenum = int(ll[k + 0])
                        address = int(ll[k + 1], 16)
                        if linenum not in self.lines[sourcepath]:
                            self.lines[sourcepath][linenum] = address
                        k += 2

                    j += 1

        self.logger.debug("... Parsing output of cvdump.exe finished")

    def get_recompiled_address(self, filename, line):
        recompiled_addr = None

        self.logger.debug("Looking for %s:%s", filename, line)
        filename_basename = os.path.basename(filename).lower()

        for fn in self.lines:
            # Sometimes a PDB is compiled with a relative path while we always have
            # an absolute path. Therefore we must
            try:
                if os.path.basename(
                    fn
                ).lower() == filename_basename and os.path.samefile(fn, filename):
                    filename = fn
                    break
            except FileNotFoundError:
                continue

        if filename in self.lines and line in self.lines[filename]:
            recompiled_addr = self.lines[filename][line]

            if recompiled_addr in self.funcs:
                return self.funcs[recompiled_addr]
            self.logger.error(
                "Failed to find function symbol with address: %x", recompiled_addr
            )
            return None
        self.logger.error(
            "Failed to find function symbol with filename and line: %s:%s",
            filename,
            line,
        )
        return None

    def get_recompiled_address_from_name(self, name):
        self.logger.debug("Looking for %s", name)

        if name in self.names:
            return self.names[name]
        self.logger.error("Failed to find function symbol with name: %s", name)
        return None
