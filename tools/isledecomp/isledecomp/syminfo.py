import os
from isledecomp.dir import PathResolver
from isledecomp.cvdump import Cvdump


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

    def __init__(self, pdb, sym_recompfile, sym_logger, base_dir):
        self.logger = sym_logger
        path_resolver = PathResolver(base_dir)

        self.logger.info("Parsing %s ...", pdb)
        self.logger.debug("Parsing output of cvdump.exe ...")

        cv = Cvdump(pdb).lines().symbols().publics().section_contributions().run()

        self.logger.debug("... Parsing output of cvdump.exe finished")

        contrib_dict = {(s.section, s.offset): s.size for s in cv.sizerefs}
        for pub in cv.publics:
            if pub.type == "S_PUB32" and (pub.section, pub.offset) in contrib_dict:
                size = contrib_dict[(pub.section, pub.offset)]

                info = RecompiledInfo()
                info.addr = sym_recompfile.get_abs_addr(pub.section, pub.offset)

                info.start = 0
                info.size = size
                info.name = pub.name
                self.names[pub.name] = info
                self.funcs[pub.offset] = info

        for proc in cv.symbols:
            if proc.type != "S_GPROC32":
                continue

            info = RecompiledInfo()
            info.addr = sym_recompfile.get_abs_addr(proc.section, proc.offset)

            info.start = 0
            info.size = proc.size
            info.name = proc.name

            self.names[proc.name] = info
            self.funcs[proc.offset] = info

        for sourcepath, line_no, offset in cv.lines:
            sourcepath = path_resolver.resolve_cvdump(sourcepath)

            if sourcepath not in self.lines:
                self.lines[sourcepath] = {}

            if line_no not in self.lines[sourcepath]:
                self.lines[sourcepath][line_no] = offset

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
