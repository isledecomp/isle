"""Database used to match (filename, line_number) pairs
between FUNCTION markers and PDB analysis."""
import sqlite3
import logging
from typing import Optional
from pathlib import Path
from isledecomp.dir import PathResolver


_SETUP_SQL = """
    DROP TABLE IF EXISTS `lineref`;
    CREATE TABLE `lineref` (
        path text not null,
        filename text not null,
        line int not null,
        addr int not null
    );
    CREATE INDEX `file_line` ON `lineref` (filename, line);
"""


logger = logging.getLogger(__name__)


class LinesDb:
    def __init__(self, code_dir) -> None:
        self._db = sqlite3.connect(":memory:")
        self._db.executescript(_SETUP_SQL)
        self._path_resolver = PathResolver(code_dir)

    def add_line(self, path: str, line_no: int, addr: int):
        """To be added from the LINES section of cvdump."""
        sourcepath = self._path_resolver.resolve_cvdump(path)
        filename = Path(sourcepath).name.lower()

        self._db.execute(
            "INSERT INTO `lineref` (path, filename, line, addr) VALUES (?,?,?,?)",
            (sourcepath, filename, line_no, addr),
        )

    def search_line(self, path: str, line_no: int) -> Optional[int]:
        """Using path and line number from FUNCTION marker,
        get the address of this function in the recomp."""
        filename = Path(path).name.lower()
        cur = self._db.execute(
            "SELECT path, addr FROM `lineref` WHERE filename = ? AND line = ?",
            (filename, line_no),
        )
        for source_path, addr in cur.fetchall():
            if Path(path).samefile(source_path):
                return addr

        logger.error(
            "Failed to find function symbol with filename and line: %s:%d",
            path,
            line_no,
        )
        return None
