"""Wrapper for database (here an in-memory sqlite database) that collects the
addresses/symbols that we want to compare between the original and recompiled binaries."""
import sqlite3
import logging
from collections import namedtuple
from typing import List, Optional
from isledecomp.types import SymbolType

_SETUP_SQL = """
    DROP TABLE IF EXISTS `symbols`;
    CREATE TABLE `symbols` (
        compare_type int,
        orig_addr int,
        recomp_addr int,
        name text,
        size int,
        should_skip int default(FALSE)
    );
    CREATE INDEX `symbols_re` ON `symbols` (recomp_addr);
    CREATE INDEX `symbols_na` ON `symbols` (compare_type, name);    
"""


MatchInfo = namedtuple("MatchInfo", "orig_addr, recomp_addr, size, name")


def matchinfo_factory(_, row):
    return MatchInfo(*row)


logger = logging.getLogger(__name__)


class CompareDb:
    def __init__(self):
        self._db = sqlite3.connect(":memory:")
        self._db.executescript(_SETUP_SQL)

    def set_recomp_symbol(
        self,
        addr: int,
        compare_type: Optional[SymbolType],
        name: Optional[str],
        size: Optional[int],
    ):
        compare_value = compare_type.value if compare_type is not None else None
        self._db.execute(
            "INSERT INTO `symbols` (recomp_addr, compare_type, name, size) VALUES (?,?,?,?)",
            (addr, compare_value, name, size),
        )

    def get_unmatched_strings(self) -> List[str]:
        """Return any strings not already identified by STRING markers."""

        cur = self._db.execute(
            "SELECT name FROM `symbols` WHERE compare_type = ? AND orig_addr IS NULL",
            (SymbolType.STRING.value,),
        )

        return [string for (string,) in cur.fetchall()]

    def get_one_function(self, addr: int) -> Optional[MatchInfo]:
        cur = self._db.execute(
            """SELECT orig_addr, recomp_addr, size, name
            FROM `symbols`
            WHERE compare_type = ?
            AND orig_addr = ?
            AND recomp_addr IS NOT NULL
            AND should_skip IS FALSE
            ORDER BY orig_addr
            """,
            (SymbolType.FUNCTION.value, addr),
        )
        cur.row_factory = matchinfo_factory
        return cur.fetchone()

    def get_matches(self, compare_type: SymbolType) -> List[MatchInfo]:
        cur = self._db.execute(
            """SELECT orig_addr, recomp_addr, size, name
            FROM `symbols`
            WHERE compare_type = ?
            AND orig_addr IS NOT NULL
            AND recomp_addr IS NOT NULL
            AND should_skip IS FALSE
            ORDER BY orig_addr
            """,
            (compare_type.value,),
        )
        cur.row_factory = matchinfo_factory

        return cur.fetchall()

    def set_function_pair(self, orig: int, recomp: int) -> bool:
        """For lineref match or _entry"""
        cur = self._db.execute(
            "UPDATE `symbols` SET orig_addr = ?, compare_type = ? WHERE recomp_addr = ?",
            (orig, SymbolType.FUNCTION.value, recomp),
        )

        return cur.rowcount > 0
        # TODO: Both ways required?

    def skip_compare(self, orig: int):
        self._db.execute(
            "UPDATE `symbols` SET should_skip = TRUE WHERE orig_addr = ?", (orig,)
        )

    def _match_on(self, compare_type: SymbolType, addr: int, name: str) -> bool:
        # Update the compare_type here too since the marker tells us what we should do
        logger.debug("Looking for %s %s", compare_type.name.lower(), name)
        cur = self._db.execute(
            """UPDATE `symbols`
            SET orig_addr = ?, compare_type = ?
            WHERE name = ?
            AND orig_addr IS NULL
            AND (compare_type = ? OR compare_type IS NULL)""",
            (addr, compare_type.value, name, compare_type.value),
        )

        return cur.rowcount > 0

    def match_function(self, addr: int, name: str) -> bool:
        did_match = self._match_on(SymbolType.FUNCTION, addr, name)
        if not did_match:
            logger.error("Failed to find function symbol with name: %s", name)

        return did_match

    def match_vtable(self, addr: int, name: str) -> bool:
        did_match = self._match_on(SymbolType.VTABLE, addr, name)
        if not did_match:
            logger.error("Failed to find vtable for class: %s", name)

        return did_match

    def match_variable(self, addr: int, name: str) -> bool:
        did_match = self._match_on(SymbolType.DATA, addr, name) or self._match_on(
            SymbolType.POINTER, addr, name
        )
        if not did_match:
            logger.error("Failed to find variable: %s", name)

        return did_match

    def match_string(self, addr: int, value: str) -> bool:
        did_match = self._match_on(SymbolType.STRING, addr, value)
        if not did_match:
            escaped = repr(value)
            logger.error("Failed to find string: %s", escaped)
