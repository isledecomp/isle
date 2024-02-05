"""Wrapper for database (here an in-memory sqlite database) that collects the
addresses/symbols that we want to compare between the original and recompiled binaries."""
import sqlite3
import logging
from typing import List, Optional
from isledecomp.types import SymbolType

_SETUP_SQL = """
    DROP TABLE IF EXISTS `symbols`;
    CREATE TABLE `symbols` (
        compare_type int,
        orig_addr int,
        recomp_addr int,
        name text,
        decorated_name text,
        size int,
        should_skip int default(FALSE)
    );
    CREATE INDEX `symbols_or` ON `symbols` (orig_addr);
    CREATE INDEX `symbols_re` ON `symbols` (recomp_addr);
    CREATE INDEX `symbols_na` ON `symbols` (name);
"""


class MatchInfo:
    def __init__(
        self,
        ctype: Optional[int],
        orig: Optional[int],
        recomp: Optional[int],
        name: Optional[str],
        size: Optional[int],
    ) -> None:
        self.compare_type = SymbolType(ctype) if ctype is not None else None
        self.orig_addr = orig
        self.recomp_addr = recomp
        self.name = name
        self.size = size

    def match_name(self) -> str:
        """Combination of the name and compare type.
        Intended for name substitution in the diff. If there is a diff,
        it will be more obvious what this symbol indicates."""
        if self.name is None:
            return None

        ctype = self.compare_type.name if self.compare_type is not None else "UNK"
        name = repr(self.name) if ctype == "STRING" else self.name
        return f"{name} ({ctype})"


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
        decorated_name: Optional[str],
        size: Optional[int],
    ):
        compare_value = compare_type.value if compare_type is not None else None
        self._db.execute(
            "INSERT INTO `symbols` (recomp_addr, compare_type, name, decorated_name, size) VALUES (?,?,?,?,?)",
            (addr, compare_value, name, decorated_name, size),
        )

    def get_unmatched_strings(self) -> List[str]:
        """Return any strings not already identified by STRING markers."""

        cur = self._db.execute(
            "SELECT name FROM `symbols` WHERE compare_type = ? AND orig_addr IS NULL",
            (SymbolType.STRING.value,),
        )

        return [string for (string,) in cur.fetchall()]

    def get_all(self) -> List[MatchInfo]:
        cur = self._db.execute(
            """SELECT compare_type, orig_addr, recomp_addr, name, size
            FROM `symbols`
            ORDER BY orig_addr NULLS LAST
            """,
        )
        cur.row_factory = matchinfo_factory

        return cur.fetchall()

    def get_matches(self) -> Optional[MatchInfo]:
        cur = self._db.execute(
            """SELECT compare_type, orig_addr, recomp_addr, name, size
            FROM `symbols`
            WHERE orig_addr IS NOT NULL
            AND recomp_addr IS NOT NULL
            AND should_skip IS FALSE
            ORDER BY orig_addr
            """,
        )
        cur.row_factory = matchinfo_factory

        return cur.fetchall()

    def get_one_match(self, addr: int) -> Optional[MatchInfo]:
        cur = self._db.execute(
            """SELECT compare_type, orig_addr, recomp_addr, name, size
            FROM `symbols`
            WHERE orig_addr = ?
            AND recomp_addr IS NOT NULL
            AND should_skip IS FALSE
            """,
            (addr,),
        )
        cur.row_factory = matchinfo_factory
        return cur.fetchone()

    def get_by_orig(self, addr: int) -> Optional[MatchInfo]:
        cur = self._db.execute(
            """SELECT compare_type, orig_addr, recomp_addr, name, size
            FROM `symbols`
            WHERE orig_addr = ?
            """,
            (addr,),
        )
        cur.row_factory = matchinfo_factory
        return cur.fetchone()

    def get_by_recomp(self, addr: int) -> Optional[MatchInfo]:
        cur = self._db.execute(
            """SELECT compare_type, orig_addr, recomp_addr, name, size
            FROM `symbols`
            WHERE recomp_addr = ?
            """,
            (addr,),
        )
        cur.row_factory = matchinfo_factory
        return cur.fetchone()

    def get_matches_by_type(self, compare_type: SymbolType) -> List[MatchInfo]:
        cur = self._db.execute(
            """SELECT compare_type, orig_addr, recomp_addr, name, size
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

    def set_pair(
        self, orig: int, recomp: int, compare_type: Optional[SymbolType] = None
    ) -> bool:
        compare_value = compare_type.value if compare_type is not None else None
        cur = self._db.execute(
            "UPDATE `symbols` SET orig_addr = ?, compare_type = ? WHERE recomp_addr = ?",
            (orig, compare_value, recomp),
        )

        return cur.rowcount > 0

    def set_function_pair(self, orig: int, recomp: int) -> bool:
        """For lineref match or _entry"""
        self.set_pair(orig, recomp, SymbolType.FUNCTION)
        # TODO: Both ways required?

    def skip_compare(self, orig: int):
        self._db.execute(
            "UPDATE `symbols` SET should_skip = TRUE WHERE orig_addr = ?", (orig,)
        )

    def _match_on(self, compare_type: SymbolType, addr: int, name: str) -> bool:
        # Update the compare_type here too since the marker tells us what we should do

        # Truncate the name to 255 characters. It will not be possible to match a name
        # longer than that because MSVC truncates the debug symbols to this length.
        # See also: warning C4786.
        name = name[:255]

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

    def match_static_variable(self, addr: int, name: str, function_addr: int) -> bool:
        """Matching a static function variable by combining the variable name
        with the decorated (mangled) name of its parent function."""

        cur = self._db.execute(
            """SELECT name, decorated_name
            FROM `symbols`
            WHERE orig_addr = ?""",
            (function_addr,),
        )

        if (result := cur.fetchone()) is None:
            logger.error("No function for static variable: %s", name)
            return False

        # Get the friendly name for the "failed to match" error message
        (function_name, decorated_name) = result

        # Now we have to combine the variable name (read from the marker)
        # and the decorated name of the enclosing function (the above variable)
        # into a LIKE clause and try to match.
        # For example, the variable "g_startupDelay" from function "IsleApp::Tick"
        # has symbol: "?g_startupDelay@?1??Tick@IsleApp@@QAEXH@Z@4HA"
        # The function's decorated name is: "?Tick@IsleApp@@QAEXH@Z"
        cur = self._db.execute(
            """UPDATE `symbols`
            SET orig_addr = ?
            WHERE name LIKE '%' || ? || '%' || ? || '%'
            AND orig_addr IS NULL
            AND (compare_type = ? OR compare_type = ? OR compare_type IS NULL)""",
            (
                addr,
                name,
                decorated_name,
                SymbolType.DATA.value,
                SymbolType.POINTER.value,
            ),
        )

        did_match = cur.rowcount > 0

        if not did_match:
            logger.error(
                "Failed to match static variable %s from function %s",
                name,
                function_name,
            )

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

        return did_match
