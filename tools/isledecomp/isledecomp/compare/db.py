"""Wrapper for database (here an in-memory sqlite database) that collects the
addresses/symbols that we want to compare between the original and recompiled binaries."""
import sqlite3
import logging
from typing import List, Optional
from isledecomp.types import SymbolType
from isledecomp.cvdump.demangler import get_vtordisp_name

_SETUP_SQL = """
    DROP TABLE IF EXISTS `symbols`;
    DROP TABLE IF EXISTS `match_options`;

    CREATE TABLE `symbols` (
        compare_type int,
        orig_addr int,
        recomp_addr int,
        name text,
        decorated_name text,
        size int
    );

    CREATE TABLE `match_options` (
        addr int not null,
        name text not null,
        value text,
        primary key (addr, name)
    ) without rowid;

    CREATE VIEW IF NOT EXISTS `match_info`
    (compare_type, orig_addr, recomp_addr, name, size) AS
        SELECT compare_type, orig_addr, recomp_addr, name, size
        FROM `symbols`
        ORDER BY orig_addr NULLS LAST;

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
        # Ignore collisions here. The same recomp address can have
        # multiple names (e.g. _strlwr and __strlwr)
        if self._recomp_used(addr):
            return

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
        cur = self._db.execute("SELECT * FROM `match_info`")
        cur.row_factory = matchinfo_factory

        return cur.fetchall()

    def get_matches(self) -> Optional[MatchInfo]:
        cur = self._db.execute(
            """SELECT * FROM `match_info`
            WHERE orig_addr IS NOT NULL
            AND recomp_addr IS NOT NULL
            """,
        )
        cur.row_factory = matchinfo_factory

        return cur.fetchall()

    def get_one_match(self, addr: int) -> Optional[MatchInfo]:
        cur = self._db.execute(
            """SELECT * FROM `match_info`
            WHERE orig_addr = ?
            AND recomp_addr IS NOT NULL
            """,
            (addr,),
        )
        cur.row_factory = matchinfo_factory
        return cur.fetchone()

    def get_by_orig(self, addr: int) -> Optional[MatchInfo]:
        cur = self._db.execute(
            """SELECT * FROM `match_info`
            WHERE orig_addr = ?
            """,
            (addr,),
        )
        cur.row_factory = matchinfo_factory
        return cur.fetchone()

    def get_by_recomp(self, addr: int) -> Optional[MatchInfo]:
        cur = self._db.execute(
            """SELECT * FROM `match_info`
            WHERE recomp_addr = ?
            """,
            (addr,),
        )
        cur.row_factory = matchinfo_factory
        return cur.fetchone()

    def get_matches_by_type(self, compare_type: SymbolType) -> List[MatchInfo]:
        cur = self._db.execute(
            """SELECT * FROM `match_info`
            WHERE compare_type = ?
            AND orig_addr IS NOT NULL
            AND recomp_addr IS NOT NULL
            """,
            (compare_type.value,),
        )
        cur.row_factory = matchinfo_factory

        return cur.fetchall()

    def _orig_used(self, addr: int) -> bool:
        cur = self._db.execute("SELECT 1 FROM symbols WHERE orig_addr = ?", (addr,))
        return cur.fetchone() is not None

    def _recomp_used(self, addr: int) -> bool:
        cur = self._db.execute("SELECT 1 FROM symbols WHERE recomp_addr = ?", (addr,))
        return cur.fetchone() is not None

    def set_pair(
        self, orig: int, recomp: int, compare_type: Optional[SymbolType] = None
    ) -> bool:
        if self._orig_used(orig):
            logger.error("Original address %s not unique!", hex(orig))
            return False

        compare_value = compare_type.value if compare_type is not None else None
        cur = self._db.execute(
            "UPDATE `symbols` SET orig_addr = ?, compare_type = ? WHERE recomp_addr = ?",
            (orig, compare_value, recomp),
        )

        return cur.rowcount > 0

    def set_pair_tentative(
        self, orig: int, recomp: int, compare_type: Optional[SymbolType] = None
    ) -> bool:
        """Declare a match for the original and recomp addresses given, but only if:
        1. The original address is not used elsewhere (as with set_pair)
        2. The recomp address has not already been matched
        If the compare_type is given, update this also, but only if NULL in the db.

        The purpose here is to set matches found via some automated analysis
        but to not overwrite a match provided by the human operator."""
        if self._orig_used(orig):
            # Probable and expected situation. Just ignore it.
            return False

        compare_value = compare_type.value if compare_type is not None else None

        cur = self._db.execute(
            """UPDATE `symbols`
            SET orig_addr = ?, compare_type = coalesce(compare_type, ?)
            WHERE recomp_addr = ?
            AND orig_addr IS NULL""",
            (orig, compare_value, recomp),
        )

        return cur.rowcount > 0

    def set_function_pair(self, orig: int, recomp: int) -> bool:
        """For lineref match or _entry"""
        return self.set_pair(orig, recomp, SymbolType.FUNCTION)

    def _set_opt_bool(self, addr: int, option: str, enabled: bool = True):
        if enabled:
            self._db.execute(
                """INSERT OR IGNORE INTO `match_options`
                (addr, name)
                VALUES (?, ?)""",
                (addr, option),
            )
        else:
            self._db.execute(
                """DELETE FROM `match_options` WHERE addr = ? AND name = ?""",
                (addr, option),
            )

    def mark_stub(self, orig: int):
        self._set_opt_bool(orig, "stub")

    def skip_compare(self, orig: int):
        self._set_opt_bool(orig, "skip")

    def get_match_options(self, addr: int) -> Optional[dict]:
        cur = self._db.execute(
            """SELECT name, value FROM `match_options` WHERE addr = ?""", (addr,)
        )

        return {
            option: value if value is not None else True
            for (option, value) in cur.fetchall()
        }

    def is_vtordisp(self, recomp_addr: int) -> bool:
        """Check whether this function is a vtordisp based on its
        decorated name. If its demangled name is missing the vtordisp
        indicator, correct that."""
        row = self._db.execute(
            """SELECT name, decorated_name
            FROM `symbols`
            WHERE recomp_addr = ?""",
            (recomp_addr,),
        ).fetchone()

        if row is None:
            return False

        (name, decorated_name) = row
        if "`vtordisp" in name:
            return True

        new_name = get_vtordisp_name(decorated_name)
        if new_name is None:
            return False

        self._db.execute(
            """UPDATE `symbols`
            SET name = ?
            WHERE recomp_addr = ?""",
            (new_name, recomp_addr),
        )

        return True

    def _find_potential_match(
        self, name: str, compare_type: SymbolType
    ) -> Optional[int]:
        """Name lookup"""
        match_decorate = compare_type != SymbolType.STRING and name.startswith("?")
        if match_decorate:
            sql = """
            SELECT recomp_addr
            FROM `symbols`
            WHERE orig_addr IS NULL
            AND decorated_name = ?
            AND (compare_type IS NULL OR compare_type = ?)
            LIMIT 1
            """
        else:
            sql = """
            SELECT recomp_addr
            FROM `symbols`
            WHERE orig_addr IS NULL
            AND name = ?
            AND (compare_type IS NULL OR compare_type = ?)
            LIMIT 1
            """

        row = self._db.execute(sql, (name, compare_type.value)).fetchone()
        return row[0] if row is not None else None

    def _find_static_variable(
        self, variable_name: str, function_sym: str
    ) -> Optional[int]:
        """Get the recomp address of a static function variable.
        Matches using a LIKE clause on the combination of:
        1. The variable name read from decomp marker.
        2. The decorated name of the enclosing function.
        For example, the variable "g_startupDelay" from function "IsleApp::Tick"
        has symbol: `?g_startupDelay@?1??Tick@IsleApp@@QAEXH@Z@4HA`
        The function's decorated name is: `?Tick@IsleApp@@QAEXH@Z`"""

        row = self._db.execute(
            """SELECT recomp_addr FROM `symbols`
            WHERE decorated_name LIKE '%' || ? || '%' || ? || '%'
            AND orig_addr IS NULL
            AND (compare_type = ? OR compare_type = ? OR compare_type IS NULL)""",
            (
                variable_name,
                function_sym,
                SymbolType.DATA.value,
                SymbolType.POINTER.value,
            ),
        ).fetchone()
        return row[0] if row is not None else None

    def _match_on(self, compare_type: SymbolType, addr: int, name: str) -> bool:
        # Update the compare_type here too since the marker tells us what we should do

        # Truncate the name to 255 characters. It will not be possible to match a name
        # longer than that because MSVC truncates the debug symbols to this length.
        # See also: warning C4786.
        name = name[:255]

        logger.debug("Looking for %s %s", compare_type.name.lower(), name)
        recomp_addr = self._find_potential_match(name, compare_type)
        if recomp_addr is None:
            return False

        return self.set_pair(addr, recomp_addr, compare_type)

    def match_function(self, addr: int, name: str) -> bool:
        did_match = self._match_on(SymbolType.FUNCTION, addr, name)
        if not did_match:
            logger.error("Failed to find function symbol with name: %s", name)

        return did_match

    def match_vtable(
        self, addr: int, name: str, base_class: Optional[str] = None
    ) -> bool:
        # Only allow a match against "Class:`vftable'"
        # if this is the derived class.
        name = (
            f"{name}::`vftable'"
            if base_class is None or base_class == name
            else f"{name}::`vftable'{{for `{base_class}'}}"
        )

        row = self._db.execute(
            """
            SELECT recomp_addr
            FROM `symbols`
            WHERE orig_addr IS NULL
            AND name = ?
            AND (compare_type = ?)
            LIMIT 1
            """,
            (name, SymbolType.VTABLE.value),
        ).fetchone()

        if row is not None and self.set_pair(addr, row[0], SymbolType.VTABLE):
            return True

        logger.error("Failed to find vtable for class: %s", name)
        return False

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

        recomp_addr = self._find_static_variable(name, decorated_name)
        if recomp_addr is not None:
            # TODO: This variable could be a pointer, but I don't think we
            # have a way to tell that right now.
            if self.set_pair(addr, recomp_addr, SymbolType.DATA):
                return True

        logger.error(
            "Failed to match static variable %s from function %s",
            name,
            function_name,
        )

        return False

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
