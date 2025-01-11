from dataclasses import dataclass, field
import logging

from lego_util.exceptions import (
    TypeNotFoundInGhidraError,
    ClassOrNamespaceNotFoundInGhidraError,
)

logger = logging.getLogger(__name__)


@dataclass
class Statistics:
    functions_changed: int = 0
    successes: int = 0
    failures: dict[str, int] = field(default_factory=dict)
    known_missing_types: dict[str, int] = field(default_factory=dict)
    known_missing_namespaces: dict[str, int] = field(default_factory=dict)

    def track_failure_and_tell_if_new(self, error: Exception) -> bool:
        """
        Adds the error to the statistics. Returns `False` if logging the error would be redundant
        (e.g. because it is a `TypeNotFoundInGhidraError` with a type that has been logged before).
        """
        error_type_name = error.__class__.__name__
        self.failures[error_type_name] = (
            self.failures.setdefault(error_type_name, 0) + 1
        )

        if isinstance(error, TypeNotFoundInGhidraError):
            return self._add_occurence_and_check_if_new(
                self.known_missing_types, error.args[0]
            )

        if isinstance(error, ClassOrNamespaceNotFoundInGhidraError):
            return self._add_occurence_and_check_if_new(
                self.known_missing_namespaces, error.get_namespace_str()
            )

        # We do not have detailed tracking for other errors, so we want to log them every time
        return True

    def _add_occurence_and_check_if_new(self, target: dict[str, int], key: str) -> bool:
        old_count = target.setdefault(key, 0)
        target[key] = old_count + 1
        return old_count == 0

    def log(self):
        logger.info("Statistics:\n~~~~~")
        logger.info(
            "Missing types (with number of occurences): %s\n~~~~~",
            self.format_statistics(self.known_missing_types),
        )
        logger.info(
            "Missing classes/namespaces (with number of occurences): %s\n~~~~~",
            self.format_statistics(self.known_missing_namespaces),
        )
        logger.info("Successes: %d", self.successes)
        logger.info("Failures: %s", self.failures)
        logger.info("Functions changed: %d", self.functions_changed)

    def format_statistics(self, stats: dict[str, int]) -> str:
        if len(stats) == 0:
            return "<none>"
        return ", ".join(
            f"{entry[0]} ({entry[1]})"
            for entry in sorted(stats.items(), key=lambda x: x[1], reverse=True)
        )
