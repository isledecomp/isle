"""Provides a reference point for redistributed tools found in this directory.
This allows you to get the path for these tools from a script run anywhere."""
from os.path import join, dirname


def lib_path() -> str:
    """Returns the directory for this module."""
    return dirname(__file__)


def lib_path_join(name: str) -> str:
    """Convenience wrapper for os.path.join."""
    return join(lib_path(), name)
