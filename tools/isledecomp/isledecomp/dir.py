import os
import subprocess
import sys
import pathlib
from typing import Iterator


def winepath_win_to_unix(path: str) -> str:
    return subprocess.check_output(["winepath", path], text=True).strip()


def winepath_unix_to_win(path: str) -> str:
    return subprocess.check_output(["winepath", "-w", path], text=True).strip()


class PathResolver:
    """Intended to resolve Windows/Wine paths used in the PDB (cvdump) output
    into a "canonical" format to be matched against code file paths from os.walk.
    MSVC may include files from the parent dir using `..`. We eliminate those and create
    an absolute path so that information about the same file under different names
    will be combined into the same record. (i.e. line_no/addr pairs from LINES section.)
    """

    def __init__(self, basedir) -> None:
        """basedir is the root path of the code directory in the format for your OS.
        We will convert it to a PureWindowsPath to be platform-independent
        and match that to the paths from the PDB."""

        # Memoize the converted paths. We will need to do this for each path
        # in the PDB, for each function in that file. (i.e. lots of repeated work)
        self._memo = {}

        # Convert basedir to an absolute path if it is not already.
        # If it is not absolute, we cannot do the path swap on unix.
        self._realdir = pathlib.Path(basedir).resolve()

        self._is_unix = os.name != "nt"
        if self._is_unix:
            self._basedir = pathlib.PureWindowsPath(
                winepath_unix_to_win(str(self._realdir))
            )
        else:
            self._basedir = self._realdir

    def _memo_wrapper(self, path_str: str) -> str:
        """Wrapper so we can memoize from the public caller method"""
        path = pathlib.PureWindowsPath(path_str)
        if not path.is_absolute():
            # pathlib syntactic sugar for path concat
            path = self._basedir / path

        if self._is_unix:
            # If the given path is relative to the basedir, deconstruct the path
            # and swap in our unix path to avoid an expensive call to winepath.
            try:
                # Will raise ValueError if we are not relative to the base.
                section = path.relative_to(self._basedir)
                # Should combine to pathlib.PosixPath
                mockpath = (self._realdir / section).resolve()
                if mockpath.is_file():
                    return str(mockpath)
            except ValueError:
                pass

            # We are not relative to the basedir, or our path swap attempt
            # did not point at an actual file. Either way, we are forced
            # to call winepath using our original path.
            return winepath_win_to_unix(str(path))

        # We must be on Windows. Convert back to WindowsPath.
        # The resolve() call will eliminate intermediate backdir references.
        return str(pathlib.Path(path).resolve())

    def resolve_cvdump(self, path_str: str) -> str:
        """path_str is in Windows/Wine path format.
        We will return a path in the format for the host OS."""
        if path_str not in self._memo:
            self._memo[path_str] = self._memo_wrapper(path_str)

        return self._memo[path_str]


def is_file_cpp(filename: str) -> bool:
    (_, ext) = os.path.splitext(filename)
    return ext.lower() in (".h", ".cpp")


def walk_source_dir(source: str, recursive: bool = True) -> Iterator[str]:
    """Generator to walk the given directory recursively and return
    any C++ files found."""

    source = os.path.abspath(source)
    for subdir, _, files in os.walk(source):
        for file in files:
            if is_file_cpp(file):
                yield os.path.join(subdir, file)

        if not recursive:
            break


def get_file_in_script_dir(fn):
    return os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), fn)
