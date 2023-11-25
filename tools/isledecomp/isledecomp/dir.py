import os
import subprocess
import sys
from typing import Iterator


class WinePathConverter:
    def __init__(self, unix_cwd):
        self.unix_cwd = unix_cwd
        self.win_cwd = self._call_winepath_unix2win(self.unix_cwd)

    def get_wine_path(self, unix_fn: str) -> str:
        if unix_fn.startswith("./"):
            return self.win_cwd + "\\" + unix_fn[2:].replace("/", "\\")
        if unix_fn.startswith(self.unix_cwd):
            return (
                self.win_cwd
                + "\\"
                + unix_fn.removeprefix(self.unix_cwd).replace("/", "\\").lstrip("\\")
            )
        return self._call_winepath_unix2win(unix_fn)

    def get_unix_path(self, win_fn: str) -> str:
        if win_fn.startswith(".\\") or win_fn.startswith("./"):
            return self.unix_cwd + "/" + win_fn[2:].replace("\\", "/")
        if win_fn.startswith(self.win_cwd):
            return (
                self.unix_cwd
                + "/"
                + win_fn.removeprefix(self.win_cwd).replace("\\", "/")
            )
        return self._call_winepath_win2unix(win_fn)

    @staticmethod
    def _call_winepath_unix2win(fn: str) -> str:
        return subprocess.check_output(["winepath", "-w", fn], text=True).strip()

    @staticmethod
    def _call_winepath_win2unix(fn: str) -> str:
        return subprocess.check_output(["winepath", fn], text=True).strip()


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
