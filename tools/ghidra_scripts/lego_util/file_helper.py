import os
import sys

if sys.version_info.major > 2:
    from typing import Callable


def iterate_dir(path, file_callback):  # type: (str, Callable[[str], None]) -> None
    for file_or_dir_name in os.listdir(path):  # pathlib not supported
        child_path = os.path.join(path, file_or_dir_name)
        if os.path.isdir(child_path):
            iterate_dir(child_path, file_callback)
        else:
            file_callback(child_path)
