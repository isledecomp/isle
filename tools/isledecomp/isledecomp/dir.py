import os
from typing import Iterator


def is_file_cpp(filename: str) -> bool:
    (_, ext) = os.path.splitext(filename)
    return ext.lower() in ('.h', '.cpp')


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
