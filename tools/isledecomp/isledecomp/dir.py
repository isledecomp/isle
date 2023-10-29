import os
from typing import Iterator


def file_is_cpp(filename: str) -> bool:
    (basefile, ext) = os.path.splitext(filename)
    return ext.lower() in ('.h', '.cpp')


def walk_source_dir(source: str) -> Iterator[str]:
    """Generator to walk the given directory recursively and return
       any C++ files found."""

    for subdir, dirs, files in os.walk(source):
        for file in files:
            if file_is_cpp(file):
                yield os.path.join(subdir, file)
