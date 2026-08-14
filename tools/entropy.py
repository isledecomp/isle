"""Generate deterministic, non-emitting C++ declaration entropy."""

from __future__ import annotations

import argparse
import io
import os
from pathlib import Path
import random
import string
import sys
import tempfile


# Parameters for tweaking:
MAX_CLASSES = 10
MAX_FUNC_PER_CLASS = 10

# Only the unique suffix, not counting "Class" or "Function"
CLASS_NAME_LEN = 6
FUNC_NAME_LEN = 8


def random_camel_case(generator: random.Random, length: int) -> str:
    """Return a random string with first letter capitalized."""
    return "".join(
        [
            generator.choice(string.ascii_uppercase),
            *generator.choices(string.ascii_lowercase, k=length - 1),
        ]
    )


def generate(seed: int) -> str:
    """Return the exact historical entropy header for ``seed``."""
    generator = random.Random(seed)
    stream = io.StringIO()
    print(f"// Seed: {seed}\n", file=stream)

    num_classes = generator.randint(1, MAX_CLASSES)
    for _ in range(num_classes):
        class_name = "Class" + random_camel_case(generator, CLASS_NAME_LEN)
        print(f"class {class_name} {{", file=stream)
        num_functions = generator.randint(1, MAX_FUNC_PER_CLASS)
        for _ in range(num_functions):
            function_name = "Function" + random_camel_case(generator, FUNC_NAME_LEN)
            print(f"\tinline void {function_name}() {{}}", file=stream)

        print("};\n", file=stream)

    print(file=stream)
    return stream.getvalue()


def atomic_write(path: Path, data: bytes) -> None:
    """Install ``data`` without exposing a partial generated header."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("seed", type=int, nargs="?")
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args(argv)
    seed = (
        arguments.seed
        if arguments.seed is not None
        else random.SystemRandom().randint(0, 10000)
    )
    data = generate(seed).encode("utf-8")
    if arguments.output is None:
        sys.stdout.buffer.write(data)
    else:
        atomic_write(arguments.output, data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
