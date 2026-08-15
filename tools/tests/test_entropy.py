#!/usr/bin/env python3
"""Standalone tests for deterministic declaration entropy generation."""

from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))

import entropy  # noqa: E402


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class EntropyTests(unittest.TestCase):
    def test_declaration_shape_matches_exact_authenticated_bytes(self):
        expected = (
            b"// Generated declaration-only entropy shape. Emits no code or data.\n"
            b"// Shape: classes=2 functions=3\n"
            b"\n"
            b"class ClassAaaaaa {\n"
            b"public:\n"
            b"\tinline void FunctionAaaaaaaa() {}\n"
            b"\tinline void FunctionBaaaaaaa() {}\n"
            b"};\n"
            b"\n"
            b"class ClassBaaaaa {\n"
            b"public:\n"
            b"\tinline void FunctionCaaaaaaa() {}\n"
            b"};\n"
            b"\n"
        )
        actual = entropy.generate_shape(2, 3).encode("utf-8")
        self.assertEqual(actual, expected)
        self.assertEqual(
            digest(actual),
            "fcac8dfe7db78fdfbe3d9f1942feb51de8fc0f14885b8e4c23b695da2b4dff27",
        )

    def test_declaration_shape_is_deterministic(self):
        first = entropy.generate_shape(10, 100)
        self.assertEqual(entropy.generate_shape(10, 100), first)

    def test_declaration_shape_accepts_inclusive_dimension_bounds(self):
        self.assertTrue(entropy.generate_shape(1, 1))
        self.assertTrue(entropy.generate_shape(10, 10))
        self.assertTrue(entropy.generate_shape(10, 100))

    def test_declaration_shape_rejects_out_of_range_dimensions(self):
        invalid = (
            (0, 1),
            (11, 11),
            (1, 0),
            (1, 11),
            (2, 1),
            (2, 21),
            (10, 9),
            (10, 101),
        )
        for classes, functions in invalid:
            with self.subTest(classes=classes, functions=functions):
                with self.assertRaises(ValueError):
                    entropy.generate_shape(classes, functions)

    def test_legacy_generator_and_cli_surface_are_absent(self):
        self.assertEqual(
            {name for name in vars(entropy) if not name.startswith("_")},
            {"generate_shape"},
        )
        for name in (
            "atomic_write",
            "generate",
            "main",
            "random",
            "random_camel_case",
        ):
            with self.subTest(name=name):
                self.assertFalse(hasattr(entropy, name))

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "entropy.h"
            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOLS / "entropy.py"),
                    "638847751",
                    "--output",
                    str(output),
                ],
                check=False,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")
            self.assertEqual(result.stderr, b"")
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
