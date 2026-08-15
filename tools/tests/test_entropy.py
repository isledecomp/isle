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

    def test_forward_run_matches_exact_authenticated_bytes(self):
        expected = b"".join(
            b"class Zq%02d;\n" % number for number in range(13)
        )
        actual = entropy.generate_forward_run("Zq", 13, 2).encode("utf-8")
        self.assertEqual(actual, expected)
        self.assertEqual(
            digest(actual),
            "51fbda28b802be9f2b7ca3ea2d04830811034a677df18eba799443c021d2d394",
        )
        self.assertEqual(
            digest(entropy.generate_forward_run(
                "MxUnkRecVA", 57, 3).encode("utf-8")),
            "c081b11da0c6102c839a9ae7c34b4b342ab634b2f9aed182e9b18ceab539f759",
        )

    def test_forward_run_is_deterministic_and_declaration_only(self):
        first = entropy.generate_forward_run("MxUnkRecVA", 57, 3)
        self.assertEqual(entropy.generate_forward_run("MxUnkRecVA", 57, 3),
                         first)
        for line in first.splitlines():
            self.assertRegex(line, r"^class [A-Za-z][A-Za-z0-9]*\d+;$")

    def test_forward_run_rejects_invalid_parameters(self):
        invalid = (
            ("", 1, 1),
            ("9bad", 1, 1),
            ("Has Space", 1, 1),
            ("Zq", 0, 2),
            ("Zq", 1000, 3),
            ("Zq", 1, 0),
            ("Zq", 1, 4),
            ("Zq", 101, 2),
        )
        for prefix, count, width in invalid:
            with self.subTest(prefix=prefix, count=count, width=width):
                with self.assertRaises(ValueError):
                    entropy.generate_forward_run(prefix, count, width)

    def test_extern_run_is_deterministic_and_declaration_only(self):
        first = entropy.generate_extern_run("g_p", 17, 2)
        self.assertEqual(entropy.generate_extern_run("g_p", 17, 2), first)
        for line in first.splitlines():
            self.assertRegex(line, r"^extern int [A-Za-z_][A-Za-z0-9_]*\d+;$")
        with self.assertRaises(ValueError):
            entropy.generate_extern_run("", 1, 1)
        with self.assertRaises(ValueError):
            entropy.generate_extern_run("g_p", 1000, 3)

    def test_legacy_generator_and_cli_surface_are_absent(self):
        self.assertEqual(
            {name for name in vars(entropy) if not name.startswith("_")},
            {"generate_shape", "generate_forward_run", "generate_extern_run"},
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
