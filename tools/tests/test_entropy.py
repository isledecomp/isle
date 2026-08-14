#!/usr/bin/env python3
"""Standalone tests for deterministic declaration entropy generation."""

from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import unittest


TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))

import entropy  # noqa: E402


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class EntropyTests(unittest.TestCase):
    def test_historical_seed_bytes_remain_stable(self):
        self.assertEqual(
            digest(entropy.generate(638847751)),
            "ab52dfd59e21a2e67253e650f9ce656511b93fe06a8e2c6c92f47892c21e6cc7",
        )

    def test_declaration_shape_matches_the_authenticated_search_bytes(self):
        self.assertEqual(
            digest(entropy.generate_shape(2, 3)),
            "fcac8dfe7db78fdfbe3d9f1942feb51de8fc0f14885b8e4c23b695da2b4dff27",
        )

    def test_declaration_shape_rejects_out_of_range_dimensions(self):
        for classes, functions in ((0, 1), (11, 11), (2, 1), (2, 21)):
            with self.subTest(classes=classes, functions=functions):
                with self.assertRaises(ValueError):
                    entropy.generate_shape(classes, functions)


if __name__ == "__main__":
    unittest.main()
