"""Tests for composition RE-PINNING.

A pin is a claim about what the compiler produced.  When a deliberate source
recovery moves a COMDAT the manifest already composes, that claim stops being
true and the unit refuses -- correctly.  Re-pinning restates the claim from the
objects and then re-runs the UNCHANGED composer over it, exactly as
`repin_overlay.py` restates the overlay's content pins.

These tests fix the three things that make that safe: it refreshes only what
the entry states ABOUT THE OBJECTS, it never invents a key the entry does not
already carry, and it refuses outright for a splice class whose declaration
carries free parameters rather than measurements.
"""
from __future__ import annotations

import copy
import struct
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import byte_identity  # noqa: E402
sys.path.insert(0, str(TOOLS / "tests"))
from test_register_bijection import (  # noqa: E402
    BODY, TARGET_SYMBOL, make_coff, sigma_image,
)


def entry(**overrides):
    record = {
        "mangled": TARGET_SYMBOL,
        "donor": "d_0123456789ab",
        "splice_class": "equal_body_strict",
        "expected_body_length": len(BODY),
        "expected_body_sha256": byte_identity.sha256_bytes(BODY),
        "expected_changed_offsets": [],
    }
    record.update(overrides)
    return record


class RepinnableClassesTest(unittest.TestCase):

    def test_the_closed_set_is_the_measurement_only_classes(self):
        self.assertEqual(
            byte_identity.REPINNABLE_SPLICE_CLASSES,
            frozenset({"equal_body_strict",
                       "equal_body_eh_structural_local",
                       "equal_body_eh_reloc_layout",
                       "same_slot_resize"}),
        )

    def test_refuses_a_certificate_class(self):
        # A certificate's regions, mappings and window orders are DECISIONS.
        # Re-pinning them would silently redesign the proof.
        for splice_class in (byte_identity.REGISTER_BIJECTION_CLASS,
                             byte_identity.INSTRUCTION_SCHEDULE_CLASS,
                             byte_identity.REGISTER_BIJECTION_REENCODING_CLASS,
                             "retail_exact_instruction_mosaic"):
            with self.assertRaises(byte_identity.ByteIdentityError) as caught:
                byte_identity.measure_composition_pins(
                    make_coff(), make_coff(),
                    entry(splice_class=splice_class), "ctx")
            self.assertIn("outside the repinnable classes",
                          str(caught.exception))


class MeasurementTest(unittest.TestCase):

    def setUp(self):
        self.seed = make_coff()
        # A donor at a different colouring: sigma's image over the same body.
        self.donor = make_coff(body=sigma_image())

    def test_a_matching_entry_moves_nothing(self):
        record = entry(
            expected_body_sha256=byte_identity.sha256_bytes(sigma_image()),
            expected_changed_offsets=sorted(
                index for index in range(len(BODY))
                if BODY[index] != sigma_image()[index]),
        )
        _refreshed, moved = byte_identity.repin_composition_function(
            self.seed, self.donor, record, "ctx")
        self.assertEqual(moved, [])

    def test_a_stale_digest_and_delta_are_both_refreshed(self):
        record = entry()          # pins the SEED's body, not the donor's
        refreshed, moved = byte_identity.repin_composition_function(
            self.seed, self.donor, record, "ctx")
        self.assertEqual(moved, ["expected_body_sha256",
                                 "expected_changed_offsets"])
        self.assertEqual(refreshed["expected_body_sha256"],
                         byte_identity.sha256_bytes(sigma_image()))
        self.assertEqual(
            refreshed["expected_changed_offsets"],
            sorted(index for index in range(len(BODY))
                   if BODY[index] != sigma_image()[index]))
        # and the refreshed entry is what the UNCHANGED composer accepts
        composed, _detail = byte_identity.compose_equal_body_comdat(
            self.seed, self.donor, refreshed)
        checked = byte_identity.CoffObject(composed)
        self.assertEqual(
            bytes(byte_identity.coff_body(
                checked, checked.function_section(TARGET_SYMBOL))),
            sigma_image())

    def test_the_stale_entry_still_refuses_before_re_pinning(self):
        with self.assertRaises(byte_identity.ByteIdentityError):
            byte_identity.compose_equal_body_comdat(
                self.seed, self.donor, entry())

    def test_it_never_adds_a_key_the_entry_does_not_carry(self):
        record = entry()
        refreshed, _moved = byte_identity.repin_composition_function(
            self.seed, self.donor, record, "ctx")
        self.assertEqual(set(refreshed), set(record))
        self.assertNotIn("expected_seed_length", refreshed)

    def test_it_never_touches_a_decision_or_a_retail_pin(self):
        record = entry(retail_oracle={"image": "LEGO1.DLL",
                                      "address": "0x10057180",
                                      "verdict": "MATCH",
                                      "length": len(BODY)},
                       retail_relocations=[])
        refreshed, _moved = byte_identity.repin_composition_function(
            self.seed, self.donor, record, "ctx")
        for key in ("mangled", "donor", "splice_class", "retail_oracle",
                    "retail_relocations"):
            self.assertEqual(refreshed[key], record[key])

    def test_an_equal_body_entry_whose_lengths_diverged_refuses(self):
        # Not a re-pin away from valid: the class installs an EQUAL body.
        short = make_coff(body=BODY[:-1] + b"", relocations=(5, 13, 21))
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.measure_composition_pins(
                self.seed, short, entry(), "ctx")
        self.assertIn("no longer the same length", str(caught.exception))

    def test_same_slot_resize_measures_the_span_from_the_donor(self):
        record = {
            "mangled": TARGET_SYMBOL,
            "donor": "d_0123456789ab",
            "splice_class": "same_slot_resize",
            "expected_seed_length": 1,
            "expected_donor_length": 1,
            "expected_linked_span": 16,
            "expected_body_sha256": "0" * 64,
        }
        refreshed, moved = byte_identity.repin_composition_function(
            self.seed, self.donor, record, "ctx")
        self.assertEqual(refreshed["expected_seed_length"], len(BODY))
        self.assertEqual(refreshed["expected_donor_length"], len(BODY))
        self.assertEqual(refreshed["expected_linked_span"],
                         ((len(BODY) + 15) // 16) * 16)
        self.assertEqual(
            set(moved),
            {"expected_seed_length", "expected_donor_length",
             "expected_linked_span", "expected_body_sha256"})


if __name__ == "__main__":
    unittest.main()
