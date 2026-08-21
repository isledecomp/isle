"""Tests for the instruction-FORM screen.

The screen's verdict decides whether a row is funded as a colouring problem or
as a source problem, so the four corrections that make it sound each get a
test: `+r` opcodes carry their register IN the opcode, a field-only comparison
misses displacements, the accumulator short forms are one byte shorter than
their ModRM equivalents, and the two operand-direction encodings are the same
instruction.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import formscan  # noqa: E402


EMPTY = frozenset()


def scan(ours: bytes, theirs: bytes, masked=EMPTY):
    return formscan.scan(ours, theirs, masked)


def kinds(result):
    return sorted(step["kind"] for step in result["steps"] if step["kind"])


class OpcodeRegisterFieldTest(unittest.TestCase):
    """`push esi` and `push edi` are the SAME form."""

    def test_opreg_forms_are_one_form(self):
        result = scan(bytes.fromhex("56c3"), bytes.fromhex("57c3"))
        self.assertIsNone(result["error"])
        self.assertEqual(len(result["steps"]), 2)
        self.assertEqual(result["steps"][0]["ours_registers"], [6])
        self.assertEqual(result["steps"][0]["retail_registers"], [7])
        self.assertFalse(result["steps"][0]["same"])
        self.assertEqual(kinds(result), [])

    def test_a_genuinely_different_opcode_still_diverges(self):
        # push esi against pop esi: different operation, same +r field.
        result = scan(bytes.fromhex("56c3"), bytes.fromhex("5ec3"))
        self.assertIn("form divergence", result["error"])


class NonRegisterResidueTest(unittest.TestCase):
    """A field-only comparison misses displacements; this one must not."""

    def test_a_displacement_difference_is_structural(self):
        # fld qword [esp+0x10] against fld qword [esp+0x18]
        ours = bytes.fromhex("dd44241033c3")
        theirs = bytes.fromhex("dd44241833c3")
        result = scan(ours, theirs)
        self.assertIsNone(result["error"])
        self.assertEqual(kinds(result), ["other"])

    def test_a_relocated_operand_is_masked_out(self):
        # mov ebx,[_Nil]: the four relocated bytes differ and must not count.
        ours = bytes.fromhex("8b1d00000000c3")
        theirs = bytes.fromhex("8b1d00320f10c3")
        masked = frozenset({2, 3, 4, 5})
        result = scan(ours, theirs, masked)
        self.assertIsNone(result["error"])
        self.assertEqual(kinds(result), [])
        self.assertTrue(result["steps"][0]["same"])

    def test_the_same_displacement_is_not_residue(self):
        result = scan(bytes.fromhex("dd44241033c3"),
                      bytes.fromhex("dd44241033c3"))
        self.assertEqual(kinds(result), [])
        self.assertTrue(all(step["same"] for step in result["steps"]))


class AccumulatorFormTest(unittest.TestCase):
    """`add eax,imm32` is one byte shorter than `add r/m32,imm32`."""

    def test_the_two_encodings_are_one_form_with_a_length_change(self):
        ours = bytes.fromhex("81c2c0000000c3")     # add edx, 0xc0   (6 bytes)
        theirs = bytes.fromhex("05c0000000c3")     # add eax, 0xc0   (5 bytes)
        result = scan(ours, theirs)
        self.assertIsNone(result["error"])
        self.assertEqual(kinds(result), ["accform"])
        self.assertEqual(result["steps"][0]["ours_registers"], [2])
        self.assertEqual(result["steps"][0]["retail_registers"], [0])

    def test_a_different_immediate_is_not_the_same_form(self):
        ours = bytes.fromhex("81c2c0000000c3")
        theirs = bytes.fromhex("05c1000000c3")
        result = scan(ours, theirs)
        self.assertIn("form divergence", result["error"])

    def test_a_different_group_digit_is_not_the_same_form(self):
        ours = bytes.fromhex("81eac0000000c3")     # sub edx, 0xc0
        theirs = bytes.fromhex("05c0000000c3")     # add eax, 0xc0
        result = scan(ours, theirs)
        self.assertIn("form divergence", result["error"])


class OperandDirectionFormTest(unittest.TestCase):
    """`3B /r` and `39 /r` are the same instruction in two encodings."""

    def test_the_two_directions_of_one_compare_agree(self):
        ours = bytes.fromhex("3bd6c3")             # cmp edx, esi
        theirs = bytes.fromhex("39f2c3")           # cmp edx, esi
        result = scan(ours, theirs)
        self.assertIsNone(result["error"])
        self.assertEqual(kinds(result), ["dirform"])
        self.assertTrue(result["steps"][0]["same"])

    def test_reversed_operands_are_reported_as_a_register_difference(self):
        ours = bytes.fromhex("3bd6c3")             # cmp edx, esi
        theirs = bytes.fromhex("39d6c3")           # cmp esi, edx
        result = scan(ours, theirs)
        self.assertIsNone(result["error"])
        self.assertFalse(result["steps"][0]["same"])

    def test_a_memory_operand_is_not_a_direction_form(self):
        # ours `cmp edx, esi`, retail `cmp [ebp+0x20], esi` -- genuinely
        # different instructions, and the screen must say so.
        ours = bytes.fromhex("3bd6c3")
        theirs = bytes.fromhex("397520c3")
        result = scan(ours, theirs)
        self.assertIn("form divergence", result["error"])


class VerdictTest(unittest.TestCase):

    def test_closable_shape_needs_the_walk_to_complete_and_other_zero(self):
        ours = bytes.fromhex("56c3")
        theirs = bytes.fromhex("57c3")
        label, counts = formscan.verdict(scan(ours, theirs))
        self.assertEqual(label, "CLOSABLE SHAPE")
        self.assertEqual(counts, {})

    def test_a_structural_residue_is_not_closable(self):
        ours = bytes.fromhex("dd44241033c3")
        theirs = bytes.fromhex("dd44241833c3")
        label, counts = formscan.verdict(scan(ours, theirs))
        self.assertEqual(label, "STRUCTURAL")
        self.assertEqual(counts, {"other": 1})

    def test_a_form_divergence_is_reported_as_diverging(self):
        label, _counts = formscan.verdict(
            scan(bytes.fromhex("56c3"), bytes.fromhex("5ec3")))
        self.assertEqual(label, "DIVERGES")

    def test_a_ragged_end_is_an_error(self):
        result = scan(bytes.fromhex("56c3"), bytes.fromhex("56"))
        self.assertIsNotNone(result["error"])


if __name__ == "__main__":
    unittest.main()


class ReEncodeVersusTranspositionTest(unittest.TestCase):
    """A length difference is only an EBP re-encoding when EBP forces it.

    Found on 0x100b2a70: three inlined `PrepareRects` `sub` transpositions
    change a step's length, and classifying every length change as `reencode`
    hid them from the `other == 0` screen -- a FALSE PASS on a row that does
    not close.
    """

    def test_an_ebp_base_growing_a_disp8_is_a_reencoding(self):
        ours = bytes.fromhex("8b2fc3")        # mov ebp, [edi]     2 bytes
        theirs = bytes.fromhex("8b7d00c3")    # mov edi, [ebp+0]   3 bytes
        result = scan(ours, theirs)
        self.assertIsNone(result["error"])
        self.assertEqual(kinds(result), ["reencode"])

    def test_a_transposition_that_changes_length_is_STRUCTURAL(self):
        # `sub eax, [ebp-0x38]` (3 B) against `sub eax, ecx` (2 B): same
        # opcode, but no EBP base crossing -- one side has a register operand.
        ours = bytes.fromhex("2b45c8c3")
        theirs = bytes.fromhex("2bc1c3")
        result = scan(ours, theirs)
        self.assertEqual(kinds(result), ["other"])

    def test_a_length_change_with_no_ebp_on_either_side_is_structural(self):
        ours = bytes.fromhex("8b08c3")        # mov ecx, [eax]     2 bytes
        theirs = bytes.fromhex("8b4800c3")    # mov ecx, [eax+0]   3 bytes
        result = scan(ours, theirs)
        self.assertEqual(kinds(result), ["other"])

    def test_a_length_change_with_a_different_opcode_is_structural(self):
        ours = bytes.fromhex("8b2fc3")        # mov ebp, [edi]
        theirs = bytes.fromhex("037d00c3")    # add edi, [ebp+0]
        result = scan(ours, theirs)
        self.assertIn(kinds(result), (["other"], []))
        self.assertNotEqual(kinds(result), ["reencode"])
