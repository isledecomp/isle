"""Tests for obligation 6b of the instruction-schedule certificate: a window
that MOVES a relocated operand.

The class previously refused any window carrying a relocation.  The extension
admits exactly one thing: a window that DECLARES where each of its relocations
lands, where the landing site is re-derived from the permutation itself (the
record moves with its own instruction, by nothing else) and must equal the
declaration.  Everything the record carries but its offset -- symbol, type,
width, addend -- is untouched, the ascending-offset invariant of the table is
re-asserted, and installation is delegated to `equal_body_eh_reloc_layout`,
the one primitive that can install a moved record.

The fixture is the real shape of `Act3Ammo::Animate`'s window:

    0:  53              push ebx                        <- outside the window
    1:  56              push esi
    2:  c7 45 84 <r32>  mov dword ptr [ebp-0x7c], SYM    <- window, relocated
    9:  8b 45 94        mov eax, dword ptr [ebp-0x6c]
    12: 5e              pop esi                          <- outside the window
    13: 5b              pop ebx
    14: c3              ret

The two window instructions touch disjoint `ebp` spans and disjoint registers,
so the dependence DAG is empty and `[1, 0]` is a legal topological order.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import byte_identity  # noqa: E402


PROLOGUE = bytes.fromhex("5356")
STORE = bytes.fromhex("c7458400000000")      # mov [ebp-0x7c], imm32
LOAD = bytes.fromhex("8b4594")               # mov eax, [ebp-0x6c]
EPILOGUE = bytes.fromhex("5e5bc3")
BODY = PROLOGUE + STORE + LOAD + EPILOGUE
START = len(PROLOGUE)
END = START + len(STORE) + len(LOAD)
IMAGE = PROLOGUE + LOAD + STORE + EPILOGUE

RELOCATION_OFFSET = START + 3                # the store's imm32 field
RESEATED_OFFSET = START + len(LOAD) + 3      # where the permutation puts it
SYMBOLS = {RELOCATION_OFFSET: {"width": 4, "target": "??_7Vector3@@6B@"}}
COVERED = frozenset(range(RELOCATION_OFFSET, RELOCATION_OFFSET + 4))


def window(reseat=None, order=(1, 0), lengths=(7, 3), edges=()):
    declaration = {
        "start": START, "end": END,
        "source_instruction_lengths": list(lengths),
        "target_order": list(order),
        "expected_dependence_edges": [list(edge) for edge in edges],
    }
    if reseat is not None:
        declaration["relocation_reseat"] = [list(pair) for pair in reseat]
    return declaration


def apply(windows=None, body=BODY, covered=COVERED, symbols=None):
    return byte_identity.apply_instruction_schedule(
        body,
        [window([[RELOCATION_OFFSET, RESEATED_OFFSET]])]
        if windows is None else windows,
        covered, "image", SYMBOLS if symbols is None else symbols)


class ReseatDerivationTests(unittest.TestCase):
    """The reseat is MEASURED from the permutation, never taken on trust."""

    def test_the_declared_reseat_is_the_permutation_s_own(self):
        image, proof = apply()
        self.assertEqual(image, IMAGE)
        self.assertEqual(proof["relocation_reseat"],
                         [[RELOCATION_OFFSET, RESEATED_OFFSET]])
        self.assertEqual(proof["windows"][0]["relocation_reseat"],
                         [[RELOCATION_OFFSET, RESEATED_OFFSET]])
        # the operand bytes travel with their instruction and nothing else
        self.assertEqual(image[RESEATED_OFFSET:RESEATED_OFFSET + 4],
                         BODY[RELOCATION_OFFSET:RELOCATION_OFFSET + 4])

    def test_an_undeclared_relocation_still_refuses(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            apply(windows=[window()])
        self.assertIn("refuses to move a relocation", str(caught.exception))

    def test_a_reseat_that_differs_from_the_measurement_refuses(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            apply(windows=[window([[RELOCATION_OFFSET, RESEATED_OFFSET + 1]])])
        self.assertIn("differs from its declaration", str(caught.exception))

    def test_a_reseat_declared_with_no_relocation_inside_refuses(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            apply(covered=frozenset(), symbols={})
        self.assertIn("no relocation operand lies inside the window",
                      str(caught.exception))

    def test_a_relocation_straddling_the_window_boundary_refuses(self):
        symbols = dict(SYMBOLS)
        symbols[START - 1] = {"width": 4, "target": "??_7Vector3@@6B@"}
        covered = COVERED | frozenset(range(START - 1, START + 3))
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            apply(covered=covered, symbols=symbols)
        self.assertIn("straddles the window boundary", str(caught.exception))

    def test_a_relocation_straddling_an_instruction_boundary_refuses(self):
        symbols = {START + 5: {"width": 4, "target": "??_7Vector3@@6B@"}}
        covered = frozenset(range(START + 5, START + 9))
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            apply(windows=[window([[START + 5, START + 8]])],
                  covered=covered, symbols=symbols)
        self.assertIn("straddles an instruction boundary",
                      str(caught.exception))

    def test_a_reseat_without_the_relocation_records_refuses(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            apply(symbols={})
        self.assertIn("needs the relocation records", str(caught.exception))


class ReseatSchemaTests(unittest.TestCase):
    """The manifest declaration is a closed, bounded shape."""

    def spec(self, reseat):
        return {
            "kind": "topological_window_reordering_v1",
            "windows": [{**window(reseat), "expected_line_rows": []}],
            "expected_instruction_count": 6,
            "expected_changed_offsets": list(range(START, END)),
            "expected_procedure_range": [len(BODY), 0, len(BODY)],
            "expected_code_symbol_references": [],
            "authenticity_rationale": "x" * 64,
        }

    def test_a_valid_reseat_is_normalised(self):
        value = byte_identity.validate_instruction_schedule(
            self.spec([[RELOCATION_OFFSET, RESEATED_OFFSET]]), "spec",
            len(BODY))
        self.assertEqual(value["windows"][0]["relocation_reseat"],
                         [[RELOCATION_OFFSET, RESEATED_OFFSET]])

    def test_a_window_without_a_reseat_declares_none(self):
        value = byte_identity.validate_instruction_schedule(
            self.spec(None), "spec", len(BODY))
        self.assertNotIn("relocation_reseat", value["windows"][0])

    def test_an_offset_outside_the_window_is_refused(self):
        for bad in ([[0, RESEATED_OFFSET]],
                    [[RELOCATION_OFFSET, END]],
                    [[RELOCATION_OFFSET, RELOCATION_OFFSET]],
                    [[RELOCATION_OFFSET, RESEATED_OFFSET],
                     [RELOCATION_OFFSET, START]],
                    []):
            with self.subTest(bad=bad):
                with self.assertRaises(byte_identity.ByteIdentityError):
                    byte_identity.validate_instruction_schedule(
                        self.spec(bad), "spec", len(BODY))


class ReseatDelegateTests(unittest.TestCase):
    """Only one installation primitive can carry a moved record."""

    def test_a_reseat_selects_the_reloc_layout_delegate(self):
        for closure in (byte_identity.INSTRUCTION_SCHEDULE_FPO_CLOSURE,
                        byte_identity.INSTRUCTION_SCHEDULE_EH_CLOSURE):
            for renames in ([], [[12, "L"]]):
                with self.subTest(closure=closure, renames=renames):
                    self.assertEqual(
                        byte_identity.instruction_schedule_delegate(
                            closure, renames, True),
                        "equal_body_eh_reloc_layout")

    def test_without_a_reseat_the_delegates_are_unchanged(self):
        self.assertEqual(
            byte_identity.instruction_schedule_delegate(
                byte_identity.INSTRUCTION_SCHEDULE_FPO_CLOSURE, []),
            "equal_body_strict")
        self.assertEqual(
            byte_identity.instruction_schedule_delegate(
                byte_identity.INSTRUCTION_SCHEDULE_EH_CLOSURE, []),
            "equal_body_eh_structural_local")


if __name__ == "__main__":
    unittest.main()
