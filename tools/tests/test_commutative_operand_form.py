r"""Tests for the COMMUTATIVE OPERAND FORM primitive.

MSVC 4.2 canonicalises which operand of a commutative x87 product is loaded
first as a function of the translation unit's parse state, so the same
written source renders either `fld X ; fmul Y` or `fld Y ; fmul X`.
`apply_commutative_operand_form` exchanges the two MEMORY OPERANDS of one
adjacent pair and nothing else, under obligations K1..K10.

The fixture computes (v0 * a) + (b + c)-ish shapes; stack depth is not the
primitive's concern (it proves form, adjacency and boundary invariance, and
the arithmetic obligation K7 is discharged in the class comment):

     0: 90            nop                  (shift: pair offsets are positive)
     1: d9 01         fld dword [ecx]      <- site 0 (fmul pair)
     3: d8 08         fmul dword [eax]
     5: de c1         faddp st(1)
     7: d9 42 04      fld dword [edx+4]    <- site 1 (fadd pair)
    10: d8 46 08      fadd dword [esi+8]
    13: de c1         faddp st(1)
    15: d9 5d ec      fstp dword [ebp-0x14]
    18: c3            ret
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import byte_identity  # noqa: E402


BODY = bytes.fromhex(
    "90" "d901" "d808" "dec1" "d94204" "d84608" "dec1" "d95dec" "c3")


def site(pair_offset=1, operation="fmul", offsets=(2, 4), **overrides):
    declared = {
        "pair_offset": pair_offset, "operation": operation,
        "expected_rewritten_offsets": list(offsets),
    }
    declared.update(overrides)
    return declared


def apply(body=BODY, sites=None, relocation_offsets=frozenset(), **kwargs):
    if sites is None:
        sites = [site()]
    return byte_identity.apply_commutative_operand_form(
        body, sites, relocation_offsets, "test", **kwargs)


class CommutativeOperandFormTests(unittest.TestCase):
    def test_the_exchange_swaps_the_operands_and_nothing_else(self):
        image, proof = apply()
        # fld [ecx]; fmul [eax]  ->  fld [eax]; fmul [ecx]
        self.assertEqual(image[1:5], bytes.fromhex("d900d809"))
        self.assertEqual(image[:1], BODY[:1])
        self.assertEqual(image[5:], BODY[5:])
        self.assertEqual(proof["kind"], "commutative_operand_form_v1")
        self.assertEqual(proof["sites"][0]["expected_rewritten_offsets"],
                         [2, 4])
        self.assertEqual(proof["sites"][0]["operation"], "fmul")

    def test_a_disp8_fadd_pair_exchanges_both_encodings(self):
        image, proof = apply(sites=[site(pair_offset=7, operation="fadd",
                                         offsets=(8, 9, 11, 12))])
        # fld [edx+4]; fadd [esi+8]  ->  fld [esi+8]; fadd [edx+4]
        self.assertEqual(image[7:13], bytes.fromhex("d94608" "d84204"))
        self.assertEqual(image[:7], BODY[:7])
        self.assertEqual(image[13:], BODY[13:])
        self.assertEqual(proof["sites"][0]["width"], "m32")

    def test_two_sites_compose_in_order(self):
        image, proof = apply(sites=[
            site(),
            site(pair_offset=7, operation="fadd", offsets=(8, 9, 11, 12)),
        ])
        self.assertEqual(image[1:5], bytes.fromhex("d900d809"))
        self.assertEqual(image[7:13], bytes.fromhex("d94608" "d84204"))
        self.assertEqual(len(proof["sites"]), 2)

    def test_unsorted_sites_are_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            apply(sites=[
                site(pair_offset=7, operation="fadd",
                     offsets=(8, 9, 11, 12)),
                site(),
            ])
        self.assertIn("unsorted or overlapping", str(raised.exception))

    def test_a_non_commutative_operator_is_refused(self):
        """K1: /4 is fsub, which is not commutative."""
        body = bytearray(BODY)
        body[4] = 0x20                          # d8 20 = fsub dword [eax]
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            apply(body=bytes(body))
        self.assertIn("COMMUTATIVE", str(raised.exception))

    def test_fcomp_is_refused(self):
        """K1: /3 does not write ST(0)."""
        body = bytearray(BODY)
        body[4] = 0x18                          # d8 18 = fcomp dword [eax]
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            apply(body=bytes(body))
        self.assertIn("COMMUTATIVE", str(raised.exception))

    def test_a_width_mismatch_is_refused(self):
        """K1: fld m32 with a DC (m64) operator."""
        body = bytearray(BODY)
        body[3] = 0xDC                          # dc 08 = fmul qword [eax]
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            apply(body=bytes(body))
        self.assertIn("m32 x87 memory binary operation",
                      str(raised.exception))

    def test_a_length_mismatch_is_refused(self):
        """K3: exchanging [ecx] with [eax+4] would move the boundary."""
        body = bytearray(BODY[:3]) + bytes.fromhex("d84804") + BODY[5:]
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            apply(body=bytes(body))
        self.assertIn("differ in length", str(raised.exception))

    def test_a_relocation_inside_the_pair_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            apply(relocation_offsets=frozenset({3}))
        self.assertIn("relocation lies inside the pair",
                      str(raised.exception))

    def test_an_absolute_operand_is_refused(self):
        """K4: mod 0, r/m 5 is an absolute address."""
        body = (b"\x90" + bytes.fromhex("d905" "44332211")
                + bytes.fromhex("d808" "dec1" "d95dec" "c3"))
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            apply(body=body, sites=[site(offsets=(2,))])
        self.assertIn("absolute address", str(raised.exception))

    def test_a_branch_into_the_operator_is_refused(self):
        """K5: entering at the operator applies the exchanged operand to a
        different ST(0)."""
        #  0: 74 02      jz +2  (target = 4, the operator)
        #  2: d9 01      fld dword [ecx]
        #  4: d8 08      fmul dword [eax]
        #  6: de c1      faddp
        #  8: d9 5d ec   fstp dword [ebp-0x14]
        # 11: c3         ret
        body = bytes.fromhex("7402" "d901" "d808" "dec1" "d95dec" "c3")
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            apply(body=body, sites=[site(pair_offset=2, offsets=(3, 5))])
        self.assertIn("branch targets the operator", str(raised.exception))

    def test_equal_operands_are_refused(self):
        body = bytearray(BODY)
        body[4] = 0x09                          # d8 09 = fmul dword [ecx]
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            apply(body=bytes(body))
        self.assertIn("already equal", str(raised.exception))

    def test_a_declared_operation_mismatch_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            apply(sites=[site(operation="fadd")])
        self.assertIn("declared operation differs", str(raised.exception))

    def test_wrong_expected_offsets_are_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            apply(sites=[site(offsets=(2, 3))])
        self.assertIn("are not the declared", str(raised.exception))

    def test_a_non_boundary_pair_offset_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            apply(sites=[site(pair_offset=2)])
        self.assertIn("not an instruction boundary", str(raised.exception))

    def test_a_register_operand_is_refused(self):
        """K1: fmul st, st(n) has no memory operand to exchange."""
        body = bytearray(BODY)
        body[3:5] = bytes.fromhex("d8c9")       # fmul st, st(1)
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            apply(body=bytes(body))
        self.assertIn("is a register, not memory", str(raised.exception))


class SeamValidatorTests(unittest.TestCase):
    """The forms list validates inside both seam declarations."""

    def declaration(self, forms):
        return {
            "kind": byte_identity.COMPOSED_REWRITING_KIND,
            "commutative_operand_forms": forms,
            "expected_instruction_count": 9,
            "expected_changed_offsets": sorted(
                {offset for form in forms
                 for offset in form["expected_rewritten_offsets"]}),
            "expected_procedure_range": [len(BODY), 0, len(BODY)],
            "expected_code_symbol_references": [],
            "expected_external_entries": [],
            "expected_seed_debug_s_sha256": "0" * 64,
            "expected_image_debug_s_sha256": "1" * 64,
            "authenticity_rationale": (
                "test fixture: the parse-state-dependent operand order of a "
                "commutative x87 product"),
        }

    def test_a_lone_form_may_stand_alone(self):
        normalized = byte_identity.validate_composed_rewriting(
            self.declaration([site()]), "test", len(BODY))
        self.assertEqual(normalized["commutative_operand_forms"],
                         [{"pair_offset": 1, "operation": "fmul",
                           "expected_rewritten_offsets": [2, 4]}])

    def test_duplicate_rewritten_bytes_are_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            byte_identity.validate_composed_rewriting(
                self.declaration([site(), site(pair_offset=3,
                                               offsets=(4, 6))]),
                "test", len(BODY))
        self.assertIn("rewrite the same byte", str(raised.exception))

    def test_an_unknown_operation_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            byte_identity.validate_composed_rewriting(
                self.declaration([site(operation="fsub")]),
                "test", len(BODY))
        self.assertIn("not a commutative", str(raised.exception))

    def test_donor_seam_accepts_the_same_forms_list(self):
        declaration = {
            "kind": byte_identity.DONOR_REWRITING_KIND,
            "commutative_operand_forms": [site()],
            "expected_instruction_count": 9,
            "expected_changed_offsets": [2, 4],
            "expected_procedure_range": [len(BODY), 0, len(BODY)],
            "expected_code_symbol_references": [],
            "expected_external_entries": [],
            "authenticity_rationale": (
                "test fixture: the parse-state-dependent operand order of a "
                "commutative x87 product"),
        }
        normalized = byte_identity.validate_donor_rewriting(
            declaration, "test", len(BODY))
        self.assertEqual(normalized["commutative_operand_forms"],
                         [{"pair_offset": 1, "operation": "fmul",
                           "expected_rewritten_offsets": [2, 4]}])


if __name__ == "__main__":
    unittest.main()
