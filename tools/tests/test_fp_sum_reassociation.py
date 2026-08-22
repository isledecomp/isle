r"""Tests for the FP-SUM REASSOCIATION primitive and the donor-rewriting class.

A dot-product expression compiles, under MSVC 4.2 /O2, to (fld m64; fmul m64)
product pairs joined by `faddp st(1)` -- and the order in which the compiler
emits the pairs is an internal scheduling choice, not the source's: one macro
expansion renders its sums in several different pair orders inside a single
function, and donor states of the same translation unit render yet others,
including retail's.  `apply_fp_sum_reassociation` expresses exactly that
licence: a permutation of whole product pairs among the PAIR slots of one
chain, with the faddp skeleton, the pair multiset and every byte outside the
chain unchanged (obligations F1..F5 in the class comment).

The fixture body is a miniature of the real row (0x100a46b0):

     0:  53              push ebx
     1:  56              push esi
     2:  33 c9           xor  ecx, ecx        <- sigma region
     4:  8b 09           mov  ecx, [ecx]      <- sigma region
     6:  dd 44 24 10     fld  qword [esp+0x10]  \  pair 0
    10:  dc 4c 24 18     fmul qword [esp+0x18]  /
    14:  dd 44 24 20     fld  qword [esp+0x20]  \  pair 1
    18:  dc 4c 24 28     fmul qword [esp+0x28]  /
    22:  de c1           faddp st(1)
    24:  dd 44 24 30     fld  qword [esp+0x30]  \  pair 2
    28:  dc 4c 24 38     fmul qword [esp+0x38]  /
    32:  de c1           faddp st(1)
    34:  dd 5c 24 08     fstp qword [esp+8]
    38:  5e 5b c3        pop esi; pop ebx; ret
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import byte_identity  # noqa: E402
import test_instruction_schedule as fixture  # noqa: E402
import test_composed_rewriting as composed_fixture  # noqa: E402


PROLOGUE = bytes.fromhex("5356" "33c9" "8b09")
PAIRS = [bytes.fromhex("dd442410" "dc4c2418"),
         bytes.fromhex("dd442420" "dc4c2428"),
         bytes.fromhex("dd442430" "dc4c2438")]
FADDP = bytes.fromhex("dec1")
FSTP = bytes.fromhex("dd5c2408")
TAIL = FSTP + bytes.fromhex("5e5bc3")
CHAIN = PAIRS[0] + PAIRS[1] + FADDP + PAIRS[2] + FADDP
BODY = PROLOGUE + CHAIN + TAIL
SIZE = len(BODY)
CHAIN_START = len(PROLOGUE)
CHAIN_END = CHAIN_START + len(CHAIN)
SIGMA_REGION = (2, 6)
ORDER = [1, 0, 2]
PERMUTED = PAIRS[1] + PAIRS[0] + FADDP + PAIRS[2] + FADDP
IMAGE_FP = PROLOGUE + PERMUTED + TAIL


def chain_declaration(**overrides):
    item = {
        "chain_start": CHAIN_START, "chain_end": CHAIN_END,
        "order": list(ORDER),
        "expected_rewritten_offsets": sorted(
            index for index in range(CHAIN_START, CHAIN_END)
            if BODY[index] != IMAGE_FP[index]),
    }
    item.update(overrides)
    return item


def apply_chains(body=BODY, chains=None, relocations=frozenset()):
    return byte_identity.apply_fp_sum_reassociation(
        body, chains if chains is not None else [chain_declaration()],
        relocations, "test")


class ApplyTests(unittest.TestCase):
    """F1..F5 on the primitive itself."""

    def test_a_declared_permutation_reaches_the_permuted_chain(self):
        image, proof = apply_chains()
        self.assertEqual(image, IMAGE_FP)
        chain = proof["chains"][0]
        self.assertEqual(chain["pair_count"], 3)
        self.assertEqual(chain["faddp_count"], 2)
        self.assertEqual(chain["order"], ORDER)

    def test_the_pair_multiset_and_skeleton_survive_the_rewrite(self):
        image, _ = apply_chains()
        self.assertEqual(sorted([image[6:14], image[14:22], image[24:32]]),
                         sorted(PAIRS))
        self.assertEqual(image[22:24], FADDP)
        self.assertEqual(image[32:34], FADDP)
        self.assertEqual(image[:CHAIN_START], BODY[:CHAIN_START])
        self.assertEqual(image[CHAIN_END:], BODY[CHAIN_END:])

    def test_an_identity_permutation_does_not_move_the_body(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            apply_chains(chains=[chain_declaration(
                order=[0, 1, 2], expected_rewritten_offsets=[CHAIN_START])])
        self.assertIn("does not move the body", str(raised.exception))

    def test_an_order_that_is_not_a_permutation_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            apply_chains(chains=[chain_declaration(order=[1, 1, 2])])
        self.assertIn("not a permutation", str(raised.exception))

    def test_a_non_fp_instruction_inside_the_chain_is_refused(self):
        """F1: only fld m64, fmul m64 and faddp st(1) may appear."""
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            apply_chains(chains=[chain_declaration(chain_end=CHAIN_END + 4)])
        self.assertIn("not an fld m64, fmul m64 or faddp",
                      str(raised.exception))

    def test_a_chain_that_splits_a_product_pair_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            apply_chains(chains=[chain_declaration(
                chain_end=CHAIN_START + 4, order=[1, 0])])
        self.assertIn("ends inside a product pair", str(raised.exception))

    def test_a_relocation_inside_the_chain_is_refused(self):
        """F3: a relocated operand cannot travel with a permuted pair."""
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            apply_chains(relocations=frozenset({CHAIN_START + 4}))
        self.assertIn("relocation lies inside the chain",
                      str(raised.exception))

    def test_a_branch_into_the_chain_interior_is_refused(self):
        """F3: the chain is reached only by falling into its first byte."""
        branched = bytearray(BODY)
        branched[4:6] = bytes.fromhex("7212")   # jb +0x12 -> offset 24
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            apply_chains(body=bytes(branched))
        self.assertIn("branch targets the chain interior",
                      str(raised.exception))

    def test_variable_length_pairs_keep_the_chain_length(self):
        """Pairs of different encodings permute as whole units."""
        short = bytes.fromhex("dd4560" "dc4d68")     # fld/fmul [ebp+disp8]
        body = PROLOGUE + PAIRS[0] + short + FADDP + PAIRS[2] + FADDP + TAIL
        chain_end = len(PROLOGUE) + 8 + 6 + 2 + 8 + 2
        image, _ = apply_chains(body=body, chains=[{
            "chain_start": CHAIN_START, "chain_end": chain_end,
            "order": [1, 0, 2],
            "expected_rewritten_offsets": sorted(
                index for index in range(CHAIN_START, chain_end)
                if body[index] != (PROLOGUE + short + PAIRS[0] + FADDP
                                   + PAIRS[2] + FADDP + TAIL)[index]),
        }])
        self.assertEqual(
            image, PROLOGUE + short + PAIRS[0] + FADDP + PAIRS[2] + FADDP
            + TAIL)


class DonorRewritingValidatorTests(unittest.TestCase):
    """The declaration layer of retail_exact_donor_rewriting."""

    def spec(self, **overrides):
        value = {
            "kind": byte_identity.DONOR_REWRITING_KIND,
            "fp_sum_rotations": [chain_declaration()],
            "register_bijections": [{
                "mapping": {"ecx": "edx", "edx": "ecx"},
                "region_start": SIGMA_REGION[0],
                "region_end": SIGMA_REGION[1],
                "expected_region_instruction_count": 2,
                "expected_rewritten_offsets": [3, 5],
            }],
            "expected_instruction_count": 14,
            "expected_changed_offsets": sorted(
                set(chain_declaration()["expected_rewritten_offsets"])
                | {3, 5}),
            "expected_procedure_range": [SIZE, 2, SIZE - 3],
            "expected_code_symbol_references": [],
            "expected_external_entries": [],
            "authenticity_rationale": "x" * 64,
        }
        value.update(overrides)
        return byte_identity.validate_donor_rewriting(value, "test", SIZE)

    def test_a_valid_declaration_normalizes(self):
        spec = self.spec()
        self.assertEqual(len(spec["fp_sum_rotations"]), 1)
        self.assertEqual(len(spec["register_bijections"]), 1)

    def test_a_declaration_without_any_certificate_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            self.spec(fp_sum_rotations=[], register_bijections=[],
                      expected_changed_offsets=[1])
        self.assertIn("declares no certificate", str(raised.exception))

    def test_overlapping_chains_are_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            self.spec(fp_sum_rotations=[
                chain_declaration(),
                chain_declaration(chain_start=CHAIN_START + 2)])
        self.assertIn("unsorted or overlapping", str(raised.exception))

    def test_a_bijection_inside_a_chain_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            self.spec(register_bijections=[{
                "mapping": {"ecx": "edx", "edx": "ecx"},
                "region_start": CHAIN_START + 1,
                "region_end": CHAIN_START + 5,
                "expected_region_instruction_count": 1,
                "expected_rewritten_offsets": [CHAIN_START + 2],
            }], expected_changed_offsets=sorted(
                set(chain_declaration()["expected_rewritten_offsets"])
                | {CHAIN_START + 2}))
        self.assertIn("inside an fp-sum chain", str(raised.exception))

    def test_a_structural_register_in_the_mapping_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            self.spec(register_bijections=[{
                "mapping": {"esp": "edx", "edx": "esp"},
                "region_start": SIGMA_REGION[0],
                "region_end": SIGMA_REGION[1],
                "expected_region_instruction_count": 2,
                "expected_rewritten_offsets": [3, 5],
            }])
        self.assertIn("touches ESP or EBP", str(raised.exception))

    def test_a_changed_set_that_omits_a_rewritten_byte_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            self.spec(expected_changed_offsets=[3, 5])
        self.assertIn("omits a rewritten byte", str(raised.exception))


class ComposedRewritingIntegrationTests(unittest.TestCase):
    """fp_sum_rotations inside the composed-rewriting seam."""

    IMAGE = None

    @classmethod
    def setUpClass(cls):
        sigma = bytearray(IMAGE_FP)
        sigma[3] = 0xD2   # xor ecx,ecx -> xor edx,edx
        sigma[5] = 0x12   # mov ecx,[ecx] -> mov edx,[edx]
        cls.IMAGE = bytes(sigma)
        cls.PROCEDURE_RANGE = [SIZE, 2, SIZE - 3]
        cls.stream = fixture.codeview_stream(
            size=SIZE, debug_start=2, debug_end=SIZE - 3)
        cls.seed = composed_fixture.make_coff(
            body=BODY, line_rows=((0, 11), (CHAIN_START, 12)),
            debug_stream=cls.stream)

    def record(self, **spec_overrides):
        spec = {
            "kind": byte_identity.COMPOSED_REWRITING_KIND,
            "windows": [],
            "relational_sites": [],
            "fp_sum_rotations": [chain_declaration()],
            "register_bijections": [{
                "mapping": {"ecx": "edx", "edx": "ecx"},
                "region_start": SIGMA_REGION[0],
                "region_end": SIGMA_REGION[1],
                "expected_region_instruction_count": 2,
                "expected_rewritten_offsets": [3, 5],
                "debug_s_register_map": [],
            }],
            "expected_instruction_count": len(
                byte_identity.decode_ia32_bijection_body(
                    self.IMAGE, "fixture", {})),
            "expected_changed_offsets": sorted(
                index for index in range(SIZE)
                if BODY[index] != self.IMAGE[index]),
            "expected_procedure_range": list(self.PROCEDURE_RANGE),
            "expected_code_symbol_references": [],
            "expected_external_entries": [],
            "expected_seed_debug_s_sha256":
                byte_identity.sha256_bytes(self.stream),
            "expected_image_debug_s_sha256":
                byte_identity.sha256_bytes(self.stream),
            "authenticity_rationale":
                "One chain-scoped fp-sum rotation and one regional register "
                "bijection composed inside a single entry.",
        }
        spec.update(spec_overrides)
        return composed_fixture.function_record(
            self.seed, self.seed, self.IMAGE, composed_rewriting=spec)

    def test_a_rotation_and_a_bijection_compose_retails_own_code(self):
        composed, detail = (
            byte_identity.compose_retail_exact_composed_rewriting(
                self.seed, self.seed, self.record(), self.IMAGE))
        checked = byte_identity.CoffObject(composed)
        section = checked.function_section(fixture.TARGET_SYMBOL)
        self.assertEqual(byte_identity.coff_body(checked, section),
                         self.IMAGE)
        self.assertTrue(detail["retail_exact"])
        self.assertEqual(len(detail["fp_sum_reassociation"]), 1)
        self.assertEqual(len(detail["register_bijections"]), 1)

    def test_a_rotation_whose_rewrite_set_differs_is_refused(self):
        record = self.record()
        record["composed_rewriting"]["fp_sum_rotations"][0][
            "expected_rewritten_offsets"] = [CHAIN_START]
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            byte_identity.compose_retail_exact_composed_rewriting(
                self.seed, self.seed, record, self.IMAGE)
        self.assertIn("rewrote a different byte set", str(raised.exception))

    def test_a_chain_overlapping_a_bijection_region_is_refused(self):
        record = self.record(register_bijections=[{
                "mapping": {"ecx": "edx", "edx": "ecx"},
                "region_start": CHAIN_START + 1,
                "region_end": CHAIN_START + 5,
                "expected_region_instruction_count": 1,
                "expected_rewritten_offsets": [CHAIN_START + 2],
                "debug_s_register_map": [],
            }], expected_changed_offsets=sorted(
                set(chain_declaration()["expected_rewritten_offsets"])
                | {CHAIN_START + 2}))
        del record["composed_rewriting"]["windows"]
        del record["composed_rewriting"]["relational_sites"]
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            byte_identity.validate_composed_rewriting(
                record["composed_rewriting"], "test", SIZE)
        self.assertIn("overlaps another certificate", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
