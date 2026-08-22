r"""Tests for the SIMULATED REGION REWRITE primitive.

A straight-line region whose transformation -- an instruction permutation
plus register-field rewrites -- is proved by symbolic execution: same FP
stack, same push sequence, same frame-slot values (except declared dead
scratch slots), same registers (except declared dead ones proved dead on the
exit edge), flags equal or dead.

Fixture: two independent value moves whose registers swap and whose order
swaps -- the temporary-assignment shape the compiler varies freely:

     0: 90            nop
     1: 8b 4d f0      mov ecx, [ebp-0x10]
     4: 8b 55 f4      mov edx, [ebp-0xc]
     7: 89 4d ec      mov [ebp-0x14], ecx
    10: 89 55 e8      mov [ebp-0x18], edx
    13: 33 c9         xor ecx, ecx
    15: 33 d2         xor edx, edx
    17: c3            ret

Retail's shape loads in the other order with the other registers; the values
reaching [ebp-0x14] and [ebp-0x18] are identical.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import byte_identity  # noqa: E402


BODY = bytes.fromhex(
    "90" "8b4df0" "8b55f4" "894dec" "8955e8" "33c9" "33d2" "c3")
REGION = (1, 13)


def declaration(**overrides):
    item = {
        "region_start": REGION[0], "region_end": REGION[1],
        # image: load [ebp-0xc] first into ecx, [ebp-0x10] into edx,
        # store [ebp-0x14] from edx, [ebp-0x18] from ecx.
        "target_order": [1, 0, 2, 3],
        "field_rewrites": [[0, 0, "edx"], [1, 0, "ecx"],
                           [2, 0, "edx"], [3, 0, "ecx"]],
        "dead_registers": ["ecx", "edx"],
        "dead_slots": [],
    }
    item.update(overrides)
    return item


def apply(body=BODY, items=None):
    return byte_identity.apply_simulated_region_rewrite(
        body, items if items is not None else [declaration()],
        frozenset(), "test")


class RewriteTests(unittest.TestCase):
    def test_a_proved_rewrite_reaches_the_permuted_renamed_region(self):
        image, proof = apply()
        expected = bytes.fromhex(
            "90" "8b4df4" "8b55f0" "8955ec" "894de8" "33c9" "33d2" "c3")
        self.assertEqual(image, expected)
        self.assertEqual(proof["regions"][0]["dead_registers"],
                         ["ecx", "edx"])
        self.assertEqual(proof["relocation_reseat"], [])

    def test_differing_slot_values_are_refused(self):
        """Without the cross-rename the two stores swap their VALUES."""
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            apply(items=[declaration(field_rewrites=[])])
        self.assertIn("are not the declared dead set", str(raised.exception))

    def test_a_live_renamed_register_is_refused(self):
        leaky = bytearray(BODY)
        leaky[13:15] = bytes.fromhex("8bc1")   # mov eax, ecx (reads ecx)
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            apply(body=bytes(leaky))
        self.assertIn("live on the region's exit edge",
                      str(raised.exception))

    def test_an_instruction_outside_the_simulator_set_is_refused(self):
        # The region reaches the terminating `ret` -- a control transfer the
        # simulator never admits.  (The self-XOR that used to play this role
        # was deliberately admitted on 2026-08-22 as the zero idiom.)
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            apply(items=[declaration(region_end=18,
                                     target_order=[1, 0, 2, 3, 4, 5, 6])])
        self.assertIn("outside the simulator's closed set",
                      str(raised.exception))

    def test_a_non_permutation_order_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            apply(items=[declaration(target_order=[1, 1, 2, 3])])
        self.assertIn("not a permutation", str(raised.exception))

    def test_a_moved_relocation_is_reseated_with_its_instruction(self):
        body = bytes.fromhex(
            "90" "c745f011223344" "8b55f4" "33d2" "c3")
        # region: [mov [ebp-0x10],imm(reloc)] [mov edx,[ebp-0xc]] permuted
        item = {
            "region_start": 1, "region_end": 11,
            "target_order": [1, 0],
            "field_rewrites": [],
            "dead_registers": [], "dead_slots": [],
        }
        image, proof = byte_identity.apply_simulated_region_rewrite(
            body, [item], frozenset({4, 5, 6, 7}), "test")
        self.assertEqual(proof["relocation_reseat"], [[4, 7]])
        self.assertEqual(image[1:4], bytes.fromhex("8b55f4"))
        self.assertEqual(image[4:11], bytes.fromhex("c745f011223344"))


if __name__ == "__main__":
    unittest.main()
