r"""Tests for the FP POINTER-ADDEND EXCHANGE primitive.

Two pointer registers receive element offsets of one vector, their products
join one faddp summation chain, and two optimizer states differ only in
WHICH register received WHICH offset -- two exchanged `add r32, imm`
immediates.  `apply_fp_pointer_exchange` proves the exchange by symbolic
execution (X1..X4) and proves the diverging pointer registers dead on the
region's exit edge with the bijection certificate's own liveness (X5).

The fixture computes v[0]^2 + v[1]^2 + v[2]^2:

     0: 8b 55 f0     mov edx, [ebp-0x10]
     3: 8b 4d f0     mov ecx, [ebp-0x10]
     6: 83 c2 04     add edx, 4          <- exchanged
     9: 83 c1 08     add ecx, 8          <- exchanged
    12: 8b 45 f0     mov eax, [ebp-0x10]
    15: d9 00        fld dword [eax]
    17: d8 08        fmul dword [eax]
    19: d9 02        fld dword [edx]
    21: d8 0a        fmul dword [edx]
    23: de c1        faddp st(1)
    25: d9 01        fld dword [ecx]
    27: d8 09        fmul dword [ecx]
    29: de c1        faddp st(1)
    31: d9 5d ec     fstp dword [ebp-0x14]
    34: 33 c9        xor ecx, ecx
    36: 33 d2        xor edx, edx
    38: 33 c0        xor eax, eax
    40: c3           ret
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import byte_identity  # noqa: E402


BODY = bytes.fromhex(
    "8b55f0" "8b4df0" "83c204" "83c108" "8b45f0"
    "d900" "d808" "d902" "d80a" "dec1" "d901" "d809" "dec1"
    "d95dec" "33c9" "33d2" "33c0" "c3")
REGION = (0, 31)
SWAP = [6, 9]


def declaration(**overrides):
    item = {
        "region_start": REGION[0], "region_end": REGION[1],
        "swap_offsets": list(SWAP),
        "dead_registers": ["ecx", "edx"],
    }
    item.update(overrides)
    return item


def apply(body=BODY, items=None):
    # region_start must be positive; shift the fixture by one prologue byte.
    shifted = b"\x90" + body
    if items is None:
        items = [declaration()]
    moved = [{**item,
              "region_start": item["region_start"] + 1,
              "region_end": item["region_end"] + 1,
              "swap_offsets": [offset + 1 for offset
                               in item["swap_offsets"]]}
             for item in items]
    return byte_identity.apply_fp_pointer_exchange(
        shifted, moved, frozenset(), "test")


class ExchangeTests(unittest.TestCase):
    def test_the_exchange_swaps_the_two_immediates_and_nothing_else(self):
        image, proof = apply()
        self.assertEqual(image[9], 0x08)     # add edx, 8 (shifted by 1)
        self.assertEqual(image[12], 0x04)    # add ecx, 4
        self.assertEqual(image[:9], b"\x90" + BODY[:8])
        self.assertEqual(image[13:], BODY[12:])
        self.assertEqual(proof["exchanges"][0]["dead_registers"],
                         ["ecx", "edx"])

    def test_a_dead_set_that_differs_from_the_measurement_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            apply(items=[declaration(dead_registers=["ecx"])])
        self.assertIn("not the declared dead set", str(raised.exception))

    def test_a_live_pointer_register_is_refused(self):
        """X5: a stored-away pointer value keeps its register live."""
        leaky = bytearray(BODY)
        leaky[36:38] = bytes.fromhex("8bc2")   # mov eax, edx (reads edx)
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            apply(body=bytes(leaky))
        self.assertIn("live on the region's exit edge",
                      str(raised.exception))

    def test_a_region_ending_inside_the_chain_is_refused(self):
        """The two versions then leave different FP stacks."""
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            apply(items=[declaration(region_end=25)])
        self.assertIn("different FP stacks", str(raised.exception))

    def test_an_instruction_outside_the_simulator_set_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            apply(items=[declaration(region_end=34)])   # fstp writes memory
        self.assertIn("outside the simulator's closed set",
                      str(raised.exception))

    def test_equal_immediates_are_refused(self):
        same = bytearray(BODY)
        same[11] = 0x04                       # add ecx, 4 too
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            apply(body=bytes(same))
        self.assertIn("already equal", str(raised.exception))

    def test_a_branch_into_the_region_interior_is_refused(self):
        branched = bytearray(BODY)
        branched[34:36] = bytes.fromhex("7bef")   # jnp -17 -> boundary 20
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            apply(body=bytes(branched))
        self.assertIn("targets the region interior", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
