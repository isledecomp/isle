"""The copy-elision-with-resize primitive: oracle bytes, simulator-proved."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import byte_identity  # noqa: E402


# ours: nop | mov edx,[ebp-0x10]; mov edi,[edx]; push eax; mov ecx,edx;
#       call [edi+0x28] | ret
BODY = bytes.fromhex("90" "8b55f0" "8b3a" "50" "8bca" "ff5728" "c3")
# retail: nop | mov ecx,[ebp-0x10]; push eax; mov edi,[ecx];
#         call [edi+0x28] | ret
RETAIL = bytes.fromhex("90" "8b4df0" "50" "8b39" "ff5728" "c3")


def declaration(**overrides):
    item = {"region_start": 1, "region_end": 12,
            "image_start": 1, "image_length": 9}
    item.update(overrides)
    return item


def apply(body=BODY, retail=RETAIL, items=None, widenings=None):
    return byte_identity.apply_simulated_elision(
        body, items if items is not None else [declaration()],
        frozenset(), "test", retail, branch_widenings=widenings)


class ElisionTests(unittest.TestCase):
    def test_a_proved_elision_installs_the_oracle_bytes(self):
        image, proof = apply()
        self.assertEqual(image, RETAIL)
        self.assertEqual(proof["regions"][0]["image_length"], 9)
        self.assertEqual(proof["relocation_reseat"], [])

    def test_a_different_call_target_is_refused(self):
        # retail calls [edi+0x2c] instead: the terminal-call state differs.
        bad = bytearray(RETAIL)
        bad[9] = 0x2C
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            apply(retail=bytes(bad))
        self.assertIn("terminal", str(raised.exception))

    def test_a_differing_register_needs_a_dead_declaration(self):
        # Without the terminal call the elided copy leaves EDX differing.
        body = bytes.fromhex("90" "8b55f0" "8b3a" "50" "8bca" "c3")
        retail = bytes.fromhex("90" "8b4df0" "50" "8b39" "c3")
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            apply(body=body, retail=retail,
                  items=[declaration(region_end=9, image_length=6)])
        self.assertIn("declared dead set", str(raised.exception))

    def test_an_integer_sub_chain_commutes(self):
        # ours: sub edi,eax; sub edi,[ebp-0x1c] -- retail: the reverse.
        body = bytes.fromhex("90" "2bf8" "2b7de4" "c3")
        retail = bytes.fromhex("90" "2b7de4" "2bf8" "c3")
        image, proof = byte_identity.apply_simulated_elision(
            body, [{"region_start": 1, "region_end": 6,
                    "image_start": 1, "image_length": 5}],
            frozenset(), "test", retail)
        self.assertEqual(image, retail)

    def test_a_crossing_branch_is_repaired(self):
        # jne +0x0b hops the region; the elision shrinks it by 2.
        body = bytes.fromhex("750b" "8b55f0" "8b3a" "50" "8bca" "ff5728" "c3")
        retail = bytes.fromhex("7509" "8b4df0" "50" "8b39" "ff5728" "c3")
        image, proof = byte_identity.apply_simulated_elision(
            body, [{"region_start": 2, "region_end": 13,
                    "image_start": 2, "image_length": 9}],
            frozenset(), "test", retail)
        self.assertEqual(image, retail)
        self.assertEqual(proof["branch_repairs"], [0])

    def test_a_relocation_inside_the_region_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            byte_identity.apply_simulated_elision(
                BODY, [declaration()], frozenset({4}), "test", RETAIL)
        self.assertIn("relocation lies inside", str(raised.exception))

    def test_an_undeclared_widening_is_refused(self):
        # A backward rel8 branch at the edge of range: after a +126-byte
        # growth it can no longer reach, and without a declaration the
        # composition refuses rather than widening.
        pad = bytes.fromhex("90") * 108
        body = bytes.fromhex("90" "8bca" "c3") + pad + bytes.fromhex(
            "7d" + format(256 - 113 - 2, "02x"))
        # jge back to offset 0 over 113 bytes; growing the region to 127
        # bytes pushes the displacement past -128.
        grown = bytes.fromhex("90" * 124)
        retail = bytes.fromhex("90") + grown + bytes.fromhex("c3") + pad
        with self.assertRaises(byte_identity.ByteIdentityError):
            byte_identity.apply_simulated_elision(
                body, [{"region_start": 1, "region_end": 3,
                        "image_start": 1, "image_length": 124}],
                frozenset(), "test", retail)


if __name__ == "__main__":
    unittest.main()
