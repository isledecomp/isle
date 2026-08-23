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


# ---------------------------------------------------------------------------
# The callee-inlined extensions: verified callee bodies, vtable oracles,
# region relocations, entry loads, RMW windows, and the symmetric compare.
# ---------------------------------------------------------------------------

CALLEE = bytes.fromhex("8b442404" "8945f8" "c20400")     # mov eax,[esp+4];
                                                          # mov [ebp-8],eax;
                                                          # ret 4
CALL_BODY = bytes.fromhex("90" "6a01" "e800000000"
                          "c745f402000000" "c3")
CALL_RETAIL = bytes.fromhex("90" "c745f402000000" "6a01"
                            "e800000000" "c3")


class InlinedCalleeTests(unittest.TestCase):
    def _apply(self, oracles=None, pairs=None, image_relocations=None):
        return byte_identity.apply_simulated_elision(
            CALL_BODY,
            [{"region_start": 1, "region_end": 15,
              "image_start": 1, "image_length": 14,
              "relocation_pairs": pairs if pairs is not None
              else [[4, 11]]}],
            frozenset({4, 5, 6, 7}), "test", CALL_RETAIL,
            {4: {"width": 4, "target": "?C@@YGXH@Z"}},
            image_relocations=(image_relocations
                               if image_relocations is not None
                               else {11: "?C@@YGXH@Z"}),
            oracles=oracles if oracles is not None
            else {"callees": {"?C@@YGXH@Z": CALLEE}, "vtables": {}})

    def test_a_store_window_across_an_inlined_call_composes(self):
        image, proof = self._apply()
        self.assertEqual(image, CALL_RETAIL)
        self.assertEqual(proof["relocation_reseat"], [[4, 11]])

    def test_an_uncovered_callee_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            self._apply(oracles={"callees": {}, "vtables": {}})
        self.assertIn("no verified callee oracle", str(raised.exception))

    def test_a_mismatched_relocation_pair_symbol_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            self._apply(image_relocations={11: "?D@@YGXH@Z"})
        self.assertIn("names", str(raised.exception))

    def test_an_unpaired_region_relocation_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            self._apply(pairs=[])
        self.assertIn("relocation_pairs", str(raised.exception))

    def test_a_vtable_dispatch_window_composes(self):
        body = bytes.fromhex("90" "c745fc00000000" "8b45fc" "ff5004"
                             "c745f401000000" "c3")
        retail = bytes.fromhex("90" "c745f401000000" "c745fc00000000"
                               "8b45fc" "ff5004" "c3")
        image, proof = byte_identity.apply_simulated_elision(
            body,
            [{"region_start": 1, "region_end": 21,
              "image_start": 1, "image_length": 20,
              "relocation_pairs": [[4, 11]]}],
            frozenset({4, 5, 6, 7}), "test", retail,
            {4: {"width": 4, "target": "??_7X@@6B@"}},
            image_relocations={11: "??_7X@@6B@"},
            oracles={"callees": {"?V@@YGXXZ": b"\xc3"},
                     "vtables": {"??_7X@@6B@": {4: "?V@@YGXXZ"}}})
        self.assertEqual(image, retail)

    def test_an_undeclared_vtable_slot_is_refused(self):
        body = bytes.fromhex("90" "c745fc00000000" "8b45fc" "ff5008"
                             "c745f401000000" "c3")
        retail = bytes.fromhex("90" "c745f401000000" "c745fc00000000"
                               "8b45fc" "ff5008" "c3")
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            byte_identity.apply_simulated_elision(
                body,
                [{"region_start": 1, "region_end": 21,
                  "image_start": 1, "image_length": 20,
                  "relocation_pairs": [[4, 11]]}],
                frozenset({4, 5, 6, 7}), "test", retail,
                {4: {"width": 4, "target": "??_7X@@6B@"}},
                image_relocations={11: "??_7X@@6B@"},
                oracles={"callees": {"?V@@YGXXZ": b"\xc3"},
                         "vtables": {"??_7X@@6B@": {4: "?V@@YGXXZ"}}})
        self.assertIn("no verified target", str(raised.exception))


class EntryLoadTests(unittest.TestCase):
    BODY = bytes.fromhex("90" "8b7df0" "8bc7" "8945f8" "c3")
    RETAIL = bytes.fromhex("90" "8b7df0" "8b45f0" "8945f8" "c3")

    def test_a_verified_entry_load_unifies_the_expressions(self):
        image, proof = byte_identity.apply_simulated_elision(
            self.BODY,
            [{"region_start": 4, "region_end": 9,
              "image_start": 4, "image_length": 6,
              "entry_loads": {"edi": -16}}],
            frozenset(), "test", self.RETAIL)
        self.assertEqual(image, self.RETAIL)

    def test_without_the_entry_load_the_slots_differ(self):
        with self.assertRaises(byte_identity.ByteIdentityError):
            byte_identity.apply_simulated_elision(
                self.BODY,
                [{"region_start": 4, "region_end": 9,
                  "image_start": 4, "image_length": 6,
                  "dead_registers": ["eax"]}],
                frozenset(), "test", self.RETAIL)

    def test_a_missing_dominating_load_is_refused(self):
        body = bytes.fromhex("90" "8b75f0" "8bc7" "8945f8" "c3")
        retail = bytes.fromhex("90" "8b75f0" "8b45f0" "8945f8" "c3")
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            byte_identity.apply_simulated_elision(
                body,
                [{"region_start": 4, "region_end": 9,
                  "image_start": 4, "image_length": 6,
                  "entry_loads": {"edi": -16},
                  "dead_registers": ["eax"]}],
                frozenset(), "test", retail)
        self.assertIn("no dominating", str(raised.exception))


class WindowExtensionTests(unittest.TestCase):
    def test_a_read_modify_write_window_composes(self):
        body = bytes.fromhex("90" "8345f804" "ff45f4" "90" "c3")
        retail = bytes.fromhex("90" "ff45f4" "8345f804" "90" "c3")
        image, proof = byte_identity.apply_simulated_elision(
            body,
            [{"region_start": 1, "region_end": 8,
              "image_start": 1, "image_length": 7}],
            frozenset(), "test", retail)
        self.assertEqual(image, retail)

    def test_overlapping_frame_stores_are_refused(self):
        body = bytes.fromhex("90" "c745f801000000" "c745fa02000000" "c3")
        retail = bytes.fromhex("90" "c745fa02000000" "c745f801000000" "c3")
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            byte_identity.apply_simulated_elision(
                body,
                [{"region_start": 1, "region_end": 15,
                  "image_start": 1, "image_length": 14}],
                frozenset(), "test", retail)
        self.assertIn("overlap", str(raised.exception))

    def test_a_mirrored_compare_with_an_equality_consumer_composes(self):
        body = bytes.fromhex("90" "3bc1" "7402" "9090" "c3")
        retail = bytes.fromhex("90" "3bc8" "7402" "9090" "c3")
        image, proof = byte_identity.apply_simulated_elision(
            body,
            [{"region_start": 1, "region_end": 3,
              "image_start": 1, "image_length": 2}],
            frozenset(), "test", retail)
        self.assertEqual(image, retail)

    def test_a_mirrored_compare_with_an_ordered_consumer_is_refused(self):
        body = bytes.fromhex("90" "3bc1" "7702" "9090" "c3")
        retail = bytes.fromhex("90" "3bc8" "7702" "9090" "c3")
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            byte_identity.apply_simulated_elision(
                body,
                [{"region_start": 1, "region_end": 3,
                  "image_start": 1, "image_length": 2}],
                frozenset(), "test", retail)
        self.assertIn("not an equality branch", str(raised.exception))
