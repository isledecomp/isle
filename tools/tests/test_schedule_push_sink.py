"""Tests for the PUSH-SINK extension to the instruction-schedule certificate.

A `push` lowers ESP by four, so an ESP-relative operand the permutation moves
from one side of a push to the other must have its displacement changed by four
to name the SAME address.  The class used to refuse such a window outright:

    "a push shares the window with the esp-relative memory operand at N, whose
     address the push's own esp delta would move"

That refusal was carrying three separate facts, and admitting the push means
stating all three:

  1  the ADJUSTMENT itself, derived from the declared permutation and never a
     free parameter;
  2  the ALIASING fact the refusal gave for free -- a push writes the four
     bytes below ESP, so every ESP displacement in the window must be
     non-negative or the pushed slot could alias one of them;
  3  which ESP dependences the adjustment DISCHARGES -- only those between a
     stack operation and an instruction whose sole use of ESP is an address
     the adjustment restores.  A push against a push, or anything that reads
     ESP as a value, keeps its edge.

Motivated and validated by `0x10051ac0 LegoAct2::SpawnBricks`, whose residue
against retail goes to zero under two of these plus register bijections.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import byte_identity  # noqa: E402


def decode(body: bytes):
    instructions, offset = [], 0
    while offset < len(body):
        item = byte_identity.decode_ia32_bijection_instruction(
            body, offset, "decode")
        instructions.append(item)
        offset += item["length"]
    return instructions


# mov eax,[esp+0x18] / lea edx,[esp+0x14] / mov ecx,[edx] / push edx
LOAD = bytes.fromhex("8b442418")
LEA = bytes.fromhex("8d542414")
PLAIN = bytes.fromhex("8b0a")
PUSH = bytes.fromhex("52")
NONESP_LOAD = bytes.fromhex("8b01")       # mov eax,[ecx]
NONESP_LOAD_2 = bytes.fromhex("8b5904")   # mov ebx,[ecx+4]
STACK_FRONTIER = byte_identity.IA32_SCHEDULE_STACK_FRONTIER_THEOREM


class DerivationTest(unittest.TestCase):

    def test_a_push_moved_before_a_load_raises_its_displacement(self):
        body = LOAD + PUSH                      # [load, push]
        instructions = decode(body)
        found = byte_identity.ia32_schedule_stack_adjustments(
            body, instructions, [1, 0], "w")    # push first
        self.assertEqual(found, [[0, 3, 0x18, 0x1c]])

    def test_a_push_moved_after_a_load_lowers_its_displacement(self):
        body = PUSH + LOAD                      # [push, load]
        instructions = decode(body)
        found = byte_identity.ia32_schedule_stack_adjustments(
            body, instructions, [1, 0], "w")    # load first
        self.assertEqual(found, [[1, 4, 0x18, 0x14]])

    def test_a_lea_of_an_esp_address_is_adjusted_too(self):
        # `lea` has no memory OPERAND for the decoder to report, but its
        # displacement moves with ESP exactly as a load's does.
        body = LEA + PUSH
        found = byte_identity.ia32_schedule_stack_adjustments(
            body, decode(body), [1, 0], "w")
        self.assertEqual(found, [[0, 3, 0x14, 0x18]])

    def test_no_push_means_no_adjustment(self):
        body = LOAD + PLAIN
        self.assertEqual(
            byte_identity.ia32_schedule_stack_adjustments(
                body, decode(body), [1, 0], "w"),
            [])

    def test_an_operand_that_does_not_cross_the_push_is_untouched(self):
        # [load, plain, push] -> [plain, load, push]: the load never crosses.
        body = LOAD + PLAIN + PUSH
        self.assertEqual(
            byte_identity.ia32_schedule_stack_adjustments(
                body, decode(body), [1, 0, 2], "w"),
            [])

    def test_a_displacement_that_would_overflow_its_field_refuses(self):
        body = bytes.fromhex("8b44247f") + PUSH   # [esp+0x7f], a disp8 at max
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.ia32_schedule_stack_adjustments(
                body, decode(body), [1, 0], "w")
        self.assertIn("would overflow", str(caught.exception))

    def test_an_esp_base_with_no_displacement_byte_refuses(self):
        body = bytes.fromhex("8b0424") + PUSH     # mov eax,[esp], mod 0
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.ia32_schedule_stack_adjustments(
                body, decode(body), [1, 0], "w")
        self.assertIn("no displacement byte", str(caught.exception))


class ObligationTest(unittest.TestCase):

    def test_a_push_is_still_refused_without_a_declaration(self):
        body = LOAD + PUSH
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.ia32_schedule_dependence_edges(decode(body), "w")
        self.assertIn("a push shares the window", str(caught.exception))

    def test_a_negative_esp_displacement_refuses(self):
        # `mov eax,[esp-8]` names a slot BELOW esp, where the push writes.
        body = bytes.fromhex("8b4424f8") + PUSH
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.ia32_schedule_dependence_edges(
                decode(body), "w", body, True)
        self.assertIn("below ESP", str(caught.exception))

    def test_the_esp_edge_is_discharged_for_an_adjusted_address(self):
        body = LOAD + PUSH
        _facts, edges = byte_identity.ia32_schedule_dependence_edges(
            decode(body), "w", body, True)
        self.assertEqual(edges, [],
                         "an adjusted address does not depend on the push")

    def test_the_esp_edge_SURVIVES_when_esp_is_read_as_a_value(self):
        # `mov eax, esp` reads ESP itself; no displacement can compensate it.
        body = bytes.fromhex("8bc4") + PUSH
        _facts, edges = byte_identity.ia32_schedule_dependence_edges(
            decode(body), "w", body, True)
        self.assertTrue(any("register_war" in edge[2] for edge in edges),
                        "reading ESP as a value must keep its edge")

    def test_two_pushes_still_cannot_be_reordered(self):
        body = PUSH + PUSH
        _facts, edges = byte_identity.ia32_schedule_dependence_edges(
            decode(body), "w", body, True)
        self.assertEqual([edge[:2] for edge in edges], [[0, 1]])


class ApplicationTest(unittest.TestCase):

    def test_the_image_carries_the_adjusted_displacement(self):
        body = LOAD + PUSH
        instructions = decode(body)
        order = [1, 0]
        stack = byte_identity.ia32_schedule_stack_adjustments(
            body, instructions, order, "w")
        _facts, edges = byte_identity.ia32_schedule_dependence_edges(
            instructions, "w", body, True)
        window = {
            "start": 0, "end": len(body),
            "source_instruction_lengths": [4, 1],
            "target_order": order,
            "expected_dependence_edges": edges,
            "expected_line_rows": [],
            "stack_adjustments": stack,
        }
        image, proof = byte_identity.apply_instruction_schedule(
            body, [window], frozenset(), "s")
        self.assertEqual(image, PUSH + bytes.fromhex("8b44241c"))
        self.assertEqual(proof["stack_adjustments"], [[0, 3, 0x18, 0x1c]])

    def test_a_declaration_that_disagrees_is_refused(self):
        body = LOAD + PUSH
        instructions = decode(body)
        _facts, edges = byte_identity.ia32_schedule_dependence_edges(
            instructions, "w", body, True)
        window = {
            "start": 0, "end": len(body),
            "source_instruction_lengths": [4, 1],
            "target_order": [1, 0],
            "expected_dependence_edges": edges,
            "expected_line_rows": [],
            "stack_adjustments": [[0, 3, 0x18, 0x20]],
        }
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.apply_instruction_schedule(
                body, [window], frozenset(), "s")
        self.assertIn("differs from its declaration", str(caught.exception))


class StackFrontierProjectionTest(unittest.TestCase):

    @staticmethod
    def window(theorem=STACK_FRONTIER):
        return {
            "start": 0,
            "end": len(NONESP_LOAD + PUSH + NONESP_LOAD_2),
            "source_instruction_lengths": [2, 1, 3],
            "target_order": [1, 0, 2],
            "stack_frontier_theorem": theorem,
            "expected_dependence_edges": [[1, 2, ["memory"]]],
            "expected_line_rows": [],
        }

    def test_only_the_crossed_push_memory_reason_is_projected(self):
        body = NONESP_LOAD + PUSH + NONESP_LOAD_2
        image, proof = byte_identity.apply_instruction_schedule(
            body, [self.window()], frozenset(), "frontier")

        self.assertEqual(image, PUSH + NONESP_LOAD + NONESP_LOAD_2)
        window = proof["windows"][0]
        self.assertEqual(window["dependence_edges"], [[1, 2, ["memory"]]])
        receipt = window["stack_frontier"]
        self.assertEqual(
            receipt["strict_dependence_edges"],
            [[0, 1, ["memory"]], [1, 2, ["memory"]]],
        )
        self.assertEqual(
            [item["source_pair"]
             for item in receipt["discharged_memory_pairs"]],
            [[0, 1]],
        )

    def test_a_non_memory_reason_on_the_crossed_pair_is_retained(self):
        # mov edx,[ecx] / push edx: the memory reason is theorem-scoped, but
        # the true register flow remains and therefore forbids the swap.
        body = bytes.fromhex("8b1152")
        window = {
            "start": 0,
            "end": len(body),
            "source_instruction_lengths": [2, 1],
            "target_order": [1, 0],
            "stack_frontier_theorem": STACK_FRONTIER,
            "expected_dependence_edges": [[0, 1, ["register_raw"]]],
            "expected_line_rows": [],
        }
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.apply_instruction_schedule(
                body, [window], frozenset(), "frontier")
        self.assertIn("dependence DAG forbids", str(caught.exception))

    def test_the_exact_marker_is_validated_and_preserved(self):
        body = NONESP_LOAD + PUSH + NONESP_LOAD_2
        normalized = byte_identity._validate_schedule_windows(
            [self.window()], "frontier", len(body))
        self.assertEqual(
            normalized[0]["stack_frontier_theorem"], STACK_FRONTIER)

        invalid = self.window("msvc-4.20-win32-register-push-frontier-v0")
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity._validate_schedule_windows(
                [invalid], "frontier", len(body))
        self.assertIn("stack_frontier_theorem differs",
                      str(caught.exception))

    def test_a_marker_without_a_crossed_memory_edge_refuses(self):
        body = NONESP_LOAD + NONESP_LOAD_2 + PUSH
        window = {
            "start": 0,
            "end": len(body),
            "source_instruction_lengths": [2, 3, 1],
            "target_order": [1, 0, 2],
            "stack_frontier_theorem": STACK_FRONTIER,
            "expected_dependence_edges": [
                [0, 2, ["memory"]], [1, 2, ["memory"]]],
            "expected_line_rows": [],
        }
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.apply_instruction_schedule(
                body, [window], frozenset(), "frontier")
        self.assertIn("discharges no crossed PUSH-memory edge",
                      str(caught.exception))


if __name__ == "__main__":
    unittest.main()
