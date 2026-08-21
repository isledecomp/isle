"""Tests for the web-recolour CERTIFICATE class.

The class renames ONE def-use web from a source register to an image register.
Unlike a register bijection, the map is not injective at the register level:
the image register is already occupied by another value somewhere in the body.
That makes it a live-range COALESCE, and the one obligation the whole class
turns on is that the two ranges are provably NON-OVERLAPPING.  These tests fix
that obligation and the refusals around it -- above all the pair where the
SAME recolour is refused on the unreordered body and admitted only after the
reordering that separates the ranges.

The fixture is a miniature of `Act3::TriggerHitSound`:

    0:  53                    push ebx
    1:  33 c9                 xor  ecx, ecx      <- ecx becomes the index
    3:  8b 04 8d 00000000     mov  eax, [ecx*4]  <- the web's definition;
                                                    reads ecx, writes eax
   10:  eb 00                 jmp  12
   12:  8d 8e 20420000        lea  ecx, [esi+0x4220]
   18:  50                    push eax           <- the web's use
   19:  b8 00000000           mov  eax, 0        <- kills the web, as the
   24:  5b                    pop  ebx              real callee's clobber does
   25:  c3                    ret

Retail's shape is `mov ecx, [ecx*4]` ... `push ecx; lea ecx, [esi+0x4220]`:
the web lives in ecx, which is only possible once the `lea` moves BELOW the
push.  So the certificate declares a window reordering first and proves the
recolour on its result.
"""
from __future__ import annotations

import copy
import struct
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import byte_identity  # noqa: E402
import test_instruction_schedule as fixture  # noqa: E402


TARGET_SYMBOL = fixture.TARGET_SYMBOL
DEFINITION = bytes.fromhex("8b048d00000000")
BODY = (bytes.fromhex("53") + bytes.fromhex("33c9") + DEFINITION
        + bytes.fromhex("eb00") + bytes.fromhex("8d8e20420000")
        + bytes.fromhex("50") + bytes.fromhex("b800000000")
        + bytes.fromhex("5b") + bytes.fromhex("c3"))
SIZE = len(BODY)
WINDOW = (12, 19)
LINE_ROWS = ((0, 11), (24, 12))
PROCEDURE_RANGE = [SIZE, 1, 24]

# A diamond: two definitions reach one use, so the reaching-definition
# direction of the web closure has something to find.
DIAMOND = (bytes.fromhex("53") + bytes.fromhex("33c9") + DEFINITION
           + bytes.fromhex("7402") + bytes.fromhex("8bc3")
           + bytes.fromhex("50") + bytes.fromhex("b800000000")
           + bytes.fromhex("5b") + bytes.fromhex("c3"))


def reordered(body=BODY):
    start, end = WINDOW
    return body[:start] + body[start + 6:end] + body[start:start + 6] \
        + body[end:]


def recoloured(body):
    image = bytearray(body)
    image[4] = 0x0C                 # ModRM reg field: eax -> ecx
    image[12] = 0x51                # push eax -> push ecx
    return bytes(image)


IMAGE = recoloured(reordered())


def window_declaration(**overrides):
    window = {
        "start": WINDOW[0], "end": WINDOW[1],
        "source_instruction_lengths": [6, 1],
        "target_order": [1, 0],
        "expected_dependence_edges": [],
        "expected_line_rows": [],
    }
    window.update(overrides)
    return window


def web_declaration(**overrides):
    web = {
        "source_register": "eax", "image_register": "ecx",
        "definitions": [3], "uses": [12],
        "expected_rewritten_offsets": [4, 12],
    }
    web.update(overrides)
    return web


def recolour_spec(**overrides):
    spec = {
        "kind": byte_identity.WEB_RECOLOUR_KIND,
        "windows": [window_declaration()],
        "webs": [web_declaration()],
        "expected_instruction_count": 9,
        "expected_changed_offsets": sorted(
            index for index in range(SIZE) if BODY[index] != IMAGE[index]),
        "expected_procedure_range": list(PROCEDURE_RANGE),
        "expected_code_symbol_references": [],
        "expected_debug_s_registers": [],
        "authenticity_rationale":
            "One def-use web moves to a register whose own value dies at the "
            "web's definition, after a reordering that separates the ranges.",
    }
    spec.update(overrides)
    return spec


def make_coff(**overrides):
    options = {
        "body": BODY,
        "line_rows": LINE_ROWS,
        "debug_stream": fixture.codeview_stream(
            size=SIZE, debug_start=1, debug_end=24),
    }
    options.update(overrides)
    return fixture.make_coff(**options)


def function_record(seed_bytes, donor_bytes, image, **overrides):
    seed = byte_identity.CoffObject(seed_bytes)
    donor = byte_identity.CoffObject(donor_bytes)
    sp = seed.function_section(TARGET_SYMBOL)
    dp = donor.function_section(TARGET_SYMBOL)
    seed_body = byte_identity.coff_body(seed, sp)
    record = {
        "mangled": TARGET_SYMBOL,
        "donor": "d_0123456789ab",
        "splice_class": byte_identity.WEB_RECOLOUR_CLASS,
        "expected_section_number": sp["number"],
        "expected_section_count": len(seed.sections),
        "expected_body_length": sp["raw_size"],
        "expected_characteristics": sp["characteristics"],
        "expected_selection": byte_identity.section_definitions(
            seed)[sp["number"]]["selection"],
        "expected_relocation_count": sp["relocation_count"],
        "expected_seed_line_count": sp["line_count"],
        "expected_donor_line_count": dp["line_count"],
        "expected_function_count": sum(
            byte_identity.function_multiset(seed).values()),
        "expected_comdat_count": sum(
            byte_identity.comdat_primary_identity_multiset(seed).values()),
        "expected_seed_body_sha256": byte_identity.sha256_bytes(seed_body),
        "expected_donor_body_sha256": byte_identity.sha256_bytes(
            byte_identity.coff_body(donor, dp)),
        "expected_body_sha256": byte_identity.sha256_bytes(image),
        "expected_seed_metadata_sha256":
            byte_identity.instruction_mosaic_metadata_sha256(seed, sp),
        "expected_donor_metadata_sha256":
            byte_identity.instruction_mosaic_metadata_sha256(donor, dp),
        "expected_changed_offsets": sorted(
            index for index in range(len(image))
            if seed_body[index] != image[index]),
        "expected_closure": [".debug$F", ".debug$S"],
        "retail_oracle": {
            "image": "LEGO1.DLL",
            "address": "0x%08x" % fixture.RETAIL_ADDRESS,
            "verdict": "MATCH",
            "length": len(image),
        },
        "retail_relocations": [],
        "web_recolour": recolour_spec(),
    }
    record.update(overrides)
    return record


class CoalesceObligationTests(unittest.TestCase):
    """The one obligation the class exists for."""

    def apply(self, body, webs=None, relocations=frozenset()):
        return byte_identity.apply_web_recolour(
            body, [web_declaration()] if webs is None else webs,
            relocations, "web")

    def test_the_recolour_is_refused_before_the_reordering(self):
        # the SAME web, on the body as compiled: `lea ecx, [esi+0x4220]` sits
        # between the definition and the use, so the two live ranges overlap
        webs = [web_declaration(definitions=[3], uses=[18],
                                expected_rewritten_offsets=[4, 18])]
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self.apply(BODY, webs)
        self.assertIn("inside the web's live range", str(caught.exception))

    def test_the_recolour_is_admitted_after_the_reordering(self):
        image, proof = self.apply(reordered())
        self.assertEqual(image, IMAGE)
        self.assertEqual(proof["rewritten_offsets"], [4, 12])
        self.assertEqual(proof["webs"][0]["live_range"], [10, 12])

    def test_the_reordering_alone_leaves_the_body_semantically_equal(self):
        # the reordering is a topological order of the window's own DAG: the
        # `lea` and the `push` share no register, no flag and no memory cell
        decoded = [
            byte_identity.decode_ia32_bijection_instruction(
                BODY, offset, "decode")
            for offset in (12, 18)
        ]
        _, edges = byte_identity.ia32_schedule_dependence_edges(
            decoded, "dag")
        self.assertEqual(edges, [])

    def test_a_value_live_in_the_image_register_at_the_definition_refuses(
            self):
        # `mov edx, ecx` after the definition keeps the index alive past it,
        # so the index's range no longer ends where the web's begins
        body = bytearray(reordered())
        body[10:12] = bytes.fromhex("8bd1")     # jmp 12 -> mov edx, ecx
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self.apply(bytes(body))
        self.assertIn("the two live ranges overlap and cannot be coalesced",
                      str(caught.exception))

    def test_a_consumer_of_the_source_outside_the_web_refuses(self):
        # `mov edx, eax` reads the web's value at a site the declaration
        # omits, so the web is not closed and the rename would strand it
        body = bytearray(reordered())
        body[10:12] = bytes.fromhex("8bd0")     # jmp 12 -> mov edx, eax
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self.apply(bytes(body))
        self.assertIn("which is not the declared use set",
                      str(caught.exception))


class WebDerivationTests(unittest.TestCase):
    """W3: the web is derived from the graph, never taken on trust."""

    def apply(self, webs, body=None):
        return byte_identity.apply_web_recolour(
            reordered() if body is None else body, webs, frozenset(), "web")

    def test_an_undeclared_definition_that_reaches_the_use_is_refused(self):
        # the diamond's `je` path skips `mov eax, ebx`, so BOTH definitions
        # reach the push and a declaration that names one of them is not a web
        webs = [web_declaration(definitions=[3], uses=[14],
                                expected_rewritten_offsets=[4, 14])]
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self.apply(webs, DIAMOND)
        self.assertIn("which is not the declared definition set",
                      str(caught.exception))

    def test_the_whole_diamond_web_is_accepted(self):
        webs = [web_declaration(definitions=[3, 12], uses=[14],
                                expected_rewritten_offsets=[4, 13, 14])]
        image, proof = self.apply(webs, DIAMOND)
        self.assertEqual(proof["webs"][0]["rewritten_offsets"],
                         [4, 13, 14])

    def test_a_definition_that_reads_the_source_is_refused(self):
        webs = [web_declaration(definitions=[10], uses=[12],
                                expected_rewritten_offsets=[11, 12])]
        body = bytearray(reordered())
        body[10:12] = bytes.fromhex("03c1")     # jmp 12 -> add eax, ecx
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self.apply(webs, bytes(body))
        self.assertIn("also reads the source register", str(caught.exception))

    def test_a_use_that_already_names_the_image_register_is_refused(self):
        body = bytearray(reordered())
        body[12:13] = bytes.fromhex("41")       # push eax -> inc ecx
        with self.assertRaises(byte_identity.ByteIdentityError):
            self.apply([web_declaration()], bytes(body))

    def test_a_declared_offset_off_a_boundary_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self.apply([web_declaration(definitions=[5])])
        self.assertIn("not an instruction boundary", str(caught.exception))

    def test_a_rewritten_offset_set_that_differs_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self.apply([web_declaration(expected_rewritten_offsets=[4, 13])])
        self.assertIn("differs from its declaration", str(caught.exception))


class StructuralRefusalTests(unittest.TestCase):
    """W1 and W2."""

    def test_esp_and_ebp_are_refused(self):
        for names in (("esp", "ecx"), ("eax", "ebp")):
            with self.assertRaises(byte_identity.ByteIdentityError) as caught:
                byte_identity.apply_web_recolour(
                    reordered(),
                    [web_declaration(source_register=names[0],
                                     image_register=names[1])],
                    frozenset(), "web")
            self.assertIn("ESP or EBP", str(caught.exception))

    def test_a_rewritten_byte_over_a_relocation_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.apply_web_recolour(
                reordered(), [web_declaration()], frozenset({4}), "web")
        self.assertIn("overlaps a relocation", str(caught.exception))

    def test_an_unreachable_instruction_is_refused(self):
        # `jmp 19` skips the window entirely, so the push is unreachable
        body = bytearray(reordered())
        body[10:12] = bytes.fromhex("eb07")
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.apply_web_recolour(
                bytes(body), [web_declaration()], frozenset(), "web")
        self.assertIn("unreachable from the entry", str(caught.exception))

    def test_a_computed_jump_without_the_target_set_is_refused(self):
        body = bytearray(reordered())
        body[10:12] = bytes.fromhex("ffe1")     # jmp ecx
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.apply_web_recolour(
                bytes(body), [web_declaration()], frozenset(), "web")
        self.assertIn("requires the relocated in-body target set",
                      str(caught.exception))

    def test_a_use_whose_two_fields_name_the_source_is_refused(self):
        # `mov [eax], eax` names eax as BOTH the stored value and the address,
        # so which occurrence belongs to the web is not decidable
        body = bytearray(reordered())
        body[10:12] = bytes.fromhex("8900")
        webs = [web_declaration(uses=[10, 12],
                                expected_rewritten_offsets=[4, 11, 12])]
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.apply_web_recolour(
                bytes(body), webs, frozenset(), "web")
        self.assertIn("register fields", str(caught.exception))


class RecolourSchemaTests(unittest.TestCase):
    """The manifest schema closes what the composer then measures."""

    def validate(self, **overrides):
        return byte_identity.validate_web_recolour(
            recolour_spec(**overrides), "recolour", SIZE)

    def test_the_reference_declaration_validates(self):
        normalized = self.validate()
        self.assertEqual(normalized["webs"][0]["definitions"], [3])
        self.assertEqual(normalized["windows"][0]["target_order"], [1, 0])

    def test_a_web_that_names_one_register_twice_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError):
            self.validate(webs=[web_declaration(image_register="eax")])

    def test_a_rewritten_count_that_misses_an_occurrence_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError):
            self.validate(webs=[web_declaration(
                expected_rewritten_offsets=[4])])

    def test_a_changed_set_that_omits_a_recoloured_byte_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError):
            self.validate(expected_changed_offsets=[13, 14, 15, 16, 17, 18])

    def test_the_windows_are_optional(self):
        normalized = byte_identity.validate_web_recolour(
            recolour_spec(windows=None,
                          expected_changed_offsets=[4, 12]),
            "recolour", SIZE)
        self.assertNotIn("windows", normalized)


class DebugRegisterTests(unittest.TestCase):
    """W8: the S_REGISTER record list is pinned."""

    def stream(self, numbers=(17, 18)):
        records = bytearray()

        def record(kind, payload):
            records.extend(struct.pack("<HH", len(payload) + 2, kind))
            records.extend(payload)

        proc = bytearray(33)
        struct.pack_into("<III", proc, 12, SIZE, 1, 24)
        name = b"Fixture::Read"
        record(0x0205, bytes(proc) + bytes([len(name)]) + name)
        for index, number in enumerate(numbers):
            payload = struct.pack("<HH", 0x74, number)
            local = b"this" if index == 0 else b"selector"
            record(0x0002, payload + bytes([len(local)]) + local)
        record(0x0006, b"")
        return bytes(records)

    def measured(self, numbers=(17, 18)):
        stream = self.stream(numbers)
        rows = []
        for record in byte_identity.parse_codeview_symbol_stream(
                stream, "registers"):
            if record["type"] != byte_identity.CODEVIEW_REGISTER_RECORD_TYPE:
                continue
            field_at = byte_identity._codeview_register_field(
                record, "registers")
            rows.append([record["name"], record["offset"],
                         byte_identity._codeview_register_name(
                             stream, field_at, "registers")])
        return stream, rows

    def test_the_record_list_is_measured(self):
        stream, rows = self.measured()
        self.assertEqual([row[2] for row in rows], ["eax", "ecx"])
        self.assertEqual(
            byte_identity.require_web_recolour_debug_registers(
                stream, rows, "registers"), rows)

    def test_a_record_list_that_differs_is_refused(self):
        _, rows = self.measured()
        stream, _ = self.measured(numbers=(17, 20))
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.require_web_recolour_debug_registers(
                stream, rows, "registers")
        self.assertIn("differs from its declaration", str(caught.exception))


class RecolourCompositionTests(unittest.TestCase):
    """The whole certificate, including the oracle."""

    def setUp(self):
        self.seed = make_coff()
        self.donor = make_coff()
        self.record = function_record(self.seed, self.donor, IMAGE)

    def test_the_certificate_composes_retails_own_code(self):
        composed, detail = (
            byte_identity.compose_retail_exact_web_recolour(
                self.seed, self.donor, self.record, IMAGE))
        coff = byte_identity.CoffObject(composed)
        section = coff.function_section(TARGET_SYMBOL)
        self.assertEqual(byte_identity.coff_body(coff, section), IMAGE)
        self.assertTrue(detail["retail_exact"])
        self.assertEqual(detail["web_recolour"][0]["definitions"], [3])

    def test_an_image_that_is_not_the_oracle_is_refused(self):
        oracle = bytearray(IMAGE)
        oracle[4] ^= 0x08
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.compose_retail_exact_web_recolour(
                self.seed, self.donor, self.record, bytes(oracle))
        self.assertIn("is not retail-exact", str(caught.exception))

    def test_a_donor_that_does_not_reproduce_the_seed_is_refused(self):
        other = bytearray(BODY)
        other[1:3] = bytes.fromhex("33d2")      # xor edx, edx
        donor = make_coff(body=bytes(other))
        record = copy.deepcopy(self.record)
        record["expected_donor_body_sha256"] = byte_identity.sha256_bytes(
            bytes(other))
        record["expected_donor_metadata_sha256"] = (
            byte_identity.instruction_mosaic_metadata_sha256(
                byte_identity.CoffObject(donor),
                byte_identity.CoffObject(donor).function_section(
                    TARGET_SYMBOL)))
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.compose_retail_exact_web_recolour(
                self.seed, donor, record, IMAGE)
        self.assertIn("does not reproduce the seed's body",
                      str(caught.exception))

    def test_the_output_keeps_the_seed_line_and_relocation_tables(self):
        composed, _ = (
            byte_identity.compose_retail_exact_web_recolour(
                self.seed, self.donor, self.record, IMAGE))
        seed = byte_identity.CoffObject(self.seed)
        out = byte_identity.CoffObject(composed)
        sp = seed.function_section(TARGET_SYMBOL)
        cp = out.function_section(TARGET_SYMBOL)
        self.assertEqual(
            byte_identity._coff_table_bytes(out, cp, "lines"),
            byte_identity._coff_table_bytes(seed, sp, "lines"))
        for child in (".debug$F", ".debug$S"):
            self.assertEqual(
                byte_identity.coff_body(
                    out, byte_identity._comdat_child(out, cp, child)),
                byte_identity.coff_body(
                    seed, byte_identity._comdat_child(seed, sp, child)))

    def test_a_declaration_that_omits_the_reordering_is_refused(self):
        # the same recolour, declared on the body as compiled: refused,
        # because the `lea` that writes ecx still sits inside the range
        record = copy.deepcopy(self.record)
        del record["web_recolour"]["windows"]
        record["web_recolour"]["webs"] = [web_declaration(
            uses=[18], expected_rewritten_offsets=[4, 18])]
        record["web_recolour"]["expected_changed_offsets"] = [4, 18]
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.compose_retail_exact_web_recolour(
                self.seed, self.donor, record, IMAGE)
        self.assertIn("inside the web's live range", str(caught.exception))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
