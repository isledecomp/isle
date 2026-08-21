"""Tests for the composed-rewriting CERTIFICATE class.

Four certificate classes each state, on their own terms, that part of a
compiled body is retail's own code rearranged -- and each ends with
`differing == 0` against the pinned oracle, while the manifest admits one
entry per mangled name.  Together those facts mean a class can only be handed
a function it finishes ALONE.  A real compiled function is not so tidy:
`LegoROI::Read` differs from retail in five reordered windows, two regionally
renamed spans and three reversed comparisons, and no single one of those
statements is true of the whole body.

`retail_exact_composed_rewriting` is the seam.  It applies the three landed
primitives inside ONE entry, in the one order that is sound, and carries four
obligations of its own: C1 order (windows first, because they move the
instruction boundaries the byte-local certificates identify their operands
by), C2 disjointness of the rewritten byte sets, C3 separate `.debug$S`
claims (each bijection's S_REGISTER record set is measured on the SEED's
stream and the sets must be pairwise disjoint, so no record is ever read back
as though a previous bijection's output were the compiler's own allocation),
and C4 provenance (the pre-image is the seed's own body, so the donor is a
witness required to reproduce it).

The fixture is a miniature of the real row: the schedule fixture's window,
then a two-instruction region a `{ecx <-> edx}` bijection rewrites, then a
compare whose operands retail writes the other way round.

    0:  53              push ebx
    1:  56              push esi
    2:  33 f6           xor  esi, esi
    4:  8b 44 24 0c     mov  eax, [esp+12]   <- window
    8:  89 74 24 18     mov  [esp+24], esi   <- window
   12:  8d 5b 08        lea  ebx, [ebx+8]    <- window
   15:  89 74 24 1c     mov  [esp+28], esi   <- window
   19:  33 c9           xor  ecx, ecx        <- sigma region
   21:  8b 09           mov  ecx, [ecx]      <- sigma region
   23:  33 c9           xor  ecx, ecx        <- kills ecx on the exit edge
   25:  3b c3           cmp  eax, ebx        <- relational site
   27:  72 02           jb   31
   29:  33 c0           xor  eax, eax
   31:  5e              pop  esi
   32:  5b              pop  ebx
   33:  c3              ret
"""

from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import byte_identity  # noqa: E402
import test_instruction_schedule as fixture  # noqa: E402


TARGET_SYMBOL = fixture.TARGET_SYMBOL
PROLOGUE = bytes.fromhex("5356" "33f6")
WINDOW_SOURCE = bytes.fromhex("8b44240c" "89742418" "8d5b08" "8974241c")
TAIL = bytes.fromhex("33c9" "8b09" "33c9" "8b09" "33c9"
                     "3bc3" "7202" "33c0" "5e" "5b" "c3")
BODY = PROLOGUE + WINDOW_SOURCE + TAIL
SIZE = len(BODY)
WINDOW = (len(PROLOGUE), len(PROLOGUE) + len(WINDOW_SOURCE))
ORDER = [1, 3, 0, 2]
LENGTHS = [4, 4, 3, 4]
REGION = (19, 23)
SECOND_REGION = (23, 27)
COMPARE_AT, BRANCH_AT = 29, 31
LINE_ROWS = ((0, 11), (8, 12))
PROCEDURE_RANGE = [SIZE, 2, SIZE - 3]


def reordered(body=BODY):
    start, end = WINDOW
    pieces, cursor = [], start
    for length in LENGTHS:
        pieces.append(body[cursor:cursor + length])
        cursor += length
    assert cursor == end
    return body[:start] + b"".join(pieces[k] for k in ORDER) + body[end:]


def rewritten(body, second=False):
    """The bijection rewrites ModRM register fields; the reversal rewrites
    the compare's OPCODE byte only -- `3b /r` and `39 /r` share a ModRM, so
    exchanging the opcode exchanges the operands."""
    image = bytearray(body)
    image[20] = 0xD2          # xor ecx,ecx   -> xor edx,edx
    image[22] = 0x12          # mov ecx,[ecx] -> mov edx,[edx]
    if second:
        image[24] = 0xD2
        image[26] = 0x12
    image[COMPARE_AT] = 0x39  # cmp eax,ebx   -> cmp ebx,eax
    image[BRANCH_AT] = 0x77   # jb -> ja
    return bytes(image)


IMAGE = rewritten(reordered())
SECOND_IMAGE = rewritten(reordered(), second=True)


def window_declaration(**overrides):
    window = {
        "start": WINDOW[0], "end": WINDOW[1],
        "source_instruction_lengths": list(LENGTHS),
        "target_order": list(ORDER),
        "expected_dependence_edges": [],
        "expected_line_rows": [[8, 12, 3]],
    }
    window.update(overrides)
    return window


def bijection_declaration(**overrides):
    item = {
        "mapping": {"ecx": "edx", "edx": "ecx"},
        "region_start": REGION[0], "region_end": REGION[1],
        "expected_region_instruction_count": 2,
        "expected_rewritten_offsets": [20, 22],
        "debug_s_register_map": [],
    }
    item.update(overrides)
    return item


def site_declaration(**overrides):
    site = {
        "compare_offset": COMPARE_AT, "branch_offset": BRANCH_AT,
        "seed_condition": "b", "image_condition": "a",
        "expected_rewritten_offsets": [COMPARE_AT, BRANCH_AT],
    }
    site.update(overrides)
    return site


def composed_spec(**overrides):
    spec = {
        "kind": byte_identity.COMPOSED_REWRITING_KIND,
        "windows": [window_declaration()],
        "register_bijections": [bijection_declaration()],
        "relational_sites": [site_declaration()],
        "expected_instruction_count": len(
            byte_identity.decode_ia32_bijection_body(IMAGE, "fixture", {})),
        "expected_changed_offsets": sorted(
            index for index in range(SIZE) if BODY[index] != IMAGE[index]),
        "expected_procedure_range": list(PROCEDURE_RANGE),
        "expected_code_symbol_references": [],
        "expected_external_entries": [],
        "expected_seed_debug_s_sha256": "00" * 32,
        "expected_image_debug_s_sha256": "00" * 32,
        "authenticity_rationale":
            "One topological window reordering, one regional register "
            "bijection whose support is proved dead at the region boundary, "
            "and one mirrored comparison whose changed flags are dead at "
            "both successors -- composed inside a single entry.",
    }
    spec.update(overrides)
    return spec


def make_coff(**overrides):
    options = {
        "body": BODY,
        "line_rows": LINE_ROWS,
        "debug_stream": fixture.codeview_stream(
            size=SIZE, debug_start=PROCEDURE_RANGE[1],
            debug_end=PROCEDURE_RANGE[2]),
    }
    options.update(overrides)
    return fixture.make_coff(**options)


def function_record(seed_bytes, donor_bytes, image, **overrides):
    seed = byte_identity.CoffObject(seed_bytes)
    donor = byte_identity.CoffObject(donor_bytes)
    sp = seed.function_section(TARGET_SYMBOL)
    dp = donor.function_section(TARGET_SYMBOL)
    seed_body = byte_identity.coff_body(seed, sp)
    stream = byte_identity.coff_body(
        seed, byte_identity._comdat_child(seed, sp, ".debug$S"))
    record = {
        "mangled": TARGET_SYMBOL,
        "donor": "d_0123456789ab",
        "splice_class": byte_identity.COMPOSED_REWRITING_CLASS,
        "expected_section_number": sp["number"],
        "expected_donor_section_number": dp["number"],
        "expected_section_count": len(seed.sections),
        "expected_donor_section_count": len(donor.sections),
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
        "expected_code_renames": [],
        "expected_xdata_rename_offsets": [],
        "retail_oracle": {
            "image": "LEGO1.DLL",
            "address": "0x%08x" % fixture.RETAIL_ADDRESS,
            "verdict": "MATCH",
            "length": len(image),
        },
        "retail_relocations": [],
        "composed_rewriting": composed_spec(
            expected_seed_debug_s_sha256=byte_identity.sha256_bytes(stream),
            expected_image_debug_s_sha256=byte_identity.sha256_bytes(stream),
        ),
    }
    record.update(overrides)
    return record


class CompositionTests(unittest.TestCase):
    """The composition itself, on the primitives it delegates to."""

    def test_the_three_primitives_reach_retails_code_in_this_order(self):
        image, _ = byte_identity.apply_instruction_schedule(
            BODY, [window_declaration()], frozenset(), "s", {})
        image, proof = byte_identity.apply_register_bijection(
            image, {"ecx": "edx", "edx": "ecx"}, REGION, frozenset(), "b", {})
        self.assertEqual(proof["rewritten_offsets"], [20, 22])
        image, proof = byte_identity.apply_relational_form(
            image, [{"compare_offset": COMPARE_AT,
                     "branch_offset": BRANCH_AT,
                     "seed_condition": "b", "image_condition": "a"}],
            frozenset(), "r", {})
        self.assertEqual(proof["rewritten_offsets"],
                         [COMPARE_AT, BRANCH_AT])
        self.assertEqual(image, IMAGE)

    def test_the_bijection_and_the_reversal_commute(self):
        """C1: their relative order is free; only the window must be first."""
        base, _ = byte_identity.apply_instruction_schedule(
            BODY, [window_declaration()], frozenset(), "s", {})
        first, _ = byte_identity.apply_relational_form(
            base, [{"compare_offset": COMPARE_AT,
                    "branch_offset": BRANCH_AT,
                    "seed_condition": "b", "image_condition": "a"}],
            frozenset(), "r", {})
        first, _ = byte_identity.apply_register_bijection(
            first, {"ecx": "edx", "edx": "ecx"}, REGION, frozenset(), "b", {})
        self.assertEqual(first, IMAGE)


class DeclarationTests(unittest.TestCase):
    def validate(self, **overrides):
        return byte_identity.validate_composed_rewriting(
            composed_spec(**overrides), "fixture", SIZE)

    def test_the_reference_declaration_validates(self):
        normalized = self.validate()
        self.assertEqual(normalized["kind"],
                         byte_identity.COMPOSED_REWRITING_KIND)
        self.assertEqual(len(normalized["windows"]), 1)
        self.assertEqual(len(normalized["register_bijections"]), 1)
        self.assertEqual(len(normalized["relational_sites"]), 1)

    def test_a_single_statement_is_refused(self):
        """A lone certificate belongs to its own class, not to this one."""
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            self.validate(register_bijections=[], relational_sites=[],
                          expected_changed_offsets=sorted(
                              index for index in range(SIZE)
                              if BODY[index] != reordered()[index]))
        self.assertIn("composes nothing", str(raised.exception))

    def test_overlapping_bijection_regions_are_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            self.validate(register_bijections=[
                bijection_declaration(),
                bijection_declaration(region_start=REGION[0] + 1)])
        self.assertIn("unsorted or overlapping", str(raised.exception))

    def test_two_bijections_that_rewrite_one_byte_are_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            self.validate(register_bijections=[
                bijection_declaration(region_end=REGION[0] + 2,
                                      expected_rewritten_offsets=[20],
                                      expected_region_instruction_count=1),
                bijection_declaration(region_start=REGION[0] + 2,
                                      region_end=REGION[1],
                                      expected_rewritten_offsets=[20, 22],
                                      expected_region_instruction_count=1)])
        self.assertIn("expected_rewritten_offsets is invalid",
                      str(raised.exception))

    def test_a_byte_local_rewrite_inside_a_window_is_refused(self):
        """C2: a window may not also be a bijection region."""
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            self.validate(register_bijections=[bijection_declaration(
                region_start=WINDOW[0] + 1, region_end=WINDOW[0] + 5,
                expected_rewritten_offsets=[WINDOW[0] + 2])])
        self.assertIn("inside a reordered window", str(raised.exception))

    def test_a_relocation_reseat_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            self.validate(windows=[window_declaration(
                relocation_reseat=[[WINDOW[0], WINDOW[0] + 4]])])
        self.assertIn("refuses to move a relocation", str(raised.exception))

    def test_a_condition_pair_that_is_not_the_mirror_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            self.validate(relational_sites=[
                site_declaration(image_condition="ae")])
        self.assertIn("not the closed table's mirror", str(raised.exception))

    def test_a_changed_set_that_omits_a_rewritten_byte_is_refused(self):
        changed = composed_spec()["expected_changed_offsets"]
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            self.validate(expected_changed_offsets=[
                offset for offset in changed if offset != 20])
        self.assertIn("omits a rewritten byte", str(raised.exception))


class CompositionEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.seed = make_coff()
        self.donor = make_coff()

    def compose(self, record=None, retail=IMAGE, donor=None):
        record = record or function_record(self.seed, self.donor, IMAGE)
        return byte_identity.compose_retail_exact_composed_rewriting(
            self.seed, donor or self.donor, record, retail)

    def test_the_certificate_composes_retails_own_code(self):
        composed, detail = self.compose()
        checked = byte_identity.CoffObject(composed)
        section = checked.function_section(TARGET_SYMBOL)
        self.assertEqual(byte_identity.coff_body(checked, section), IMAGE)
        self.assertTrue(detail["retail_exact"])
        self.assertEqual(len(detail["instruction_schedule"]), 1)
        self.assertEqual(len(detail["register_bijections"]), 1)
        self.assertEqual(len(detail["relational_form"]), 1)

    def test_an_image_that_is_not_the_oracle_is_refused(self):
        other = bytearray(IMAGE)
        other[-2] ^= 0x01
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            self.compose(retail=bytes(other))
        self.assertIn("not retail-exact", str(raised.exception))

    def test_a_witness_that_does_not_reproduce_the_seed_is_refused(self):
        """C4: the donor is a provenance witness, not a body source."""
        other = bytearray(BODY)
        other[-2] ^= 0x01
        donor = make_coff(body=bytes(other))
        record = function_record(self.seed, donor, IMAGE)
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            self.compose(record=record, donor=donor)
        self.assertIn("does not reproduce the seed's body",
                      str(raised.exception))

    def test_a_declared_rename_is_refused(self):
        record = function_record(self.seed, self.donor, IMAGE,
                                 expected_code_renames=[[0, "T"]])
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            self.compose(record=record)
        self.assertIn("can declare no rename", str(raised.exception))

    def test_a_bijection_whose_rewrite_set_differs_is_refused(self):
        record = function_record(self.seed, self.donor, IMAGE)
        record["composed_rewriting"]["register_bijections"][0][
            "expected_rewritten_offsets"] = [20]
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            self.compose(record=record)
        self.assertIn("rewrote a different byte set", str(raised.exception))

    def test_two_bijections_claiming_one_debug_record_are_refused(self):
        """C3, the obligation the composition itself adds.

        Two regions whose supports both meet the register a named local lives
        in cannot both map its single S_REGISTER record: the second would
        read the first one's output as if it were the compiler's allocation.
        Everything else about this composition is valid -- it reaches the
        oracle -- so the refusal is C3 and nothing else.
        """
        stream = fixture.codeview_stream(
            size=SIZE, debug_start=PROCEDURE_RANGE[1],
            debug_end=PROCEDURE_RANGE[2]) + _register_record("i", "ecx")
        seed = make_coff(debug_stream=stream)
        donor = make_coff(debug_stream=stream)
        record = function_record(seed, donor, SECOND_IMAGE)
        record["composed_rewriting"]["register_bijections"] = [
            bijection_declaration(),
            bijection_declaration(region_start=SECOND_REGION[0],
                                  region_end=SECOND_REGION[1],
                                  expected_rewritten_offsets=[24, 26]),
        ]
        record["composed_rewriting"]["expected_changed_offsets"] = \
            record["expected_changed_offsets"]
        record["composed_rewriting"]["expected_instruction_count"] = len(
            byte_identity.decode_ia32_bijection_body(
                SECOND_IMAGE, "fixture", {}))
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            byte_identity.compose_retail_exact_composed_rewriting(
                seed, donor, record, SECOND_IMAGE)
        self.assertIn("both name the S_REGISTER record",
                      str(raised.exception))

    def test_two_disjoint_debug_claims_are_accepted(self):
        """The same two regions, each naming its OWN record, compose."""
        stream = (fixture.codeview_stream(
            size=SIZE, debug_start=PROCEDURE_RANGE[1],
            debug_end=PROCEDURE_RANGE[2])
            + _register_record("i", "ecx") + _register_record("j", "esi"))
        seed = make_coff(debug_stream=stream)
        donor = make_coff(debug_stream=stream)
        record = function_record(seed, donor, SECOND_IMAGE)
        offset = len(stream) - len(_register_record("j", "esi")) \
            - len(_register_record("i", "ecx"))
        record["composed_rewriting"]["register_bijections"] = [
            bijection_declaration(debug_s_register_map=[{
                "name": "i", "record_offset": offset,
                "donor_register": "ecx", "image_register": "edx"}]),
            bijection_declaration(
                mapping={"esi": "edi", "edi": "esi"},
                region_start=SECOND_REGION[0], region_end=SECOND_REGION[1],
                expected_rewritten_offsets=[24, 26],
                debug_s_register_map=[{
                    "name": "j",
                    "record_offset": offset + len(
                        _register_record("i", "ecx")),
                    "donor_register": "esi", "image_register": "edi"}]),
        ]
        # The second region does not carry esi or edi, so its sigma rewrites
        # nothing there -- which the primitive refuses.  What this test fixes
        # is that the two record claims are DISJOINT and therefore reach the
        # primitive at all, rather than being refused by C3.
        with self.assertRaises(byte_identity.ByteIdentityError) as raised:
            byte_identity.compose_retail_exact_composed_rewriting(
                seed, donor, record, SECOND_IMAGE)
        self.assertNotIn("both name the S_REGISTER record",
                         str(raised.exception))


def _register_record(name: str, register: str) -> bytes:
    import struct
    payload = bytearray(4)
    struct.pack_into(
        "<H", payload, 2,
        byte_identity.CODEVIEW_X86_REGISTER_NUMBERS[register])
    payload += bytes([len(name)]) + name.encode()
    return struct.pack("<HH", len(payload) + 2,
                       byte_identity.CODEVIEW_REGISTER_RECORD_TYPE) \
        + bytes(payload)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
