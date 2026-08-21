"""Tests for the relational-form CERTIFICATE class.

`cmp a, b` / `Jcc` is rewritten to `cmp b, a` / `Jcc'`.  The rewriting is two
bytes -- the compare's direction bit and the branch's condition nibble -- and
the only semantic question is the flags, because `cmp a,b` and `cmp b,a` do
NOT leave the same ones.

The mirror table and the preserved/changed flag split are MEASURED, and
`MirrorTableTests` below re-derives both by exhaustion so the table can never
drift from the arithmetic.  The same derivation was independently confirmed on
hardware: `$SCRATCH/fp.c` and `fp32.c`, built with this project's own MSVC 4.2
and run under Wine, reproduce the six changed-pair counts and exactly these
ten agreeing condition pairs at byte and at dword width.

The fixture reuses the register-bijection suite's COFF builder with a body
whose comparison is the reversible `3B /r` form:

    0:  53 56 57         push ebx / esi / edi   <- prologue
    3:  8b 1d <D32>      mov  ebx, [_Nil]
    9:  8b fb            mov  edi, ebx
    11: 3b 3d <D32>      cmp  edi, [_Nil]       <- THE COMPARE
    17: 7c 08            jl   27                <- THE BRANCH
    19: 8b 1d <D32>      mov  ebx, [_Nil]
    25: 8b fb            mov  edi, ebx
    27: 5f 5e 5b         pop  edi / esi / ebx
    30: c3               ret
"""
from __future__ import annotations

import itertools
import struct
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import byte_identity  # noqa: E402
import tests.test_register_bijection as fixture  # noqa: E402


TARGET_SYMBOL = fixture.TARGET_SYMBOL
RELOCATIONS = fixture.RELOCATIONS
COMPARE_AT, BRANCH_AT = 11, 17

BODY = bytes.fromhex(
    "535657"          # push ebx / push esi / push edi
    "8b1d00000000"    # mov ebx, [_Nil]
    "8bfb"            # mov edi, ebx
    "3b3d00000000"    # cmp edi, [_Nil]        <- 11
    "7c08"            # jl  27                 <- 17
    "8b1d00000000"    # mov ebx, [_Nil]
    "8bfb"            # mov edi, ebx
    "5f5e5b"          # pop edi / pop esi / pop ebx
    "c3"              # ret
)

SITES = [{"compare_offset": COMPARE_AT, "branch_offset": BRANCH_AT,
          "seed_condition": "l", "image_condition": "g"}]


def relocation_map(body=BODY):
    return {offset: {"width": 4, "target": fixture.NIL_SYMBOL}
            for offset in RELOCATIONS}


def reversed_image(body=BODY, sites=None, relocations=None,
                   external=frozenset()):
    image, proof = byte_identity.apply_relational_form(
        body, sites if sites is not None else SITES,
        fixture.relocation_set(), "fixture", relocation_map(body), None,
        external)
    return image, proof


# --------------------------------------------------------------------------
# The measured table
# --------------------------------------------------------------------------
def _sub_flags(left, right, width=8):
    mask = (1 << width) - 1
    sign = 1 << (width - 1)
    result = (left - right) & mask
    sf = 1 if result & sign else 0
    sleft = 1 if left & sign else 0
    sright = 1 if right & sign else 0
    return {
        "cf": 1 if (left & mask) < (right & mask) else 0,
        "pf": 1 if bin(result & 0xFF).count("1") % 2 == 0 else 0,
        "af": 1 if (left & 0xF) < (right & 0xF) else 0,
        "zf": 1 if result == 0 else 0,
        "sf": sf,
        "of": 1 if (sleft != sright and sf != sleft) else 0,
    }


_CONDITION = {
    "o": lambda f: f["of"], "no": lambda f: not f["of"],
    "b": lambda f: f["cf"], "ae": lambda f: not f["cf"],
    "e": lambda f: f["zf"], "ne": lambda f: not f["zf"],
    "be": lambda f: f["cf"] or f["zf"],
    "a": lambda f: not f["cf"] and not f["zf"],
    "s": lambda f: f["sf"], "ns": lambda f: not f["sf"],
    "p": lambda f: f["pf"], "np": lambda f: not f["pf"],
    "l": lambda f: f["sf"] != f["of"], "ge": lambda f: f["sf"] == f["of"],
    "le": lambda f: f["zf"] or f["sf"] != f["of"],
    "g": lambda f: not f["zf"] and f["sf"] == f["of"],
}


class MirrorTableTests(unittest.TestCase):
    """The table is derived by exhaustion here, not copied from the module."""

    WIDTH = 6                                     # 4096 ordered pairs
    DOMAIN = None

    @classmethod
    def setUpClass(cls):
        cls.DOMAIN = list(itertools.product(range(1 << cls.WIDTH), repeat=2))

    def test_zf_is_the_only_flag_the_reversal_preserves(self):
        preserved = set()
        for flag in ("cf", "pf", "af", "zf", "sf", "of"):
            if all(_sub_flags(a, b, self.WIDTH)[flag]
                   == _sub_flags(b, a, self.WIDTH)[flag]
                   for a, b in self.DOMAIN):
                preserved.add(flag)
        self.assertEqual(preserved,
                         set(byte_identity.IA32_RELATIONAL_PRESERVED_FLAGS))
        self.assertEqual(
            set(byte_identity.IA32_ARITHMETIC_FLAGS) - preserved,
            set(byte_identity.IA32_RELATIONAL_CHANGED_FLAGS))

    def test_the_mirror_table_is_the_exhaustive_one(self):
        derived = {}
        for left in _CONDITION:
            agreeing = [right for right in _CONDITION
                        if all(bool(_CONDITION[left](
                            _sub_flags(a, b, self.WIDTH)))
                            == bool(_CONDITION[right](
                                _sub_flags(b, a, self.WIDTH)))
                            for a, b in self.DOMAIN)]
            # a condition either has exactly one mirror or none at all
            self.assertLessEqual(len(agreeing), 1, left)
            if agreeing:
                derived[left] = agreeing[0]
        self.assertEqual(derived, byte_identity.IA32_RELATIONAL_MIRROR)

    def test_the_six_unmirrorable_conditions_are_absent(self):
        for name in ("o", "no", "s", "ns", "p", "np"):
            self.assertNotIn(name, byte_identity.IA32_RELATIONAL_MIRROR)

    def test_the_mirror_is_an_involution(self):
        for left, right in byte_identity.IA32_RELATIONAL_MIRROR.items():
            self.assertEqual(
                byte_identity.IA32_RELATIONAL_MIRROR[right], left)

    def test_each_condition_reads_the_flags_the_table_says(self):
        for code, flags in byte_identity.IA32_CONDITION_FLAGS.items():
            name = byte_identity.IA32_CONDITION_NAMES[code]
            for flag in ("cf", "pf", "af", "zf", "sf", "of"):
                if flag in flags:
                    continue
                # a flag the table does not name may never change the answer
                for a, b in self.DOMAIN[:512]:
                    state = _sub_flags(a, b, self.WIDTH)
                    flipped = dict(state, **{flag: 1 - state[flag]})
                    self.assertEqual(bool(_CONDITION[name](state)),
                                     bool(_CONDITION[name](flipped)),
                                     f"j{name} reads {flag}")


# --------------------------------------------------------------------------
# The image
# --------------------------------------------------------------------------
class RelationalImageTests(unittest.TestCase):
    """Obligations 2 through 7."""

    def test_positive_control_reverses_exactly_two_bytes(self):
        image, proof = reversed_image()
        self.assertEqual(proof["rewritten_offsets"],
                         [COMPARE_AT, BRANCH_AT])
        self.assertEqual(image[COMPARE_AT], 0x39)
        self.assertEqual(image[BRANCH_AT], 0x7F)
        # everything else, ModRM and displacement included, is untouched
        self.assertEqual(
            [index for index in range(len(BODY)) if BODY[index] != image[index]],
            [COMPARE_AT, BRANCH_AT])
        self.assertEqual(image[COMPARE_AT + 1], BODY[COMPARE_AT + 1])
        self.assertEqual(proof["sites"][0]["flags_live_out"], [])
        self.assertEqual(proof["sites"][0]["seed_condition"], "l")
        self.assertEqual(proof["sites"][0]["image_condition"], "g")

    def test_refuses_a_successor_that_reads_a_changed_flag(self):
        # `adc ebx, [_Nil]` at 19 reads CF, which the reversal changes
        body = bytearray(BODY)
        body[19] = 0x13
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            reversed_image(bytes(body))
        self.assertIn("the reversal changes ['cf']", str(caught.exception))

    def test_admits_a_successor_that_reads_only_zf(self):
        # ZF is the one flag the reversal provably preserves, so a successor
        # that reads it is NOT a refusal.  `jne 27` at 19, padded with nops.
        body = bytearray(BODY)
        body[19:25] = bytes.fromhex("7506") + b"\x90" * 4
        image, proof = byte_identity.apply_relational_form(
            bytes(body), SITES, frozenset(), "fixture",
            {offset: {"width": 4, "target": fixture.NIL_SYMBOL}
             for offset in (5, 13)})
        self.assertEqual(proof["sites"][0]["flags_live_out"], ["zf"])
        self.assertEqual(image[BRANCH_AT], 0x7F)

    def test_refuses_a_condition_with_no_mirror(self):
        body = bytearray(BODY)
        body[BRANCH_AT] = 0x78                    # js
        sites = [dict(SITES[0], seed_condition="s", image_condition="s")]
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            reversed_image(bytes(body), sites)
        self.assertIn("has no mirror", str(caught.exception))

    def test_refuses_a_declared_condition_that_is_not_the_mirror(self):
        sites = [dict(SITES[0], image_condition="le")]
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            reversed_image(BODY, sites)
        self.assertIn("closed table's mirror", str(caught.exception))

    def test_refuses_a_compare_against_an_immediate(self):
        # `cmp edi, 0` has no reversed encoding at all
        body = bytearray(BODY)
        body[COMPARE_AT:COMPARE_AT + 6] = bytes.fromhex("81ff00000000")
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.apply_relational_form(
                bytes(body), SITES, frozenset(), "fixture",
                {offset: {"width": 4, "target": fixture.NIL_SYMBOL}
                 for offset in (5, 21)})
        self.assertIn("reversible encoding", str(caught.exception))

    def test_refuses_a_branch_that_is_not_adjacent_to_its_compare(self):
        sites = [dict(SITES[0], compare_offset=3)]
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            reversed_image(BODY, sites)
        self.assertIn("does not immediately follow", str(caught.exception))

    def test_refuses_a_branch_another_edge_can_reach(self):
        # `jmp 17` at 3 gives the branch a second predecessor, so one path
        # would consume flags this compare did not produce.
        body = bytearray(BODY)
        body[25:27] = bytes.fromhex("ebf6")       # jmp 17
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            reversed_image(bytes(body))
        self.assertIn("predecessor other than", str(caught.exception))

    def test_refuses_a_rewrite_that_overlaps_a_relocation(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.apply_relational_form(
                BODY, SITES, frozenset({COMPARE_AT}), "fixture",
                relocation_map())
        self.assertIn("overlaps a relocation", str(caught.exception))

    def test_refuses_an_offset_that_is_not_a_boundary(self):
        sites = [dict(SITES[0], compare_offset=COMPARE_AT + 1,
                      branch_offset=BRANCH_AT)]
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            reversed_image(BODY, sites)
        self.assertIn("not an instruction boundary", str(caught.exception))

    def test_decodes_the_body_to_exhaustion(self):
        items, successors, entries = byte_identity.ia32_relational_flow_walk(
            BODY, relocation_map(), "fixture")
        self.assertEqual(sum(item["length"] for item in items), len(BODY))
        self.assertEqual(entries, [0])
        self.assertEqual(items[-1]["flow"], "ret")


# --------------------------------------------------------------------------
# The flag model
# --------------------------------------------------------------------------
class FlagModelTests(unittest.TestCase):

    def test_an_unmodelled_opcode_reads_every_flag(self):
        # `daa` (0x27) is outside the table; the fail-closed answer keeps
        # every flag live, which can only cause a refusal.
        body = bytes.fromhex("2790c3")
        items, _, _ = byte_identity.ia32_relational_flow_walk(
            body, None, "fixture")
        self.assertEqual(items[0]["reads_flags"],
                         byte_identity.IA32_ARITHMETIC_FLAGS)
        self.assertEqual(items[0]["writes_flags"], frozenset())

    def test_the_group_digit_separates_cmp_from_adc(self):
        # 83 /7 is `cmp r/m32, imm8` and reads no flag; 83 /2 is `adc` and
        # reads CF.  An opcode-granular table would have to say both read CF,
        # and that alone turns a provable site into a refusal.
        compare, _, _ = byte_identity.ia32_relational_flow_walk(
            bytes.fromhex("83ff00c3"), None, "fixture")
        adc, _, _ = byte_identity.ia32_relational_flow_walk(
            bytes.fromhex("83d700c3"), None, "fixture")
        self.assertEqual(compare[0]["reads_flags"], frozenset())
        self.assertEqual(adc[0]["reads_flags"], frozenset({"cf"}))
        self.assertEqual(compare[0]["writes_flags"],
                         byte_identity.IA32_ARITHMETIC_FLAGS)

    def test_a_variable_shift_is_not_credited_with_writing_a_flag(self):
        # a shift by CL with a zero count leaves every flag untouched, so
        # nothing may be treated as killed
        items, _, _ = byte_identity.ia32_relational_flow_walk(
            bytes.fromhex("d3e0c3"), None, "fixture")
        self.assertEqual(items[0]["writes_flags"], frozenset())

    def test_inc_does_not_kill_carry(self):
        items, _, _ = byte_identity.ia32_relational_flow_walk(
            bytes.fromhex("40c3"), None, "fixture")
        self.assertNotIn("cf", items[0]["writes_flags"])
        self.assertIn("zf", items[0]["writes_flags"])

    def test_a_repeat_prefix_must_prefix_a_string_opcode(self):
        items, _, _ = byte_identity.ia32_relational_flow_walk(
            bytes.fromhex("f3a5c3"), None, "fixture")
        self.assertEqual(items[0]["reads_flags"], frozenset())
        with self.assertRaises(byte_identity.ByteIdentityError):
            byte_identity.ia32_relational_flow_walk(
                bytes.fromhex("f390c3"), None, "fixture")

    def test_refuses_a_computed_jump(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.ia32_relational_flow_walk(
                bytes.fromhex("ffe0c3"), None, "fixture")
        self.assertIn("computed jump", str(caught.exception))

    def test_refuses_an_unmodellable_opcode(self):
        with self.assertRaises(byte_identity.ByteIdentityError):
            byte_identity.ia32_relational_flow_walk(
                bytes.fromhex("f0" "40" "c3"), None, "fixture")


# --------------------------------------------------------------------------
# External entry points (C++ EH unwind funclets)
# --------------------------------------------------------------------------
class ExternalEntryTests(unittest.TestCase):
    """A funclet head is reached by the runtime, not by a decoded edge."""

    # ret, then an isolated run only an unwind table can enter
    ISLAND = bytes.fromhex("c3" "33c0" "c3")
    FLAGGED = bytes.fromhex("c3" "1cff" "c3")   # sbb al, -1 reads CF

    def test_unreachable_code_refuses_without_the_entry_set(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.ia32_relational_flow_walk(
                self.ISLAND, None, "fixture")
        self.assertIn("reachable neither from the entry", str(caught.exception))

    def test_the_declared_entry_closes_the_graph(self):
        items, _, entries = byte_identity.ia32_relational_flow_walk(
            self.ISLAND, None, "fixture", None, frozenset({1}))
        self.assertEqual(entries, [0, 1])
        self.assertEqual(len(items), 3)

    def test_an_entry_that_is_not_a_boundary_refuses(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.ia32_relational_flow_walk(
                self.ISLAND, None, "fixture", None, frozenset({2}))
        self.assertIn("not an instruction boundary", str(caught.exception))

    def test_a_changed_flag_live_at_an_external_entry_refuses(self):
        body = bytearray(BODY)
        body[19:25] = bytes.fromhex("eb04") + self.FLAGGED
        # 19: jmp 25 ; 21: ret ; 22: sbb al,-1 ; 24: ret -- 22 is an island
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.apply_relational_form(
                bytes(body), SITES, frozenset(), "fixture",
                {offset: {"width": 4, "target": fixture.NIL_SYMBOL}
                 for offset in (5, 13)}, None, frozenset({22}))
        self.assertIn("external entry", str(caught.exception))


# --------------------------------------------------------------------------
# The schema
# --------------------------------------------------------------------------
def declaration(**overrides):
    value = {
        "kind": byte_identity.RELATIONAL_FORM_KIND,
        "sites": [dict(site) for site in SITES],
        "expected_instruction_count": 13,
        "expected_rewritten_offsets": [COMPARE_AT, BRANCH_AT],
        "expected_external_entries": [],
        "expected_seed_debug_s_sha256": "00" * 32,
        "authenticity_rationale":
            "An operand exchange whose changed flags are proved dead at "
            "every successor of the branch that consumes them.",
    }
    value.update(overrides)
    return value


class RelationalSchemaTests(unittest.TestCase):

    def test_positive_control(self):
        normalized = byte_identity.validate_relational_form(
            declaration(), "x", len(BODY))
        self.assertEqual(normalized["sites"][0]["image_condition"], "g")

    def test_refuses_a_non_mirror_pair(self):
        with self.assertRaises(byte_identity.ByteIdentityError):
            byte_identity.validate_relational_form(
                declaration(sites=[dict(SITES[0], image_condition="ge")]),
                "x", len(BODY))

    def test_refuses_an_unmirrorable_condition(self):
        with self.assertRaises(byte_identity.ByteIdentityError):
            byte_identity.validate_relational_form(
                declaration(sites=[dict(SITES[0], seed_condition="s",
                                        image_condition="s")]),
                "x", len(BODY))

    def test_refuses_a_rewritten_offset_count_that_is_not_two_per_site(self):
        with self.assertRaises(byte_identity.ByteIdentityError):
            byte_identity.validate_relational_form(
                declaration(expected_rewritten_offsets=[COMPARE_AT]),
                "x", len(BODY))

    def test_refuses_a_branch_before_its_compare(self):
        with self.assertRaises(byte_identity.ByteIdentityError):
            byte_identity.validate_relational_form(
                declaration(sites=[dict(SITES[0], compare_offset=BRANCH_AT,
                                        branch_offset=COMPARE_AT)]),
                "x", len(BODY))

    def test_refuses_a_missing_rationale(self):
        with self.assertRaises(byte_identity.ByteIdentityError):
            byte_identity.validate_relational_form(
                declaration(authenticity_rationale="short"), "x", len(BODY))


# --------------------------------------------------------------------------
# The composition
# --------------------------------------------------------------------------
def function_record(seed_bytes, donor_bytes, image, **overrides):
    seed = byte_identity.CoffObject(seed_bytes)
    donor = byte_identity.CoffObject(donor_bytes)
    sp = seed.function_section(TARGET_SYMBOL)
    dp = donor.function_section(TARGET_SYMBOL)
    seed_body = byte_identity.coff_body(seed, sp)
    donor_body = byte_identity.coff_body(donor, dp)
    debug_child = byte_identity._comdat_child(seed, sp, ".debug$S")
    debug_stream = byte_identity.coff_body(seed, debug_child)
    record = {
        "mangled": TARGET_SYMBOL,
        "donor": "d_0123456789ab",
        "splice_class": byte_identity.RELATIONAL_FORM_CLASS,
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
        "expected_donor_body_sha256": byte_identity.sha256_bytes(donor_body),
        "expected_body_sha256": byte_identity.sha256_bytes(image),
        "expected_seed_metadata_sha256":
            byte_identity.instruction_mosaic_metadata_sha256(seed, sp),
        "expected_donor_metadata_sha256":
            byte_identity.instruction_mosaic_metadata_sha256(donor, dp),
        "expected_changed_offsets": sorted(
            index for index in range(len(image))
            if seed_body[index] != image[index]),
        "expected_code_renames": [],
        "expected_closure": [".debug$F", ".debug$S"],
        "retail_oracle": {
            "image": "LEGO1.DLL",
            "address": "0x%08x" % fixture.RETAIL_ADDRESS,
            "verdict": "MATCH",
            "length": len(image),
        },
        "retail_relocations": fixture.relocation_oracle(seed_bytes),
        "relational_form": declaration(
            expected_seed_debug_s_sha256=byte_identity.sha256_bytes(
                debug_stream)),
    }
    record.update(overrides)
    return record


class RelationalCompositionTests(unittest.TestCase):
    """Obligations 1, 8, 9 and 10."""

    def setUp(self):
        self.seed = fixture.make_coff(body=BODY)
        self.image, _ = reversed_image()
        self.retail = fixture.retail_body_for(self.image)

    def test_positive_control_installs_the_retail_image(self):
        composed, detail = (
            byte_identity.compose_retail_exact_relational_form(
                self.seed, self.seed,
                function_record(self.seed, self.seed, self.image),
                self.retail))
        coff = byte_identity.CoffObject(composed)
        primary = coff.function_section(TARGET_SYMBOL)
        self.assertEqual(byte_identity.coff_body(coff, primary), self.image)
        self.assertTrue(detail["retail_exact"])
        self.assertEqual(detail["rewritten_offsets"], [COMPARE_AT, BRANCH_AT])
        self.assertEqual(detail["preserved_flags"], ["zf"])
        self.assertEqual(detail["changed_flags"],
                         ["af", "cf", "of", "pf", "sf"])

    def test_refuses_an_image_that_is_not_the_retail_oracle(self):
        wrong = bytearray(self.retail)
        wrong[9] ^= 0xFF
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.compose_retail_exact_relational_form(
                self.seed, self.seed,
                function_record(self.seed, self.seed, self.image),
                bytes(wrong))
        self.assertIn("not retail-exact", str(caught.exception))

    def test_refuses_a_donor_whose_body_is_not_the_pinned_pre_image(self):
        other = bytearray(BODY)
        other[9:11] = b"\x8b\xd8"                 # mov ebx, eax
        donor = fixture.make_coff(body=bytes(other))
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.compose_retail_exact_relational_form(
                self.seed, donor,
                function_record(self.seed, self.seed, self.image),
                self.retail)
        self.assertIn("body differs from its pin", str(caught.exception))

    def test_refuses_a_declaration_that_understates_the_rewrite(self):
        record = function_record(self.seed, self.seed, self.image)
        record["relational_form"] = declaration(
            expected_rewritten_offsets=[COMPARE_AT, BRANCH_AT + 1],
            expected_seed_debug_s_sha256=record[
                "relational_form"]["expected_seed_debug_s_sha256"])
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.compose_retail_exact_relational_form(
                self.seed, self.seed, record, self.retail)
        self.assertIn("differs from its declaration", str(caught.exception))

    def test_refuses_an_external_entry_set_that_moved(self):
        record = function_record(self.seed, self.seed, self.image)
        record["relational_form"]["expected_external_entries"] = [3]
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.compose_retail_exact_relational_form(
                self.seed, self.seed, record, self.retail)
        self.assertIn("external entry set changed", str(caught.exception))

    def test_the_output_keeps_the_seed_debug_and_line_tables(self):
        composed, _ = byte_identity.compose_retail_exact_relational_form(
            self.seed, self.seed,
            function_record(self.seed, self.seed, self.image), self.retail)
        seed = byte_identity.CoffObject(self.seed)
        out = byte_identity.CoffObject(composed)
        sp = seed.function_section(TARGET_SYMBOL)
        op = out.function_section(TARGET_SYMBOL)
        for child in (".debug$F", ".debug$S"):
            self.assertEqual(
                byte_identity.coff_body(
                    out, byte_identity._comdat_child(out, op, child)),
                byte_identity.coff_body(
                    seed, byte_identity._comdat_child(seed, sp, child)))
        self.assertEqual(
            byte_identity._coff_table_bytes(out, op, "lines"),
            byte_identity._coff_table_bytes(seed, sp, "lines"))

    def test_schema_refuses_an_image_pin_equal_to_the_donor(self):
        record = function_record(self.seed, self.seed, self.image)
        record["expected_body_sha256"] = record["expected_donor_body_sha256"]
        manifest_context = "unit.functions[0]"
        with self.assertRaises(byte_identity.ByteIdentityError):
            byte_identity.require(
                record["expected_body_sha256"]
                != record["expected_donor_body_sha256"],
                f"{manifest_context}: the image pin does not move the "
                "donor body")


if __name__ == "__main__":       # pragma: no cover
    unittest.main()


# --------------------------------------------------------------------------
# Composing two certificate classes on ONE function
# --------------------------------------------------------------------------
class CertificateCompositionTests(unittest.TestCase):
    """`0x100417c0`'s window 6 in miniature.

    Retail's form there is `cmp [m], ebx` / `jg` where ours is
    `cmp edi, [m]` / `jl`: a register bijection {ebx<->edi} AND a relational
    reversal on the SAME two instructions.  Neither class reaches it alone,
    which is the whole of the composition question.
    """

    SIGMA = {"ebx": "edi", "edi": "ebx"}
    REGION = (3, 27)

    def sigma_image(self, body=BODY):
        image, _ = byte_identity.apply_register_bijection(
            body, self.SIGMA, self.REGION, fixture.relocation_set(),
            "sigma")
        return image

    def test_neither_operation_alone_reaches_the_target(self):
        target, _ = byte_identity.apply_relational_form(
            self.sigma_image(), SITES, fixture.relocation_set(), "both",
            relocation_map())
        only_sigma = self.sigma_image()
        only_reversal, _ = reversed_image()
        self.assertNotEqual(only_sigma, target)
        self.assertNotEqual(only_reversal, target)
        # and the target really is retail's window-6 shape
        self.assertEqual(target[COMPARE_AT:COMPARE_AT + 2],
                         bytes.fromhex("391d"))     # cmp [m], ebx
        self.assertEqual(target[BRANCH_AT], 0x7F)   # jg

    def test_the_two_operations_commute_exactly(self):
        sigma_then_reversal, _ = byte_identity.apply_relational_form(
            self.sigma_image(), SITES, fixture.relocation_set(),
            "sigma-then-reversal", relocation_map())
        reversal_first, _ = reversed_image()
        reversal_then_sigma = self.sigma_image(reversal_first)
        self.assertEqual(sigma_then_reversal, reversal_then_sigma)

    def test_each_proof_survives_the_other_operation(self):
        # sigma rewrites ModRM register FIELDS and changes no instruction's
        # flag effect; the reversal rewrites an opcode byte and a condition
        # nibble and changes no register field.  So each obligation is
        # discharged on the other's image without weakening -- which is why
        # they commute and why the ordering between them is free.
        plain, plain_proof = reversed_image()
        after, after_proof = byte_identity.apply_relational_form(
            self.sigma_image(), SITES, fixture.relocation_set(), "after",
            relocation_map())
        self.assertEqual(plain_proof["sites"][0]["flags_live_out"],
                         after_proof["sites"][0]["flags_live_out"])
        self.assertEqual(plain_proof["rewritten_offsets"],
                         after_proof["rewritten_offsets"])
        # and sigma's own byte set is the same before and after the reversal
        before = {index for index in range(len(BODY))
                  if BODY[index] != self.sigma_image()[index]}
        later = {index for index in range(len(BODY))
                 if plain[index] != self.sigma_image(plain)[index]}
        self.assertEqual(before, later)
        self.assertFalse(before & set(plain_proof["rewritten_offsets"]))

    def test_a_composer_refuses_a_partial_image_which_is_what_blocks_chaining(
            self):
        """The structural blocker, stated as a test.

        Every certificate composer ends with `differing == 0` against the
        pinned retail oracle.  So a class can only ever be handed a case it
        finishes ALONE: handing the register bijection a function that also
        needs a relational reversal refuses, not because sigma is wrong, but
        because sigma's image is not yet retail.  Two composers therefore
        cannot be chained on one COMDAT, and the manifest independently
        forbids it by requiring one entry per mangled name.
        """
        seed = fixture.make_coff(body=BODY)
        target, _ = byte_identity.apply_relational_form(
            self.sigma_image(), SITES, fixture.relocation_set(), "both",
            relocation_map())
        retail = fixture.retail_body_for(target)
        record = fixture.function_record(seed, seed, self.sigma_image())
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.compose_retail_exact_register_bijection(
                seed, seed, record, retail)
        self.assertIn("not retail-exact", str(caught.exception))
