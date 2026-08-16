"""Red-first tests for the two COMDAT-splicing extensions.

Contract: docs/comdat-splice-extensions-spec.md §4.  Every test here must be
observed FAILING before any implementation lands.

The fixture models the real shape of `0x1003cf20 ~LegoCacheSoundManager`,
which is the first customer of the class:

  * seed and donor bodies differ in length (30 vs 26 here; 274 vs 258 there),
  * their primary relocation COUNTS are equal, and
  * exactly one ordinal is a *global* target substitution
    (`?SeedCallee@@YAXXZ` -> `?RetailCallee@@YAXXZ`; there,
    `??3@YAXPAX@Z` -> `??1LegoCacheSoundEntry@@QAE@XZ`),
  * plus one compiler-local `$T` serial rename, which the existing pairing
    machinery already tolerates.

Note for the reviewer: the spec's §2 motivation says an inline flip changes
the relocation *count*.  That is true of `0x1009f490` (12 -> 13) but NOT of
`0x1003cf20`, where the count is 14 on both sides and a global symbol is
*substituted* at equal count.  The class must handle both.
"""
from __future__ import annotations

import copy
import hashlib
import json
import struct
import sys
import unittest
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

TOOLS = Path(__file__).resolve().parents[1]
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))
import byte_identity  # noqa: E402

TARGET_SYMBOL = "?Target@@YAXXZ"
COMMON = "?Common@@YAXXZ"
SEED_CALLEE = "?SeedCallee@@YAXXZ"
RETAIL_CALLEE = "?RetailCallee@@YAXXZ"
OTHER = "?Other@@YAXXZ"
DIRECTIVE = b"-defaultlib:LIBCMT -defaultlib:OLDNAMES "

SEED_SIZE = 30
DONOR_SIZE = 26
LINKED_SPAN = 32          # both round up to the same 16-byte bucket
RETAIL_ADDRESS = 0x1003CF20


def _section_aux(length, relocations, lines, selection, associated=0,
                 checksum=0):
    result = bytearray(18)
    struct.pack_into("<IHHI", result, 0, length, relocations, lines, checksum)
    struct.pack_into("<H", result, 12, associated & 0xFFFF)
    result[14] = selection
    struct.pack_into("<H", result, 16, associated >> 16)
    return bytes(result)


def _function_aux(total_size, line_pointer):
    result = bytearray(18)
    struct.pack_into("<II", result, 4, total_size, line_pointer)
    return bytes(result)


def _marker_aux(line, next_function=0):
    result = bytearray(18)
    struct.pack_into("<H", result, 4, line)
    struct.pack_into("<I", result, 12, next_function)
    return bytes(result)


def _body(size, salt):
    body = bytearray(((i * 7 + salt) & 0xFF) for i in range(size))
    return body


def make_divergent_coff(
    *,
    donor=False,
    swap_text_sections=False,
    substituted=None,
    retail_callee_storage=2,
    duplicate_retail_callee=False,
    declare_retail_callee=True,
    other_symbol=OTHER,
):
    """One classic-i386 COFF with a complete EH COMDAT closure.

    donor=True produces the shorter body whose second relocation names
    `substituted` (default RETAIL_CALLEE) instead of SEED_CALLEE.
    """
    size = DONOR_SIZE if donor else SEED_SIZE
    body = _body(size, 13 if donor else 3)
    reloc_offsets = [4, 12, 18 if donor else 20]
    for off in reloc_offsets:
        body[off:off + 4] = b"\0" * 4
    second = (substituted or RETAIL_CALLEE) if donor else SEED_CALLEE
    local_name = "$T200" if donor else "$T100"

    xdata = bytes(bytearray(16))
    debug_s = bytearray(40)
    struct.pack_into("<H", debug_s, 2, 0x0205)
    struct.pack_into("<III", debug_s, 16, size, 2 if donor else 1,
                     size - 2)

    # symbol indices, counting auxiliary records
    target_index = 2
    common_index = 8
    seed_callee_index = 9
    retail_callee_index = 10
    local_index = 15

    target_lines = bytearray(struct.pack("<IH", target_index, 0))
    target_lines.extend(struct.pack("<IH", 3 if donor else 4,
                                    21 if donor else 11))
    other_lines = (struct.pack("<IH", 18, 0) + struct.pack("<IH", 1, 77))

    target_input = {
        "name": ".text", "raw": bytes(body),
        "relocations": [(reloc_offsets[0], common_index, 0x14),
                        (reloc_offsets[1],
                         retail_callee_index if donor else seed_callee_index,
                         0x14),
                        (reloc_offsets[2], local_index, 0x06)],
        "lines": bytes(target_lines), "characteristics": 0x60501020}
    other_input = {
        "name": ".text", "raw": b"OTHER-FN",
        "relocations": [], "lines": other_lines,
        "characteristics": 0x60501020}
    # swap_text_sections moves the target to section 4 with its size intact,
    # so the earlier length/span guards pass and the SEAT check is what fires.
    target_seat, other_seat = (4, 1) if swap_text_sections else (1, 4)
    first, fourth = ((other_input, target_input) if swap_text_sections
                     else (target_input, other_input))
    section_inputs = [
        first,
        {"name": ".xdata$x", "raw": xdata,
         "relocations": [(0, target_index, 0x0007)],
         "lines": b"", "characteristics": 0x40301040},
        {"name": ".debug$S", "raw": bytes(debug_s),
         "relocations": [(28, target_index, 0x000B),
                         (32, target_index, 0x000A)],
         "lines": b"", "characteristics": 0x42101048},
        fourth,
        {"name": ".drectve", "raw": DIRECTIVE,
         "relocations": [], "lines": b"", "characteristics": 0x00100A00},
    ]
    target_slot = 3 if swap_text_sections else 0
    other_slot = 0 if swap_text_sections else 3

    cursor = 20 + len(section_inputs) * 40
    payload = bytearray()
    sections = []
    for item in section_inputs:
        raw_offset = cursor
        payload.extend(item["raw"])
        cursor += len(item["raw"])
        table = b"".join(struct.pack("<IIH", *row)
                         for row in item["relocations"])
        table_offset = cursor if table else 0
        payload.extend(table)
        cursor += len(table)
        line_offset = cursor if item["lines"] else 0
        payload.extend(item["lines"])
        cursor += len(item["lines"])
        sections.append({**item, "raw_offset": raw_offset,
                         "relocation_offset": table_offset,
                         "line_offset": line_offset})

    checksum = int.from_bytes(hashlib.sha256(bytes(body)).digest()[:4],
                              "little")
    symbols = [
        (".text", 0, target_seat, 0, 3,
         _section_aux(size, 3, 2, 2, checksum=checksum)),
        (TARGET_SYMBOL, 0, target_seat, 0x20, 2,
         _function_aux(size, sections[target_slot]["line_offset"])),
        (".bf", 0, target_seat, 0, 101, _marker_aux(20 if donor else 10)),
        (".ef", size, target_seat, 0, 101,
         _marker_aux(41 if donor else 31)),
        (COMMON, 0, 0, 0x20, 2, None),
        (SEED_CALLEE, 0, 0, 0x20, 2, None),
        (RETAIL_CALLEE, 0, 0, 0x20, retail_callee_storage, None)
        if declare_retail_callee else (
            "?MissingPlaceholder@@YAXXZ", 0, 0, 0x20, 2, None
        ),
        (".xdata$x", 0, 2, 0, 3,
         _section_aux(16, 1, 0, 5, associated=target_seat)),
        (".debug$S", 0, 3, 0, 3,
         _section_aux(40, 2, 0, 5, associated=target_seat)),
        (local_name, 4, 2, 0, 3, None),
        (".text", 0, other_seat, 0, 3,
         _section_aux(8, 0, 2, 2, checksum=0x12345678)),
        (other_symbol, 0, other_seat, 0x20, 2,
         _function_aux(8, sections[other_slot]["line_offset"])),
        (".bf", 0, other_seat, 0, 101, _marker_aux(70)),
        (".ef", 8, other_seat, 0, 101, _marker_aux(71)),
        (".drectve", 0, 5, 0, 3, _section_aux(len(DIRECTIVE), 0, 0, 0)),
    ]
    if duplicate_retail_callee:
        symbols.append((RETAIL_CALLEE, 0, 0, 0x20, 2, None))

    string_offsets = {}
    strings = bytearray(b"\0\0\0\0")

    def encoded(name):
        raw = name.encode("ascii")
        if len(raw) <= 8:
            return raw.ljust(8, b"\0")
        if name not in string_offsets:
            string_offsets[name] = len(strings)
            strings.extend(raw + b"\0")
        return b"\0\0\0\0" + struct.pack("<I", string_offsets[name])

    table = bytearray()
    count = 0
    for name, value, section, stype, storage, aux in symbols:
        table.extend(encoded(name) + struct.pack(
            "<IhHBB", value, section, stype, storage,
            1 if aux is not None else 0))
        count += 1
        if aux is not None:
            assert len(aux) == 18
            table.extend(aux)
            count += 1
    struct.pack_into("<I", strings, 0, len(strings))

    headers = bytearray()
    for item in sections:
        headers.extend(item["name"].encode("ascii").ljust(8, b"\0"))
        headers.extend(struct.pack(
            "<IIIIIIHHI", 0, 0, len(item["raw"]), item["raw_offset"],
            item["relocation_offset"], item["line_offset"],
            len(item["relocations"]), len(item["lines"]) // 6,
            item["characteristics"]))
    header = struct.pack("<HHIIIHH", 0x14C, len(sections), 0x1234,
                         cursor, count, 0, 0)
    return bytes(header + headers + payload + table + strings)


def retail_body_for(donor_bytes):
    """Retail's own bytes: the donor body with its relocation fields
    resolved to real addresses, which is exactly what masking removes."""
    coff = byte_identity.CoffObject(donor_bytes)
    section = coff.function_section(TARGET_SYMBOL)
    body = bytearray(byte_identity.coff_body(coff, section))
    for record in byte_identity.detailed_relocations(coff, section):
        off, width = record["offset"], record["width"]
        body[off:off + width] = bytes(
            (0xA0 + i) & 0xFF for i in range(width))
    return bytes(body)


def relocation_oracle_for(donor_bytes, retail_body):
    coff = byte_identity.CoffObject(donor_bytes)
    section = coff.function_section(TARGET_SYMBOL)
    result = []
    for record in byte_identity.detailed_relocations(coff, section):
        offset = record["offset"]
        operand = retail_body[offset:offset + 4]
        if record["type"] == 0x0006:
            resolved = int.from_bytes(operand, "little")
        else:
            resolved = (
                RETAIL_ADDRESS + offset + 4
                + int.from_bytes(operand, "little", signed=True)
            ) & 0xFFFFFFFF
        result.append({
            **{key: record[key] for key in (
                "offset", "type", "addend", "target", "target_section",
                "target_value", "target_type", "target_storage",
            )},
            "retail_target":
                f"0x{(resolved - record['addend']) & 0xFFFFFFFF:08x}",
        })
    return result


def function_record(donor_bytes, **overrides):
    coff = byte_identity.CoffObject(donor_bytes)
    section = coff.function_section(TARGET_SYMBOL)
    record = {
        "mangled": TARGET_SYMBOL,
        "donor": "d_fixture",
        "splice_class": "retail_exact_reloc_divergent",
        "expected_seed_length": SEED_SIZE,
        "expected_donor_length": DONOR_SIZE,
        "expected_linked_span": LINKED_SPAN,
        "expected_body_sha256": hashlib.sha256(
            byte_identity.coff_body(coff, section)).hexdigest(),
        "retail_oracle": {"image": "LEGO1.DLL", "address": "0x1003cf20",
                          "verdict": "MATCH", "length": DONOR_SIZE},
        "retail_relocations": relocation_oracle_for(
            donor_bytes, retail_body_for(donor_bytes)
        ),
    }
    record.update(overrides)
    return record


class RetailExactRelocDivergentTests(unittest.TestCase):
    """Spec §4 tests 1-8 — the splice class."""

    def compose(self, seed, donor, function, retail):
        return byte_identity.compose_retail_exact_reloc_divergent(
            seed, donor, function, retail)

    def test_00_positive_control_composes_the_retail_body(self):
        """Not in §4, but the class is worthless if the happy path fails."""
        seed = make_divergent_coff()
        donor = make_divergent_coff(donor=True)
        composed, detail = self.compose(
            seed, donor, function_record(donor), retail_body_for(donor))
        checked = byte_identity.CoffObject(composed)
        section = checked.function_section(TARGET_SYMBOL)
        self.assertEqual(
            byte_identity.coff_body(checked, section),
            byte_identity.coff_body(
                byte_identity.CoffObject(donor),
                byte_identity.CoffObject(donor).function_section(
                    TARGET_SYMBOL)))
        self.assertEqual(detail["splice_class"],
                         "retail_exact_reloc_divergent")
        self.assertEqual(detail["substituted_relocations"], 1)

    def test_01_rejects_body_that_is_not_retail_exact(self):
        seed = make_divergent_coff()
        donor = make_divergent_coff(donor=True)
        retail = bytearray(retail_body_for(donor))
        retail[9] ^= 0xFF          # a byte no relocation masks
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "retail"):
            self.compose(seed, donor, function_record(donor), bytes(retail))

    def test_02_rejects_retail_body_of_the_wrong_length(self):
        seed = make_divergent_coff()
        donor = make_divergent_coff(donor=True)
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "length"):
            self.compose(seed, donor, function_record(donor),
                         retail_body_for(donor)[:-1])

    def test_03_rejects_donor_relocation_absent_from_the_seed(self):
        seed = make_divergent_coff(declare_retail_callee=False)
        donor = make_divergent_coff(donor=True)
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "not declared|absent"):
            self.compose(seed, donor, function_record(donor),
                         retail_body_for(donor))

    def test_04_rejects_seed_symbol_of_a_different_storage_class(self):
        seed = make_divergent_coff(retail_callee_storage=3)
        donor = make_divergent_coff(donor=True)
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "storage|type"):
            self.compose(seed, donor, function_record(donor),
                         retail_body_for(donor))

    def test_05_rejects_ambiguous_symbol_remap(self):
        seed = make_divergent_coff(duplicate_retail_callee=True)
        donor = make_divergent_coff(donor=True)
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "ambiguous"):
            self.compose(seed, donor, function_record(donor),
                         retail_body_for(donor))

    def test_06_rejects_section_seat_mismatch(self):
        seed = make_divergent_coff()
        donor = make_divergent_coff(donor=True, swap_text_sections=True)
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "seat"):
            self.compose(seed, donor, function_record(donor),
                         retail_body_for(donor))

    def test_07_rejects_linked_span_mismatch(self):
        seed = make_divergent_coff()
        donor = make_divergent_coff(donor=True)
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "span"):
            self.compose(seed, donor,
                         function_record(donor, expected_linked_span=48),
                         retail_body_for(donor))

    def test_08_rejects_differing_function_multiset(self):
        seed = make_divergent_coff()
        donor = make_divergent_coff(donor=True, other_symbol="?Extra@@YAXXZ")
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "function set"):
            self.compose(seed, donor, function_record(donor),
                         retail_body_for(donor))

    def test_rejects_changed_retail_relocation_operand_before_masking(self):
        seed = make_divergent_coff()
        donor = make_divergent_coff(donor=True)
        retail = bytearray(retail_body_for(donor))
        first = byte_identity.detailed_relocations(
            byte_identity.CoffObject(donor),
            byte_identity.CoffObject(donor).function_section(TARGET_SYMBOL),
        )[0]
        retail[first["offset"]] ^= 1
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "resolves"):
            self.compose(seed, donor, function_record(donor), bytes(retail))

    def test_relocation_oracle_refuses_overlapping_masks(self):
        donor = make_divergent_coff(donor=True)
        oracle = function_record(donor)["retail_relocations"]
        oracle[1]["offset"] = oracle[0]["offset"] + 1
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "overlap"):
            byte_identity.validate_retail_relocation_oracle(
                oracle, "fixture", DONOR_SIZE
            )

    def test_core_refuses_caller_selected_closure_mode(self):
        seed = make_divergent_coff()
        donor = make_divergent_coff(donor=True)
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "topology mode"):
            byte_identity.compose_same_slot_resize(
                seed, donor, function_record(donor),
                retail_body=retail_body_for(donor),
                target_closure_extract=True,
            )

    def test_base_composer_refuses_a_source_proof_bypass(self):
        seed = make_divergent_coff()
        donor = make_divergent_coff(donor=True)
        function = function_record(donor)
        function["target_source_refactor"] = {"present": True}
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "source-proof composer"):
            self.compose(seed, donor, function, retail_body_for(donor))


class RetailExactTargetClosureTests(unittest.TestCase):
    def _live_anim_case(self):
        manifest = json.loads(
            (TOOLS / "byte_identity_manifest.json").read_text()
        )
        unit = next(
            item for item in manifest["translation_units"]
            if item["source"] == "LEGO1/lego/sources/anim/legoanim.cpp"
        )
        return unit, copy.deepcopy(unit["donors"][0]["recipe"]), \
            copy.deepcopy(unit["functions"][0])

    def _source_fixture(self):
        target = b"// FUNCTION: LEGO1 0x10000010\nint f() { return 1; }\n"
        seed = b"seed entropy\n" + target + b"// FUNCTION: LEGO1 0x10000020\n"
        donor = b"donor entropy\n" + target + b"// FUNCTION: LEGO1 0x10000020\n"
        return seed, donor, {
            "start_marker": "// FUNCTION: LEGO1 0x10000010",
            "end_marker": "// FUNCTION: LEGO1 0x10000020",
            "range_pin": {
                "baseline_sha256": hashlib.sha256(target).hexdigest(),
                "baseline_size": len(target),
                "baseline_line_count": target.count(b"\n"),
                "baseline_significant_token_sha256":
                    byte_identity.source_overlay_significant_sha256(target),
            },
        }

    def test_target_source_window_is_identical_while_entropy_differs(self):
        seed, donor, proof = self._source_fixture()
        detail = byte_identity.require_target_source_range_identity(
            seed, donor, proof, "fixture"
        )
        self.assertEqual(detail["target_source_size"],
                         proof["range_pin"]["baseline_size"])

    def test_target_source_change_is_refused(self):
        seed, donor, proof = self._source_fixture()
        donor = donor.replace(b"return 1", b"return 2")
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "target source range"):
            byte_identity.require_target_source_range_identity(
                seed, donor, proof, "fixture"
            )

    def test_ambiguous_target_marker_is_refused(self):
        seed, donor, proof = self._source_fixture()
        donor += proof["start_marker"].encode("ascii")
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "not unique"):
            byte_identity.require_target_source_range_identity(
                seed, donor, proof, "fixture"
            )

    def test_topology_allows_only_the_declared_seed_subset(self):
        seed = SimpleNamespace(sections=[None] * 5)
        donor = SimpleNamespace(sections=[None] * 3)
        seed_functions = Counter({TARGET_SYMBOL: 1, COMMON: 1, OTHER: 1})
        donor_functions = Counter({TARGET_SYMBOL: 1})
        seed_comdats = Counter({
            (TARGET_SYMBOL, 0x20, 2, ".text", 2, (".debug$S",)): 1,
            (COMMON, 0x20, 2, ".text", 2, (".debug$S",)): 1,
            (OTHER, 0x20, 2, ".text", 2, (".debug$S",)): 1,
        })
        donor_comdats = Counter({
            (TARGET_SYMBOL, 0x20, 2, ".text", 2, (".debug$S",)): 1,
        })
        function = {
            "expected_seed_section_count": 5,
            "expected_donor_section_count": 3,
            "expected_seed_only_functions": sorted([COMMON, OTHER]),
        }
        with mock.patch.object(
                byte_identity, "function_multiset",
                side_effect=lambda obj: (seed_functions if obj is seed
                                         else donor_functions)), \
             mock.patch.object(
                byte_identity, "comdat_primary_identity_multiset",
                side_effect=lambda obj: (seed_comdats if obj is seed
                                         else donor_comdats)):
            detail = byte_identity.require_target_closure_extraction_topology(
                seed, donor, function, "fixture"
            )
        self.assertEqual(detail["seed_only_functions"],
                         sorted([COMMON, OTHER]))

    def test_topology_refuses_a_donor_added_function(self):
        seed = SimpleNamespace(sections=[None] * 5)
        donor = SimpleNamespace(sections=[None] * 3)
        function = {
            "expected_seed_section_count": 5,
            "expected_donor_section_count": 3,
            "expected_seed_only_functions": [OTHER],
        }
        with mock.patch.object(
                byte_identity, "function_multiset",
                side_effect=lambda obj: (
                    Counter({TARGET_SYMBOL: 1, OTHER: 1}) if obj is seed
                    else Counter({TARGET_SYMBOL: 1, "?Added@@YAXXZ": 1})
                )), mock.patch.object(
                byte_identity, "comdat_primary_identity_multiset",
                return_value=Counter()):
            with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                        "adds functions"):
                byte_identity.require_target_closure_extraction_topology(
                    seed, donor, function, "fixture"
                )

    def test_topology_refuses_an_added_data_comdat(self):
        seed = SimpleNamespace(sections=[None] * 5)
        donor = SimpleNamespace(sections=[None] * 3)
        seed_functions = Counter({TARGET_SYMBOL: 1, OTHER: 1})
        donor_functions = Counter({TARGET_SYMBOL: 1})
        target = (TARGET_SYMBOL, 0x20, 2, ".text", 2, (".debug$S",))
        other = (OTHER, 0x20, 2, ".text", 2, (".debug$S",))
        added_data = ("?Data@@3HA", 0, 2, ".data", 2, ())
        function = {
            "expected_seed_section_count": 5,
            "expected_donor_section_count": 3,
            "expected_seed_only_functions": [OTHER],
        }
        with mock.patch.object(
                byte_identity, "function_multiset",
                side_effect=lambda obj: (seed_functions if obj is seed
                                         else donor_functions)), \
             mock.patch.object(
                byte_identity, "comdat_primary_identity_multiset",
                side_effect=lambda obj: (
                    Counter({target: 1, other: 1}) if obj is seed
                    else Counter({target: 1, added_data: 1})
                )):
            with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                        "adds or exchanges"):
                byte_identity.require_target_closure_extraction_topology(
                    seed, donor, function, "fixture"
                )

    def test_recipe_policy_refuses_a_live_body_generator(self):
        unit, recipe, function = self._live_anim_case()
        recipe["renderings"][0]["operations"][0]["gen"] = {
            "k": "noop_assign", "assignment_target": "p_time", "repeat": 1,
        }
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "emitting or unsupported generator"):
            byte_identity.require_target_closure_recipe_policy(
                recipe, function, ROOT, unit["source"], "fixture"
            )

    def test_live_target_closure_recipe_satisfies_the_narrow_policy(self):
        unit, recipe, function = self._live_anim_case()
        detail = byte_identity.require_target_closure_recipe_policy(
            recipe, function, ROOT, unit["source"], "fixture"
        )
        self.assertEqual(detail["destructive_source_binding_count"], 1)
        self.assertEqual(detail["fresh_declaration_identifier_count"], 10)
        self.assertEqual(
            detail["target_closure_generator_kinds"],
            ["composed_typed_sequence_v1", "declaration_sequence_v1",
             "line_reservation_v1"],
        )

    def test_recipe_policy_refuses_an_unretained_destructive_binding(self):
        unit, recipe, function = self._live_anim_case()
        function["destructive_source_bindings"][0]["retained_function"] = (
            TARGET_SYMBOL
        )
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "seed-retained definition"):
            byte_identity.require_target_closure_recipe_policy(
                recipe, function, ROOT, unit["source"], "fixture"
            )

    def test_recipe_policy_refuses_a_clean_identifier_collision(self):
        unit, recipe, function = self._live_anim_case()
        recipe["renderings"][0]["operations"][0]["gen"]["items"][1][
            "id"
        ] = "LegoAnimScene"
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "collides with clean source"):
            byte_identity.require_target_closure_recipe_policy(
                recipe, function, ROOT, unit["source"], "fixture"
            )


class DonorSourceOverlayTests(unittest.TestCase):
    """Spec §4 tests 9-11 — extension A."""

    HEADER = "LEGO1/lego/legoomni/include/legocachesoundmanager.h"

    def _recipe(self, **overrides):
        # The clean pin must be the real one, otherwise the drift guard fires
        # first and the anchor obligation never gets exercised.
        clean = hashlib.sha256((ROOT / self.HEADER).read_bytes()).hexdigest()
        recipe = {
            "kind": "donor_source_overlay",
            "compile_lane": {"required_define": "BYTE_IDENTITY_DONOR_FIXTURE"},
            "renderings": [
                {
                    "path": self.HEADER,
                    "clean_sha256": clean,
                    "rendered_sha256": "1" * 64,
                    "operations": [],
                },
            ],
        }
        recipe.update(overrides)
        return recipe

    def test_09_rejects_op_list_that_perturbs_the_seed_rendering(self):
        """A2: the seed's rendered TU must be bit-identical to today's."""
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "seed"):
            byte_identity.validate_donor_source_overlay_recipe(
                self._recipe(), ROOT, seed_outputs_touched=True)

    def test_10_rejects_anchor_that_does_not_seat_uniquely(self):
        recipe = self._recipe()
        recipe["renderings"][0]["operations"] = [
            {
                "op": "delete",
                "anchor": {"ctx": "0" * 64,
                           "line_before": "0" * 64,
                           "line_after": "0" * 64},
                "length": 1,
            },
        ]
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "anchor|seat"):
            byte_identity.validate_donor_source_overlay_recipe(
                recipe, ROOT, seed_outputs_touched=False)

    def test_11_rejects_donor_object_reaching_the_link(self):
        """A4: the donor object is a byte source only, asserted not assumed."""
        donor = make_divergent_coff(donor=True)
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "donor object"):
            byte_identity.validate_donor_object_excluded(donor, [donor])


class SourcePermutationTests(unittest.TestCase):
    SOURCE = "LEGO1/lego/legoomni/src/common/legocharactermanager.cpp"

    def _generator(self, **extra):
        generator = {
            "k": "bind_once", "type": "int", "id": "saved",
            "expression": "f(x)",
            "use": {
                "kind": "member_assignment_receiver_binding",
                "member_identifier": "field",
                "value_identifier": "rhs",
            },
            "declaration_indent": "\t",
        }
        generator.update(extra)
        return byte_identity.validate_source_overlay_generator(generator, "gen")

    def _live_case(self):
        manifest = json.loads(
            (TOOLS / "byte_identity_manifest.json").read_text()
        )
        unit = next(item for item in manifest["translation_units"]
                    if item["source"] == self.SOURCE)
        function = next(item for item in unit["functions"]
                        if item["mangled"].startswith("?GetActorROI@"))
        donor = next(item for item in unit["donors"]
                     if item["id"] == function["donor"])
        function = copy.deepcopy(function)
        function["target_source_refactor"] = (
            byte_identity.validate_target_source_refactor_proof(
                function["target_source_refactor"], "proof"
            )
        )
        return copy.deepcopy(donor["recipe"]), function

    def test_manifest_fields_render_one_binding_and_one_use(self):
        self.assertEqual(
            byte_identity.render_source_overlay_generator(self._generator()),
            b"\tint saved = f(x);\n\tsaved->field = rhs;\n",
        )
        self.assertEqual(
            byte_identity.render_single_evaluation_binding_input(
                self._generator()["params"]
            ),
            b"\tf(x)->field = rhs;\n",
        )

    def test_permutation_rejects_multiple_statements_and_layout_overrides(self):
        for unsafe in (
            "consume({value})", "sizeof({value})", '"{value}"',
            "prefix_{value}", "condition ? {value} : fallback",
        ):
            with self.subTest(unsafe=unsafe), self.assertRaisesRegex(
                    byte_identity.ByteIdentityError, "use must be an object"):
                self._generator(use=unsafe)
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "unsupported"):
            self._generator(use={"kind": "short_circuit_context"})
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "layout overrides"):
            self._generator(nl=False)
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "single safe expression"):
            self._generator(expression="f(x); return 7")

    def test_generator_is_donor_only(self):
        generator = self._generator()
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "donor-only"):
            byte_identity.assert_source_permutations_are_donor_only(
                {"generator": generator}
            )

    def test_live_recipe_is_source_derived_and_policy_bound(self):
        recipe, function = self._live_case()
        detail = byte_identity.require_target_source_refactor_recipe_policy(
            recipe, function, ROOT, self.SOURCE, "fixture"
        )
        self.assertEqual(detail["refactor_operation_ids"], [
            "op_getactor_actor_info", "op_getactor_strlen_extent",
        ])
        rendered = byte_identity.render_donor_source_overlay(recipe, ROOT)
        self.assertEqual(
            hashlib.sha256(rendered[self.SOURCE]).hexdigest(),
            recipe["renderings"][0]["rendered_sha256"],
        )

    def test_live_policy_refuses_manifest_permutation_drift(self):
        recipe, function = self._live_case()
        operations = recipe["renderings"][0]["operations"]
        target = next(item for item in operations
                      if item.get("id") == "op_getactor_actor_info")
        target["gen"]["use"]["member_identifier"] = "drifted_member"
        with self.assertRaises(byte_identity.ByteIdentityError):
            byte_identity.require_target_source_refactor_recipe_policy(
                recipe, function, ROOT, self.SOURCE, "fixture"
            )

    def test_source_window_pins_both_complete_forms(self):
        recipe, function = self._live_case()
        proof = function["target_source_refactor"]
        donor = byte_identity.render_donor_source_overlay(recipe, ROOT)[
            self.SOURCE
        ]
        # Reconstruct the shipped range only from the two manifest-declared
        # permutations.  Product source text is intentionally absent here and
        # from the framework engine.
        seed = donor
        operation_ids = set(proof["operation_ids"])
        for operation in recipe["renderings"][0]["operations"]:
            if operation.get("id") not in operation_ids:
                continue
            generator = byte_identity.validate_source_overlay_generator(
                operation["gen"], "fixture.generator"
            )
            output = byte_identity.render_source_overlay_generator(generator)
            original = byte_identity.render_single_evaluation_binding_input(
                generator["params"]
            )
            self.assertEqual(seed.count(output), 1)
            seed = seed.replace(output, original, 1)
        detail = byte_identity.require_target_source_refactor_identity(
            seed, donor, proof, "fixture"
        )
        self.assertEqual(detail["seed_target_source_size"], 1230)
        bad = bytearray(donor)
        mutation = bad.index(proof["start_marker"].encode("ascii")) + 80
        bad[mutation] = ord("X") if bad[mutation] != ord("X") else ord("Y")
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "target range"):
            byte_identity.require_target_source_refactor_identity(
                seed, bytes(bad), proof, "fixture"
            )


class MemberSignatureGeneratorTests(unittest.TestCase):
    """Spec A7 — the one authorised signature emitter, and its limits.

    A7e is the point of this class: prove it cannot emit an arbitrary
    function.  A7c is structural — the parameter set has no return type, no
    parameter list and no body, so none can be rendered.
    """

    HEADER = "LEGO1/lego/legoomni/include/legocachesoundmanager.h"

    def _gen(self, **overrides):
        params = {"class_identifier": "LegoCacheSoundEntry",
                  "member_identifier": "LegoCacheSoundEntry",
                  "kind": "destructor",
                  "form": "in_class_declaration"}
        params.update(overrides)
        return {"k": "member_sig", **params}

    def _render(self, **overrides):
        return byte_identity.render_source_overlay_generator(
            byte_identity.validate_source_overlay_generator(
                self._gen(**overrides), "gen"))

    def test_a7f_renders_exactly_the_two_authorised_forms(self):
        # The generator emits exactly the specification's texts and carries
        # no indentation of its own; the framework's default seating adds the
        # LF, and the standard `nl` layout override suppresses it where the
        # seat's own clean source already supplies one.
        self.assertEqual(self._render(form="in_class_declaration"),
                         b"~LegoCacheSoundEntry();\n")
        self.assertEqual(self._render(form="qualified_definition_header"),
                         b"LegoCacheSoundEntry::~LegoCacheSoundEntry()\n")
        self.assertEqual(self._render(form="in_class_declaration", nl=False),
                         b"~LegoCacheSoundEntry();")
        self.assertEqual(
            self._render(form="qualified_definition_header", nl=False),
            b"LegoCacheSoundEntry::~LegoCacheSoundEntry()")

    def test_a7c_emits_signature_text_only_in_both_forms(self):
        for form in ("in_class_declaration", "qualified_definition_header"):
            with self.subTest(form=form):
                rendered = self._render(form=form)
                # no body, no return type, no parameter list
                self.assertNotIn(b"{", rendered)
                self.assertNotIn(b"void", rendered)
                self.assertEqual(rendered.count(b"("), 1)
                self.assertEqual(rendered[rendered.index(b"(") + 1],
                                 ord(")"))
        # only the in-class form terminates; the definition header must not,
        # or the relocated body could never follow it.
        self.assertTrue(self._render(
            form="in_class_declaration").rstrip().endswith(b";"))
        self.assertFalse(self._render(
            form="qualified_definition_header").rstrip().endswith(b";"))

    def test_a7f_rejects_a_form_outside_the_closed_enum(self):
        for form in ("definition", "body", "prototype", "inline", ""):
            with self.subTest(form=form):
                with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                            "form is outside the closed enum"):
                    byte_identity.validate_source_overlay_generator(
                        self._gen(form=form), "gen")

    def test_a7f_rejects_a_missing_form(self):
        generator = self._gen()
        del generator["form"]
        with self.assertRaises(byte_identity.ByteIdentityError):
            byte_identity.validate_source_overlay_generator(generator, "gen")

    def test_a7b_rejects_a_kind_outside_the_closed_enum(self):
        for kind in ("constructor", "method", "operator", "function"):
            with self.subTest(kind=kind):
                with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                            "closed enum"):
                    byte_identity.validate_source_overlay_generator(
                        self._gen(kind=kind), "gen")

    def test_a7c_rejects_any_attempt_to_carry_a_body_or_signature_parts(self):
        for extra in ("body", "return_type", "parameters", "statements"):
            with self.subTest(extra=extra):
                generator = self._gen()
                generator[extra] = "void"
                with self.assertRaises(byte_identity.ByteIdentityError):
                    byte_identity.validate_source_overlay_generator(
                        generator, "gen")

    def test_a7a_rejects_an_identifier_absent_from_checked_in_source(self):
        data = (ROOT / self.HEADER).read_bytes()
        self.assertTrue(byte_identity.source_overlay_member_is_declared(
            data, "LegoCacheSoundEntry", "LegoCacheSoundEntry", "destructor"))
        for klass, member in (
            ("LegoCacheSoundEntry", "NotAMember"),
            ("NoSuchClass", "NoSuchClass"),
            ("LegoCacheSoundManager", "LegoCacheSoundEntry"),
        ):
            with self.subTest(klass=klass, member=member):
                self.assertFalse(
                    byte_identity.source_overlay_member_is_declared(
                        data, klass, member, "destructor"))

    def test_a7a_recipe_refuses_a_signature_with_no_declaration(self):
        clean = hashlib.sha256((ROOT / self.HEADER).read_bytes()).hexdigest()
        recipe = {
            "kind": "donor_source_overlay",
            "compile_lane": {"required_define": "BYTE_IDENTITY_DONOR_FIXTURE"},
            "renderings": [{
                "path": self.HEADER,
                "clean_sha256": clean,
                "rendered_sha256": "1" * 64,
                "operations": [{
                    "op": "append",
                    "gen": self._gen(class_identifier="NoSuchClass",
                                     member_identifier="NoSuchClass"),
                }],
            }],
        }
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "not declared in any checked-in source"):
            byte_identity.validate_donor_source_overlay_recipe(
                recipe, ROOT, seed_outputs_touched=False)

    def test_a7d_refuses_the_generator_in_the_shipped_rendering(self):
        overlay = {"outputs": [{"path": "x.cpp", "operations": [
            {"op": "append", "generator": byte_identity
             .validate_source_overlay_generator(self._gen(), "gen")},
        ]}]}
        with self.assertRaisesRegex(byte_identity.ByteIdentityError, "A7d"):
            byte_identity.assert_member_signature_is_donor_only(overlay)



class B7CountDivergentPath(unittest.TestCase):
    """B7: the donor may carry MORE relocations than the seed."""

    def test_shrinking_donor_table_is_refused(self):
        """A donor with FEWER relocations is refused, not silently padded."""
        seed_rows = [{"target": "?a@@YAXXZ", "offset": 0, "type": 0x14,
                      "addend": 0, "symbol_index": 1, "target_section": 1,
                      "target_type": 0x20, "target_storage": 2,
                      "target_value": 0},
                     {"target": "?b@@YAXXZ", "offset": 8, "type": 0x14,
                      "addend": 0, "symbol_index": 2, "target_section": 1,
                      "target_type": 0x20, "target_storage": 2,
                      "target_value": 0}]
        donor_rows = seed_rows[:1]
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity._pair_reloc_divergent(
                None, None, seed_rows, donor_rows, 1, 1, 2, 2, {}, "primary")
        self.assertIn("FEWER relocations", str(caught.exception))

    def test_appended_compiler_local_target_is_refused(self):
        """An appended $L/$T target has no seed symbol and must refuse."""
        seed_rows = []
        donor_rows = [{"target": "$T4554", "offset": 4, "type": 0x06,
                       "addend": 0, "symbol_index": 7, "target_section": 1,
                       "target_type": 0x00, "target_storage": 3,
                       "target_value": 0}]
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity._pair_reloc_divergent(
                None, None, seed_rows, donor_rows, 1, 1, 2, 2, {}, "primary")
        self.assertIn("no seed symbol", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
