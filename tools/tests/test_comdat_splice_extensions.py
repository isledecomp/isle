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
import tempfile
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


def _patched_target_body(data, replacements):
    coff = byte_identity.CoffObject(data)
    section = coff.function_section(TARGET_SYMBOL)
    output = bytearray(data)
    for start, replacement in replacements:
        at = section["raw_offset"] + start
        output[at:at + len(replacement)] = replacement
    return bytes(output)


class RetailExactInstructionMosaicTests(unittest.TestCase):
    """A retail-exact body assembled from whole compiler instructions."""

    def fixture(
        self, *, donor_range=(0, 3), donor_extra=(24, 27),
        preserve_relocation_operands=False,
    ):
        seed = make_divergent_coff()
        seed_coff = byte_identity.CoffObject(seed)
        section = seed_coff.function_section(TARGET_SYMBOL)
        seed_body = byte_identity.coff_body(seed_coff, section)
        start, end = donor_range
        replacement = bytes(value ^ 0x41 for value in seed_body[start:end])
        if preserve_relocation_operands:
            replacement = bytearray(replacement)
            for row in byte_identity.detailed_relocations(seed_coff, section):
                operand_start = row["offset"]
                operand_end = operand_start + row["width"]
                overlap_start = max(start, operand_start)
                overlap_end = min(end, operand_end)
                if overlap_start < overlap_end:
                    relative = overlap_start - start
                    replacement[relative:relative + overlap_end - overlap_start] = (
                        seed_body[overlap_start:overlap_end]
                    )
            replacement = bytes(replacement)
        extra_start, extra_end = donor_extra
        extra = bytes(value ^ 0x27
                      for value in seed_body[extra_start:extra_end])
        donor = _patched_target_body(
            seed, [(start, replacement), (extra_start, extra)])
        donor_coff = byte_identity.CoffObject(donor)
        donor_section = donor_coff.function_section(TARGET_SYMBOL)
        donor_body = byte_identity.coff_body(donor_coff, donor_section)
        mosaic = bytearray(seed_body)
        mosaic[start:end] = donor_body[start:end]
        mosaic = bytes(mosaic)
        retail = bytearray(mosaic)
        for record in byte_identity.detailed_relocations(seed_coff, section):
            offset, width = record["offset"], record["width"]
            retail[offset:offset + width] = bytes(
                (0xB0 + offset + index) & 0xFF for index in range(width))
        retail = bytes(retail)
        seed_instruction = seed_body[start:end]
        donor_instruction = donor_body[start:end]
        function = {
            "mangled": TARGET_SYMBOL,
            "donor": "d_fixture",
            "splice_class": "retail_exact_instruction_mosaic",
            "expected_section_number": section["number"],
            "expected_section_count": len(seed_coff.sections),
            "expected_body_length": len(seed_body),
            "expected_relocation_count": section["relocation_count"],
            "expected_line_count": section["line_count"],
            "expected_seed_body_sha256": hashlib.sha256(seed_body).hexdigest(),
            "expected_donor_body_sha256": hashlib.sha256(donor_body).hexdigest(),
            "expected_body_sha256": hashlib.sha256(mosaic).hexdigest(),
            "instruction_ranges": [{
                "kind": "same_offset_complete_x86_instruction_v1",
                "start": start,
                "end": end,
                "seed_bytes": seed_instruction.hex(),
                "seed_sha256": hashlib.sha256(seed_instruction).hexdigest(),
                "donor_bytes": donor_instruction.hex(),
                "donor_sha256": hashlib.sha256(donor_instruction).hexdigest(),
            }],
            "retail_oracle": {
                "image": "LEGO1.DLL", "address": "0x1003cf20",
                "verdict": "MATCH", "length": len(seed_body),
            },
            "retail_relocations": relocation_oracle_for(seed, retail),
        }
        return seed, donor, function, retail, mosaic

    def compose(self, seed, donor, function, retail):
        return byte_identity.compose_retail_exact_instruction_mosaic(
            seed, donor, function, retail)

    def test_positive_control_imports_only_the_declared_instruction(self):
        seed, donor, function, retail, mosaic = self.fixture()
        composed, detail = self.compose(seed, donor, function, retail)
        checked = byte_identity.CoffObject(composed)
        section = checked.function_section(TARGET_SYMBOL)
        self.assertEqual(byte_identity.coff_body(checked, section), mosaic)
        self.assertEqual(detail["body_changed_offsets"], [0, 1, 2])
        self.assertTrue(detail["retail_exact"])
        seed_coff = byte_identity.CoffObject(seed)
        seed_body = byte_identity.coff_body(
            seed_coff, seed_coff.function_section(TARGET_SYMBOL))
        self.assertEqual(mosaic[24:27], seed_body[24:27])

    def test_rejects_overlapping_instruction_ranges(self):
        _, _, function, _, _ = self.fixture()
        item = copy.deepcopy(function["instruction_ranges"][0])
        item["start"] = 2
        item["seed_bytes"] = item["seed_bytes"][-2:]
        item["donor_bytes"] = item["donor_bytes"][-2:]
        item["seed_sha256"] = hashlib.sha256(
            bytes.fromhex(item["seed_bytes"])).hexdigest()
        item["donor_sha256"] = hashlib.sha256(
            bytes.fromhex(item["donor_bytes"])).hexdigest()
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "overlapping"):
            byte_identity.validate_instruction_mosaic_ranges(
                [function["instruction_ranges"][0], item], "fixture",
                function["expected_body_length"])

    def test_sequence_range_pins_both_complete_instruction_partitions(self):
        _, _, function, _, _ = self.fixture()
        item = copy.deepcopy(function["instruction_ranges"][0])
        item.update({
            "kind": "same_offset_complete_x86_instruction_sequence_v1",
            "seed_instruction_lengths": [1, 2],
            "donor_instruction_lengths": [2, 1],
        })
        normalized = byte_identity.validate_instruction_mosaic_ranges(
            [item], "fixture", function["expected_body_length"])
        self.assertEqual(normalized[0]["seed_instruction_lengths"], [1, 2])
        self.assertEqual(normalized[0]["donor_instruction_lengths"], [2, 1])

        for bad_lengths in ([0, 3], [16], [1, 1], []):
            with self.subTest(lengths=bad_lengths), self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "instruction_lengths"):
                bad = copy.deepcopy(item)
                bad["donor_instruction_lengths"] = bad_lengths
                byte_identity.validate_instruction_mosaic_ranges(
                    [bad], "fixture", function["expected_body_length"])

    def test_rejects_out_of_bounds_instruction_range(self):
        _, _, function, _, _ = self.fixture()
        item = copy.deepcopy(function["instruction_ranges"][0])
        item.update({"start": 30, "end": 31,
                     "seed_bytes": "00", "donor_bytes": "01",
                     "seed_sha256": hashlib.sha256(b"\0").hexdigest(),
                     "donor_sha256": hashlib.sha256(b"\1").hexdigest()})
        with self.assertRaises(byte_identity.ByteIdentityError):
            byte_identity.validate_instruction_mosaic_ranges(
                [item], "fixture", function["expected_body_length"])

    def test_rejects_instruction_range_overlapping_a_relocation(self):
        seed, donor, function, retail, _ = self.fixture(
            donor_range=(3, 6), donor_extra=(24, 27),
            preserve_relocation_operands=True)
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "partially overlaps a seed relocation"):
            self.compose(seed, donor, function, retail)

    def test_accepts_complete_instruction_with_identical_relocation_operand(self):
        seed, donor, function, retail, mosaic = self.fixture(
            donor_range=(3, 8), donor_extra=(24, 27),
            preserve_relocation_operands=True,
        )
        composed, detail = self.compose(seed, donor, function, retail)
        checked = byte_identity.CoffObject(composed)
        section = checked.function_section(TARGET_SYMBOL)
        self.assertEqual(byte_identity.coff_body(checked, section), mosaic)
        self.assertEqual(detail["body_changed_offsets"], [3])
        self.assertTrue(detail["retail_exact"])

    def test_rejects_complete_instruction_with_changed_relocation_operand(self):
        seed, donor, function, retail, _ = self.fixture(
            donor_range=(3, 8), donor_extra=(24, 27))
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "relocation"):
            self.compose(seed, donor, function, retail)

    def test_rejects_instruction_hash_drift(self):
        seed, donor, function, retail, _ = self.fixture()
        function["instruction_ranges"][0]["donor_sha256"] = "0" * 64
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "encoding/hash"):
            self.compose(seed, donor, function, retail)

    def test_rejects_donor_relocation_semantic_drift(self):
        seed, donor, function, retail, _ = self.fixture()
        parsed = byte_identity.CoffObject(donor)
        section = parsed.function_section(TARGET_SYMBOL)
        replacement_index = next(
            index for index, symbol in parsed.symbols.items()
            if symbol["name"] == SEED_CALLEE
        )
        corrupted = bytearray(donor)
        struct.pack_into("<I", corrupted, section["relocation_offset"] + 4,
                         replacement_index)
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "non-local relocation rename"):
            self.compose(seed, bytes(corrupted), function, retail)

    def test_rejects_donor_xdata_drift(self):
        seed, donor, function, retail, _ = self.fixture()
        parsed = byte_identity.CoffObject(donor)
        primary = parsed.function_section(TARGET_SYMBOL)
        xdata = byte_identity._comdat_child(parsed, primary, ".xdata$x")
        corrupted = bytearray(donor)
        corrupted[xdata["raw_offset"] + 8] ^= 1
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "xdata raw bytes"):
            self.compose(seed, bytes(corrupted), function, retail)

    def test_rejects_a_source_overlay_donor_recipe(self):
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "declaration-only"):
            byte_identity.require_instruction_mosaic_donor_recipe({
                "kind": "donor_source_overlay",
                "emission_policy": "donor_private_rendering_only",
            }, "fixture")

    def test_rejects_a_non_retail_final_mosaic(self):
        seed, donor, function, retail, _ = self.fixture()
        corrupted = bytearray(retail)
        corrupted[8] ^= 1
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "not retail-exact"):
            self.compose(seed, donor, function, bytes(corrupted))

    def test_rejects_any_non_target_output_mutation(self):
        seed, donor, function, retail, _ = self.fixture()
        original = byte_identity.apply_replacements

        def corrupt_non_target(data, replacements):
            output = bytearray(original(data, replacements))
            coff = byte_identity.CoffObject(data)
            output[coff.sections[3]["raw_offset"]] ^= 1
            return bytes(output)

        with mock.patch.object(byte_identity, "apply_replacements",
                               side_effect=corrupt_non_target):
            with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                        "non-target"):
                self.compose(seed, donor, function, retail)

    def test_source_permutation_wrapper_keeps_seed_metadata(self):
        seed, donor, function, retail, mosaic = self.fixture()
        parsed_donor = byte_identity.CoffObject(donor)
        primary = parsed_donor.function_section(TARGET_SYMBOL)
        debug = byte_identity._comdat_child(parsed_donor, primary, ".debug$S")
        donor_with_debug_drift = bytearray(donor)
        donor_with_debug_drift[debug["raw_offset"] + debug["raw_size"] - 1] ^= 1
        donor_with_debug_drift = bytes(donor_with_debug_drift)

        seed_source = (
            b"// SOURCE-PERMUTATION-START\nseed_form();\n"
            b"// SOURCE-PERMUTATION-END\n"
        )
        donor_source = (
            b"// SOURCE-PERMUTATION-START\ndonor_form();\n"
            b"// SOURCE-PERMUTATION-END\n"
        )
        start_marker = "// SOURCE-PERMUTATION-START"
        end_marker = "// SOURCE-PERMUTATION-END"

        def pin(data):
            start = data.index(start_marker.encode("ascii"))
            end = data.index(end_marker.encode("ascii"))
            selected = data[start:end]
            return {
                "baseline_sha256": hashlib.sha256(selected).hexdigest(),
                "baseline_size": len(selected),
                "baseline_line_count": selected.count(b"\n"),
                "baseline_significant_token_sha256":
                    byte_identity.source_overlay_significant_sha256(selected),
            }

        function["target_source_refactor"] = (
            byte_identity.validate_target_source_refactor_proof({
                "kind": "single_evaluation_bindings_v1",
                "start_marker": start_marker,
                "end_marker": end_marker,
                "seed_range_pin": pin(seed_source),
                "donor_range_pin": pin(donor_source),
                "operation_ids": ["op_fixture_binding"],
            }, "fixture.proof")
        )
        function["expected_donor_body_length"] = (
            function["expected_body_length"])
        function["expected_donor_line_count"] = function["expected_line_count"]
        seed_coff = byte_identity.CoffObject(seed)
        seed_primary = seed_coff.function_section(TARGET_SYMBOL)
        drifted_coff = byte_identity.CoffObject(donor_with_debug_drift)
        drifted_primary = drifted_coff.function_section(TARGET_SYMBOL)
        function["expected_seed_metadata_sha256"] = (
            byte_identity.instruction_mosaic_metadata_sha256(
                seed_coff, seed_primary))
        function["expected_donor_metadata_sha256"] = (
            byte_identity.instruction_mosaic_metadata_sha256(
                drifted_coff, drifted_primary))

        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "source-permutation"):
            self.compose(seed, donor_with_debug_drift, function, retail)
        composed, detail = (
            byte_identity.compose_retail_exact_source_instruction_mosaic(
                seed, donor_with_debug_drift, function, retail,
                seed_source, donor_source))
        checked = byte_identity.CoffObject(composed)
        checked_primary = checked.function_section(TARGET_SYMBOL)
        checked_debug = byte_identity._comdat_child(
            checked, checked_primary, ".debug$S")
        seed_debug = byte_identity._comdat_child(
            seed_coff, seed_primary, ".debug$S")
        self.assertEqual(byte_identity.coff_body(checked, checked_primary), mosaic)
        self.assertEqual(
            byte_identity.coff_body(checked, checked_debug),
            byte_identity.coff_body(seed_coff, seed_debug),
        )
        self.assertTrue(detail["retail_exact"])

    def _multi_donor_fixture(self):
        seed, main, function, retail, _ = self.fixture(
            donor_range=(0, 3), donor_extra=(24, 27))
        seed_coff = byte_identity.CoffObject(seed)
        seed_primary = seed_coff.function_section(TARGET_SYMBOL)
        seed_body = byte_identity.coff_body(seed_coff, seed_primary)
        main_coff = byte_identity.CoffObject(main)
        main_primary = main_coff.function_section(TARGET_SYMBOL)
        main_body = byte_identity.coff_body(main_coff, main_primary)

        variant_bytes = bytes(value ^ 0x53 for value in seed_body[24:27])
        variant = _patched_target_body(seed, [(24, variant_bytes)])
        variant_coff = byte_identity.CoffObject(variant)
        variant_primary = variant_coff.function_section(TARGET_SYMBOL)
        variant_body = byte_identity.coff_body(variant_coff, variant_primary)

        mosaic = bytearray(seed_body)
        mosaic[0:3] = main_body[0:3]
        mosaic[24:27] = variant_body[24:27]
        mosaic = bytes(mosaic)
        retail = bytearray(retail)
        retail[24:27] = mosaic[24:27]
        retail = bytes(retail)

        def pin(data):
            start = data.index(b"// SOURCE-PERMUTATION-START")
            end = data.index(b"// SOURCE-PERMUTATION-END")
            selected = data[start:end]
            return {
                "baseline_sha256": hashlib.sha256(selected).hexdigest(),
                "baseline_size": len(selected),
                "baseline_line_count": selected.count(b"\n"),
                "baseline_significant_token_sha256":
                    byte_identity.source_overlay_significant_sha256(selected),
            }

        seed_source = (
            b"// SOURCE-PERMUTATION-START\nseed_form();\n"
            b"// SOURCE-PERMUTATION-END\n"
        )
        donor_source = (
            b"// SOURCE-PERMUTATION-START\ndonor_form();\n"
            b"// SOURCE-PERMUTATION-END\n"
        )
        function.update({
            "donor": "d_aaaaaaaaaaaa",
            "target_source_refactor":
                byte_identity.validate_target_source_refactor_proof({
                    "kind": "single_evaluation_bindings_v1",
                    "start_marker": "// SOURCE-PERMUTATION-START",
                    "end_marker": "// SOURCE-PERMUTATION-END",
                    "seed_range_pin": pin(seed_source),
                    "donor_range_pin": pin(donor_source),
                    "operation_ids": ["op_fixture_binding"],
                }, "fixture.proof"),
            "expected_donor_body_length": len(main_body),
            "expected_donor_line_count": main_primary["line_count"],
            "expected_seed_metadata_sha256":
                byte_identity.instruction_mosaic_metadata_sha256(
                    seed_coff, seed_primary),
            "expected_donor_metadata_sha256":
                byte_identity.instruction_mosaic_metadata_sha256(
                    main_coff, main_primary),
            "donor_variants": [{
                "donor": "d_bbbbbbbbbbbb",
                "expected_body_length": len(variant_body),
                "expected_line_count": variant_primary["line_count"],
                "expected_body_sha256":
                    hashlib.sha256(variant_body).hexdigest(),
                "expected_metadata_sha256":
                    byte_identity.instruction_mosaic_metadata_sha256(
                        variant_coff, variant_primary),
            }],
            "expected_mosaic_donor_body_sha256":
                hashlib.sha256(mosaic).hexdigest(),
            "expected_body_sha256": hashlib.sha256(mosaic).hexdigest(),
            "retail_relocations": relocation_oracle_for(seed, retail),
        })
        function["instruction_ranges"][0]["donor"] = "d_aaaaaaaaaaaa"
        variant_range = {
            "kind": "same_offset_complete_x86_instruction_v1",
            "start": 24, "end": 27,
            "seed_bytes": seed_body[24:27].hex(),
            "seed_sha256": hashlib.sha256(seed_body[24:27]).hexdigest(),
            "donor_bytes": variant_body[24:27].hex(),
            "donor_sha256": hashlib.sha256(variant_body[24:27]).hexdigest(),
            "donor": "d_bbbbbbbbbbbb",
        }
        function["instruction_ranges"].append(variant_range)
        return (seed, main, variant, function, retail, mosaic,
                seed_source, donor_source)

    def test_two_donor_source_mosaic_records_provenance_and_keeps_seed_tables(self):
        (seed, main, variant, function, retail, mosaic,
         seed_source, donor_source) = self._multi_donor_fixture()
        composed, detail = (
            byte_identity.compose_retail_exact_source_instruction_mosaic(
                seed, main, function, retail, seed_source, donor_source,
                {"d_bbbbbbbbbbbb": variant},
            )
        )
        checked = byte_identity.CoffObject(composed)
        seed_coff = byte_identity.CoffObject(seed)
        checked_primary = checked.function_section(TARGET_SYMBOL)
        seed_primary = seed_coff.function_section(TARGET_SYMBOL)
        self.assertEqual(byte_identity.coff_body(checked, checked_primary),
                         mosaic)
        self.assertEqual(
            [item["donor"] for item in detail["instruction_ranges"]],
            ["d_aaaaaaaaaaaa", "d_bbbbbbbbbbbb"],
        )
        self.assertEqual(
            byte_identity._coff_table_bytes(checked, checked_primary, "lines"),
            byte_identity._coff_table_bytes(seed_coff, seed_primary, "lines"),
        )
        self.assertEqual(
            byte_identity.detailed_relocations(checked, checked_primary),
            byte_identity.detailed_relocations(seed_coff, seed_primary),
        )
        for child_name in (".debug$S", ".xdata$x"):
            left = byte_identity._comdat_child(
                checked, checked_primary, child_name)
            right = byte_identity._comdat_child(
                seed_coff, seed_primary, child_name)
            self.assertEqual(byte_identity.coff_body(checked, left),
                             byte_identity.coff_body(seed_coff, right))

    def test_multi_donor_mapping_is_closed_and_every_variant_is_used(self):
        (_, _, _, function, _, _, _, _) = self._multi_donor_fixture()
        ranges = byte_identity.validate_instruction_mosaic_ranges(
            function["instruction_ranges"], "fixture",
            function["expected_body_length"])
        byte_identity.require_instruction_mosaic_range_donor_bindings(
            ranges, "d_aaaaaaaaaaaa", {"d_bbbbbbbbbbbb"}, "fixture")
        cases = []
        missing = copy.deepcopy(ranges)
        del missing[1]["donor"]
        cases.append(missing)
        undeclared = copy.deepcopy(ranges)
        undeclared[1]["donor"] = "d_cccccccccccc"
        cases.append(undeclared)
        unused = copy.deepcopy(ranges[:1])
        cases.append(unused)
        for bad in cases:
            with self.subTest(ranges=bad), self.assertRaisesRegex(
                    byte_identity.ByteIdentityError, "donor variant"):
                byte_identity.require_instruction_mosaic_range_donor_bindings(
                    bad, "d_aaaaaaaaaaaa", {"d_bbbbbbbbbbbb"}, "fixture")
        single = copy.deepcopy(ranges[:1])
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "single-donor"):
            byte_identity.require_instruction_mosaic_range_donor_bindings(
                single, "d_aaaaaaaaaaaa", set(), "fixture")

    def test_multi_donor_objects_and_pins_are_fail_closed(self):
        (seed, main, variant, function, retail, _,
         seed_source, donor_source) = self._multi_donor_fixture()
        compose = byte_identity.compose_retail_exact_source_instruction_mosaic
        for mapping in ({}, {
                "d_bbbbbbbbbbbb": variant,
                "d_cccccccccccc": variant,
        }):
            with self.subTest(mapping=mapping), self.assertRaisesRegex(
                    byte_identity.ByteIdentityError, "donor set"):
                compose(seed, main, function, retail, seed_source,
                        donor_source, mapping)
        drifted = copy.deepcopy(function)
        drifted["donor_variants"][0]["expected_body_sha256"] = "0" * 64
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "body differs from its pin"):
            compose(seed, main, drifted, retail, seed_source, donor_source,
                    {"d_bbbbbbbbbbbb": variant})
        topology = bytearray(variant)
        parsed = byte_identity.CoffObject(variant)
        primary = parsed.function_section(TARGET_SYMBOL)
        struct.pack_into("<I", topology, primary["header_offset"] + 36,
                         primary["characteristics"] ^ 0x20)
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "header changed"):
            compose(seed, main, function, retail, seed_source, donor_source,
                    {"d_bbbbbbbbbbbb": bytes(topology)})

    def test_source_owner_mangled_must_exist_in_both_objects(self):
        seed, donor, function, retail, _ = self.fixture()
        function["target_source_refactor"] = {
            "source_owner_mangled": "?MissingOwner@@YAXXZ",
        }
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "expected one definition"):
            byte_identity.compose_retail_exact_source_instruction_mosaic(
                seed, donor, function, retail, b"seed", b"donor")


class CrossTuInstructionHybridResizeTests(unittest.TestCase):
    """A different-TU same-COMDAT instruction feeds an ordinary resize."""

    def fixture(self):
        seed = make_divergent_coff()
        target_donor = make_divergent_coff(donor=True)
        target_coff = byte_identity.CoffObject(target_donor)
        target_primary = target_coff.function_section(TARGET_SYMBOL)
        target_body = byte_identity.coff_body(target_coff, target_primary)

        instruction_donor = make_divergent_coff()
        instruction_coff = byte_identity.CoffObject(instruction_donor)
        instruction_primary = instruction_coff.function_section(TARGET_SYMBOL)
        instruction_body = byte_identity.coff_body(
            instruction_coff, instruction_primary)
        target_start, target_end = 0, 3
        source_start, source_end = 24, 27
        imported = bytes(value ^ 0x5A
                         for value in target_body[target_start:target_end])
        instruction_donor = _patched_target_body(
            instruction_donor, [(source_start, imported)])
        instruction_coff = byte_identity.CoffObject(instruction_donor)
        instruction_primary = instruction_coff.function_section(TARGET_SYMBOL)
        instruction_body = byte_identity.coff_body(
            instruction_coff, instruction_primary)

        hybrid = _patched_target_body(
            target_donor, [(target_start, imported)])
        hybrid_coff = byte_identity.CoffObject(hybrid)
        hybrid_primary = hybrid_coff.function_section(TARGET_SYMBOL)
        hybrid_body = byte_identity.coff_body(hybrid_coff, hybrid_primary)
        retail = retail_body_for(hybrid)

        target_instruction = target_body[target_start:target_end]
        source_instruction = instruction_body[source_start:source_end]
        function = {
            "mangled": TARGET_SYMBOL,
            "donor": "d_aaaaaaaaaaaa",
            "instruction_donor": "d_bbbbbbbbbbbb",
            "splice_class":
                "retail_exact_cross_tu_instruction_hybrid_resize",
            "expected_seed_length": SEED_SIZE,
            "expected_donor_length": DONOR_SIZE,
            "expected_linked_span": LINKED_SPAN,
            "expected_target_donor_section_number":
                target_primary["number"],
            "expected_target_donor_section_count": len(target_coff.sections),
            "expected_target_donor_relocation_count":
                target_primary["relocation_count"],
            "expected_target_donor_line_count": target_primary["line_count"],
            "expected_target_donor_body_sha256":
                hashlib.sha256(target_body).hexdigest(),
            "expected_instruction_donor_length": len(instruction_body),
            "expected_instruction_donor_section_number":
                instruction_primary["number"],
            "expected_instruction_donor_section_count":
                len(instruction_coff.sections),
            "expected_instruction_donor_relocation_count":
                instruction_primary["relocation_count"],
            "expected_instruction_donor_line_count":
                instruction_primary["line_count"],
            "expected_instruction_donor_body_sha256":
                hashlib.sha256(instruction_body).hexdigest(),
            "expected_hybrid_body_sha256":
                hashlib.sha256(hybrid_body).hexdigest(),
            "instruction_ranges": [{
                "kind":
                    "cross_tu_same_mangled_complete_x86_instruction_v1",
                "target_start": target_start,
                "target_end": target_end,
                "target_bytes": target_instruction.hex(),
                "target_sha256":
                    hashlib.sha256(target_instruction).hexdigest(),
                "instruction_donor_start": source_start,
                "instruction_donor_end": source_end,
                "instruction_donor_bytes": source_instruction.hex(),
                "instruction_donor_sha256":
                    hashlib.sha256(source_instruction).hexdigest(),
            }],
            "retail_oracle": {
                "image": "LEGO1.DLL", "address": "0x1003cf20",
                "verdict": "MATCH", "length": len(hybrid_body),
            },
            "retail_relocations": relocation_oracle_for(hybrid, retail),
        }
        return (seed, target_donor, instruction_donor, function, retail,
                hybrid)

    def compose(self, seed, target_donor, instruction_donor, function,
                retail):
        return byte_identity.compose_retail_exact_cross_tu_instruction_hybrid_resize(
            seed, target_donor, instruction_donor, function, retail)

    def test_positive_control_uses_only_the_cross_tu_instruction(self):
        (seed, target_donor, instruction_donor, function, retail,
         hybrid) = self.fixture()
        composed, detail = self.compose(
            seed, target_donor, instruction_donor, function, retail)
        checked = byte_identity.CoffObject(composed)
        primary = checked.function_section(TARGET_SYMBOL)
        hybrid_coff = byte_identity.CoffObject(hybrid)
        hybrid_primary = hybrid_coff.function_section(TARGET_SYMBOL)
        self.assertEqual(byte_identity.coff_body(checked, primary),
                         byte_identity.coff_body(hybrid_coff, hybrid_primary))
        self.assertEqual(
            detail["splice_class"],
            "retail_exact_cross_tu_instruction_hybrid_resize")
        self.assertEqual(detail["instruction_ranges"][0]["target_start"], 0)
        self.assertTrue(detail["retail_exact"])

    def test_output_keeps_target_donor_metadata_and_seed_non_targets(self):
        (seed, target_donor, instruction_donor, function, retail,
         _) = self.fixture()
        composed, _ = self.compose(
            seed, target_donor, instruction_donor, function, retail)
        seed_coff = byte_identity.CoffObject(seed)
        donor_coff = byte_identity.CoffObject(target_donor)
        checked = byte_identity.CoffObject(composed)
        seed_primary = seed_coff.function_section(TARGET_SYMBOL)
        donor_primary = donor_coff.function_section(TARGET_SYMBOL)
        checked_primary = checked.function_section(TARGET_SYMBOL)
        def relocation_shape(coff, primary):
            return [
                (row["offset"], row["type"],
                 byte_identity.local_symbol_kind(row["target"])
                 or row["target"])
                for row in byte_identity.detailed_relocations(coff, primary)
            ]
        self.assertEqual(
            relocation_shape(checked, checked_primary),
            relocation_shape(donor_coff, donor_primary),
        )
        self.assertEqual(
            byte_identity._coff_table_bytes(checked, checked_primary, "lines"),
            byte_identity._coff_table_bytes(donor_coff, donor_primary, "lines"),
        )
        for before in seed_coff.sections:
            if before["number"] in {1, 2, 3}:
                continue
            after = checked.sections[before["number"] - 1]
            self.assertEqual(byte_identity.coff_body(seed_coff, before),
                             byte_identity.coff_body(checked, after))

    def test_rejects_instruction_donor_with_a_different_mangled_comdat(self):
        (seed, target_donor, instruction_donor, function, retail,
         _) = self.fixture()
        renamed = instruction_donor.replace(
            TARGET_SYMBOL.encode("ascii"),
            TARGET_SYMBOL.replace("Target", "Borrow").encode("ascii"),
        )
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "definition"):
            self.compose(seed, target_donor, renamed, function, retail)

    def test_rejects_cross_tu_body_or_instruction_pin_drift(self):
        (seed, target_donor, instruction_donor, function, retail,
         _) = self.fixture()
        for key in ("expected_instruction_donor_body_sha256",):
            with self.subTest(key=key):
                bad = copy.deepcopy(function)
                bad[key] = "0" * 64
                with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                            "body"):
                    self.compose(seed, target_donor, instruction_donor,
                                 bad, retail)
        bad = copy.deepcopy(function)
        bad["instruction_ranges"][0]["instruction_donor_sha256"] = "0" * 64
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "encoding/hash"):
            self.compose(seed, target_donor, instruction_donor, bad, retail)

    def test_rejects_a_range_overlapping_either_relocation_table(self):
        (seed, target_donor, instruction_donor, function, retail,
         _) = self.fixture()
        bad = copy.deepcopy(function)
        target_coff = byte_identity.CoffObject(target_donor)
        target_primary = target_coff.function_section(TARGET_SYMBOL)
        target_body = byte_identity.coff_body(target_coff, target_primary)
        instruction_coff = byte_identity.CoffObject(instruction_donor)
        instruction_primary = instruction_coff.function_section(TARGET_SYMBOL)
        instruction_body = byte_identity.coff_body(
            instruction_coff, instruction_primary)
        item = bad["instruction_ranges"][0]
        item.update({
            "target_start": 3, "target_end": 7,
            "target_bytes": target_body[3:7].hex(),
            "target_sha256": hashlib.sha256(target_body[3:7]).hexdigest(),
            "instruction_donor_start": 20,
            "instruction_donor_end": 24,
            "instruction_donor_bytes": instruction_body[20:24].hex(),
            "instruction_donor_sha256":
                hashlib.sha256(instruction_body[20:24]).hexdigest(),
        })
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "relocation"):
            self.compose(seed, target_donor, instruction_donor, bad, retail)

    def test_rejects_a_hybrid_that_is_not_retail_exact(self):
        (seed, target_donor, instruction_donor, function, retail,
         _) = self.fixture()
        wrong = bytearray(retail)
        wrong[8] ^= 1
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "retail-exact"):
            self.compose(seed, target_donor, instruction_donor, function,
                         bytes(wrong))

    def test_live_manifest_cross_tu_recipe_is_clean_and_source_pinned(self):
        manifest = json.loads(
            (TOOLS / "byte_identity_manifest.json").read_text())
        matches = [
            (unit, function)
            for unit in manifest["translation_units"]
            for function in unit.get("functions", [])
            if function.get("splice_class")
            == byte_identity.CROSS_TU_INSTRUCTION_HYBRID_RESIZE_CLASS
        ]
        self.assertEqual(len(matches), 1)
        unit, function = matches[0]
        donor = next(
            item for item in unit["donors"]
            if item["id"] == function["instruction_donor"])
        overlaid = {
            item["path"] for item in manifest["source_overlay"]["outputs"]
        }
        normalized = (
            byte_identity.validate_clean_current_source_cross_tu_recipe(
                donor["recipe"], ROOT, unit["source"], overlaid, "fixture")
        )
        self.assertNotEqual(normalized["donor_source"], unit["source"])
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "effective source overlay"):
            byte_identity.validate_clean_current_source_cross_tu_recipe(
                donor["recipe"], ROOT, unit["source"],
                overlaid | {normalized["donor_source"]}, "fixture")

    def test_clean_cross_tu_role_binding_accepts_one_instruction_use(self):
        byte_identity.require_clean_current_source_cross_tu_bindings(
            {
                "d_target": "forward_declaration_run",
                "d_clean":
                    byte_identity.CLEAN_CURRENT_SOURCE_CROSS_TU_RECIPE,
            },
            ["d_target"], ["d_clean"], "fixture",
        )

    def test_clean_cross_tu_role_binding_rejects_an_unbound_recipe(self):
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "consumed exactly once"):
            byte_identity.require_clean_current_source_cross_tu_bindings(
                {"d_clean":
                    byte_identity.CLEAN_CURRENT_SOURCE_CROSS_TU_RECIPE},
                [], [], "fixture",
            )

    def test_clean_cross_tu_role_binding_rejects_primary_use(self):
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "not primary donors"):
            byte_identity.require_clean_current_source_cross_tu_bindings(
                {"d_clean":
                    byte_identity.CLEAN_CURRENT_SOURCE_CROSS_TU_RECIPE},
                ["d_clean"], ["d_clean"], "fixture",
            )

    def test_clean_cross_tu_role_binding_rejects_multiple_uses(self):
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "consumed exactly once"):
            byte_identity.require_clean_current_source_cross_tu_bindings(
                {"d_clean":
                    byte_identity.CLEAN_CURRENT_SOURCE_CROSS_TU_RECIPE},
                [], ["d_clean", "d_clean"], "fixture",
            )

    def test_clean_cross_tu_recipe_rejects_a_final_component_symlink(self):
        payload = b"int donor_source_fixture;\n"
        recipe = {
            "kind": byte_identity.CLEAN_CURRENT_SOURCE_CROSS_TU_RECIPE,
            "donor_source": "donor.cpp",
            "source_sha256": hashlib.sha256(payload).hexdigest(),
            "compile_lane": {"required_define": "FIXTURE_DEFINE"},
            "emission_policy":
                "unmodified_checked_in_translation_unit_only",
            "authenticity_rationale":
                "Fixture checked-in source provenance declaration only.",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            real = root / "real.cpp"
            real.write_bytes(payload)
            (root / "donor.cpp").symlink_to(real.name)
            with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                        "redirected or non-regular"):
                byte_identity.validate_clean_current_source_cross_tu_recipe(
                    recipe, root, "owner.cpp", set(), "fixture")

    def test_retail_oracle_image_is_bound_to_the_tu_target(self):
        images = {
            "PRIMARY": {
                "target": "primary", "original": "bin/PRIMARY.DLL",
            },
            "OTHER": {
                "target": "other", "original": "bin/OTHER.EXE",
            },
        }
        self.assertEqual(
            byte_identity.require_target_bound_retail_image(
                images, "primary", "PRIMARY.DLL", "fixture"),
            "PRIMARY.DLL",
        )
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "differs from the TU target"):
            byte_identity.require_target_bound_retail_image(
                images, "primary", "OTHER.EXE", "fixture")

    def test_range_schema_refuses_width_and_order_escape_hatches(self):
        (_, _, _, function, _, _) = self.fixture()
        item = function["instruction_ranges"][0]
        for mutate in (
            lambda value: value.update({"instruction_donor_end":
                                        value["instruction_donor_end"] + 1}),
            lambda value: value.update({"unexpected": True}),
        ):
            bad = copy.deepcopy(item)
            mutate(bad)
            with self.assertRaises(byte_identity.ByteIdentityError):
                byte_identity.validate_cross_tu_instruction_hybrid_ranges(
                    [bad], "fixture", function["expected_donor_length"],
                    function["expected_instruction_donor_length"])


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

    def _live_for_initializer_case(self):
        source = "LEGO1/lego/legoomni/src/paths/legopathboundary.cpp"
        manifest = json.loads(
            (TOOLS / "byte_identity_manifest.json").read_text()
        )
        unit = next(item for item in manifest["translation_units"]
                    if item["source"] == source)
        function = next(item for item in unit["functions"]
                        if item["mangled"].startswith("?RemovePresenter@"))
        donor = next(item for item in unit["donors"]
                     if item["id"] == function["donor"])
        function = copy.deepcopy(function)
        function["target_source_refactor"] = (
            byte_identity.validate_target_source_refactor_proof(
                function["target_source_refactor"], "proof"
            )
        )
        return source, copy.deepcopy(donor["recipe"]), function

    def _live_captured_tail_case(self):
        source = "LEGO1/omni/src/stream/mxdsbuffer.cpp"
        manifest = json.loads(
            (TOOLS / "byte_identity_manifest.json").read_text()
        )
        unit = next(item for item in manifest["translation_units"]
                    if item["source"] == source)
        function = next(item for item in unit["functions"]
                        if item["mangled"].startswith("?FUN_100c6fa0@"))
        donor = next(item for item in unit["donors"]
                     if item["id"] == function["donor"])
        function = copy.deepcopy(function)
        function["target_source_refactor"] = (
            byte_identity.validate_target_source_refactor_proof(
                function["target_source_refactor"], "proof"
            )
        )
        return source, copy.deepcopy(donor["recipe"]), function

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

    def test_equal_body_composer_has_no_source_proof_bypass(self):
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "unsupported"):
            byte_identity.compose_equal_body_comdat(
                b"", b"", {"target_source_refactor": {}})

    def test_for_initializer_reseat_is_closed_and_source_derived(self):
        generator = byte_identity.validate_source_overlay_generator({
            "k": "for_init_decl",
            "form": "standalone_then_assignment_v1",
            "type": "LegoAnimPresenterSet::iterator",
            "id": "it",
            "container": "m_presenters",
            "begin": "begin",
            "end": "end",
            "declaration_indent": "\t\t",
        }, "fixture.generator")
        self.assertEqual(
            byte_identity.render_for_initializer_declaration_reseat_input(
                generator["params"]),
            b"\t\tfor (LegoAnimPresenterSet::iterator it = "
            b"m_presenters.begin(); it != m_presenters.end(); it++) {\n",
        )
        self.assertEqual(
            byte_identity.render_source_overlay_generator(generator),
            b"\t\tLegoAnimPresenterSet::iterator it;\n\n"
            b"\t\tfor (it = m_presenters.begin(); it != "
            b"m_presenters.end(); it++) {\n",
        )
        inverse = byte_identity.validate_source_overlay_generator({
            "k": "for_init_decl",
            "form": "declaration_in_initializer_v1",
            "type": "LegoAnimPresenterSet::iterator",
            "id": "it",
            "container": "m_presenters",
            "begin": "begin",
            "end": "end",
            "declaration_indent": "\t\t",
        }, "fixture.inverse_generator")
        self.assertEqual(
            byte_identity.render_for_initializer_declaration_reseat_input(
                inverse["params"]),
            b"\t\tLegoAnimPresenterSet::iterator it;\n\n"
            b"\t\tfor (it = m_presenters.begin(); it != "
            b"m_presenters.end(); it++) {\n",
        )
        self.assertEqual(
            byte_identity.render_source_overlay_generator(inverse),
            b"\t\tfor (LegoAnimPresenterSet::iterator it = "
            b"m_presenters.begin(); it != m_presenters.end(); it++) {\n",
        )
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "layout overrides"):
            byte_identity.validate_source_overlay_generator({
                "k": "for_init_decl",
                "form": "standalone_then_assignment_v1",
                "type": "LegoAnimPresenterSet::iterator",
                "id": "it", "container": "m_presenters",
                "begin": "begin", "end": "end",
                "declaration_indent": "\t\t", "nl": False,
            }, "fixture.generator")

    def test_live_for_initializer_recipe_is_confined_to_its_owner(self):
        source, recipe, function = self._live_for_initializer_case()
        detail = byte_identity.require_target_source_refactor_recipe_policy(
            recipe, function, ROOT, source, "fixture"
        )
        self.assertEqual(
            detail["refactor_operation_ids"],
            ["op_remove_for_init_declaration"],
        )
        rendered = byte_identity.render_donor_source_overlay(recipe, ROOT)[
            source]
        proof_detail = byte_identity.require_target_source_refactor_identity(
            (ROOT / source).read_bytes(), rendered,
            function["target_source_refactor"], "fixture",
        )
        self.assertEqual(proof_detail["seed_target_source_size"], 769)
        self.assertEqual(proof_detail["donor_target_source_size"], 762)

        escaped = copy.deepcopy(recipe)
        operation = next(
            item for item in escaped["renderings"][0]["operations"]
            if item.get("id") == "op_remove_for_init_declaration"
        )
        operation["gen"]["id"] = "m_presenters"
        with self.assertRaises(byte_identity.ByteIdentityError):
            byte_identity.require_target_source_refactor_recipe_policy(
                escaped, function, ROOT, source, "fixture"
            )

    def test_live_captured_tail_recipe_is_exact_and_owner_confined(self):
        source, recipe, function = self._live_captured_tail_case()
        detail = byte_identity.require_target_source_refactor_recipe_policy(
            recipe, function, ROOT, source, "fixture"
        )
        self.assertEqual(detail["refactor_operation_ids"], [
            "op_mxds_capture_assignment",
            "op_mxds_capture_declaration",
            "op_mxds_capture_goto",
            "op_mxds_capture_read",
            "op_mxds_capture_tail",
        ])
        self.assertEqual(detail["refactor_local_identifiers"],
                         ["found", "found_current"])
        rendered = byte_identity.render_donor_source_overlay(
            recipe, ROOT)[source]
        self.assertEqual(hashlib.sha256(rendered).hexdigest(),
                         recipe["renderings"][0]["rendered_sha256"])
        proof_detail = byte_identity.require_target_source_refactor_identity(
            (ROOT / source).read_bytes(), rendered,
            function["target_source_refactor"], "fixture",
        )
        self.assertEqual(proof_detail["seed_target_source_size"], 823)
        self.assertEqual(proof_detail["donor_target_source_size"], 890)
        self.assertEqual(
            byte_identity.validate_retail_relocation_oracle(
                [], "fixture.oracle", function["expected_body_length"],
                allow_empty=True,
            ),
            [],
        )

    def test_captured_tail_contract_refuses_open_text_and_wrong_layout(self):
        base = {
            "k": "capture_tail", "role": "read_reseat",
            "capture": "found", "source": "current", "nl": False,
        }
        generator = byte_identity.validate_source_overlay_generator(
            base, "fixture.generator")
        self.assertEqual(
            byte_identity.render_captured_pointer_tail_return_input(
                generator["params"]),
            b"current",
        )
        self.assertEqual(
            byte_identity.render_source_overlay_generator(generator),
            b"found",
        )
        for mutation in (
            {key: value for key, value in base.items() if key != "nl"},
            {**base, "text": "arbitrary source"},
        ):
            with self.subTest(mutation=mutation), self.assertRaises(
                    byte_identity.ByteIdentityError):
                byte_identity.validate_source_overlay_generator(
                    mutation, "fixture.generator")

    def test_captured_tail_policy_refuses_missing_role_and_identity_drift(self):
        source, recipe, function = self._live_captured_tail_case()
        missing = copy.deepcopy(recipe)
        missing["renderings"][0]["operations"] = [
            item for item in missing["renderings"][0]["operations"]
            if item.get("id") != "op_mxds_capture_tail"
        ]
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "role set is incomplete"):
            byte_identity.require_target_source_refactor_recipe_policy(
                missing, function, ROOT, source, "fixture"
            )
        divergent = copy.deepcopy(recipe)
        operation = next(
            item for item in divergent["renderings"][0]["operations"]
            if item.get("id") == "op_mxds_capture_tail"
        )
        operation["gen"]["label"] = "different_tail"
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "identities diverge"):
            byte_identity.require_target_source_refactor_recipe_policy(
                divergent, function, ROOT, source, "fixture"
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


class SourceTargetClosureTests(unittest.TestCase):
    SOURCE = "LEGO1/realtime/orientableroi.cpp"

    def live_recipe(self):
        manifest = json.loads(
            (TOOLS / "byte_identity_manifest.json").read_text())
        unit = next(item for item in manifest["translation_units"]
                    if item["source"] == self.SOURCE)
        function = next(item for item in unit["functions"]
                        if item["splice_class"]
                        == "retail_exact_source_target_closure")
        donor = next(item for item in unit["donors"]
                     if item["id"] == function["donor"])
        return copy.deepcopy(donor["recipe"])

    def fixture(self, *, import_missing=False):
        seed = make_divergent_coff(
            declare_retail_callee=not import_missing
        )
        donor = make_divergent_coff(
            donor=True, other_symbol="?DonorOnly@@YAXXZ")
        left, right = byte_identity.CoffObject(seed), byte_identity.CoffObject(donor)
        sp, dp = left.function_section(TARGET_SYMBOL), right.function_section(TARGET_SYMBOL)
        sx, dx = (byte_identity._comdat_child(coff, primary, ".xdata$x")
                  for coff, primary in ((left, sp), (right, dp)))
        sd, dd = (byte_identity._comdat_child(coff, primary, ".debug$S")
                  for coff, primary in ((left, sp), (right, dp)))
        source = b"prefix\n// START_TARGET\nint x;\n// END_TARGET\nsuffix\n"
        selected = source[source.index(b"// START_TARGET"):
                          source.index(b"// END_TARGET")]
        function = function_record(donor, **{
            "splice_class": "retail_exact_source_target_closure",
            "expected_seed_section_count": len(left.sections),
            "expected_donor_section_count": len(right.sections),
            "expected_section_number": sp["number"],
            "expected_xdata_section_number": sx["number"],
            "expected_debug_section_number": sd["number"],
            "expected_seed_body_sha256": hashlib.sha256(
                byte_identity.coff_body(left, sp)).hexdigest(),
            "expected_seed_xdata_sha256": hashlib.sha256(
                byte_identity.coff_body(left, sx)).hexdigest(),
            "expected_donor_xdata_sha256": hashlib.sha256(
                byte_identity.coff_body(right, dx)).hexdigest(),
            "expected_seed_debug_sha256": hashlib.sha256(
                byte_identity.coff_body(left, sd)).hexdigest(),
            "expected_donor_debug_sha256": hashlib.sha256(
                byte_identity.coff_body(right, dd)).hexdigest(),
            "expected_relocation_count": sp["relocation_count"],
            "expected_line_count": sp["line_count"],
            "expected_imported_undefined_symbols": (
                [RETAIL_CALLEE] if import_missing else []
            ),
            "target_source_range": {
                "start_marker": "// START_TARGET",
                "end_marker": "// END_TARGET",
                "range_pin": {
                    "baseline_sha256": hashlib.sha256(selected).hexdigest(),
                    "baseline_size": len(selected),
                    "baseline_line_count": selected.count(b"\n"),
                    "baseline_significant_token_sha256":
                        byte_identity.source_overlay_significant_sha256(selected),
                },
            },
        })
        return seed, donor, function, source

    def test_closed_generators_and_live_recipe(self):
        dead = byte_identity.validate_source_overlay_generator({
            "k": "dead_updates", "id": "state", "initial": 0,
            "increment": 1, "repeat": 2, "nl": False,
        }, "dead")
        ctor = byte_identity.validate_source_overlay_generator({
            "k": "default_ctor_dead_updates", "class": "Box", "id": "seat",
            "initial": 0, "increment": 1, "repeat": 1,
        }, "ctor")
        self.assertEqual(byte_identity.render_source_overlay_generator(dead),
                         b"{ int state = 0; state = state + 1; state = state + 1; }")
        self.assertEqual(byte_identity.render_source_overlay_generator(ctor),
                         b"\tBox() { int seat = 0; seat = seat + 1; }\n")
        recipe = self.live_recipe()
        detail = byte_identity.require_source_target_closure_recipe_policy(
            recipe, ROOT, self.SOURCE, "fixture")
        self.assertEqual(detail["source_permutation_count"], 2)
        rendered = byte_identity.render_donor_source_overlay(recipe, ROOT)
        for item in recipe["renderings"]:
            self.assertEqual(hashlib.sha256(rendered[item["path"]]).hexdigest(),
                             item["rendered_sha256"])

    def test_policy_rejects_arbitrary_or_overflowing_text(self):
        for generator in (
            {"k": "dead_updates", "id": "x", "initial": 0,
             "increment": 1, "repeat": 1, "body": "return 7"},
            {"k": "dead_updates", "id": "x", "initial": (1 << 31) - 1,
             "increment": 1, "repeat": 1},
        ):
            with self.subTest(generator=generator), self.assertRaises(
                    byte_identity.ByteIdentityError):
                byte_identity.validate_source_overlay_generator(generator, "bad")

    def test_target_only_composition_keeps_seed_functions_and_non_targets(self):
        seed, donor, function, source = self.fixture()
        composed, detail = byte_identity.compose_retail_exact_source_target_closure(
            seed, donor, function, retail_body_for(donor), source, source)
        before, after = byte_identity.CoffObject(seed), byte_identity.CoffObject(composed)
        target = after.function_section(TARGET_SYMBOL)
        donor_coff = byte_identity.CoffObject(donor)
        self.assertEqual(byte_identity.coff_body(after, target),
                         byte_identity.coff_body(
                             donor_coff, donor_coff.function_section(TARGET_SYMBOL)))
        self.assertEqual(byte_identity.function_multiset(after),
                         byte_identity.function_multiset(before))
        self.assertEqual(byte_identity.coff_body(after, after.sections[3]),
                         byte_identity.coff_body(before, before.sections[3]))
        self.assertEqual(detail["donor_only_function_count"], 1)
        byte_identity.validate_donor_object_excluded(composed, [donor])

    def test_missing_external_is_appended_as_one_strict_undefined_symbol(self):
        seed, donor, function, source = self.fixture(import_missing=True)
        before = byte_identity.CoffObject(seed)
        composed, detail = (
            byte_identity.compose_retail_exact_source_target_closure(
                seed, donor, function, retail_body_for(donor), source, source
            )
        )
        after = byte_identity.CoffObject(composed)
        self.assertEqual(after.symbol_count, before.symbol_count + 1)
        imported = after.symbols[before.symbol_count]
        self.assertEqual(
            (imported["name"], imported["section"], imported["value"],
             imported["type"], imported["storage"]),
            (RETAIL_CALLEE, 0, 0, 0x20, 2),
        )
        self.assertEqual(detail["imported_undefined_symbols"], [RETAIL_CALLEE])
        self.assertEqual(
            [before.symbols[index]["name"] for index in before.symbols],
            [after.symbols[index]["name"] for index in before.symbols],
        )

    def test_missing_external_with_nonzero_value_is_refused(self):
        seed, donor, function, source = self.fixture(import_missing=True)
        parsed = byte_identity.CoffObject(donor)
        symbol_index = next(
            index for index, symbol in parsed.symbols.items()
            if symbol["name"] == RETAIL_CALLEE
        )
        corrupted = bytearray(donor)
        struct.pack_into(
            "<I", corrupted, parsed.symbol_offset + symbol_index * 18 + 8, 1
        )
        oracle = next(
            item for item in function["retail_relocations"]
            if item["target"] == RETAIL_CALLEE
        )
        oracle["target_value"] = 1
        with self.assertRaisesRegex(
                byte_identity.ByteIdentityError, "absent from the seed"):
            byte_identity.compose_retail_exact_source_target_closure(
                seed, bytes(corrupted), function, retail_body_for(donor),
                source, source,
            )

    def test_source_target_policy_requires_private_source_projection(self):
        recipe = self.live_recipe()
        recipe["compile_lane"].pop("include_projection")
        with self.assertRaisesRegex(
                byte_identity.ByteIdentityError, "source-root projection"):
            byte_identity.require_source_target_closure_recipe_policy(
                recipe, ROOT, self.SOURCE, "fixture"
            )

    def test_target_only_composition_rejects_closure_or_source_drift(self):
        seed, donor, function, source = self.fixture()
        bad = copy.deepcopy(function)
        bad["expected_donor_debug_sha256"] = "0" * 64
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "debug"):
            byte_identity.compose_retail_exact_source_target_closure(
                seed, donor, bad, retail_body_for(donor), source, source)
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "target source range"):
            byte_identity.compose_retail_exact_source_target_closure(
                seed, donor, function, retail_body_for(donor), source,
                source.replace(b"int x", b"int y"))


if __name__ == "__main__":
    unittest.main()
