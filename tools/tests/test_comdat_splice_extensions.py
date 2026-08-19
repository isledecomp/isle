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
    debug_tail_extra=0,
    debug_label_relocations=False,
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
    debug_s = bytearray(40 + debug_tail_extra)
    struct.pack_into("<H", debug_s, 2, 0x0205)
    struct.pack_into("<III", debug_s, 16, size, 2 if donor else 1,
                     size - 2)

    # symbol indices, counting auxiliary records
    target_index = 4
    common_index = 10
    seed_callee_index = 11
    retail_callee_index = 12
    local_index = 17

    target_lines = bytearray(struct.pack("<IH", target_index, 0))
    target_lines.extend(struct.pack("<IH", 3 if donor else 4,
                                    21 if donor else 11))
    other_lines = (struct.pack("<IH", 20, 0) + struct.pack("<IH", 1, 77))

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
    debug_relocations = [(28, target_index, 0x000B),
                         (32, target_index, 0x000A)]
    debug_label_index = 28
    if debug_label_relocations:
        debug_relocations.extend([
            (34, debug_label_index, 0x000B),
            (38, debug_label_index, 0x000A),
        ])
    section_inputs = [
        first,
        {"name": ".xdata$x", "raw": xdata,
         "relocations": [(0, target_index, 0x0007)],
         "lines": b"", "characteristics": 0x40301040},
        {"name": ".debug$S", "raw": bytes(debug_s),
         "relocations": debug_relocations,
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
        (".file", 0, -2, 0, 103, b"fixture.cpp\0".ljust(18, b"\0")),
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
         _section_aux(len(debug_s), len(debug_relocations), 0, 5,
                      associated=target_seat)),
        (local_name, 4, 2, 0, 3, None),
        (".text", 0, other_seat, 0, 3,
         _section_aux(8, 0, 2, 2, checksum=0x12345678)),
        (other_symbol, 0, other_seat, 0x20, 2,
         _function_aux(8, sections[other_slot]["line_offset"])),
        (".bf", 0, other_seat, 0, 101, _marker_aux(70)),
        (".ef", 8, other_seat, 0, 101, _marker_aux(71)),
        (".drectve", 0, 5, 0, 3, _section_aux(len(DIRECTIVE), 0, 0, 0)),
    ]
    if debug_label_relocations:
        symbols.append(("$done$123", 24, target_seat, 0, 6, None))
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


def _patched_target_line_boundary(data, offset):
    coff = byte_identity.CoffObject(data)
    section = coff.function_section(TARGET_SYMBOL)
    output = bytearray(data)
    struct.pack_into("<I", output, section["line_offset"] + 6, offset)
    return bytes(output)


def make_decodable_instruction_hybrid_donor(encoding):
    """Make the Class-G fixture decodable from its COFF line-row boundary."""
    data = make_divergent_coff(donor=True)
    data = _patched_target_body(data, [(22, encoding)])
    return _patched_target_line_boundary(data, 22)


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

    def _swap_donor_relocation_symbols(self, donor, first, second):
        """Return the donor with the symbols of two target relocations
        exchanged, i.e. two constant stores emitted in the other order."""
        parsed = byte_identity.CoffObject(donor)
        section = parsed.function_section(TARGET_SYMBOL)
        rows = byte_identity.detailed_relocations(parsed, section)
        swapped = bytearray(donor)
        base = section["relocation_offset"]
        struct.pack_into("<I", swapped, base + 10 * first + 4,
                         rows[second]["symbol_index"])
        struct.pack_into("<I", swapped, base + 10 * second + 4,
                         rows[first]["symbol_index"])
        return bytes(swapped)

    def test_strict_order_rejects_a_permuted_donor_relocation_table(self):
        seed, donor, function, retail, _ = self.fixture()
        permuted = self._swap_donor_relocation_symbols(donor, 0, 1)
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "non-local relocation rename"):
            self.compose(seed, permuted, function, retail)

    def test_permuted_order_imports_reloc_free_instructions_and_keeps_seed_table(self):
        seed, donor, function, retail, mosaic = self.fixture()
        permuted = self._swap_donor_relocation_symbols(donor, 0, 1)
        function["relocation_order"] = "permuted_outside_ranges"
        composed, detail = self.compose(seed, permuted, function, retail)
        checked = byte_identity.CoffObject(composed)
        section = checked.function_section(TARGET_SYMBOL)
        self.assertEqual(byte_identity.coff_body(checked, section), mosaic)
        self.assertEqual(detail["body_changed_offsets"], [0, 1, 2])
        self.assertEqual(detail["relocation_order"],
                         "permuted_outside_ranges")
        seed_coff = byte_identity.CoffObject(seed)
        self.assertEqual(
            byte_identity.detailed_relocations(checked, section),
            byte_identity.detailed_relocations(
                seed_coff, seed_coff.function_section(TARGET_SYMBOL)),
        )

    def test_permuted_order_refuses_an_unpermuted_donor(self):
        seed, donor, function, retail, _ = self.fixture()
        function["relocation_order"] = "permuted_outside_ranges"
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "permutation is empty"):
            self.compose(seed, donor, function, retail)

    def test_permuted_order_refuses_a_permuted_record_inside_a_range(self):
        seed, donor, function, retail, _ = self.fixture(
            donor_range=(3, 8), donor_extra=(24, 27),
            preserve_relocation_operands=True,
        )
        permuted = self._swap_donor_relocation_symbols(donor, 0, 1)
        function["relocation_order"] = "permuted_outside_ranges"
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "lies inside an imported range"):
            self.compose(seed, permuted, function, retail)

    def test_permuted_order_refuses_a_changed_relocation_multiset(self):
        seed, donor, function, retail, _ = self.fixture()
        parsed = byte_identity.CoffObject(donor)
        section = parsed.function_section(TARGET_SYMBOL)
        rows = byte_identity.detailed_relocations(parsed, section)
        changed = bytearray(donor)
        # both ordinary relocations now name the same callee: a multiset
        # change, not a permutation
        struct.pack_into("<I", changed, section["relocation_offset"] + 4,
                         rows[1]["symbol_index"])
        function["relocation_order"] = "permuted_outside_ranges"
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "not a permutation"):
            self.compose(seed, bytes(changed), function, retail)

    def test_permuted_order_is_confined_to_the_plain_mosaic_class(self):
        seed, donor, function, retail, _ = self.fixture()
        permuted = self._swap_donor_relocation_symbols(donor, 0, 1)
        function["relocation_order"] = "permuted_outside_ranges"
        function["donor_variants"] = []
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "plain single-donor"):
            self.compose(seed, permuted, function, retail)
        function.pop("donor_variants")
        function["relocation_order"] = "anything_goes"
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "unknown relocation order"):
            self.compose(seed, permuted, function, retail)

    def reseat_fixture(self, *, donor_offset=6, window=(3, 10)):
        """A donor whose first relocation operand moved from offset 4 to
        ``donor_offset`` inside ``window`` (the call re-ordered against
        its neighbours); the operand bytes (addend) are unchanged."""
        seed = make_divergent_coff()
        seed_coff = byte_identity.CoffObject(seed)
        section = seed_coff.function_section(TARGET_SYMBOL)
        seed_body = byte_identity.coff_body(seed_coff, section)
        start, end = window
        replacement = bytearray(value ^ 0x41
                                for value in seed_body[start:end])
        replacement[donor_offset - start:donor_offset - start + 4] = (
            seed_body[4:8])
        donor = _patched_target_body(seed, [(start, bytes(replacement))])
        donor = bytearray(donor)
        struct.pack_into("<I", donor, section["relocation_offset"],
                         donor_offset)
        donor = bytes(donor)
        donor_coff = byte_identity.CoffObject(donor)
        donor_body = byte_identity.coff_body(
            donor_coff, donor_coff.function_section(TARGET_SYMBOL))
        mosaic = bytearray(seed_body)
        mosaic[start:end] = donor_body[start:end]
        mosaic = bytes(mosaic)
        output_rows = byte_identity.detailed_relocations(donor_coff, donor_coff.function_section(TARGET_SYMBOL))
        retail = bytearray(mosaic)
        for record in output_rows:
            offset, width = record["offset"], record["width"]
            retail[offset:offset + width] = bytes(
                (0xB0 + offset + index) & 0xFF for index in range(width))
        retail = bytes(retail)
        # the output table: seed records, first one reseated
        expected_table = bytearray(byte_identity._coff_table_bytes(
            seed_coff, section, "relocations"))
        struct.pack_into("<I", expected_table, 0, donor_offset)
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
            "expected_output_relocation_sha256":
                hashlib.sha256(bytes(expected_table)).hexdigest(),
            "instruction_ranges": [{
                "kind": "same_offset_complete_x86_instruction_v1",
                "start": start,
                "end": end,
                "seed_bytes": seed_body[start:end].hex(),
                "seed_sha256": hashlib.sha256(seed_body[start:end]).hexdigest(),
                "donor_bytes": donor_body[start:end].hex(),
                "donor_sha256": hashlib.sha256(donor_body[start:end]).hexdigest(),
                "relocation_reseat": True,
                "seed_relocation_offsets": [4],
                "donor_relocation_offsets": [donor_offset],
            }],
            "retail_oracle": {
                "image": "LEGO1.DLL", "address": "0x1003cf20",
                "verdict": "MATCH", "length": len(seed_body),
            },
            "retail_relocations": relocation_oracle_for(donor, retail),
        }
        return seed, donor, function, retail, mosaic, output_rows

    def test_reseat_moves_only_the_declared_operand_seat(self):
        seed, donor, function, retail, mosaic, output_rows = (
            self.reseat_fixture())
        composed, detail = self.compose(seed, donor, function, retail)
        checked = byte_identity.CoffObject(composed)
        section = checked.function_section(TARGET_SYMBOL)
        self.assertEqual(byte_identity.coff_body(checked, section), mosaic)
        rows = byte_identity.detailed_relocations(checked, section)
        self.assertEqual([row["offset"] for row in rows], [6, 12, 20])
        seed_rows = byte_identity.detailed_relocations(
            byte_identity.CoffObject(seed),
            byte_identity.CoffObject(seed).function_section(TARGET_SYMBOL))
        self.assertEqual([row["symbol_index"] for row in rows],
                         [row["symbol_index"] for row in seed_rows])
        self.assertEqual(detail["relocation_reseats"], [{
            "range": 0, "ordinal": 0, "seed_offset": 4,
            "output_offset": 6, "target": seed_rows[0]["target"]}])
        self.assertEqual(detail["body_changed_offsets"],
                         [3, 4, 5, 8, 9])

    def test_reseat_requires_its_declaration_and_pin(self):
        seed, donor, function, retail, _, _ = self.reseat_fixture()
        undeclared = copy.deepcopy(function)
        item = undeclared["instruction_ranges"][0]
        for key in ("relocation_reseat", "seed_relocation_offsets",
                    "donor_relocation_offsets"):
            item.pop(key)
        undeclared.pop("expected_output_relocation_sha256")
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "relocation offset/type/addend differs"):
            self.compose(seed, donor, undeclared, retail)
        unpinned = copy.deepcopy(function)
        unpinned.pop("expected_output_relocation_sha256")
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "output relocation table pin"):
            self.compose(seed, donor, unpinned, retail)
        wrong_pin = copy.deepcopy(function)
        wrong_pin["expected_output_relocation_sha256"] = "0" * 64
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "reseated relocation table differs"):
            self.compose(seed, donor, wrong_pin, retail)
        wrong_offsets = copy.deepcopy(function)
        wrong_offsets["instruction_ranges"][0]["donor_relocation_offsets"] = [5]
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "differ from the declared reseat"):
            self.compose(seed, donor, wrong_offsets, retail)

    def test_reseat_refuses_an_operand_that_leaves_its_window(self):
        seed, donor, function, retail, _, _ = self.reseat_fixture()
        # narrow the declared window so the donor operand (6..10) escapes it
        item = function["instruction_ranges"][0]
        item["end"] = 9
        item["seed_bytes"] = item["seed_bytes"][:12]
        item["donor_bytes"] = item["donor_bytes"][:12]
        item["seed_sha256"] = hashlib.sha256(
            bytes.fromhex(item["seed_bytes"])).hexdigest()
        item["donor_sha256"] = hashlib.sha256(
            bytes.fromhex(item["donor_bytes"])).hexdigest()
        with self.assertRaises(byte_identity.ByteIdentityError):
            self.compose(seed, donor, function, retail)

    def test_reseat_refuses_a_changed_addend(self):
        seed, donor, function, retail, _, _ = self.reseat_fixture()
        parsed = byte_identity.CoffObject(donor)
        section = parsed.function_section(TARGET_SYMBOL)
        changed = bytearray(donor)
        changed[section["raw_offset"] + 6] ^= 1
        changed_coff = byte_identity.CoffObject(bytes(changed))
        seed_coff = byte_identity.CoffObject(seed)
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "differs from the seed"):
            byte_identity.require_instruction_mosaic_semantic_relocations(
                seed_coff, seed_coff.function_section(TARGET_SYMBOL),
                changed_coff, changed_coff.function_section(TARGET_SYMBOL),
                "fixture", reseat_windows=[(3, 10)])

    def test_reseat_schema_requires_a_moved_operand(self):
        _, _, function, _, _, _ = self.reseat_fixture()
        item = copy.deepcopy(function["instruction_ranges"][0])
        item["donor_relocation_offsets"] = [4]
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "does not move a relocation operand"):
            byte_identity.validate_instruction_mosaic_ranges(
                [item], "fixture", function["expected_body_length"])
        item = copy.deepcopy(function["instruction_ranges"][0])
        item.pop("seed_relocation_offsets")
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "incomplete"):
            byte_identity.validate_instruction_mosaic_ranges(
                [item], "fixture", function["expected_body_length"])

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

    def test_source_permutation_mosaic_keeps_a_changed_non_target_function(self):
        seed, donor, function, retail, mosaic = self.fixture()
        donor_coff = byte_identity.CoffObject(donor)
        other = donor_coff.function_section(OTHER)
        collateral_donor = bytearray(donor)
        collateral_donor[other["raw_offset"]] ^= 0x5A
        collateral_donor = bytes(collateral_donor)

        seed_source = (
            b"// SOURCE-PERMUTATION-START\nseed_form();\n"
            b"// SOURCE-PERMUTATION-END\n"
        )
        donor_source = (
            b"// SOURCE-PERMUTATION-START\ndonor_form();\n"
            b"// SOURCE-PERMUTATION-END\n"
        )

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

        function["target_source_refactor"] = (
            byte_identity.validate_target_source_refactor_proof({
                "kind": "single_evaluation_bindings_v1",
                "start_marker": "// SOURCE-PERMUTATION-START",
                "end_marker": "// SOURCE-PERMUTATION-END",
                "seed_range_pin": pin(seed_source),
                "donor_range_pin": pin(donor_source),
                "operation_ids": ["op_fixture_binding"],
            }, "fixture.proof")
        )
        seed_coff = byte_identity.CoffObject(seed)
        seed_primary = seed_coff.function_section(TARGET_SYMBOL)
        donor_primary = donor_coff.function_section(TARGET_SYMBOL)
        function.update({
            "expected_donor_body_length": donor_primary["raw_size"],
            "expected_donor_line_count": donor_primary["line_count"],
            "expected_seed_metadata_sha256":
                byte_identity.instruction_mosaic_metadata_sha256(
                    seed_coff, seed_primary),
            "expected_donor_metadata_sha256":
                byte_identity.instruction_mosaic_metadata_sha256(
                    donor_coff, donor_primary),
        })
        composed, _ = (
            byte_identity.compose_retail_exact_source_instruction_mosaic(
                seed, collateral_donor, function, retail,
                seed_source, donor_source)
        )
        checked = byte_identity.CoffObject(composed)
        checked_target = checked.function_section(TARGET_SYMBOL)
        checked_other = checked.function_section(OTHER)
        seed_other = seed_coff.function_section(OTHER)
        collateral_coff = byte_identity.CoffObject(collateral_donor)
        collateral_other = collateral_coff.function_section(OTHER)
        self.assertEqual(byte_identity.coff_body(checked, checked_target),
                         mosaic)
        self.assertEqual(byte_identity.coff_body(checked, checked_other),
                         byte_identity.coff_body(seed_coff, seed_other))
        self.assertNotEqual(
            byte_identity.coff_body(checked, checked_other),
            byte_identity.coff_body(collateral_coff, collateral_other),
        )

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


class RetailExactSourceEqualBodyTests(unittest.TestCase):
    """One whole compiler body with seed-authoritative debug metadata."""

    def fixture(self):
        seed = make_divergent_coff()
        seed_coff = byte_identity.CoffObject(seed)
        seed_primary = seed_coff.function_section(TARGET_SYMBOL)
        seed_body = byte_identity.coff_body(seed_coff, seed_primary)
        donor = _patched_target_body(seed, [
            (0, bytes(value ^ 0x31 for value in seed_body[0:3])),
            (24, bytes(value ^ 0x27 for value in seed_body[24:27])),
        ])
        donor_coff = byte_identity.CoffObject(donor)
        donor_primary = donor_coff.function_section(TARGET_SYMBOL)
        donor_body = byte_identity.coff_body(donor_coff, donor_primary)
        changed = [
            index for index, pair in enumerate(zip(seed_body, donor_body))
            if pair[0] != pair[1]
        ]
        retail = retail_body_for(donor)
        definitions = byte_identity.section_definitions(seed_coff)
        function = {
            "mangled": TARGET_SYMBOL,
            "donor": "d_fixture",
            "splice_class":
                byte_identity.RETAIL_EXACT_SOURCE_EQUAL_BODY_CLASS,
            "expected_section_number": seed_primary["number"],
            "expected_section_count": len(seed_coff.sections),
            "expected_body_length": len(seed_body),
            "expected_characteristics": seed_primary["characteristics"],
            "expected_selection":
                definitions[seed_primary["number"]]["selection"],
            "expected_relocation_count": seed_primary["relocation_count"],
            "expected_seed_line_count": seed_primary["line_count"],
            "expected_donor_line_count": donor_primary["line_count"],
            "expected_function_count":
                sum(byte_identity.function_multiset(seed_coff).values()),
            "expected_comdat_count": sum(
                byte_identity.comdat_primary_identity_multiset(
                    seed_coff).values()),
            "expected_seed_body_sha256":
                hashlib.sha256(seed_body).hexdigest(),
            "expected_donor_body_sha256":
                hashlib.sha256(donor_body).hexdigest(),
            "expected_body_sha256": hashlib.sha256(donor_body).hexdigest(),
            "expected_seed_metadata_sha256":
                byte_identity.instruction_mosaic_metadata_sha256(
                    seed_coff, seed_primary),
            "expected_donor_metadata_sha256":
                byte_identity.instruction_mosaic_metadata_sha256(
                    donor_coff, donor_primary),
            "expected_changed_offsets": changed,
            "expected_code_renames": [],
            "expected_xdata_rename_offsets": [],
            "expected_debug_s_renames": [],
            "expected_closure": [".debug$S", ".xdata$x"],
            "retail_oracle": {
                "image": "LEGO1.DLL", "address": "0x1003cf20",
                "verdict": "MATCH", "length": len(donor_body),
            },
            "retail_relocations": relocation_oracle_for(seed, retail),
            "target_source_refactor": {"fixture": True},
        }
        return seed, donor, function, retail

    def compose(self, seed, donor, function, retail):
        with mock.patch.object(
            byte_identity, "require_target_source_refactor_identity",
            return_value={"source_refactor_identity": True},
        ):
            return byte_identity.compose_retail_exact_source_equal_body(
                seed, donor, function, retail, b"seed source",
                b"donor source")

    def test_whole_body_copy_retains_every_seed_metadata_byte(self):
        seed, donor, function, retail = self.fixture()
        composed, detail = self.compose(seed, donor, function, retail)
        seed_coff = byte_identity.CoffObject(seed)
        primary = seed_coff.function_section(TARGET_SYMBOL)
        start = primary["raw_offset"]
        end = start + primary["raw_size"]
        self.assertEqual(composed[:start], seed[:start])
        self.assertEqual(composed[end:], seed[end:])
        self.assertEqual(composed[start:end], donor[start:end])
        self.assertEqual(
            detail["splice_class"],
            byte_identity.RETAIL_EXACT_SOURCE_EQUAL_BODY_CLASS)
        self.assertTrue(detail["retail_exact"])

    def test_rejects_non_retail_whole_body(self):
        seed, donor, function, retail = self.fixture()
        retail = bytearray(retail)
        retail[1] ^= 1
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "retail-exact"):
            self.compose(seed, donor, function, bytes(retail))

    def test_rejects_stale_metadata_and_closure_pins(self):
        seed, donor, function, retail = self.fixture()
        stale = copy.deepcopy(function)
        stale["expected_donor_metadata_sha256"] = "0" * 64
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "metadata"):
            self.compose(seed, donor, stale, retail)
        stale = copy.deepcopy(function)
        stale["expected_debug_s_renames"] = [[28, "L"]]
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    r"debug\$S rename"):
            self.compose(seed, donor, stale, retail)

    def test_live_pizzeria_is_whole_body_and_has_no_ranges(self):
        manifest = json.loads(
            (TOOLS / "byte_identity_manifest.json").read_text())
        unit = next(
            item for item in manifest["translation_units"]
            if item["source"]
            == "LEGO1/lego/legoomni/src/actors/pizzeria.cpp")
        function = unit["functions"][0]
        self.assertEqual(
            function["splice_class"],
            byte_identity.RETAIL_EXACT_SOURCE_EQUAL_BODY_CLASS)
        self.assertNotIn("instruction_ranges", function)
        self.assertEqual(function["expected_seed_line_count"], 9)
        self.assertEqual(function["expected_donor_line_count"], 8)
        self.assertEqual(len(function["expected_changed_offsets"]), 18)


class CrossTuInstructionHybridResizeTests(unittest.TestCase):
    """A different-TU same-COMDAT instruction feeds an ordinary resize."""

    def fixture(self):
        seed = make_divergent_coff()
        target_start, target_end = 22, 26
        source_start, source_end = 22, 26
        target_encoding = bytes.fromhex("3b4c2410")
        source_encoding = bytes.fromhex("394c2410")
        target_donor = make_decodable_instruction_hybrid_donor(
            target_encoding)
        target_coff = byte_identity.CoffObject(target_donor)
        target_primary = target_coff.function_section(TARGET_SYMBOL)
        target_body = byte_identity.coff_body(target_coff, target_primary)

        instruction_donor = make_decodable_instruction_hybrid_donor(
            source_encoding)
        instruction_coff = byte_identity.CoffObject(instruction_donor)
        instruction_primary = instruction_coff.function_section(TARGET_SYMBOL)
        instruction_body = byte_identity.coff_body(
            instruction_coff, instruction_primary)
        hybrid = _patched_target_body(
            target_donor, [(target_start, source_encoding)])
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
        self.assertEqual(detail["instruction_ranges"][0]["target_start"], 22)
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
        target_donor = _patched_target_body(
            target_donor, [(18, b"\x3b\xc8\x40\x40")])
        target_donor = _patched_target_line_boundary(target_donor, 18)
        instruction_donor = _patched_target_body(
            instruction_donor, [(18, b"\x3b\xc1\x40\x40")])
        instruction_donor = _patched_target_line_boundary(
            instruction_donor, 18)
        target_coff = byte_identity.CoffObject(target_donor)
        target_primary = target_coff.function_section(TARGET_SYMBOL)
        target_body = byte_identity.coff_body(target_coff, target_primary)
        instruction_coff = byte_identity.CoffObject(instruction_donor)
        instruction_primary = instruction_coff.function_section(TARGET_SYMBOL)
        instruction_body = byte_identity.coff_body(
            instruction_coff, instruction_primary)
        bad["expected_target_donor_body_sha256"] = hashlib.sha256(
            target_body).hexdigest()
        bad["expected_instruction_donor_body_sha256"] = hashlib.sha256(
            instruction_body).hexdigest()
        item = bad["instruction_ranges"][0]
        item.update({
            "target_start": 18, "target_end": 20,
            "target_bytes": target_body[18:20].hex(),
            "target_sha256": hashlib.sha256(target_body[18:20]).hexdigest(),
            "instruction_donor_start": 18,
            "instruction_donor_end": 20,
            "instruction_donor_bytes": instruction_body[18:20].hex(),
            "instruction_donor_sha256":
                hashlib.sha256(instruction_body[18:20]).hexdigest(),
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

    def test_containing_stream_rejects_a_valid_instruction_inside_mov_imm32(self):
        data = make_divergent_coff(donor=True)
        data = _patched_target_body(
            data, [(3, bytes.fromhex("b883c00400"))])
        coff = byte_identity.CoffObject(data)
        section = coff.function_section(TARGET_SYMBOL)
        body = byte_identity.coff_body(coff, section)
        byte_identity.require_supported_complete_ia32_instruction(
            body[4:7], "isolated fixture")
        ranges = [{"target_start": 4, "target_end": 7}]
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "containing-stream"):
            byte_identity.require_coff_line_certified_ia32_boundaries(
                coff, section, body, ranges, "target", TARGET_SYMBOL,
                "fixture")
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "unsupported"):
            byte_identity.supported_ia32_instruction_length(
                b"\x0f\x38\x00\xc0", "unsupported fixture")

    def test_line_sentinel_must_name_the_unique_exact_definition(self):
        for section_number, message in (
            (0, "line sentinel"), (4, "line sentinel"),
            (1, "expected one function symbol"),
        ):
            with self.subTest(section_number=section_number):
                data = make_decodable_instruction_hybrid_donor(
                    bytes.fromhex("3b4c2410"))
                coff = byte_identity.CoffObject(data)
                section = coff.function_section(TARGET_SYMBOL)
                target_index, _ = byte_identity.function_symbol(
                    coff, TARGET_SYMBOL, section["number"])
                common_index, _ = byte_identity.unique_symbol(
                    coff, lambda symbol: symbol["name"] == COMMON,
                    "fixture common symbol")
                output = bytearray(data)
                target_at = coff.symbol_offset + target_index * 18
                common_at = coff.symbol_offset + common_index * 18
                output[common_at:common_at + 8] = output[
                    target_at:target_at + 8]
                struct.pack_into(
                    "<IhHBB", output, common_at + 8, 0, section_number,
                    0x20 if section_number else 0, 2, 0)
                struct.pack_into(
                    "<I", output, section["line_offset"], common_index)
                changed = byte_identity.CoffObject(bytes(output))
                changed_body = byte_identity.coff_body(
                    changed, section)
                with self.assertRaisesRegex(
                        byte_identity.ByteIdentityError, message):
                    byte_identity.require_coff_line_certified_ia32_boundaries(
                        changed, section, changed_body,
                        [{"target_start": 22, "target_end": 26}],
                        "target", TARGET_SYMBOL, "fixture")


class SourceInstructionHybridResizeTests(unittest.TestCase):
    """A typed same-TU source permutation may donate instructions only."""

    def fixture(self):
        seed = make_divergent_coff()
        start, end = 22, 26
        target_encoding = bytes.fromhex("3b4c2410")
        donor_encoding = bytes.fromhex("394c2410")
        target_donor = make_decodable_instruction_hybrid_donor(
            target_encoding)
        target = byte_identity.CoffObject(target_donor)
        target_primary = target.function_section(TARGET_SYMBOL)
        target_body = byte_identity.coff_body(target, target_primary)
        instruction_donor = _patched_target_body(
            target_donor, [(start, donor_encoding)])
        instruction = byte_identity.CoffObject(instruction_donor)
        instruction_primary = instruction.function_section(TARGET_SYMBOL)
        instruction_body = byte_identity.coff_body(
            instruction, instruction_primary)
        hybrid = _patched_target_body(
            target_donor, [(start, donor_encoding)])
        hybrid_coff = byte_identity.CoffObject(hybrid)
        hybrid_primary = hybrid_coff.function_section(TARGET_SYMBOL)
        hybrid_body = byte_identity.coff_body(hybrid_coff, hybrid_primary)
        seed_coff = byte_identity.CoffObject(seed)
        seed_primary = seed_coff.function_section(TARGET_SYMBOL)
        seed_body = byte_identity.coff_body(seed_coff, seed_primary)
        retail = retail_body_for(hybrid)

        def counts(coff):
            return (
                sum(byte_identity.function_multiset(coff).values()),
                sum(byte_identity.comdat_primary_identity_multiset(
                    coff).values()),
            )

        marker = "// fixture target"
        seed_source = (
            marker + "\nvoid fixture() {\n\tcursor++;\n}\n"
        ).encode("ascii")
        donor_source = seed_source.replace(b"\tcursor++;", b"\t++cursor;")

        def pin(data):
            return {
                "baseline_sha256": hashlib.sha256(data).hexdigest(),
                "baseline_size": len(data),
                "baseline_line_count": len(data.splitlines()),
                "baseline_significant_token_sha256":
                    byte_identity.source_overlay_significant_sha256(data),
            }

        function = {
            "mangled": TARGET_SYMBOL,
            "donor": "d_target",
            "instruction_donor": "d_instruction",
            "splice_class":
                byte_identity.SOURCE_INSTRUCTION_HYBRID_RESIZE_CLASS,
            "expected_seed_length": len(seed_body),
            "expected_donor_length": len(target_body),
            "expected_linked_span": LINKED_SPAN,
            "expected_seed_section_number": seed_primary["number"],
            "expected_seed_section_count": len(seed_coff.sections),
            "expected_seed_relocation_count":
                seed_primary["relocation_count"],
            "expected_seed_line_count": seed_primary["line_count"],
            "expected_seed_body_sha256":
                hashlib.sha256(seed_body).hexdigest(),
            "expected_seed_metadata_sha256":
                byte_identity.instruction_mosaic_metadata_sha256(
                    seed_coff, seed_primary),
            "expected_seed_function_count": counts(seed_coff)[0],
            "expected_seed_comdat_count": counts(seed_coff)[1],
            "expected_target_donor_section_number":
                target_primary["number"],
            "expected_target_donor_section_count": len(target.sections),
            "expected_target_donor_relocation_count":
                target_primary["relocation_count"],
            "expected_target_donor_line_count":
                target_primary["line_count"],
            "expected_target_donor_body_sha256":
                hashlib.sha256(target_body).hexdigest(),
            "expected_target_donor_metadata_sha256":
                byte_identity.instruction_mosaic_metadata_sha256(
                    target, target_primary),
            "expected_target_donor_function_count": counts(target)[0],
            "expected_target_donor_comdat_count": counts(target)[1],
            "expected_instruction_donor_length": len(instruction_body),
            "expected_instruction_donor_section_number":
                instruction_primary["number"],
            "expected_instruction_donor_section_count":
                len(instruction.sections),
            "expected_instruction_donor_relocation_count":
                instruction_primary["relocation_count"],
            "expected_instruction_donor_line_count":
                instruction_primary["line_count"],
            "expected_instruction_donor_body_sha256":
                hashlib.sha256(instruction_body).hexdigest(),
            "expected_instruction_donor_metadata_sha256":
                byte_identity.instruction_mosaic_metadata_sha256(
                    instruction, instruction_primary),
            "expected_instruction_donor_function_count":
                counts(instruction)[0],
            "expected_instruction_donor_comdat_count":
                counts(instruction)[1],
            "expected_donor_closure": list(
                byte_identity._comdat_child_closure(
                    target, target_primary)[1]),
            "expected_hybrid_body_sha256":
                hashlib.sha256(hybrid_body).hexdigest(),
            "instruction_ranges": [{
                "kind":
                    "source_same_mangled_complete_x86_instruction_v1",
                "target_start": start, "target_end": end,
                "target_bytes": target_body[start:end].hex(),
                "target_sha256":
                    hashlib.sha256(target_body[start:end]).hexdigest(),
                "instruction_donor_start": start,
                "instruction_donor_end": end,
                "instruction_donor_bytes":
                    instruction_body[start:end].hex(),
                "instruction_donor_sha256": hashlib.sha256(
                    instruction_body[start:end]).hexdigest(),
            }],
            "retail_oracle": {
                "image": "LEGO1.DLL", "address": "0x1003cf20",
                "verdict": "MATCH", "length": len(hybrid_body),
            },
            "retail_relocations": relocation_oracle_for(hybrid, retail),
            "instruction_donor_source_refactor": {
                "kind": "discarded_postfix_increment_v1",
                "selector": "brace_balanced_function_after_marker_v1",
                "start_marker": marker,
                "source_owner_mangled": TARGET_SYMBOL,
                "seed_range_pin": pin(seed_source),
                "donor_range_pin": pin(donor_source),
                "operation_ids": ["op_fixture_increment"],
            },
        }
        return (seed, target_donor, instruction_donor, function, retail,
                seed_source, donor_source, hybrid)

    def compose(self, fixture, function=None, retail=None):
        (seed, target, instruction, expected, oracle, seed_source,
         donor_source, _) = fixture
        return byte_identity.compose_retail_exact_source_instruction_hybrid_resize(
            seed, target, instruction, function or expected,
            oracle if retail is None else retail, seed_source, donor_source)

    def test_positive_keeps_target_metadata_and_seed_non_targets(self):
        fixture = self.fixture()
        composed, detail = self.compose(fixture)
        seed, target, instruction, _, _, _, _, hybrid = fixture
        checked = byte_identity.CoffObject(composed)
        checked_primary = checked.function_section(TARGET_SYMBOL)
        target_coff = byte_identity.CoffObject(target)
        target_primary = target_coff.function_section(TARGET_SYMBOL)
        hybrid_coff = byte_identity.CoffObject(hybrid)
        hybrid_primary = hybrid_coff.function_section(TARGET_SYMBOL)
        self.assertEqual(
            byte_identity.coff_body(checked, checked_primary),
            byte_identity.coff_body(hybrid_coff, hybrid_primary))
        self.assertEqual(
            byte_identity.instruction_mosaic_metadata_sha256(
                checked, checked_primary),
            byte_identity.instruction_mosaic_metadata_sha256(
                target_coff, target_primary))
        seed_coff = byte_identity.CoffObject(seed)
        for before in seed_coff.sections:
            if before["number"] in {1, 2, 3}:
                continue
            after = checked.sections[before["number"] - 1]
            self.assertEqual(byte_identity.coff_body(seed_coff, before),
                             byte_identity.coff_body(checked, after))
        byte_identity.validate_donor_object_excluded(
            composed, [target, instruction])
        self.assertEqual(
            detail["splice_class"],
            byte_identity.SOURCE_INSTRUCTION_HYBRID_RESIZE_CLASS)
        self.assertTrue(detail["retail_exact"])

    def test_rejects_seed_donor_metadata_closure_and_census_drift(self):
        fixture = self.fixture()
        function = fixture[3]
        mutations = (
            ("expected_seed_metadata_sha256", "0" * 64, "seed metadata"),
            ("expected_target_donor_metadata_sha256", "0" * 64,
             "target-donor metadata"),
            ("expected_instruction_donor_metadata_sha256", "0" * 64,
             "instruction-donor metadata"),
            ("expected_seed_function_count",
             function["expected_seed_function_count"] + 1,
             "function census"),
            ("expected_instruction_donor_comdat_count",
             function["expected_instruction_donor_comdat_count"] + 1,
             "COMDAT census"),
            ("expected_donor_closure", [".debug$S"], "closure"),
        )
        for key, value, message in mutations:
            bad = copy.deepcopy(function)
            bad[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(
                    byte_identity.ByteIdentityError, message):
                self.compose(fixture, bad)

    def test_rejects_offset_range_relocation_and_retail_oracle_drift(self):
        fixture = self.fixture()
        function = fixture[3]
        bad = copy.deepcopy(function)
        bad["instruction_ranges"][0]["instruction_donor_start"] -= 1
        bad["instruction_ranges"][0]["instruction_donor_end"] -= 1
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "offsets differ"):
            self.compose(fixture, bad)

        bad = copy.deepcopy(function)
        patched_target = _patched_target_body(
            fixture[1], [(18, b"\x3b\xc8\x40\x40")])
        patched_target = _patched_target_line_boundary(patched_target, 18)
        patched_instruction = _patched_target_body(
            fixture[2], [(18, b"\x3b\xc1\x40\x40")])
        patched_instruction = _patched_target_line_boundary(
            patched_instruction, 18)
        target = byte_identity.CoffObject(patched_target)
        primary = target.function_section(TARGET_SYMBOL)
        body = byte_identity.coff_body(target, primary)
        item = bad["instruction_ranges"][0]
        instruction = byte_identity.CoffObject(patched_instruction)
        instruction_primary = instruction.function_section(TARGET_SYMBOL)
        instruction_body = byte_identity.coff_body(
            instruction, instruction_primary)
        bad["expected_target_donor_body_sha256"] = hashlib.sha256(
            body).hexdigest()
        bad["expected_target_donor_metadata_sha256"] = (
            byte_identity.instruction_mosaic_metadata_sha256(
                target, primary)
        )
        bad["expected_instruction_donor_body_sha256"] = hashlib.sha256(
            instruction_body).hexdigest()
        bad["expected_instruction_donor_metadata_sha256"] = (
            byte_identity.instruction_mosaic_metadata_sha256(
                instruction, instruction_primary)
        )
        item.update({
            "target_start": 18, "target_end": 20,
            "target_bytes": body[18:20].hex(),
            "target_sha256": hashlib.sha256(body[18:20]).hexdigest(),
            "instruction_donor_start": 18,
            "instruction_donor_end": 20,
            "instruction_donor_bytes": instruction_body[18:20].hex(),
            "instruction_donor_sha256":
                hashlib.sha256(instruction_body[18:20]).hexdigest(),
        })
        relocation_fixture = list(fixture)
        relocation_fixture[1] = patched_target
        relocation_fixture[2] = patched_instruction
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "relocation"):
            self.compose(tuple(relocation_fixture), bad)

        bad = copy.deepcopy(function)
        retail_target = bad["retail_relocations"][0]["retail_target"]
        bad["retail_relocations"][0]["retail_target"] = hex(
            int(retail_target, 16) + 1)
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "retail"):
            self.compose(fixture, bad)

    def test_live_manifest_has_split_ranges_and_full_relocation_oracle(self):
        manifest = json.loads(
            (TOOLS / "byte_identity_manifest.json").read_text())
        matches = [
            function
            for unit in manifest["translation_units"]
            for function in unit.get("functions", [])
            if function.get("splice_class")
            == byte_identity.SOURCE_INSTRUCTION_HYBRID_RESIZE_CLASS
        ]
        if not matches:
            self.skipTest("no live source instruction-hybrid instance")
        self.assertEqual(len(matches), 1)
        function = matches[0]
        self.assertEqual(len(function["instruction_ranges"]), 11)
        self.assertIn((416, 419), {
            (item["target_start"], item["target_end"])
            for item in function["instruction_ranges"]
        })
        self.assertIn((419, 420), {
            (item["target_start"], item["target_end"])
            for item in function["instruction_ranges"]
        })
        self.assertEqual(len(function["retail_relocations"]), 23)

    def test_source_instruction_donor_has_one_nonprimary_proof_binding(self):
        byte_identity.require_source_refactor_donor_bindings(
            {"d_instruction"}, ["d_target"], [], ["d_instruction"],
            "fixture", ["d_instruction"])
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "non-primary roles"):
            byte_identity.require_source_refactor_donor_bindings(
                {"d_instruction"}, ["d_target"], [],
                ["d_instruction", "d_instruction"], "fixture",
                ["d_instruction"])


class SameTuInstructionHybridResizeTests(unittest.TestCase):
    """Two source-identical carrier states may supply one hybrid resize."""

    def fixture(self):
        seed = make_divergent_coff()
        start, end = 22, 26
        target_encoding = bytes.fromhex("3b4c2410")
        instruction_encoding = bytes.fromhex("394c2410")
        target_donor = make_decodable_instruction_hybrid_donor(
            target_encoding)
        instruction_donor = _patched_target_body(
            target_donor, [(start, instruction_encoding)])
        target = byte_identity.CoffObject(target_donor)
        target_primary = target.function_section(TARGET_SYMBOL)
        target_body = byte_identity.coff_body(target, target_primary)
        instruction = byte_identity.CoffObject(instruction_donor)
        instruction_primary = instruction.function_section(TARGET_SYMBOL)
        instruction_body = byte_identity.coff_body(
            instruction, instruction_primary)
        seed_coff = byte_identity.CoffObject(seed)
        seed_primary = seed_coff.function_section(TARGET_SYMBOL)
        seed_body = byte_identity.coff_body(seed_coff, seed_primary)
        hybrid = _patched_target_body(
            target_donor, [(start, instruction_encoding)])
        hybrid_coff = byte_identity.CoffObject(hybrid)
        hybrid_primary = hybrid_coff.function_section(TARGET_SYMBOL)
        hybrid_body = byte_identity.coff_body(hybrid_coff, hybrid_primary)
        retail = retail_body_for(hybrid)

        def counts(coff):
            return (
                sum(byte_identity.function_multiset(coff).values()),
                sum(byte_identity.comdat_primary_identity_multiset(
                    coff).values()),
            )

        source = (
            b"// fixture target\n"
            b"void fixture() {\n\tcursor++;\n}\n"
        )
        source_pin = {
            "baseline_sha256": hashlib.sha256(source).hexdigest(),
            "baseline_size": len(source),
            "baseline_line_count": source.count(b"\n"),
            "baseline_significant_token_sha256":
                byte_identity.source_overlay_significant_sha256(source),
        }
        function = {
            "mangled": TARGET_SYMBOL,
            "donor": "d_target",
            "instruction_donor": "d_instruction",
            "splice_class":
                byte_identity.SAME_TU_INSTRUCTION_HYBRID_RESIZE_CLASS,
            "expected_seed_length": len(seed_body),
            "expected_donor_length": len(target_body),
            "expected_linked_span": LINKED_SPAN,
            "expected_seed_section_number": seed_primary["number"],
            "expected_seed_section_count": len(seed_coff.sections),
            "expected_seed_relocation_count":
                seed_primary["relocation_count"],
            "expected_seed_line_count": seed_primary["line_count"],
            "expected_seed_body_sha256":
                hashlib.sha256(seed_body).hexdigest(),
            "expected_seed_metadata_sha256":
                byte_identity.instruction_mosaic_metadata_sha256(
                    seed_coff, seed_primary),
            "expected_seed_function_count": counts(seed_coff)[0],
            "expected_seed_comdat_count": counts(seed_coff)[1],
            "expected_target_donor_section_number": target_primary["number"],
            "expected_target_donor_section_count": len(target.sections),
            "expected_target_donor_relocation_count":
                target_primary["relocation_count"],
            "expected_target_donor_line_count": target_primary["line_count"],
            "expected_target_donor_body_sha256":
                hashlib.sha256(target_body).hexdigest(),
            "expected_target_donor_metadata_sha256":
                byte_identity.instruction_mosaic_metadata_sha256(
                    target, target_primary),
            "expected_target_donor_function_count": counts(target)[0],
            "expected_target_donor_comdat_count": counts(target)[1],
            "expected_instruction_donor_length": len(instruction_body),
            "expected_instruction_donor_section_number":
                instruction_primary["number"],
            "expected_instruction_donor_section_count":
                len(instruction.sections),
            "expected_instruction_donor_relocation_count":
                instruction_primary["relocation_count"],
            "expected_instruction_donor_line_count":
                instruction_primary["line_count"],
            "expected_instruction_donor_body_sha256":
                hashlib.sha256(instruction_body).hexdigest(),
            "expected_instruction_donor_metadata_sha256":
                byte_identity.instruction_mosaic_metadata_sha256(
                    instruction, instruction_primary),
            "expected_instruction_donor_function_count":
                counts(instruction)[0],
            "expected_instruction_donor_comdat_count":
                counts(instruction)[1],
            "expected_donor_closure": list(
                byte_identity._comdat_child_closure(
                    target, target_primary)[1]),
            "expected_hybrid_body_sha256":
                hashlib.sha256(hybrid_body).hexdigest(),
            "same_tu_source_identity": {
                "kind": "same_tu_function_source_identity_v1",
                "selector": "brace_balanced_function_physical_line_v1",
                "start_marker": "// fixture target",
                "source_owner_mangled": TARGET_SYMBOL,
                "range_pin": source_pin,
            },
            "instruction_ranges": [{
                "kind":
                    "same_tu_source_identical_complete_x86_instruction_v1",
                "target_start": start,
                "target_end": end,
                "target_bytes": target_body[start:end].hex(),
                "target_sha256":
                    hashlib.sha256(target_body[start:end]).hexdigest(),
                "instruction_donor_start": start,
                "instruction_donor_end": end,
                "instruction_donor_bytes":
                    instruction_body[start:end].hex(),
                "instruction_donor_sha256": hashlib.sha256(
                    instruction_body[start:end]).hexdigest(),
            }],
            "retail_oracle": {
                "image": "LEGO1.DLL", "address": "0x1003cf20",
                "verdict": "MATCH", "length": len(hybrid_body),
            },
            "retail_image_target": "lego1",
            "retail_relocations": relocation_oracle_for(hybrid, retail),
        }
        return (seed, target_donor, instruction_donor, function, retail,
                source, hybrid)

    def compose(self, fixture, function=None, retail=None,
                sources=None, instruction=None):
        (seed, target, default_instruction, expected, oracle, source,
         _) = fixture
        source_rows = sources or (source, source, source)
        return byte_identity.compose_retail_exact_same_tu_instruction_hybrid_resize(
            seed, target,
            default_instruction if instruction is None else instruction,
            function or expected, oracle if retail is None else retail,
            *source_rows)

    def test_positive_conserves_target_metadata_and_seed_non_targets(self):
        fixture = self.fixture()
        composed, detail = self.compose(fixture)
        seed, target, instruction, _, _, _, hybrid = fixture
        checked = byte_identity.CoffObject(composed)
        checked_primary = checked.function_section(TARGET_SYMBOL)
        target_coff = byte_identity.CoffObject(target)
        target_primary = target_coff.function_section(TARGET_SYMBOL)
        hybrid_coff = byte_identity.CoffObject(hybrid)
        hybrid_primary = hybrid_coff.function_section(TARGET_SYMBOL)
        self.assertEqual(
            byte_identity.coff_body(checked, checked_primary),
            byte_identity.coff_body(hybrid_coff, hybrid_primary))
        self.assertEqual(
            byte_identity.instruction_mosaic_metadata_sha256(
                checked, checked_primary),
            byte_identity.instruction_mosaic_metadata_sha256(
                target_coff, target_primary))
        seed_coff = byte_identity.CoffObject(seed)
        for before in seed_coff.sections:
            if before["number"] in {1, 2, 3}:
                continue
            after = checked.sections[before["number"] - 1]
            self.assertEqual(byte_identity.coff_body(seed_coff, before),
                             byte_identity.coff_body(checked, after))
        byte_identity.validate_donor_object_excluded(
            composed, [target, instruction])
        self.assertEqual(
            detail["splice_class"],
            byte_identity.SAME_TU_INSTRUCTION_HYBRID_RESIZE_CLASS)
        self.assertEqual(detail["target_source_size"], len(fixture[5]))
        self.assertTrue(detail["retail_exact"])

    def test_rejects_source_identity_and_object_pin_drift(self):
        fixture = self.fixture()
        changed_source = fixture[5].replace(b"cursor", b"other_")
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "authenticated input-range"):
            self.compose(
                fixture,
                sources=(fixture[5], changed_source, fixture[5]))

        for key, value, message in (
            ("expected_seed_metadata_sha256", "0" * 64,
             "seed metadata"),
            ("expected_target_donor_metadata_sha256", "0" * 64,
             "target-donor metadata"),
            ("expected_instruction_donor_body_sha256", "0" * 64,
             "instruction donor body"),
            ("expected_instruction_donor_comdat_count",
             fixture[3]["expected_instruction_donor_comdat_count"] + 1,
             "COMDAT census"),
        ):
            bad = copy.deepcopy(fixture[3])
            bad[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(
                    byte_identity.ByteIdentityError, message):
                self.compose(fixture, bad)

    def test_rejects_donor_universe_and_semantic_relocation_drift(self):
        fixture = self.fixture()
        renamed = fixture[2].replace(
            OTHER.encode("ascii"), b"?Extra@@YAXXZ")
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "function universe"):
            self.compose(fixture, instruction=renamed)

        changed = bytearray(fixture[2])
        changed_coff = byte_identity.CoffObject(bytes(changed))
        changed_primary = changed_coff.function_section(TARGET_SYMBOL)
        common_index, _ = byte_identity.unique_symbol(
            changed_coff, lambda symbol: symbol["name"] == COMMON,
            "fixture common symbol")
        struct.pack_into(
            "<I", changed, changed_primary["relocation_offset"] + 14,
            common_index)
        changed = bytes(changed)
        changed_coff = byte_identity.CoffObject(changed)
        changed_primary = changed_coff.function_section(TARGET_SYMBOL)
        bad = copy.deepcopy(fixture[3])
        bad["expected_instruction_donor_body_sha256"] = hashlib.sha256(
            byte_identity.coff_body(changed_coff, changed_primary)).hexdigest()
        bad["expected_instruction_donor_metadata_sha256"] = (
            byte_identity.instruction_mosaic_metadata_sha256(
                changed_coff, changed_primary)
        )
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "relocation"):
            self.compose(fixture, bad, instruction=changed)

    def test_rejects_relocation_overlap_and_retail_oracle_drift(self):
        fixture = self.fixture()
        bad = copy.deepcopy(fixture[3])
        target = _patched_target_body(
            fixture[1], [(18, b"\x3b\xc8\x40\x40")])
        target = _patched_target_line_boundary(target, 18)
        instruction = _patched_target_body(
            fixture[2], [(18, b"\x3b\xc1\x40\x40")])
        instruction = _patched_target_line_boundary(instruction, 18)
        target_coff = byte_identity.CoffObject(target)
        target_primary = target_coff.function_section(TARGET_SYMBOL)
        target_body = byte_identity.coff_body(target_coff, target_primary)
        instruction_coff = byte_identity.CoffObject(instruction)
        instruction_primary = instruction_coff.function_section(
            TARGET_SYMBOL)
        instruction_body = byte_identity.coff_body(
            instruction_coff, instruction_primary)
        bad.update({
            "expected_target_donor_body_sha256":
                hashlib.sha256(target_body).hexdigest(),
            "expected_target_donor_metadata_sha256":
                byte_identity.instruction_mosaic_metadata_sha256(
                    target_coff, target_primary),
            "expected_instruction_donor_body_sha256":
                hashlib.sha256(instruction_body).hexdigest(),
            "expected_instruction_donor_metadata_sha256":
                byte_identity.instruction_mosaic_metadata_sha256(
                    instruction_coff, instruction_primary),
        })
        item = bad["instruction_ranges"][0]
        item.update({
            "target_start": 18, "target_end": 20,
            "target_bytes": target_body[18:20].hex(),
            "target_sha256": hashlib.sha256(target_body[18:20]).hexdigest(),
            "instruction_donor_start": 18,
            "instruction_donor_end": 20,
            "instruction_donor_bytes": instruction_body[18:20].hex(),
            "instruction_donor_sha256": hashlib.sha256(
                instruction_body[18:20]).hexdigest(),
        })
        changed_fixture = list(fixture)
        changed_fixture[1] = target
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "relocation"):
            self.compose(tuple(changed_fixture), bad,
                         instruction=instruction)

        bad = copy.deepcopy(fixture[3])
        bad["retail_relocations"][0]["retail_target"] = "0x00000001"
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "retail"):
            self.compose(fixture, bad)

    def test_carrier_rendering_and_live_source_identity_match_all_pins(self):
        manifest = json.loads(
            (TOOLS / "byte_identity_manifest.json").read_text())
        unit = next(
            item for item in manifest["translation_units"]
            if item["source"] == "LEGO1/viewmanager/viewmanager.cpp")
        overlay = byte_identity.validate_source_overlay(
            manifest["source_overlay"], ROOT)
        source = overlay["rendered_by_path"][unit["source"]]
        generated = {}
        rendered = {}
        for donor in unit["donors"]:
            if (donor["recipe"].get("kind")
                    != byte_identity.SAME_TU_DECLARATION_CARRIER_RECIPE):
                continue
            _, generated[donor["id"]], rendered[donor["id"]] = (
                byte_identity.validate_same_tu_declaration_carrier_recipe(
                    donor["recipe"], source, "fixture")
            )
        self.assertEqual(set(generated), {
            "d_02c3090ca79b", "d_282491eaa62c"})
        function = next(
            item for item in unit["functions"]
            if item.get("splice_class")
            == byte_identity.SAME_TU_INSTRUCTION_HYBRID_RESIZE_CLASS)
        detail = byte_identity.require_same_tu_source_identity(
            source, rendered[function["donor"]],
            rendered[function["instruction_donor"]],
            byte_identity.validate_same_tu_source_identity_proof(
                function["same_tu_source_identity"], "fixture"),
            "fixture")
        self.assertEqual(detail["target_source_size"], 1732)

    def test_carrier_recipe_rejects_seat_width_and_render_pin_drift(self):
        manifest = json.loads(
            (TOOLS / "byte_identity_manifest.json").read_text())
        unit = next(
            item for item in manifest["translation_units"]
            if item["source"] == "LEGO1/viewmanager/viewmanager.cpp")
        recipe = next(
            copy.deepcopy(item["recipe"]) for item in unit["donors"]
            if item["recipe"].get("kind")
            == byte_identity.SAME_TU_DECLARATION_CARRIER_RECIPE)
        overlay = byte_identity.validate_source_overlay(
            manifest["source_overlay"], ROOT)
        source = overlay["rendered_by_path"][unit["source"]]
        mutations = (
            (lambda value: value["seat_proof"].update(
                {"following_line_sha256": "0" * 64}), "witness"),
            (lambda value: value.update({"extern_width": 3}), "widths"),
            (lambda value: value.update({"forward_prefix": "VmL"}),
             "collides"),
            (lambda value: value.update(
                {"rendered_source_sha256": "0" * 64}), "rendered source"),
        )
        for mutate, message in mutations:
            bad = copy.deepcopy(recipe)
            mutate(bad)
            with self.subTest(message=message), self.assertRaisesRegex(
                    byte_identity.ByteIdentityError, message):
                byte_identity.validate_same_tu_declaration_carrier_recipe(
                    bad, source, "fixture")

    def test_donor_governed_span_allows_the_live_boundary_crossing_only(self):
        byte_identity.require_instruction_hybrid_resize_span(
            557, 561, 576, donor_governed=True, context="fixture")
        self.assertEqual(((557 + 15) // 16) * 16, 560)
        for span, seed in ((560, 557), (576, 577)):
            with self.subTest(span=span, seed=seed), self.assertRaisesRegex(
                    byte_identity.ByteIdentityError, "spans differ"):
                byte_identity.require_instruction_hybrid_resize_span(
                    seed, 561, span, donor_governed=True,
                    context="fixture")

    def test_role_binding_accepts_only_one_target_and_instruction_use(self):
        byte_identity.require_same_tu_hybrid_carrier_bindings(
            {"d_target", "d_instruction"},
            ["d_target"], ["d_instruction"],
            ["d_target"], ["d_instruction"], "fixture")
        cases = (
            ({"d_target", "d_instruction", "d_unbound"},
             ["d_target"], ["d_instruction"],
             ["d_target"], ["d_instruction"], "bound exactly once"),
            ({"d_target", "d_instruction"},
             ["d_target", "d_target"], ["d_instruction"],
             ["d_target"], ["d_instruction"], "ordinary"),
            ({"d_target", "d_instruction"},
             ["d_target"], ["d_instruction", "d_instruction"],
             ["d_target"], ["d_instruction"], "non-primary"),
        )
        for carriers, primary, nonprimary, target, instruction, message \
                in cases:
            with self.subTest(message=message), self.assertRaisesRegex(
                    byte_identity.ByteIdentityError, message):
                byte_identity.require_same_tu_hybrid_carrier_bindings(
                    carriers, primary, nonprimary, target, instruction,
                    "fixture")

    def test_live_manifest_preflight_rejects_unbound_and_ordinary_reuse(self):
        original = json.loads(
            (TOOLS / "byte_identity_manifest.json").read_text())
        unit_index = next(
            index for index, unit in enumerate(original["translation_units"])
            if any(function.get("splice_class")
                   == byte_identity.SAME_TU_INSTRUCTION_HYBRID_RESIZE_CLASS
                   for function in unit.get("functions", [])))
        function = next(
            item for item in original["translation_units"][unit_index][
                "functions"]
            if item.get("splice_class")
            == byte_identity.SAME_TU_INSTRUCTION_HYBRID_RESIZE_CLASS)
        mutations = []
        unbound = copy.deepcopy(original)
        unbound["translation_units"][unit_index]["functions"] = [
            item for item in unbound["translation_units"][unit_index][
                "functions"] if item.get("mangled") != function["mangled"]
        ]
        mutations.append((unbound, "bound exactly once"))
        reused = copy.deepcopy(original)
        reused["translation_units"][unit_index]["functions"].append({
            "mangled": "?OrdinarySameTuReuseFixture@@YAXXZ",
            "donor": function["donor"],
            "splice_class": "equal_body_strict",
        })
        mutations.append((reused, "ordinary"))
        for manifest, message in mutations:
            with self.subTest(message=message), tempfile.TemporaryDirectory() \
                    as temporary:
                temporary = Path(temporary).resolve()
                manifest_path = temporary / "manifest.json"
                build_dir = temporary / "build"
                build_dir.mkdir()
                manifest_path.write_text(json.dumps(manifest))
                with self.assertRaisesRegex(
                        byte_identity.ByteIdentityError, message):
                    byte_identity.validate_manifest(
                        manifest_path, ROOT, build_dir)

    def test_live_manifest_pins_one_range_eleven_relocs_and_right_image(self):
        manifest = json.loads(
            (TOOLS / "byte_identity_manifest.json").read_text())
        function = next(
            function for unit in manifest["translation_units"]
            for function in unit.get("functions", [])
            if function.get("splice_class")
            == byte_identity.SAME_TU_INSTRUCTION_HYBRID_RESIZE_CLASS
            and function["mangled"].startswith(
                "?ManageVisibilityAndDetailRecursively@ViewManager@@"))
        self.assertEqual(len(function["instruction_ranges"]), 3)
        self.assertEqual((function["instruction_ranges"][-1]["target_start"],
                          function["instruction_ranges"][-1]["target_end"]),
                         (516, 518))
        self.assertEqual(len(function["retail_relocations"]), 11)
        self.assertEqual(function["expected_hybrid_body_sha256"],
                         "01949ffd3e0c851db40055f6a1c5978091144dea8b2de977502762fe061c76e8")
        self.assertEqual(
            byte_identity.require_target_bound_retail_image(
                manifest["images"], function["retail_image_target"],
                function["retail_oracle"]["image"], "fixture"),
            "LEGO1.DLL")
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "differs from the TU target"):
            byte_identity.require_target_bound_retail_image(
                manifest["images"], "isle",
                function["retail_oracle"]["image"], "fixture")


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

    def test_rejects_final_source_component_symlink(self):
        payload = b"int source_overlay_fixture;\n"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            real = root / "real.cpp"
            real.write_bytes(payload)
            (root / "unit.cpp").symlink_to(real.name)
            recipe = {
                "kind": "donor_source_overlay",
                "renderings": [{
                    "path": "unit.cpp",
                    "clean_sha256": hashlib.sha256(payload).hexdigest(),
                    "rendered_sha256": hashlib.sha256(payload).hexdigest(),
                    "operations": [],
                }],
                "compile_lane": {"required_define": "FIXTURE_DEFINE"},
            }
            with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                        "redirected or non-regular"):
                byte_identity.validate_donor_source_overlay_recipe(
                    recipe, root)


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

    def _fixed_array_generator(self, **overrides):
        generator = {
            "k": "fixed_array_fill",
            "array": "slots",
            "index": "cursor",
            "index_type": "unsigned int",
            "count": 7,
            "value": -1,
            "declaration_indent": "  ",
        }
        generator.update(overrides)
        return byte_identity.validate_source_overlay_generator(
            generator, "fixture.fixed_array")

    def _inclusive_extent_generator(self, **overrides):
        generator = {
            "k": "inclusive_extent",
            "type": "MxS32",
            "id": "width",
            "source": {
                "object": "video_param",
                "aggregate_accessor": "GetRect",
            },
            "seed_extent_accessor": "GetWidth",
            "upper_endpoint_accessor": "GetRight",
            "lower_endpoint_accessor": "GetLeft",
            "destination": {"object": "desc", "member": "width"},
            "declaration_indent": "\t\t",
            "barrier": "msvc_i386_empty_inline_assembly_v1",
        }
        generator.update(overrides)
        return byte_identity.validate_source_overlay_generator(
            generator, "fixture.inclusive_extent")

    def _live_case(self):
        manifest = json.loads(
            (TOOLS / "byte_identity_manifest.json").read_text()
        )
        unit = next(item for item in manifest["translation_units"]
                    if item["source"] == self.SOURCE)
        function = next(item for item in unit["functions"]
                        if item["mangled"].startswith("?GetActorROI@"))
        if "target_source_refactor" not in function:
            # GetActorROI closed from a plain declaration carrier once the
            # comparator signatures were corrected (2026-08-18); the
            # single-evaluation permutation mechanism stays fixture-tested.
            self.skipTest("no live single-evaluation source permutation")
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

    def _live_fixed_array_case(self):
        manifest = json.loads(
            (TOOLS / "byte_identity_manifest.json").read_text()
        )
        matches = [
            (unit, function)
            for unit in manifest["translation_units"]
            for function in unit.get("functions", [])
            if function.get("target_source_refactor", {}).get("kind")
            == "fixed_array_fill_loop_v1"
        ]
        self.assertEqual(len(matches), 1)
        unit, function = matches[0]
        donor = next(item for item in unit["donors"]
                     if item["id"] == function["donor"])
        function = copy.deepcopy(function)
        function["target_source_refactor"] = (
            byte_identity.validate_target_source_refactor_proof(
                function["target_source_refactor"], "proof"
            )
        )
        return unit["source"], copy.deepcopy(donor["recipe"]), function

    def _live_inclusive_extent_case(self):
        manifest = json.loads(
            (TOOLS / "byte_identity_manifest.json").read_text()
        )
        matches = [
            (unit, function)
            for unit in manifest["translation_units"]
            for function in unit.get("functions", [])
            if function.get("target_source_refactor", {}).get("kind")
            == "inclusive_extent_assignment_v1"
        ]
        self.assertEqual(len(matches), 1)
        unit, function = matches[0]
        donor = next(item for item in unit["donors"]
                     if item["id"] == function["donor"])
        function = copy.deepcopy(function)
        function["target_source_refactor"] = (
            byte_identity.validate_target_source_refactor_proof(
                function["target_source_refactor"], "proof"
            )
        )
        overlay = byte_identity.validate_source_overlay(
            manifest["source_overlay"], ROOT)
        canonical = next(
            item["operations"] for item in overlay["outputs"]
            if item["logical_path"] == unit["source"]
        )
        overlaid_paths = {
            item["logical_path"] for item in overlay["outputs"]
        }
        return (unit["source"], copy.deepcopy(donor["recipe"]),
                function, canonical, overlaid_paths)

    def _live_discarded_increment_case(self):
        manifest = json.loads(
            (TOOLS / "byte_identity_manifest.json").read_text()
        )
        matches = [
            (unit, function)
            for unit in manifest["translation_units"]
            for function in unit.get("functions", [])
            if function.get(
                "instruction_donor_source_refactor", {}
            ).get("kind") == "discarded_postfix_increment_v1"
        ]
        if not matches:
            # The live discarded-increment hybrid was retired on 2026-08-18
            # when BuildROIMap's loop was corrected in source (BETA10
            # 0x1004f976); the mechanism stays implemented and fixture-tested.
            self.skipTest("no live discarded_postfix_increment_v1 instance")
        self.assertEqual(len(matches), 1)
        unit, function = matches[0]
        donor = next(
            item for item in unit["donors"]
            if item["id"] == function["instruction_donor"]
        )
        function = copy.deepcopy(function)
        function["instruction_donor_source_refactor"] = (
            byte_identity.validate_target_source_refactor_proof(
                function["instruction_donor_source_refactor"], "proof"
            )
        )
        overlay = byte_identity.validate_source_overlay(
            manifest["source_overlay"], ROOT)
        canonical = next(
            item["operations"] for item in overlay["outputs"]
            if item["logical_path"] == unit["source"]
        )
        overlaid_paths = {
            item["logical_path"] for item in overlay["outputs"]
        }
        profile = manifest["toolchain"]["backend_profiles"][
            byte_identity.POSIX_WINE_BACKEND
        ]
        return (
            manifest, unit["source"], copy.deepcopy(donor["recipe"]),
            function, canonical, overlaid_paths,
            ROOT.parent / "MSVC420", profile["sealed_include_trees"],
        )

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

    def test_fixed_array_fill_is_closed_source_derived_and_donor_only(self):
        generator = self._fixed_array_generator()
        self.assertEqual(
            byte_identity.render_fixed_array_fill_loop_input(
                generator["params"]),
            b"  memset(slots, -1, sizeof(slots));\n",
        )
        self.assertEqual(
            byte_identity.render_source_overlay_generator(generator),
            b"  for (unsigned int cursor = 0; cursor < 7; cursor++) "
            b"slots[cursor] = -1;\n",
        )
        roles = byte_identity.source_overlay_expected_identifier_roles(
            generator["kind"], generator["params"])
        self.assertEqual(roles["emitted_identifiers"], [])
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "donor-only"):
            byte_identity.assert_source_permutations_are_donor_only(
                {"generator": generator})

    def test_fixed_array_fill_refuses_schema_type_value_and_layout_escape(self):
        mutations = (
            {"value": 0},
            {"count": 0},
            {"count": 4097},
            {"index_type": "const int"},
            {"index_type": "int*"},
            {"index_type": "ArbitraryCounter"},
            {"nl": False},
            {"text": "open source text"},
            {"index": "slots"},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(
                    byte_identity.ByteIdentityError):
                self._fixed_array_generator(**mutation)

    def test_inclusive_extent_is_closed_source_derived_and_donor_only(self):
        generator = self._inclusive_extent_generator()
        self.assertEqual(
            byte_identity.render_inclusive_extent_assignment_input(
                generator["params"]),
            b"\t\tdesc.width = video_param.GetRect().GetWidth();\n",
        )
        self.assertEqual(
            byte_identity.render_source_overlay_generator(generator),
            b"\t\tMxS32 width = video_param.GetRect().GetRight() - "
            b"video_param.GetRect().GetLeft();\n"
            b"\t\t++width;\n"
            b"#if defined(_MSC_VER) && defined(_M_IX86)\n"
            b"\t\t__asm {\n\t\t}\n#endif\n"
            b"\t\tdesc.width = width;\n",
        )
        roles = byte_identity.source_overlay_expected_identifier_roles(
            generator["kind"], generator["params"])
        self.assertEqual(roles["emitted_identifiers"], [])
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "donor-only"):
            byte_identity.assert_source_permutations_are_donor_only(
                {"generator": generator})

    def test_inclusive_extent_refuses_type_role_barrier_and_layout_escape(self):
        mutations = (
            {"type": "MxS32*"},
            {"type": "ArbitraryCoordinate"},
            {"id": "video_param"},
            {"source": {"object": "video_param",
                        "aggregate_accessor": "GetWidth"}},
            {"upper_endpoint_accessor": "GetLeft"},
            {"barrier": "free_form_assembly"},
            {"nl": False},
            {"text": "arbitrary source"},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(
                    byte_identity.ByteIdentityError):
                self._inclusive_extent_generator(**mutation)

    def test_live_inclusive_extent_witness_and_canonical_overlay_are_exact(self):
        source, recipe, function, canonical, overlaid_paths = (
            self._live_inclusive_extent_case())
        self.assertEqual(
            function["splice_class"],
            byte_identity.RETAIL_EXACT_SOURCE_EQUAL_BODY_CLASS)
        self.assertEqual(function["retail_image_target"], "lego1")
        self.assertNotIn("instruction_ranges", function)
        self.assertEqual(function["expected_changed_offsets"],
                         [489, 490, 491, 492, 493, 496, 497, 498, 500])
        self.assertEqual(
            [(item["offset"], item["width"], item["type"],
              item["target"], item["target_section"],
              item["target_value"], item["target_type"],
              item["target_storage"])
             for item in function["source_fpo_identity"]["debug_s"]
             ["expected_extra_relocations"]],
            [(66, 4, 11, "$done$35563", 39, 646, 0, 6),
             (70, 2, 10, "$done$35563", 39, 646, 0, 6)],
        )
        detail = byte_identity.require_target_source_refactor_recipe_policy(
            recipe, function, ROOT, source, "fixture", canonical,
            overlaid_paths)
        self.assertEqual(detail["inclusive_extent_include_edges"], 3)
        self.assertEqual(detail["inclusive_extent_semantic_lines"], 6)
        self.assertEqual(detail["inclusive_extent_coordinate_type"], "MxS32")
        self.assertEqual(detail["concrete_accessor_shadow_count"], 0)
        self.assertEqual(detail["fresh_local_identifier"], "width")
        self.assertGreater(detail["fresh_local_disjoint_occurrences"], 0)

        rendered = byte_identity.render_donor_source_overlay(
            recipe, ROOT)[source]
        self.assertEqual(hashlib.sha256(rendered).hexdigest(),
                         "1ee6f076b6189a719315185a494518b94aae689fc612989111f730b73e9cec0f")
        operation = next(
            item for item in recipe["renderings"][0]["operations"]
            if item.get("id") == "op_mxdisplay_create_inclusive_extent")
        generator = byte_identity.validate_source_overlay_generator(
            operation["gen"], "fixture.generator")
        output = byte_identity.render_source_overlay_generator(generator)
        original = byte_identity.render_inclusive_extent_assignment_input(
            generator["params"])
        self.assertEqual(hashlib.sha256(output).hexdigest(),
                         "6c80fc83cadd89378334277273cae6057a7b564436c0d861b5c832c68c8c191b")
        seed = rendered.replace(output, original, 1)
        source_detail = byte_identity.require_target_source_refactor_identity(
            seed, rendered, function["target_source_refactor"], "fixture")
        self.assertEqual(source_detail["seed_target_source_size"], 3088)
        self.assertEqual(source_detail["donor_target_source_size"], 3220)

        omitted = copy.deepcopy(recipe)
        omitted["renderings"][0]["operations"].pop(0)
        omitted_rendered = byte_identity.render_donor_source_overlay(
            omitted, ROOT, repin=True)[source]
        omitted["renderings"][0]["rendered_sha256"] = hashlib.sha256(
            omitted_rendered).hexdigest()
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "omits a canonical"):
            byte_identity.require_target_source_refactor_recipe_policy(
                omitted, function, ROOT, source, "fixture", canonical,
                overlaid_paths)

        drifted = copy.deepcopy(recipe)
        drifted["renderings"][0]["operations"][0]["gen"]["style"] = "angle"
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "canonical source operation differs"):
            byte_identity.require_target_source_refactor_recipe_policy(
                drifted, function, ROOT, source, "fixture", canonical,
                overlaid_paths)

        wrong_formula = copy.deepcopy(function)
        wrong_formula["target_source_refactor"]["semantic_witness"][
            "upper_member"] = "m_bottom"
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "semantic declaration"):
            byte_identity.require_target_source_refactor_recipe_policy(
                recipe, wrong_formula, ROOT, source, "fixture", canonical,
                overlaid_paths)

        wrong_include = copy.deepcopy(function)
        wrong_include["target_source_refactor"]["semantic_witness"][
            "source_owner_header"]["unit_include_range_pin"][
                "baseline_sha256"] = "0" * 64
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "input-range pins"):
            byte_identity.require_target_source_refactor_recipe_policy(
                recipe, wrong_include, ROOT, source, "fixture", canonical,
                overlaid_paths)

        witness_path = function["target_source_refactor"][
            "semantic_witness"]["extent_header"]["path"]
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "effective source overlay"):
            byte_identity.require_target_source_refactor_recipe_policy(
                recipe, function, ROOT, source, "fixture", canonical,
                overlaid_paths | {witness_path})

    def test_discarded_increment_and_carrier_are_closed_typed_forms(self):
        generator = byte_identity.validate_source_overlay_generator({
            "k": "discarded_increment", "id": "cursor",
            "declaration_indent": "\t\t",
        }, "fixture.generator")
        self.assertEqual(
            byte_identity.render_discarded_postfix_increment_input(
                generator["params"]),
            b"\t\tcursor++;\n",
        )
        self.assertEqual(
            byte_identity.render_source_overlay_generator(generator),
            b"\t\t++cursor;\n",
        )
        self.assertEqual(
            byte_identity.source_overlay_expected_identifier_roles(
                generator["kind"], generator["params"]
            )["emitted_identifiers"],
            [],
        )
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "donor-only"):
            byte_identity.assert_source_permutations_are_donor_only({
                "generator": generator,
            })
        for mutation in (
            {"nl": False}, {"text": "open source"},
            {"declaration_indent": ""}, {"id": "cursor++"},
        ):
            candidate = {
                "k": "discarded_increment", "id": "cursor",
                "declaration_indent": "\t\t", **mutation,
            }
            with self.subTest(mutation=mutation), self.assertRaises(
                    byte_identity.ByteIdentityError):
                byte_identity.validate_source_overlay_generator(
                    candidate, "fixture.generator")

        (_, _, recipe, _, _, _, _, _) = (
            self._live_discarded_increment_case())
        carrier = recipe["compiler_state_carrier"]
        normalized = (
            byte_identity.validate_donor_source_compiler_state_carrier(
                carrier, "fixture.carrier")
        )
        self.assertEqual(normalized["header_count"], 8)
        self.assertEqual(normalized["seat_count"], 17)
        self.assertEqual(normalized["width"], 2)
        for key, value in (
            ("generated_declarations_sha256", "0" * 64),
            ("placement", "arbitrary_seat"),
            ("seat_prefix", carrier["header_prefix"]),
        ):
            bad = copy.deepcopy(carrier)
            bad[key] = value
            with self.subTest(key=key), self.assertRaises(
                    byte_identity.ByteIdentityError):
                byte_identity.validate_donor_source_compiler_state_carrier(
                    bad, "fixture.carrier")

    def test_live_discarded_increment_semantics_render_and_role_are_exact(self):
        (manifest, source, recipe, function, canonical, overlaid_paths,
         compiler_root, sealed_trees) = self._live_discarded_increment_case()
        detail = byte_identity.require_target_source_refactor_recipe_policy(
            recipe, function, ROOT, source, "fixture", canonical,
            overlaid_paths,
            proof_key="instruction_donor_source_refactor",
            compiler_root=compiler_root,
            sealed_include_trees=sealed_trees,
        )
        self.assertEqual(detail["refactor_operation_ids"],
                         ["op_discarded_iterator_increment"])
        self.assertEqual(detail["discarded_increment_include_edges"], 10)
        self.assertEqual(detail["discarded_increment_iterator_uses"], 6)
        self.assertEqual(detail["compiler_state_carrier_identifier_count"],
                         25)

        rendered = byte_identity.render_donor_source_overlay(
            recipe, ROOT, canonical_operations=canonical)[source]
        self.assertEqual(
            hashlib.sha256(rendered).hexdigest(),
            "620ae3b60263c140dfd23126cc5b2257c4a15f8235244a11168912391410b575",
        )
        clean = (ROOT / source).read_bytes()
        proof_detail = byte_identity.require_target_source_refactor_identity(
            clean, rendered,
            function["instruction_donor_source_refactor"], "fixture")
        self.assertEqual(proof_detail["seed_target_source_size"], 1016)
        self.assertEqual(proof_detail["donor_target_source_size"], 1016)

        no_replay = copy.deepcopy(recipe)
        no_replay.pop("canonical_overlay_replay")
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "omits a canonical"):
            byte_identity.require_target_source_refactor_recipe_policy(
                no_replay, function, ROOT, source, "fixture", canonical,
                overlaid_paths,
                proof_key="instruction_donor_source_refactor",
                compiler_root=compiler_root,
                sealed_include_trees=sealed_trees,
            )

        witness_path = function["instruction_donor_source_refactor"][
            "semantic_witness"]["source_alias_header"]["path"]
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "effective source overlay"):
            byte_identity.require_target_source_refactor_recipe_policy(
                recipe, function, ROOT, source, "fixture", canonical,
                overlaid_paths | {witness_path},
                proof_key="instruction_donor_source_refactor",
                compiler_root=compiler_root,
                sealed_include_trees=sealed_trees,
            )

        unit = next(
            item for item in manifest["translation_units"]
            if item["source"] == source)
        live = next(
            item for item in unit["functions"]
            if item.get("splice_class")
            == byte_identity.SOURCE_INSTRUCTION_HYBRID_RESIZE_CLASS)
        unit["functions"].append({
            "mangled": "?OrdinarySourceInstructionReuse@@YAXXZ",
            "donor": live["instruction_donor"],
            "splice_class": "equal_body_strict",
        })
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary).resolve()
            manifest_path = temporary / "manifest.json"
            build_dir = temporary / "build"
            build_dir.mkdir()
            manifest_path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                        "total primary"):
                byte_identity.validate_manifest(
                    manifest_path, ROOT, build_dir)

    def test_discarded_increment_rejects_repinned_copy_and_state_effects(self):
        (_, source, recipe, function, canonical, overlaid_paths,
         compiler_root, sealed_trees) = self._live_discarded_increment_case()
        proof = function["instruction_donor_source_refactor"]
        witness = proof["semantic_witness"]
        operation = next(
            item for item in recipe["renderings"][0]["operations"]
            if item["id"] == proof["operation_ids"][0]
        )
        params = byte_identity.validate_source_overlay_generator(
            operation["gen"], "fixture.generator")["params"]
        unit_data = (ROOT / source).read_bytes()
        target = byte_identity.select_source_permutation_window(
            unit_data, proof, "fixture")

        def range_pin(data):
            return {
                "baseline_sha256": hashlib.sha256(data).hexdigest(),
                "baseline_size": len(data),
                "baseline_line_count": len(data.splitlines()),
                "baseline_significant_token_sha256":
                    byte_identity.source_overlay_significant_sha256(data),
            }

        def class_range(data, outer, nested=None):
            tokens = byte_identity._semantic_significant_tokens(data)
            _, opening, closing = byte_identity._unique_class_body(
                tokens, outer, "fixture")
            start = next(
                index for index in range(opening)
                if tokens[index][0] in {"class", "struct"}
                and tokens[index + 1][0] == outer)
            if nested is not None:
                start, opening, closing = (
                    byte_identity._unique_nested_class_body(
                        tokens, opening, closing, nested, "fixture")
                )
            begin, end = byte_identity._physical_source_range_for_tokens(
                data, tokens, start, closing, "fixture")
            return data[begin:end]

        compiler_files = ("MAP", "XTREE", "ITERATOR", "UTILITY",
                          "MEMORY", "XMEMORY")
        mutations = (
            (
                "copy",
                "XTREE",
                b"\tprotected:\r\n\t\t_Nodeptr _Ptr;",
                b"\t\titerator(iterator& _X)\r\n"
                b"\t\t\t: _Ptr(_X._Ptr) {}\r\n"
                b"\tprotected:\r\n\t\t_Nodeptr _Ptr;",
                "user-defined copy",
            ),
            (
                "member",
                "XTREE",
                b"\t\t_Nodeptr _Ptr;\r\n\t\t};",
                b"\t\t_Nodeptr _Ptr;\r\n"
                b"\t\t_Nodeptr _Other;\r\n\t\t};",
                "state beyond",
            ),
            (
                "base",
                "UTILITY",
                b"\tstruct _Bidit : public "
                b"iterator<bidirectional_iterator_tag,\r\n"
                b"\t\t_TYPE, _D> {};",
                b"\tstruct _Bidit : public "
                b"iterator<bidirectional_iterator_tag,\r\n"
                b"\t\t_TYPE, _D> {_TYPE _State;};",
                "not empty",
            ),
        )
        for role, filename, before, after, message in mutations:
            with self.subTest(role=role), tempfile.TemporaryDirectory() \
                    as temporary:
                temporary = Path(temporary).resolve()
                include = temporary / "include"
                include.mkdir()
                for name in compiler_files:
                    (include / name).write_bytes(
                        (compiler_root / "include" / name).read_bytes())
                changed_path = include / filename
                changed = changed_path.read_bytes()
                self.assertEqual(changed.count(before), 1)
                changed = changed.replace(before, after, 1)
                changed_path.write_bytes(changed)

                mutated = copy.deepcopy(proof)
                mutated_witness = mutated["semantic_witness"]
                if filename == "XTREE":
                    spec = mutated_witness["tree_header"]
                    spec["source_sha256"] = hashlib.sha256(changed).hexdigest()
                    spec["iterator_class_range_pin"] = range_pin(
                        class_range(changed, "_Tree", "iterator"))
                else:
                    spec = mutated_witness["utility_header"]
                    spec["source_sha256"] = hashlib.sha256(changed).hexdigest()
                    spec["bidirectional_base_range_pin"] = range_pin(
                        class_range(changed, "_Bidit"))
                with self.assertRaisesRegex(
                        byte_identity.ByteIdentityError, message):
                    byte_identity.require_discarded_increment_semantic_identity(
                        ROOT, source, unit_data, target, mutated, params,
                        "fixture", compiler_root=temporary,
                        sealed_include_trees=[{
                            "role": "msvc_include", "path": "include",
                        }],
                    )

    def test_manifest_rejects_discarded_increment_witness_header_overlay(self):
        (manifest, _, _, function, _, _, _, _) = (
            self._live_discarded_increment_case())
        witness_path = function["instruction_donor_source_refactor"][
            "semantic_witness"]["source_alias_header"]["path"]
        manifest["source_overlay"]["outputs"].append({"path": witness_path})
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary).resolve()
            manifest_path = temporary / "manifest.json"
            build_dir = temporary / "build"
            build_dir.mkdir()
            manifest_path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                        "effective source overlay"):
                byte_identity.validate_manifest(
                    manifest_path, ROOT, build_dir)

    def test_manifest_preflight_rejects_unbound_raw_discarded_increment_donor(self):
        manifest, _, _, function, _, _, _, _ = (
            self._live_discarded_increment_case())
        for unit in manifest["translation_units"]:
            unit["functions"] = [
                item for item in unit.get("functions", [])
                if item.get("mangled") != function["mangled"]
            ]
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary).resolve()
            manifest_path = temporary / "manifest.json"
            build_dir = temporary / "build"
            build_dir.mkdir()
            manifest_path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                        "bound exactly once"):
                byte_identity.validate_manifest(
                    manifest_path, ROOT, build_dir)

    def test_manifest_preflight_rejects_ordinary_primary_increment_donor(self):
        manifest, _, _, function, _, _, _, _ = (
            self._live_discarded_increment_case())
        owner_unit = next(
            unit for unit in manifest["translation_units"]
            if any(item.get("mangled") == function["mangled"]
                   for item in unit.get("functions", [])))
        owner_unit["functions"].append({
            "mangled": "?OrdinaryIncrementReuseFixture@@YAXXZ",
            "donor": function["instruction_donor"],
            "splice_class": "equal_body_strict",
        })
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary).resolve()
            manifest_path = temporary / "manifest.json"
            build_dir = temporary / "build"
            build_dir.mkdir()
            manifest_path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                        "exactly one total primary"):
                byte_identity.validate_manifest(
                    manifest_path, ROOT, build_dir)

    def test_manifest_rejects_inclusive_extent_witness_header_overlay(self):
        manifest = json.loads(
            (TOOLS / "byte_identity_manifest.json").read_text())
        function = next(
            function
            for unit in manifest["translation_units"]
            for function in unit.get("functions", [])
            if function.get("target_source_refactor", {}).get("kind")
            == "inclusive_extent_assignment_v1")
        witness_path = function["target_source_refactor"][
            "semantic_witness"]["extent_header"]["path"]
        manifest["source_overlay"]["outputs"].append({
            "path": witness_path,
        })
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary).resolve()
            manifest_path = temporary / "manifest.json"
            build_dir = temporary / "build"
            build_dir.mkdir()
            manifest_path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                        "effective source overlay"):
                byte_identity.validate_manifest(
                    manifest_path, ROOT, build_dir)

    def test_manifest_rejects_repin_of_concrete_extent_accessor_shadow(self):
        manifest = json.loads(
            (TOOLS / "byte_identity_manifest.json").read_text())
        function = next(
            function
            for unit in manifest["translation_units"]
            for function in unit.get("functions", [])
            if function.get("target_source_refactor", {}).get("kind")
            == "inclusive_extent_assignment_v1")
        witness = function["target_source_refactor"]["semantic_witness"]
        extent = witness["extent_header"]
        original = (ROOT / extent["path"]).read_bytes()
        class_start = original.index(
            b"class MxRect32 : public MxRect<MxS32> {\n")
        class_close = original.index(b"};\n", class_start)
        shadow = b"\tMxS32 GetWidth() const { return 0; }\n"
        changed = original[:class_close] + shadow + original[class_close:]
        changed_close = changed.index(b"};\n", class_start) + 3
        class_range = changed[class_start:changed_close]
        extent["source_sha256"] = hashlib.sha256(changed).hexdigest()
        extent["concrete_class_range_pin"] = {
            "baseline_sha256": hashlib.sha256(class_range).hexdigest(),
            "baseline_size": len(class_range),
            "baseline_line_count": len(class_range.splitlines()),
            "baseline_significant_token_sha256":
                byte_identity.source_overlay_significant_sha256(class_range),
        }
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary).resolve()
            source_root = temporary / "source"
            header_path = source_root / extent["path"]
            header_path.parent.mkdir(parents=True)
            header_path.write_bytes(changed)
            build_dir = temporary / "build"
            build_dir.mkdir()
            manifest_path = temporary / "manifest.json"
            manifest_path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                        "shadows an inherited accessor"):
                byte_identity.validate_manifest(
                    manifest_path, source_root, build_dir)

    def test_inclusive_extent_semantic_source_refuses_final_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            real = root / "real.h"
            real.write_bytes(b"class Witness {};\n")
            link = root / "witness.h"
            link.symlink_to(real.name)
            spec = {
                "path": "witness.h",
                "source_sha256": hashlib.sha256(real.read_bytes()).hexdigest(),
            }
            with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                        "redirected or non-regular"):
                byte_identity._read_pinned_semantic_source(
                    root, spec, "fixture")

    def test_inclusive_extent_local_may_reuse_only_a_disjoint_scope_name(self):
        source = (
            b"Owner::Build() {\n"
            b"  if (flag) { int width = 1; consume(width); }\n"
            b"  else { target(); }\n"
            b"}\n"
        )
        seat = source.index(b"target")
        detail = byte_identity.require_identifier_fresh_at_source_seat(
            source, seat, "width", "fixture")
        self.assertEqual(detail["fresh_local_disjoint_occurrences"], 2)

        visible = source.replace(b"  if (flag) { int width = 1; "
                                 b"consume(width); }\n", b"  int width;\n")
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "visible ancestor"):
            byte_identity.require_identifier_fresh_at_source_seat(
                visible, visible.index(b"target"), "width", "fixture")
        same_block = source.replace(b"  else { target(); }",
                                    b"  else { int width; target(); }")
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "destination block"):
            byte_identity.require_identifier_fresh_at_source_seat(
                same_block, same_block.index(b"target"), "width", "fixture")

    def test_manifest_rejects_ordinary_reuse_of_inclusive_extent_donor(self):
        manifest = json.loads(
            (TOOLS / "byte_identity_manifest.json").read_text())
        unit = next(
            item for item in manifest["translation_units"]
            if any(function.get("target_source_refactor", {}).get("kind")
                   == "inclusive_extent_assignment_v1"
                   for function in item.get("functions", [])))
        function = next(
            item for item in unit["functions"]
            if item.get("target_source_refactor", {}).get("kind")
            == "inclusive_extent_assignment_v1")
        unit["functions"].append({
            "mangled": "?OrdinaryInclusiveExtentReuse@@YAXXZ",
            "donor": function["donor"],
            "splice_class": "equal_body_strict",
        })
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary).resolve()
            manifest_path = temporary / "manifest.json"
            build_dir = temporary / "build"
            build_dir.mkdir()
            manifest_path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                        "exactly one total primary"):
                byte_identity.validate_manifest(
                    manifest_path, ROOT, build_dir)

    def test_source_refactor_donor_has_one_source_aware_primary_use(self):
        byte_identity.require_source_refactor_donor_bindings(
            {"d_refactor"}, ["d_refactor"], ["d_refactor"], [],
            "fixture")

        # A second ordinary function using the same donor would dispatch a
        # composer with no source-refactor proof and could import collateral.
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "exactly one total primary"):
            byte_identity.require_source_refactor_donor_bindings(
                {"d_refactor"}, ["d_refactor", "d_refactor"],
                ["d_refactor"], [], "fixture")

        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "non-primary roles"):
            byte_identity.require_source_refactor_donor_bindings(
                {"d_refactor"}, ["d_refactor"], ["d_refactor"],
                ["d_refactor"], "fixture")

    def test_manifest_rejects_second_ordinary_use_of_live_refactor_donor(self):
        manifest = json.loads(
            (TOOLS / "byte_identity_manifest.json").read_text())
        matches = [
            (unit, function)
            for unit in manifest["translation_units"]
            for function in unit.get("functions", [])
            if function.get("target_source_refactor", {}).get("kind")
            == "fixed_array_fill_loop_v1"
        ]
        self.assertEqual(len(matches), 1)
        unit, function = matches[0]
        unit["functions"].append({
            "mangled": "?OrdinaryReuseFixture@@YAXXZ",
            "donor": function["donor"],
            "splice_class": "equal_body_strict",
        })
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary).resolve()
            manifest_path = temporary / "manifest.json"
            build_dir = temporary / "build"
            build_dir.mkdir()
            manifest_path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                        "exactly one total primary"):
                byte_identity.validate_manifest(
                    manifest_path, ROOT, build_dir)

    def test_fixed_array_declaration_requires_unique_direct_header_include(self):
        include_line = b'#include "array_owner.h"\n'
        include_pin = byte_identity.validate_source_overlay_range_pin({
            "baseline_sha256": hashlib.sha256(include_line).hexdigest(),
            "baseline_size": len(include_line),
            "baseline_line_count": 1,
            "baseline_significant_token_sha256":
                byte_identity.source_overlay_significant_sha256(
                    include_line),
        }, "fixture.include_pin")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "include").mkdir()
            (root / "source").mkdir()
            header = root / "include" / "array_owner.h"
            header.write_bytes(b"struct ArrayOwner {};\n")
            declaration = {
                "path": "include/array_owner.h",
                "direct_include_range_pin": include_pin,
            }
            detail = byte_identity.require_direct_array_header_include(
                root, "source/unit.cpp", include_line, declaration, header,
                "fixture")
            self.assertEqual(detail["array_declaration_include"],
                             "array_owner.h")

            with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                        "does not directly include"):
                byte_identity.require_direct_array_header_include(
                    root, "source/unit.cpp", b'#include "other.h"\n',
                    declaration, header, "fixture")

            (root / "other").mkdir()
            (root / "other" / "array_owner.h").write_bytes(
                b"struct WrongOwner {};\n")
            with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                        "unique checked-in"):
                byte_identity.require_direct_array_header_include(
                    root, "source/unit.cpp", include_line, declaration,
                    header, "fixture")

    def test_fixed_array_owner_and_unshadowed_member_are_exact(self):
        self.assertEqual(
            byte_identity.decorated_member_owner_identifier(
                "??0ArrayOwner@@QAE@XZ", "fixture"),
            "ArrayOwner",
        )
        self.assertEqual(
            byte_identity.decorated_member_owner_identifier(
                "?Fill@ArrayOwner@@QAEXXZ", "fixture"),
            "ArrayOwner",
        )
        self.assertEqual(
            byte_identity.decorated_member_owner_identifier(
                "?Fill@ArrayOwnerExtra@@QAEXXZ", "fixture"),
            "ArrayOwnerExtra",
        )
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "closed form"):
            byte_identity.decorated_member_owner_identifier(
                "?Fill@ArrayOwnerExtra@QAEXXZ", "fixture")

        statement = b"  memset(slots, -1, sizeof(slots));\n"
        byte_identity.require_fixed_array_member_use_is_unshadowed(
            b"ArrayOwner::ArrayOwner() {\n" + statement + b"}\n",
            statement, "slots", "fixture")
        shadowed_sources = (
            b"ArrayOwner::ArrayOwner(int slots) {\n" + statement + b"}\n",
            b"ArrayOwner::ArrayOwner() {\n  int slots[7];\n"
            + statement + b"}\n",
        )
        for source in shadowed_sources:
            with self.subTest(source=source), self.assertRaisesRegex(
                    byte_identity.ByteIdentityError, "shadowed"):
                byte_identity.require_fixed_array_member_use_is_unshadowed(
                    source, statement, "slots", "fixture")

    def test_live_fixed_array_fill_binds_extent_owner_and_fresh_index(self):
        source, recipe, function = self._live_fixed_array_case()
        detail = byte_identity.require_target_source_refactor_recipe_policy(
            recipe, function, ROOT, source, "fixture")
        self.assertEqual(detail["array_extent"], 5)
        self.assertEqual(detail["array_declaration_include_owner"], source)
        self.assertEqual(detail["array_member_source_occurrences"], 2)
        self.assertEqual(detail["refactor_operation_ids"],
                         ["op_fixed_array_fill_loop"])

        rendered = byte_identity.render_donor_source_overlay(
            recipe, ROOT)[source]
        operation = next(
            item for item in recipe["renderings"][0]["operations"]
            if item.get("id") in
            function["target_source_refactor"]["operation_ids"]
        )
        generator = byte_identity.validate_source_overlay_generator(
            operation["gen"], "fixture.generator")
        output = byte_identity.render_source_overlay_generator(generator)
        original = byte_identity.render_fixed_array_fill_loop_input(
            generator["params"])
        self.assertEqual(hashlib.sha256(output).hexdigest(),
                         "5e74cd70d4accadd59ab40111c51afdcb1b684979ab7345e232a10af2c4892fb")
        self.assertEqual(rendered.count(output), 1)
        seed = rendered.replace(output, original, 1)
        source_detail = byte_identity.require_target_source_refactor_identity(
            seed, rendered, function["target_source_refactor"], "fixture")
        self.assertEqual(source_detail["seed_target_source_size"], 663)
        self.assertEqual(source_detail["donor_target_source_size"], 671)

        mismatched = copy.deepcopy(recipe)
        mismatch_operation = next(
            item for item in mismatched["renderings"][0]["operations"]
            if item.get("id") in
            function["target_source_refactor"]["operation_ids"]
        )
        mismatch_operation["gen"]["count"] -= 1
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "bound differs"):
            byte_identity.require_target_source_refactor_recipe_policy(
                mismatched, function, ROOT, source, "fixture")

        structurally_wrong_extent = copy.deepcopy(recipe)
        extent_operation = next(
            item for item in
            structurally_wrong_extent["renderings"][0]["operations"]
            if item.get("id") in
            function["target_source_refactor"]["operation_ids"]
        )
        extent_operation["gen"]["count"] -= 1
        extent_function = copy.deepcopy(function)
        extent_function["target_source_refactor"][
            "array_declaration"]["extent"] -= 1
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "declaration is absent"):
            byte_identity.require_target_source_refactor_recipe_policy(
                structurally_wrong_extent, extent_function, ROOT, source,
                "fixture")

        wrong_element_type = copy.deepcopy(function)
        wrong_element_type["target_source_refactor"]["array_declaration"][
            "element_type"] = byte_identity.validate_source_overlay_cpp_type(
                "unsigned int", "fixture.element_type")
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "declaration is absent"):
            byte_identity.require_target_source_refactor_recipe_policy(
                recipe, wrong_element_type, ROOT, source, "fixture")

        stale_index = copy.deepcopy(recipe)
        stale_operation = next(
            item for item in stale_index["renderings"][0]["operations"]
            if item.get("id") in
            function["target_source_refactor"]["operation_ids"]
        )
        proof = function["target_source_refactor"]
        clean = (ROOT / source).read_bytes()
        target = byte_identity.select_source_permutation_window(
            clean, proof, "fixture")
        reserved = {
            stale_operation["gen"]["array"],
            stale_operation["gen"]["index"],
        }
        existing = next(
            token for token, _, _ in byte_identity.source_overlay_tokens(target)
            if byte_identity.SOURCE_OVERLAY_IDENTIFIER_RE.fullmatch(token)
            and token not in reserved
        )
        stale_operation["gen"]["index"] = existing
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "not fresh"):
            byte_identity.require_target_source_refactor_recipe_policy(
                stale_index, function, ROOT, source, "fixture")

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


def make_fpo_instruction_mosaic_coff(
    *, donor=False, source_refactor=False, debug_label_relocations=False,
):
    """Turn the small EH fixture into an equal-size FPO mosaic fixture."""
    data = make_divergent_coff(
        debug_tail_extra=15 if donor and source_refactor else 0,
        debug_label_relocations=debug_label_relocations)
    parsed = byte_identity.CoffObject(data)
    primary = parsed.function_section(TARGET_SYMBOL)
    fpo_section = parsed.sections[1]
    fpo_symbol_index, _ = byte_identity.section_symbol(parsed, fpo_section)
    output = bytearray(data)
    output[fpo_section["header_offset"]:
           fpo_section["header_offset"] + 8] = b".debug$F"
    output[parsed.symbol_offset + fpo_symbol_index * 18:
           parsed.symbol_offset + fpo_symbol_index * 18 + 8] = b".debug$F"
    fpo = struct.pack("<IIIHBB", 0, SEED_SIZE, 2, 1, 2, 0x10)
    output[fpo_section["raw_offset"]:
           fpo_section["raw_offset"] + 16] = fpo
    struct.pack_into("<I", output, primary["line_offset"] + 6, 24)
    encoding = bytes.fromhex("8b590441" if donor else "8b410443")
    output[primary["raw_offset"] + 24:
           primary["raw_offset"] + 28] = encoding
    if donor:
        output[primary["raw_offset"] + 29] ^= 0x5A
        debug_s = parsed.sections[2]
        output[debug_s["raw_offset"] + debug_s["raw_size"] - 1] ^= 1
    return bytes(output)


def make_cross_tu_complete_target_coff(role):
    """Build a resize fixture with one complete ordinary FPO closure."""
    if role not in {"seed", "target", "complete"}:
        raise ValueError(role)
    data = make_divergent_coff(
        donor=role != "seed", swap_text_sections=role == "complete")
    parsed = byte_identity.CoffObject(data)
    primary = parsed.function_section(TARGET_SYMBOL)
    fpo_section = parsed.sections[1]
    fpo_symbol_index, _ = byte_identity.section_symbol(parsed, fpo_section)
    output = bytearray(data)
    output[fpo_section["header_offset"]:
           fpo_section["header_offset"] + 8] = b".debug$F"
    output[parsed.symbol_offset + fpo_symbol_index * 18:
           parsed.symbol_offset + fpo_symbol_index * 18 + 8] = b".debug$F"
    locals_count = 1 if role == "target" else 2
    fpo = struct.pack(
        "<IIIHBB", 0, primary["raw_size"], locals_count, 1, 2, 0x10)
    output[fpo_section["raw_offset"]:
           fpo_section["raw_offset"] + 16] = fpo
    if role == "target":
        output[primary["raw_offset"] + 24] ^= 0x5A
        struct.pack_into("<I", output, primary["line_offset"] + 6, 2)
        debug_s = parsed.sections[2]
        struct.pack_into("<I", output, debug_s["raw_offset"] + 20, 1)
    elif role == "complete":
        debug_s = parsed.sections[2]
        output[debug_s["raw_offset"] + 36:
               debug_s["raw_offset"] + 38] = b"\x34\x12"
    return bytes(output)


class CrossTuCompleteTargetResizeTests(unittest.TestCase):
    """A different TU may supply one whole target, never code ranges."""

    @staticmethod
    def _file_aux(coff, primary):
        function_index, _ = byte_identity.function_symbol(
            coff, TARGET_SYMBOL, primary["number"])
        index, symbol = max(
            (index, symbol) for index, symbol in coff.symbols.items()
            if index < function_index and symbol["name"] == ".file"
            and symbol["storage"] == 103)
        start = coff.symbol_offset + (index + 1) * 18
        return coff.data[start:start + symbol["aux_count"] * 18]

    def fixture(self):
        seed = make_cross_tu_complete_target_coff("seed")
        target = make_cross_tu_complete_target_coff("target")
        complete = make_cross_tu_complete_target_coff("complete")
        seed_coff = byte_identity.CoffObject(seed)
        target_coff = byte_identity.CoffObject(target)
        complete_coff = byte_identity.CoffObject(complete)
        seed_primary = seed_coff.function_section(TARGET_SYMBOL)
        target_primary = target_coff.function_section(TARGET_SYMBOL)
        complete_primary = complete_coff.function_section(TARGET_SYMBOL)

        normalized = bytearray(target)
        normalized[target_primary["raw_offset"]:
                   target_primary["raw_offset"]
                   + target_primary["raw_size"]] = byte_identity.coff_body(
                       complete_coff, complete_primary)
        complete_lines = bytearray(byte_identity._coff_table_bytes(
            complete_coff, complete_primary, "lines"))
        target_index, _ = byte_identity.function_symbol(
            target_coff, TARGET_SYMBOL, target_primary["number"])
        complete_lines[:4] = target_index.to_bytes(4, "little")
        normalized[target_primary["line_offset"]:
                   target_primary["line_offset"]
                   + len(complete_lines)] = complete_lines
        target_fpo = byte_identity._comdat_child(
            target_coff, target_primary, ".debug$F")
        complete_fpo = byte_identity._comdat_child(
            complete_coff, complete_primary, ".debug$F")
        normalized[target_fpo["raw_offset"]:
                   target_fpo["raw_offset"]
                   + target_fpo["raw_size"]] = byte_identity.coff_body(
                       complete_coff, complete_fpo)
        target_debug = byte_identity._comdat_child(
            target_coff, target_primary, ".debug$S")
        complete_debug = byte_identity._comdat_child(
            complete_coff, complete_primary, ".debug$S")
        normalized_debug = bytearray(byte_identity.coff_body(
            target_coff, target_debug))
        normalized_debug[16:28] = byte_identity.coff_body(
            complete_coff, complete_debug)[16:28]
        normalized[target_debug["raw_offset"]:
                   target_debug["raw_offset"]
                   + target_debug["raw_size"]] = normalized_debug
        normalized = bytes(normalized)
        normalized_coff = byte_identity.CoffObject(normalized)
        normalized_primary = normalized_coff.function_section(TARGET_SYMBOL)
        normalized_fpo = byte_identity._comdat_child(
            normalized_coff, normalized_primary, ".debug$F")
        normalized_debug_section = byte_identity._comdat_child(
            normalized_coff, normalized_primary, ".debug$S")
        retail = retail_body_for(normalized)

        def count_functions(coff):
            return sum(byte_identity.function_multiset(coff).values())

        def count_comdats(coff):
            return sum(
                byte_identity.comdat_primary_identity_multiset(coff).values())

        function = {
            "mangled": TARGET_SYMBOL,
            "donor": "d_aaaaaaaaaaaa",
            "complete_donor": "d_bbbbbbbbbbbb",
            "splice_class":
                byte_identity.CROSS_TU_COMPLETE_TARGET_RESIZE_CLASS,
            "expected_seed_length": seed_primary["raw_size"],
            "expected_donor_length": target_primary["raw_size"],
            "expected_linked_span": LINKED_SPAN,
            "expected_characteristics": target_primary["characteristics"],
            "expected_selection": byte_identity.section_definitions(
                target_coff)[target_primary["number"]]["selection"],
            "expected_seed_section_number": seed_primary["number"],
            "expected_seed_section_count": len(seed_coff.sections),
            "expected_seed_relocation_count":
                seed_primary["relocation_count"],
            "expected_seed_line_count": seed_primary["line_count"],
            "expected_seed_body_sha256": hashlib.sha256(
                byte_identity.coff_body(seed_coff, seed_primary)).hexdigest(),
            "expected_seed_metadata_sha256":
                byte_identity.instruction_mosaic_metadata_sha256(
                    seed_coff, seed_primary),
            "expected_seed_function_count": count_functions(seed_coff),
            "expected_seed_comdat_count": count_comdats(seed_coff),
            "expected_target_donor_section_number":
                target_primary["number"],
            "expected_target_donor_section_count": len(target_coff.sections),
            "expected_target_donor_relocation_count":
                target_primary["relocation_count"],
            "expected_target_donor_line_count": target_primary["line_count"],
            "expected_target_donor_body_sha256": hashlib.sha256(
                byte_identity.coff_body(
                    target_coff, target_primary)).hexdigest(),
            "expected_target_donor_metadata_sha256":
                byte_identity.instruction_mosaic_metadata_sha256(
                    target_coff, target_primary),
            "expected_target_donor_function_count":
                count_functions(target_coff),
            "expected_target_donor_comdat_count": count_comdats(target_coff),
            "expected_complete_donor_length": complete_primary["raw_size"],
            "expected_complete_donor_section_number":
                complete_primary["number"],
            "expected_complete_donor_section_count":
                len(complete_coff.sections),
            "expected_complete_donor_relocation_count":
                complete_primary["relocation_count"],
            "expected_complete_donor_line_count":
                complete_primary["line_count"],
            "expected_complete_donor_body_sha256": hashlib.sha256(
                byte_identity.coff_body(
                    complete_coff, complete_primary)).hexdigest(),
            "expected_complete_donor_metadata_sha256":
                byte_identity.instruction_mosaic_metadata_sha256(
                    complete_coff, complete_primary),
            "expected_complete_donor_function_count":
                count_functions(complete_coff),
            "expected_complete_donor_comdat_count":
                count_comdats(complete_coff),
            "expected_preceding_file_aux_sha256": hashlib.sha256(
                self._file_aux(target_coff, target_primary)).hexdigest(),
            "expected_donor_closure": [".debug$F", ".debug$S"],
            "expected_debug_s_diff_offsets": [20, 36, 37],
            "expected_codeview_type_index_offsets": [36],
            "expected_normalized_body_sha256": hashlib.sha256(
                byte_identity.coff_body(
                    normalized_coff, normalized_primary)).hexdigest(),
            "expected_normalized_line_sha256": hashlib.sha256(
                byte_identity._coff_table_bytes(
                    normalized_coff, normalized_primary, "lines")).hexdigest(),
            "expected_normalized_fpo_sha256": hashlib.sha256(
                byte_identity.coff_body(
                    normalized_coff, normalized_fpo)).hexdigest(),
            "expected_normalized_debug_s_sha256": hashlib.sha256(
                byte_identity.coff_body(
                    normalized_coff, normalized_debug_section)).hexdigest(),
            "expected_normalized_metadata_sha256":
                byte_identity.instruction_mosaic_metadata_sha256(
                    normalized_coff, normalized_primary),
            "retail_oracle": {
                "image": "LEGO1.DLL", "address": "0x1003cf20",
                "verdict": "MATCH", "length": target_primary["raw_size"],
            },
            "retail_relocations": relocation_oracle_for(normalized, retail),
        }
        return seed, target, complete, function, retail, normalized

    def compose(self, seed, target, complete, function, retail):
        return (
            byte_identity
            .compose_retail_exact_cross_tu_complete_target_resize(
                seed, target, complete, function, retail)
        )

    def test_positive_control_transfers_one_whole_target_and_closure(self):
        seed, target, complete, function, retail, normalized = self.fixture()
        composed, detail = self.compose(
            seed, target, complete, function, retail)
        checked = byte_identity.CoffObject(composed)
        normalized_coff = byte_identity.CoffObject(normalized)
        checked_primary = checked.function_section(TARGET_SYMBOL)
        normalized_primary = normalized_coff.function_section(TARGET_SYMBOL)
        self.assertEqual(
            byte_identity.coff_body(checked, checked_primary),
            byte_identity.coff_body(normalized_coff, normalized_primary))
        self.assertEqual(
            detail["splice_class"],
            byte_identity.CROSS_TU_COMPLETE_TARGET_RESIZE_CLASS)
        self.assertTrue(detail["retail_exact"])
        byte_identity.validate_donor_object_excluded(
            composed, [target, complete])

    def test_rejects_any_instruction_range_contract(self):
        seed, target, complete, function, retail, _ = self.fixture()
        function["instruction_ranges"] = []
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "may not carry instruction ranges"):
            self.compose(seed, target, complete, function, retail)

    def test_rejects_complete_body_drift(self):
        seed, target, complete, function, retail, _ = self.fixture()
        complete_coff = byte_identity.CoffObject(complete)
        primary = complete_coff.function_section(TARGET_SYMBOL)
        changed = bytearray(complete)
        changed[primary["raw_offset"] + 24] ^= 1
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "complete donor body differs"):
            self.compose(seed, target, bytes(changed), function, retail)

    def test_rejects_preceding_file_byte_drift(self):
        seed, target, complete, function, retail, _ = self.fixture()
        complete_coff = byte_identity.CoffObject(complete)
        primary = complete_coff.function_section(TARGET_SYMBOL)
        function_index, _ = byte_identity.function_symbol(
            complete_coff, TARGET_SYMBOL, primary["number"])
        file_index, _ = max(
            (index, symbol) for index, symbol in complete_coff.symbols.items()
            if index < function_index and symbol["name"] == ".file")
        changed = bytearray(complete)
        changed[complete_coff.symbol_offset + (file_index + 1) * 18] ^= 1
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "preceding .file bytes"):
            self.compose(seed, target, bytes(changed), function, retail)

    def test_source_renderer_rejects_path_source_and_render_drift(self):
        source = b"#include <set>\nint fixture;\n"
        forward = b"class FixtureCarrier;\n"
        rendered = b"\n".join(
            source.split(b"\n") + forward.rstrip(b"\n").split(b"\n"))
        recipe = {
            "role_policy":
                byte_identity.CROSS_TU_COMPLETE_TARGET_RECIPE_POLICY,
            "placement": "suffix",
            "donor_effective_source_sha256": hashlib.sha256(
                source).hexdigest(),
            "rendered_source_sha256": hashlib.sha256(rendered).hexdigest(),
            "rendered_source_size": len(rendered),
            "rendered_source_line_count": rendered.count(b"\n"),
        }
        self.assertEqual(
            byte_identity.render_cross_tu_complete_target_source(
                recipe, "owner.cpp", "donor.cpp", source, forward,
                "fixture"),
            rendered,
        )
        cases = [
            ("owner.cpp", "owner.cpp", source, recipe,
             "different translation unit"),
            ("owner.cpp", "donor.cpp", source + b" ", recipe,
             "effective donor source differs"),
            ("owner.cpp", "donor.cpp", source,
             {**recipe, "rendered_source_sha256": "0" * 64},
             "rendered cross-TU donor source differs"),
        ]
        for owner, donor, payload, candidate, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(
                    byte_identity.ByteIdentityError, message):
                byte_identity.render_cross_tu_complete_target_source(
                    candidate, owner, donor, payload, forward, "fixture")


class OrdinaryFpoInstructionMosaicTests(unittest.TestCase):
    """The ordinary carrier path admits one exact FPO/CodeView closure."""

    ROLE = byte_identity.ORDINARY_FPO_MOSAIC_ROLE_POLICY

    @staticmethod
    def _reseat_fpo_objects():
        """Seed/donor whose [16,24) window carries the same DIR32 record at
        offset 20 (seed: nop nop mov ecx,[disp32]) and 18 (donor: mov
        ecx,[disp32] nop nop); the compiler line row anchors at 16."""
        objects = []
        for donor in (False, True):
            data = bytearray(make_fpo_instruction_mosaic_coff(donor=donor))
            coff = byte_identity.CoffObject(bytes(data))
            primary = coff.function_section(TARGET_SYMBOL)
            at = primary["raw_offset"] + 16
            data[at:at + 8] = (bytes.fromhex("8b0d0000000090" "90") if donor
                               else bytes.fromhex("90908b0d00000000"))
            struct.pack_into("<I", data, primary["line_offset"] + 6, 16)
            if donor:
                struct.pack_into("<I", data,
                                 primary["relocation_offset"] + 20, 18)
            objects.append(bytes(data))
        return objects

    def fixture(self, *, reseat=False):
        if reseat:
            seed, donor = self._reseat_fpo_objects()
        else:
            seed = make_fpo_instruction_mosaic_coff()
            donor = make_fpo_instruction_mosaic_coff(donor=True)
        seed_coff = byte_identity.CoffObject(seed)
        donor_coff = byte_identity.CoffObject(donor)
        sp = seed_coff.function_section(TARGET_SYMBOL)
        dp = donor_coff.function_section(TARGET_SYMBOL)
        seed_body = byte_identity.coff_body(seed_coff, sp)
        donor_body = byte_identity.coff_body(donor_coff, dp)
        window = (16, 24) if reseat else (24, 28)
        hybrid = bytearray(seed)
        hybrid[sp["raw_offset"] + window[0]:sp["raw_offset"] + window[1]] = (
            donor_body[window[0]:window[1]])
        if reseat:
            struct.pack_into("<I", hybrid, sp["relocation_offset"] + 20, 18)
        hybrid = bytes(hybrid)
        hybrid_coff = byte_identity.CoffObject(hybrid)
        hybrid_body = byte_identity.coff_body(
            hybrid_coff, hybrid_coff.function_section(TARGET_SYMBOL))

        def child_pin(name):
            left = byte_identity._comdat_child(seed_coff, sp, name)
            right = byte_identity._comdat_child(donor_coff, dp, name)
            definitions = byte_identity.section_definitions(seed_coff)
            result = {
                "section_number": left["number"],
                "raw_size": left["raw_size"],
                "relocation_count": left["relocation_count"],
                "line_count": left["line_count"],
                "characteristics": left["characteristics"],
                "selection": definitions[left["number"]]["selection"],
                "associated": definitions[left["number"]]["associated"],
                "expected_seed_body_sha256": hashlib.sha256(
                    byte_identity.coff_body(seed_coff, left)).hexdigest(),
                "expected_donor_body_sha256": hashlib.sha256(
                    byte_identity.coff_body(donor_coff, right)).hexdigest(),
                "expected_seed_relocation_sha256": hashlib.sha256(
                    byte_identity._coff_table_bytes(
                        seed_coff, left, "relocations")).hexdigest(),
                "expected_donor_relocation_sha256": hashlib.sha256(
                    byte_identity._coff_table_bytes(
                        donor_coff, right, "relocations")).hexdigest(),
            }
            return result, left, right

        debug_f, sf, df = child_pin(".debug$F")
        debug_f["expected_record"] = byte_identity.parse_fpo_data(
            byte_identity.coff_body(seed_coff, sf),
            expected_proc_size=len(seed_body))
        debug_s, ss, ds = child_pin(".debug$S")
        common = byte_identity.coff_body(seed_coff, ss)[:28]
        cb_proc, dbg_start, dbg_end = struct.unpack_from("<III", common, 16)
        debug_s.update({
            "expected_common_prefix_sha256": hashlib.sha256(common).hexdigest(),
            "expected_record_kind": common[2:4].hex(),
            "expected_cb_proc": cb_proc,
            "expected_dbg_start": dbg_start,
            "expected_dbg_end": dbg_end,
        })
        identity = {
            "kind": byte_identity.ORDINARY_FPO_MOSAIC_IDENTITY_KIND,
            "expected_primary_characteristics": sp["characteristics"],
            "expected_primary_selection":
                byte_identity.section_definitions(seed_coff)[sp["number"]]
                ["selection"],
            "expected_function_count": sum(
                byte_identity.function_multiset(seed_coff).values()),
            "expected_comdat_count": sum(
                byte_identity.comdat_primary_identity_multiset(
                    seed_coff).values()),
            "expected_seed_line_sha256": hashlib.sha256(
                byte_identity._coff_table_bytes(
                    seed_coff, sp, "lines")).hexdigest(),
            "expected_donor_line_sha256": hashlib.sha256(
                byte_identity._coff_table_bytes(
                    donor_coff, dp, "lines")).hexdigest(),
            "debug_f": debug_f,
            "debug_s": debug_s,
        }
        identity = byte_identity.validate_ordinary_fpo_mosaic_identity(
            identity, "fixture", sp["number"], len(seed_body))
        function = {
            "mangled": TARGET_SYMBOL,
            "donor": "d_fpo",
            "splice_class": "retail_exact_instruction_mosaic",
            "expected_section_number": sp["number"],
            "expected_section_count": len(seed_coff.sections),
            "expected_body_length": len(seed_body),
            "expected_relocation_count": sp["relocation_count"],
            "expected_line_count": sp["line_count"],
            "expected_seed_body_sha256": hashlib.sha256(
                seed_body).hexdigest(),
            "expected_donor_body_sha256": hashlib.sha256(
                donor_body).hexdigest(),
            "expected_seed_metadata_sha256":
                byte_identity.instruction_mosaic_metadata_sha256(
                    seed_coff, sp),
            "expected_donor_metadata_sha256":
                byte_identity.instruction_mosaic_metadata_sha256(
                    donor_coff, dp),
            "expected_body_sha256": hashlib.sha256(hybrid_body).hexdigest(),
            "ordinary_fpo_identity": identity,
            "instruction_ranges": [{
                "kind": "same_offset_complete_x86_instruction_sequence_v1",
                "start": window[0], "end": window[1],
                "seed_bytes": seed_body[window[0]:window[1]].hex(),
                "seed_sha256": hashlib.sha256(
                    seed_body[window[0]:window[1]]).hexdigest(),
                "donor_bytes": donor_body[window[0]:window[1]].hex(),
                "donor_sha256": hashlib.sha256(
                    donor_body[window[0]:window[1]]).hexdigest(),
                "seed_instruction_lengths": [1, 1, 6] if reseat else [3, 1],
                "donor_instruction_lengths": [6, 1, 1] if reseat else [3, 1],
            }],
            "retail_oracle": {
                "image": "LEGO1.DLL", "address": "0x1003cf20",
                "verdict": "MATCH", "length": len(hybrid_body),
            },
            "retail_relocations": relocation_oracle_for(
                hybrid, retail_body_for(hybrid)),
        }
        if reseat:
            function["instruction_ranges"][0].update({
                "relocation_reseat": True,
                "seed_relocation_offsets": [20],
                "donor_relocation_offsets": [18],
            })
            hybrid_primary = hybrid_coff.function_section(TARGET_SYMBOL)
            function["expected_output_relocation_sha256"] = hashlib.sha256(
                byte_identity._coff_table_bytes(
                    hybrid_coff, hybrid_primary, "relocations")).hexdigest()
            function["expected_output_metadata_sha256"] = (
                byte_identity.instruction_mosaic_metadata_sha256(
                    hybrid_coff, hybrid_primary))
        return seed, donor, function, retail_body_for(hybrid), hybrid

    def compose(self, fixture, function=None, seed=None, donor=None,
                retail=None):
        base_seed, base_donor, expected, oracle, _ = fixture
        return byte_identity.compose_retail_exact_instruction_mosaic(
            base_seed if seed is None else seed,
            base_donor if donor is None else donor,
            expected if function is None else function,
            oracle if retail is None else retail,
        )

    def test_fpo_reseat_moves_the_operand_seat_and_pins_output_metadata(self):
        fixture = self.fixture(reseat=True)
        composed, detail = self.compose(fixture)
        seed, donor, function, _, hybrid = fixture
        checked = byte_identity.CoffObject(composed)
        primary = checked.function_section(TARGET_SYMBOL)
        expected = byte_identity.CoffObject(hybrid)
        self.assertEqual(
            byte_identity.coff_body(checked, primary),
            byte_identity.coff_body(
                expected, expected.function_section(TARGET_SYMBOL)))
        rows = byte_identity.detailed_relocations(checked, primary)
        self.assertEqual([row["offset"] for row in rows], [4, 12, 18])
        self.assertEqual(detail["relocation_reseats"][0]["output_offset"], 18)
        self.assertTrue(detail["ordinary_fpo_identity"])
        # the seed pins alone (no output metadata pin) are refused
        unpinned = copy.deepcopy(function)
        unpinned.pop("expected_output_metadata_sha256")
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "output metadata pin"):
            self.compose(fixture, function=unpinned)
        wrong = copy.deepcopy(function)
        wrong["expected_output_metadata_sha256"] = "0" * 64
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "output metadata changed"):
            self.compose(fixture, function=wrong)
        # a plain (EH) mosaic may not carry the FPO output metadata pin
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "output metadata pin"):
            plain = copy.deepcopy(function)
            plain.pop("ordinary_fpo_identity")
            self.compose(fixture, function=plain)

    def test_positive_conserves_seed_metadata_and_omits_donor_collateral(self):
        fixture = self.fixture()
        composed, detail = self.compose(fixture)
        seed, donor, function, _, hybrid = fixture
        checked = byte_identity.CoffObject(composed)
        primary = checked.function_section(TARGET_SYMBOL)
        expected = byte_identity.CoffObject(hybrid)
        expected_primary = expected.function_section(TARGET_SYMBOL)
        self.assertEqual(
            byte_identity.coff_body(checked, primary),
            byte_identity.coff_body(expected, expected_primary))
        self.assertEqual(
            byte_identity.instruction_mosaic_metadata_sha256(checked, primary),
            function["expected_seed_metadata_sha256"])
        donor_coff = byte_identity.CoffObject(donor)
        donor_body = byte_identity.coff_body(
            donor_coff, donor_coff.function_section(TARGET_SYMBOL))
        self.assertNotEqual(
            byte_identity.coff_body(checked, primary)[29], donor_body[29])
        byte_identity.validate_donor_object_excluded(composed, [donor])
        self.assertTrue(detail["ordinary_fpo_identity"])

    def test_role_policy_is_exactly_once_primary_and_never_other_role(self):
        byte_identity.require_ordinary_fpo_mosaic_donor_bindings(
            {"d_fpo"}, ["d_fpo"], [], ["d_fpo"], "fixture")
        cases = (
            ({"d_fpo"}, [], [], [], "bound exactly once"),
            ({"d_fpo"}, ["d_fpo", "d_fpo"], [], ["d_fpo"],
             "ordinary or repeated"),
            ({"d_fpo"}, ["d_fpo"], ["d_fpo"], ["d_fpo"],
             "non-primary"),
        )
        for recipes, primary, other, bound, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(
                    byte_identity.ByteIdentityError, message):
                byte_identity.require_ordinary_fpo_mosaic_donor_bindings(
                    recipes, primary, other, bound, "fixture")

    def test_live_manifest_role_preflight_rejects_unbound_and_reused_carrier(self):
        manifest = json.loads(
            (TOOLS / "byte_identity_manifest.json").read_text())
        byte_identity.require_manifest_source_refactor_role_preflight(
            manifest, "fixture", ROOT)
        unit = next(
            unit for unit in manifest["translation_units"]
            if any(donor.get("id") == "d_ca1ae06a8585"
                   for donor in unit.get("donors", [])))
        function = next(
            item for item in unit["functions"]
            if "ordinary_fpo_identity" in item)
        unit["functions"].remove(function)
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "bound exactly once"):
            byte_identity.require_manifest_source_refactor_role_preflight(
                manifest, "fixture", ROOT)
        unit["functions"].append(function)
        reused = copy.deepcopy(function)
        reused.pop("ordinary_fpo_identity")
        reused["mangled"] = "?AnotherFixture@@YAXXZ"
        unit["functions"].append(reused)
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "ordinary or repeated"):
            byte_identity.require_manifest_source_refactor_role_preflight(
                manifest, "fixture", ROOT)

    def test_decoder_covers_the_flat_ia32_maps_and_fails_closed(self):
        accepted = {
            "41": 1, "43": 1, "45": 1, "90": 1, "99": 1, "c3": 1,
            "7400": 2, "7c00": 2, "7d00": 2, "7f00": 2, "7200": 2,
            "eb00": 2, "01c8": 2, "03c8": 2, "2bc8": 2, "32c0": 2,
            "f7d8": 2, "f7d0": 2, "f7c000000000": 6, "f7d100": 2,
            "f6c001": 3, "66f7c00000": 5,
            "0fafc1": 3, "0fb6c0": 3, "0f8400000000": 6, "0f94c0": 3,
            "c6830700000000": 7, "c744c13c00000000": 8, "c20800": 3,
            "8b442454": 4, "8d048500000000": 7, "d9ee": 2, "dd442404": 4,
            "e800000000": 5, "a100000000": 5, "6800000000": 5, "6a00": 2,
            "c1e802": 3, "d1e8": 2, "6bc00c": 3, "69c000010000": 6,
            "b800000000": 5, "66b80000": 4, "668b00": 3, "b000": 2,
            "c8000000": 4, "0fbae005": 4, "f3ab": 2, "f3a5": 2, "f2ae": 2,
            "0f1f4000": 4, "8f00": 2, "8b048500000000": 7,
        }
        for encoded, length in accepted.items():
            with self.subTest(encoded=encoded):
                self.assertEqual(
                    byte_identity.supported_ia32_instruction_length(
                        bytes.fromhex(encoded), "fixture"), length)
        for encoded in (
            "0f", "0f38", "0f3a00", "0f19", "0fae", "66", "6666", "6667",
            "f0f0", "d6", "f1", "8b", "8b04", "e8000000", "0f840000",
            "c700000000", "b8000000", "26262626268b00", "0f0500",
            "f7c100",
        ):
            with self.subTest(encoded=encoded), self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "unsupported|truncated|ModRM|SIB|prefix"):
                byte_identity.supported_ia32_instruction_length(
                    bytes.fromhex(encoded), "fixture")
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "not one complete"):
            byte_identity.require_supported_complete_ia32_instruction(
                bytes.fromhex("9090"), "fixture")

    def test_line_certificate_rejects_partial_endpoints_and_wrong_partition(self):
        seed, _, function, _, _ = self.fixture()
        coff = byte_identity.CoffObject(seed)
        primary = coff.function_section(TARGET_SYMBOL)
        body = byte_identity.coff_body(coff, primary)
        base = function["instruction_ranges"][0]
        mutations = (
            ({**base, "start": 25, "seed_instruction_lengths": [2, 1]},
             "containing-stream"),
            ({**base, "end": 26, "seed_instruction_lengths": [2]},
             "containing-stream"),
            ({**base, "seed_instruction_lengths": [2, 2]},
             "partition"),
        )
        for item, message in mutations:
            with self.subTest(message=message), self.assertRaisesRegex(
                    byte_identity.ByteIdentityError, message):
                byte_identity.require_coff_line_certified_ia32_boundaries(
                    coff, primary, body, [item], "seed", TARGET_SYMBOL,
                    "fixture")

    def test_line_certificate_rejects_bad_sentinel_and_rows(self):
        seed, _, function, _, _ = self.fixture()
        for kind in ("sentinel", "sentinel_line", "unsorted", "outside"):
            parsed = byte_identity.CoffObject(seed)
            primary = parsed.function_section(TARGET_SYMBOL)
            changed = bytearray(seed)
            if kind == "sentinel":
                struct.pack_into("<I", changed, primary["line_offset"], 0)
            elif kind == "sentinel_line":
                struct.pack_into("<H", changed, primary["line_offset"] + 4, 1)
            elif kind == "unsorted":
                struct.pack_into("<H", changed, primary["header_offset"] + 34,
                                 3)
                struct.pack_into("<IH", changed, primary["line_offset"] + 6,
                                 24, 10)
                struct.pack_into("<IH", changed, primary["line_offset"] + 12,
                                 23, 11)
            else:
                struct.pack_into("<I", changed, primary["line_offset"] + 6,
                                 primary["raw_size"] + 1)
            changed = bytes(changed)
            coff = byte_identity.CoffObject(changed)
            changed_primary = coff.function_section(TARGET_SYMBOL)
            with self.subTest(kind=kind), self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "sentinel|boundary"):
                byte_identity.require_coff_line_certified_ia32_boundaries(
                    coff, changed_primary,
                    byte_identity.coff_body(coff, changed_primary),
                    function["instruction_ranges"], "seed", TARGET_SYMBOL,
                    "fixture")

    def test_fpo_identity_rejects_every_pinned_geometry_or_body_family(self):
        fixture = self.fixture()
        checks = (
            (("expected_primary_characteristics",), "characteristics"),
            (("expected_function_count",), "function census"),
            (("debug_f", "section_number"), "geometry"),
            (("debug_f", "associated"), "geometry"),
            (("debug_f", "expected_seed_body_sha256"), "body pin"),
            (("debug_f", "expected_seed_relocation_sha256"),
             "relocation-table pin"),
            (("debug_f", "expected_record", "cbProcSize"), "parsed FPO"),
            (("debug_s", "expected_donor_body_sha256"), "body pin"),
            (("debug_s", "expected_common_prefix_sha256"),
             "CodeView procedure"),
            (("debug_s", "expected_dbg_end"), "CodeView procedure range"),
        )
        for path, message in checks:
            bad = copy.deepcopy(fixture[2])
            target = bad["ordinary_fpo_identity"]
            for key in path[:-1]:
                target = target[key]
            key = path[-1]
            value = target[key]
            target[key] = ("0" * 64 if isinstance(value, str)
                           else value + 1)
            with self.subTest(path=path), self.assertRaisesRegex(
                    byte_identity.ByteIdentityError, message):
                self.compose(fixture, bad)

    def test_fpo_and_eh_branches_cannot_cross(self):
        fixture = self.fixture()
        eh_seed = make_divergent_coff()
        eh_donor = _patched_target_body(eh_seed, [(24, b"\x41\x41\x41")])
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "FPO.*closure"):
            self.compose(fixture, seed=eh_seed, donor=eh_donor)
        ordinary = copy.deepcopy(fixture[2])
        ordinary.pop("ordinary_fpo_identity")
        ordinary.pop("expected_seed_metadata_sha256")
        ordinary.pop("expected_donor_metadata_sha256")
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "closure class"):
            self.compose(fixture, ordinary)

    def test_child_relocation_semantics_reject_offset_type_and_target_drift(self):
        fixture = self.fixture()
        for mutation in ("offset", "type", "target"):
            changed = bytearray(fixture[1])
            parsed = byte_identity.CoffObject(fixture[1])
            primary = parsed.function_section(TARGET_SYMBOL)
            child = byte_identity._comdat_child(parsed, primary, ".debug$F")
            if mutation == "offset":
                struct.pack_into("<I", changed, child["relocation_offset"], 1)
            elif mutation == "type":
                struct.pack_into("<H", changed,
                                 child["relocation_offset"] + 8, 6)
            else:
                common_index, _ = byte_identity.unique_symbol(
                    parsed, lambda symbol: symbol["name"] == COMMON,
                    "fixture common symbol")
                struct.pack_into("<I", changed,
                                 child["relocation_offset"] + 4,
                                 common_index)
            changed = bytes(changed)
            changed_coff = byte_identity.CoffObject(changed)
            changed_primary = changed_coff.function_section(TARGET_SYMBOL)
            changed_child = byte_identity._comdat_child(
                changed_coff, changed_primary, ".debug$F")
            bad = copy.deepcopy(fixture[2])
            bad["ordinary_fpo_identity"]["debug_f"][
                "expected_donor_relocation_sha256"] = hashlib.sha256(
                    byte_identity._coff_table_bytes(
                        changed_coff, changed_child,
                        "relocations")).hexdigest()
            with self.subTest(mutation=mutation), self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "relocation|semantic"):
                self.compose(fixture, bad, donor=changed)

    def test_fpo_and_codeview_object_bytes_are_structurally_checked(self):
        fixture = self.fixture()
        raw = bytearray(struct.pack("<IIIHBB", 0, SEED_SIZE - 1,
                                    2, 1, 2, 0x10))
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "cbProcSize"):
            byte_identity.parse_fpo_data(
                bytes(raw), expected_proc_size=SEED_SIZE)
        raw = bytearray(struct.pack("<IIIHBB", 0, SEED_SIZE,
                                    2, 1, 2, 0x30))
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "reserved"):
            byte_identity.parse_fpo_data(bytes(raw))

        changed = bytearray(fixture[1])
        parsed = byte_identity.CoffObject(fixture[1])
        primary = parsed.function_section(TARGET_SYMBOL)
        debug_s = byte_identity._comdat_child(parsed, primary, ".debug$S")
        changed[debug_s["raw_offset"] + 2] ^= 1
        changed = bytes(changed)
        changed_coff = byte_identity.CoffObject(changed)
        changed_primary = changed_coff.function_section(TARGET_SYMBOL)
        changed_debug = byte_identity._comdat_child(
            changed_coff, changed_primary, ".debug$S")
        bad = copy.deepcopy(fixture[2])
        bad["ordinary_fpo_identity"]["debug_s"][
            "expected_donor_body_sha256"] = hashlib.sha256(
                byte_identity.coff_body(
                    changed_coff, changed_debug)).hexdigest()
        bad["expected_donor_metadata_sha256"] = (
            byte_identity.instruction_mosaic_metadata_sha256(
                changed_coff, changed_primary))
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "CodeView procedure"):
            self.compose(fixture, bad, donor=changed)

    def test_rejects_retail_oracle_drift_and_non_target_output_mutation(self):
        fixture = self.fixture()
        retail = bytearray(fixture[3])
        retail[8] ^= 1
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "retail-exact"):
            self.compose(fixture, retail=bytes(retail))
        original = byte_identity.apply_replacements

        def corrupt(data, replacements):
            output = bytearray(original(data, replacements))
            output[byte_identity.CoffObject(data).sections[3]["raw_offset"]] ^= 1
            return bytes(output)

        with mock.patch.object(byte_identity, "apply_replacements",
                               side_effect=corrupt):
            with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                        "non-target"):
                self.compose(fixture)

        def corrupt_child(data, replacements):
            output = bytearray(original(data, replacements))
            parsed = byte_identity.CoffObject(data)
            primary = parsed.function_section(TARGET_SYMBOL)
            child = byte_identity._comdat_child(parsed, primary, ".debug$S")
            output[child["raw_offset"] + child["raw_size"] - 1] ^= 1
            return bytes(output)

        with mock.patch.object(byte_identity, "apply_replacements",
                               side_effect=corrupt_child):
            with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                        "non-target"):
                self.compose(fixture)

    def test_live_manifest_has_exact_half_open_ranges_and_omits_collateral(self):
        manifest = json.loads(
            (TOOLS / "byte_identity_manifest.json").read_text())
        function = next(
            function
            for unit in manifest["translation_units"]
            for function in unit.get("functions", [])
            if "ordinary_fpo_identity" in function)
        expected = [
            (337, 360), (389, 398), (400, 429), (444, 453),
            (472, 473), (481, 490), (491, 499), (549, 568),
            (604, 613), (615, 637), (648, 650), (711, 720),
            (721, 729),
        ]
        actual = [(item["start"], item["end"])
                  for item in function["instruction_ranges"]]
        self.assertEqual(actual, expected)
        for offset in (499, 506, 729, 736):
            self.assertFalse(any(start <= offset < end
                                 for start, end in actual))
        self.assertEqual(len(function["retail_relocations"]), 2)


def make_fpo_self_permutation_coff(*, donor=False):
    """Make one equal-size FPO fixture with the live commute shape."""
    data = make_fpo_instruction_mosaic_coff()
    parsed = byte_identity.CoffObject(data)
    primary = parsed.function_section(TARGET_SYMBOL)
    output = bytearray(data)
    # One compiler line row certifies the containing stream from +8 through
    # the self-permutation window at the end of this small fixture.
    struct.pack_into("<I", output, primary["line_offset"] + 6, 8)
    common = bytes.fromhex(
        "8b542414"       # relocation operand, one complete MOV encoding
        "8b442410"
        "8b542414"       # relocation operand, one complete MOV encoding
        "33ff8b542414"   # XOR EDI,EDI; MOV EDX,[ESP+14h]
    )
    prefix = bytes.fromhex("3bf07610" if donor else "3bc67310")
    output[primary["raw_offset"] + 8:primary["raw_offset"] + 30] = (
        prefix + common)
    if donor:
        # Authenticated donor collateral that the seed-based result must omit.
        output[primary["raw_offset"] + 1] ^= 0x5A
    return bytes(output)


class OrdinaryFpoSelfPermutationTests(unittest.TestCase):
    """An ordinary carrier may feed only one closed commuting permutation."""

    DONOR_ID = "d_e5f44f6a786e"

    def live_records(self):
        manifest = json.loads(
            (TOOLS / "byte_identity_manifest.json").read_text())
        unit = next(
            unit for unit in manifest["translation_units"]
            if any(donor.get("id") == self.DONOR_ID
                   for donor in unit.get("donors", [])))
        donor = next(item for item in unit["donors"]
                     if item["id"] == self.DONOR_ID)
        function = next(item for item in unit["functions"]
                        if item["donor"] == self.DONOR_ID)
        return manifest, unit, donor, function

    def fixture(self):
        seed = make_fpo_self_permutation_coff()
        donor = make_fpo_self_permutation_coff(donor=True)
        seed_coff = byte_identity.CoffObject(seed)
        donor_coff = byte_identity.CoffObject(donor)
        sp = seed_coff.function_section(TARGET_SYMBOL)
        dp = donor_coff.function_section(TARGET_SYMBOL)
        seed_body = byte_identity.coff_body(seed_coff, sp)
        donor_body = byte_identity.coff_body(donor_coff, dp)
        mosaic = bytearray(seed_body)
        mosaic[8:12] = donor_body[8:12]
        mosaic[24:28] = donor_body[26:30]
        mosaic[28:30] = donor_body[24:26]
        mosaic = bytes(mosaic)
        hybrid = byte_identity.apply_replacements(seed, [
            (sp["raw_offset"] + 8, sp["raw_offset"] + 12, mosaic[8:12]),
            (sp["raw_offset"] + 24, sp["raw_offset"] + 30, mosaic[24:30]),
        ])

        def child_pin(name):
            left = byte_identity._comdat_child(seed_coff, sp, name)
            right = byte_identity._comdat_child(donor_coff, dp, name)
            definitions = byte_identity.section_definitions(seed_coff)
            return ({
                "section_number": left["number"],
                "raw_size": left["raw_size"],
                "relocation_count": left["relocation_count"],
                "line_count": left["line_count"],
                "characteristics": left["characteristics"],
                "selection": definitions[left["number"]]["selection"],
                "associated": definitions[left["number"]]["associated"],
                "expected_seed_body_sha256": hashlib.sha256(
                    byte_identity.coff_body(seed_coff, left)).hexdigest(),
                "expected_donor_body_sha256": hashlib.sha256(
                    byte_identity.coff_body(donor_coff, right)).hexdigest(),
                "expected_seed_relocation_sha256": hashlib.sha256(
                    byte_identity._coff_table_bytes(
                        seed_coff, left, "relocations")).hexdigest(),
                "expected_donor_relocation_sha256": hashlib.sha256(
                    byte_identity._coff_table_bytes(
                        donor_coff, right, "relocations")).hexdigest(),
            }, left, right)

        debug_f, sf, _ = child_pin(".debug$F")
        debug_f["expected_record"] = byte_identity.parse_fpo_data(
            byte_identity.coff_body(seed_coff, sf),
            expected_proc_size=len(seed_body))
        debug_s, ss, _ = child_pin(".debug$S")
        common = byte_identity.coff_body(seed_coff, ss)[:28]
        cb_proc, dbg_start, dbg_end = struct.unpack_from("<III", common, 16)
        debug_s.update({
            "expected_common_prefix_sha256": hashlib.sha256(common).hexdigest(),
            "expected_record_kind": common[2:4].hex(),
            "expected_cb_proc": cb_proc,
            "expected_dbg_start": dbg_start,
            "expected_dbg_end": dbg_end,
        })
        identity = byte_identity.validate_ordinary_fpo_mosaic_identity({
            "kind": byte_identity.ORDINARY_FPO_MOSAIC_IDENTITY_KIND,
            "expected_primary_characteristics": sp["characteristics"],
            "expected_primary_selection":
                byte_identity.section_definitions(seed_coff)[sp["number"]]
                ["selection"],
            "expected_function_count": sum(
                byte_identity.function_multiset(seed_coff).values()),
            "expected_comdat_count": sum(
                byte_identity.comdat_primary_identity_multiset(
                    seed_coff).values()),
            "expected_seed_line_sha256": hashlib.sha256(
                byte_identity._coff_table_bytes(
                    seed_coff, sp, "lines")).hexdigest(),
            "expected_donor_line_sha256": hashlib.sha256(
                byte_identity._coff_table_bytes(
                    donor_coff, dp, "lines")).hexdigest(),
            "debug_f": debug_f,
            "debug_s": debug_s,
        }, "fixture", sp["number"], len(seed_body))
        seed_linker = byte_identity.linker_payload_multiset(seed_coff)
        carrier_header = byte_identity.entropy_generator.generate_extern_run(
            "CarrierHeader", 2, 2).encode("ascii")
        carrier_seat = byte_identity.entropy_generator.generate_extern_run(
            "CarrierSeat", 2, 2).encode("ascii")
        carrier = {
            "kind": "extern_run_pair_v1",
            "placement": "after_includes_and_eof_v1",
            "header_prefix": "CarrierHeader",
            "header_count": 2,
            "seat_prefix": "CarrierSeat",
            "seat_count": 2,
            "width": 2,
            "generated_declarations_sha256": hashlib.sha256(
                carrier_header + carrier_seat).hexdigest(),
        }
        changed = [
            index for index, (left, right) in enumerate(zip(seed_body, mosaic))
            if left != right
        ]
        function = {
            "mangled": TARGET_SYMBOL,
            "donor": "d_self_permutation",
            "splice_class": "retail_exact_instruction_mosaic",
            "expected_section_number": sp["number"],
            "expected_section_count": len(seed_coff.sections),
            "expected_body_length": len(seed_body),
            "expected_relocation_count": sp["relocation_count"],
            "expected_line_count": sp["line_count"],
            "expected_seed_body_sha256": hashlib.sha256(seed_body).hexdigest(),
            "expected_donor_body_sha256": hashlib.sha256(donor_body).hexdigest(),
            "expected_seed_metadata_sha256":
                byte_identity.instruction_mosaic_metadata_sha256(
                    seed_coff, sp),
            "expected_donor_metadata_sha256":
                byte_identity.instruction_mosaic_metadata_sha256(
                    donor_coff, dp),
            "expected_body_sha256": hashlib.sha256(mosaic).hexdigest(),
            "ordinary_fpo_identity": identity,
            "same_function_source_identity": {
                "carrier": carrier,
            },
            "instruction_ranges": [{
                "kind": "same_offset_complete_x86_instruction_sequence_v1",
                "start": 8, "end": 12,
                "seed_bytes": seed_body[8:12].hex(),
                "seed_sha256": hashlib.sha256(seed_body[8:12]).hexdigest(),
                "donor_bytes": donor_body[8:12].hex(),
                "donor_sha256": hashlib.sha256(donor_body[8:12]).hexdigest(),
                "seed_instruction_lengths": [2, 2],
                "donor_instruction_lengths": [2, 2],
            }],
            "instruction_self_permutation": {
                "kind": byte_identity.ORDINARY_FPO_SELF_PERMUTATION_KIND,
                "source_start": 24, "source_end": 30,
                "target_start": 24, "target_end": 30,
                "source_instruction_lengths": [2, 4],
                "target_instruction_lengths": [4, 2],
                "moves": [{
                    "target_start": 24, "target_end": 28,
                    "target_bytes": donor_body[26:30].hex(),
                    "target_sha256": hashlib.sha256(
                        donor_body[26:30]).hexdigest(),
                    "donor_start": 26, "donor_end": 30,
                    "donor_bytes": donor_body[26:30].hex(),
                    "donor_sha256": hashlib.sha256(
                        donor_body[26:30]).hexdigest(),
                }, {
                    "target_start": 28, "target_end": 30,
                    "target_bytes": donor_body[24:26].hex(),
                    "target_sha256": hashlib.sha256(
                        donor_body[24:26]).hexdigest(),
                    "donor_start": 24, "donor_end": 26,
                    "donor_bytes": donor_body[24:26].hex(),
                    "donor_sha256": hashlib.sha256(
                        donor_body[24:26]).hexdigest(),
                }],
                "expected_changed_offsets": changed,
                "expected_function_multiset_sha256":
                    byte_identity.canonical_counter_receipt_sha256(
                        byte_identity.function_multiset(seed_coff)),
                "expected_comdat_multiset_sha256":
                    byte_identity.canonical_counter_receipt_sha256(
                        byte_identity.comdat_primary_identity_multiset(
                            seed_coff)),
                "expected_section_shape_sha256":
                    byte_identity.section_shape_receipt_sha256(seed_coff),
                "expected_linker_payload_count": sum(seed_linker.values()),
                "expected_linker_payload_sha256":
                    byte_identity.canonical_counter_receipt_sha256(
                        seed_linker),
            },
            "retail_oracle": {
                "image": "LEGO1.DLL", "address": "0x1003cf20",
                "verdict": "MATCH", "length": len(mosaic),
            },
            "retail_relocations": relocation_oracle_for(
                hybrid, retail_body_for(hybrid)),
        }
        return seed, donor, function, retail_body_for(hybrid), hybrid

    def compose(self, fixture, function=None, seed=None, donor=None,
                retail=None):
        base_seed, base_donor, expected, oracle, _ = fixture
        return byte_identity.compose_retail_exact_instruction_mosaic(
            base_seed if seed is None else seed,
            base_donor if donor is None else donor,
            expected if function is None else function,
            oracle if retail is None else retail,
        )

    def test_positive_is_seed_authoritative_and_omits_donor_collateral(self):
        fixture = self.fixture()
        self.assertNotIn(
            "carrier_identifiers",
            fixture[2]["same_function_source_identity"],
        )
        composed, detail = self.compose(fixture)
        seed, donor, function, _, hybrid = fixture
        checked = byte_identity.CoffObject(composed)
        primary = checked.function_section(TARGET_SYMBOL)
        expected = byte_identity.CoffObject(hybrid)
        self.assertEqual(
            byte_identity.coff_body(checked, primary),
            byte_identity.coff_body(
                expected, expected.function_section(TARGET_SYMBOL)))
        donor_coff = byte_identity.CoffObject(donor)
        donor_primary = donor_coff.function_section(TARGET_SYMBOL)
        seed_coff = byte_identity.CoffObject(seed)
        seed_primary = seed_coff.function_section(TARGET_SYMBOL)
        self.assertEqual(
            byte_identity.coff_body(checked, primary)[1],
            byte_identity.coff_body(seed_coff, seed_primary)[1])
        self.assertNotEqual(
            byte_identity.coff_body(checked, primary)[1],
            byte_identity.coff_body(donor_coff, donor_primary)[1])
        self.assertEqual(detail["body_changed_offsets"],
                         function["instruction_self_permutation"][
                             "expected_changed_offsets"])
        self.assertEqual(len(detail["instruction_self_permutation"]), 2)
        byte_identity.validate_donor_object_excluded(composed, [donor])

    def test_schema_rejects_non_bijections_gaps_and_partition_drift(self):
        fixture = self.fixture()
        original = fixture[2]["instruction_self_permutation"]
        cases = []
        bad = copy.deepcopy(original)
        bad["moves"].pop()
        cases.append((bad, "exactly two"))
        bad = copy.deepcopy(original)
        bad["moves"][1].update({"donor_start": 26, "donor_end": 28})
        cases.append((bad, "source partition|widths differ"))
        bad = copy.deepcopy(original)
        bad["target_instruction_lengths"] = [3, 3]
        cases.append((bad, "target partition"))
        bad = copy.deepcopy(original)
        bad["moves"] = list(reversed(bad["moves"]))
        cases.append((bad, "exact two-instruction reversal"))
        for value, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(
                    byte_identity.ByteIdentityError, message):
                byte_identity.validate_instruction_self_permutation(
                    value, "fixture", SEED_SIZE)

    def test_schema_rejects_literal_hash_and_effect_pair_drift(self):
        fixture = self.fixture()
        original = fixture[2]["instruction_self_permutation"]
        cases = []
        bad = copy.deepcopy(original)
        bad["moves"][0]["target_sha256"] = "0" * 64
        cases.append((bad, "encoding/hash"))
        bad = copy.deepcopy(original)
        for prefix in ("target", "donor"):
            bad["moves"][1][f"{prefix}_bytes"] = "33d2"
            bad["moves"][1][f"{prefix}_sha256"] = hashlib.sha256(
                bytes.fromhex("33d2")).hexdigest()
        cases.append((bad, "closed XOR-zero|same register"))
        bad = copy.deepcopy(original)
        for prefix in ("target", "donor"):
            bad["moves"][0][f"{prefix}_bytes"] = "8b7c2414"
            bad["moves"][0][f"{prefix}_sha256"] = hashlib.sha256(
                bytes.fromhex("8b7c2414")).hexdigest()
        cases.append((bad, "closed stack-load|same register"))
        for value, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(
                    byte_identity.ByteIdentityError, message):
                byte_identity.validate_instruction_self_permutation(
                    value, "fixture", SEED_SIZE)

    def test_containing_stream_rejects_mid_instruction_boundaries(self):
        fixture = self.fixture()
        donor = byte_identity.CoffObject(fixture[1])
        primary = donor.function_section(TARGET_SYMBOL)
        body = byte_identity.coff_body(donor, primary)
        claims = (
            ({"start": 25, "end": 30,
              "donor_instruction_lengths": [1, 4]}, "containing-stream"),
            ({"start": 24, "end": 29,
              "donor_instruction_lengths": [2, 3]}, "containing-stream"),
        )
        for claim, message in claims:
            with self.subTest(claim=claim), self.assertRaisesRegex(
                    byte_identity.ByteIdentityError, message):
                byte_identity.require_coff_line_certified_ia32_boundaries(
                    donor, primary, body, [claim], "donor", TARGET_SYMBOL,
                    "fixture")

    def test_decoder_refuses_a_truncated_short_branch(self):
        self.assertEqual(
            byte_identity.supported_ia32_instruction_length(
                bytes.fromhex("7300"), "fixture"), 2)
        for raw in (bytes.fromhex("73"), bytes.fromhex("e9000000")):
            with self.subTest(raw=raw.hex()), self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "truncated|unsupported"):
                byte_identity.supported_ia32_instruction_length(
                    raw, "fixture")

    def test_line_certificate_rejects_wrong_sentinel_and_anchor(self):
        fixture = self.fixture()
        for kind in ("sentinel", "anchor"):
            changed = bytearray(fixture[0])
            parsed = byte_identity.CoffObject(fixture[0])
            primary = parsed.function_section(TARGET_SYMBOL)
            if kind == "sentinel":
                struct.pack_into("<I", changed, primary["line_offset"], 0)
            else:
                struct.pack_into("<I", changed,
                                 primary["line_offset"] + 6, 9)
            changed = bytes(changed)
            coff = byte_identity.CoffObject(changed)
            changed_primary = coff.function_section(TARGET_SYMBOL)
            with self.subTest(kind=kind), self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "sentinel|preceding compiler line|containing-stream"):
                byte_identity.require_coff_line_certified_ia32_boundaries(
                    coff, changed_primary,
                    byte_identity.coff_body(coff, changed_primary),
                    fixture[2]["instruction_ranges"], "seed",
                    TARGET_SYMBOL, "fixture")

    def test_same_offset_range_may_not_overlap_permutation_window(self):
        fixture = self.fixture()
        bad = copy.deepcopy(fixture[2])
        seed_body = byte_identity.coff_body(
            byte_identity.CoffObject(fixture[0]),
            byte_identity.CoffObject(fixture[0]).function_section(
                TARGET_SYMBOL))
        donor_body = byte_identity.coff_body(
            byte_identity.CoffObject(fixture[1]),
            byte_identity.CoffObject(fixture[1]).function_section(
                TARGET_SYMBOL))
        bad["instruction_ranges"] = [{
            "kind": "same_offset_complete_x86_instruction_sequence_v1",
            "start": 24, "end": 26,
            "seed_bytes": seed_body[24:26].hex(),
            "seed_sha256": hashlib.sha256(seed_body[24:26]).hexdigest(),
            "donor_bytes": "33f6",
            "donor_sha256": hashlib.sha256(
                bytes.fromhex("33f6")).hexdigest(),
            "seed_instruction_lengths": [2],
            "donor_instruction_lengths": [2],
        }]
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "overlap.*self-permutation"):
            self.compose(fixture, function=bad)

    def test_self_permutation_requires_identical_fpo_child_bodies(self):
        fixture = self.fixture()
        changed = bytearray(fixture[1])
        parsed = byte_identity.CoffObject(fixture[1])
        primary = parsed.function_section(TARGET_SYMBOL)
        child = byte_identity._comdat_child(parsed, primary, ".debug$S")
        changed[child["raw_offset"] + child["raw_size"] - 1] ^= 1
        changed = bytes(changed)
        changed_coff = byte_identity.CoffObject(changed)
        changed_primary = changed_coff.function_section(TARGET_SYMBOL)
        changed_child = byte_identity._comdat_child(
            changed_coff, changed_primary, ".debug$S")
        bad = copy.deepcopy(fixture[2])
        bad["ordinary_fpo_identity"]["debug_s"][
            "expected_donor_body_sha256"] = hashlib.sha256(
                byte_identity.coff_body(
                    changed_coff, changed_child)).hexdigest()
        bad["expected_donor_metadata_sha256"] = (
            byte_identity.instruction_mosaic_metadata_sha256(
                changed_coff, changed_primary))
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "body differs between compiler states"):
            self.compose(fixture, function=bad, donor=changed)

    def test_linker_payload_closure_rejects_same_target_body_carrier(self):
        fixture = self.fixture()
        changed = bytearray(fixture[1])
        parsed = byte_identity.CoffObject(fixture[1])
        directive = next(section for section in parsed.sections
                         if section["name"] == ".drectve")
        changed[directive["raw_offset"]] ^= 1
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "linker payload"):
            self.compose(fixture, donor=bytes(changed))

    def test_object_wide_receipt_pins_are_independently_required(self):
        fixture = self.fixture()
        fields = (
            "expected_function_multiset_sha256",
            "expected_comdat_multiset_sha256",
            "expected_section_shape_sha256",
            "expected_linker_payload_sha256",
        )
        for field in fields:
            bad = copy.deepcopy(fixture[2])
            bad["instruction_self_permutation"][field] = "0" * 64
            with self.subTest(field=field), self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "function multiset|COMDAT multiset|section shape|linker payload"):
                self.compose(fixture, function=bad)

    def test_retail_and_changed_offset_pins_are_required(self):
        fixture = self.fixture()
        bad = copy.deepcopy(fixture[2])
        bad["instruction_self_permutation"][
            "expected_changed_offsets"] = [9, 10, 24]
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "changed-offset set"):
            self.compose(fixture, function=bad)
        retail = bytearray(fixture[3])
        retail[0] ^= 1
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "retail-exact"):
            self.compose(fixture, retail=bytes(retail))

    def test_class_crossing_and_non_target_output_mutation_fail(self):
        fixture = self.fixture()
        bad = copy.deepcopy(fixture[2])
        bad.pop("ordinary_fpo_identity")
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "isolated ordinary FPO"):
            self.compose(fixture, function=bad)

        original = byte_identity.apply_replacements

        def corrupt(data, replacements):
            output = bytearray(original(data, replacements))
            parsed = byte_identity.CoffObject(data)
            output[parsed.sections[3]["raw_offset"]] ^= 1
            return bytes(output)

        with mock.patch.object(byte_identity, "apply_replacements",
                               side_effect=corrupt):
            with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                        "non-target"):
                self.compose(fixture)

    def test_role_policy_is_exact_once_primary_and_never_other_role(self):
        byte_identity.require_ordinary_fpo_self_permutation_donor_bindings(
            {"d_perm"}, ["d_perm"], [], ["d_perm"], "fixture")
        cases = (
            ({"d_perm", "d_unbound"}, ["d_perm"], [], ["d_perm"],
             "bound exactly once"),
            ({"d_perm"}, ["d_perm", "d_perm"], [], ["d_perm"],
             "ordinary or repeated"),
            ({"d_perm"}, ["d_perm"], ["d_perm"], ["d_perm"],
             "non-primary"),
        )
        for recipes, primary, other, bound, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(
                    byte_identity.ByteIdentityError, message):
                byte_identity.require_ordinary_fpo_self_permutation_donor_bindings(
                    recipes, primary, other, bound, "fixture")

    def test_live_raw_preflight_rejects_unbound_reuse_and_class_crossing(self):
        manifest, unit, _, function = self.live_records()
        byte_identity.require_manifest_source_refactor_role_preflight(
            manifest, "fixture", ROOT)
        unit["functions"].remove(function)
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "bound exactly once"):
            byte_identity.require_manifest_source_refactor_role_preflight(
                manifest, "fixture", ROOT)
        unit["functions"].append(function)
        unit["functions"].append({
            "mangled": "?OrdinarySelfPermutationReuse@@YAXXZ",
            "donor": self.DONOR_ID,
            "splice_class": "equal_body_strict",
        })
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "ordinary or repeated"):
            byte_identity.require_manifest_source_refactor_role_preflight(
                manifest, "fixture", ROOT)
        unit["functions"].pop()
        function.pop("ordinary_fpo_identity")
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "ordinary FPO mosaic|bound exactly once"):
            byte_identity.require_manifest_source_refactor_role_preflight(
                manifest, "fixture", ROOT)

    def test_live_source_render_and_exact_retail_shape_are_pinned(self):
        manifest, unit, donor, function = self.live_records()
        overlay = byte_identity.validate_source_overlay(
            manifest["source_overlay"], ROOT)
        effective = overlay["rendered_by_path"][unit["source"]]
        clean = (ROOT / unit["source"]).read_bytes()
        identity = byte_identity.validate_same_function_carrier_source_identity(
            function["same_function_source_identity"], "fixture.identity")
        detail = byte_identity.require_same_function_carrier_source_identity(
            ROOT, unit["source"], clean, effective, donor["recipe"],
            identity, {item["logical_path"] for item in overlay["outputs"]},
            "fixture")
        self.assertEqual(detail["target_source_sha256"],
                         function["same_function_source_identity"][
                             "function_range_sha256"])
        self.assertEqual(
            hashlib.sha256(byte_identity.render_extern_run_pair_recipe_source(
                effective, donor["recipe"])).hexdigest(),
            function["same_function_source_identity"][
                "rendered_source_sha256"])
        self.assertEqual(function["expected_relocation_count"], 0)
        self.assertEqual(function["retail_relocations"], [])
        self.assertEqual(
            function["expected_body_sha256"],
            "396edefeaa6433477d701b4f0ad053572ddffb7739f54dc4f8ffeb5444a06864")
        self.assertEqual(
            function["instruction_self_permutation"][
                "expected_changed_offsets"],
            [14, 15, 17, 18, 19, 20, 21, 22])

    def test_live_source_identity_rejects_every_outer_pin_family(self):
        manifest, unit, donor, function = self.live_records()
        overlay = byte_identity.validate_source_overlay(
            manifest["source_overlay"], ROOT)
        effective = overlay["rendered_by_path"][unit["source"]]
        clean = (ROOT / unit["source"]).read_bytes()
        paths = {item["logical_path"] for item in overlay["outputs"]}
        raw = function["same_function_source_identity"]
        cases = []
        bad = copy.deepcopy(raw)
        bad["rendered_source_sha256"] = "0" * 64
        cases.append((bad, paths, "carrier-rendered source"))
        bad = copy.deepcopy(raw)
        bad["function_range_sha256"] = "0" * 64
        cases.append((bad, paths, "target function source range"))
        bad = copy.deepcopy(raw)
        bad["owner_header"]["source_sha256"] = "0" * 64
        cases.append((bad, paths, "differs from its pin"))
        bad = copy.deepcopy(raw)
        bad["owner_header"]["declaration_sha256"] = "0" * 64
        cases.append((bad, paths, "member declaration"))
        cases.append((copy.deepcopy(raw),
                      paths | {raw["owner_header"]["path"]},
                      "effective source overlay"))
        for value, overlaid, message in cases:
            normalized = (
                byte_identity.validate_same_function_carrier_source_identity(
                    value, "fixture.identity"))
            with self.subTest(message=message), self.assertRaisesRegex(
                    byte_identity.ByteIdentityError, message):
                byte_identity.require_same_function_carrier_source_identity(
                    ROOT, unit["source"], clean, effective,
                    donor["recipe"], normalized, overlaid, "fixture")

    def test_carrier_descriptor_binds_prefix_count_and_width_to_recipe(self):
        manifest, unit, donor, function = self.live_records()
        overlay = byte_identity.validate_source_overlay(
            manifest["source_overlay"], ROOT)
        effective = overlay["rendered_by_path"][unit["source"]]
        clean = (ROOT / unit["source"]).read_bytes()
        overlaid = {item["logical_path"] for item in overlay["outputs"]}
        original = function["same_function_source_identity"]

        def with_carrier(**changes):
            value = copy.deepcopy(original)
            carrier = value["carrier"]
            carrier.update(changes)
            generated = b"".join(
                byte_identity.entropy_generator.generate_extern_run(
                    carrier[f"{role}_prefix"],
                    carrier[f"{role}_count"], carrier["width"],
                ).encode("ascii")
                for role in ("header", "seat")
            )
            carrier["generated_declarations_sha256"] = hashlib.sha256(
                generated).hexdigest()
            return value

        cases = (
            with_carrier(header_prefix="AltHeader"),
            with_carrier(header_count=99),
            with_carrier(width=3),
        )
        for value in cases:
            normalized = (
                byte_identity.validate_same_function_carrier_source_identity(
                    value, "fixture.identity"))
            with self.subTest(carrier=value["carrier"]), self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "descriptor differs from the donor recipe"):
                byte_identity.require_same_function_carrier_source_identity(
                    ROOT, unit["source"], clean, effective,
                    donor["recipe"], normalized, overlaid, "fixture")

    def test_effective_source_generated_identifier_leakage_is_rejected(self):
        manifest, unit, donor, function = self.live_records()
        overlay = byte_identity.validate_source_overlay(
            manifest["source_overlay"], ROOT)
        effective = overlay["rendered_by_path"][unit["source"]]
        clean = (ROOT / unit["source"]).read_bytes()
        leaked = effective + b"extern int g_h00;\n"
        raw = copy.deepcopy(function["same_function_source_identity"])
        raw["effective_source_sha256"] = hashlib.sha256(leaked).hexdigest()
        rendered = byte_identity.render_extern_run_pair_recipe_source(
            leaked, donor["recipe"])
        raw["rendered_source_sha256"] = hashlib.sha256(rendered).hexdigest()
        raw["rendered_source_size"] = len(rendered)
        normalized = byte_identity.validate_same_function_carrier_source_identity(
            raw, "fixture.identity")
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "identity collides with source"):
            byte_identity.require_same_function_carrier_source_identity(
                ROOT, unit["source"], clean, leaked, donor["recipe"],
                normalized,
                {item["logical_path"] for item in overlay["outputs"]},
                "fixture")


class SourceFpoInstructionMosaicTests(unittest.TestCase):
    """A typed source refactor may feed only its isolated FPO composer."""

    DONOR_ID = "d_613e82f21601"

    def live_records(self):
        manifest = json.loads(
            (TOOLS / "byte_identity_manifest.json").read_text())
        unit = next(
            unit for unit in manifest["translation_units"]
            if any(donor.get("id") == self.DONOR_ID
                   for donor in unit.get("donors", [])))
        donor = next(item for item in unit["donors"]
                     if item["id"] == self.DONOR_ID)
        function = next(item for item in unit["functions"]
                        if item["donor"] == self.DONOR_ID)
        return manifest, unit, donor, function

    def fixture(self, *, debug_label_relocations=False):
        seed = make_fpo_instruction_mosaic_coff(
            source_refactor=True,
            debug_label_relocations=debug_label_relocations)
        donor = make_fpo_instruction_mosaic_coff(
            donor=True, source_refactor=True,
            debug_label_relocations=debug_label_relocations)
        seed_coff = byte_identity.CoffObject(seed)
        donor_coff = byte_identity.CoffObject(donor)
        sp = seed_coff.function_section(TARGET_SYMBOL)
        dp = donor_coff.function_section(TARGET_SYMBOL)
        seed_body = byte_identity.coff_body(seed_coff, sp)
        donor_body = byte_identity.coff_body(donor_coff, dp)
        hybrid = bytearray(seed)
        hybrid[sp["raw_offset"] + 24:sp["raw_offset"] + 28] = (
            donor_body[24:28])
        hybrid = bytes(hybrid)
        hybrid_coff = byte_identity.CoffObject(hybrid)
        hybrid_body = byte_identity.coff_body(
            hybrid_coff, hybrid_coff.function_section(TARGET_SYMBOL))

        def child_pin(name):
            left = byte_identity._comdat_child(seed_coff, sp, name)
            right = byte_identity._comdat_child(donor_coff, dp, name)
            definitions = byte_identity.section_definitions(seed_coff)
            return ({
                "section_number": left["number"],
                "expected_seed_raw_size": left["raw_size"],
                "expected_donor_raw_size": right["raw_size"],
                "relocation_count": left["relocation_count"],
                "line_count": left["line_count"],
                "characteristics": left["characteristics"],
                "selection": definitions[left["number"]]["selection"],
                "associated": definitions[left["number"]]["associated"],
                "expected_seed_body_sha256": hashlib.sha256(
                    byte_identity.coff_body(seed_coff, left)).hexdigest(),
                "expected_donor_body_sha256": hashlib.sha256(
                    byte_identity.coff_body(donor_coff, right)).hexdigest(),
                "expected_seed_relocation_sha256": hashlib.sha256(
                    byte_identity._coff_table_bytes(
                        seed_coff, left, "relocations")).hexdigest(),
                "expected_donor_relocation_sha256": hashlib.sha256(
                    byte_identity._coff_table_bytes(
                        donor_coff, right, "relocations")).hexdigest(),
            }, left, right)

        debug_f, sf, df = child_pin(".debug$F")
        debug_f["expected_record"] = byte_identity.parse_fpo_data(
            byte_identity.coff_body(seed_coff, sf),
            expected_proc_size=len(seed_body))
        debug_s, ss, ds = child_pin(".debug$S")
        seed_s = byte_identity.coff_body(seed_coff, ss)
        donor_s = byte_identity.coff_body(donor_coff, ds)
        cb_proc, dbg_start, dbg_end = struct.unpack_from("<III", seed_s, 16)
        debug_s.update({
            "expected_common_prefix_sha256": hashlib.sha256(
                seed_s[:28]).hexdigest(),
            "expected_record_kind": seed_s[2:4].hex(),
            "expected_cb_proc": cb_proc,
            "expected_dbg_start": dbg_start,
            "expected_dbg_end": dbg_end,
            "expected_seed_tail_sha256": hashlib.sha256(
                seed_s[28:]).hexdigest(),
            "expected_donor_tail_sha256": hashlib.sha256(
                donor_s[28:]).hexdigest(),
        })
        extra_rows = byte_identity.detailed_relocations(
            seed_coff, ss)[2:]
        if extra_rows:
            debug_s["expected_extra_relocations"] = [
                {key: row[key] for key in (
                    "offset", "width", "type", "addend", "target",
                    "target_section", "target_value", "target_type",
                    "target_storage",
                )}
                for row in extra_rows
            ]
        identity = byte_identity.validate_source_fpo_mosaic_identity({
            "kind": byte_identity.SOURCE_FPO_MOSAIC_IDENTITY_KIND,
            "expected_primary_characteristics": sp["characteristics"],
            "expected_primary_selection":
                byte_identity.section_definitions(seed_coff)[sp["number"]]
                ["selection"],
            "expected_function_count": sum(
                byte_identity.function_multiset(seed_coff).values()),
            "expected_comdat_count": sum(
                byte_identity.comdat_primary_identity_multiset(
                    seed_coff).values()),
            "expected_seed_line_sha256": hashlib.sha256(
                byte_identity._coff_table_bytes(
                    seed_coff, sp, "lines")).hexdigest(),
            "expected_donor_line_sha256": hashlib.sha256(
                byte_identity._coff_table_bytes(
                    donor_coff, dp, "lines")).hexdigest(),
            "debug_f": debug_f,
            "debug_s": debug_s,
        }, "fixture", sp["number"], len(seed_body))
        function = {
            "mangled": TARGET_SYMBOL,
            "donor": "d_source_fpo",
            "splice_class": "retail_exact_instruction_mosaic",
            "expected_section_number": sp["number"],
            "expected_section_count": len(seed_coff.sections),
            "expected_body_length": len(seed_body),
            "expected_donor_body_length": len(donor_body),
            "expected_relocation_count": sp["relocation_count"],
            "expected_line_count": sp["line_count"],
            "expected_donor_line_count": dp["line_count"],
            "expected_seed_body_sha256": hashlib.sha256(
                seed_body).hexdigest(),
            "expected_donor_body_sha256": hashlib.sha256(
                donor_body).hexdigest(),
            "expected_seed_metadata_sha256":
                byte_identity.instruction_mosaic_metadata_sha256(
                    seed_coff, sp),
            "expected_donor_metadata_sha256":
                byte_identity.instruction_mosaic_metadata_sha256(
                    donor_coff, dp),
            "expected_body_sha256": hashlib.sha256(hybrid_body).hexdigest(),
            "source_fpo_identity": identity,
            "instruction_ranges": [{
                "kind":
                    "same_offset_complete_x86_instruction_sequence_v1",
                "start": 24, "end": 28,
                "seed_bytes": seed_body[24:28].hex(),
                "seed_sha256": hashlib.sha256(
                    seed_body[24:28]).hexdigest(),
                "donor_bytes": donor_body[24:28].hex(),
                "donor_sha256": hashlib.sha256(
                    donor_body[24:28]).hexdigest(),
                "seed_instruction_lengths": [3, 1],
                "donor_instruction_lengths": [3, 1],
            }],
            "retail_oracle": {
                "image": "LEGO1.DLL", "address": "0x1003cf20",
                "verdict": "MATCH", "length": len(hybrid_body),
            },
            "retail_relocations": relocation_oracle_for(
                hybrid, retail_body_for(hybrid)),
        }
        return seed, donor, function, retail_body_for(hybrid), hybrid

    def compose(self, fixture, function=None, seed=None, donor=None,
                retail=None, source_permutation=True):
        base_seed, base_donor, expected, oracle, _ = fixture
        return byte_identity._compose_retail_exact_instruction_mosaic_core(
            base_seed if seed is None else seed,
            base_donor if donor is None else donor,
            expected if function is None else function,
            oracle if retail is None else retail,
            source_permutation=source_permutation,
        )

    def equal_body_fixture(self, *, debug_label_relocations=False):
        seed, donor, function, _, _ = self.fixture(
            debug_label_relocations=debug_label_relocations)
        seed_coff = byte_identity.CoffObject(seed)
        donor_coff = byte_identity.CoffObject(donor)
        sp = seed_coff.function_section(TARGET_SYMBOL)
        dp = donor_coff.function_section(TARGET_SYMBOL)
        seed_body = byte_identity.coff_body(seed_coff, sp)
        donor_body = byte_identity.coff_body(donor_coff, dp)
        whole = copy.deepcopy(function)
        for name in (
            "expected_donor_body_length", "expected_line_count",
            "instruction_ranges",
        ):
            whole.pop(name)
        whole.update({
            "splice_class":
                byte_identity.RETAIL_EXACT_SOURCE_EQUAL_BODY_CLASS,
            "expected_characteristics": sp["characteristics"],
            "expected_selection":
                byte_identity.section_definitions(seed_coff)[sp["number"]]
                ["selection"],
            "expected_seed_line_count": sp["line_count"],
            "expected_function_count": sum(
                byte_identity.function_multiset(seed_coff).values()),
            "expected_comdat_count": sum(
                byte_identity.comdat_primary_identity_multiset(
                    seed_coff).values()),
            "expected_body_sha256": hashlib.sha256(donor_body).hexdigest(),
            "expected_changed_offsets": [
                index for index, pair in enumerate(
                    zip(seed_body, donor_body)) if pair[0] != pair[1]
            ],
            "expected_code_renames": [],
            "expected_xdata_rename_offsets": [],
            "expected_debug_s_renames": [],
            "expected_closure": [".debug$F", ".debug$S"],
            "target_source_refactor": {"fixture": True},
        })
        retail = retail_body_for(donor)
        whole["retail_relocations"] = relocation_oracle_for(seed, retail)
        return seed, donor, whole, retail

    def compose_equal_body(self, fixture, function=None):
        seed, donor, expected, retail = fixture
        with mock.patch.object(
            byte_identity, "require_target_source_refactor_identity",
            return_value={"source_refactor_identity": True},
        ):
            return byte_identity.compose_retail_exact_source_equal_body(
                seed, donor, expected if function is None else function,
                retail, b"seed source", b"donor source")

    def test_equal_body_fpo_branch_keeps_seed_metadata_shell(self):
        fixture = self.equal_body_fixture(debug_label_relocations=True)
        seed, donor, function, _ = fixture
        composed, detail = self.compose_equal_body(fixture)
        seed_coff = byte_identity.CoffObject(seed)
        donor_coff = byte_identity.CoffObject(donor)
        checked = byte_identity.CoffObject(composed)
        sp = seed_coff.function_section(TARGET_SYMBOL)
        dp = donor_coff.function_section(TARGET_SYMBOL)
        cp = checked.function_section(TARGET_SYMBOL)
        start, end = sp["raw_offset"], sp["raw_offset"] + sp["raw_size"]
        self.assertEqual(composed[:start], seed[:start])
        self.assertEqual(composed[end:], seed[end:])
        self.assertEqual(
            byte_identity.coff_body(checked, cp),
            byte_identity.coff_body(donor_coff, dp))
        self.assertEqual(
            byte_identity._coff_table_bytes(checked, cp, "lines"),
            byte_identity._coff_table_bytes(seed_coff, sp, "lines"))
        for child_name in (".debug$F", ".debug$S"):
            before = byte_identity._comdat_child(
                seed_coff, sp, child_name)
            after = byte_identity._comdat_child(
                checked, cp, child_name)
            self.assertEqual(
                byte_identity.coff_body(checked, after),
                byte_identity.coff_body(seed_coff, before))
        self.assertTrue(detail["source_fpo_identity"])
        self.assertEqual(detail["body_changed_offsets"],
                         function["expected_changed_offsets"])

    def test_equal_body_fpo_branch_requires_complete_identity(self):
        fixture = self.equal_body_fixture()
        bad = copy.deepcopy(fixture[2])
        bad.pop("source_fpo_identity")
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "target closure"):
            self.compose_equal_body(fixture, bad)

        bad = copy.deepcopy(fixture[2])
        bad["source_fpo_identity"]["expected_donor_line_sha256"] = "0" * 64
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "line-table pin"):
            self.compose_equal_body(fixture, bad)

    def test_equal_body_extra_fpo_relocations_are_exactly_pinned(self):
        fixture = self.equal_body_fixture(debug_label_relocations=True)
        identity = fixture[2]["source_fpo_identity"]
        extras = identity["debug_s"]["expected_extra_relocations"]
        self.assertEqual(len(extras), 2)
        self.assertEqual(
            [(item["offset"], item["width"], item["type"],
              item["target"], item["target_section"],
              item["target_value"], item["target_type"],
              item["target_storage"])
             for item in extras],
            [(34, 4, 11, "$done$123", 1, 24, 0, 6),
             (38, 2, 10, "$done$123", 1, 24, 0, 6)],
        )
        mutations = {
            "offset": extras[0]["offset"] + 1,
            "width": 2,
            "type": 20,
            "addend": 1,
            "target": "$other$123",
            "target_section": extras[0]["target_section"] + 1,
            "target_value": extras[0]["target_value"] + 1,
            "target_type": 1,
            "target_storage": 3,
        }
        for field, value in mutations.items():
            bad = copy.deepcopy(fixture[2])
            bad["source_fpo_identity"]["debug_s"][
                "expected_extra_relocations"][0][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "extra semantic relocations"):
                self.compose_equal_body(fixture, bad)

        missing = copy.deepcopy(identity)
        missing["debug_s"].pop("expected_extra_relocations")
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "CodeView procedure record"):
            byte_identity.validate_source_fpo_mosaic_identity(
                missing, "fixture", 1, SEED_SIZE)

        empty = copy.deepcopy(identity)
        empty["debug_s"]["expected_extra_relocations"] = []
        empty["debug_s"]["relocation_count"] = 2
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "is empty"):
            byte_identity.validate_source_fpo_mosaic_identity(
                empty, "fixture", 1, SEED_SIZE)

    def test_positive_allows_pinned_codeview_growth_but_keeps_seed_shell(self):
        fixture = self.fixture()
        composed, detail = self.compose(fixture)
        seed, donor, function, _, hybrid = fixture
        checked = byte_identity.CoffObject(composed)
        primary = checked.function_section(TARGET_SYMBOL)
        seed_coff = byte_identity.CoffObject(seed)
        seed_primary = seed_coff.function_section(TARGET_SYMBOL)
        donor_coff = byte_identity.CoffObject(donor)
        donor_primary = donor_coff.function_section(TARGET_SYMBOL)
        self.assertEqual(
            byte_identity.coff_body(checked, primary),
            byte_identity.coff_body(
                byte_identity.CoffObject(hybrid),
                byte_identity.CoffObject(hybrid).function_section(
                    TARGET_SYMBOL)))
        self.assertNotEqual(
            byte_identity._comdat_child(
                seed_coff, seed_primary, ".debug$S")["raw_size"],
            byte_identity._comdat_child(
                donor_coff, donor_primary, ".debug$S")["raw_size"])
        for name in (".debug$F", ".debug$S"):
            before = byte_identity._comdat_child(
                seed_coff, seed_primary, name)
            after = byte_identity._comdat_child(checked, primary, name)
            self.assertEqual(
                byte_identity.coff_body(checked, after),
                byte_identity.coff_body(seed_coff, before))
        self.assertEqual(
            byte_identity.instruction_mosaic_metadata_sha256(
                checked, primary),
            function["expected_seed_metadata_sha256"])
        self.assertTrue(detail["source_fpo_identity"])
        byte_identity.validate_donor_object_excluded(composed, [donor])

    def test_live_generator_inverse_recipe_and_semantic_witness(self):
        manifest, unit, donor, function = self.live_records()
        overlay = byte_identity.validate_source_overlay(
            manifest["source_overlay"], ROOT)
        output = next(
            item for item in overlay["outputs"]
            if item["logical_path"] == unit["source"])
        proof = byte_identity.validate_target_source_refactor_proof(
            function["target_source_refactor"], "fixture.proof")
        normalized_function = {**function, "target_source_refactor": proof}
        detail = byte_identity.require_target_source_refactor_recipe_policy(
            donor["recipe"], normalized_function, ROOT, unit["source"],
            "fixture", output["operations"],
            {item["logical_path"] for item in overlay["outputs"]},
        )
        rendered = byte_identity.render_donor_source_overlay(
            donor["recipe"], ROOT,
            canonical_operations=output["operations"])
        self.assertEqual(
            hashlib.sha256(rendered[unit["source"]]).hexdigest(),
            donor["recipe"]["renderings"][0]["rendered_sha256"])
        generator = byte_identity.validate_source_overlay_generator(
            donor["recipe"]["renderings"][0]["operations"][0]["gen"],
            "fixture.generator")
        self.assertEqual(
            hashlib.sha256(
                byte_identity.render_fixed_array_shuffle_countdown_input(
                    generator["params"])).hexdigest(),
            "10f00454b3c20b09846d2f00cf0da59fba9502dc8d5444a1478fb3d9036f5654")
        self.assertEqual(
            hashlib.sha256(
                byte_identity.render_source_overlay_generator(
                    generator)).hexdigest(),
            "1b32636fbc36bd7df1628b9e036e2d47fd7837f4f70fb265cf83c1fb84468198")
        self.assertEqual(detail["shuffle_extent"], 640)

    def test_semantic_witness_rejects_extent_pin_and_header_overlay_drift(self):
        manifest, unit, donor, function = self.live_records()
        overlay = byte_identity.validate_source_overlay(
            manifest["source_overlay"], ROOT)
        output = next(
            item for item in overlay["outputs"]
            if item["logical_path"] == unit["source"])
        overlaid_paths = {
            item["logical_path"] for item in overlay["outputs"]
        }
        proof = byte_identity.validate_target_source_refactor_proof(
            function["target_source_refactor"], "fixture.proof")

        bad = copy.deepcopy(proof)
        bad["semantic_witness"]["extent"] -= 1
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "roles, types, or extent"):
            byte_identity.require_target_source_refactor_recipe_policy(
                donor["recipe"], {**function, "target_source_refactor": bad},
                ROOT, unit["source"], "fixture", output["operations"],
                overlaid_paths)

        bad = copy.deepcopy(proof)
        bad["semantic_witness"]["owner_header"]["source_sha256"] = "0" * 64
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "differs from its pin"):
            byte_identity.require_target_source_refactor_recipe_policy(
                donor["recipe"], {**function, "target_source_refactor": bad},
                ROOT, unit["source"], "fixture", output["operations"],
                overlaid_paths)

        witness_path = proof["semantic_witness"]["owner_header"]["path"]
        manifest["source_overlay"]["outputs"].append({"path": witness_path})
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "witness header.*source overlay"):
            byte_identity.require_manifest_source_refactor_role_preflight(
                manifest, "fixture", ROOT)

    def test_generator_rejects_free_keys_role_collisions_and_type_drift(self):
        _, _, donor, _ = self.live_records()
        raw = donor["recipe"]["renderings"][0]["operations"][0]["gen"]
        mutations = (
            ({**raw, "body": "arbitrary"}, "schema"),
            ({**raw, "pointer": raw["index"]}, "distinct"),
            ({**raw, "element_type": "Widget"}, "integral"),
            ({**raw, "count": 0}, "count"),
        )
        for bad, message in mutations:
            with self.subTest(message=message), self.assertRaisesRegex(
                    byte_identity.ByteIdentityError, message):
                byte_identity.validate_source_overlay_generator(
                    bad, "fixture")
        normalized = byte_identity.validate_source_overlay_generator(
            raw, "fixture")
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "donor-only"):
            byte_identity.assert_source_permutations_are_donor_only(
                normalized)

    def test_live_role_preflight_rejects_unbound_and_ordinary_reuse(self):
        manifest, unit, _, function = self.live_records()
        byte_identity.require_manifest_source_refactor_role_preflight(
            manifest, "fixture", ROOT)
        unit["functions"].remove(function)
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "bound exactly once"):
            byte_identity.require_manifest_source_refactor_role_preflight(
                manifest, "fixture", ROOT)
        unit["functions"].append(function)
        reused = copy.deepcopy(function)
        reused.pop("target_source_refactor")
        reused.pop("source_fpo_identity")
        reused["mangled"] = "?AnotherSourceFpoFixture@@YAXXZ"
        unit["functions"].append(reused)
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "primary donor use"):
            byte_identity.require_manifest_source_refactor_role_preflight(
                manifest, "fixture", ROOT)

    def test_live_role_preflight_rejects_alternate_composer_class(self):
        manifest, _, _, function = self.live_records()
        function["splice_class"] = "retail_exact_reloc_divergent"
        function.pop("source_fpo_identity")
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "isolated source FPO"):
            byte_identity.require_manifest_source_refactor_role_preflight(
                manifest, "fixture", ROOT)

    def test_decoder_accepts_shuffle_encodings_and_fails_closed(self):
        accepted = {
            "8d7e36": 3, "668b6ffe": 4, "66894ffe": 4,
            "e800000000": 5, "99": 1, "4b": 1, "4f": 1,
        }
        for encoded, length in accepted.items():
            with self.subTest(encoded=encoded):
                self.assertEqual(
                    byte_identity.supported_ia32_instruction_length(
                        bytes.fromhex(encoded), "fixture"), length)
        for encoded in (
            "66", "66668b00", "e80000", "8d", "9090", "8d7e3690",
        ):
            with self.subTest(encoded=encoded), self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "unsupported|truncated|prefix|ModRM|not one complete"):
                byte_identity.require_supported_complete_ia32_instruction(
                    bytes.fromhex(encoded), "fixture")

    def test_source_fpo_identity_rejects_geometry_body_and_record_drift(self):
        fixture = self.fixture()
        checks = (
            (("expected_function_count",), "function census"),
            (("debug_f", "associated"), "geometry"),
            (("debug_f", "expected_donor_body_sha256"), "body pin"),
            (("debug_f", "expected_record", "cbProcSize"), "parsed FPO"),
            (("debug_s", "expected_donor_raw_size"), "geometry"),
            (("debug_s", "expected_donor_tail_sha256"),
             "CodeView procedure"),
            (("debug_s", "expected_dbg_end"),
             "CodeView procedure range"),
        )
        for path, message in checks:
            bad = copy.deepcopy(fixture[2])
            target = bad["source_fpo_identity"]
            for key in path[:-1]:
                target = target[key]
            key = path[-1]
            value = target[key]
            target[key] = "0" * 64 if isinstance(value, str) else value + 1
            with self.subTest(path=path), self.assertRaisesRegex(
                    byte_identity.ByteIdentityError, message):
                self.compose(fixture, bad)

    def test_source_fpo_rejects_child_semantic_relocation_drift(self):
        fixture = self.fixture()
        donor = bytearray(fixture[1])
        parsed = byte_identity.CoffObject(bytes(donor))
        primary = parsed.function_section(TARGET_SYMBOL)
        child = byte_identity._comdat_child(parsed, primary, ".debug$F")
        other_index = next(
            index for index, symbol in parsed.symbols.items()
            if symbol["name"] == OTHER)
        struct.pack_into(
            "<I", donor, child["relocation_offset"] + 4, other_index)
        donor = bytes(donor)
        changed = byte_identity.CoffObject(donor)
        changed_primary = changed.function_section(TARGET_SYMBOL)
        changed_child = byte_identity._comdat_child(
            changed, changed_primary, ".debug$F")
        bad = copy.deepcopy(fixture[2])
        bad["source_fpo_identity"]["debug_f"][
            "expected_donor_relocation_sha256"] = hashlib.sha256(
                byte_identity._coff_table_bytes(
                    changed, changed_child, "relocations")).hexdigest()
        bad["expected_donor_metadata_sha256"] = (
            byte_identity.instruction_mosaic_metadata_sha256(
                changed, changed_primary))
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "relocation"):
            self.compose(fixture, bad, donor=donor)

    def test_source_fpo_rejects_relocation_overlap_even_when_bytes_match(self):
        fixture = self.fixture()
        seed_coff = byte_identity.CoffObject(fixture[0])
        donor_coff = byte_identity.CoffObject(fixture[1])
        seed_primary = seed_coff.function_section(TARGET_SYMBOL)
        donor_primary = donor_coff.function_section(TARGET_SYMBOL)
        seed_body = byte_identity.coff_body(seed_coff, seed_primary)
        donor_body = byte_identity.coff_body(donor_coff, donor_primary)
        bad = copy.deepcopy(fixture[2])
        bad["instruction_ranges"] = [{
            "kind": "same_offset_complete_x86_instruction_sequence_v1",
            "start": 20, "end": 28,
            "seed_bytes": seed_body[20:28].hex(),
            "seed_sha256": hashlib.sha256(seed_body[20:28]).hexdigest(),
            "donor_bytes": donor_body[20:28].hex(),
            "donor_sha256": hashlib.sha256(donor_body[20:28]).hexdigest(),
            "seed_instruction_lengths": [4, 3, 1],
            "donor_instruction_lengths": [4, 3, 1],
        }]
        with mock.patch.object(
                byte_identity,
                "require_coff_line_certified_ia32_boundaries",
                return_value={}), self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "source FPO.*overlaps a relocation operand"):
            self.compose(fixture, bad)

    def test_source_fpo_rejects_wrong_line_sentinel_identity(self):
        fixture = self.fixture()
        donor = bytearray(fixture[1])
        parsed = byte_identity.CoffObject(bytes(donor))
        primary = parsed.function_section(TARGET_SYMBOL)
        other_index = next(
            index for index, symbol in parsed.symbols.items()
            if symbol["name"] == OTHER)
        struct.pack_into("<I", donor, primary["line_offset"], other_index)
        donor = bytes(donor)
        changed = byte_identity.CoffObject(donor)
        changed_primary = changed.function_section(TARGET_SYMBOL)
        bad = copy.deepcopy(fixture[2])
        bad["source_fpo_identity"]["expected_donor_line_sha256"] = (
            hashlib.sha256(byte_identity._coff_table_bytes(
                changed, changed_primary, "lines")).hexdigest())
        bad["expected_donor_metadata_sha256"] = (
            byte_identity.instruction_mosaic_metadata_sha256(
                changed, changed_primary))
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "line marker changed identity"):
            self.compose(fixture, bad, donor=donor)

    def test_source_and_ordinary_fpo_classes_cannot_cross(self):
        fixture = self.fixture()
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "requires the source-permutation"):
            self.compose(fixture, source_permutation=False)
        bad = copy.deepcopy(fixture[2])
        bad["ordinary_fpo_identity"] = {}
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "mutually exclusive"):
            self.compose(fixture, bad)
        eh_seed = make_divergent_coff()
        eh_donor = _patched_target_body(
            eh_seed, [(24, bytes.fromhex("8b590441"))])
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "source FPO.*closure"):
            self.compose(fixture, seed=eh_seed, donor=eh_donor)

    def test_line_certificate_rejects_partial_range_and_bad_partition(self):
        seed, _, function, _, _ = self.fixture()
        coff = byte_identity.CoffObject(seed)
        primary = coff.function_section(TARGET_SYMBOL)
        body = byte_identity.coff_body(coff, primary)
        base = function["instruction_ranges"][0]
        cases = (
            ({**base, "start": 25,
              "seed_instruction_lengths": [2, 1]}, "containing-stream"),
            ({**base, "end": 26,
              "seed_instruction_lengths": [3]}, "containing-stream"),
            ({**base, "seed_instruction_lengths": [2, 2]}, "partition"),
        )
        for item, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(
                    byte_identity.ByteIdentityError, message):
                byte_identity.require_coff_line_certified_ia32_boundaries(
                    coff, primary, body, [item], "seed", TARGET_SYMBOL,
                    "fixture")

    def test_retail_and_output_conservation_gates_reject_drift(self):
        fixture = self.fixture()
        retail = bytearray(fixture[3])
        retail[8] ^= 1
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "retail-exact"):
            self.compose(fixture, retail=bytes(retail))
        original = byte_identity.apply_replacements

        def corrupt(data, replacements):
            output = bytearray(original(data, replacements))
            output[byte_identity.CoffObject(data).sections[3][
                "raw_offset"]] ^= 1
            return bytes(output)

        with mock.patch.object(byte_identity, "apply_replacements",
                               side_effect=corrupt):
            with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                        "non-target"):
                self.compose(fixture)

        bad = copy.deepcopy(fixture[2])
        bad["retail_relocations"][0]["retail_target"] = "0x10000000"
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "resolves to"):
            self.compose(fixture, bad)

        seed_coff = byte_identity.CoffObject(fixture[0])
        primary = seed_coff.function_section(TARGET_SYMBOL)
        debug_s = byte_identity._comdat_child(
            seed_coff, primary, ".debug$S")

        def corrupt_debug_child(data, replacements):
            output = bytearray(original(data, replacements))
            output[debug_s["raw_offset"] + debug_s["raw_size"] - 1] ^= 1
            return bytes(output)

        with mock.patch.object(byte_identity, "apply_replacements",
                               side_effect=corrupt_debug_child):
            with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                        "non-target"):
                self.compose(fixture)

    def test_live_manifest_uses_complete_fpo_body_without_ranges(self):
        _, _, donor, function = self.live_records()
        self.assertEqual(
            donor["recipe"]["rendering_identity_sha256"],
            "613e82f21601cbcd402434a74805e45b6491dc88e45f8957bc0297872678c5bc")
        self.assertEqual(
            function["splice_class"],
            byte_identity.RETAIL_EXACT_SOURCE_EQUAL_BODY_CLASS)
        self.assertNotIn("instruction_ranges", function)
        self.assertEqual(function["expected_changed_offsets"],
                         [61, 63, 69, 79, 88, 98])
        self.assertEqual(function["expected_closure"],
                         [".debug$F", ".debug$S"])
        self.assertEqual(function["expected_seed_line_count"], 42)
        self.assertEqual(function["expected_donor_line_count"], 44)
        self.assertEqual(len(function["retail_relocations"]), 8)
        self.assertEqual(
            function["source_fpo_identity"]["kind"],
            byte_identity.SOURCE_FPO_MOSAIC_IDENTITY_KIND)


if __name__ == "__main__":
    unittest.main()
