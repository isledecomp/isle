"""Tests for the register-bijection CERTIFICATE class.

The class installs sigma(donor body) and refuses unless the result is
retail's own code.  These tests fix the four refusals that make that claim
honest -- a bijection that cannot preserve an encoding's length, one that
meets an instruction with an implicit general-register operand, one that
would rewrite a relocated byte, and one whose image is not the oracle -- plus
the liveness boundary proof and the CodeView register mapping.

The fixture is a complete classic-i386 COMDAT with the ordinary FPO closure
(`.debug$F`, `.debug$S`) and a body of real, decodable VC4.2-shaped code:

    0:  53              push ebx          <- prologue, outside the region
    1:  56              push esi
    2:  57              push edi
    3:  8b 1d <D32>     mov  ebx, [_Nil]  <- region starts here
    9:  8b fb           mov  edi, ebx
    11: 3b 3d <D32>     cmp  edi, [_Nil]
    17: 74 08           je   27
    19: 8b 1d <D32>     mov  ebx, [_Nil]
    25: 8b fb           mov  edi, ebx
    27: 5f              pop  edi          <- epilogue, outside the region
    28: 5e              pop  esi
    29: 5b              pop  ebx
    30: c3              ret
"""
from __future__ import annotations

import copy
import hashlib
import struct
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import byte_identity  # noqa: E402


TARGET_SYMBOL = "?_Erase@?$_Tree@PAVFixture@@@@IAEXPAU_Node@1@@Z"
NIL_SYMBOL = "?_Nil@?$_Tree@PAVFixture@@@@1PAU_Node@1@A"
OTHER_SYMBOL = "?Other@@YAXXZ"
DIRECTIVE = b"-defaultlib:LIBCMT -defaultlib:OLDNAMES "
RETAIL_ADDRESS = 0x10057180
REGION = (3, 27)
SIGMA = {"ebx": "edi", "edi": "ebx"}

BODY = bytes.fromhex(
    "535657"          # push ebx / push esi / push edi
    "8b1d00000000"    # mov ebx, [_Nil]
    "8bfb"            # mov edi, ebx
    "3b3d00000000"    # cmp edi, [_Nil]
    "7408"            # je 27
    "8b1d00000000"    # mov ebx, [_Nil]
    "8bfb"            # mov edi, ebx
    "5f5e5b"          # pop edi / pop esi / pop ebx
    "c3"              # ret
)
SIZE = len(BODY)
RELOCATIONS = (5, 13, 21)


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
    struct.pack_into("<IIII", result, 0, 0, total_size, line_pointer, 0)
    return bytes(result)


def _marker_aux(line, next_function=0):
    result = bytearray(18)
    struct.pack_into("<I", result, 0, 0)
    struct.pack_into("<H", result, 4, line)
    struct.pack_into("<I", result, 12, next_function)
    return bytes(result)


def codeview_stream(register_numbers=(23, 24)):
    """A well-formed CodeView symbol stream: S_LPROC32, two S_REGISTERs, END.

    The second S_REGISTER names the local the bijection moves, exactly as the
    real `_Tree::_Erase` closure names `_Y`.
    """
    records = bytearray()

    def record(kind, payload):
        records.extend(struct.pack("<HH", len(payload) + 2, kind))
        records.extend(payload)

    proc = bytearray(33)
    struct.pack_into("<III", proc, 12, SIZE, 3, SIZE - 4)
    name = b"_Tree<Fixture>::_Erase"
    record(0x0205, bytes(proc) + bytes([len(name)]) + name)
    for index, number in enumerate(register_numbers):
        payload = struct.pack("<HH", 0x74, number)
        local = b"this" if index == 0 else b"_Y"
        record(0x0002, payload + bytes([len(local)]) + local)
    record(0x0006, b"")
    return bytes(records)


def make_coff(*, body=BODY, relocations=RELOCATIONS,
              debug_stream=None, extra_relocations=()):
    """One classic-i386 COFF with an ordinary FPO COMDAT closure."""
    debug_s = debug_stream if debug_stream is not None else codeview_stream()
    fpo = struct.pack("<IIIHBB", 0, len(body), 2, 1, 2, 0x10)
    target_index = 4
    nil_index = 10
    lines = bytearray(struct.pack("<IH", target_index, 0))
    lines.extend(struct.pack("<IH", 3, 11))
    lines.extend(struct.pack("<IH", 19, 12))
    reloc_rows = [(offset, nil_index, 0x0006) for offset in relocations]
    reloc_rows.extend(extra_relocations)
    section_inputs = [
        {"name": ".text", "raw": bytes(body), "relocations": reloc_rows,
         "lines": bytes(lines), "characteristics": 0x60501020},
        {"name": ".debug$F", "raw": fpo, "relocations": [],
         "lines": b"", "characteristics": 0x42101040},
        {"name": ".debug$S", "raw": debug_s, "relocations": [],
         "lines": b"", "characteristics": 0x42101048},
        {"name": ".text", "raw": b"OTHER-FN", "relocations": [],
         "lines": struct.pack("<IH", 16, 0) + struct.pack("<IH", 1, 77),
         "characteristics": 0x60501020},
        {"name": ".drectve", "raw": DIRECTIVE, "relocations": [],
         "lines": b"", "characteristics": 0x00100A00},
    ]
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
    checksum = int.from_bytes(
        hashlib.sha256(bytes(body)).digest()[:4], "little")
    symbols = [
        (".text", 0, 1, 0, 3,
         _section_aux(len(body), len(reloc_rows), len(lines) // 6, 2,
                      checksum=checksum)),
        (".file", 0, -2, 0, 103, b"fixture.cpp\0".ljust(18, b"\0")),
        (TARGET_SYMBOL, 0, 1, 0x20, 2,
         _function_aux(len(body), sections[0]["line_offset"])),
        (".bf", 0, 1, 0, 101, _marker_aux(11)),
        (".ef", len(body), 1, 0, 101, _marker_aux(13)),
        (".debug$F", 0, 2, 0, 3,
         _section_aux(len(fpo), 0, 0, 5, associated=1)),
        (".debug$S", 0, 3, 0, 3,
         _section_aux(len(debug_s), 0, 0, 5, associated=1)),
        (NIL_SYMBOL, 0, 0, 0x00, 2, None),
        (".text", 0, 4, 0, 3, _section_aux(8, 0, 2, 2, checksum=0x1234)),
        (OTHER_SYMBOL, 0, 4, 0x20, 2,
         _function_aux(8, sections[3]["line_offset"])),
        (".bf", 0, 4, 0, 101, _marker_aux(70)),
        (".ef", 8, 4, 0, 101, _marker_aux(71)),
        (".drectve", 0, 5, 0, 3, _section_aux(len(DIRECTIVE), 0, 0, 0)),
    ]
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


def relocation_set(offsets=RELOCATIONS):
    return frozenset(offset + byte
                     for offset in offsets for byte in range(4))


def sigma_image(body=BODY):
    image, _ = byte_identity.apply_register_bijection(
        body, SIGMA, REGION, relocation_set(), "fixture")
    return image


def retail_body_for(image):
    """Retail's own bytes: the image with its DIR32 operands resolved."""
    resolved = bytearray(image)
    for offset in RELOCATIONS:
        resolved[offset:offset + 4] = struct.pack("<I", 0x100F3200)
    return bytes(resolved)


def relocation_oracle(seed_bytes):
    coff = byte_identity.CoffObject(seed_bytes)
    primary = coff.function_section(TARGET_SYMBOL)
    rows = byte_identity.detailed_relocations(coff, primary)
    return [{
        "offset": row["offset"], "type": row["type"], "addend": row["addend"],
        "target": row["target"], "target_section": row["target_section"],
        "target_value": row["target_value"], "target_type": row["target_type"],
        "target_storage": row["target_storage"],
        "retail_target": "0x100f3200",
    } for row in rows]


def function_record(seed_bytes, donor_bytes, image, **overrides):
    seed = byte_identity.CoffObject(seed_bytes)
    donor = byte_identity.CoffObject(donor_bytes)
    sp = seed.function_section(TARGET_SYMBOL)
    dp = donor.function_section(TARGET_SYMBOL)
    seed_body = byte_identity.coff_body(seed, sp)
    donor_body = byte_identity.coff_body(donor, dp)
    debug_child = byte_identity._comdat_child(seed, sp, ".debug$S")
    debug_stream = byte_identity.coff_body(seed, debug_child)
    declared = [{
        "name": "_Y", "record_offset": next(
            record["offset"] for record in
            byte_identity.parse_codeview_symbol_stream(debug_stream, "x")
            if record["type"] == 0x0002 and record["name"] == "_Y"),
        "donor_register": "edi", "image_register": "ebx",
    }]
    debug_image = byte_identity.apply_codeview_register_bijection(
        debug_stream, SIGMA, declared, "x")
    record = {
        "mangled": TARGET_SYMBOL,
        "donor": "d_0123456789ab",
        "splice_class": byte_identity.REGISTER_BIJECTION_CLASS,
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
            "address": "0x%08x" % RETAIL_ADDRESS,
            "verdict": "MATCH",
            "length": len(image),
        },
        "retail_relocations": relocation_oracle(seed_bytes),
        "register_bijection": {
            "kind": byte_identity.REGISTER_BIJECTION_KIND,
            "mapping": dict(SIGMA),
            "region_start": REGION[0], "region_end": REGION[1],
            "expected_region_instruction_count": 6,
            "expected_instruction_count": 13,
            "expected_rewritten_offsets": [4, 10, 12, 20, 26],
            "debug_s_register_map": declared,
            "expected_seed_debug_s_sha256":
                byte_identity.sha256_bytes(debug_stream),
            "expected_image_debug_s_sha256":
                byte_identity.sha256_bytes(debug_image),
            "authenticity_rationale":
                "A bijective renaming of general registers proved dead on "
                "entry and dead on exit for the region.",
        },
    }
    record.update(overrides)
    return record


class RegisterBijectionImageTests(unittest.TestCase):
    """Obligations 2, 4, 5, 6 and 7: the image itself."""

    def test_positive_control_is_the_expected_renaming(self):
        image, proof = byte_identity.apply_register_bijection(
            BODY, SIGMA, REGION, relocation_set(), "fixture")
        self.assertEqual(proof["rewritten_offsets"], [4, 10, 12, 20, 26])
        self.assertEqual(proof["region_instruction_count"], 6)
        self.assertEqual(proof["instruction_count"], 13)
        self.assertEqual(len(image), len(BODY))
        # the prologue and epilogue are untouched, and the region is sigma
        self.assertEqual(image[:3], BODY[:3])
        self.assertEqual(image[27:], BODY[27:])
        self.assertEqual(image[3:5], bytes.fromhex("8b3d"))
        self.assertEqual(image[9:11], bytes.fromhex("8bdf"))
        self.assertEqual(image[11:13], bytes.fromhex("3b1d"))

    def test_refuses_a_bijection_that_cannot_preserve_a_length(self):
        """EBP/ESP encodings carry ModRM/SIB structure.

        `mov ebx, [_Nil]` is `8b 1d D32`; renaming EBX to EBP would turn
        `mov ebx, [ebx]` into a disp32 form and `[esp]` into a SIB form, so
        every such mapping is refused before a single byte is rewritten.
        """
        for mapping in ({"ebx": "ebp", "ebp": "ebx"},
                        {"esi": "esp", "esp": "esi"}):
            with self.assertRaises(byte_identity.ByteIdentityError) as caught:
                byte_identity.apply_register_bijection(
                    BODY, mapping, REGION, relocation_set(), "fixture")
            self.assertIn("ESP or EBP", str(caught.exception))

    def test_refuses_an_instruction_with_an_implicit_operand(self):
        """CDQ writes EDX and MUL reads/writes EDX:EAX implicitly.

        Neither can be expressed under a renaming, so both are outside the
        closed table and the whole body is refused rather than approximated.
        """
        for encoding, name in ((b"\x99", "cdq"), (b"\xf7\xe3", "mul ebx")):
            body = BODY[:25] + encoding + BODY[25 + len(encoding):]
            with self.assertRaises(byte_identity.ByteIdentityError) as caught:
                byte_identity.apply_register_bijection(
                    body, SIGMA, REGION, relocation_set(), name)
            self.assertIn("outside the register-bijection table",
                          str(caught.exception))

    def test_refuses_a_rewrite_that_overlaps_a_relocation(self):
        """A relocated operand belongs to the linker, not to sigma."""
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.apply_register_bijection(
                BODY, SIGMA, REGION,
                relocation_set() | {4}, "fixture")
        self.assertIn("overlaps a relocation", str(caught.exception))

    def test_refuses_a_region_whose_registers_are_live_on_entry(self):
        """Starting at `mov edi, ebx` makes EBX an input of the region."""
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.apply_register_bijection(
                BODY, SIGMA, (9, 27), relocation_set(), "fixture")
        self.assertIn("live on entry", str(caught.exception))

    def test_refuses_a_region_whose_registers_are_live_on_exit(self):
        """Ending before the epilogue's `pop`s leaves EBX/EDI live at RET."""
        body = bytearray(BODY)
        # `pop edi` / `pop esi` become `mov ebx, ebx`, so EDI reaches the RET
        # without being restored and is therefore an output of the region.
        body[27:29] = bytes.fromhex("8bdb")
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.apply_register_bijection(
                bytes(body), SIGMA, REGION, relocation_set(), "fixture")
        self.assertIn("live on an edge leaving the region",
                      str(caught.exception))

    def test_refuses_a_region_that_is_not_instruction_aligned(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.apply_register_bijection(
                BODY, SIGMA, (4, 27), relocation_set(), "fixture")
        self.assertIn("whole instructions", str(caught.exception))

    def test_refuses_a_branch_into_the_middle_of_the_region(self):
        body = bytearray(BODY)
        body[18] = 0x06        # je 25 -- lands inside, not at the entry
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.apply_register_bijection(
                bytes(body), SIGMA, (19, 27), relocation_set(), "fixture")
        self.assertIn("enters the region", str(caught.exception))

    def test_refuses_a_mapping_that_is_not_a_bijection(self):
        with self.assertRaises(byte_identity.ByteIdentityError):
            byte_identity.apply_register_bijection(
                BODY, {"ebx": "edi"}, REGION, relocation_set(), "fixture")

    def test_decodes_the_body_to_exhaustion(self):
        # cut inside the six-byte `mov ebx, [_Nil]` at 19
        with self.assertRaises(byte_identity.ByteIdentityError):
            byte_identity.decode_ia32_bijection_body(
                BODY[:22], "truncated")


class CodeViewRegisterMapTests(unittest.TestCase):
    """Obligation 9: the debug records name the register the code uses."""

    def test_maps_only_the_declared_register_records(self):
        stream = codeview_stream()
        declared = [{
            "name": "_Y",
            "record_offset": next(
                record["offset"] for record in
                byte_identity.parse_codeview_symbol_stream(stream, "x")
                if record["type"] == 0x0002 and record["name"] == "_Y"),
            "donor_register": "edi", "image_register": "ebx",
        }]
        image = byte_identity.apply_codeview_register_bijection(
            stream, SIGMA, declared, "x")
        self.assertEqual(len(image), len(stream))
        records = byte_identity.parse_codeview_symbol_stream(image, "x")
        registers = [
            int.from_bytes(image[record["offset"] + 6:
                                 record["offset"] + 8], "little")
            for record in records if record["type"] == 0x0002
        ]
        self.assertEqual(registers, [23, 20])   # esi untouched, edi -> ebx

    def test_refuses_an_undeclared_register_record(self):
        stream = codeview_stream(register_numbers=(24, 24))
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.apply_codeview_register_bijection(
                stream, SIGMA, [], "x")
        self.assertIn("differs from its declaration", str(caught.exception))


class RegisterBijectionCompositionTests(unittest.TestCase):
    """Obligations 1, 3, 8 and 10: the composition itself."""

    def setUp(self):
        self.seed = make_coff()
        self.donor = make_coff()
        self.image = sigma_image()
        self.retail = retail_body_for(self.image)
        self.function = function_record(self.seed, self.donor, self.image)

    def test_positive_control_installs_the_retail_image(self):
        composed, detail = (
            byte_identity.compose_retail_exact_register_bijection(
                self.seed, self.donor, self.function, self.retail))
        coff = byte_identity.CoffObject(composed)
        primary = coff.function_section(TARGET_SYMBOL)
        self.assertEqual(byte_identity.coff_body(coff, primary), self.image)
        self.assertTrue(detail["retail_exact"])
        self.assertEqual(detail["rewritten_offsets"], [4, 10, 12, 20, 26])
        # the prologue and epilogue survive literally
        self.assertEqual(
            byte_identity.coff_body(coff, primary)[:3], BODY[:3])
        # and the CodeView record now names EBX
        child = byte_identity._comdat_child(coff, primary, ".debug$S")
        stream = byte_identity.coff_body(coff, child)
        registers = [
            int.from_bytes(stream[record["offset"] + 6:
                                  record["offset"] + 8], "little")
            for record in byte_identity.parse_codeview_symbol_stream(
                stream, "x")
            if record["type"] == 0x0002
        ]
        self.assertEqual(registers, [23, 20])

    def test_refuses_an_image_that_is_not_the_retail_oracle(self):
        wrong = bytearray(self.retail)
        wrong[10] ^= 0x08
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.compose_retail_exact_register_bijection(
                self.seed, self.donor, self.function, bytes(wrong))
        self.assertIn("not retail-exact", str(caught.exception))

    def test_refuses_a_donor_whose_body_is_not_the_pinned_pre_image(self):
        donor = bytearray(self.donor)
        coff = byte_identity.CoffObject(self.donor)
        primary = coff.function_section(TARGET_SYMBOL)
        donor[primary["raw_offset"] + 9] = 0xDF     # already sigma'd
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.compose_retail_exact_register_bijection(
                self.seed, bytes(donor), self.function, self.retail)
        self.assertIn("differs from its pin", str(caught.exception))

    def test_refuses_a_declaration_that_understates_the_rewrite(self):
        function = copy.deepcopy(self.function)
        function["register_bijection"]["expected_rewritten_offsets"] = [4]
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.compose_retail_exact_register_bijection(
                self.seed, self.donor, function, self.retail)
        self.assertIn("differs from its declaration", str(caught.exception))

    def test_refuses_a_region_that_includes_the_prologue(self):
        function = copy.deepcopy(self.function)
        function["register_bijection"]["region_start"] = 0
        with self.assertRaises(byte_identity.ByteIdentityError):
            byte_identity.compose_retail_exact_register_bijection(
                self.seed, self.donor, function, self.retail)

    def test_schema_refuses_an_image_pin_equal_to_the_donor(self):
        """A certificate that installs the donor unchanged is not this class."""
        spec = copy.deepcopy(self.function["register_bijection"])
        normalized = byte_identity.validate_register_bijection(
            spec, "spec", SIZE)
        self.assertEqual(normalized["mapping"], {"ebx": "edi", "edi": "ebx"})
        for broken, message in (
            ({**spec, "mapping": {"ebx": "ebp", "ebp": "ebx"}}, "ESP or EBP"),
            ({**spec, "mapping": {"ebx": "ebx", "edi": "edi"}},
             "fixed-point-free"),
            ({**spec, "region_start": 0}, "region_start"),
        ):
            with self.assertRaises(byte_identity.ByteIdentityError) as caught:
                byte_identity.validate_register_bijection(broken, "spec", SIZE)
            self.assertIn(message, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
