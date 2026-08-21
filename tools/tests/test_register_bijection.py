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


SYMBOL_SHAPE = (
    (".text", True), (".file", True), (TARGET_SYMBOL, True), (".bf", True),
    (".ef", True), (".debug$F", True), (".debug$S", True),
    ("<local>", False), (".text", True), (OTHER_SYMBOL, True),
    (".bf", True), (".ef", True), (".drectve", True),
)


def symbols_preview():
    """The aux-expanded symbol shape, so an index can be computed up front."""
    return [(name, None, None, None, None, aux) for name, aux in SYMBOL_SHAPE]


def make_coff(*, body=BODY, relocations=RELOCATIONS,
              debug_stream=None, extra_relocations=(),
              local_symbol=None):
    """One classic-i386 COFF with an ordinary FPO COMDAT closure."""
    debug_s = debug_stream if debug_stream is not None else codeview_stream()
    nil_symbol = local_symbol if local_symbol is not None else NIL_SYMBOL
    fpo = struct.pack("<IIIHBB", 0, len(body), 2, 1, 2, 0x10)
    target_index = 4
    nil_index = 10
    lines = bytearray(struct.pack("<IH", target_index, 0))
    lines.extend(struct.pack("<IH", 3, 11))
    lines.extend(struct.pack("<IH", 19, 12))
    if local_symbol is not None:
        # point the code relocations at the object-local symbol itself, so a
        # donor compiled with a different serial produces a real $L/$T rename
        nil_index = 0
        for name, _value, _section, _stype, _storage, aux in symbols_preview():
            if name == "<local>":
                break
            nil_index += 2 if aux else 1
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
        (nil_symbol, 0, 0, 0x00, 2, None),
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


# ---------------------------------------------------------------------------
# The callee-argument model, the widened semantic table and the external
# tail-jump.  A `call` CLOBBERS EAX/ECX/EDX; whether it READS one of them is
# the callee's calling convention, and the model DERIVES that from the
# callee's own decoration through a closed table.  Every test below is about
# the direction that matters: the refinement may never make a register that a
# callee really reads look dead.
# ---------------------------------------------------------------------------

CDECL_SYMBOL = "?CreateCursorSurface@MxDisplaySurface@@SAPAUIFixture@@XZ"
THISCALL_SYMBOL = "?PlaceActor@LegoWorld@@QAEJPAVLegoPathActor@@@Z"
FASTCALL_SYMBOL = "?Fast@Scope@@QAIXH@Z"
STDCALL_SYMBOL = "?Api@@YGXH@Z"
UNMANGLED_SYMBOL = "__ftol"
THUNK_SYMBOL = "?Tickle@Base@@W3AEJXZ"

# 0:  53              push ebx
# 1:  8b 0d <D32>     mov ecx, [_Nil]     <- region starts here
# 7:  8b 01           mov eax, [ecx]
# 9:  e8 <REL32>      call <callee>       <- region ends here (9)
# 14: 5b              pop ebx
# 15: c3              ret
CALL_BODY = bytes.fromhex("53" "8b0d00000000" "8b01" "e800000000" "5b" "c3")
CALL_REGION = (1, 9)
CALL_SIGMA = {"eax": "ecx", "ecx": "eax"}
CALL_RELOCATION_OFFSETS = frozenset(
    offset + byte for offset in (3, 10) for byte in range(4))


def call_relocations(callee, *, extra=()):
    rows = {3: {"width": 4, "target": NIL_SYMBOL},
            10: {"width": 4, "target": callee}}
    rows.update(extra)
    return rows


class CallArgumentModelTests(unittest.TestCase):
    """Obligation 7's call model: derived, never assumed, and fail-closed."""

    def test_decoration_table_reads_the_conventions_it_knows(self):
        for symbol, expected in (
            (CDECL_SYMBOL, frozenset()),
            ("?MVideoManager@@YAPAVMxVideoManager@@XZ", frozenset()),
            (STDCALL_SYMBOL, frozenset()),
            (THISCALL_SYMBOL, frozenset({"ecx"})),
            ("?Insert@Act3List@@QAEXHW4Mode@Element@@@Z", frozenset({"ecx"})),
            (FASTCALL_SYMBOL, frozenset({"ecx", "edx"})),
        ):
            self.assertEqual(
                byte_identity.msvc_call_argument_registers(symbol), expected,
                symbol)

    def test_decoration_table_fails_closed(self):
        """Anything the closed table does not recognise reads everything."""
        for symbol in (UNMANGLED_SYMBOL, "_chkstk", "___CxxFrameHandler",
                       "__imp__CreateWindowExA@48", THUNK_SYMBOL,
                       "?_Nil@?$_Tree@PAVFixture@@@@1PAU_Node@1@A",
                       # An operator decoration terminates its (empty) scope
                       # list with a single `@`, so the table's `@@` scan
                       # never reaches it.  That is the safe direction: the
                       # call simply stays fully conservative.
                       "??3@YAXPAX@Z",
                       "", "?", None, 17):
            self.assertIsNone(
                byte_identity.msvc_call_argument_registers(symbol),
                repr(symbol))

    def test_a_cdecl_callee_lets_the_region_prove(self):
        """The control: EAX/ECX are clobbered by the call and read by nobody."""
        image, proof = byte_identity.apply_register_bijection(
            CALL_BODY, CALL_SIGMA, CALL_REGION, CALL_RELOCATION_OFFSETS,
            "cdecl", call_relocations(CDECL_SYMBOL))
        self.assertEqual(proof["rewritten_offsets"], [2, 8])
        self.assertEqual(image[1:3], bytes.fromhex("8b05"))
        self.assertEqual(image[7:9], bytes.fromhex("8b08"))

    def test_a_thiscall_callee_keeps_ecx_live_and_refuses(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.apply_register_bijection(
                CALL_BODY, CALL_SIGMA, CALL_REGION, CALL_RELOCATION_OFFSETS,
                "thiscall", call_relocations(THISCALL_SYMBOL))
        self.assertIn("['ecx'] is live on an edge leaving the region",
                      str(caught.exception))

    def test_a_fastcall_callee_keeps_edx_live_and_refuses(self):
        # EDX is not touched anywhere in the body, so only a callee that
        # reads it as an argument can make this mapping unsound.
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.apply_register_bijection(
                CALL_BODY, {"eax": "edx", "edx": "eax"}, CALL_REGION,
                CALL_RELOCATION_OFFSETS, "fastcall",
                call_relocations(FASTCALL_SYMBOL))
        # EDX is live both on entry and on the exit edge here, and for the
        # same single reason: the callee reads it.
        self.assertIn("['edx'] is live", str(caught.exception))
        # ... and the same mapping proves against a __cdecl callee.
        byte_identity.apply_register_bijection(
            CALL_BODY, {"eax": "edx", "edx": "eax"}, CALL_REGION,
            CALL_RELOCATION_OFFSETS, "fastcall",
            call_relocations(CDECL_SYMBOL))

    def test_an_unrecognised_decoration_stays_conservative(self):
        for callee in (UNMANGLED_SYMBOL, THUNK_SYMBOL):
            with self.assertRaises(byte_identity.ByteIdentityError) as caught:
                byte_identity.apply_register_bijection(
                    CALL_BODY, CALL_SIGMA, CALL_REGION,
                    CALL_RELOCATION_OFFSETS, callee,
                    call_relocations(callee))
            self.assertIn("is live on an edge leaving the region",
                          str(caught.exception))

    def test_an_indirect_call_can_never_be_named_and_stays_conservative(self):
        """`call [_Nil]` has no callee name, so the whole clobber set is read."""
        body = bytes.fromhex("53" "8b0d00000000" "8b01"
                             "ff1500000000" "5b" "c3")
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.apply_register_bijection(
                body, CALL_SIGMA, CALL_REGION, CALL_RELOCATION_OFFSETS,
                "indirect",
                {3: {"width": 4, "target": NIL_SYMBOL},
                 11: {"width": 4, "target": CDECL_SYMBOL}})
        self.assertIn("is live on an edge leaving the region",
                      str(caught.exception))

    def test_an_unrelocated_call_stays_conservative(self):
        """Without a relocation the callee is unknown, so nothing is assumed."""
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.apply_register_bijection(
                CALL_BODY, CALL_SIGMA, CALL_REGION,
                CALL_RELOCATION_OFFSETS, "no-relocations")
        self.assertIn("is live on an edge leaving the region",
                      str(caught.exception))

    def test_a_call_result_that_is_read_stays_live(self):
        """The clobber set may never hide a return value from liveness."""
        body = bytes.fromhex("53" "e800000000" "8bc8" "8b19" "5b" "c3")
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.apply_register_bijection(
                body, CALL_SIGMA, (6, 8),
                frozenset(range(2, 6)), "result",
                {2: {"width": 4, "target": CDECL_SYMBOL}})
        self.assertIn("['eax'] is live on entry", str(caught.exception))

    def test_an_indirect_jump_is_still_refused(self):
        """`FF /4` would break the control-flow graph and is not admitted."""
        body = bytes.fromhex("53" "8b0d00000000" "8b01" "ffe0" "5b" "c3")
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.apply_register_bijection(
                body, CALL_SIGMA, CALL_REGION, frozenset(range(3, 7)),
                "indirect-jump", {3: {"width": 4, "target": NIL_SYMBOL}})
        self.assertIn("outside the register-bijection table",
                      str(caught.exception))


class WidenedSemanticTableTests(unittest.TestCase):
    """The table additions each carry their own reads/writes and refusal."""

    def test_an_x87_memory_form_rewrites_only_its_address_register(self):
        """The FPU stack is invisible to a general-register bijection."""
        body = bytes.fromhex("53" "8b0d00000000" "d901" "d919"
                             "e800000000" "5b" "c3")
        image, proof = byte_identity.apply_register_bijection(
            body, {"ecx": "edx", "edx": "ecx"}, (1, 11),
            frozenset(offset + byte for offset in (3, 12)
                      for byte in range(4)),
            "x87", {3: {"width": 4, "target": NIL_SYMBOL},
                    12: {"width": 4, "target": CDECL_SYMBOL}})
        self.assertEqual(proof["rewritten_offsets"], [2, 8, 10])
        self.assertEqual(image[1:3], bytes.fromhex("8b15"))
        self.assertEqual(image[7:9], bytes.fromhex("d902"))
        self.assertEqual(image[9:11], bytes.fromhex("d91a"))

    def test_refuses_a_sub_register_field_sigma_cannot_rewrite(self):
        """AL..BH number the low AND high bytes of only four registers.

        A byte field naming a register in sigma's support cannot carry the
        32-bit permutation, so it is refused rather than left unrewritten.
        """
        body = bytes.fromhex("53" "8b0d00000000" "8a01" "e800000000"
                             "5b" "c3")
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.apply_register_bijection(
                body, CALL_SIGMA, CALL_REGION, CALL_RELOCATION_OFFSETS,
                "byte", call_relocations(CDECL_SYMBOL))
        self.assertIn("is named by a sub-register field",
                      str(caught.exception))

    def test_a_byte_write_does_not_kill_its_parent(self):
        """`mov al, [ecx]` writes part of EAX, so EAX stays live through it."""
        decoded = byte_identity.decode_ia32_bijection_instruction(
            bytes.fromhex("8a01"), 0, "byte-mov")
        self.assertIn("eax", decoded["reads"])
        self.assertNotIn("eax", decoded["writes"])
        self.assertEqual(decoded["frozen"], frozenset({"eax"}))
        # the frozen AL field is not offered; the 32-bit memory BASE is
        self.assertEqual(decoded["fields"], [(1, 0)])

    def test_refuses_an_implicit_operand_form_inside_a_widened_group(self):
        """F6 /4 MUL reads and writes EDX:EAX implicitly and stays refused."""
        for encoding in (b"\xf6\xe1", b"\xf7\xf1"):
            body = (bytes.fromhex("53" "8b0d00000000") + encoding
                    + bytes.fromhex("e800000000" "5b" "c3"))
            with self.assertRaises(byte_identity.ByteIdentityError) as caught:
                byte_identity.apply_register_bijection(
                    body, CALL_SIGMA, CALL_REGION, CALL_RELOCATION_OFFSETS,
                    "group3", call_relocations(CDECL_SYMBOL))
            self.assertIn("outside the register-bijection table",
                          str(caught.exception))

    def test_refuses_an_operand_size_prefix_on_an_unadmitted_form(self):
        body = bytes.fromhex("53" "8b0d00000000" "668b01" "e800000000"
                             "5b" "c3")
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.apply_register_bijection(
                body, CALL_SIGMA, CALL_REGION, CALL_RELOCATION_OFFSETS,
                "osize", call_relocations(CDECL_SYMBOL))
        self.assertIn("operand-size prefix is outside",
                      str(caught.exception))

    def test_a_sixteen_bit_test_is_rewritable_and_does_not_kill(self):
        """`66 85 /r` numbers the same eight registers, so sigma applies."""
        decoded = byte_identity.decode_ia32_bijection_instruction(
            bytes.fromhex("668591d0000000"), 0, "test16")
        self.assertEqual(decoded["reads"], frozenset({"ecx", "edx"}))
        self.assertEqual(decoded["writes"], frozenset())
        self.assertEqual(decoded["frozen"], frozenset())
        self.assertEqual(sorted(decoded["fields"]), [(2, 0), (2, 3)])


class ExternalTailJumpTests(unittest.TestCase):
    """A relocated unconditional branch leaves the COMDAT."""

    # ... a `ret`, then an EH funclet that tail-jumps to an external symbol.
    FUNCLET_BODY = bytes.fromhex(
        "53" "8b0d00000000" "8b01" "e800000000" "5b" "c3" "e900000000")

    def test_a_relocated_tail_jump_is_an_exit_that_reads_everything(self):
        relocations = call_relocations(
            CDECL_SYMBOL, extra={17: {"width": 4, "target": OTHER_SYMBOL}})
        decoded = byte_identity.decode_ia32_bijection_body(
            self.FUNCLET_BODY, "funclet", relocations)
        tail = decoded[-1]
        self.assertEqual(tail["flow"], "exit")
        self.assertIsNone(tail["target"])
        self.assertEqual(
            tail["reads"],
            frozenset(byte_identity.IA32_GENERAL_REGISTER_NAMES))
        image, proof = byte_identity.apply_register_bijection(
            self.FUNCLET_BODY, CALL_SIGMA, CALL_REGION,
            CALL_RELOCATION_OFFSETS | frozenset(range(17, 21)),
            "funclet", relocations)
        self.assertEqual(proof["rewritten_offsets"], [2, 8])

    def test_an_unrelocated_branch_off_the_body_is_still_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.decode_ia32_bijection_body(
                self.FUNCLET_BODY, "funclet",
                call_relocations(CDECL_SYMBOL))
        self.assertIn("does not target an instruction boundary",
                      str(caught.exception))

    def test_an_external_tail_jump_inside_the_region_is_refused(self):
        relocations = call_relocations(
            CDECL_SYMBOL, extra={17: {"width": 4, "target": OTHER_SYMBOL}})
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.apply_register_bijection(
                self.FUNCLET_BODY, CALL_SIGMA, (1, 21),
                CALL_RELOCATION_OFFSETS | frozenset(range(17, 21)),
                "funclet", relocations)
        self.assertIn("live at the region's return", str(caught.exception))


# ---------------------------------------------------------------------------
# Obligation 10: the installation delegate is chosen FROM THE PINS.
#
# `expected_closure` and `expected_code_renames` were validated and pinned by
# this class from the day it was written, and then handed to a delegate that
# required them to be the FPO pair and empty -- so they were dead pins.  They
# now name the delegate.  These tests fix that the choice is a function of the
# manifest alone, that a pin disagreeing with the objects refuses, and that a
# rename outside the pinned set refuses.
# ---------------------------------------------------------------------------

LOCAL_SYMBOL_SEED = "$T64752"
LOCAL_SYMBOL_DONOR = "$T64763"


class DelegateSelectionTests(unittest.TestCase):
    """The delegate is a pure function of the pins, never of the objects."""

    def test_the_pins_alone_name_the_delegate(self):
        fpo = byte_identity.REGISTER_BIJECTION_FPO_CLOSURE
        eh = byte_identity.REGISTER_BIJECTION_EH_CLOSURE
        choose = byte_identity.register_bijection_delegate
        # the shape every row landed on this class so far keeps the strict one
        self.assertEqual(choose(fpo, []), "equal_body_strict")
        # a declared rename, or the EH closure, names the structural class
        self.assertEqual(choose(fpo, [[163, "T"]]),
                         "equal_body_eh_structural_local")
        self.assertEqual(choose(eh, []), "equal_body_eh_structural_local")
        self.assertEqual(choose(eh, [[12, "L"]]),
                         "equal_body_eh_structural_local")

    def test_refuses_a_closure_pin_that_disagrees_with_the_objects(self):
        """The pin is checked against BOTH objects before it selects."""
        seed = make_coff()
        donor = make_coff()
        image = sigma_image()
        function = function_record(
            seed, donor, image,
            expected_closure=byte_identity.REGISTER_BIJECTION_EH_CLOSURE,
            expected_xdata_rename_offsets=[],
        )
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.compose_retail_exact_register_bijection(
                seed, donor, function, retail_body_for(image))
        self.assertIn("target closure changed", str(caught.exception))

    def test_refuses_a_closure_pin_no_delegate_would_accept(self):
        """A shape neither delegate admits never reaches the selector.

        The objects-versus-pin check runs first, which is the stronger
        refusal: the pin is rejected for disagreeing with what the seed and
        the donor actually carry, before any delegate is named.
        """
        seed = make_coff()
        donor = make_coff()
        image = sigma_image()
        function = function_record(
            seed, donor, image, expected_closure=[".debug$S"])
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.compose_retail_exact_register_bijection(
                seed, donor, function, retail_body_for(image))
        self.assertIn("target closure changed", str(caught.exception))


class PinnedRenameTests(unittest.TestCase):
    """A rename outside the pinned set refuses; the pinned one composes."""

    def setUp(self):
        self.seed = make_coff(local_symbol=LOCAL_SYMBOL_SEED)
        self.donor = make_coff(local_symbol=LOCAL_SYMBOL_DONOR)
        self.image = sigma_image()
        self.retail = retail_body_for(self.image)
        self.renames = [[offset, "T"] for offset in RELOCATIONS]
        self.symbols = [[offset, LOCAL_SYMBOL_SEED, LOCAL_SYMBOL_DONOR]
                        for offset in RELOCATIONS]

    def _record(self, **overrides):
        return function_record(
            self.seed, self.donor, self.image, **overrides)

    def test_a_declared_object_local_rename_composes(self):
        """FPO closure + a declared $T rename -> the structural delegate."""
        function = self._record(
            expected_code_renames=self.renames,
            expected_code_rename_symbols=self.symbols,
            expected_xdata_rename_offsets=[],
        )
        composed, detail = (
            byte_identity.compose_retail_exact_register_bijection(
                self.seed, self.donor, function, self.retail))
        coff = byte_identity.CoffObject(composed)
        primary = coff.function_section(TARGET_SYMBOL)
        self.assertEqual(byte_identity.coff_body(coff, primary), self.image)
        self.assertTrue(detail["retail_exact"])
        # the installed object keeps the SEED's own symbol, not the donor's
        self.assertEqual(
            {row["target"] for row in byte_identity.detailed_relocations(
                coff, primary)},
            {LOCAL_SYMBOL_SEED})

    def test_refuses_a_rename_the_pin_does_not_declare(self):
        function = self._record(
            expected_code_renames=[], expected_xdata_rename_offsets=[])
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.compose_retail_exact_register_bijection(
                self.seed, self.donor, function, self.retail)
        self.assertIn("code rename set changed", str(caught.exception))

    def test_refuses_a_pinned_rename_that_is_not_there(self):
        """A donor with no rename may not carry a pin that declares one."""
        function = function_record(
            self.seed, self.seed, self.image,
            expected_code_renames=[self.renames[0]],
            expected_code_rename_symbols=[self.symbols[0]],
            expected_xdata_rename_offsets=[],
        )
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.compose_retail_exact_register_bijection(
                self.seed, self.seed, function, self.retail)
        self.assertIn("code rename set changed", str(caught.exception))

    def test_refuses_a_rename_whose_symbol_pair_is_wrong(self):
        """The pin names the EXACT pair, not a count and not a wildcard."""
        function = self._record(
            expected_code_renames=self.renames,
            expected_code_rename_symbols=[
                [offset, LOCAL_SYMBOL_SEED, "$T99999"]
                for offset in RELOCATIONS],
            expected_xdata_rename_offsets=[],
        )
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.compose_retail_exact_register_bijection(
                self.seed, self.donor, function, self.retail)
        self.assertIn("code rename symbol pair changed",
                      str(caught.exception))
