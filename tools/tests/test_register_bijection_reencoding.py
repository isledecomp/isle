"""Tests for the re-encoding register-bijection CERTIFICATE class.

The parent class refuses EBP because `[ebp]` has no mod=00 encoding, so a
memory base that becomes EBP must grow a zero disp8.  This class admits EBP
when -- and only when -- the COMDAT's own compiler-emitted FPO record says the
body has no EBP frame, re-encodes the ModRM `mod` field where that forces a
length change, repairs every relative branch to a fixpoint, and re-seats every
relocation, line row and debug range through its own boundary map.

The fixture is a complete classic-i386 COMDAT with the FPO closure and a body
of real, decodable VC4.2-shaped code:

     0: 53              push ebx        <- prologue, outside the region
     1: 56              push esi
     2: 57              push edi
     3: 55              push ebp
     4: 8b 1d <D32>     mov  ebx, [_Nil]
    10: 85 db           test ebx, ebx
    12: 74 08           je   22          <- displacement must be repaired
    14: 8b 3b           mov  edi, [ebx]  <- region starts here (edi/ebp dead)
    16: 8b 2f           mov  ebp, [edi]  <- becomes mov edi,[ebp]:  GROWS +1
    18: 89 07           mov  [edi], eax  <- becomes mov [ebp],eax:  GROWS +1
    20: 8b c5           mov  eax, ebp    <- becomes mov eax,edi
    22: 8b 0d <D32>     mov  ecx, [_Nil] <- its relocation must be re-seated
    28: 5d              pop  ebp         <- epilogue, outside the region
    29: 5f              pop  edi
    30: 5e              pop  esi
    31: 5b              pop  ebx
    32: c3              ret
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


TARGET_SYMBOL = "?erase@?$_Tree@PAVFixture@@@@QAE?AViterator@1@V21@@Z"
NIL_SYMBOL = "?_Nil@?$_Tree@PAVFixture@@@@1PAU_Node@1@A"
OTHER_SYMBOL = "?Other@@YAXXZ"
DIRECTIVE = b"-defaultlib:LIBCMT -defaultlib:OLDNAMES "
RETAIL_ADDRESS = 0x100A7960
SIGMA = {"edi": "ebp", "ebp": "edi"}
REGION = {"start": 14, "end": 22, "mapping": dict(SIGMA)}

BODY = bytes.fromhex(
    "53565755"        #  0 push ebx / esi / edi / ebp
    "8b1d00000000"    #  4 mov ebx, [_Nil]
    "85db"            # 10 test ebx, ebx
    "7408"            # 12 je 22
    "8b3b"            # 14 mov edi, [ebx]
    "8b2f"            # 16 mov ebp, [edi]
    "8907"            # 18 mov [edi], eax
    "8bc5"            # 20 mov eax, ebp
    "8b0d00000000"    # 22 mov ecx, [_Nil]
    "5d5f5e5b"        # 28 pop ebp / edi / esi / ebx
    "c3"              # 32 ret
)
SIZE = len(BODY)
RELOCATIONS = (6, 24)
LINE_ROWS = ((4, 11), (22, 12))
DEBUG_START = 4
DEBUG_END = 28

IMAGE = bytes.fromhex(
    "53565755"
    "8b1d00000000"
    "85db"
    "740a"            # 12 je 24   -- repaired
    "8b2b"            # 14 mov ebp, [ebx]
    "8b7d00"          # 16 mov edi, [ebp]   +1
    "894500"          # 19 mov [ebp], eax   +1
    "8bc7"            # 22 mov eax, edi
    "8b0d00000000"    # 24 mov ecx, [_Nil]
    "5d5f5e5b"
    "c3"
)


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


def codeview_stream(body_length=SIZE, debug_start=DEBUG_START,
                    debug_end=DEBUG_END):
    """S_LPROC32 + one S_REGISTER + S_END, the shape the real closure has."""
    records = bytearray()

    def record(kind, payload):
        records.extend(struct.pack("<HH", len(payload) + 2, kind))
        records.extend(payload)

    proc = bytearray(33)
    struct.pack_into("<III", proc, 12, body_length, debug_start, debug_end)
    name = b"_Tree<Fixture>::erase"
    record(0x0205, bytes(proc) + bytes([len(name)]) + name)
    record(0x0002, struct.pack("<HH", 0x74, 23) + bytes([4]) + b"this")
    record(0x0006, b"")
    return bytes(records)


def make_coff(*, body=BODY, relocations=RELOCATIONS, lines=LINE_ROWS,
              fpo_packed=0x14, debug_stream=None):
    """One classic-i386 COFF with an ordinary FPO COMDAT closure.

    `fpo_packed` is the FPO record's bitfield byte: 0x14 is cbRegs=4,
    fHasSEH=0, fUseBP=1, cbFrame=FRAME_FPO -- exactly what MSVC 4.2 emits for
    the real `_Tree<...>::erase`.
    """
    debug_s = (debug_stream if debug_stream is not None
               else codeview_stream(len(body)))
    fpo = struct.pack("<IIIHBB", 0, len(body), 1, 2, 4, fpo_packed)
    # Aux-expanded symbol indices: .text, .file, TARGET, .bf, .ef,
    # .debug$F and .debug$S each occupy two slots, so `_Nil` is the 15th.
    target_index = 4
    nil_index = 14
    line_bytes = bytearray(struct.pack("<IH", target_index, 0))
    for offset, number in lines:
        line_bytes.extend(struct.pack("<IH", offset, number))
    reloc_rows = [(offset, nil_index, 0x0006) for offset in relocations]
    section_inputs = [
        {"name": ".text", "raw": bytes(body), "relocations": reloc_rows,
         "lines": bytes(line_bytes), "characteristics": 0x60501020},
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
    symbols = [
        (".text", 0, 1, 0, 3,
         _section_aux(len(body), len(reloc_rows), len(line_bytes) // 6, 2)),
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


def relocation_map(offsets=RELOCATIONS):
    return {offset: {"width": 4, "target": NIL_SYMBOL} for offset in offsets}


def apply_fixture(body=BODY, regions=(REGION,), frame_pointer_free=True,
                  offsets=RELOCATIONS):
    return byte_identity.apply_register_bijection_reencoding(
        body, [dict(item) for item in regions], relocation_set(offsets),
        "fixture", relocation_map(offsets), None, None, frame_pointer_free)


def retail_body_for(image, moved_offsets):
    """Retail's own bytes: the image with its DIR32 operands resolved."""
    resolved = bytearray(image)
    for offset in moved_offsets:
        resolved[offset:offset + 4] = struct.pack("<I", 0x100F3200)
    return bytes(resolved)


def relocation_oracle(coff_bytes, moved=()):
    coff = byte_identity.CoffObject(coff_bytes)
    primary = coff.function_section(TARGET_SYMBOL)
    rows = byte_identity.detailed_relocations(coff, primary)
    moved_map = dict(moved)
    return [{
        "offset": moved_map.get(row["offset"], row["offset"]),
        "type": row["type"], "addend": row["addend"],
        "target": row["target"], "target_section": row["target_section"],
        "target_value": row["target_value"], "target_type": row["target_type"],
        "target_storage": row["target_storage"],
        "retail_target": "0x100f3200",
    } for row in rows]


def function_record(seed_bytes, donor_bytes, image, proof, derived_detail,
                    **overrides):
    seed = byte_identity.CoffObject(seed_bytes)
    donor = byte_identity.CoffObject(donor_bytes)
    sp = seed.function_section(TARGET_SYMBOL)
    dp = donor.function_section(TARGET_SYMBOL)
    record = {
        "mangled": TARGET_SYMBOL,
        "donor": "d_0123456789ab",
        "splice_class": byte_identity.REGISTER_BIJECTION_REENCODING_CLASS,
        "expected_section_number": sp["number"],
        "expected_section_count": len(seed.sections),
        "expected_seed_length": sp["raw_size"],
        "expected_preimage_length": dp["raw_size"],
        "expected_body_length": len(image),
        "expected_donor_length": len(image),
        "expected_linked_span": ((len(image) + 15) // 16) * 16,
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
        "expected_seed_body_sha256": byte_identity.sha256_bytes(
            byte_identity.coff_body(seed, sp)),
        "expected_donor_body_sha256": byte_identity.sha256_bytes(
            byte_identity.coff_body(donor, dp)),
        "expected_body_sha256": byte_identity.sha256_bytes(image),
        "expected_seed_metadata_sha256":
            byte_identity.instruction_mosaic_metadata_sha256(seed, sp),
        "expected_donor_metadata_sha256":
            byte_identity.instruction_mosaic_metadata_sha256(donor, dp),
        "expected_closure": [".debug$F", ".debug$S"],
        "retail_oracle": {
            "image": "LEGO1.DLL",
            "address": "0x%08x" % RETAIL_ADDRESS,
            "verdict": "MATCH",
            "length": len(image),
        },
        "retail_relocations": relocation_oracle(
            donor_bytes, proof["relocation_reseat"]),
        "register_bijection_reencoding": {
            "kind": byte_identity.REGISTER_BIJECTION_REENCODING_KIND,
            "regions": [dict(REGION)],
            "expected_fpo_record": {
                "ulOffStart": 0, "cbProcSize": dp["raw_size"],
                "cdwLocals": 1, "cdwParams": 2, "cbProlog": 4,
                "cbRegs": 4, "fHasSEH": 0, "fUseBP": 1, "reserved": 0,
                "cbFrame": 0,
            },
            "expected_growth": proof["growth"],
            "expected_branch_repairs": proof["branch_repairs"],
            "expected_relocation_reseat": proof["relocation_reseat"],
            "expected_rewritten_field_offsets":
                proof["rewritten_field_offsets"],
            "expected_region_instruction_counts":
                proof["region_instruction_counts"],
            "expected_instruction_count": proof["instruction_count"],
            "expected_image_code_length": proof["image_code_length"],
            "expected_procedure_range": derived_detail["procedure_range"],
            "expected_carried_code_symbols":
                derived_detail["carried_code_symbols"],
            "authenticity_rationale": "fixture",
        },
    }
    record.update(overrides)
    return record


class ReEncodingPrimitiveTest(unittest.TestCase):
    """Obligations 12 to 14, measured on the image."""

    def test_image_is_the_expected_re_encoding(self):
        image, proof = apply_fixture()
        self.assertEqual(image, IMAGE)
        self.assertEqual(len(image), SIZE + 2)
        self.assertEqual(proof["growth"], [[16, 16, 2, 3], [18, 19, 2, 3]])
        self.assertEqual(proof["relocation_reseat"], [[24, 26]])
        self.assertEqual(proof["branch_repairs"], [12])
        self.assertEqual(proof["region_instruction_counts"], [4])

    def test_the_boundary_map_covers_every_instruction_and_the_end(self):
        _image, proof = apply_fixture()
        offset_map = {int(key): value
                      for key, value in proof["offset_map"].items()}
        self.assertEqual(offset_map[0], 0)
        self.assertEqual(offset_map[14], 14)
        self.assertEqual(offset_map[22], 24)
        self.assertEqual(offset_map[SIZE], SIZE + 2)

    def test_a_relocation_before_the_growth_does_not_move(self):
        _image, proof = apply_fixture()
        self.assertNotIn(6, dict(proof["relocation_reseat"]))

    def test_refuses_ebp_without_the_frame_proof(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            apply_fixture(frame_pointer_free=False)
        self.assertIn("frame-pointer-free proof", str(caught.exception))

    def test_refuses_esp_in_sigma(self):
        region = {"start": 14, "end": 22, "mapping": {"esp": "edi",
                                                      "edi": "esp"}}
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            apply_fixture(regions=(region,))
        self.assertIn("ESP", str(caught.exception))

    def test_refuses_a_register_live_on_entry_to_the_region(self):
        # Starting one instruction later leaves EDI live at the boundary:
        # `mov ebp, [edi]` reads it.
        region = {"start": 16, "end": 22, "mapping": dict(SIGMA)}
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            apply_fixture(regions=(region,))
        self.assertIn("live on entry", str(caught.exception))

    def test_refuses_a_region_that_does_not_end_on_a_boundary(self):
        region = {"start": 14, "end": 21, "mapping": dict(SIGMA)}
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            apply_fixture(regions=(region,))
        self.assertIn("whole instructions", str(caught.exception))

    def test_refuses_overlapping_regions(self):
        regions = ({"start": 14, "end": 22, "mapping": dict(SIGMA)},
                   {"start": 20, "end": 22, "mapping": dict(SIGMA)})
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            apply_fixture(regions=regions)
        self.assertIn("overlapping", str(caught.exception))

    def test_refuses_a_rewrite_that_overlaps_a_relocation(self):
        # Byte 15 is the ModRM of `mov edi, [ebx]`, the first instruction the
        # region rewrites.  Declaring it relocated must refuse the rewrite
        # rather than write over a byte the linker owns.
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.apply_register_bijection_reencoding(
                BODY, [dict(REGION)],
                relocation_set() | frozenset({15}), "fixture",
                relocation_map(), None, None, True)
        self.assertIn("overlaps a relocation", str(caught.exception))

    def test_refuses_a_branch_that_enters_a_region_interior(self):
        # `je 22` targets the region's LAST instruction, not its head.
        region = {"start": 14, "end": 28, "mapping": dict(SIGMA)}
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            apply_fixture(regions=(region,))
        self.assertIn("control enters the region", str(caught.exception))

    def test_refuses_when_a_short_branch_would_need_widening(self):
        # A 2-byte `je` whose target is already 126 bytes away cannot absorb
        # the two bytes the re-encoding inserts.
        filler = b"\x90" * 120
        body = (BODY[:12] + b"\x74\x7e" + BODY[14:22] + filler + BODY[22:])
        offsets = (6, 24 + len(filler))
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.apply_register_bijection_reencoding(
                body, [dict(REGION)], relocation_set(offsets), "fixture",
                relocation_map(offsets), None, None, True)
        self.assertIn("no longer reaches its target", str(caught.exception))


class FramePointerProofTest(unittest.TestCase):
    """Obligation 11: EBP is only admitted against the compiler's own record."""

    def _proof(self, coff_bytes):
        coff = byte_identity.CoffObject(coff_bytes)
        primary = coff.function_section(TARGET_SYMBOL)
        body = bytes(byte_identity.coff_body(coff, primary))
        instructions = byte_identity.decode_ia32_bijection_body(
            body, "fixture", relocation_map(), None)
        return byte_identity.require_frame_pointer_free_frame(
            coff, primary, body, instructions, "fixture")

    def test_accepts_the_msvc_fpo_record(self):
        record = self._proof(make_coff())
        self.assertEqual(record["cbFrame"], 0)
        self.assertEqual(record["cbRegs"], 4)
        self.assertEqual(record["fUseBP"], 1)

    def test_refuses_a_declared_ebp_frame(self):
        # cbFrame = FRAME_NONFPO (1): the compiler says EBP IS the frame.
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self._proof(make_coff(fpo_packed=0x14 | (1 << 6)))
        self.assertIn("FRAME_FPO", str(caught.exception))

    def test_refuses_a_body_with_structured_exception_handling(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self._proof(make_coff(fpo_packed=0x14 | (1 << 3)))
        self.assertIn("structured exception", str(caught.exception))

    def test_refuses_a_body_that_derives_ebp_from_esp(self):
        # `mov ebp, esp` in place of `test ebx, ebx`.
        body = BODY[:10] + bytes.fromhex("8bec") + BODY[12:]
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self._proof(make_coff(body=body))
        self.assertIn("establishes a frame pointer", str(caught.exception))

    def test_a_pop_ebp_epilogue_is_not_a_frame_pointer(self):
        # The epilogue's `pop ebp` reads ESP implicitly; that is not a frame.
        self.assertEqual(self._proof(make_coff())["cbFrame"], 0)


SEED_BODY = BODY[:20] + bytes.fromhex("8bc7") + BODY[22:]


def composed_fixture(seed_body=SEED_BODY, **coff_overrides):
    """A seed, a donor at a different colouring, and the proved image."""
    seed_bytes = make_coff(body=seed_body, **coff_overrides)
    donor_bytes = make_coff(**coff_overrides)
    image, proof = apply_fixture()
    derived, derived_detail = byte_identity._reencoded_donor_object(
        donor_bytes, TARGET_SYMBOL, image, proof, "derived")
    return seed_bytes, donor_bytes, image, proof, derived, derived_detail


class DerivedDonorTest(unittest.TestCase):
    """Obligations 14 to 16: every record that states a code offset moves."""

    def setUp(self):
        (self.seed, self.donor, self.image, self.proof,
         self.derived, self.detail) = composed_fixture()
        self.coff = byte_identity.CoffObject(self.derived)
        self.primary = self.coff.function_section(TARGET_SYMBOL)

    def test_the_body_is_the_image(self):
        self.assertEqual(
            bytes(byte_identity.coff_body(self.coff, self.primary)),
            self.image)
        self.assertEqual(self.primary["raw_size"], len(self.image))

    def test_the_line_rows_are_carried_through_the_boundary_map(self):
        table = byte_identity._coff_table_bytes(
            self.coff, self.primary, "lines")
        rows = [struct.unpack_from("<IH", table, index * 6)
                for index in range(1, self.primary["line_count"])]
        # (4, 11) is before the growth and stays; (22, 12) moves to 24.
        self.assertEqual(rows, [(4, 11), (24, 12)])

    def test_the_relocation_offsets_are_the_proved_reseat(self):
        rows = byte_identity.detailed_relocations(self.coff, self.primary)
        self.assertEqual([row["offset"] for row in rows], [6, 26])
        self.assertEqual([row["target"] for row in rows],
                         [NIL_SYMBOL, NIL_SYMBOL])

    def test_the_procedure_record_and_fpo_follow_the_image(self):
        stream = bytes(byte_identity.coff_body(
            self.coff, byte_identity._comdat_child(
                self.coff, self.primary, ".debug$S")))
        self.assertEqual(struct.unpack_from("<III", stream, 16),
                         (len(self.image), DEBUG_START, DEBUG_END + 2))
        self.assertEqual(self.detail["procedure_range"],
                         [len(self.image), DEBUG_START, DEBUG_END + 2])
        fpo = bytes(byte_identity.coff_body(
            self.coff, byte_identity._comdat_child(
                self.coff, self.primary, ".debug$F")))
        record = byte_identity.parse_fpo_data(
            fpo, expected_proc_size=len(self.image))
        self.assertEqual(record["cbFrame"], 0)
        original = byte_identity.parse_fpo_data(
            bytes(byte_identity.coff_body(
                byte_identity.CoffObject(self.donor),
                byte_identity._comdat_child(
                    byte_identity.CoffObject(self.donor),
                    byte_identity.CoffObject(
                        self.donor).function_section(TARGET_SYMBOL),
                    ".debug$F"))),
            expected_proc_size=SIZE)
        self.assertEqual(
            {key: value for key, value in record.items()
             if key not in ("cbProcSize", "raw_sha256")},
            {key: value for key, value in original.items()
             if key not in ("cbProcSize", "raw_sha256")})

    def test_the_markers_and_auxiliaries_follow_the_image(self):
        index, marker = byte_identity._coff_marker(
            self.coff, ".ef", self.primary["number"])
        self.assertEqual(marker["value"], len(self.image))
        function_index, symbol = byte_identity.function_symbol(
            self.coff, TARGET_SYMBOL, self.primary["number"])
        auxiliary = byte_identity.coff_auxiliary(
            self.coff, function_index, symbol)
        self.assertEqual(int.from_bytes(auxiliary[4:8], "little"),
                         len(self.image))
        section_index, section_symbol = byte_identity._coff_section_symbol(
            self.coff, self.primary)
        section_aux = byte_identity.coff_auxiliary(
            self.coff, section_index, section_symbol)
        self.assertEqual(int.from_bytes(section_aux[0:4], "little"),
                         len(self.image))

    def test_the_object_topology_is_unchanged(self):
        donor = byte_identity.CoffObject(self.donor)
        self.assertEqual(byte_identity.function_multiset(self.coff),
                         byte_identity.function_multiset(donor))
        self.assertEqual(len(self.coff.sections), len(donor.sections))


class ComposerTest(unittest.TestCase):
    """The certificate end to end, and the refusals that make it honest."""

    def setUp(self):
        (self.seed, self.donor, self.image, self.proof,
         self.derived, self.detail) = composed_fixture()
        self.retail = retail_body_for(self.image, (6, 26))
        self.record = function_record(
            self.seed, self.donor, self.image, self.proof, self.detail)

    def _compose(self, record=None, retail=None):
        return byte_identity \
            .compose_retail_exact_register_bijection_reencoding(
                self.seed, self.donor, record or self.record,
                retail if retail is not None else self.retail)

    def test_composes_retails_own_body(self):
        composed, detail = self._compose()
        coff = byte_identity.CoffObject(composed)
        primary = coff.function_section(TARGET_SYMBOL)
        self.assertEqual(bytes(byte_identity.coff_body(coff, primary)),
                         self.image)
        self.assertEqual(detail["splice_class"],
                         byte_identity.REGISTER_BIJECTION_REENCODING_CLASS)
        self.assertTrue(detail["retail_exact"])
        self.assertEqual(detail["growth"], [[16, 16, 2, 3], [18, 19, 2, 3]])

    def test_the_composed_object_keeps_every_other_comdat(self):
        composed, _detail = self._compose()
        coff = byte_identity.CoffObject(composed)
        seed = byte_identity.CoffObject(self.seed)
        self.assertEqual(byte_identity.function_multiset(coff),
                         byte_identity.function_multiset(seed))
        other = coff.function_section(OTHER_SYMBOL)
        self.assertEqual(bytes(byte_identity.coff_body(coff, other)),
                         b"OTHER-FN")

    def test_refuses_an_oracle_that_is_not_retails_body(self):
        wrong = bytearray(self.retail)
        wrong[22] ^= 0xFF
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self._compose(retail=bytes(wrong))
        self.assertIn("not retail-exact", str(caught.exception))

    def test_refuses_a_declaration_that_disagrees_with_the_measurement(self):
        record = copy.deepcopy(self.record)
        record["register_bijection_reencoding"]["expected_growth"] = [
            [16, 16, 2, 3]]
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self._compose(record)
        self.assertIn("differs from its declaration", str(caught.exception))

    def test_refuses_a_stale_fpo_declaration(self):
        record = copy.deepcopy(self.record)
        record["register_bijection_reencoding"][
            "expected_fpo_record"]["cbRegs"] = 3
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self._compose(record)
        self.assertIn("FPO record differs", str(caught.exception))

    def test_refuses_when_the_object_declares_an_ebp_frame(self):
        seed, donor, image, proof, _derived, detail = composed_fixture(
            fpo_packed=0x14 | (1 << 6))
        record = function_record(seed, donor, image, proof, detail)
        record["register_bijection_reencoding"][
            "expected_fpo_record"]["cbFrame"] = 1
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity \
                .compose_retail_exact_register_bijection_reencoding(
                    seed, donor, record, retail_body_for(image, (6, 26)))
        self.assertIn("FRAME_FPO", str(caught.exception))

    def test_refuses_a_wrong_image_pin(self):
        record = copy.deepcopy(self.record)
        record["expected_body_sha256"] = "0" * 64
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self._compose(record)
        self.assertIn("image differs from its pin", str(caught.exception))


class ManifestValidationTest(unittest.TestCase):
    """The declaration must state every quantity the composer measures."""

    def setUp(self):
        (self.seed, self.donor, self.image, self.proof,
         self.derived, self.detail) = composed_fixture()
        self.record = function_record(
            self.seed, self.donor, self.image, self.proof, self.detail)
        self.spec = self.record["register_bijection_reencoding"]

    def _validate(self, spec=None, preimage=SIZE, image=None):
        return byte_identity.validate_register_bijection_reencoding(
            spec or self.spec, "spec", preimage,
            len(self.image) if image is None else image)

    def test_accepts_the_measured_declaration(self):
        normalized = self._validate()
        self.assertEqual(normalized["regions"][0]["mapping"],
                         {"ebp": "edi", "edi": "ebp"})

    def test_requires_a_region_to_name_ebp(self):
        spec = copy.deepcopy(self.spec)
        spec["regions"][0]["mapping"] = {"eax": "edi", "edi": "eax"}
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self._validate(spec)
        self.assertIn("no region names EBP", str(caught.exception))

    def test_rejects_esp(self):
        spec = copy.deepcopy(self.spec)
        spec["regions"][0]["mapping"] = {"esp": "ebp", "ebp": "esp"}
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self._validate(spec)
        self.assertIn("touches ESP", str(caught.exception))

    def test_rejects_a_declared_ebp_frame(self):
        spec = copy.deepcopy(self.spec)
        spec["expected_fpo_record"]["cbFrame"] = 1
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self._validate(spec)
        self.assertIn("frame-pointer-free", str(caught.exception))

    def test_growth_must_account_for_the_length_change(self):
        spec = copy.deepcopy(self.spec)
        spec["expected_growth"] = [[16, 16, 2, 3]]
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self._validate(spec)
        self.assertIn("does not account for", str(caught.exception))

    def test_growth_may_only_move_one_byte_per_instruction(self):
        spec = copy.deepcopy(self.spec)
        spec["expected_growth"] = [[16, 16, 2, 4]]
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self._validate(spec)
        self.assertIn("expected_growth is invalid", str(caught.exception))

    def test_rejects_a_reseat_that_collides(self):
        spec = copy.deepcopy(self.spec)
        spec["expected_relocation_reseat"] = [[6, 26], [24, 26]]
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self._validate(spec)
        self.assertIn("expected_relocation_reseat is invalid",
                      str(caught.exception))

    def test_rejects_a_rewritten_field_outside_every_region(self):
        spec = copy.deepcopy(self.spec)
        spec["expected_rewritten_field_offsets"] = [5]
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self._validate(spec)
        self.assertIn("expected_rewritten_field_offsets is invalid",
                      str(caught.exception))

    def test_rejects_a_procedure_range_that_is_not_the_image(self):
        spec = copy.deepcopy(self.spec)
        spec["expected_procedure_range"] = [SIZE, DEBUG_START, DEBUG_END]
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self._validate(spec)
        self.assertIn("expected_procedure_range is invalid",
                      str(caught.exception))

    def test_rejects_unsorted_regions(self):
        spec = copy.deepcopy(self.spec)
        spec["regions"] = [{"start": 18, "end": 22, "mapping": dict(SIGMA)},
                           {"start": 14, "end": 18, "mapping": dict(SIGMA)}]
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self._validate(spec)
        self.assertIn("unsorted", str(caught.exception))

    def test_rejects_an_unknown_key(self):
        spec = copy.deepcopy(self.spec)
        spec["unexpected"] = 1
        with self.assertRaises(byte_identity.ByteIdentityError):
            self._validate(spec)


if __name__ == "__main__":
    unittest.main()
