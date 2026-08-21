"""Tests for the instruction-schedule CERTIFICATE class.

The class installs a topological reordering of a closed window of a
compiler-produced body and refuses unless the result is retail's own code.
These tests fix the refusals that make that claim honest -- a window a branch
enters, a store reordered past a load that cannot be disambiguated, an order
that is not a topological order of the dependence DAG, a relocation the window
would have to move, a line row the reordering would leave off an instruction
boundary, and an image that is not the oracle -- plus the positive
disambiguation proof the whole class rests on.

The fixture is a complete classic-i386 COMDAT with the ordinary FPO closure
and a body of real, decodable VC4.2-shaped code:

    0:  53              push ebx           <- prologue, outside the window
    1:  56              push esi
    2:  33 f6           xor  esi, esi
    4:  8b 44 24 0c     mov  eax, [esp+12] <- window starts here
    8:  89 74 24 18     mov  [esp+24], esi
    12: 8d 5b 08        lea  ebx, [ebx+8]
    15: 89 74 24 1c     mov  [esp+28], esi
    19: 85 c0           test eax, eax      <- window ends here
    21: 74 02           je   25
    23: 33 c0           xor  eax, eax
    25: 5e              pop  esi
    26: 5b              pop  ebx
    27: c3              ret

Every window memory operand is [esp + constant] with a disjoint span, so the
window's dependence DAG is empty and retail's order -- the stores first, then
the load, then the lea -- is a legal topological order.
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


TARGET_SYMBOL = "?Read@Fixture@@QAEJPAVStorage@@@Z"
NIL_SYMBOL = "?_Nil@Fixture@@1PAU_Node@1@A"
OTHER_SYMBOL = "?Other@@YAXXZ"
DIRECTIVE = b"-defaultlib:LIBCMT -defaultlib:OLDNAMES "
RETAIL_ADDRESS = 0x100AA510

PROLOGUE = bytes.fromhex("5356" "33f6")
WINDOW_SOURCE = bytes.fromhex("8b44240c" "89742418" "8d5b08" "8974241c")
EPILOGUE = bytes.fromhex("85c0" "7402" "33c0" "5e5b" "c3")
BODY = PROLOGUE + WINDOW_SOURCE + EPILOGUE
SIZE = len(BODY)
WINDOW = (len(PROLOGUE), len(PROLOGUE) + len(WINDOW_SOURCE))
ORDER = [1, 3, 0, 2]
LENGTHS = [4, 4, 3, 4]
LINE_ROWS = ((0, 11), (8, 12))
RELOCATIONS = ()


def reordered(body=BODY, order=ORDER, window=WINDOW):
    start, end = window
    pieces = []
    cursor = start
    for length in LENGTHS:
        pieces.append(body[cursor:cursor + length])
        cursor += length
    assert cursor == end
    return body[:start] + b"".join(pieces[k] for k in order) + body[end:]


IMAGE = reordered()


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


def codeview_stream(size=SIZE, debug_start=2, debug_end=None):
    """S_LPROC32 with a code length and debug range, then END."""
    records = bytearray()

    def record(kind, payload):
        records.extend(struct.pack("<HH", len(payload) + 2, kind))
        records.extend(payload)

    proc = bytearray(33)
    struct.pack_into("<III", proc, 12, size, debug_start,
                     size - 5 if debug_end is None else debug_end)
    name = b"Fixture::Read"
    record(0x0205, bytes(proc) + bytes([len(name)]) + name)
    record(0x0006, b"")
    return bytes(records)


SYMBOL_SHAPE = (
    (".text", True), (".file", True), (TARGET_SYMBOL, True), (".bf", True),
    (".ef", True), (".debug$F", True), (".debug$S", True),
    ("<local>", False), (".text", True), (OTHER_SYMBOL, True),
    (".bf", True), (".ef", True), (".drectve", True),
)


def make_coff(*, body=BODY, relocations=RELOCATIONS, debug_stream=None,
              line_rows=LINE_ROWS, code_relocations=()):
    """One classic-i386 COFF with an ordinary FPO COMDAT closure.

    `code_relocations` is a list of `(offset, label, value)` triples.  Each
    adds a static symbol in the target's OWN section at `value` and a DIR32
    relocation naming it at `offset` -- the shape a compiler-emitted switch
    dispatch and its jump table have, and the only shape from which the
    relocated in-body target set can be read.
    """
    debug_s = debug_stream if debug_stream is not None else codeview_stream()
    fpo = struct.pack("<IIIHBB", 0, len(body), 2, 1, 2, 0x10)
    target_index = 4
    nil_index = 10
    label_base = 25
    label_index = {}
    for position, (_, label, _) in enumerate(code_relocations):
        label_index.setdefault(label, label_base + len(label_index))
    lines = bytearray(struct.pack("<IH", target_index, 0))
    for offset, line in line_rows:
        lines.extend(struct.pack("<IH", offset, line))
    reloc_rows = [(offset, nil_index, 0x0006) for offset in relocations]
    reloc_rows += [(offset, label_index[label], 0x0006)
                   for offset, label, _ in code_relocations]
    reloc_rows.sort()
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
    seen = {}
    for _, label, value in code_relocations:
        if label not in seen:
            seen[label] = value
            symbols.append((label, value, 1, 0, 3, None))
    assert all(label_index[label] == label_base + position
               for position, label in enumerate(seen))
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


# A body that ends in a compiler-emitted switch table: the same window, then
# the dispatch `jmp dword ptr [eax*4 + $Ltable]`, then two 4-byte table entries
# which are DATA and must never be decoded.
#
#     0:  53 56 33 f6                 prologue, outside the window
#     4:  ...                         the window, unchanged
#    19:  ff 24 85 <$Ltable>          the dispatch -- terminal, no fall-through
#    26:  <$Lcase0> <$Lcase1>         the table
SWITCH_DISPATCH = bytes.fromhex("ff2485") + struct.pack("<I", 0)
SWITCH_CODE = PROLOGUE + WINDOW_SOURCE + SWITCH_DISPATCH
SWITCH_CODE_LENGTH = len(SWITCH_CODE)
SWITCH_BODY = SWITCH_CODE + struct.pack("<II", 0, 0)
SWITCH_IMAGE = reordered(SWITCH_BODY)
SWITCH_RELOCATIONS = (
    (22, "$Ltable", SWITCH_CODE_LENGTH),
    (26, "$Lcase0", 0),
    (30, "$Lcase1", 19),
)
SWITCH_TARGETS = frozenset({0, 19, SWITCH_CODE_LENGTH})


def window_declaration(start=WINDOW[0], end=WINDOW[1], order=None,
                       edges=None, line_rows=None, lengths=None):
    return {
        "start": start, "end": end,
        "source_instruction_lengths": list(LENGTHS if lengths is None
                                           else lengths),
        "target_order": list(ORDER if order is None else order),
        "expected_dependence_edges": [] if edges is None else edges,
        "expected_line_rows": ([[8, 12, 3]] if line_rows is None
                               else line_rows),
    }


def schedule_spec(**overrides):
    spec = {
        "kind": byte_identity.INSTRUCTION_SCHEDULE_KIND,
        "windows": [window_declaration()],
        "expected_instruction_count": 13,
        "expected_changed_offsets": sorted(
            index for index in range(SIZE) if BODY[index] != IMAGE[index]),
        "expected_procedure_range": [SIZE, 2, SIZE - 5],
        "expected_code_symbol_references": [],
        "authenticity_rationale":
            "A topological reordering of one closed call-free window whose "
            "memory operands are frame-relative with disjoint spans.",
    }
    spec.update(overrides)
    return spec


def function_record(seed_bytes, donor_bytes, image, **overrides):
    seed = byte_identity.CoffObject(seed_bytes)
    donor = byte_identity.CoffObject(donor_bytes)
    sp = seed.function_section(TARGET_SYMBOL)
    dp = donor.function_section(TARGET_SYMBOL)
    seed_body = byte_identity.coff_body(seed, sp)
    donor_body = byte_identity.coff_body(donor, dp)
    record = {
        "mangled": TARGET_SYMBOL,
        "donor": "d_0123456789ab",
        "splice_class": byte_identity.INSTRUCTION_SCHEDULE_CLASS,
        "expected_section_number": sp["number"],
        "expected_donor_section_number": dp["number"],
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
        "retail_relocations": [],
        "instruction_schedule": schedule_spec(),
    }
    record.update(overrides)
    return record


class DisambiguationTests(unittest.TestCase):
    """Obligation 4: the only admitted memory proof, and its refusals."""

    def decode(self, body=BODY, window=WINDOW):
        spans, _ = byte_identity.ia32_schedule_body_walk(body, None, "walk")
        return [
            byte_identity.decode_ia32_bijection_instruction(
                body, start, "decode")
            for start, _ in spans if window[0] <= start < window[1]
        ]

    def test_same_base_disjoint_spans_carry_no_edge(self):
        _, edges = byte_identity.ia32_schedule_dependence_edges(
            self.decode(), "dag")
        self.assertEqual(edges, [])

    def test_overlapping_spans_on_one_base_are_a_dependence(self):
        # the second store lands on [esp+24] as well, so it aliases the first
        body = BODY.replace(bytes.fromhex("8974241c"),
                            bytes.fromhex("89742418"))
        _, edges = byte_identity.ia32_schedule_dependence_edges(
            self.decode(body), "dag")
        self.assertEqual([edge[:2] for edge in edges], [[1, 3]])
        self.assertIn("memory", edges[0][2])

    def test_a_different_base_register_is_never_a_disjointness_proof(self):
        # `mov eax, [ecx+12]` reads a cell that cannot be shown disjoint from
        # the `[esp+24]` the next instruction writes, whatever the constants
        pair = bytes.fromhex("8b410c") + bytes.fromhex("89742418")
        decoded = [
            byte_identity.decode_ia32_bijection_instruction(
                pair, offset, "decode")
            for offset in (0, 3)
        ]
        _, edges = byte_identity.ia32_schedule_dependence_edges(
            decoded, "dag")
        self.assertEqual([edge[:2] for edge in edges], [[0, 1]])
        self.assertEqual(edges[0][2], ["memory"])

    def test_an_absolute_memory_operand_is_refused(self):
        body = (PROLOGUE + bytes.fromhex("a100000000") + WINDOW_SOURCE[4:]
                + EPILOGUE)
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.ia32_schedule_dependence_edges(
                self.decode(body, (4, 16)), "dag")
        self.assertIn("outside the instruction-schedule table",
                      str(caught.exception))

    def test_a_base_written_inside_the_window_is_refused(self):
        # `lea esp, [ebx+8]` would move the base every displacement is
        # measured against
        body = BODY.replace(bytes.fromhex("8d5b08"),
                            bytes.fromhex("8d6308"))
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.ia32_schedule_dependence_edges(
                self.decode(body), "dag")
        self.assertIn("is written inside the window", str(caught.exception))

    def test_two_pushes_can_never_be_reordered(self):
        # both read AND write esp, so every pair of pushes carries an edge
        decoded = [
            byte_identity.decode_ia32_bijection_instruction(
                bytes.fromhex("5051"), offset, "decode")
            for offset in (0, 1)
        ]
        _, edges = byte_identity.ia32_schedule_dependence_edges(
            decoded, "dag")
        self.assertEqual([edge[:2] for edge in edges], [[0, 1]])
        self.assertEqual(edges[0][2],
                         ["register_raw", "register_war", "register_waw"])

    def test_a_push_transposes_with_an_esp_free_instruction(self):
        # `lea ecx, [esi+0x4220]` accesses no memory and names no esp, so it
        # is independent of `push eax` -- the one pairing the stack ruling
        # admits without a delta proof
        raw = bytes.fromhex("8d8e20420000" "50")
        decoded = [
            byte_identity.decode_ia32_bijection_instruction(
                raw, offset, "decode")
            for offset in (0, 6)
        ]
        _, edges = byte_identity.ia32_schedule_dependence_edges(
            decoded, "dag")
        self.assertEqual(edges, [])
        byte_identity.require_topological_instruction_order(
            2, edges, [1, 0], "order")

    def test_flags_are_a_dependence(self):
        # `test eax, eax` then `sbb eax, [esp+16]`: the second reads CF
        decoded = [
            byte_identity.decode_ia32_bijection_instruction(
                bytes.fromhex("85c0") + bytes.fromhex("1b442410"),
                offset, "decode")
            for offset in (0, 2)
        ]
        _, edges = byte_identity.ia32_schedule_dependence_edges(
            decoded, "dag")
        self.assertEqual([edge[:2] for edge in edges], [[0, 1]])
        self.assertIn("flags_raw", edges[0][2])


class TopologicalOrderTests(unittest.TestCase):
    """Obligation 4: the declared order must respect every edge."""

    def test_an_order_that_violates_an_edge_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.require_topological_instruction_order(
                3, [[0, 2, ["memory"]]], [2, 0, 1], "order")
        self.assertIn("which the dependence DAG forbids",
                      str(caught.exception))

    def test_an_order_that_respects_every_edge_is_accepted(self):
        byte_identity.require_topological_instruction_order(
            3, [[0, 2, ["memory"]]], [1, 0, 2], "order")

    def test_the_identity_is_not_a_reordering(self):
        with self.assertRaises(byte_identity.ByteIdentityError):
            byte_identity.require_topological_instruction_order(
                3, [], [0, 1, 2], "order")


class WindowImageTests(unittest.TestCase):
    """Obligations 2, 3, 5 and 6: the image itself."""

    def apply(self, body=BODY, windows=None, relocations=frozenset(),
              symbols=None):
        return byte_identity.apply_instruction_schedule(
            body, [window_declaration()] if windows is None else windows,
            relocations, "image", symbols)

    def test_the_window_is_reordered_and_nothing_else_moves(self):
        image, proof = self.apply()
        self.assertEqual(image, IMAGE)
        self.assertEqual(image[:WINDOW[0]], BODY[:WINDOW[0]])
        self.assertEqual(image[WINDOW[1]:], BODY[WINDOW[1]:])
        self.assertEqual(proof["instruction_count"], 13)
        self.assertEqual(proof["windows"][0]["dependence_edges"], [])

    def test_the_multiset_is_preserved(self):
        image, _ = self.apply()
        self.assertEqual(sorted(image[WINDOW[0]:WINDOW[1]]),
                         sorted(BODY[WINDOW[0]:WINDOW[1]]))

    def test_a_branch_into_the_window_is_refused(self):
        # retarget `je 25` at offset 8, inside the window
        body = bytearray(BODY)
        body[22] = (8 - 23) & 0xFF
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self.apply(bytes(body))
        self.assertIn("targets the window interior", str(caught.exception))

    def test_a_relocation_inside_the_window_is_refused(self):
        offsets = frozenset(range(8, 12))
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self.apply(relocations=offsets)
        self.assertIn("refuses to move a relocation", str(caught.exception))

    def test_a_call_inside_the_window_is_refused(self):
        body = (PROLOGUE + bytes.fromhex("e80f000000") + WINDOW_SOURCE[4:]
                + EPILOGUE)
        windows = [window_declaration(end=20, lengths=[5, 4, 3, 4],
                                      line_rows=[[9, 12, 3]])]
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self.apply(body, windows)
        self.assertIn("outside the instruction-schedule table",
                      str(caught.exception))

    def test_an_x87_form_inside_the_window_is_refused(self):
        body = (PROLOGUE + bytes.fromhex("d9442418") + WINDOW_SOURCE[4:]
                + EPILOGUE)
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self.apply(body)
        self.assertIn("outside the instruction-schedule table",
                      str(caught.exception))

    def test_a_push_beside_an_esp_relative_operand_is_refused(self):
        # the fixture's window stores to [esp+24] and [esp+28]; a push moved
        # across either would change the address it names, and the second
        # branch of the stack ruling (prove the delta) is not implemented
        body = (PROLOGUE + bytes.fromhex("50") + WINDOW_SOURCE[4:]
                + EPILOGUE)
        windows = [window_declaration(end=12, lengths=[1, 3, 4],
                                      order=[1, 2, 0], line_rows=[])]
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self.apply(body, windows)
        self.assertIn("whose address the push's own esp delta would move",
                      str(caught.exception))

    def test_a_pop_is_still_outside_the_table(self):
        # `pop` READS [esp], which is live memory; the below-esp axiom says
        # nothing about it, so it is not admitted
        body = (PROLOGUE + bytes.fromhex("58") + WINDOW_SOURCE[4:]
                + EPILOGUE)
        windows = [window_declaration(end=12, lengths=[1, 3, 4],
                                      order=[1, 2, 0], line_rows=[])]
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self.apply(body, windows)
        self.assertIn("outside the instruction-schedule table",
                      str(caught.exception))

    def test_an_indirect_jump_makes_the_entry_set_unknowable(self):
        body = BODY + bytes.fromhex("ffe0")
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self.apply(body)
        self.assertIn("makes the window's entry set unknowable",
                      str(caught.exception))

    def test_a_declared_edge_set_that_differs_is_refused(self):
        windows = [window_declaration(edges=[[0, 1, ["memory"]]])]
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self.apply(windows=windows)
        self.assertIn("dependence DAG differs from its declaration",
                      str(caught.exception))

    def test_a_declared_partition_that_differs_is_refused(self):
        windows = [window_declaration(lengths=[4, 4, 4, 3])]
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self.apply(windows=windows)
        self.assertIn("instruction partition differs", str(caught.exception))


class DebugFidelityTests(unittest.TestCase):
    """Obligation 7: the line rows and the procedure range."""

    def check(self, seed_bytes, image, spec, windows=None):
        coff = byte_identity.CoffObject(seed_bytes)
        section = coff.function_section(TARGET_SYMBOL)
        return byte_identity.require_instruction_schedule_debug_fidelity(
            coff, section, image,
            spec["windows"] if windows is None else windows,
            spec, TARGET_SYMBOL, "debug",
        )

    def test_every_line_row_is_re_derived_against_the_image(self):
        detail = self.check(make_coff(), IMAGE, schedule_spec())
        self.assertEqual(detail["window_line_rows"], [[8, 12, 3]])
        self.assertEqual(detail["procedure_range"], [SIZE, 2, SIZE - 5])

    def test_a_line_row_left_off_a_boundary_is_refused(self):
        # offset 15 begins an instruction in the SOURCE order and does not in
        # the image, which is exactly the case obligation 7 exists to catch
        seed = make_coff(line_rows=((0, 11), (15, 12)))
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self.check(seed, IMAGE, schedule_spec(
                windows=[window_declaration(line_rows=[[15, 12, 2]])]))
        self.assertIn("is not an instruction boundary of the image",
                      str(caught.exception))

    def test_an_undeclared_interior_line_row_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self.check(make_coff(), IMAGE, schedule_spec(
                windows=[window_declaration(line_rows=[])]))
        self.assertIn("line rows inside window", str(caught.exception))

    def test_a_procedure_range_inside_a_window_is_refused(self):
        seed = make_coff(debug_stream=codeview_stream(debug_start=8))
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self.check(seed, IMAGE,
                       schedule_spec(expected_procedure_range=[SIZE, 8,
                                                               SIZE - 5]))
        self.assertIn("falls inside a reordered window",
                      str(caught.exception))


class ScheduleSchemaTests(unittest.TestCase):
    """The manifest schema closes what the composer then measures."""

    def validate(self, **overrides):
        return byte_identity.validate_instruction_schedule(
            schedule_spec(**overrides), "schedule", SIZE)

    def test_the_reference_declaration_validates(self):
        normalized = self.validate()
        self.assertEqual(normalized["windows"][0]["target_order"], ORDER)

    def test_an_identity_permutation_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError):
            self.validate(windows=[window_declaration(order=[0, 1, 2, 3])])

    def test_overlapping_windows_are_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self.validate(windows=[window_declaration(),
                                   window_declaration(start=8, end=19,
                                                      lengths=[4, 3, 4],
                                                      order=[1, 2, 0],
                                                      line_rows=[])])
        self.assertIn("unsorted, empty or overlapping", str(caught.exception))

    def test_an_unknown_dependence_reason_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError):
            self.validate(windows=[window_declaration(
                edges=[[0, 1, ["handwave"]]])])

    def test_a_changed_offset_outside_every_window_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError):
            self.validate(expected_changed_offsets=[0, 8])


class ScheduleCompositionTests(unittest.TestCase):
    """Obligations 1, 8 and 9: the composition and the oracle."""

    def setUp(self):
        self.seed = make_coff()
        self.donor = make_coff()
        self.record = function_record(self.seed, self.donor, IMAGE)

    def test_the_certificate_composes_retails_own_code(self):
        composed, detail = (
            byte_identity.compose_retail_exact_instruction_schedule(
                self.seed, self.donor, self.record, IMAGE))
        coff = byte_identity.CoffObject(composed)
        section = coff.function_section(TARGET_SYMBOL)
        self.assertEqual(byte_identity.coff_body(coff, section), IMAGE)
        self.assertTrue(detail["retail_exact"])
        self.assertEqual(detail["debug_fidelity"]["window_line_rows"],
                         [[8, 12, 3]])

    def test_an_image_that_is_not_the_oracle_is_refused(self):
        oracle = bytearray(IMAGE)
        oracle[WINDOW[1]] ^= 0x01
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.compose_retail_exact_instruction_schedule(
                self.seed, self.donor, self.record, bytes(oracle))
        self.assertIn("is not retail-exact", str(caught.exception))

    def test_a_body_that_is_already_the_oracle_still_needs_the_proof(self):
        # the reordering must be declared; an identity declaration refuses in
        # the schema, and a mis-declared image refuses in the composer
        record = copy.deepcopy(self.record)
        record["expected_body_sha256"] = byte_identity.sha256_bytes(BODY)
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.compose_retail_exact_instruction_schedule(
                self.seed, self.donor, record, IMAGE)
        self.assertIn("image differs from its pin", str(caught.exception))

    def test_the_output_keeps_the_seed_line_and_relocation_tables(self):
        composed, _ = (
            byte_identity.compose_retail_exact_instruction_schedule(
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

    def test_the_delegate_is_read_off_the_closure_pin(self):
        self.assertEqual(
            byte_identity.instruction_schedule_delegate(
                [".debug$F", ".debug$S"], []),
            "equal_body_strict")
        self.assertEqual(
            byte_identity.instruction_schedule_delegate(
                [".debug$S", ".xdata$x"], []),
            "equal_body_eh_structural_local")


class SwitchTableTailTests(unittest.TestCase):
    """The `expected_code_length` pin, and the tail it proves unreachable.

    Without the pin a COMDAT that ends in a compiler-emitted switch table is
    walked as if the table were code -- and the table's bytes usually DO
    decode, so the walk succeeds and every claim after it is nonsense.  The
    pin says where code ends; the tail is then never decoded, never inside a
    window and never rewritten, and the walk proves the code cannot fall
    through into it.  A computed jump is admitted only against the relocated
    in-body target set, which is what bounds where control can re-enter.
    """

    def walk(self, body=SWITCH_BODY, code_length=SWITCH_CODE_LENGTH,
             targets=SWITCH_TARGETS, relocations=None):
        return byte_identity.ia32_schedule_body_walk(
            body, relocations, "walk", code_length, targets)

    def test_the_pinned_code_decodes_and_the_tail_does_not(self):
        spans, targets = self.walk()
        self.assertEqual(spans[-1], (19, len(SWITCH_DISPATCH)))
        self.assertEqual(sum(length for _, length in spans),
                         SWITCH_CODE_LENGTH)
        self.assertLessEqual(SWITCH_TARGETS, targets)

    def test_a_computed_jump_without_the_target_set_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self.walk(targets=None)
        self.assertIn("makes the window's entry set unknowable",
                      str(caught.exception))

    def test_a_relocated_target_off_an_instruction_boundary_is_refused(self):
        # 5 is inside the window's first instruction, so a computed jump that
        # could reach it means the decode itself is wrong
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self.walk(targets=frozenset({0, 5, SWITCH_CODE_LENGTH}))
        self.assertIn("is not an instruction boundary of this body",
                      str(caught.exception))

    def test_a_pin_that_straddles_an_instruction_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self.walk(code_length=SWITCH_CODE_LENGTH - 1)
        self.assertIn("truncated", str(caught.exception))

    def test_a_pin_out_of_range_is_refused(self):
        for length in (0, len(SWITCH_BODY) + 1):
            with self.assertRaises(byte_identity.ByteIdentityError) as caught:
                self.walk(code_length=length)
            self.assertIn("code length is out of range",
                          str(caught.exception))

    def test_code_that_falls_through_into_the_tail_is_refused(self):
        # `xor esi, esi` at 2 is the last instruction before the pin, and it
        # falls through -- so the bytes after it are reachable and are not a
        # data tail at all
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self.walk(code_length=4)
        self.assertIn("falls through into the body's data tail",
                      str(caught.exception))

    def test_the_unpinned_walk_decodes_the_table_as_code(self):
        # the control this whole pin exists for: the tail decodes, so an
        # unpinned walk reports a longer, meaningless instruction list
        spans, _ = byte_identity.ia32_schedule_body_walk(
            SWITCH_BODY, None, "walk", None, SWITCH_TARGETS)
        self.assertGreater(len(spans), 8)
        self.assertEqual(sum(length for _, length in spans),
                         len(SWITCH_BODY))

    def test_a_window_that_reaches_into_the_tail_is_refused(self):
        windows = [window_declaration(end=SWITCH_CODE_LENGTH + 4,
                                      lengths=LENGTHS + [7, 4],
                                      order=[1, 3, 0, 2, 4, 5],
                                      line_rows=[])]
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.apply_instruction_schedule(
                SWITCH_BODY, windows, frozenset(), "image", None,
                SWITCH_CODE_LENGTH, SWITCH_TARGETS)
        self.assertIn("reaches into the body's data tail",
                      str(caught.exception))

    def test_a_relocated_target_entering_a_window_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.apply_instruction_schedule(
                SWITCH_BODY, [window_declaration()], frozenset(), "image",
                None, SWITCH_CODE_LENGTH,
                frozenset({0, 8, SWITCH_CODE_LENGTH}))
        self.assertIn("targets the window interior", str(caught.exception))

    def test_the_window_is_reordered_and_the_tail_is_untouched(self):
        image, proof = byte_identity.apply_instruction_schedule(
            SWITCH_BODY, [window_declaration()], frozenset(), "image", None,
            SWITCH_CODE_LENGTH, SWITCH_TARGETS)
        self.assertEqual(image, SWITCH_IMAGE)
        self.assertEqual(image[SWITCH_CODE_LENGTH:],
                         SWITCH_BODY[SWITCH_CODE_LENGTH:])
        self.assertEqual(proof["code_length"], SWITCH_CODE_LENGTH)
        self.assertEqual(proof["instruction_count"], 8)


def switch_spec(**overrides):
    spec = schedule_spec(
        expected_instruction_count=8,
        expected_changed_offsets=sorted(
            index for index in range(len(SWITCH_BODY))
            if SWITCH_BODY[index] != SWITCH_IMAGE[index]),
        expected_procedure_range=[len(SWITCH_BODY), 2, 19],
        expected_code_length=SWITCH_CODE_LENGTH,
        expected_internal_relocation_targets=sorted(SWITCH_TARGETS),
    )
    spec.update(overrides)
    return spec


class SwitchTableSchemaTests(unittest.TestCase):
    """The pins are declared in the manifest before they are measured."""

    def validate(self, **overrides):
        return byte_identity.validate_instruction_schedule(
            switch_spec(**overrides), "schedule", len(SWITCH_BODY))

    def test_the_switch_declaration_validates(self):
        normalized = self.validate()
        self.assertEqual(normalized["expected_code_length"],
                         SWITCH_CODE_LENGTH)
        self.assertEqual(normalized["expected_internal_relocation_targets"],
                         sorted(SWITCH_TARGETS))

    def test_a_window_past_the_declared_code_length_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self.validate(expected_code_length=12)
        self.assertIn("reaches past the declared code length",
                      str(caught.exception))

    def test_a_declared_target_inside_a_window_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            self.validate(expected_internal_relocation_targets=[0, 8, 26])
        self.assertIn("enters the window's interior", str(caught.exception))

    def test_an_unsorted_target_set_is_refused(self):
        with self.assertRaises(byte_identity.ByteIdentityError):
            self.validate(expected_internal_relocation_targets=[26, 0, 19])

    def test_the_pins_stay_optional(self):
        normalized = byte_identity.validate_instruction_schedule(
            schedule_spec(), "schedule", SIZE)
        self.assertNotIn("expected_code_length", normalized)
        self.assertNotIn("expected_internal_relocation_targets", normalized)


class SwitchTableCompositionTests(unittest.TestCase):
    """The whole certificate, on a body that ends in a switch table."""

    def setUp(self):
        stream = codeview_stream(size=len(SWITCH_BODY), debug_start=2,
                                 debug_end=19)
        self.seed = make_coff(body=SWITCH_BODY, debug_stream=stream,
                              code_relocations=SWITCH_RELOCATIONS)
        self.donor = make_coff(body=SWITCH_BODY, debug_stream=stream,
                               code_relocations=SWITCH_RELOCATIONS)
        coff = byte_identity.CoffObject(self.seed)
        rows = byte_identity.detailed_relocations(
            coff, coff.function_section(TARGET_SYMBOL))
        oracle = []
        for row in rows:
            raw = int.from_bytes(
                SWITCH_IMAGE[row["offset"]:row["offset"] + 4], "little")
            oracle.append({
                field: row[field] for field in (
                    "offset", "type", "addend", "target", "target_section",
                    "target_value", "target_type", "target_storage")})
            oracle[-1]["retail_target"] = "0x%08x" % (
                (raw - row["addend"]) & 0xFFFFFFFF)
        self.record = function_record(
            self.seed, self.donor, SWITCH_IMAGE,
            instruction_schedule=switch_spec(),
            retail_relocations=oracle)

    def test_the_certificate_composes_retails_own_code(self):
        composed, detail = (
            byte_identity.compose_retail_exact_instruction_schedule(
                self.seed, self.donor, self.record, SWITCH_IMAGE))
        coff = byte_identity.CoffObject(composed)
        section = coff.function_section(TARGET_SYMBOL)
        self.assertEqual(byte_identity.coff_body(coff, section), SWITCH_IMAGE)
        self.assertTrue(detail["retail_exact"])
        self.assertEqual(detail["instruction_count"], 8)

    def test_a_code_length_that_differs_from_its_pin_is_refused(self):
        record = copy.deepcopy(self.record)
        record["instruction_schedule"]["expected_code_length"] = 12
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.compose_retail_exact_instruction_schedule(
                self.seed, self.donor, record, SWITCH_IMAGE)
        self.assertIn("data tail", str(caught.exception))

    def test_a_missing_code_length_pin_is_refused(self):
        # without the pin the table is walked as code, the dispatch's own
        # relocated operand is read as a branch displacement, and the
        # composition no longer describes the body it installs
        record = copy.deepcopy(self.record)
        del record["instruction_schedule"]["expected_code_length"]
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.compose_retail_exact_instruction_schedule(
                self.seed, self.donor, record, SWITCH_IMAGE)
        self.assertIn("differs from its declaration", str(caught.exception))

    def test_a_target_set_that_differs_from_its_pin_is_refused(self):
        record = copy.deepcopy(self.record)
        record["instruction_schedule"][
            "expected_internal_relocation_targets"] = [0, 19]
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.compose_retail_exact_instruction_schedule(
                self.seed, self.donor, record, SWITCH_IMAGE)
        self.assertIn("in-body relocated target set changed",
                      str(caught.exception))

    def test_an_image_that_is_not_the_oracle_is_refused(self):
        oracle = bytearray(SWITCH_IMAGE)
        oracle[5] ^= 0x01
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.compose_retail_exact_instruction_schedule(
                self.seed, self.donor, self.record, bytes(oracle))
        self.assertIn("is not retail-exact", str(caught.exception))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
