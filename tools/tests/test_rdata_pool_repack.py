#!/usr/bin/env python3
"""Fail-closed tests for the object-level constant-pool repack.

The transform re-seats the ``$T`` literal run of one non-COMDAT ``.rdata``
pool in one pre-link object into the emission order retail's object carried.
It is a declared SYNTHETIC construct, so these tests are mostly refusals:
every pin has to be the thing that stops the transform, not decoration.
"""

import copy
import hashlib
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import byte_identity  # noqa: E402
import pe_rdatarepack as repack  # noqa: E402


POOL_CHARACTERISTICS = 0x40400040
TEXT_CHARACTERISTICS = 0x60500020
PREFIX_SIZE = 192

# The fixed $S block: named statics, numbered at parse, that never move.
STATICS = (
    ("_alpha$S11", 0, 8),
    ("_beta$S12", 8, 16),
    ("_gamma$S13", 24, 96),
    ("_delta$S14", 120, 72),
)

# The $T literal run, in the order our compiler emits it, with the order
# retail's object emitted.  The sizes reproduce the real geometry: three
# alignment pads before the repack, one after it.
LITERALS = (
    # symbol, size, old_offset
    ("$T1001", 4, 192),
    ("$T1002", 4, 196),
    ("$T1003", 4, 200),
    ("$T1004", 8, 208),
    ("$T1005", 4, 216),
    ("$T1006", 4, 220),
    ("$T1007", 4, 224),
    ("$T1008", 8, 232),
    ("$T1009", 4, 240),
    ("$T1010", 8, 248),
    ("$T1011", 8, 256),
    ("$T1012", 8, 264),
    ("$T1013", 8, 272),
)
RETAIL_ORDER = (
    "$T1001", "$T1002", "$T1003", "$T1007", "$T1008", "$T1005", "$T1009",
    "$T1010", "$T1011", "$T1012", "$T1004", "$T1006", "$T1013",
)
PRE_SIZE = 280
POST_SIZE = 272

# Two literals are referenced from .text; the rest are emitted because the
# parse saw them, exactly as MSVC 4.2 does.
REFERENCES = (("$T1002", 0x00), ("$T1002", 0x08), ("$T1005", 0x10))

SIZES = {symbol: size for symbol, size, _ in LITERALS}
OLD_OFFSETS = {symbol: offset for symbol, _, offset in LITERALS}
RATIONALE = (
    "SYNTHETIC CONSTRUCT standing in for a source structure that could not "
    "be recovered; every byte written is a byte the object already held."
)


def retail_seats():
    """The seats the retail order and these sizes imply."""
    cursor = PREFIX_SIZE
    seats = {}
    for symbol in RETAIL_ORDER:
        size = SIZES[symbol]
        seat = (cursor + size - 1) & ~(size - 1)
        seats[symbol] = seat
        cursor = seat + size
    return seats, cursor


NEW_OFFSETS, DERIVED_POST_SIZE = retail_seats()
assert DERIVED_POST_SIZE == POST_SIZE, DERIVED_POST_SIZE


def make_pool():
    """A 280-byte pool: a fixed prefix, thirteen literals, three pads."""
    pool = bytearray(PRE_SIZE)
    for index in range(PREFIX_SIZE):
        pool[index] = (index * 7 + 11) & 0xFF
    for symbol, size, offset in LITERALS:
        tag = int(symbol[2:])
        pool[offset:offset + size] = (
            tag.to_bytes(4, "little") * (size // 4))
    return bytes(pool)


POOL = make_pool()


def repacked_pool(pool=POOL):
    """The pool the declared permutation produces out of those bytes."""
    packed = bytearray(POST_SIZE)
    packed[:PREFIX_SIZE] = pool[:PREFIX_SIZE]
    for symbol in RETAIL_ORDER:
        size = SIZES[symbol]
        old, new = OLD_OFFSETS[symbol], NEW_OFFSETS[symbol]
        packed[new:new + size] = pool[old:old + size]
    return bytes(packed)


def _section_aux(length, relocations, lines, number, selection=0):
    return struct.pack("<IHHIHB", length, relocations, lines, 0, number,
                       selection) + b"\0\0\0"


def make_object(*, pool=POOL, characteristics=POOL_CHARACTERISTICS,
                references=REFERENCES, text_body=None, symbol_values=None,
                omit=(), extra_symbols=(), relocation_type=0x0006,
                pool_relocations=0):
    """One classic-i386 COFF carrying the pool and its .text references."""
    body = bytearray(text_body if text_body is not None else bytes(0x40))
    values = dict(symbol_values or {})

    names = []
    for name, offset, _size in STATICS:
        if name not in omit:
            names.append((name, values.get(name, offset)))
    for symbol, _size, offset in LITERALS:
        if symbol not in omit:
            names.append((symbol, values.get(symbol, offset)))
    names.extend(extra_symbols)

    # .text and .rdata section symbols occupy two records each.
    index_of = {}
    cursor = 4
    for name, _value in names:
        index_of[name] = cursor
        cursor += 1

    reloc_rows = [
        (offset, index_of[symbol], relocation_type)
        for symbol, offset in references
    ]
    # A debug section seated AFTER the pool, so the applier's file-offset
    # shift has raw data, a relocation table and a line table to move.
    debug_relocations = [(0, index_of[STATICS[0][0]], 0x000B)]
    debug_lines = struct.pack("<IH", 0, 0) + struct.pack("<IH", 4, 11)
    sections = [
        {"name": ".text", "raw": bytes(body), "relocations": reloc_rows,
         "lines": b"", "characteristics": TEXT_CHARACTERISTICS},
        {"name": ".rdata", "raw": pool,
         "relocations": [(0, index_of[LITERALS[0][0]], 0x0006)] *
                        pool_relocations,
         "lines": b"", "characteristics": characteristics},
        {"name": ".debug$S", "raw": bytes(range(16)),
         "relocations": debug_relocations, "lines": debug_lines,
         "characteristics": 0x42101048},
    ]
    offset = 20 + len(sections) * 40
    payload = bytearray()
    for item in sections:
        item["raw_offset"] = offset
        payload.extend(item["raw"])
        offset += len(item["raw"])
        table = b"".join(struct.pack("<IIH", *row)
                         for row in item["relocations"])
        item["relocation_offset"] = offset if table else 0
        payload.extend(table)
        offset += len(table)
        item["line_offset"] = offset if item["lines"] else 0
        payload.extend(item["lines"])
        offset += len(item["lines"])

    symbols = [
        (".text", 0, 1, 0, 3,
         _section_aux(len(body), len(reloc_rows), 0, 1)),
        (".rdata", 0, 2, 0, 3,
         _section_aux(len(pool), pool_relocations, 0, 2)),
    ]
    symbols.extend((name, value, 2, 0, 3, None) for name, value in names)
    symbols.append(
        (".debug$S", 0, 3, 0, 3,
         _section_aux(16, len(debug_relocations), len(debug_lines) // 6, 3)))

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
                         offset, count, 0, 0)
    return bytes(header + headers + payload + table + strings)


def make_declaration(*, pool=POOL, characteristics=POOL_CHARACTERISTICS):
    packed = repacked_pool(pool)
    counted = {symbol: 0 for symbol, _size, _offset in LITERALS}
    for symbol, _offset in REFERENCES:
        counted[symbol] += 1
    return {
        "schema": "rdata_pool_repack_v1",
        "rationale": RATIONALE,
        "object": "CMakeFiles/fixture.dir/fixture.cpp.obj",
        "translation_unit": "FIXTURE/fixture.cpp",
        "section": {
            "index": 2,
            "name": ".rdata",
            "characteristics": "0x%08x" % characteristics,
            "relocation_count": 0,
            "line_number_count": 0,
        },
        "pad_fill": "00",
        "pre_image": {
            "size": len(pool),
            "sha256": hashlib.sha256(pool).hexdigest(),
            "fixed_prefix": {
                "size": PREFIX_SIZE,
                "sha256": hashlib.sha256(pool[:PREFIX_SIZE]).hexdigest(),
                "symbols": [
                    {"symbol": name, "offset": offset, "size": size}
                    for name, offset, size in STATICS
                ],
            },
        },
        "permutation": [
            {
                "symbol": symbol,
                "old_offset": OLD_OFFSETS[symbol],
                "new_offset": NEW_OFFSETS[symbol],
                "size": SIZES[symbol],
                "references": counted[symbol],
            }
            for symbol in RETAIL_ORDER
        ],
        "post_image": {
            "size": POST_SIZE,
            "sha256": hashlib.sha256(packed).hexdigest(),
        },
    }


def validate(declaration, pool=None):
    return byte_identity.validate_rdata_pool_repack_declaration(
        declaration, "images.LEGO1.rdata_pool_repack", pool_bytes=pool)


class DeclarationTests(unittest.TestCase):
    """The manifest pin refuses anything it cannot re-derive."""

    def test_declaration_validates(self):
        self.assertEqual(validate(make_declaration())["schema"],
                         "rdata_pool_repack_v1")

    def test_pool_bytes_close_the_declaration(self):
        validate(make_declaration(), POOL)

    def test_unknown_key_refused(self):
        declaration = make_declaration()
        declaration["shift"] = 8
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            validate(declaration)
        self.assertIn("schema differs", str(caught.exception))

    def test_missing_key_refused(self):
        declaration = make_declaration()
        del declaration["post_image"]
        with self.assertRaises(byte_identity.ByteIdentityError):
            validate(declaration)

    def test_unsupported_schema_refused(self):
        declaration = make_declaration()
        declaration["schema"] = "rdata_pool_repack_v2"
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            validate(declaration)
        self.assertIn("schema is unsupported", str(caught.exception))

    def test_rationale_must_name_the_construct_synthetic(self):
        declaration = make_declaration()
        declaration["rationale"] = "The retail object emitted this order."
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            validate(declaration)
        self.assertIn("must name this construct as synthetic",
                      str(caught.exception))

    def test_pad_fill_is_a_closed_enum(self):
        declaration = make_declaration()
        declaration["pad_fill"] = "cc"
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            validate(declaration)
        self.assertIn("pad_fill is unsupported", str(caught.exception))

    def test_comdat_pool_refused(self):
        declaration = make_declaration()
        declaration["section"]["characteristics"] = "0x40401040"
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            validate(declaration)
        self.assertIn("non-COMDAT data section", str(caught.exception))

    def test_writable_pool_refused(self):
        declaration = make_declaration()
        declaration["section"]["characteristics"] = "0xc0400040"
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            validate(declaration)
        self.assertIn("read-only", str(caught.exception))

    def test_pool_with_relocations_refused(self):
        declaration = make_declaration()
        declaration["section"]["relocation_count"] = 1
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            validate(declaration)
        self.assertIn("no relocations", str(caught.exception))

    def test_section_size_may_not_exceed_alignment(self):
        declaration = make_declaration()
        # ALIGN_4BYTES cannot hold the eight-byte doubles this pool declares.
        declaration["section"]["characteristics"] = "0x40300040"
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            validate(declaration)
        self.assertIn("exceeds the declared section alignment",
                      str(caught.exception))

    def test_static_prefix_must_tile(self):
        declaration = make_declaration()
        declaration["pre_image"]["fixed_prefix"]["symbols"][2]["size"] = 92
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            validate(declaration)
        self.assertIn("must be contiguous", str(caught.exception))

    def test_static_prefix_must_reach_its_declared_size(self):
        declaration = make_declaration()
        declaration["pre_image"]["fixed_prefix"]["symbols"].pop()
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            validate(declaration)
        self.assertIn("not the declared prefix size", str(caught.exception))

    def test_permutation_may_not_name_a_static(self):
        declaration = make_declaration()
        declaration["permutation"][0]["symbol"] = "_alpha$S11"
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            validate(declaration)
        self.assertIn("must be one MSVC 4.2 $T pool literal",
                      str(caught.exception))

    def test_static_named_like_a_literal_refused(self):
        declaration = make_declaration()
        declaration["pre_image"]["fixed_prefix"]["symbols"][0]["symbol"] = (
            "_alpha$S1001")
        declaration["permutation"][0]["symbol"] = "_alpha$S1001"
        with self.assertRaises(byte_identity.ByteIdentityError):
            validate(declaration)

    def test_permutation_may_not_reach_into_the_prefix(self):
        declaration = make_declaration()
        entry = declaration["permutation"][0]
        entry["old_offset"] = PREFIX_SIZE - 8
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            validate(declaration)
        self.assertIn("the $S block may never move", str(caught.exception))

    def test_permutation_may_not_seat_a_literal_in_the_prefix(self):
        declaration = make_declaration()
        for entry in declaration["permutation"]:
            entry["new_offset"] -= 8
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            validate(declaration)
        self.assertIn("the $S block may never move", str(caught.exception))

    def test_duplicate_symbol_refused(self):
        declaration = make_declaration()
        declaration["permutation"][1]["symbol"] = (
            declaration["permutation"][0]["symbol"])
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            validate(declaration)
        self.assertIn("names a symbol twice", str(caught.exception))

    def test_duplicate_pre_image_offset_refused(self):
        declaration = make_declaration()
        declaration["permutation"][1]["old_offset"] = (
            declaration["permutation"][0]["old_offset"])
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            validate(declaration)
        self.assertIn("share one pre-image offset", str(caught.exception))

    def test_duplicate_post_image_offset_refused(self):
        declaration = make_declaration()
        # Two literals seated on top of each other is exactly the shape a
        # bijection forbids; the seat derivation must not paper over it.
        declaration["permutation"][2]["new_offset"] = (
            declaration["permutation"][1]["new_offset"])
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            validate(declaration)
        self.assertIn("bijection", str(caught.exception))

    def test_permutation_must_be_declared_in_seat_order(self):
        declaration = make_declaration()
        declaration["permutation"].reverse()
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            validate(declaration)
        self.assertIn("post-image seat order", str(caught.exception))

    def test_alignment_must_follow_the_declared_sizes(self):
        declaration = make_declaration()
        for entry in declaration["permutation"]:
            if entry["symbol"] == "$T1013":
                entry["new_offset"] = 260
        declaration["post_image"]["size"] = 268
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            validate(declaration)
        self.assertIn("does not match what its sizes imply",
                      str(caught.exception))

    def test_pre_image_size_must_match_the_seats(self):
        declaration = make_declaration()
        declaration["pre_image"]["size"] = 288
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            validate(declaration)
        self.assertIn("pre-image bytes", str(caught.exception))

    def test_post_image_size_must_match_the_seats(self):
        declaration = make_declaration()
        declaration["post_image"]["size"] = 264
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            validate(declaration)
        self.assertIn("post-image bytes", str(caught.exception))

    def test_growing_the_pool_refused(self):
        declaration = make_declaration()
        declaration["post_image"]["size"] = 288
        with self.assertRaises(byte_identity.ByteIdentityError):
            validate(declaration)

    def test_identical_pre_and_post_digest_refused(self):
        declaration = make_declaration()
        declaration["post_image"]["sha256"] = (
            declaration["pre_image"]["sha256"])
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            validate(declaration)
        self.assertIn("identical pre- and post-image", str(caught.exception))

    def test_literal_width_is_a_closed_enum(self):
        declaration = make_declaration()
        declaration["permutation"][0]["size"] = 2
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            validate(declaration)
        self.assertIn("not an admitted literal width", str(caught.exception))

    def test_object_path_must_be_relative(self):
        declaration = make_declaration()
        declaration["object"] = "/tmp/fixture.cpp.obj"
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            validate(declaration)
        self.assertIn("canonical relative .obj path", str(caught.exception))

    def test_boolean_is_not_an_integer(self):
        declaration = make_declaration()
        declaration["permutation"][0]["references"] = True
        with self.assertRaises(byte_identity.ByteIdentityError):
            validate(declaration)

    def test_drifted_pre_image_refused(self):
        drifted = bytearray(POOL)
        drifted[PREFIX_SIZE] ^= 0xFF
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            validate(make_declaration(), bytes(drifted))
        self.assertIn("pre-image digest differs", str(caught.exception))

    def test_drifted_static_prefix_refused(self):
        drifted = bytearray(POOL)
        drifted[7] ^= 0xFF
        declaration = make_declaration()
        declaration["pre_image"]["sha256"] = hashlib.sha256(
            bytes(drifted)).hexdigest()
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            validate(declaration, bytes(drifted))
        self.assertIn("fixed $S prefix differs", str(caught.exception))

    def test_pre_image_pad_must_be_the_declared_filler(self):
        drifted = bytearray(POOL)
        drifted[204:208] = b"\xcc\xcc\xcc\xcc"
        declaration = make_declaration(pool=bytes(drifted))
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            validate(declaration, bytes(drifted))
        self.assertIn("is not the declared 0x00 filler", str(caught.exception))

    def test_post_image_digest_mismatch_refused(self):
        declaration = make_declaration()
        declaration["post_image"]["sha256"] = "0" * 64
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            validate(declaration, POOL)
        self.assertIn(
            "post-image digest differs from the image the declared "
            "permutation actually produces", str(caught.exception))

    def test_swapped_seats_change_the_post_image_digest(self):
        # A permutation that is geometrically legal but seats two same-width
        # literals the wrong way round must still be caught by the digest.
        declaration = make_declaration()
        seats = {entry["symbol"]: entry
                 for entry in declaration["permutation"]}
        seats["$T1011"]["old_offset"], seats["$T1012"]["old_offset"] = (
            seats["$T1012"]["old_offset"], seats["$T1011"]["old_offset"])
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            validate(declaration, POOL)
        self.assertIn("post-image digest differs", str(caught.exception))


class ApplierTests(unittest.TestCase):
    """The applier refuses rather than guessing on any disagreement."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def write(self, data, declaration):
        object_path = self.root / "fixture.cpp.obj"
        object_path.write_bytes(data)
        declaration_path = self.root / "declaration.json"
        declaration_path.write_text(json.dumps(declaration, indent=1))
        return object_path, declaration_path

    def pool_of(self, data):
        coff = byte_identity.CoffObject(data)
        section = next(s for s in coff.sections
                       if s["name"] == ".rdata"
                       and not s["characteristics"] & 0x1000)
        return data[section["raw_offset"]:
                    section["raw_offset"] + section["raw_size"]]

    def symbol_values(self, data):
        coff = byte_identity.CoffObject(data)
        return {symbol["name"]: symbol["value"]
                for symbol in coff.symbols.values()
                if symbol["section"] == 2 and not symbol["aux_count"]}

    def test_happy_path(self):
        original = make_object()
        result = repack.repack(original, make_declaration())
        self.assertEqual(self.pool_of(result), repacked_pool())
        self.assertEqual(len(result), len(original) - 8)
        values = self.symbol_values(result)
        for name, offset, _size in STATICS:
            self.assertEqual(values[name], offset)
        for symbol in RETAIL_ORDER:
            self.assertEqual(values[symbol], NEW_OFFSETS[symbol])

    def test_result_is_a_well_formed_object(self):
        result = repack.repack(make_object(), make_declaration())
        coff = byte_identity.CoffObject(result)
        pool = next(s for s in coff.sections if s["name"] == ".rdata")
        self.assertEqual(pool["raw_size"], POST_SIZE)
        aux_at = coff.symbol_offset + 3 * 18
        self.assertEqual(struct.unpack_from("<I", result, aux_at)[0],
                         POST_SIZE)
        # Nothing after the pool may be left pointing into the removed tail.
        for section in coff.sections:
            for key, size in (("raw_offset", section["raw_size"]),
                              ("relocation_offset",
                               section["relocation_count"] * 10)):
                if section[key]:
                    self.assertLessEqual(section[key] + size, len(result))

    def test_text_bytes_and_relocations_survive(self):
        original = make_object()
        result = repack.repack(original, make_declaration())
        before = byte_identity.CoffObject(original)
        after = byte_identity.CoffObject(result)
        for index in (0,):
            was, now = before.sections[index], after.sections[index]
            self.assertEqual(
                original[was["raw_offset"]:
                         was["raw_offset"] + was["raw_size"]],
                result[now["raw_offset"]:now["raw_offset"] + now["raw_size"]])
            self.assertEqual(
                original[was["relocation_offset"]:
                         was["relocation_offset"]
                         + was["relocation_count"] * 10],
                result[now["relocation_offset"]:
                       now["relocation_offset"]
                       + now["relocation_count"] * 10])

    def test_sections_after_the_pool_move_down_by_the_removed_tail(self):
        original = make_object()
        result = repack.repack(original, make_declaration())
        before = byte_identity.CoffObject(original)
        after = byte_identity.CoffObject(result)
        was, now = before.sections[2], after.sections[2]
        self.assertEqual(was["name"], ".debug$S")
        for key in ("raw_offset", "relocation_offset", "line_offset"):
            self.assertEqual(now[key], was[key] - 8)
        self.assertEqual(
            original[was["raw_offset"]:was["raw_offset"] + was["raw_size"]],
            result[now["raw_offset"]:now["raw_offset"] + now["raw_size"]])
        self.assertEqual(
            original[was["line_offset"]:was["line_offset"] + 12],
            result[now["line_offset"]:now["line_offset"] + 12])
        self.assertEqual(after.symbol_offset, before.symbol_offset - 8)

    def test_second_application_refuses(self):
        result = repack.repack(make_object(), make_declaration())
        with self.assertRaises(repack.RepackError) as caught:
            repack.repack(result, make_declaration())
        self.assertIn("not the declared pre-image size", str(caught.exception))

    def test_drifted_pre_image_refuses(self):
        drifted = bytearray(POOL)
        drifted[PRE_SIZE - 1] ^= 0xFF
        with self.assertRaises(repack.RepackError) as caught:
            repack.repack(make_object(pool=bytes(drifted)),
                          make_declaration())
        self.assertIn("pre-image digest differs", str(caught.exception))

    def test_post_image_digest_mismatch_refuses(self):
        declaration = make_declaration()
        declaration["post_image"]["sha256"] = "f" * 64
        with self.assertRaises(repack.RepackError) as caught:
            repack.repack(make_object(), declaration)
        self.assertIn("post-image digest differs", str(caught.exception))

    def test_non_bijective_permutation_refuses(self):
        declaration = make_declaration()
        declaration["permutation"][3]["symbol"] = (
            declaration["permutation"][2]["symbol"])
        with self.assertRaises(repack.RepackError) as caught:
            repack.repack(make_object(), declaration)
        self.assertIn("bijection", str(caught.exception))

    def test_moving_a_static_refuses(self):
        declaration = make_declaration()
        declaration["permutation"].append({
            "symbol": "$T1014", "old_offset": 120, "new_offset": 264,
            "size": 8, "references": 0,
        })
        with self.assertRaises(repack.RepackError) as caught:
            repack.repack(make_object(), declaration)
        self.assertIn("the $S block may never move", str(caught.exception))

    def test_static_seated_elsewhere_in_the_object_refuses(self):
        moved = make_object(symbol_values={"_beta$S12": 16})
        with self.assertRaises(repack.RepackError) as caught:
            repack.repack(moved, make_declaration())
        self.assertIn("fixed static _beta$S12 sits at 16",
                      str(caught.exception))

    def test_literal_seated_elsewhere_in_the_object_refuses(self):
        moved = make_object(symbol_values={"$T1013": 264})
        with self.assertRaises(repack.RepackError) as caught:
            repack.repack(moved, make_declaration())
        self.assertIn("not the declared pre-image offset",
                      str(caught.exception))

    def test_missing_pool_symbol_refuses(self):
        with self.assertRaises(repack.RepackError) as caught:
            repack.repack(make_object(omit=("$T1009",)), make_declaration())
        self.assertIn("missing", str(caught.exception))

    def test_undeclared_pool_symbol_refuses(self):
        extra = make_object(extra_symbols=(("$T1099", 192),))
        with self.assertRaises(repack.RepackError) as caught:
            repack.repack(extra, make_declaration())
        self.assertIn("extra", str(caught.exception))

    def test_reference_count_drift_refuses(self):
        declaration = make_declaration()
        for entry in declaration["permutation"]:
            if entry["symbol"] == "$T1002":
                entry["references"] = 3
        with self.assertRaises(repack.RepackError) as caught:
            repack.repack(make_object(), declaration)
        self.assertIn("is referenced 2 times, not the declared 3",
                      str(caught.exception))

    def test_non_zero_addend_reference_refuses(self):
        body = bytearray(0x40)
        body[0x10:0x14] = struct.pack("<I", 4)
        with self.assertRaises(repack.RepackError) as caught:
            repack.repack(make_object(text_body=bytes(body)),
                          make_declaration())
        self.assertIn("may not be referenced at an offset",
                      str(caught.exception))

    def test_section_relative_reference_refuses(self):
        with self.assertRaises(repack.RepackError) as caught:
            repack.repack(make_object(relocation_type=0x000B),
                          make_declaration())
        self.assertIn("not DIR32", str(caught.exception))

    def test_section_index_mismatch_refuses(self):
        declaration = make_declaration()
        declaration["section"]["index"] = 1
        with self.assertRaises(repack.RepackError) as caught:
            repack.repack(make_object(), declaration)
        self.assertIn("not the declared 1", str(caught.exception))

    def test_comdat_pool_is_not_a_candidate(self):
        declaration = make_declaration(characteristics=0x40401040)
        with self.assertRaises(repack.RepackError) as caught:
            repack.repack(make_object(characteristics=0x40401040),
                          declaration)
        self.assertIn("non-COMDAT data section", str(caught.exception))

    def test_pool_carrying_relocations_refuses(self):
        with self.assertRaises(repack.RepackError) as caught:
            repack.repack(make_object(pool_relocations=1), make_declaration())
        self.assertIn("relocations or line numbers", str(caught.exception))

    def test_aux_length_disagreement_refuses(self):
        data = bytearray(make_object())
        coff = byte_identity.CoffObject(bytes(data))
        struct.pack_into("<I", data, coff.symbol_offset + 3 * 18, 999)
        with self.assertRaises(repack.RepackError) as caught:
            repack.repack(bytes(data), make_declaration())
        self.assertIn("aux record declares 999", str(caught.exception))

    def test_declaration_is_not_mutated(self):
        declaration = make_declaration()
        snapshot = copy.deepcopy(declaration)
        repack.repack(make_object(), declaration)
        self.assertEqual(declaration, snapshot)

    def test_cli_check_mode_does_not_write(self):
        object_path, declaration_path = self.write(
            make_object(), make_declaration())
        before = object_path.read_bytes()
        self.assertEqual(
            repack.main(["pe_rdatarepack.py", str(object_path),
                         str(declaration_path), "--check"]), 0)
        self.assertEqual(object_path.read_bytes(), before)

    def test_cli_writes_and_refuses(self):
        object_path, declaration_path = self.write(
            make_object(), make_declaration())
        self.assertEqual(
            repack.main(["pe_rdatarepack.py", str(object_path),
                         str(declaration_path)]), 0)
        self.assertEqual(self.pool_of(object_path.read_bytes()),
                         repacked_pool())
        after = object_path.read_bytes()
        self.assertEqual(
            repack.main(["pe_rdatarepack.py", str(object_path),
                         str(declaration_path)]), 1)
        self.assertEqual(object_path.read_bytes(), after)

    def test_cli_usage_refuses(self):
        self.assertEqual(repack.main(["pe_rdatarepack.py"]), 2)

    def test_duplicate_json_key_refuses(self):
        object_path = self.root / "fixture.cpp.obj"
        object_path.write_bytes(make_object())
        declaration_path = self.root / "declaration.json"
        declaration_path.write_text(
            '{"schema": "rdata_pool_repack_v1", '
            '"schema": "rdata_pool_repack_v1"}')
        self.assertEqual(
            repack.main(["pe_rdatarepack.py", str(object_path),
                         str(declaration_path)]), 1)


if __name__ == "__main__":
    unittest.main()
