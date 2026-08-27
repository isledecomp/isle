"""debug_representation_delta: the pinned seed<->donor `.debug$S` proof.

The delta replaces D1's raw-size equality proxy with a record-by-record
same-function proof; these tests pin the three closed kinds and every
refusal edge of both the shape validator and the prover."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import byte_identity as bi


def record(kind, payload):
    return (len(payload) + 2).to_bytes(2, "little") \
        + kind.to_bytes(2, "little") + payload


def gproc(length, end, start=5, name=b"f"):
    return record(0x205, bytes(12) + length.to_bytes(4, "little")
                  + start.to_bytes(4, "little") + end.to_bytes(4, "little")
                  + bytes(4) + bytes(2) + bytes(2) + b"\x00"
                  + bytes([len(name)]) + name)


def label(name):
    return record(0x209, bytes(7) + bytes([len(name)]) + name)


def reg_local(typind, reg, name):
    return record(0x0002, typind.to_bytes(2, "little")
                  + reg.to_bytes(2, "little")
                  + bytes([len(name)]) + name)


def bprel_local(offset, typind, name):
    return record(0x0200, offset.to_bytes(4, "little", signed=True)
                  + typind.to_bytes(2, "little")
                  + bytes([len(name)]) + name)


END = record(0x0006, b"")
SEED = gproc(100, 90) + label(b"$L1") + reg_local(0x74, 17, b"x") + END
DONOR = gproc(105, 95) + label(b"$L2") + bprel_local(-8, 0x74, b"x") + END
DELTA = [
    {"kind": "procedure_extent", "record_index": 0},
    {"kind": "compiler_label_number", "record_index": 1},
    {"kind": "local_location", "record_index": 2, "name": "x",
     "type": 0x74, "seed_location": {"register": 17},
     "donor_location": {"bp_offset": -8}},
]


def test_proves_the_three_closed_kinds():
    detail = bi.require_debug_symbol_representation_delta(
        SEED, DONOR, DELTA, 100, 105, "test")
    assert [item["kind"] for item in detail] == [
        "procedure_extent", "compiler_label_number", "local_location"]
    assert detail[2]["name"] == "x"


def test_refuses_an_undeclared_difference():
    with pytest.raises(bi.ByteIdentityError, match="without a declaration"):
        bi.require_debug_symbol_representation_delta(
            SEED, DONOR, DELTA[:2], 100, 105, "test")


def test_refuses_a_dead_declaration():
    with pytest.raises(bi.ByteIdentityError, match="does not differ"):
        bi.require_debug_symbol_representation_delta(
            SEED, SEED, [DELTA[1]], 100, 100, "test")


def test_refuses_an_extent_off_the_length_pins():
    with pytest.raises(bi.ByteIdentityError, match="length pins"):
        bi.require_debug_symbol_representation_delta(
            SEED, DONOR, DELTA, 100, 104, "test")


def test_refuses_a_debug_range_outside_its_extent():
    drifted = gproc(105, 106) + DONOR[len(gproc(105, 95)):]
    with pytest.raises(bi.ByteIdentityError,
                       match="inside its own extent"):
        bi.require_debug_symbol_representation_delta(
            SEED, drifted, DELTA, 100, 105, "test")


def test_refuses_a_procedure_name_change_as_extent():
    renamed = gproc(105, 95, name=b"g") + DONOR[len(gproc(105, 95)):]
    with pytest.raises(bi.ByteIdentityError,
                       match="more than the procedure extent"):
        bi.require_debug_symbol_representation_delta(
            SEED, renamed, DELTA, 100, 105, "test")


def test_refuses_a_non_serial_label_pair():
    named = gproc(105, 95) + label(b"$T7") + DONOR[
        len(gproc(105, 95)) + len(label(b"$L2")):]
    with pytest.raises(bi.ByteIdentityError, match="compiler-numbered"):
        bi.require_debug_symbol_representation_delta(
            SEED, named, DELTA, 100, 105, "test")


def test_refuses_a_location_off_its_declaration():
    moved = DONOR.replace(bprel_local(-8, 0x74, b"x"),
                          bprel_local(-12, 0x74, b"x"))
    with pytest.raises(bi.ByteIdentityError, match="location differs"):
        bi.require_debug_symbol_representation_delta(
            SEED, moved, DELTA, 100, 105, "test")


def test_refuses_a_record_count_change():
    with pytest.raises(bi.ByteIdentityError, match="record counts differ"):
        bi.require_debug_symbol_representation_delta(
            SEED, DONOR + END, DELTA, 100, 105, "test")


def test_validator_pins_the_declaration_shape():
    normalized = bi.validate_debug_representation_delta(DELTA, "test")
    assert normalized[2]["seed_location"] == {"register": 17}
    unsorted = [DELTA[1], DELTA[0]]
    with pytest.raises(bi.ByteIdentityError, match="unsorted"):
        bi.validate_debug_representation_delta(unsorted, "test")
    compiler_named = [dict(DELTA[2], name="$L80981")]
    with pytest.raises(bi.ByteIdentityError, match="source-named"):
        bi.validate_debug_representation_delta(compiler_named, "test")
    fixed_point = [dict(DELTA[2], donor_location={"register": 17})]
    with pytest.raises(bi.ByteIdentityError, match="move the local"):
        bi.validate_debug_representation_delta(fixed_point, "test")


def test_pins_an_inserted_donor_local():
    donor = (gproc(105, 95) + label(b"$L2") + bprel_local(-8, 0x74, b"x")
             + reg_local(0x75, 18, b"col") + END)
    delta = DELTA + [{"kind": "inserted_donor_local", "record_index": 3,
                      "name": "col", "type": 0x75,
                      "location": {"register": 18}}]
    detail = bi.require_debug_symbol_representation_delta(
        SEED, donor, delta, 100, 105, "test")
    assert detail[-1]["kind"] == "inserted_donor_local"
    wrong = DELTA + [{"kind": "inserted_donor_local", "record_index": 3,
                      "name": "col", "type": 0x75,
                      "location": {"register": 19}}]
    with pytest.raises(bi.ByteIdentityError, match="differs from"):
        bi.require_debug_symbol_representation_delta(
            SEED, donor, wrong, 100, 105, "test")
    with pytest.raises(bi.ByteIdentityError, match="record counts differ"):
        bi.require_debug_symbol_representation_delta(
            SEED, donor, DELTA, 100, 105, "test")
