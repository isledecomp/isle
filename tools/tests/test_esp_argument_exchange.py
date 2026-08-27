"""esp_argument_exchange_v1: the incoming-argument role exchange primitive.

The applier discharges E1..E7 on the measured body; E8 (the paired register
bijection) is a seam obligation exercised through the composed-rewriting
host.  These tests pin the closed prologue form and every refusal edge."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import byte_identity as bi


def prologue(first_disp=0x08, second_disp=0x08, tail=b"\xc2\x08\x00"):
    #   mov edx, [esp+first]     8B 54 24 xx
    #   push esi                 56
    #   mov esi, [esp+second]    8B 74 24 xx
    return (bytes([0x8B, 0x54, 0x24, first_disp, 0x56,
                   0x8B, 0x74, 0x24, second_disp]) + tail)


ITEM = {"first_offset": 0, "second_offset": 5,
        "expected_rewritten_offsets": [3, 8]}


def test_exchanges_the_two_argument_slots():
    body = prologue()
    image, proof = bi.apply_esp_argument_exchange(
        body, [dict(ITEM)], frozenset(), "test")
    # depths: 0 at the first load, 4 after push esi; entry-relative slots
    # are 8 and 4, so the first load takes 4 and the second takes 8+4=12.
    assert image[3] == 0x04 and image[8] == 0x0C
    assert image[:3] == body[:3] and image[4:8] == body[4:8]
    assert image[9:] == body[9:]
    assert proof["sites"][0]["registers"] == ["edx", "esi"]
    assert proof["sites"][0]["rewritten_offsets"] == [3, 8]


def test_refuses_a_relocation_under_the_displacement():
    with pytest.raises(bi.ByteIdentityError, match="relocation"):
        bi.apply_esp_argument_exchange(
            prologue(), [dict(ITEM)], frozenset({3}), "test")


def test_refuses_a_prefix_outside_the_closed_form():
    body = b"\x90" + prologue()
    item = {"first_offset": 1, "second_offset": 6,
            "expected_rewritten_offsets": [4, 9]}
    with pytest.raises(bi.ByteIdentityError, match="closed form"):
        bi.apply_esp_argument_exchange(body, [item], frozenset(), "test")


def test_refuses_identical_argument_slots():
    # second load at [esp+0xc] with depth 4 addresses slot 8 == the first's.
    body = prologue(first_disp=0x08, second_disp=0x0C)
    with pytest.raises(bi.ByteIdentityError, match="distinct incoming"):
        bi.apply_esp_argument_exchange(
            body, [dict(ITEM)], frozenset(), "test")


def test_refuses_a_third_load_of_an_exchanged_slot():
    #   mov edx,[esp+8]; push esi; mov esi,[esp+8]; mov eax,[esp+8]
    body = (bytes([0x8B, 0x54, 0x24, 0x08, 0x56,
                   0x8B, 0x74, 0x24, 0x08,
                   0x8B, 0x44, 0x24, 0x08]) + b"\xc2\x08\x00")
    with pytest.raises(bi.ByteIdentityError, match="another prefix load"):
        bi.apply_esp_argument_exchange(
            body, [dict(ITEM)], frozenset(), "test")


def test_refuses_an_offset_that_is_not_a_load():
    item = {"first_offset": 0, "second_offset": 4,
            "expected_rewritten_offsets": [3, 7]}
    with pytest.raises(bi.ByteIdentityError, match="not an argument load"):
        bi.apply_esp_argument_exchange(
            prologue(), [item], frozenset(), "test")


def test_refuses_structural_destination():
    #   mov ebp, [esp+8] as the second load
    body = (bytes([0x8B, 0x54, 0x24, 0x08, 0x56,
                   0x8B, 0x6C, 0x24, 0x0C]) + b"\xc2\x08\x00")
    with pytest.raises(bi.ByteIdentityError, match="distinct general"):
        bi.apply_esp_argument_exchange(
            body, [dict(ITEM)], frozenset(), "test")


def test_shape_validator_pins_the_declaration():
    spec = {"esp_argument_exchanges": [dict(ITEM)]}
    normalized, rewritten = bi._validate_esp_argument_exchanges(
        spec, "test", 64)
    assert normalized == [ITEM]
    assert rewritten == [3, 8]
    bad = {"esp_argument_exchanges": [
        {"first_offset": 5, "second_offset": 0,
         "expected_rewritten_offsets": [3, 8]}]}
    with pytest.raises(bi.ByteIdentityError, match="unsorted"):
        bi._validate_esp_argument_exchanges(bad, "test", 64)
