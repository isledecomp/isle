"""x87_squared_addend_exchange_v1: unit exchange inside a squared sum.

The primitive permutes contiguous `fld m32` + `fsub/fadd m32` units whose
values provably enter the result only as SQUARES folded by faddp into one
sum, and only by permutations that are exact under IEEE commutativity
against the measured fold tree.  Relocated constant operands ride with
their units through a declared relocation_reseat.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import byte_identity as bi


def build_body(units, consumption, tail=b"\xc3"):
    # A one-byte prologue (push esi): chains never begin at offset 0.
    return b"\x56" + b"".join(units) + consumption + tail


# Three canonical units: fld [edx+8]; fsub [eax+0x38] etc.
U0 = bytes.fromhex("d94208d86038")
U1 = bytes.fromhex("d94204d86034")
U2 = bytes.fromhex("d902d86030")
# fxch st(2); fmul st0,st0; fxch st(1); fmul; faddp; fxch st(1); fmul; faddp
CONSUME = bytes.fromhex("d9cadcc8d9c9dcc8dec1d9c9dcc8dec1")
BODY = build_body([U0, U1, U2], CONSUME)
START = 1
END = START + len(U0) + len(U1) + len(U2)


def run(chain, body=BODY, relocs=frozenset(), **kw):
    return bi.apply_x87_squared_addend_exchange(
        body, [chain], relocs, "test", **kw)


class TestExchange:
    def test_adjacent_swap_is_exact(self):
        image, proof = run({
            "chain_start": START, "chain_end": END, "order": [1, 0, 2],
            "expected_rewritten_offsets": [3, 6, 9, 12]})
        assert image[START:END] == U1 + U0 + U2
        assert image[END:] == BODY[END:]
        assert proof["chains"][0]["unit_count"] == 3

    def test_identity_refused(self):
        with pytest.raises(bi.ByteIdentityError, match="identity"):
            run({"chain_start": START, "chain_end": END, "order": [0, 1, 2],
                 "expected_rewritten_offsets": [2]})

    def test_regrouping_permutation_refused(self):
        # [2, 0, 1] regroups the fixed fold tree ((p0,p1),p2) -- inexact.
        with pytest.raises(bi.ByteIdentityError,
                           match="commutativity-exact"):
            run({"chain_start": START, "chain_end": END, "order": [2, 0, 1],
                 "expected_rewritten_offsets": [0]})

    def test_outer_swap_refused(self):
        with pytest.raises(bi.ByteIdentityError,
                           match="commutativity-exact"):
            run({"chain_start": START, "chain_end": END, "order": [2, 1, 0],
                 "expected_rewritten_offsets": [0]})

    def test_wrong_rewritten_set_refused(self):
        with pytest.raises(bi.ByteIdentityError, match="different byte"):
            run({"chain_start": START, "chain_end": END, "order": [1, 0, 2],
                 "expected_rewritten_offsets": [3, 6]})

    def test_non_unit_window_refused(self):
        # Window truncated mid-unit.
        with pytest.raises(bi.ByteIdentityError):
            run({"chain_start": START, "chain_end": END - 2,
                 "order": [1, 0], "expected_rewritten_offsets": [2]})

    def test_unsquared_unit_refused(self):
        # Drop one fmul: a unit is summed unsquared.
        consume = bytes.fromhex("d9cadcc8d9c9dec1d9c9dcc8dec1")
        body = build_body([U0, U1, U2], consume)
        with pytest.raises(bi.ByteIdentityError, match="squared"):
            run({"chain_start": START, "chain_end": END, "order": [1, 0, 2],
                 "expected_rewritten_offsets": [3, 6, 9, 12]}, body=body)

    def test_foreign_op_in_region_breaks_fold(self):
        # An fstp before any faddp leaves the fold unfinished.
        consume = bytes.fromhex("d9cadcc8d95c2404")
        body = build_body([U0, U1, U2], consume)
        with pytest.raises(bi.ByteIdentityError, match="fold"):
            run({"chain_start": START, "chain_end": END, "order": [1, 0, 2],
                 "expected_rewritten_offsets": [3, 6, 9, 12]}, body=body)

    def test_neutral_integer_instruction_is_transparent(self):
        # cmp dword [esi+0x1144], 0 interleaved mid-fold (the LegoAct2
        # scheduler shape) is skipped, not interpreted.
        consume = bytes.fromhex(
            "d9cadcc8d9c9dcc8"      # fxch/sq/fxch/sq
            "83be4411000000"        # cmp dword [esi+0x1144], 0
            "dec1d9c9dcc8dec1")
        body = build_body([U0, U1, U2], consume)
        image, proof = run(
            {"chain_start": START, "chain_end": END, "order": [1, 0, 2],
             "expected_rewritten_offsets": [3, 6, 9, 12]}, body=body)
        assert image[START:END] == U1 + U0 + U2

    def test_relocated_unit_requires_declared_reseat(self):
        # Units with absolute m32 constants: d9 40 04 / d8 25 imm32.
        ua = bytes.fromhex("d94004d825") + b"\x00" * 4
        ub = bytes.fromhex("d94008d805") + b"\x11" * 4
        consume = bytes.fromhex("d9c9dcc8d9c9dcc8dec1")
        body = build_body([ua, ub], consume)
        relocs = frozenset(range(6, 10)) | frozenset(range(15, 19))
        chain = {"chain_start": 1, "chain_end": 19, "order": [1, 0],
                 "expected_rewritten_offsets": [
                     1 + offset for offset in range(18)
                     if (ub + ua)[offset] != (ua + ub)[offset]]}
        with pytest.raises(bi.ByteIdentityError, match="reseat"):
            run(dict(chain), body=body, relocs=relocs)
        image, proof = run(
            dict(chain, relocation_reseat=[[6, 15], [15, 6]]),
            body=body, relocs=relocs)
        assert image[1:19] == ub + ua
        assert proof["chains"][0]["relocation_reseat"] == [[6, 15],
                                                           [15, 6]]

    def test_record_straddling_unit_boundary_refused(self):
        ua = bytes.fromhex("d94004d825") + b"\x00" * 4
        ub = bytes.fromhex("d94008d805") + b"\x11" * 4
        consume = bytes.fromhex("d9c9dcc8d9c9dcc8dec1")
        body = build_body([ua, ub], consume)
        relocs = frozenset(range(8, 12))  # crosses the 9-byte unit edge
        with pytest.raises(bi.ByteIdentityError, match="straddles"):
            run({"chain_start": 1, "chain_end": 19, "order": [1, 0],
                 "expected_rewritten_offsets": [3],
                 "relocation_reseat": [[8, 17]]},
                body=body, relocs=relocs)

    def test_branch_into_chain_refused(self):
        # jmp into the chain interior.
        body = b"\xeb\x03" + BODY  # jmp lands inside unit 0
        with pytest.raises(bi.ByteIdentityError, match="branch"):
            run({"chain_start": 2 + START, "chain_end": 2 + END,
                 "order": [1, 0, 2], "expected_rewritten_offsets": [5]},
                body=body)


class TestFourUnitTrees:
    # Four units, folded top-down: sq p3; then fxch/sq/faddp three times
    # gives the left-leaning tree (((p3, p2), p1), p0).  Only positions 2
    # and 3 -- the innermost commutative pair -- may exchange.
    U3 = bytes.fromhex("d94210d86040")
    UNITS = [U0, U1, U2, U3]
    CONSUME = bytes.fromhex("dcc8" + "d9c9dcc8dec1" * 3)

    def test_only_the_innermost_pair_commutes(self):
        body = build_body(self.UNITS, self.CONSUME)
        end = 1 + sum(len(unit) for unit in self.UNITS)
        good = {"chain_start": 1, "chain_end": end, "order": [0, 1, 3, 2]}
        swapped = U0 + U1 + self.U3 + U2
        image, proof = bi.apply_x87_squared_addend_exchange(
            body, [dict(
                good, expected_rewritten_offsets=[
                    1 + offset for offset in range(end - 1)
                    if swapped[offset] != body[1 + offset]])],
            frozenset(), "test")
        assert image[1:end] == swapped
        for bad in ([1, 0, 2, 3], [2, 3, 0, 1], [0, 2, 1, 3]):
            with pytest.raises(bi.ByteIdentityError,
                               match="commutativity-exact"):
                bi.apply_x87_squared_addend_exchange(
                    build_body(self.UNITS, self.CONSUME),
                    [dict(good, order=bad,
                          expected_rewritten_offsets=[1])],
                    frozenset(), "test")
