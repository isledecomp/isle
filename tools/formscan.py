#!/usr/bin/env python3
"""Instruction-FORM screen: is a row's residue a renaming, or a real difference?

WHAT THIS ANSWERS

  The certificate classes rewrite a compiler-produced body under a proof and
  refuse unless the result is retail's own bytes.  Before funding any of them
  on a row, the question worth asking is cheap and binary:

      do our body and retail's carry the SAME INSTRUCTIONS, differing only in
      which register each field names?

  If yes, the row is a colouring problem and a bijection certificate can close
  it.  If no, the compiler has to emit different bytes and the row is a source
  problem.  Getting that wrong in either direction is expensive, so this walks
  the two bodies in lockstep with the project's own closed decoder rather than
  diffing disassembly text.

WHY A NAIVE WALK GETS IT WRONG -- four corrections, each of which produced a
wrong verdict before it was fixed:

  1  `+r` forms encode their register IN THE OPCODE's low three bits, so
     `push esi` (0x56) and `push edi` (0x57) are the SAME form.  Comparing raw
     opcodes calls that a structural divergence when it is exactly the renaming
     being looked for.  Masked here the way `apply_register_bijection`'s own
     image check masks it.
  2  Comparing register fields alone is NOT sound.  Two instructions can share
     a form and a register set and still differ in a displacement or an
     immediate -- which is precisely what `0x100a46b0`'s 86 x87 stack-slot
     displacements are, and a field-only walk calls that row clean.  So every
     non-register bit is compared too, with our own relocations masked.
  3  The ACCUMULATOR short forms: `add eax, imm32` is `05 imm32`, one byte
     shorter than `81 /0 imm32`.  A bijection that maps a register to or from
     EAX therefore changes an instruction's LENGTH, exactly as one that maps to
     or from EBP does.  Normalising both encodings to (group, digit, register,
     immediate) lets the walk see them as one form.
  4  The OPERAND-DIRECTION forms: every ALU opcode and MOV has two
     register-to-register encodings of the identical operation (`X+1 /r` puts
     the destination in r/m, `X+3 /r` in reg).  MSVC 4.2 emits BOTH for the
     same comparison in one translation unit.

RESIDUE CLASSES.  Each instruction that differs outside its register fields is
classified, because only one of the four is a real obstacle:

  branch    a relative branch whose only differing bytes are its displacement
            field -- repaired by the re-encoding certificate's own fixpoint
  reencode  the two encodings differ in LENGTH, which is what an EBP-base
            re-encoding IS
  accform   an accumulator short form against its ModRM equivalent
  dirform   the two operand-direction encodings of one operation
  other     a genuine structural difference

THE SCREEN IS: the walk completes AND `other == 0`.

Validation: `0x100a7960` at its carrier minimum reports `{branch: 8,
reencode: 2}` and closed on the re-encoding certificate; `0x100a46b0` reports
537 instructions walked, no form divergence, and `{other: 86}` -- independently
reproducing the recorded x87 slot-displacement finding.

usage:
  formscan.py <retail-va> <object-path> [-v]
  formscan.py --rows rows.json --objects <build-dir>   [screen a whole board]
"""
import argparse
import collections
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import byte_identity as bi  # noqa: E402

RETAIL_IMAGE = Path("/Users/foxtacles/Projects/isle/legobin/LEGO1.DLL")

# Accumulator short form -> (canonical group opcode, /digit).
ACC_FORMS = {
    0x04: (0x80, 0), 0x05: (0x81, 0), 0x0C: (0x80, 1), 0x0D: (0x81, 1),
    0x14: (0x80, 2), 0x15: (0x81, 2), 0x1C: (0x80, 3), 0x1D: (0x81, 3),
    0x24: (0x80, 4), 0x25: (0x81, 4), 0x2C: (0x80, 5), 0x2D: (0x81, 5),
    0x34: (0x80, 6), 0x35: (0x81, 6), 0x3C: (0x80, 7), 0x3D: (0x81, 7),
    0xA8: (0xF6, 0), 0xA9: (0xF7, 0),
}

# ALU/MOV bases whose `+1` and `+3` forms are the two directions of one op.
DIR_BASES = (0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x88)

RESIDUE_CLASSES = ("branch", "reencode", "accform", "dirform", "other")


def retail_sections(data: bytes):
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    count = struct.unpack_from("<H", data, pe + 6)[0]
    optional = struct.unpack_from("<H", data, pe + 20)[0]
    base = struct.unpack_from("<I", data, pe + 24 + 28)[0]
    sections, cursor = [], pe + 24 + optional
    for _ in range(count):
        virtual_size, virtual_address, raw_size, pointer = struct.unpack_from(
            "<IIII", data, cursor + 8)
        sections.append((virtual_address, virtual_size, pointer, raw_size))
        cursor += 40
    return base, sections


def retail_body(data: bytes, address: int, length: int) -> bytes:
    base, sections = retail_sections(data)
    rva = address - base
    for virtual_address, virtual_size, pointer, raw_size in sections:
        if virtual_address <= rva < virtual_address + max(virtual_size,
                                                          raw_size):
            start = pointer + rva - virtual_address
            return data[start:start + length]
    raise KeyError(hex(address))


def _accumulator_key(body: bytes, item: dict):
    """(group, digit, [register], immediate) for either encoding, or None."""
    opcode, encoding = item["opcode"], item["encoding"]
    if opcode in ACC_FORMS:
        group, digit = ACC_FORMS[opcode]
        immediate = bytes(body[item["offset"] + 1:
                               item["offset"] + item["length"]])
        return (group, digit, [0], immediate)
    if (opcode in (0x80, 0x81, 0xF6, 0xF7)
            and encoding is not None and encoding["mode"] == 3):
        immediate = bytes(body[encoding["modrm_at"] + 1:
                               item["offset"] + item["length"]])
        return (opcode, encoding["reg"], [encoding["rm"]], immediate)
    return None


def _direction_key(item: dict):
    """(base opcode, destination, source) for a register-direct ALU/MOV."""
    encoding = item["encoding"]
    if encoding is None or encoding["mode"] != 3:
        return None
    for base in DIR_BASES:
        if item["opcode"] == base + 1:
            return (base, encoding["rm"], encoding["reg"])
        if item["opcode"] == base + 3:
            return (base, encoding["reg"], encoding["rm"])
    return None


def _register_numbers(body: bytes, item: dict) -> list:
    return [(body[byte_index] >> shift) & 7
            for byte_index, shift in item["fields"]]


def scan(ours: bytes, theirs: bytes, masked: frozenset,
         relocations: dict | None = None) -> dict:
    """Walk both bodies in lockstep; report every step and the first divergence."""
    steps, ours_at, theirs_at = [], 0, 0
    while ours_at < len(ours) and theirs_at < len(theirs):
        try:
            left = bi.decode_ia32_bijection_instruction(
                ours, ours_at, "ours", relocations)
        except bi.ByteIdentityError as error:
            return {"error": f"ours decode at {ours_at:#x}: {error}",
                    "steps": steps}
        try:
            right = bi.decode_ia32_bijection_instruction(
                theirs, theirs_at, "retail", None)
        except bi.ByteIdentityError as error:
            return {"error": f"retail decode at {theirs_at:#x}: {error}",
                    "steps": steps}
        form = bi._bijection_form_for(left["opcode"])
        opreg = form is not None and form["opreg"] is not None
        mask = 0xF8 if opreg else 0xFFFF
        left_acc = _accumulator_key(ours, left)
        right_acc = _accumulator_key(theirs, right)
        accumulator = (left_acc is not None and right_acc is not None
                       and left_acc[0] == right_acc[0]
                       and left_acc[1] == right_acc[1]
                       and left_acc[3] == right_acc[3]
                       and left["opcode"] != right["opcode"])
        left_dir, right_dir = _direction_key(left), _direction_key(right)
        direction = (left_dir is not None and right_dir is not None
                     and left_dir[0] == right_dir[0]
                     and left["opcode"] != right["opcode"])
        if (not accumulator and not direction
                and ((left["opcode"] & mask) != (right["opcode"] & mask)
                     or len(left["fields"]) != len(right["fields"]))):
            return {
                "error": (f"form divergence at ours {ours_at:#x} / retail "
                          f"{theirs_at:#x} ({left['opcode']:#x} vs "
                          f"{right['opcode']:#x})"),
                "steps": steps,
            }
        if accumulator:
            left_registers, right_registers = left_acc[2], right_acc[2]
        elif direction:
            left_registers = [left_dir[1], left_dir[2]]
            right_registers = [right_dir[1], right_dir[2]]
        else:
            left_registers = _register_numbers(ours, left)
            right_registers = _register_numbers(theirs, right)
        residue = None
        if accumulator or direction:
            residue = None if left["length"] != right["length"] else []
        elif left["length"] == right["length"]:
            owned = {}
            for byte_index, shift in left["fields"]:
                position = byte_index - ours_at
                owned[position] = owned.get(position, 0) | (7 << shift)
            residue = [
                position for position in range(left["length"])
                if ours_at + position not in masked
                and (ours[ours_at + position] & ~owned.get(position, 0) & 0xFF)
                != (theirs[theirs_at + position]
                    & ~owned.get(position, 0) & 0xFF)
            ]
        kind = ""
        if direction and left["length"] == right["length"]:
            kind = "dirform"
        elif accumulator:
            kind = "accform"
        elif residue is None:
            kind = "reencode"
        elif residue:
            width = form["displacement"] if form else 0
            kind = ("branch"
                    if (left["flow"] in ("jcc", "jmp") and width
                        and all(position >= left["length"] - width
                                for position in residue))
                    else "other")
        steps.append({
            "ours": ours_at, "retail": theirs_at,
            "ours_length": left["length"], "retail_length": right["length"],
            "ours_registers": left_registers,
            "retail_registers": right_registers,
            "same": left_registers == right_registers and residue == [],
            "kind": kind,
        })
        ours_at += left["length"]
        theirs_at += right["length"]
    error = None
    if ours_at != len(ours) or theirs_at != len(theirs):
        error = (f"ragged end: ours {ours_at}/{len(ours)}, "
                 f"retail {theirs_at}/{len(theirs)}")
    return {"error": error, "steps": steps}


def verdict(result: dict) -> tuple[str, dict]:
    counts = collections.Counter(step["kind"] for step in result["steps"]
                                 if step["kind"])
    if result["error"]:
        return "DIVERGES", dict(counts)
    if counts.get("other"):
        return "STRUCTURAL", dict(counts)
    return "CLOSABLE SHAPE", dict(counts)


def screen(address: int, object_path: Path, mangled: str, length: int,
           verbose: bool = False) -> dict:
    coff = bi.CoffObject(object_path.read_bytes())
    section = coff.function_section(mangled)
    ours = bytes(bi.coff_body(coff, section))
    rows = bi.detailed_relocations(coff, section)
    masked = frozenset(row["offset"] + byte
                       for row in rows for byte in range(row["width"]))
    relocations = {row["offset"]: {"width": row["width"],
                                   "target": row["target"]} for row in rows}
    theirs = retail_body(RETAIL_IMAGE.read_bytes(), address, length)
    result = scan(ours, theirs, masked, relocations)
    label, counts = verdict(result)
    result["verdict"] = label
    result["counts"] = counts
    if verbose:
        print(f"{address:#x}: {label}  walked "
              f"{len(result['steps'])} instruction(s)  residue {counts}")
        if result["error"]:
            print("  " + result["error"])
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("address")
    parser.add_argument("object", type=Path)
    parser.add_argument("mangled")
    parser.add_argument("length", type=int)
    parser.add_argument("-v", "--verbose", action="store_true")
    arguments = parser.parse_args()
    result = screen(int(arguments.address, 16), arguments.object,
                    arguments.mangled, arguments.length, verbose=True)
    if arguments.verbose:
        for step in result["steps"]:
            if step["kind"] or not step["same"]:
                print("  %#06x %-9s ours=%s retail=%s"
                      % (step["ours"], step["kind"] or "regs",
                         step["ours_registers"], step["retail_registers"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
