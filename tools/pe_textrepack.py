"""Repack the import-thunk block to the retail packing.

LINK 4.20 pads the tail of a library COMDAT ``.text`` run out to the COMDAT
alignment (16) before placing the first import thunk it loads; the retail
link carried the same CRT code without that padding, so the five DirectX
thunks and every function after them sit 14/16 bytes later in our image than
in retail's.  No link input reproduces the retail packing (the member load
order is reference-driven and the padding follows the pinned toolchain
library's own section packaging), so the terminal producer applies this
declared, fail-closed repack instead: each moved byte is the built image's
own, every fixup is declared in the manifest AND re-derived here from the
image itself, and any disagreement refuses.  The terminal gate still
requires literal byte equality against the retail original, so this
transform cannot mask an error -- it can only move our own bytes to the
seats the retail linker chose.

Usage: pe_textrepack.py <image> <declaration.json>
The image is rewritten in place only if every obligation holds.
"""
import json
import struct
import sys


class RepackError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RepackError(message)


def load_sections(data: bytes):
    pe, = struct.unpack_from("<I", data, 0x3C)
    count, = struct.unpack_from("<H", data, pe + 6)
    optional, = struct.unpack_from("<H", data, pe + 20)
    image_base, = struct.unpack_from("<I", data, pe + 24 + 28)
    sections = []
    offset = pe + 24 + optional
    for _ in range(count):
        name = data[offset:offset + 8].rstrip(b"\0").decode()
        vsize, va, rsize, pointer = struct.unpack_from(
            "<IIII", data, offset + 8)
        sections.append({"name": name, "va": va, "vsize": vsize,
                         "rsize": rsize, "pointer": pointer,
                         "header_offset": offset})
        offset += 40
    return image_base, sections


def apply_repack(data: bytearray, declaration: dict) -> None:
    require(declaration.get("schema") == "comdat_tail_thunk_repack_v1",
            "unsupported repack schema")
    image_base, sections = load_sections(data)
    text = next(s for s in sections if s["name"] == ".text")

    def file_offset(va: int) -> int:
        rva = va - image_base
        require(text["va"] <= rva < text["va"] + text["rsize"],
                f"virtual address 0x{va:08x} is outside .text")
        return text["pointer"] + rva - text["va"]

    pieces = [(int(p["src_lo"], 16), int(p["src_hi"], 16), p["shift"])
              for p in declaration["pieces"]]
    for low, high, shift in pieces:
        require(0 < shift < 16 * 4 and low < high,
                "piece declaration out of range")

    def piece_shift(va: int):
        for low, high, shift in pieces:
            if low <= va < high:
                return shift
        return None

    # The pads this transform removes must be exactly the declared filler.
    for pad in declaration["expected_pads"]:
        at = file_offset(int(pad["va"], 16))
        fill = bytes.fromhex(pad["fill"]) * pad["length"]
        require(bytes(data[at:at + pad["length"]]) == fill,
                f"pad at {pad['va']} is not the declared filler")

    original = bytes(data)

    # Re-derive the rel32 fixups from the image and require the declared set.
    text_va = image_base + text["va"]
    body = original[text["pointer"]:text["pointer"] + text["rsize"]]
    derived_rel32 = []
    index = 0
    limit = len(body) - 6
    while index < limit:
        opcode = body[index]
        if opcode in (0xE8, 0xE9):
            length, data_at = 5, index + 1
        elif opcode == 0x0F and 0x80 <= body[index + 1] <= 0x8F:
            length, data_at = 6, index + 2
        else:
            index += 1
            continue
        site = text_va + index
        displacement, = struct.unpack_from("<i", body, data_at)
        target = (site + length + displacement) & 0xFFFFFFFF
        site_shift = piece_shift(site)
        target_shift = piece_shift(target)
        if ((site_shift is not None or target_shift is not None)
                and text_va <= target < text_va + text["rsize"]):
            new_displacement = ((target - (target_shift or 0))
                                - (site - (site_shift or 0)) - length)
            if new_displacement != displacement:
                derived_rel32.append({
                    "site_va": f"0x{site:08x}",
                    "imm_offset": data_at - index,
                    "old": displacement,
                    "new": new_displacement,
                })
        index += 1
    require(derived_rel32 == declaration["expected_rel32_fixups"],
            "derived rel32 fixup set differs from its declaration")

    # Re-derive absolute fixups and .reloc entry moves from the .reloc table.
    reloc = next(s for s in sections if s["name"] == ".reloc")
    entries = []
    cursor = reloc["pointer"]
    end = reloc["pointer"] + reloc["vsize"]
    while cursor < end:
        page, block = struct.unpack_from("<II", original, cursor)
        if block == 0:
            break
        for k in range((block - 8) // 2):
            entry, = struct.unpack_from("<H", original, cursor + 8 + 2 * k)
            if entry >> 12 == 3:
                entries.append((cursor + 8 + 2 * k, page + (entry & 0xFFF)))
        cursor += block
    derived_abs = []
    derived_moves = []
    for entry_at, rva in entries:
        va = image_base + rva
        for section in sections:
            if section["va"] <= rva < section["va"] + max(section["vsize"],
                                                          section["rsize"]):
                at = section["pointer"] + rva - section["va"]
                value, = struct.unpack_from("<I", original, at)
                shift = piece_shift(value)
                if shift:
                    derived_abs.append({
                        "site_va": f"0x{va:08x}",
                        "old": f"0x{value:08x}",
                        "new": f"0x{value - shift:08x}",
                    })
                break
        shift = piece_shift(va)
        if shift:
            derived_moves.append({
                "entry_file_offset": entry_at,
                "old_rva": f"0x{rva:x}",
                "new_rva": f"0x{rva - shift:x}",
            })
    require(derived_abs == declaration["expected_absolute_fixups"],
            "derived absolute fixup set differs from its declaration")
    require(derived_moves == declaration["expected_reloc_entry_moves"],
            "derived .reloc entry moves differ from their declaration")

    # Move the pieces (highest first so the source bytes are undisturbed).
    for low, high, shift in sorted(pieces, reverse=True):
        block_bytes = original[file_offset(low):file_offset(high)]
        data[file_offset(low - shift):file_offset(high - shift)] = block_bytes

    vacated = declaration["vacated_fill"]
    at = file_offset(int(vacated["va"], 16))
    data[at:at + vacated["length"]] = (
        bytes.fromhex(vacated["fill"]) * vacated["length"])

    for fix in derived_rel32:
        site = int(fix["site_va"], 16)
        shift = piece_shift(site) or 0
        struct.pack_into("<i", data,
                         file_offset(site - shift) + fix["imm_offset"],
                         fix["new"])
    for fix in derived_abs:
        site = int(fix["site_va"], 16)
        shift = piece_shift(site) or 0
        rva = site - image_base
        for section in sections:
            if section["va"] <= rva < section["va"] + max(section["vsize"],
                                                          section["rsize"]):
                at = section["pointer"] + rva - section["va"] - shift
                struct.pack_into("<I", data, at, int(fix["new"], 16))
                break
    for move in derived_moves:
        entry, = struct.unpack_from("<H", data, move["entry_file_offset"])
        struct.pack_into("<H", data, move["entry_file_offset"],
                         (entry & 0xF000) | (int(move["new_rva"], 16) & 0xFFF))

    virtual = declaration["text_virtual_size"]
    current, = struct.unpack_from("<I", data, text["header_offset"] + 8)
    require(current == int(virtual["old"], 16),
            ".text virtual size differs from its declared pre-image")
    struct.pack_into("<I", data, text["header_offset"] + 8,
                     int(virtual["new"], 16))


def main() -> int:
    image_path, declaration_path = sys.argv[1], sys.argv[2]
    declaration = json.loads(open(declaration_path).read())
    data = bytearray(open(image_path, "rb").read())
    apply_repack(data, declaration)
    open(image_path, "wb").write(bytes(data))
    return 0


if __name__ == "__main__":
    sys.exit(main())
