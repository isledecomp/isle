#!/usr/bin/env python3
"""Repack one pre-link object's constant pool to the retail emission order.

MSVC 4.2 numbers a translation unit's ``$T`` pool literals at CODEGEN, in
the order the bodies that reference them are emitted, and lays them out in
that number order with each literal aligned to its own width.  Our
``viewmanager.cpp`` emits the same thirteen literals as retail's object but
in a different order, and that order costs three alignment pads where retail
paid one -- eight bytes of ``.rdata`` we cannot shed from the source (the
only source shape that reproduces the retail order needs a mid-file
``#include`` between two function definitions, which changes an unrelated
object's codegen).

THIS TRANSFORM IS A DECLARED SYNTHETIC CONSTRUCT.  It stands in for a source
structure that was measured unrecoverable; it is not a recovered 1997 fact
and must never be read as one.  What keeps it honest is that it invents no
data: every byte it writes is a byte the object already held, the fixed
``$S`` prefix is required to stay exactly where the compiler put it, the
pre-image is pinned by digest, the permutation is re-derived against the
object's own symbol table and relocations, and the post-image digest is
required of the result.  The terminal gate still demands literal byte
equality against the retail original, so this can only re-seat our own pool,
never mask a difference.

Usage: pe_rdatarepack.py <object.obj> <declaration.json> [--check]
The object is rewritten in place only if every obligation holds; ``--check``
verifies without writing.
"""
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import byte_identity  # noqa: E402


COFF_RELOCATION_SIZE = 10
COFF_LINE_NUMBER_SIZE = 6
COFF_SYMBOL_SIZE = 18
COFF_REL_I386_DIR32 = 0x0006
COFF_SYM_CLASS_STATIC = 3


class RepackError(Exception):
    """The object, the declaration, or the result failed an obligation."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RepackError(message)


def validated(declaration: object, pool: bytes | None = None) -> dict:
    """Run the manifest validator, restating its refusal as ours."""
    try:
        return byte_identity.validate_rdata_pool_repack_declaration(
            declaration, "rdata_pool_repack", pool_bytes=pool)
    except byte_identity.ByteIdentityError as error:
        raise RepackError(str(error)) from error


def pool_section(coff: "byte_identity.CoffObject", declaration: dict) -> dict:
    """Locate the one non-COMDAT pool section the declaration names."""
    declared = declaration["section"]
    candidates = [
        section for section in coff.sections
        if section["name"] == declared["name"]
        and not section["characteristics"] & byte_identity.COFF_SCN_LNK_COMDAT
    ]
    require(
        len(candidates) == 1,
        f"object carries {len(candidates)} non-COMDAT {declared['name']} "
        "sections; the repack is declared for exactly one",
    )
    section = candidates[0]
    require(
        section["number"] == declared["index"],
        f"the non-COMDAT {declared['name']} pool is section "
        f"{section['number']}, not the declared {declared['index']}",
    )
    require(
        section["characteristics"] == int(declared["characteristics"], 16),
        "pool section characteristics are "
        f"0x{section['characteristics']:08x}, not the declared "
        f"{declared['characteristics']}",
    )
    require(
        section["relocation_count"] == declared["relocation_count"]
        and section["line_count"] == declared["line_number_count"],
        "pool section carries relocations or line numbers its declaration "
        "does not admit",
    )
    require(section["raw_offset"] > 0 and section["raw_size"] > 0,
            "pool section has no raw data in the object")
    return section


def section_symbol(coff, section: dict) -> tuple[int, int]:
    """Return the pool's section-defining symbol and its aux record offset."""
    defining = [
        symbol for symbol in coff.symbols.values()
        if symbol["section"] == section["number"] and symbol["aux_count"]
    ]
    require(
        len(defining) == 1
        and defining[0]["name"] == section["name"]
        and defining[0]["value"] == 0
        and defining[0]["storage"] == COFF_SYM_CLASS_STATIC
        and defining[0]["aux_count"] == 1,
        "pool section does not have exactly one well-formed section symbol",
    )
    index = defining[0]["index"]
    aux_at = coff.symbol_offset + (index + 1) * COFF_SYMBOL_SIZE
    length, = struct.unpack_from("<I", coff.data, aux_at)
    require(
        length == section["raw_size"],
        f"pool section aux record declares {length} bytes, but the section "
        f"header declares {section['raw_size']}",
    )
    return index, aux_at


def pool_symbols(coff, section: dict, defining_index: int) -> dict:
    """Map every pool symbol other than the section symbol to its record."""
    symbols = {}
    for symbol in coff.symbols.values():
        if symbol["section"] != section["number"]:
            continue
        if symbol["index"] == defining_index:
            continue
        require(
            symbol["aux_count"] == 0,
            f"pool symbol {symbol['name']} carries auxiliary records",
        )
        require(
            symbol["name"] not in symbols,
            f"pool symbol {symbol['name']} is defined twice",
        )
        symbols[symbol["name"]] = symbol
    return symbols


def symbol_references(coff, moved: set[str]) -> dict:
    """Count, and vet, every relocation that names a literal we move.

    A moved literal may only be referenced the way MSVC 4.2 references a pool
    constant: an ``IMAGE_REL_I386_DIR32`` against the literal's own symbol
    with a zero addend in the referring section's data.  Anything else -- a
    non-zero addend, a section-relative form -- carries a byte offset into
    the pool that this permutation would silently invalidate, so it refuses.
    """
    counts = {name: 0 for name in moved}
    for section in coff.sections:
        count = section["relocation_count"]
        if not count:
            continue
        require(count < 0xFFFF,
                f"section {section['number']} uses the COFF relocation "
                "overflow convention, which is unsupported here")
        for slot in range(count):
            at = section["relocation_offset"] + slot * COFF_RELOCATION_SIZE
            offset, symbol_index, kind = struct.unpack_from(
                "<IIH", coff.data, at)
            symbol = coff.symbols.get(symbol_index)
            require(
                symbol is not None,
                f"section {section['number']} relocation {slot} names "
                "symbol table slot "
                f"{symbol_index}, which is not a symbol record",
            )
            if symbol["name"] not in counts:
                continue
            require(
                kind == COFF_REL_I386_DIR32,
                f"relocation to {symbol['name']} at section "
                f"{section['number']}+0x{offset:x} is type 0x{kind:04x}, not "
                "DIR32: a moved pool literal may only be referenced through "
                "its own symbol",
            )
            require(
                section["raw_offset"] > 0
                and offset + 4 <= section["raw_size"],
                f"relocation to {symbol['name']} at section "
                f"{section['number']}+0x{offset:x} lies outside that "
                "section's raw data",
            )
            addend, = struct.unpack_from(
                "<I", coff.data, section["raw_offset"] + offset)
            require(
                addend == 0,
                f"relocation to {symbol['name']} at section "
                f"{section['number']}+0x{offset:x} carries addend "
                f"0x{addend:08x}: a moved pool literal may not be referenced "
                "at an offset",
            )
            counts[symbol["name"]] += 1
    return counts


def shifted(field: int, cut_start: int, cut_end: int, delta: int,
            what: str) -> int:
    """Move one file offset across the bytes the pool no longer needs."""
    if field == 0 or field <= cut_start:
        return field
    require(
        field >= cut_end,
        f"{what} points at file offset {field}, inside the pool tail this "
        f"repack removes ({cut_start}..{cut_end})",
    )
    return field - delta


def repack(data: bytes, declaration: object) -> bytes:
    """Return the object with its declared pool re-seated, or refuse."""
    declaration = validated(declaration)
    try:
        coff = byte_identity.CoffObject(data)
    except byte_identity.ByteIdentityError as error:
        raise RepackError(f"object is not a readable i386 COFF: {error}")
    section = pool_section(coff, declaration)

    pre = declaration["pre_image"]
    post = declaration["post_image"]
    require(
        section["raw_size"] == pre["size"],
        f"pool section is {section['raw_size']} bytes, not the declared "
        f"pre-image size {pre['size']}",
    )
    pool = data[section["raw_offset"]:section["raw_offset"] + pre["size"]]
    # Re-runs the whole declaration against the bytes in hand: pre-image
    # digest, fixed $S prefix, pad filler, and the post-image digest of the
    # image the permutation actually produces.
    validated(declaration, pool)
    packed = byte_identity.rdata_pool_repack_image(
        declaration, pool, "rdata_pool_repack")

    defining_index, aux_at = section_symbol(coff, section)
    present = pool_symbols(coff, section, defining_index)
    fixed = {
        static["symbol"]: static
        for static in pre["fixed_prefix"]["symbols"]
    }
    moved = {entry["symbol"]: entry for entry in declaration["permutation"]}
    require(
        set(present) == set(fixed) | set(moved),
        "the pool's symbols differ from the declaration; object has "
        f"{sorted(set(present) - (set(fixed) | set(moved)))} extra and "
        f"{sorted((set(fixed) | set(moved)) - set(present))} missing",
    )
    for name, static in fixed.items():
        require(
            present[name]["value"] == static["offset"],
            f"fixed static {name} sits at {present[name]['value']}, not the "
            f"declared {static['offset']}",
        )
    for name, entry in moved.items():
        require(
            present[name]["value"] == entry["old_offset"],
            f"pool literal {name} sits at {present[name]['value']}, not the "
            f"declared pre-image offset {entry['old_offset']}",
        )

    counts = symbol_references(coff, set(moved))
    for name, entry in moved.items():
        require(
            counts[name] == entry["references"],
            f"pool literal {name} is referenced {counts[name]} times, not "
            f"the declared {entry['references']}",
        )

    cut_start = section["raw_offset"] + post["size"]
    cut_end = section["raw_offset"] + pre["size"]
    delta = pre["size"] - post["size"]
    require(delta > 0, "the declared repack removes no pool bytes")
    updated = bytearray(
        data[:section["raw_offset"]] + packed + data[cut_end:])

    struct.pack_into("<I", updated, section["header_offset"] + 16,
                     post["size"])
    for other in coff.sections:
        header = other["header_offset"]
        if other["number"] != section["number"]:
            struct.pack_into(
                "<I", updated, header + 20,
                shifted(other["raw_offset"], cut_start, cut_end, delta,
                        f"section {other['number']} raw data"))
        struct.pack_into(
            "<I", updated, header + 24,
            shifted(other["relocation_offset"], cut_start, cut_end, delta,
                    f"section {other['number']} relocations"))
        struct.pack_into(
            "<I", updated, header + 28,
            shifted(other["line_offset"], cut_start, cut_end, delta,
                    f"section {other['number']} line numbers"))
    struct.pack_into(
        "<I", updated, 8,
        shifted(coff.symbol_offset, cut_start, cut_end, delta,
                "the symbol table"))
    struct.pack_into("<I", updated, aux_at - delta, post["size"])
    for name, entry in moved.items():
        record = (coff.symbol_offset - delta
                  + present[name]["index"] * COFF_SYMBOL_SIZE)
        struct.pack_into("<I", updated, record + 8, entry["new_offset"])

    result = bytes(updated)
    verify(coff, result, declaration, section, packed,
           {present[name]["index"]: entry["new_offset"]
            for name, entry in moved.items()},
           defining_index + 1)
    return result


def verify(coff, result: bytes, declaration: dict, section: dict,
           packed: bytes, reseated: dict, aux_index: int) -> None:
    """Prove the rewritten object differs only where it was licensed to."""
    try:
        after = byte_identity.CoffObject(result)
    except byte_identity.ByteIdentityError as error:
        raise RepackError(f"the repacked object is not well formed: {error}")
    require(
        after.section_count == coff.section_count
        and after.symbol_count == coff.symbol_count
        and after.machine == coff.machine
        and after.timestamp == coff.timestamp
        and after.characteristics == coff.characteristics,
        "the repacked object's COFF header or table sizes changed",
    )
    for before_section, after_section in zip(coff.sections, after.sections):
        target = before_section["number"] == section["number"]
        require(
            before_section["name"] == after_section["name"]
            and before_section["characteristics"]
            == after_section["characteristics"]
            and before_section["relocation_count"]
            == after_section["relocation_count"]
            and before_section["line_count"] == after_section["line_count"]
            and after_section["raw_size"] == (
                declaration["post_image"]["size"] if target
                else before_section["raw_size"]),
            f"section {before_section['number']} identity changed",
        )
        for key, unit in (("raw", 1),
                          ("relocation", COFF_RELOCATION_SIZE),
                          ("line", COFF_LINE_NUMBER_SIZE)):
            if key == "raw":
                size, offset_key = before_section["raw_size"], "raw_offset"
            elif key == "relocation":
                size = before_section["relocation_count"] * unit
                offset_key = "relocation_offset"
            else:
                size = before_section["line_count"] * unit
                offset_key = "line_offset"
            if not size or not before_section[offset_key]:
                continue
            was = coff.data[
                before_section[offset_key]:before_section[offset_key] + size]
            if target and key == "raw":
                now = result[after_section["raw_offset"]:
                             after_section["raw_offset"]
                             + after_section["raw_size"]]
                require(now == packed,
                        "the repacked pool is not the image the declaration "
                        "produces")
                continue
            now = result[
                after_section[offset_key]:after_section[offset_key] + size]
            require(
                was == now,
                f"section {before_section['number']} {key} bytes changed",
            )
    for index in range(coff.symbol_count):
        was = coff.data[coff.symbol_offset + index * COFF_SYMBOL_SIZE:
                        coff.symbol_offset + (index + 1) * COFF_SYMBOL_SIZE]
        now = result[after.symbol_offset + index * COFF_SYMBOL_SIZE:
                     after.symbol_offset + (index + 1) * COFF_SYMBOL_SIZE]
        if index in reseated:
            require(
                now[:8] == was[:8] and now[12:] == was[12:]
                and struct.unpack_from("<I", now, 8)[0] == reseated[index],
                f"symbol record {index} was not re-seated as declared",
            )
        elif index == aux_index:
            require(
                now[4:] == was[4:]
                and struct.unpack_from("<I", now, 0)[0]
                == declaration["post_image"]["size"],
                "the pool section's aux record was not resized as declared",
            )
        else:
            require(was == now, f"symbol record {index} changed")
    require(
        coff.data[coff.string_offset:] == result[after.string_offset:],
        "the string table changed",
    )
    require(
        len(result) == len(coff.data) - (
            declaration["pre_image"]["size"]
            - declaration["post_image"]["size"]),
        "the repacked object is not exactly the pool tail shorter",
    )


def main(argv: list[str]) -> int:
    if not 3 <= len(argv) <= 4 or (len(argv) == 4 and argv[3] != "--check"):
        print("usage: pe_rdatarepack.py <object.obj> <declaration.json> "
              "[--check]", file=sys.stderr)
        return 2
    object_path, declaration_path = Path(argv[1]), Path(argv[2])
    check_only = len(argv) == 4
    try:
        declaration = byte_identity.strict_json_loads(
            declaration_path.read_text())
        data = object_path.read_bytes()
        result = repack(data, declaration)
    except (RepackError, byte_identity.ByteIdentityError, OSError) as error:
        print(f"pe_rdatarepack: refusing: {error}", file=sys.stderr)
        return 1
    if not check_only:
        object_path.write_bytes(result)
    print(
        "pe_rdatarepack: %s %s pool %d -> %d bytes, %d literals re-seated"
        % ("checked" if check_only else "repacked", object_path.name,
           len(data) - len(result) + declaration["post_image"]["size"],
           declaration["post_image"]["size"],
           len(declaration["permutation"])))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
