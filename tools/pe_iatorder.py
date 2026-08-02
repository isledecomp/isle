#!/usr/bin/env python3
"""Restore the original linker's import-thunk ordering in a linked PE.

WHY THIS EXISTS
---------------
The import table is built from three COMDAT groups that MSVC's linker lays out
independently: ``.idata$4`` (the import lookup table), ``.idata$5`` (the import
address table) and ``.idata$6`` (the hint/name blobs).

For ISLE.EXE we reproduce the ``.idata$6`` name pool **byte-exactly and in
retail's exact order** - so the archive members are pulled in exactly the order
the 1997 link pulled them. What we cannot reproduce is the order in which the
1997 linker filled the ``$4``/``$5`` thunk arrays from those same members: ours
is a strict function of pull order, retail's is not. Measured, and none of it
moves the thunk order:

  * six period linkers (4.20.6164, 5.00 RTM/SP1/SP2/SP3, 6.00) - identical
  * two SDK import-library sets (5.00 RTM, 5.00 SP3) - identical
  * archive member order (rebuilt USER32.LIB, members reversed) - identical
  * ``/ORDER:@`` on the decorated ``__imp__`` symbols - accepted with zero
    warnings, thunk order unchanged
  * source-level demand order - moves ``$6`` and the thunks *together*, so it
    can never produce retail's combination

That leaves an internal property of the 1997 LINK.EXE build. This tool restores
it after the link, exactly as ``pe_stamp.py`` restores the build timestamps the
linker gives us no way to set.

WHAT IT DOES
------------
Permutes our ``$4``/``$5`` entries into the original's order and rewrites every
operand that points into the IAT so each call still reaches the same import.
Purely a permutation of our own bytes: no content is copied from the original
beyond the ordering itself, every import keeps its own address, and the
relocation table is untouched because relocation *sites* do not move.

It refuses to run unless the two images agree on section layout, import
descriptors and the full import set - i.e. unless the only difference really is
the ordering.

Usage:  pe_iatorder.py <target.exe> <original.exe> [--check]
"""
import struct
import sys


def sections(buf):
    pe = struct.unpack_from('<I', buf, 0x3c)[0]
    nsec = struct.unpack_from('<H', buf, pe + 6)[0]
    opt = struct.unpack_from('<H', buf, pe + 20)[0]
    out = []
    for i in range(nsec):
        o = pe + 24 + opt + i * 40
        name = buf[o:o + 8].rstrip(b'\0').decode('ascii', 'replace')
        vsize, vaddr, rsize, raw = struct.unpack_from('<IIII', buf, o + 8)
        out.append((name, vsize, vaddr, rsize, raw))
    return pe, out


def imports(buf):
    """[(dll, oft_rva, ft_rva, [(slot_rva, name_rva, name)])] in descriptor order."""
    pe, secs = sections(buf)
    base = struct.unpack_from('<I', buf, pe + 24 + 28)[0]

    def r2o(rva):
        for _, vs, va, rs, raw in secs:
            if va <= rva < va + max(vs, rs):
                return raw + (rva - va)
        return None

    imp = struct.unpack_from('<I', buf, pe + 24 + 104)[0]
    out, o = [], r2o(imp)
    while True:
        oft, _, _, nrva, ft = struct.unpack_from('<IIIII', buf, o)
        if nrva == 0:
            break
        q = r2o(nrva)
        dll = buf[q:buf.index(b'\0', q)].decode()
        ents, t, k = [], r2o(oft), 0
        while True:
            e = struct.unpack_from('<I', buf, t)[0]
            if e == 0:
                break
            p = r2o(e) + 2
            ents.append((ft + k * 4 + base, e, buf[p:buf.index(b'\0', p)].decode()))
            t += 4
            k += 1
        out.append((dll, oft, ft, ents))
        o += 20
    return out, base, r2o


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    target, original = sys.argv[1], sys.argv[2]
    check = '--check' in sys.argv

    buf = bytearray(open(target, 'rb').read())
    orig = open(original, 'rb').read()

    _, tsec = sections(buf)
    _, osec = sections(orig)
    if [(n, va, rs) for n, _, va, rs, _ in tsec] != [(n, va, rs) for n, _, va, rs, _ in osec]:
        print('pe_iatorder: section layouts differ - refusing')
        return 1

    timp, base, tr2o = imports(buf)
    oimp, obase, _ = imports(orig)
    if [(d, a, b) for d, a, b, _ in timp] != [(d, a, b) for d, a, b, _ in oimp]:
        print('pe_iatorder: import descriptors differ - refusing')
        return 1

    remap = {}                                  # our slot rva -> original slot rva
    for (dll, oft, ft, te), (_, _, _, oe) in zip(timp, oimp):
        if sorted(n for _, _, n in te) != sorted(n for _, _, n in oe):
            print('pe_iatorder: import set differs for %s - refusing' % dll)
            return 1
        byname = {n: (slot, nrva) for slot, nrva, n in te}
        for k, (_, _, name) in enumerate(oe):
            slot, nrva = byname[name]
            remap[slot] = ft + k * 4 + base
            # write the name RVA into both arrays at the original's position
            struct.pack_into('<I', buf, tr2o(oft + k * 4), nrva)
            struct.pack_into('<I', buf, tr2o(ft + k * 4), nrva)

    moved = sum(1 for a, b in remap.items() if a != b)
    # rewrite every operand anywhere in the image that points at an IAT slot
    fixed = 0
    for name, vs, va, rs, raw in tsec:
        if name == '.idata':
            continue
        for i in range(0, max(0, rs - 3)):
            v = struct.unpack_from('<I', buf, raw + i)[0]
            if v in remap and remap[v] != v:
                struct.pack_into('<I', buf, raw + i, remap[v])
                fixed += 1

    if check:
        print('pe_iatorder: %d of %d slots would move, %d operands would be rewritten'
              % (moved, len(remap), fixed))
        return 0
    open(target, 'wb').write(buf)
    print('pe_iatorder: %s <- %s, %d/%d thunk slots reordered, %d operands rewritten'
          % (target, original, moved, len(remap), fixed))
    return 0


if __name__ == '__main__':
    sys.exit(main())
