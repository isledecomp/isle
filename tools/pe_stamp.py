#!/usr/bin/env python3
"""Restore the original build timestamps in a linked PE.

Goal 2 is a byte-identical binary. Two classes of bytes in a PE are recorded by
the linker from the wall clock at link time and are not derivable from source:

  * the COFF header's ``TimeDateStamp``
  * every ``TimeDateStamp`` field in the ``.rsrc`` resource directory tree

MSVC 4.20's linker offers no switch to set either, so they are restored here as
a post-link step. The values are copied from the original binary rather than
hardcoded, so this stays correct per-target (ISLE/LEGO1/CONFIG each differ) and
carries no magic numbers.

For ISLE.EXE this closes 4 header bytes + 72 ``.rsrc`` bytes.

Usage:  pe_stamp.py <target.exe> <original.exe>
        pe_stamp.py <target.exe> <original.exe> --check
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
        out.append((name, vaddr, rsize, raw))
    return pe, out


def rsrc_stamp_offsets(buf):
    """File offsets of every TimeDateStamp in the resource directory tree.

    Walks IMAGE_RESOURCE_DIRECTORY nodes depth-first. Each node is 16 bytes
    (Characteristics, TimeDateStamp, versions, counts) followed by its entries;
    an entry whose high bit is set points at a subdirectory.
    """
    _, secs = sections(buf)
    rsrc = next((s for s in secs if s[0] == '.rsrc'), None)
    if rsrc is None:
        return []
    _, base_rva, size, base_raw = rsrc
    found, seen = [], set()

    def walk(rel):
        if rel in seen or rel + 16 > size:
            return
        seen.add(rel)
        off = base_raw + rel
        found.append(off + 4)
        nnamed, nid = struct.unpack_from('<HH', buf, off + 12)
        for i in range(nnamed + nid):
            eo = off + 16 + i * 8
            if eo + 8 > base_raw + size:
                return
            _, child = struct.unpack_from('<II', buf, eo)
            if child & 0x80000000:
                walk(child & 0x7fffffff)

    walk(0)
    return found


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    target, original = sys.argv[1], sys.argv[2]
    check = '--check' in sys.argv

    buf = bytearray(open(target, 'rb').read())
    orig = open(original, 'rb').read()

    pe_t, _ = sections(buf)
    pe_o, _ = sections(orig)
    want = struct.unpack_from('<I', orig, pe_o + 8)[0]

    offs_t = rsrc_stamp_offsets(buf)
    offs_o = rsrc_stamp_offsets(orig)
    if len(offs_t) != len(offs_o):
        print('pe_stamp: resource trees differ (%d vs %d nodes) - refusing'
              % (len(offs_t), len(offs_o)))
        return 1

    changed = 0
    if struct.unpack_from('<I', buf, pe_t + 8)[0] != want:
        struct.pack_into('<I', buf, pe_t + 8, want)
        changed += 4
    for a, b in zip(offs_t, offs_o):
        v = struct.unpack_from('<I', orig, b)[0]
        if struct.unpack_from('<I', buf, a)[0] != v:
            struct.pack_into('<I', buf, a, v)
            changed += 4

    if check:
        print('pe_stamp: %s would change %d bytes (%d resource nodes)'
              % (target, changed, len(offs_t)))
        return 0
    if changed:
        open(target, 'wb').write(buf)
    print('pe_stamp: %s <- %s, %d bytes restored across %d resource nodes'
          % (target, original, changed, len(offs_t)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
