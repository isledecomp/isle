#!/usr/bin/env python3
"""Synthesize 3rdparty/smacker/smackw32.lib for the isle decomp.

Carves the original Win32 Smacker (mid-1997 RAD static lib) contribution out of
legobin/LEGO1.DLL and rebuilds it as a single-member COFF archive whose members
link back to the exact original bytes.

Forensics (verified in this script):
  .text contribution: LEGO1 VA [0x100cd300, 0x100d0723), 0x3423 bytes.
      0x100cd300..0x100cd782 = internal helpers (bit reader, tree decoders)
      0x100cd782..           = _SmackGetSizeTables ... _SmackRemapTables
      (0x100d0723..0x100d0730 is linker int3 padding, not part of the obj;
       0x100d0730 is MxRAMStreamProvider game code.)
  .data contribution: LEGO1 VA [0x10102660, 0x10102850), 0x1f0 bytes.
      zeros (decoder state) + the size-deltas table {1..0x3b,0x80..0x800}.
  All 677 base-reloc sites in the .text range target either the .text range
  itself (33, jump tables) or the .data range (644). There are ZERO references
  to anything outside the contribution (no CRT, no imports) and zero
  E8/E9 rel32 branches leaving the range -> the member needs no externals.
  BETA10.DLL contains the identical contribution at +0x92400 (.text) /
  +0x102450 (.data), byte-identical modulo relocated dwords.

The synthesized member:
  .text  align 16, chars 0x60500020, 677 IMAGE_REL_I386_DIR32 relocs against
         the .text/.data section symbols, addend stored in place
         (section-relative offset), original bytes otherwise.
  .data  align 16, chars 0xC0500040, no relocs, original bytes.
  8 external symbols (class 2, type 0x20) at their section offsets.

Usage:  python3 tools/gen_smacker_lib.py [--check]
Writes: <repo>/3rdparty/smacker/smackw32.lib
"""

import argparse
import os
import struct
import sys
from collections import Counter

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DLL = REPO + '/legobin/LEGO1.DLL'
BETA = REPO + '/legobin/BETA10.DLL'
OUT = REPO + '/3rdparty/smacker/smackw32.lib'

TEXT_LO, TEXT_HI = 0x100cd300, 0x100d0723
DATA_LO, DATA_HI = 0x10102660, 0x10102850

# Annotated entry points (LEGO1/library_smack.h) -> LEGO1 VA
FUNCS = [
    ('_SmackGetSizeTables',   0x100cd782),
    ('_SmackDoTables',        0x100cd7e8),
    ('_SmackDoFrameToBuffer', 0x100cda83),
    ('_SmackDoFrameToVESA',   0x100cea58),
    ('_SmackDoPCM',           0x100cfd90),
    ('_SmackGetSizeDeltas',   0x100d052c),
    ('_SmackGetRect',         0x100d0543),
    ('_SmackRemapTables',     0x100d0654),
]

BETA_TEXT_DELTA = 0x1015fb82 - 0x100cd782   # BETA10 layout shift for .text
BETA_DATA_DELTA = 0x10204b30 - 0x10102660   # BETA10 layout shift for .data

TIMESTAMP = 865123200  # 1997-06-01 00:00:00 UTC, era-appropriate & reproducible

IMAGE_REL_I386_DIR32 = 6


# --------------------------------------------------------------------------
# PE reading (minimal, no external deps)
# --------------------------------------------------------------------------
class Pe:
    def __init__(self, path):
        self.raw = open(path, 'rb').read()
        pe_off = struct.unpack_from('<I', self.raw, 0x3c)[0]
        assert self.raw[pe_off:pe_off + 4] == b'PE\0\0'
        nsec, = struct.unpack_from('<H', self.raw, pe_off + 6)
        optsz, = struct.unpack_from('<H', self.raw, pe_off + 20)
        self.base, = struct.unpack_from('<I', self.raw, pe_off + 24 + 28)
        self.secs = []
        sec0 = pe_off + 24 + optsz
        for i in range(nsec):
            s = self.raw[sec0 + 40 * i: sec0 + 40 * i + 40]
            name = s[:8].rstrip(b'\0').decode()
            vsz, va, rawsz, rawptr = struct.unpack_from('<IIII', s, 8)
            self.secs.append((name, va, vsz, rawsz, rawptr))
        dd_reloc = struct.unpack_from('<II', self.raw, pe_off + 24 + 96 + 5 * 8)

        self.reloc_rva, self.reloc_size = dd_reloc

    def va2off(self, va):
        rva = va - self.base
        for name, sva, vsz, rawsz, rawptr in self.secs:
            if sva <= rva < sva + max(vsz, rawsz):
                off = rva - sva
                return rawptr + off if off < rawsz else None
        return None

    def read(self, va, n):
        out = bytearray()
        for k in range(n):
            off = self.va2off(va + k)
            out.append(self.raw[off] if off is not None else 0)
        return bytes(out)

    def rd32(self, va):
        return struct.unpack('<I', self.read(va, 4))[0]

    def base_relocs(self):
        """All HIGHLOW base-reloc site VAs."""
        out = []
        off = self.va2off(self.base + self.reloc_rva)
        end = off + self.reloc_size
        while off < end:
            page_rva, blksz = struct.unpack_from('<II', self.raw, off)
            if blksz < 8:
                break
            for k in range(8, blksz, 2):
                e, = struct.unpack_from('<H', self.raw, off + k)
                if e >> 12 == 3:  # HIGHLOW
                    out.append(self.base + page_rva + (e & 0xfff))
            off += blksz
        return sorted(out)


# --------------------------------------------------------------------------
# Carve + classify
# --------------------------------------------------------------------------
def carve(pe):
    text = bytearray(pe.read(TEXT_LO, TEXT_HI - TEXT_LO))
    data = bytes(pe.read(DATA_LO, DATA_HI - DATA_LO))
    sites = pe.base_relocs()

    in_text = [s for s in sites if TEXT_LO <= s < TEXT_HI]
    in_data = [s for s in sites if DATA_LO <= s < DATA_HI]
    assert not in_data, 'unexpected relocs inside the data block'
    assert all(s + 4 <= TEXT_HI for s in in_text), 'reloc dword crosses range end'

    relocs = []          # (section_offset, target_section: 1|2, addend)
    stats = Counter()
    for s in in_text:
        t = struct.unpack_from('<I', text, s - TEXT_LO)[0]
        if TEXT_LO <= t < TEXT_HI:
            sec, addend = 1, t - TEXT_LO
            stats['text->text'] += 1
        elif DATA_LO <= t < DATA_HI:
            sec, addend = 2, t - DATA_LO
            stats['text->data'] += 1
        else:
            raise AssertionError('unclassified reloc target %#x at site %#x'
                                 % (t, s))
        struct.pack_into('<I', text, s - TEXT_LO, addend)  # in-place addend
        relocs.append((s - TEXT_LO, sec, addend))

    # closure: nothing else in the image may point into the contribution
    leaks = []
    for s in sites:
        if TEXT_LO <= s < TEXT_HI or DATA_LO <= s < DATA_HI:
            continue
        t = pe.rd32(s)
        if TEXT_LO <= t < TEXT_HI or DATA_LO <= t < DATA_HI:
            leaks.append((s, t))
    assert not leaks, 'external reloc sites target the contribution: %s' % (
        [(hex(a), hex(b)) for a, b in leaks])

    return bytes(text), data, relocs, stats


def beta10_crosscheck(pe, sites):
    """retail vs BETA10: contribution must be byte-identical mod relocs."""
    try:
        beta = Pe(BETA)
    except (OSError, AssertionError):
        return 'BETA10.DLL not available - skipped'
    blo = TEXT_LO + BETA_TEXT_DELTA
    bsites = set(beta.base_relocs())
    mask = set()
    for s in sites:
        if TEXT_LO <= s < TEXT_HI:
            assert (s + BETA_TEXT_DELTA) in bsites, \
                'reloc site mismatch vs BETA10 at %#x' % s
            mask.update(range(s - TEXT_LO, s - TEXT_LO + 4))
    rbuf = pe.read(TEXT_LO, TEXT_HI - TEXT_LO)
    bbuf = beta.read(blo, TEXT_HI - TEXT_LO)
    bad = [k for k in range(len(rbuf)) if k not in mask and rbuf[k] != bbuf[k]]
    assert not bad, 'BETA10 text mismatch at offsets %s' % bad[:8]
    rdat = pe.read(DATA_LO, DATA_HI - DATA_LO)
    bdat = beta.read(DATA_LO + BETA_DATA_DELTA, DATA_HI - DATA_LO)
    assert rdat == bdat, 'BETA10 data block differs'
    return ('text byte-identical mod relocs at %#x, data identical at %#x'
            % (blo, DATA_LO + BETA_DATA_DELTA))


# --------------------------------------------------------------------------
# COFF object
# --------------------------------------------------------------------------
def build_obj(text, data, relocs):
    IMAGE_FILE_MACHINE_I386 = 0x14c
    TEXT_CHARS = 0x60500020  # CODE | ALIGN_16BYTES | EXECUTE | READ
    DATA_CHARS = 0xC0500040  # INITIALIZED_DATA | ALIGN_16BYTES | READ | WRITE

    # symbol table: .text + aux, .data + aux, 8 externals
    symtab = bytearray()
    strtab = bytearray()

    def symname(name):
        b = name.encode()
        if len(b) <= 8:
            return b.ljust(8, b'\0')
        off = 4 + len(strtab)
        strtab.extend(b + b'\0')
        return struct.pack('<II', 0, off)

    def sym(name, value, secnum, styp, cls, naux=0):
        symtab.extend(symname(name))
        symtab.extend(struct.pack('<IhHBB', value, secnum, styp, cls, naux))

    def aux_secdef(length, nrel):
        symtab.extend(struct.pack('<IHHIHB3x', length, nrel, 0, 0, 0, 0))

    SYM_TEXT = 0
    sym('.text', 0, 1, 0, 3, 1)          # class 3 = static (section)
    aux_secdef(len(text), len(relocs))
    SYM_DATA = 2
    sym('.data', 0, 2, 0, 3, 1)
    aux_secdef(len(data), 0)
    for name, va in FUNCS:
        sym(name, va - TEXT_LO, 1, 0x20, 2)   # type 0x20 function, class 2 ext
    nsyms = 4 + len(FUNCS)

    # relocation records against the two section symbols
    relbuf = bytearray()
    for off, sec, _ in relocs:
        symidx = SYM_TEXT if sec == 1 else SYM_DATA
        relbuf.extend(struct.pack('<IIH', off, symidx, IMAGE_REL_I386_DIR32))

    hdr_sz = 20 + 2 * 40
    text_ptr = hdr_sz
    data_ptr = text_ptr + len(text)
    rel_ptr = data_ptr + len(data)
    sym_ptr = rel_ptr + len(relbuf)

    hdr = struct.pack('<HHIIIHH', IMAGE_FILE_MACHINE_I386, 2, TIMESTAMP,
                      sym_ptr, nsyms, 0, 0)
    s1 = struct.pack('<8sIIIIIIHHI', b'.text', 0, 0, len(text), text_ptr,
                     rel_ptr, 0, len(relocs), 0, TEXT_CHARS)
    s2 = struct.pack('<8sIIIIIIHHI', b'.data', 0, 0, len(data), data_ptr,
                     0, 0, 0, 0, DATA_CHARS)

    obj = bytearray()
    obj += hdr + s1 + s2 + text + data + relbuf + symtab
    obj += struct.pack('<I', 4 + len(strtab)) + strtab
    return bytes(obj)


# --------------------------------------------------------------------------
# Archive (.lib)
# --------------------------------------------------------------------------
def build_lib(obj, member_name='smackw32.obj'):
    pubs = [name for name, _ in FUNCS]

    def member_hdr(name, size):
        h = '%-16s%-12d%-6s%-6s%-8s%-10d`\n' % (name, TIMESTAMP, '0', '0',
                                                '100666', size)
        return h.encode()

    # layout: !<arch> | '/' first | '/' second | '//' empty | member
    # sizes of linker members depend only on counts/names
    first_sz = 4 + 4 * len(pubs) + sum(len(p) + 1 for p in pubs)
    second_sz = 4 + 4 * 1 + 4 + 2 * len(pubs) + sum(len(p) + 1
                                                    for p in sorted(pubs))
    off = 8
    off1 = off
    off += 60 + first_sz + (first_sz & 1)
    off2 = off
    off += 60 + second_sz + (second_sz & 1)
    off3 = off
    off += 60 + 0
    member_off = off

    first = struct.pack('>I', len(pubs))
    first += b''.join(struct.pack('>I', member_off) for _ in pubs)
    first += b''.join(p.encode() + b'\0' for p in pubs)

    second = struct.pack('<I', 1) + struct.pack('<I', member_off)
    second += struct.pack('<I', len(pubs))
    order = sorted(range(len(pubs)), key=lambda i: pubs[i])
    second += b''.join(struct.pack('<H', 1) for _ in order)
    second += b''.join(pubs[i].encode() + b'\0' for i in order)
    assert len(first) == first_sz and len(second) == second_sz

    lib = bytearray(b'!<arch>\n')
    for name, payload in (('/', first), ('/', second), ('//', b'')):
        lib += member_hdr(name, len(payload)) + payload
        if len(lib) & 1:
            lib += b'\n'
    assert len(lib) == member_off
    lib += member_hdr(member_name + '/', len(obj)) + obj
    if len(lib) & 1:
        lib += b'\n'
    return bytes(lib)


# --------------------------------------------------------------------------
# Validation: parse the lib back, simulate the link, compare to LEGO1.DLL
# --------------------------------------------------------------------------
def validate(libbytes, pe):
    # -- archive sanity
    assert libbytes[:8] == b'!<arch>\n'
    off = 8
    members = []
    while off < len(libbytes) - 1:
        if off & 1:
            assert libbytes[off:off + 1] == b'\n'
            off += 1
        hdr = libbytes[off:off + 60]
        assert hdr[58:60] == b'`\n', 'bad member header at %#x' % off
        name = hdr[:16].decode().rstrip()
        size = int(hdr[48:58].decode().strip())
        members.append((name, off + 60, size))
        off += 60 + size
    names = [m[0] for m in members]
    assert names == ['/', '/', '//', 'smackw32.obj/'], names
    mo, ms = members[3][1], members[3][2]
    obj = libbytes[mo:mo + ms]

    # first linker member offsets must point at the member header
    n, = struct.unpack_from('>I', libbytes, members[0][1])
    offs = struct.unpack_from('>%dI' % n, libbytes, members[0][1] + 4)
    assert all(o == mo - 60 for o in offs)

    # -- COFF sanity
    machine, nsec, ts, symptr, nsyms, optsz, chars = struct.unpack_from(
        '<HHIIIHH', obj, 0)
    assert (machine, nsec, optsz, chars) == (0x14c, 2, 0, 0)
    sects = []
    for i in range(nsec):
        nm = obj[20 + 40 * i:28 + 40 * i].rstrip(b'\0').decode()
        vsz, va, rawsz, rawptr, relptr, lnptr, nrel, nln, ch = \
            struct.unpack_from('<IIIIIIHHI', obj, 28 + 40 * i)
        sects.append((nm, rawsz, rawptr, relptr, nrel, ch))
    assert sects[0][0] == '.text' and sects[1][0] == '.data'

    strtab_off = symptr + 18 * nsyms
    def sname(i):
        rec = obj[symptr + 18 * i: symptr + 18 * i + 18]
        if rec[:4] == b'\0\0\0\0':
            o, = struct.unpack_from('<I', rec, 4)
            end = obj.index(b'\0', strtab_off + o)
            return obj[strtab_off + o:end].decode()
        return rec[:8].rstrip(b'\0').decode()

    syms = {}
    i = 0
    while i < nsyms:
        rec = obj[symptr + 18 * i: symptr + 18 * i + 18]
        val, secn, typ, cls, naux = struct.unpack_from('<IhHBB', rec, 8)
        syms[sname(i)] = (val, secn, typ, cls)
        i += 1 + naux

    for fname, va in FUNCS:
        val, secn, typ, cls = syms[fname]
        assert (secn, typ, cls) == (1, 0x20, 2), fname
        assert val == va - TEXT_LO, fname

    # -- simulated link at the original addresses
    tname, trawsz, trawptr, trelptr, tnrel, tch = sects[0]
    dname, drawsz, drawptr, drelptr, dnrel, dch = sects[1]
    image_text = bytearray(obj[trawptr:trawptr + trawsz])
    image_data = obj[drawptr:drawptr + drawsz]
    reloc_report = Counter()
    for r in range(tnrel):
        va, symidx, rtype = struct.unpack_from('<IIH', obj, trelptr + 10 * r)
        assert rtype == IMAGE_REL_I386_DIR32
        target_sec = sname(symidx)
        addend, = struct.unpack_from('<I', image_text, va)
        base = TEXT_LO if target_sec == '.text' else DATA_LO
        struct.pack_into('<I', image_text, va, (base + addend) & 0xffffffff)
        reloc_report[target_sec] += 1

    orig_text = pe.read(TEXT_LO, TEXT_HI - TEXT_LO)
    orig_data = pe.read(DATA_LO, DATA_HI - DATA_LO)
    assert bytes(image_text) == orig_text, 'simulated .text differs'
    assert image_data == orig_data, 'simulated .data differs'

    # -- per-function byte equality table
    bounds = sorted([va for _, va in FUNCS]) + [TEXT_HI]
    rows = []
    for fname, va in FUNCS:
        end = bounds[bounds.index(va) + 1]
        soff = syms[fname][0]
        got = bytes(image_text[soff:soff + (end - va)])
        want = pe.read(va, end - va)
        rows.append((fname, va, soff, end - va, got == want))
    helpers_ok = bytes(image_text[:FUNCS[0][1] - TEXT_LO]) == \
        pe.read(TEXT_LO, FUNCS[0][1] - TEXT_LO)
    return rows, helpers_ok, reloc_report, len(obj)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="compare the regenerated archive with the checked-in library; do not write",
    )
    args = parser.parse_args()

    if not os.path.isfile(DLL):
        parser.error("missing legobin/LEGO1.DLL; place the English 1.1 retail library there")
    if args.check and not os.path.isfile(OUT):
        parser.error("missing checked-in archive: 3rdparty/smacker/smackw32.lib")

    pe = Pe(DLL)
    text, data, relocs, stats = carve(pe)
    print('carved .text %#x bytes, .data %#x bytes' % (len(text), len(data)))
    print('relocs: %d (%s)' % (len(relocs), dict(stats)))

    beta_msg = beta10_crosscheck(pe, pe.base_relocs())
    print('BETA10 cross-check:', beta_msg)

    obj = build_obj(text, data, relocs)
    lib = build_lib(obj)

    rows, helpers_ok, reloc_report, objsz = validate(lib, pe)
    print('\nsimulated link vs LEGO1.DLL: .text and .data byte-exact')
    print('reloc targets: %s' % dict(reloc_report))
    print('internal helper region [%#x,%#x): %s'
          % (TEXT_LO, FUNCS[0][1], 'MATCH' if helpers_ok else 'MISMATCH'))
    print('\n%-24s %-12s %-8s %-7s %s' % ('symbol', 'LEGO1 VA', 'offset',
                                          'size', 'bytes'))
    for fname, va, soff, size, ok in rows:
        print('%-24s 0x%08x   0x%04x   0x%04x  %s'
              % (fname, va, soff, size, 'MATCH' if ok else 'MISMATCH'))
    assert helpers_ok and all(r[-1] for r in rows)

    if args.check:
        with open(OUT, 'rb') as f:
            checked_in = f.read()
        if checked_in != lib:
            print(
                '\nCHECK FAILED: regenerated archive differs from '
                '3rdparty/smacker/smackw32.lib '
                '(%d generated bytes, %d checked-in bytes)' % (len(lib), len(checked_in)),
                file=sys.stderr,
            )
            return 1
        print(
            '\nCHECK OK: regenerated archive is byte-identical to '
            '3rdparty/smacker/smackw32.lib (%d bytes)' % len(lib)
        )
        return 0

    with open(OUT, 'wb') as f:
        f.write(lib)
    print('\nwrote %s (%d bytes, member %d bytes)' % (OUT, len(lib), len(obj)))
    print('ALL CHECKS PASSED')
    return 0


if __name__ == '__main__':
    sys.exit(main())
