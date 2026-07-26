#!/usr/bin/env python3
"""Regenerate 3rdparty/smartheap/SHLW32MT.LIB (SmartHeap 3.31) from the 3.30 lib.

The original ISLE.EXE/LEGO1.DLL link SmartHeap 3.31; the lib previously in the
repo is 3.30 (members dated 1997-03-19). Exactly eight .text sections differ,
plus the version string 'SmartHeap330MutexMovShrName' -> '...331...':

  task.obj   sec8   @_shi_taskRemovePool@4        one immediate byte 01->11
  info.obj   sec23  @_shi_isBlockInUseFS@12       regalloc recompile, 0 relocs
  info.obj   sec17  @shi_isBlockInUseSmall@8      one byte (cmp operand swap)
  heap.obj   sec60  @_shi_resizeVar@8             regalloc recompile, 0 relocs
  heap.obj   sec6   _MemPoolPreAllocate@12        same-size recompile
  heap.obj   sec56  _MemReAllocPtr@12             same-size recompile
  heap.obj   sec58  @_shi_resizeAny@16            same-size recompile
  syswin32.obj sec101 _shi_enterPoolInitMutexWriter  tail change, 16 relocs rebuilt

New code bytes are taken from the original ISLE.EXE (legobin/); relocation
addends are restored from the 3.30 lib where layout is unchanged, and for
_shi_enterPoolInitMutexWriter the relocation entries are rebuilt by resolving
each DIR32 site via PE base relocs + annotations (ISLE/library_smartheap.h)
and each external REL32 branch via the same annotations. The same four
public functions differ in LEGO1.DLL at 0x10087910/0x10089350/0x10089f70/
0x1008aac0; ISLE and LEGO1 SmartHeap bytes are identical, so one lib fixes
both binaries.

Usage:
  python3 tools/patch_smartheap_331.py --from-git <rev-with-3.30-lib> --check
  python3 tools/patch_smartheap_331.py --input SHLW32MT.LIB.330 [--output PATH]

--check compares the regenerated archive against the lib currently in the
tree and exits nonzero on any difference.
"""
import argparse
import re
import struct
import subprocess
import sys
import os

try:
    import pefile
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
except ImportError:
    sys.exit("pefile and capstone are required (pip install pefile capstone)")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIB_REL = "3rdparty/smartheap/SHLW32MT.LIB"

IMAGE_REL_I386_DIR32 = 6
IMAGE_REL_I386_REL32 = 20
RELOC_TYPES = {6: "DIR32", 7: "DIR32NB", 20: "REL32", 11: "SECTION", 12: "SECREL"}

md = Cs(CS_ARCH_X86, CS_MODE_32)


# ---------------------------------------------------------------- COFF archive
class Member:
    def __init__(self, hdr_off, name_raw, hdr, data):
        self.hdr_off = hdr_off
        self.name_raw = name_raw
        self.hdr = hdr
        self.data = data
        self.name = None


def parse_archive(buf):
    assert buf[:8] == b"!<arch>\n", "bad archive magic"
    members = []
    off = 8
    while off < len(buf):
        if off % 2:
            assert buf[off:off + 1] == b"\n", f"bad pad at 0x{off:x}"
            off += 1
        if off >= len(buf):
            break
        hdr = buf[off:off + 60]
        assert hdr[58:60] == b"`\n", f"bad member header terminator at 0x{off:x}"
        name = hdr[0:16].rstrip(b" ").decode()
        size = int(hdr[48:58].rstrip(b" ").decode())
        members.append(Member(off, name, hdr, bytearray(buf[off + 60:off + 60 + size])))
        off = off + 60 + size
    longnames = next((bytes(m.data) for m in members if m.name_raw == "//"), None)
    for m in members:
        n = m.name_raw
        if n in ("/", "//"):
            m.name = n
        elif n.startswith("/"):
            o = int(n[1:])
            m.name = longnames[o:longnames.index(b"\x00", o)].decode()
        else:
            m.name = n.rstrip("/")
    return members


def rebuild_archive(members):
    out = bytearray(b"!<arch>\n")
    offsets = {}
    for m in members:
        if len(out) % 2:
            out += b"\n"
        offsets[id(m)] = len(out)
        hdr = bytearray(m.hdr)
        hdr[48:58] = str(len(m.data)).ljust(10).encode()
        assert hdr[58:60] == b"`\n"
        out += hdr
        out += m.data
    if len(out) % 2:
        out += b"\n"
    return bytes(out), offsets


class Section:
    SHDR = struct.Struct("<8sIIIIIIHHI")

    def __init__(self, idx, raw):
        self.idx = idx
        (self.name, self.vsize, self.vaddr, self.size_raw, self.ptr_raw,
         self.ptr_reloc, self.ptr_lines, self.n_reloc, self.n_lines,
         self.flags) = self.SHDR.unpack(raw)
        self.name = self.name.rstrip(b"\x00").decode()


class Symbol:
    def __init__(self, i, name, value, secnum, typ, sclass, naux, aux):
        self.idx = i
        self.name = name
        self.value = value
        self.secnum = secnum
        self.typ = typ
        self.sclass = sclass
        self.naux = naux
        self.aux = aux


class Coff:
    def __init__(self, data):
        self.data = bytearray(data)
        (self.machine, self.nsec, self.ts, self.ptr_sym, self.nsym,
         self.opt, self.chars) = struct.unpack_from("<HHIIIHH", data, 0)
        assert self.machine == 0x14C, hex(self.machine)
        assert self.opt == 0
        self.sections = [Section(i + 1, bytes(data[20 + 40 * i: 60 + 40 * i]))
                         for i in range(self.nsec)]
        self.symbols = []
        strtab_off = self.ptr_sym + 18 * self.nsym
        self.strtab = bytes(data[strtab_off:])
        i = 0
        while i < self.nsym:
            off = self.ptr_sym + 18 * i
            raw = bytes(data[off:off + 18])
            if raw[:4] == b"\x00\x00\x00\x00":
                so = struct.unpack_from("<I", raw, 4)[0]
                name = self.strtab[so:self.strtab.index(b"\x00", so)].decode()
            else:
                name = raw[:8].rstrip(b"\x00").decode()
            value, secnum, typ, sclass, naux = struct.unpack_from("<IhHBB", raw, 8)
            aux = bytes(data[off + 18: off + 18 + 18 * naux])
            self.symbols.append(Symbol(i, name, value, secnum, typ, sclass, naux, aux))
            i += 1 + naux

    def section_data(self, s):
        return bytes(self.data[s.ptr_raw: s.ptr_raw + s.size_raw])

    def relocs(self, s):
        return [struct.unpack_from("<IIH", self.data, s.ptr_reloc + 10 * i)
                for i in range(s.n_reloc)]


# ---------------------------------------------------------------- patch logic
def load_annotations(path, tag):
    out = {}
    lines = open(path).read().splitlines()
    for i, ln in enumerate(lines):
        m = re.match(rf"// (LIBRARY|GLOBAL): {tag} (0x[0-9a-f]+)", ln)
        if m:
            out[int(m.group(2), 16)] = lines[i + 1].split("// ")[1].strip()
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--input", help="path to the SmartHeap 3.30 SHLW32MT.LIB")
    src.add_argument("--from-git", metavar="REV",
                     help=f"read the 3.30 lib from `git show REV:{LIB_REL}`")
    ap.add_argument("--output", default=os.path.join(REPO, LIB_REL))
    ap.add_argument("--check", action="store_true",
                    help="compare the result against the lib in the tree; do not write")
    args = ap.parse_args()

    if args.from_git:
        lib330 = subprocess.run(["git", "-C", REPO, "show", f"{args.from_git}:{LIB_REL}"],
                                capture_output=True, check=True).stdout
    else:
        lib330 = open(args.input, "rb").read()
    assert b"SmartHeap330MutexMovShrName" in lib330, "input lib is not SmartHeap 3.30"

    ann = load_annotations(os.path.join(REPO, "ISLE/library_smartheap.h"), "ISLE")
    pe = pefile.PE(os.path.join(REPO, "legobin/ISLE.EXE"))
    base = pe.OPTIONAL_HEADER.ImageBase
    assert base == 0x400000
    iat = {}
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.name:
                iat[imp.address] = imp.name.decode()
    base_relocs = set()
    for b in pe.DIRECTORY_ENTRY_BASERELOC:
        for e in b.entries:
            if e.type == 3:
                base_relocs.add(base + e.rva)

    def isle_bytes(va, n):
        return bytearray(pe.get_data(va - base, n))

    def external_rel32_sites(code, va):
        out = []
        for ins in md.disasm(bytes(code), va):
            b = ins.bytes
            t = None
            if b[0] in (0xE8, 0xE9):
                t = ins.address + ins.size + struct.unpack("<i", b[1:5])[0]
                doff = ins.address - va + 1
            elif b[0] == 0x0F and 0x80 <= b[1] <= 0x8F:
                t = ins.address + ins.size + struct.unpack("<i", b[2:6])[0]
                doff = ins.address - va + 2
            if t is not None and not (va <= t < va + len(code)):
                out.append((doff, t))
        return out

    # ---- 3.31 payloads from the original ISLE.EXE
    FUNC = {
        "resizeVar": dict(va=0x404650, ln=0x1c3),
        "isBlockFS": dict(va=0x407800, ln=0x75),
        "taskRemove": dict(va=0x406cb0, ln=0x99),
        "enterPool": dict(va=0x406090, ln=0xc9),
    }
    for k in ("resizeVar", "isBlockFS"):
        f = FUNC[k]
        code = isle_bytes(f["va"], f["ln"])
        assert not [a for a in base_relocs if f["va"] <= a < f["va"] + f["ln"]], k
        assert not external_rel32_sites(code, f["va"]), k
        f["raw"] = bytes(code)

    f = FUNC["enterPool"]
    code = isle_bytes(f["va"], f["ln"])
    dir32 = sorted(a - f["va"] for a in base_relocs if f["va"] <= a < f["va"] + f["ln"])
    rel32 = external_rel32_sites(code, f["va"])
    sites = []
    for off in dir32:
        val = struct.unpack_from("<I", code, off)[0]
        if val in ann:
            name = ann[val]
        elif val in iat:
            name = "__imp__" + iat[val]
        else:
            raise AssertionError(f"DIR32 value 0x{val:x} at +0x{off:x} unresolved")
        sites.append((off, name, IMAGE_REL_I386_DIR32))
    for off, tgt in rel32:
        assert tgt in ann, hex(tgt)
        sites.append((off, ann[tgt], IMAGE_REL_I386_REL32))
    sites.sort()
    offs = [s[0] for s in sites]
    assert len(sites) == 16 and len(set(offs)) == 16
    for a, b2 in zip(offs, offs[1:]):
        assert b2 - a >= 4
    for off, name, typ in sites:
        struct.pack_into("<I", code, off, 0)
    f["raw"] = bytes(code)
    f["sites"] = sites
    print("enterPool reloc plan:")
    for off, name, typ in sites:
        print(f"  +0x{off:03x} {RELOC_TYPES[typ]:6s} {name}")

    # ---- load archive
    members = parse_archive(lib330)
    by_name = {m.name: m for m in members if m.name not in ("/", "//")}
    orig_offsets = {id(m): m.hdr_off for m in members}

    def patch_obj(member, secidx, new_raw, new_reloc_entries=None,
                  fpo_cbproc=None, fpo_cbprolog=None, extra_edits=()):
        """Replace section raw data (resizing if needed) and fix every derived field."""
        data = bytearray(member.data)
        c = Coff(data)
        s = c.sections[secidx - 1]
        old_size = s.size_raw
        start = s.ptr_raw
        delta = len(new_raw) - old_size
        assert s.name == ".text"
        if new_reloc_entries is not None:
            assert len(new_reloc_entries) == s.n_reloc, "reloc count change not supported"

        data[start:start + old_size] = new_raw

        if delta:
            (mach, nsec, ts, ptr_sym, nsym, opt, chars) = struct.unpack_from("<HHIIIHH", data, 0)
            assert ptr_sym > start
            struct.pack_into("<I", data, 8, ptr_sym + delta)
            for i in range(nsec):
                ho = 20 + 40 * i
                for fo in (20, 24, 28):
                    v = struct.unpack_from("<I", data, ho + fo)[0]
                    if v > start:
                        struct.pack_into("<I", data, ho + fo, v + delta)
                if i + 1 > secidx:
                    phys = struct.unpack_from("<I", data, ho + 8)[0]
                    struct.pack_into("<I", data, ho + 8, phys + delta)

        ho = 20 + 40 * (secidx - 1)
        struct.pack_into("<I", data, ho + 16, len(new_raw))

        if new_reloc_entries is not None:
            ptr_rel = struct.unpack_from("<I", data, ho + 24)[0]
            for i, (off, symidx, typ) in enumerate(new_reloc_entries):
                struct.pack_into("<IIH", data, ptr_rel + 10 * i, off, symidx, typ)

        c2 = Coff(data)
        for sym in c2.symbols:
            if sym.secnum == secidx and sym.sclass == 3 and sym.naux:
                aux_off = c2.ptr_sym + 18 * (sym.idx + 1)
                assert struct.unpack_from("<I", data, aux_off)[0] == old_size
                struct.pack_into("<I", data, aux_off, len(new_raw))
                nrel_aux = struct.unpack_from("<H", data, aux_off + 4)[0]
                assert nrel_aux == c2.sections[secidx - 1].n_reloc

        dbg = c2.sections[secidx]
        assert dbg.name == ".debug$F"
        if fpo_cbproc is not None:
            assert struct.unpack_from("<I", data, dbg.ptr_raw + 4)[0] == old_size
            struct.pack_into("<I", data, dbg.ptr_raw + 4, fpo_cbproc)
        if fpo_cbprolog is not None:
            w = struct.unpack_from("<H", data, dbg.ptr_raw + 14)[0]
            struct.pack_into("<H", data, dbg.ptr_raw + 14, (w & 0xFF00) | fpo_cbprolog)

        for off, oldb, newb in extra_edits:
            assert off < start
            assert data[off] == oldb, f"expect 0x{oldb:x} at 0x{off:x}, got 0x{data[off]:x}"
            data[off] = newb

        member.data = data
        return delta

    def raw_from_isle_preserving_addends(member, secidx, va):
        """New raw = ISLE 3.31 bytes with lib addend dwords restored at existing
        reloc sites. Requires identical section size and reloc layout 3.30/3.31."""
        c = Coff(member.data)
        s = c.sections[secidx - 1]
        old = c.section_data(s)
        new = bytearray(isle_bytes(va, s.size_raw))
        rel = c.relocs(s)
        dir32_offs = {off for off, _, typ in rel if typ == IMAGE_REL_I386_DIR32}
        br = {a - va for a in base_relocs if va <= a < va + s.size_raw}
        assert br == dir32_offs, (member.name, secidx, sorted(map(hex, br)),
                                  sorted(map(hex, dir32_offs)))
        gap = (-(va + s.size_raw)) % 16
        pad = isle_bytes(va + s.size_raw, gap)
        assert pad == b"\xcc" * gap, (member.name, secidx, pad.hex())
        for off, symidx, typ in rel:
            new[off:off + 4] = old[off:off + 4]
        changed = [i for i in range(s.size_raw) if old[i] != new[i]]
        print(f"  {member.name} sec{secidx}: {len(changed)} bytes change "
              f"at {[hex(x) for x in changed[:24]]}")
        return bytes(new)

    # task.obj: single immediate byte
    m = by_name["task.obj"]
    c = Coff(m.data)
    s = c.sections[7]
    new = bytearray(c.section_data(s))
    assert new[0x10] == 0x01
    new[0x10] = 0x11
    isle_trp = isle_bytes(FUNC["taskRemove"]["va"], 0x99)
    masked = set()
    for va_r, _, _ in c.relocs(s):
        masked.update(range(va_r, va_r + 4))
    mism = [i for i in range(0x99) if i not in masked and new[i] != isle_trp[i]]
    assert mism == [], [hex(x) for x in mism]
    patch_obj(m, 8, bytes(new))

    # info.obj
    patch_obj(by_name["info.obj"], 23, FUNC["isBlockFS"]["raw"], fpo_cbprolog=19)
    m = by_name["info.obj"]
    patch_obj(m, 17, raw_from_isle_preserving_addends(m, 17, 0x407540))

    # heap.obj
    patch_obj(by_name["heap.obj"], 60, FUNC["resizeVar"]["raw"], fpo_cbproc=0x1c3)
    m = by_name["heap.obj"]
    patch_obj(m, 6, raw_from_isle_preserving_addends(m, 6, 0x403180))
    patch_obj(m, 56, raw_from_isle_preserving_addends(m, 56, 0x404260))
    patch_obj(m, 58, raw_from_isle_preserving_addends(m, 58, 0x4043b0))

    # syswin32.obj
    m = by_name["syswin32.obj"]
    c = Coff(m.data)
    entries = []
    for off, name, typ in FUNC["enterPool"]["sites"]:
        if name.startswith("__imp__"):
            cands = [s2 for s2 in c.symbols if s2.name == name or s2.name.startswith(name + "@")]
        else:
            cands = [s2 for s2 in c.symbols if s2.name == name]
        assert len(cands) == 1, (name, [x.name for x in cands])
        entries.append((off, cands[0].idx, typ))
        print(f"  reloc +0x{off:03x} -> sym[{cands[0].idx}] {cands[0].name}")
    soff = bytes(m.data).find(b"SmartHeap330MutexMovShrName")
    assert soff == 0x1160
    patch_obj(m, 101, FUNC["enterPool"]["raw"], new_reloc_entries=entries,
              fpo_cbproc=0xc9, extra_edits=[(soff + 11, ord("0"), ord("1"))])

    # ---- rebuild archive, fix both linker members' offset tables
    blob, new_off = rebuild_archive(members)
    remap = {orig_offsets[id(mm)]: new_off[id(mm)] for mm in members}

    lm1 = members[0]
    assert lm1.name_raw == "/"
    d1 = bytearray(lm1.data)
    n1 = struct.unpack_from(">I", d1, 0)[0]
    for i in range(n1):
        o = struct.unpack_from(">I", d1, 4 + 4 * i)[0]
        struct.pack_into(">I", d1, 4 + 4 * i, remap[o])
    lm1.data = d1

    lm2 = members[1]
    assert lm2.name_raw == "/"
    d2 = bytearray(lm2.data)
    n2 = struct.unpack_from("<I", d2, 0)[0]
    for i in range(n2):
        o = struct.unpack_from("<I", d2, 4 + 4 * i)[0]
        struct.pack_into("<I", d2, 4 + 4 * i, remap[o])
    lm2.data = d2

    blob2, _ = rebuild_archive(members)

    if args.check:
        cur = open(os.path.join(REPO, LIB_REL), "rb").read()
        if blob2 == cur:
            print(f"\nCHECK OK: regenerated archive is byte-identical to {LIB_REL} "
                  f"({len(blob2)} bytes)")
            return 0
        print(f"\nCHECK FAILED: regenerated {len(blob2)} bytes != tree {len(cur)} bytes")
        return 1
    open(args.output, "wb").write(blob2)
    print(f"\nwrote {args.output} ({len(blob2)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
