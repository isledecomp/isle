#!/usr/bin/env python3
"""Regenerate 3rdparty/smartheap/SHLW32MT.LIB (SmartHeap 3.31) from the 3.30 lib.

The original ISLE.EXE/LEGO1.DLL link SmartHeap 3.31; the lib previously in the
repo is 3.30 (members dated 1997-03-19). Nineteen .text sections differ, plus
the version string 'SmartHeap330MutexMovShrName' -> '...331...'.

Eight small deltas (addends preserved, layout unchanged):

  task.obj   sec8   @_shi_taskRemovePool@4        one immediate byte 01->11
  info.obj   sec23  @_shi_isBlockInUseFS@12       regalloc recompile, 0 relocs
  info.obj   sec17  @shi_isBlockInUseSmall@8      one byte (cmp operand swap)
  heap.obj   sec60  @_shi_resizeVar@8             regalloc recompile, 0 relocs
  heap.obj   sec6   _MemPoolPreAllocate@12        same-size recompile
  heap.obj   sec56  _MemReAllocPtr@12             same-size recompile
  heap.obj   sec58  @_shi_resizeAny@16            same-size recompile
  syswin32.obj sec101 _shi_enterPoolInitMutexWriter  tail change, 16 relocs rebuilt

Six more of the same kind (SPLICE_INPLACE): info.obj @shi_walkPoolSmall@12 /
@_shi_walkPoolExternal@8, syswin32.obj @shi_findAddrInProcess@20 /
@_shi_sysFreePool@8, pool.obj @_shi_normalizePageSize@4, check.obj
@_shi_validateFreeListVar@4 -- all a flipped compare direction plus the
matching branch condition.

And five wholesale recompiles (SPLICE) that change size and move (or reorder)
their relocation sites:

  syswin32.obj sec25 @shi_sysAllocRegion@16       0x138 -> 0x13a,  7 relocs
  syswin32.obj sec27 @_shi_sysAllocNamedShared@32 0x227 -> 0x22b, 19 relocs
  syswin32.obj sec29 @shi_findSharedAddress@16    0x1d4 -> 0x1d2, 11 relocs
  syswin32.obj sec76 @shi_initPoolMutexShr@4      0x069 -> 0x068,  4 relocs (reordered)
  pool.obj     sec16 @_shi_initPool@36            0x2a9 -> 0x2a4, 25 relocs

New code bytes are taken from the original ISLE.EXE (legobin/); relocation
addends are restored from the 3.30 lib where layout is unchanged, and for
_shi_enterPoolInitMutexWriter the relocation entries are rebuilt by resolving
each DIR32 site via PE base relocs + annotations (ISLE/library_smartheap.h)
and each external REL32 branch via the same annotations. The five SPLICE
functions resolve their sites the same way but against ISLE_SYMS, and require
the (symbol, type, addend) multiset to match 3.30 exactly. Every size change
is absorbed by the 16-byte COMDAT padding, so no other function moves in
either binary. ISLE and LEGO1 SmartHeap bytes are identical, so one lib fixes
both: after this patch ISLE.EXE's .text differs from retail only in import
address-table operands (a .idata ordering issue) and .reloc is byte-identical.

Usage:
  python3 tools/patch_smartheap_331.py --check
  python3 tools/patch_smartheap_331.py --input SHLW32MT.LIB.330 [--output PATH]

--check compares the regenerated archive against the lib currently in the
tree and exits nonzero on any difference. By default, the 3.30 input is read
from its pinned revision in this repository's history.
"""
import argparse
import os
import re
import struct
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIB_REL = "3rdparty/smartheap/SHLW32MT.LIB"
DEFAULT_330_REV = "2ffe227d82916ae37b4916cbd8a714f4ef627f78"

IMAGE_REL_I386_DIR32 = 6
IMAGE_REL_I386_REL32 = 20
RELOC_TYPES = {6: "DIR32", 7: "DIR32NB", 20: "REL32", 11: "SECTION", 12: "SECREL"}

pefile = None
md = None


def load_dependencies(parser):
    global pefile, md
    try:
        import pefile as pefile_module
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    except ImportError:
        parser.error(
            "missing pefile or capstone; install the tool dependencies with "
            "python -m pip install -r tools/requirements.txt"
        )
    pefile = pefile_module
    md = Cs(CS_ARCH_X86, CS_MODE_32)

# ---------------------------------------------------------------- 3.31 splices
# Retail ISLE.EXE addresses of the SmartHeap symbols referenced by the five
# recompiled functions below.  ISLE.EXE's .text layout is reproduced exactly by
# the repo build, so these are stable; every use is cross-checked against the
# 3.30 relocation table (same symbol, same type, same addend) before it is used.
ISLE_SYMS = {
    "@shi_insertSharedPool@8":       0x405b50,
    "@shi_initPoolMutexShr@4":       0x405d70,
    "@shi_deleteSharedPool@4":       0x405c60,
    "@shi_freeFreeRegion@8":         0x405b00,
    "@shi_findSharedAddress@16":     0x4050a0,
    "_shi_isNT":                     0x406180,
    "@shi_putSharedPoolMapping@16":  0x4052f0,
    "@_shi_sysAllocNear@4":          0x404bd0,
    "@shi_findAddrInProcess@20":     0x405280,
    "_rand":                         0x4081f0,
    "@_shi_sysFreeNear@4":           0x404bf0,
    "@shi_findSharedPool@4":         0x405d10,
    "@shi_genMutexName@8":           0x405de0,
    "_shi_enterPoolInitMutexReader": 0x405fd0,
    "_shi_poolAttachShared":         0x4061d0,
    "@_shi_sysAllocNamedShared@32":  0x404e70,
    "@shi_sysAllocRegion@16":        0x404d30,
    "@_shi_sysAllocPool@12":         0x405300,
    "@_shi_invokeErrorHandler1@8":   0x4068c0,
    "_shi_leavePoolInitMutexReader": 0x406060,
    "@_shi_registerShared@16":       0x405800,
    "@_shi_sysFreePool@8":           0x405640,
    "__shi_createAndEnterMutex":     0x405ec0,
    "@_shi_getNextPool@4":           0x405b20,
    "_MemPoolSetBlockSizeFS@8":      0x406630,
    "@_shi_poolFree@8":              0x406710,
    "_MemPoolPreAllocate@12":        0x403180,
    "__shi_TaskRecord":              0x4105b0,
    "__shi_mutexGlobal":             0x412870,
    "__shi_mutexGlobalInit":         0x41032c,
}

# (object, symbol, retail VA, VA of the next .text COMDAT) for the five
# functions whose 3.31 codegen differs from 3.30 by more than address operands.
# The real size is "up to the last non-int3 byte before the next COMDAT"; the
# linker re-pads to the same 16-byte boundary, so no other function moves.
SPLICE = [
    ("syswin32.obj", "@shi_sysAllocRegion@16",      0x404d30, 0x404e70),
    ("syswin32.obj", "@_shi_sysAllocNamedShared@32", 0x404e70, 0x4050a0),
    ("syswin32.obj", "@shi_findSharedAddress@16",   0x4050a0, 0x405280),
    ("syswin32.obj", "@shi_initPoolMutexShr@4",     0x405d70, 0x405de0),
    ("pool.obj",     "@_shi_initPool@36",           0x406270, 0x406520),
]

# Same size, same relocation layout: 3.31 only flips a compare direction (and
# the matching branch condition) or swaps a base/displacement pair.
SPLICE_INPLACE = [
    ("info.obj",     "@shi_walkPoolSmall@12",      0x407420),
    ("info.obj",     "@_shi_walkPoolExternal@8",   0x407380),
    ("syswin32.obj", "@shi_findAddrInProcess@20",  0x405280),
    ("syswin32.obj", "@_shi_sysFreePool@8",        0x405640),
    ("pool.obj",     "@_shi_normalizePageSize@4",  0x4065e0),
    ("check.obj",    "@_shi_validateFreeListVar@4", 0x407a50),
]


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
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--input", help="path to the SmartHeap 3.30 SHLW32MT.LIB")
    src.add_argument("--from-git", metavar="REV",
                     help=f"read the 3.30 lib from git revision REV at {LIB_REL}")
    ap.add_argument("--output", default=os.path.join(REPO, LIB_REL),
                    help=f"archive to write (default: {LIB_REL})")
    ap.add_argument("--check", action="store_true",
                    help="compare the result against the lib in the tree; do not write")
    args = ap.parse_args()

    load_dependencies(ap)
    retail = os.path.join(REPO, "legobin/ISLE.EXE")
    if not os.path.isfile(retail):
        ap.error("missing legobin/ISLE.EXE; place the English 1.1 retail executable there")
    if args.check and not os.path.isfile(os.path.join(REPO, LIB_REL)):
        ap.error(f"missing checked-in archive: {LIB_REL}")

    if args.input:
        if not os.path.isfile(args.input):
            ap.error(f"SmartHeap 3.30 input does not exist: {args.input}")
        lib330 = open(args.input, "rb").read()
    else:
        source_rev = args.from_git or DEFAULT_330_REV
        try:
            lib330 = subprocess.run(
                ["git", "-C", REPO, "show", f"{source_rev}:{LIB_REL}"],
                capture_output=True,
                check=True,
            ).stdout
        except subprocess.CalledProcessError:
            ap.error(
                f"could not read {LIB_REL} from Git revision {source_rev}; "
                "fetch that revision or provide --input"
            )
    assert b"SmartHeap330MutexMovShrName" in lib330, "input lib is not SmartHeap 3.30"

    ann = load_annotations(os.path.join(REPO, "ISLE/library_smartheap.h"), "ISLE")
    pe = pefile.PE(retail)
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

    def splice(member, symname, va, next_va):
        """Splice a whole 3.31 function out of ISLE.EXE, rebuilding its relocs.

        The 3.31 recompile keeps the same set of external references but moves
        (and, for one function, reorders) their sites, and changes the function
        size.  Sites are recovered from the image: DIR32 from the PE base-reloc
        table, REL32 from every branch that leaves the function.  Each site is
        resolved against the candidate symbols named by the 3.30 relocation
        table of that very section, and the resulting (symbol, type, addend)
        multiset must match 3.30 exactly.
        """
        c = Coff(member.data)
        s0 = [s for s in c.symbols if s.name == symname]
        assert len(s0) == 1, symname
        secidx = s0[0].secnum
        assert s0[0].value == 0
        sec = c.sections[secidx - 1]
        symbyidx = {s.idx: s for s in c.symbols}
        old_rel = [(off, symbyidx[si].name, typ,
                    struct.unpack_from("<I", c.section_data(sec), off)[0])
                   for off, si, typ in c.relocs(sec)]

        # size: up to the last byte before the next COMDAT that is not int3 pad
        blob = isle_bytes(va, next_va - va)
        end = len(blob)
        while end and blob[end - 1] == 0xCC:
            end -= 1
        code = bytearray(blob[:end])
        pos = 0
        for ins in md.disasm(bytes(code), va):
            assert ins.address - va == pos, (symname, hex(ins.address))
            pos += ins.size
        assert pos == end, (symname, pos, end)

        cand = {}
        for _, name, typ, _ in old_rel:
            if not name.startswith("__imp__"):
                assert name in ISLE_SYMS, (symname, name)
                cand.setdefault(typ, {})[name] = ISLE_SYMS[name]

        def resolve(value, typ, exact):
            best = None
            for name, sva in cand.get(typ, {}).items():
                d = value - sva
                if 0 <= d < 0x1000 and (best is None or d < best[1]):
                    best = (name, d)
            assert best is not None, (symname, typ, hex(value))
            assert not exact or best[1] == 0, (symname, hex(value), best)
            return best

        sites = []
        for a in sorted(base_relocs):
            if not va <= a < va + end:
                continue
            off = a - va
            value = struct.unpack_from("<I", code, off)[0]
            if value in iat:
                name, addend = "__imp__" + iat[value], 0
            else:
                name, addend = resolve(value, IMAGE_REL_I386_DIR32, False)
            sites.append((off, name, IMAGE_REL_I386_DIR32, addend))
        for off, tgt in external_rel32_sites(code, va):
            name, addend = resolve(tgt, IMAGE_REL_I386_REL32, True)
            sites.append((off, name, IMAGE_REL_I386_REL32, addend))
        sites.sort()

        def key(name, typ, addend):
            return (name.split("@")[0] if name.startswith("__imp__") else name,
                    typ, addend)
        want = sorted(key(n, t, a) for _, n, t, a in old_rel)
        got = sorted(key(n, t, a) for _, n, t, a in sites)
        assert want == got, (symname, [x for x in want if x not in got],
                             [x for x in got if x not in want])

        entries = []
        for off, name, typ, addend in sites:
            if name.startswith("__imp__"):
                cs = [x for x in c.symbols
                      if x.name == name or x.name.startswith(name + "@")]
            else:
                cs = [x for x in c.symbols if x.name == name]
            assert len(cs) == 1, (name, [x.name for x in cs])
            entries.append((off, cs[0].idx, typ))
            struct.pack_into("<I", code, off, addend)

        order = ("order kept" if [key(n, t, a) for _, n, t, a in sites] ==
                 [key(n, t, a) for _, n, t, a in old_rel] else "REORDERED")
        print(f"  {member.name} sec{secidx} {symname}: "
              f"0x{sec.size_raw:x} -> 0x{end:x} bytes, {len(entries)} relocs, {order}")
        patch_obj(member, secidx, bytes(code), new_reloc_entries=entries,
                  fpo_cbproc=end)

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

    # ---- the five wholesale 3.31 recompiles (syswin32 x4, pool x1)
    print("3.31 whole-function splices:")
    for objname, symname, va, next_va in SPLICE:
        splice(by_name[objname], symname, va, next_va)

    print("3.31 same-layout recompiles:")
    for objname, symname, va in SPLICE_INPLACE:
        m = by_name[objname]
        secidx = [s for s in Coff(m.data).symbols if s.name == symname][0].secnum
        patch_obj(m, secidx, raw_from_isle_preserving_addends(m, secidx, va))

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
