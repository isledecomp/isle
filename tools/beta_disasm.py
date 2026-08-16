#!/usr/bin/env python3
"""Disassemble a function out of BETA10.DLL (or ALPHA.DLL) by virtual address.

The beta is a debug build: statement order, named locals and un-inlined calls
survive, so its code reads much closer to the original source than retail's.
usage: beta.py <va> [--image BETA10.DLL] [--max 400]
"""
import sys, pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
va = int(sys.argv[1], 16)
img = sys.argv[2] if len(sys.argv) > 2 else "BETA10.DLL"
lim = int(sys.argv[3]) if len(sys.argv) > 3 else 400
pe = pefile.PE(f"/Users/foxtacles/Projects/isle/legobin/{img}", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
rva = va - base
data = pe.get_memory_mapped_image()[rva:rva+lim*8]
MD = Cs(CS_ARCH_X86, CS_MODE_32); MD.detail = False
out = []
for i in MD.disasm(data, va):
    out.append(f"  {i.address:#010x}  {i.mnemonic:<7s} {i.op_str}")
    if i.mnemonic == "ret" and len(out) > 4: break
    if len(out) >= lim: break
print(f"=== {img} @ {va:#x} (base {base:#x}) ===")
print("\n".join(out))
