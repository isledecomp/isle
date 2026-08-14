#!/usr/bin/env python3
"""Restore a linked PE's import-thunk ordering from an original image.

Only the *ordering* comes from the original. The rewritten ILT/IAT values are
the target image's own named-import RVAs or ordinal thunks, and each relocated
operand is remapped to the new slot holding the same import.

The transform is deliberately fail-closed. It requires compatible PE32/i386
section layouts, byte-exact import descriptors, the same import multiset in
each descriptor, a true slot permutation, and a HIGHLOW base relocation for
every operand it would rewrite.

Usage: pe_iatorder.py <target.exe> <original.exe> [--check]
"""

from __future__ import print_function

import collections
import dataclasses
import hashlib
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile


IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x010B
IMAGE_ORDINAL_FLAG32 = 0x80000000
IMAGE_REL_BASED_ABSOLUTE = 0
IMAGE_REL_BASED_HIGHLOW = 3


class PEFormatError(ValueError):
    """The input is not a well-formed PE32 image understood by this tool."""


class CompatibilityError(ValueError):
    """The two valid images do not meet the transform's safety contract."""


def _require(condition, message, exc=PEFormatError):
    if not condition:
        raise exc(message)


def _unpack_from(fmt, buf, offset, what):
    size = struct.calcsize(fmt)
    _require(isinstance(offset, int) and 0 <= offset <= len(buf) - size,
             '%s is outside the file' % what)
    return struct.unpack_from(fmt, buf, offset)


def _cstring(buf, offset, limit, what):
    _require(0 <= offset < limit <= len(buf), '%s is outside the file' % what)
    end = buf.find(b'\0', offset, limit)
    _require(end >= 0, '%s is not NUL-terminated in its section' % what)
    return bytes(buf[offset:end])


@dataclasses.dataclass(frozen=True)
class Section:
    raw_descriptor: bytes
    name_bytes: bytes
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_offset: int
    characteristics: int

    @property
    def raw_end(self):
        return self.raw_offset + self.raw_size


@dataclasses.dataclass(frozen=True)
class ImportEntry:
    slot_va: int
    thunk: int
    identity: tuple


@dataclasses.dataclass(frozen=True)
class ImportDescriptor:
    raw_descriptor: bytes
    dll_bytes: bytes
    dll: str
    original_first_thunk: int
    first_thunk: int
    entries: tuple


@dataclasses.dataclass(frozen=True)
class Result:
    total_slots: int
    moved_slots: int
    rewritten_operands: int
    changed_bytes: int
    before_md5: str
    after_md5: str


class PEImage:
    def __init__(self, buf):
        self.buf = buf
        _require(len(buf) >= 64 and bytes(buf[:2]) == b'MZ',
                 'missing DOS MZ header')
        self.pe_offset = _unpack_from('<I', buf, 0x3C, 'DOS e_lfanew')[0]
        _require(bytes(buf[self.pe_offset:self.pe_offset + 4]) == b'PE\0\0',
                 'missing PE signature')

        file_header = self.pe_offset + 4
        (self.machine, section_count, _, _, _, optional_size,
         _) = _unpack_from('<HHIIIHH', buf, file_header, 'COFF header')
        _require(self.machine == IMAGE_FILE_MACHINE_I386,
                 'only i386 PE images are supported')
        _require(0 < section_count <= 96, 'invalid PE section count')

        self.optional_offset = file_header + 20
        _require(optional_size >= 144,
                 'PE32 optional header is too small for required directories')
        _require(self.optional_offset + optional_size <= len(buf),
                 'PE32 optional header extends past EOF')
        self.optional_size = optional_size
        magic = _unpack_from('<H', buf, self.optional_offset,
                             'optional-header magic')[0]
        _require(magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC,
                 'only PE32 images are supported')
        self.image_base = _unpack_from('<I', buf, self.optional_offset + 28,
                                       'image base')[0]
        self.section_alignment = _unpack_from('<I', buf,
                                               self.optional_offset + 32,
                                               'section alignment')[0]
        _require(self.section_alignment != 0,
                 'section alignment must be nonzero')
        directory_count = _unpack_from('<I', buf, self.optional_offset + 92,
                                        'data-directory count')[0]
        _require(directory_count >= 6,
                 'PE image lacks import/base-relocation directories')
        self.import_rva, self.import_size = _unpack_from(
            '<II', buf, self.optional_offset + 104, 'import directory')
        self.reloc_rva, self.reloc_size = _unpack_from(
            '<II', buf, self.optional_offset + 136,
            'base-relocation directory')

        section_table = self.optional_offset + optional_size
        _require(section_table + section_count * 40 <= len(buf),
                 'section table extends past EOF')
        parsed = []
        for index in range(section_count):
            offset = section_table + index * 40
            raw_descriptor = bytes(buf[offset:offset + 40])
            (name_bytes, virtual_size, virtual_address, raw_size, raw_offset,
             _, _, _, _, characteristics) = struct.unpack(
                 '<8sIIIIIIHHI', raw_descriptor)
            name = name_bytes.rstrip(b'\0').decode('ascii', 'replace')
            if raw_size:
                _require(raw_offset <= len(buf) - raw_size,
                         'section %s raw data extends past EOF' % name)
            parsed.append(Section(raw_descriptor, name_bytes, name,
                                  virtual_size, virtual_address, raw_size,
                                  raw_offset, characteristics))
        raw_ranges = sorted((s.raw_offset, s.raw_end, s.name)
                            for s in parsed if s.raw_size)
        for previous, current in zip(raw_ranges, raw_ranges[1:]):
            _require(previous[1] <= current[0],
                     'sections %s and %s overlap in the file' %
                     (previous[2], current[2]))
        self.sections = tuple(parsed)
        self.imports = self._parse_imports()

    def section_for_rva(self, rva, size=1):
        _require(size >= 0, 'negative mapped size')
        matches = []
        for section in self.sections:
            delta = rva - section.virtual_address
            if delta >= 0 and delta <= section.raw_size - size:
                matches.append(section)
        _require(len(matches) == 1,
                 'RVA 0x%x (+%d) does not map uniquely to raw section data' %
                 (rva, size))
        return matches[0]

    def rva_to_offset(self, rva, size=1):
        section = self.section_for_rva(rva, size)
        return section.raw_offset + (rva - section.virtual_address)

    def cstring_at_rva(self, rva, what):
        section = self.section_for_rva(rva, 1)
        offset = section.raw_offset + (rva - section.virtual_address)
        return _cstring(self.buf, offset, section.raw_end, what)

    def _parse_imports(self):
        _require(self.import_rva != 0 and self.import_size >= 40,
                 'missing or undersized import directory')
        _require(self.import_size % 20 == 0,
                 'import directory size is not descriptor-aligned')
        start = self.rva_to_offset(self.import_rva, self.import_size)
        end = start + self.import_size
        descriptors = []
        saw_terminator = False
        for offset in range(start, end, 20):
            raw = bytes(self.buf[offset:offset + 20])
            if raw == b'\0' * 20:
                saw_terminator = True
                _require(not any(self.buf[offset + 20:end]),
                         'nonzero import descriptor follows terminator')
                break
            _require(not saw_terminator,
                     'nonzero import descriptor follows terminator')
            oft, _, _, name_rva, ft = struct.unpack('<IIIII', raw)
            _require(name_rva != 0,
                     'non-null import descriptor has a null Name RVA')
            _require(oft != 0,
                     'OriginalFirstThunk is zero; bound imports are unsupported')
            _require(ft != 0, 'FirstThunk is zero')
            dll_bytes = self.cstring_at_rva(name_rva, 'import DLL name')
            _require(dll_bytes != b'', 'import DLL name is empty')
            dll = dll_bytes.decode('ascii', 'replace')
            entries = self._parse_import_entries(oft, ft, dll)
            descriptors.append(ImportDescriptor(raw, dll_bytes, dll, oft, ft,
                                                entries))
        _require(saw_terminator, 'import directory has no null terminator')
        _require(descriptors, 'import directory contains no DLL descriptors')
        return tuple(descriptors)

    def _parse_import_entries(self, oft, ft, dll):
        ilt_section = self.section_for_rva(oft, 4)
        iat_section = self.section_for_rva(ft, 4)
        ilt_capacity = (ilt_section.raw_size -
                        (oft - ilt_section.virtual_address)) // 4
        iat_capacity = (iat_section.raw_size -
                        (ft - iat_section.virtual_address)) // 4
        capacity = min(ilt_capacity, iat_capacity)
        _require(capacity > 0, '%s has empty thunk arrays' % dll)
        entries = []
        terminated = False
        for index in range(capacity):
            lookup_offset = self.rva_to_offset(oft + index * 4, 4)
            address_offset = self.rva_to_offset(ft + index * 4, 4)
            thunk = _unpack_from('<I', self.buf, lookup_offset,
                                 '%s ILT thunk' % dll)[0]
            iat_thunk = _unpack_from('<I', self.buf, address_offset,
                                     '%s IAT thunk' % dll)[0]
            _require(iat_thunk == thunk,
                     '%s ILT/IAT entries differ at index %d' % (dll, index))
            if thunk == 0:
                terminated = True
                break
            if thunk & IMAGE_ORDINAL_FLAG32:
                _require((thunk & 0x7FFF0000) == 0,
                         '%s has malformed ordinal thunk 0x%08x' %
                         (dll, thunk))
                ordinal = thunk & 0xFFFF
                _require(ordinal != 0,
                         '%s imports invalid ordinal zero' % dll)
                identity = ('ordinal', ordinal)
            else:
                name = self.cstring_at_rva(thunk + 2,
                                           '%s import name' % dll)
                _require(name != b'', '%s has an empty import name' % dll)
                identity = ('name', name)
            entries.append(ImportEntry(self.image_base + ft + index * 4,
                                       thunk, identity))
        _require(terminated, '%s thunk arrays have no null terminator' % dll)
        return tuple(entries)

    def highlow_relocation_offsets(self):
        if self.reloc_rva == 0 and self.reloc_size == 0:
            return set()
        _require(self.reloc_rva != 0 and self.reloc_size >= 8,
                 'malformed base-relocation directory')
        start = self.rva_to_offset(self.reloc_rva, self.reloc_size)
        end = start + self.reloc_size
        offset = start
        sites = set()
        while offset < end:
            page_rva, block_size = _unpack_from(
                '<II', self.buf, offset, 'base-relocation block')
            _require(page_rva % 0x1000 == 0,
                     'base-relocation page RVA is not page-aligned')
            _require(block_size >= 8 and block_size % 4 == 0,
                     'invalid base-relocation block size')
            _require(block_size <= end - offset,
                     'base-relocation block extends past its directory')
            for entry_offset in range(offset + 8, offset + block_size, 2):
                value = _unpack_from('<H', self.buf, entry_offset,
                                     'base-relocation entry')[0]
                kind, page_offset = value >> 12, value & 0x0FFF
                if kind == IMAGE_REL_BASED_ABSOLUTE:
                    continue
                if kind != IMAGE_REL_BASED_HIGHLOW:
                    continue
                file_offset = self.rva_to_offset(page_rva + page_offset, 4)
                _require(file_offset not in sites,
                         'duplicate HIGHLOW base-relocation site')
                sites.add(file_offset)
            offset += block_size
        _require(offset == end, 'base-relocation directory was not consumed')
        return sites


def _mapped_span(section, alignment):
    size = max(section.virtual_size, section.raw_size)
    return ((size + alignment - 1) // alignment) * alignment


def _section_layouts_compatible(target, original):
    """Require exact layout fields; tolerate only inert VirtualSize drift.

    VirtualSize may differ only when every other byte of each descriptor is
    exact and both values round to the same mapped span. This cannot change an
    RVA, file offset, access permission, or loader mapping.
    """
    if len(target.sections) != len(original.sections):
        return False
    if target.section_alignment != original.section_alignment:
        return False
    for left, right in zip(target.sections, original.sections):
        # VirtualSize is the DWORD at bytes 8..11. Everything else must match.
        if (left.raw_descriptor[:8] != right.raw_descriptor[:8] or
                left.raw_descriptor[12:] != right.raw_descriptor[12:]):
            return False
        if (_mapped_span(left, target.section_alignment) !=
                _mapped_span(right, original.section_alignment)):
            return False
    return True


def _validate_pair(target, original):
    _require(target.machine == original.machine,
             'PE machine types differ', CompatibilityError)
    _require(target.image_base == original.image_base,
             'image bases differ', CompatibilityError)
    _require(_section_layouts_compatible(target, original),
             'section descriptors/layouts differ', CompatibilityError)
    _require((target.import_rva, target.import_size) ==
             (original.import_rva, original.import_size),
             'import data-directory descriptors differ', CompatibilityError)
    _require(len(target.imports) == len(original.imports),
             'import descriptor counts differ', CompatibilityError)
    for index, (left, right) in enumerate(zip(target.imports,
                                               original.imports)):
        _require(left.raw_descriptor == right.raw_descriptor,
                 'import descriptor %d differs' % index, CompatibilityError)
        _require(left.dll_bytes == right.dll_bytes,
                 'import DLL identity differs at descriptor %d' % index,
                 CompatibilityError)


def _build_plan(target, original):
    remap = {}
    table_writes = {}
    total_slots = 0
    for left, right in zip(target.imports, original.imports):
        left_counts = collections.Counter(entry.identity
                                          for entry in left.entries)
        right_counts = collections.Counter(entry.identity
                                           for entry in right.entries)
        _require(left_counts == right_counts,
                 'import multiset differs for %s' % left.dll,
                 CompatibilityError)
        buckets = collections.defaultdict(collections.deque)
        for entry in left.entries:
            buckets[entry.identity].append(entry)
        for destination_index, reference_entry in enumerate(right.entries):
            source_entry = buckets[reference_entry.identity].popleft()
            destination_va = (target.image_base + left.first_thunk +
                              destination_index * 4)
            _require(source_entry.slot_va not in remap,
                     'duplicate source IAT slot in remap', CompatibilityError)
            remap[source_entry.slot_va] = destination_va
            for table_rva in (left.original_first_thunk, left.first_thunk):
                file_offset = target.rva_to_offset(
                    table_rva + destination_index * 4, 4)
                _require(file_offset not in table_writes,
                         'overlapping ILT/IAT write plan', CompatibilityError)
                table_writes[file_offset] = source_entry.thunk
        _require(all(not queue for queue in buckets.values()),
                 'duplicate-import occurrence was not consumed',
                 CompatibilityError)
        total_slots += len(left.entries)

    _require(len(remap) == total_slots,
             'IAT remap lost one or more slots', CompatibilityError)
    _require(len(set(remap.values())) == total_slots,
             'IAT remap is not one-to-one', CompatibilityError)
    _require(set(remap) == set(remap.values()),
             'IAT remap is not a permutation of target slots',
             CompatibilityError)

    moved = {old: new for old, new in remap.items() if old != new}
    if not moved:
        return remap, table_writes, set()

    relocation_offsets = target.highlow_relocation_offsets()
    import_section = target.section_for_rva(target.import_rva,
                                            target.import_size)
    operand_offsets = set()
    unrelocated = []
    for section in target.sections:
        if section is import_section or section.raw_size < 4:
            continue
        for file_offset in range(section.raw_offset, section.raw_end - 3):
            value = struct.unpack_from('<I', target.buf, file_offset)[0]
            if value not in moved:
                continue
            if file_offset not in relocation_offsets:
                unrelocated.append(file_offset)
            else:
                operand_offsets.add(file_offset)
    _require(not unrelocated,
             ('%d IAT-looking DWORD(s) lack HIGHLOW relocations (first at '
              'file offset 0x%x)') % (len(unrelocated), unrelocated[0])
             if unrelocated else '', CompatibilityError)
    ordered_operands = sorted(operand_offsets)
    _require(all(right - left >= 4 for left, right in
                 zip(ordered_operands, ordered_operands[1:])),
             'overlapping relocated IAT operands', CompatibilityError)
    return remap, table_writes, operand_offsets


def reorder_bytes(target_bytes, original_bytes):
    """Return ``(patched_bytes, Result)`` or raise a fail-closed exception."""
    work = bytearray(target_bytes)
    target = PEImage(work)
    original = PEImage(original_bytes)
    _validate_pair(target, original)
    remap, table_writes, operand_offsets = _build_plan(target, original)

    for file_offset, thunk in table_writes.items():
        struct.pack_into('<I', work, file_offset, thunk)
    for file_offset in operand_offsets:
        old_va = struct.unpack_from('<I', work, file_offset)[0]
        struct.pack_into('<I', work, file_offset, remap[old_va])

    patched = PEImage(work)
    _require([tuple(entry.identity for entry in descriptor.entries)
              for descriptor in patched.imports] ==
             [tuple(entry.identity for entry in descriptor.entries)
              for descriptor in original.imports],
             'post-transform import order verification failed',
             CompatibilityError)
    _require([collections.Counter(entry.thunk for entry in descriptor.entries)
              for descriptor in patched.imports] ==
             [collections.Counter(entry.thunk for entry in descriptor.entries)
              for descriptor in target.imports],
             'post-transform target-thunk preservation failed',
             CompatibilityError)

    before = bytes(target_bytes)
    after = bytes(work)
    result = Result(
        total_slots=len(remap),
        moved_slots=sum(old != new for old, new in remap.items()),
        rewritten_operands=len(operand_offsets),
        changed_bytes=sum(left != right for left, right in zip(before, after)),
        before_md5=hashlib.md5(before).hexdigest(),
        after_md5=hashlib.md5(after).hexdigest(),
    )
    return after, result


# Compatibility helpers retained for existing read-only probes.
def sections(buf):
    image = PEImage(buf)
    return image.pe_offset, [
        (section.name, section.virtual_size, section.virtual_address,
         section.raw_size, section.raw_offset)
        for section in image.sections
    ]


def imports(buf):
    image = PEImage(buf)
    return ([
        (descriptor.dll, descriptor.original_first_thunk,
         descriptor.first_thunk,
         [(entry.slot_va, entry.thunk, entry.identity)
          for entry in descriptor.entries])
        for descriptor in image.imports
    ], image.image_base, image.rva_to_offset)


def _atomic_write(path, data, mode):
    descriptor, temporary = tempfile.mkstemp(
        prefix='.%s.iatorder-' % path.name, dir=str(path.parent))
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, stat.S_IMODE(mode))
        os.replace(temporary, str(path))
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    check = False
    if '--check' in argv:
        check = True
        argv.remove('--check')
    if len(argv) != 2 or any(argument.startswith('-') for argument in argv):
        print(__doc__.strip(), file=sys.stderr)
        return 2
    target_path = Path(argv[0])
    original_path = Path(argv[1])
    try:
        _require(target_path.resolve() != original_path.resolve(),
                 'target and original paths are the same', CompatibilityError)
        target_bytes = target_path.read_bytes()
        original_bytes = original_path.read_bytes()
        patched, result = reorder_bytes(target_bytes, original_bytes)
        if not check and patched != target_bytes:
            _atomic_write(target_path, patched, target_path.stat().st_mode)
    except (OSError, PEFormatError, CompatibilityError) as error:
        print('pe_iatorder: refusing: %s' % error, file=sys.stderr)
        return 1

    verb = 'would reorder' if check else 'reordered'
    print(('pe_iatorder: %s %d/%d thunk slots, %s %d operands; '
           '%d raw bytes differ; md5 %s -> %s') %
          (verb, result.moved_slots, result.total_slots,
           'would rewrite' if check else 'rewrote',
           result.rewritten_operands, result.changed_bytes,
           result.before_md5, result.after_md5))
    return 0


if __name__ == '__main__':
    sys.exit(main())
