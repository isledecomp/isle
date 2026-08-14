#!/usr/bin/env python3
"""Fail-closed regression tests for the dormant PE IAT-order shim."""

import hashlib
import struct
import sys
import tempfile
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pe_iatorder as iat


PE_OFFSET = 0x80
OPTIONAL_OFFSET = PE_OFFSET + 24
SECTION_TABLE = OPTIONAL_OFFSET + 0xE0
TEXT_RAW = 0x200
IDATA_RAW = 0x400
RELOC_RAW = 0x800
TEXT_RVA = 0x1000
IDATA_RVA = 0x2000
RELOC_RVA = 0x3000
IMAGE_BASE = 0x400000
OFT_RVA = IDATA_RVA + 0x80
FT_RVA = IDATA_RVA + 0xC0
DLL_RVA = IDATA_RVA + 0x40


def name_token(name, occurrence=0):
    return ('name', name.encode('ascii'), occurrence)


def ordinal_token(number):
    return ('ordinal', number, 0)


def identity(token):
    return token[:2]


def make_image(order):
    """Build a minimal, structurally valid i386 PE32 import fixture."""
    buf = bytearray(0xA00)
    buf[:2] = b'MZ'
    struct.pack_into('<I', buf, 0x3C, PE_OFFSET)
    buf[PE_OFFSET:PE_OFFSET + 4] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', buf, PE_OFFSET + 4,
                     iat.IMAGE_FILE_MACHINE_I386, 3, 0, 0, 0, 0xE0, 0x010F)
    struct.pack_into('<H', buf, OPTIONAL_OFFSET,
                     iat.IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    struct.pack_into('<I', buf, OPTIONAL_OFFSET + 28, IMAGE_BASE)
    struct.pack_into('<I', buf, OPTIONAL_OFFSET + 32, 0x1000)
    struct.pack_into('<I', buf, OPTIONAL_OFFSET + 36, 0x200)
    struct.pack_into('<I', buf, OPTIONAL_OFFSET + 56, 0x4000)
    struct.pack_into('<I', buf, OPTIONAL_OFFSET + 60, 0x200)
    struct.pack_into('<I', buf, OPTIONAL_OFFSET + 92, 16)
    struct.pack_into('<II', buf, OPTIONAL_OFFSET + 104, IDATA_RVA, 40)

    # Three exact section descriptors.
    struct.pack_into('<8sIIIIIIHHI', buf, SECTION_TABLE,
                     b'.text\0\0\0', 0x100, TEXT_RVA, 0x200, TEXT_RAW,
                     0, 0, 0, 0, 0x60000020)
    struct.pack_into('<8sIIIIIIHHI', buf, SECTION_TABLE + 40,
                     b'.idata\0\0', 0x300, IDATA_RVA, 0x400, IDATA_RAW,
                     0, 0, 0, 0, 0xC0000040)
    struct.pack_into('<8sIIIIIIHHI', buf, SECTION_TABLE + 80,
                     b'.reloc\0\0', 0x200, RELOC_RVA, 0x200, RELOC_RAW,
                     0, 0, 0, 0, 0x42000040)

    # The import descriptor bytes are independent of thunk order.
    struct.pack_into('<IIIII', buf, IDATA_RAW,
                     OFT_RVA, 0, 0, DLL_RVA, FT_RVA)
    buf[IDATA_RAW + 0x40:IDATA_RAW + 0x40 + 11] = b'TESTDLL.DLL\0'
    # A second identical string lets tests change Name RVA without changing the
    # parsed DLL identity.
    buf[IDATA_RAW + 0x50:IDATA_RAW + 0x50 + 11] = b'TESTDLL.DLL\0'

    unique_named_tokens = sorted(
        {token for token in order if token[0] == 'name'},
        key=lambda token: (token[1], token[2]))
    named_rvas = {}
    for index, token in enumerate(unique_named_tokens):
        rva = IDATA_RVA + 0x100 + index * 0x20
        named_rvas[token] = rva
        offset = IDATA_RAW + (rva - IDATA_RVA)
        struct.pack_into('<H', buf, offset, index)
        value = token[1] + b'\0'
        buf[offset + 2:offset + 2 + len(value)] = value

    for index, token in enumerate(order):
        if token[0] == 'ordinal':
            thunk = iat.IMAGE_ORDINAL_FLAG32 | token[1]
        else:
            thunk = named_rvas[token]
        struct.pack_into('<I', buf, IDATA_RAW + (OFT_RVA - IDATA_RVA) +
                         index * 4, thunk)
        struct.pack_into('<I', buf, IDATA_RAW + (FT_RVA - IDATA_RVA) +
                         index * 4, thunk)
        # One absolute IAT operand per source slot.
        struct.pack_into('<I', buf, TEXT_RAW + 0x10 + index * 8,
                         IMAGE_BASE + FT_RVA + index * 4)

    relocation_entries = [0x3000 | (0x10 + index * 8)
                          for index in range(len(order))]
    block_size = 8 + len(relocation_entries) * 2
    if block_size % 4:
        relocation_entries.append(0)  # IMAGE_REL_BASED_ABSOLUTE padding
        block_size += 2
    struct.pack_into('<II', buf, RELOC_RAW, TEXT_RVA, block_size)
    for index, entry in enumerate(relocation_entries):
        struct.pack_into('<H', buf, RELOC_RAW + 8 + index * 2, entry)
    struct.pack_into('<II', buf, OPTIONAL_OFFSET + 136,
                     RELOC_RVA, block_size)
    return bytes(buf)


def thunk_values(buf):
    image = iat.PEImage(buf)
    return [entry.thunk for entry in image.imports[0].entries]


class IATOrderTests(unittest.TestCase):
    def test_named_and_ordinal_imports(self):
        alpha = name_token('Alpha')
        beta = name_token('Beta')
        ordinal = ordinal_token(17)
        target = make_image([alpha, ordinal, beta])
        reference = make_image([beta, alpha, ordinal])

        patched, result = iat.reorder_bytes(target, reference)

        self.assertEqual(result.total_slots, 3)
        self.assertEqual(result.moved_slots, 3)
        self.assertEqual(result.rewritten_operands, 3)
        self.assertEqual(
            [entry.identity for entry in iat.PEImage(patched).imports[0].entries],
            [identity(beta), identity(alpha), identity(ordinal)])
        self.assertIn(iat.IMAGE_ORDINAL_FLAG32 | 17, thunk_values(patched))
        self.assertNotEqual(hashlib.md5(target).digest(),
                            hashlib.md5(patched).digest())

    def test_duplicate_named_identities_keep_every_occurrence(self):
        dup0 = name_token('Duplicate', 0)
        dup1 = name_token('Duplicate', 1)
        beta = name_token('Beta')
        target = make_image([dup0, dup1, beta])
        reference = make_image([dup1, beta, dup0])
        target_thunks = thunk_values(target)

        patched, result = iat.reorder_bytes(target, reference)

        self.assertEqual(result.total_slots, 3)
        self.assertEqual(result.moved_slots, 2)
        self.assertEqual(result.rewritten_operands, 2)
        # Duplicate occurrences are consumed FIFO, never collapsed by a dict.
        self.assertEqual(thunk_values(patched),
                         [target_thunks[0], target_thunks[2], target_thunks[1]])
        self.assertCountEqual(thunk_values(patched), target_thunks)

    def test_duplicate_multiplicity_mismatch_refuses(self):
        dup0 = name_token('Duplicate', 0)
        dup1 = name_token('Duplicate', 1)
        beta0 = name_token('Beta', 0)
        beta1 = name_token('Beta', 1)
        with self.assertRaisesRegex(iat.CompatibilityError,
                                    'import multiset differs'):
            iat.reorder_bytes(make_image([dup0, dup1, beta0]),
                              make_image([dup0, beta0, beta1]))

    def test_checked_section_descriptor_fields_are_exact(self):
        alpha = name_token('Alpha')
        beta = name_token('Beta')
        target = make_image([alpha, beta])
        mutations = {
            'name': (SECTION_TABLE, 0x01),
            'virtual_address': (SECTION_TABLE + 12, 0x01),
            'raw_size': (SECTION_TABLE + 16, 0x01),
            'raw_offset': (SECTION_TABLE + 20, 0x01),
            'relocation_pointer': (SECTION_TABLE + 24, 0x01),
            'characteristics': (SECTION_TABLE + 36, 0x01),
        }
        for label, (offset, mask) in mutations.items():
            with self.subTest(label=label):
                reference = bytearray(make_image([beta, alpha]))
                reference[offset] ^= mask
                with self.assertRaises((iat.PEFormatError,
                                        iat.CompatibilityError)):
                    iat.reorder_bytes(target, reference)

    def test_virtual_size_drift_requires_same_mapped_span(self):
        alpha = name_token('Alpha')
        beta = name_token('Beta')
        target = make_image([alpha, beta])
        compatible = bytearray(make_image([beta, alpha]))
        struct.pack_into('<I', compatible, SECTION_TABLE + 8, 0x101)
        iat.reorder_bytes(target, compatible)  # same 0x1000 mapped span

        incompatible = bytearray(make_image([beta, alpha]))
        struct.pack_into('<I', incompatible, SECTION_TABLE + 8, 0x1001)
        with self.assertRaisesRegex(iat.CompatibilityError,
                                    'section descriptors'):
            iat.reorder_bytes(target, incompatible)

    def test_import_descriptor_dwords_are_byte_exact(self):
        alpha = name_token('Alpha')
        beta = name_token('Beta')
        target = make_image([alpha, beta])
        # TimeDateStamp and ForwarderChain do not affect this parser. They must
        # still refuse, proving comparison is over the raw 20-byte descriptor.
        for label, descriptor_offset in (('timestamp', 4), ('forwarder', 8)):
            with self.subTest(label=label):
                reference = bytearray(make_image([beta, alpha]))
                struct.pack_into('<I', reference,
                                 IDATA_RAW + descriptor_offset, 1)
                with self.assertRaisesRegex(iat.CompatibilityError,
                                            'import descriptor 0 differs'):
                    iat.reorder_bytes(target, reference)

        # Point at an identical DLL string: parsed identity stays equal, raw
        # descriptor equality still catches the changed Name RVA.
        reference = bytearray(make_image([beta, alpha]))
        struct.pack_into('<I', reference, IDATA_RAW + 12, IDATA_RVA + 0x50)
        with self.assertRaisesRegex(iat.CompatibilityError,
                                    'import descriptor 0 differs'):
            iat.reorder_bytes(target, reference)

    def test_import_data_directory_descriptor_is_exact(self):
        alpha = name_token('Alpha')
        beta = name_token('Beta')
        target = make_image([alpha, beta])
        reference = bytearray(make_image([beta, alpha]))
        struct.pack_into('<I', reference, OPTIONAL_OFFSET + 108, 60)
        with self.assertRaisesRegex(iat.CompatibilityError,
                                    'data-directory descriptors differ'):
            iat.reorder_bytes(target, reference)

    def test_iat_looking_dword_without_relocation_refuses(self):
        alpha = name_token('Alpha')
        beta = name_token('Beta')
        target = bytearray(make_image([alpha, beta]))
        reference = make_image([beta, alpha])
        # Convert the first HIGHLOW entry to ABSOLUTE without touching the
        # pointer-like DWORD itself.
        struct.pack_into('<H', target, RELOC_RAW + 8, 0x0010)
        with self.assertRaisesRegex(iat.CompatibilityError,
                                    'lack HIGHLOW relocations'):
            iat.reorder_bytes(target, reference)

    def test_malformed_ordinal_refuses(self):
        ordinal = ordinal_token(17)
        alpha = name_token('Alpha')
        target = bytearray(make_image([ordinal, alpha]))
        malformed = iat.IMAGE_ORDINAL_FLAG32 | 0x00010011
        struct.pack_into('<I', target, IDATA_RAW + (OFT_RVA - IDATA_RVA),
                         malformed)
        struct.pack_into('<I', target, IDATA_RAW + (FT_RVA - IDATA_RVA),
                         malformed)
        with self.assertRaisesRegex(iat.PEFormatError,
                                    'malformed ordinal thunk'):
            iat.reorder_bytes(target, make_image([alpha, ordinal]))

    def test_check_mode_does_not_write(self):
        alpha = name_token('Alpha')
        beta = name_token('Beta')
        with tempfile.TemporaryDirectory() as directory:
            target_path = Path(directory) / 'target.exe'
            original_path = Path(directory) / 'original.exe'
            target_path.write_bytes(make_image([alpha, beta]))
            original_path.write_bytes(make_image([beta, alpha]))
            before = target_path.read_bytes()
            self.assertEqual(iat.main([str(target_path), str(original_path),
                                       '--check']), 0)
            self.assertEqual(target_path.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
