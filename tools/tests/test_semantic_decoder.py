"""Tests for the WIDENED closed semantic table.

The table `decode_ia32_bijection_instruction` reads is the foundation every
register-shaped certificate stands on -- the register bijection, the web
recolour and the instruction schedule all decode a whole COMDAT with it and
refuse the body outright if one instruction is not in it.  Before this file
existed the table refused twelve of the fourteen open rows, at eight distinct
causes, so no class could even look at them.

Every form added here was measured before it was written.  `$W/BF-probe`
generates one MSVC 4.2 inline-assembly thunk per admitted encoding, runs it
under Wine over four independent register files -- each register a distinct
pointer into a writable arena, so no encoding can fault -- and perturbs one
liveness ATOM at a time.  The run refuses the entry unless

  READ    every atom the entry does not declare read leaves the whole final
          state (registers, flags and memory) unchanged but for that atom's
          own preserved copy,
  KILL    every atom the entry declares written and not read comes out
          independent of its input,
  FROZEN  every register the instruction is observed to touch is either
          named by a rewritable field of the encoding or declared frozen,
  FIELD   every value a rewritable field takes is observed to touch the
          register it names, somewhere in the form's own encodings.

1,546 encodings, 173,280 read checks, 1,688 kill checks and 1,546 frozen
checks reproduced exactly, and fourteen deliberately broken claims were each
refused by the same run.  These tests fix the results, and the refusals fix
every form that was measured and then deliberately LEFT OUT.
"""
from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import byte_identity  # noqa: E402


def decode(encoding: str, relocations: dict | None = None) -> dict:
    return byte_identity.decode_ia32_bijection_instruction(
        bytes.fromhex(encoding), 0, encoding, relocations)


def refusal(case, encoding: str) -> str:
    with case.assertRaises(byte_identity.ByteIdentityError) as caught:
        decode(encoding)
    return str(caught.exception)


class AddedFormTests(unittest.TestCase):
    """One assertion per family, with the hardware-measured operand set."""

    def test_nop_touches_nothing(self):
        decoded = decode("90")
        self.assertEqual(decoded["length"], 1)
        self.assertEqual(decoded["reads"], frozenset())
        self.assertEqual(decoded["writes"], frozenset())
        self.assertEqual(decoded["read_atoms"], frozenset())
        self.assertEqual(decoded["write_atoms"], frozenset())
        self.assertEqual(decoded["fields"], [])
        self.assertIsNone(decoded["memory"])

    def test_the_xchg_siblings_of_nop_are_still_refused(self):
        """`90` is NOP; `91..97` exchange EAX with a register the field
        names, and the other half of that exchange is named by nothing."""
        for encoding in ("91", "92", "93", "96", "97"):
            self.assertIn("outside the register-bijection table",
                          refusal(self, encoding))

    def test_a_byte_alu_form_freezes_both_fields(self):
        decoded = decode("0ad3")               # or dl, bl
        self.assertEqual(decoded["reads"], frozenset({"ebx", "edx"}))
        self.assertEqual(decoded["writes"], frozenset())
        self.assertEqual(decoded["frozen"], frozenset({"ebx", "edx"}))
        self.assertEqual(decoded["read_atoms"], frozenset({"ebx.l", "edx.l"}))
        self.assertEqual(decoded["write_atoms"], frozenset({"edx.l"}))
        self.assertEqual(decoded["fields"], [])

    def test_a_byte_alu_memory_form_rewrites_only_its_address_register(self):
        decoded = decode("224524")             # and al, [ebp+0x24]
        self.assertEqual(decoded["reads"], frozenset({"eax", "ebp"}))
        self.assertEqual(decoded["frozen"], frozenset({"eax"}))
        self.assertEqual(decoded["read_atoms"],
                         frozenset({"eax.l", "ebp.w"}))
        self.assertEqual(decoded["write_atoms"], frozenset({"eax.l"}))
        self.assertEqual(decoded["fields"], [(1, 0)])
        self.assertEqual(decoded["memory"]["width"], 1)

    def test_a_byte_xor_of_a_register_with_itself_is_not_the_zero_idiom(self):
        """`xor al, al` zeroes AL and leaves the rest of EAX alone, so it may
        not be credited with the 32-bit idiom's full definition."""
        decoded = decode("32c0")
        self.assertEqual(decoded["writes"], frozenset())
        self.assertEqual(decoded["write_atoms"], frozenset({"eax.l"}))
        self.assertEqual(decoded["read_atoms"], frozenset({"eax.l"}))

    def test_the_byte_accumulator_forms_freeze_eax_and_kill_nothing(self):
        for encoding in ("24fd", "a801", "0c0d", "2c02", "3c05"):
            decoded = decode(encoding)
            self.assertEqual(decoded["reads"], frozenset({"eax"}), encoding)
            self.assertEqual(decoded["writes"], frozenset(), encoding)
            self.assertEqual(decoded["frozen"], frozenset({"eax"}), encoding)
            self.assertEqual(decoded["write_atoms"], frozenset(), encoding)

    def test_the_dword_accumulator_forms_define_eax(self):
        for encoding in ("25ff000000", "0d0e1a1a0f", "2d33010000",
                         "3500000400"):
            decoded = decode(encoding)
            self.assertEqual(decoded["reads"], frozenset({"eax"}), encoding)
            self.assertEqual(decoded["writes"], frozenset({"eax"}), encoding)
            self.assertEqual(decoded["frozen"], frozenset({"eax"}), encoding)

    def test_the_read_only_dword_accumulator_forms_define_nothing(self):
        for encoding in ("3d6f020000", "a900000400"):
            decoded = decode(encoding)
            self.assertEqual(decoded["reads"], frozenset({"eax"}), encoding)
            self.assertEqual(decoded["writes"], frozenset(), encoding)
            self.assertEqual(decoded["write_atoms"], frozenset(), encoding)

    def test_mov_r8_imm8_freezes_its_field_and_reads_nothing(self):
        decoded = decode("b301")               # mov bl, 1
        self.assertEqual(decoded["fields"], [])
        self.assertEqual(decoded["frozen"], frozenset({"ebx"}))
        self.assertEqual(decoded["reads"], frozenset({"ebx"}))
        self.assertEqual(decoded["writes"], frozenset())
        self.assertEqual(decoded["read_atoms"], frozenset())
        self.assertEqual(decoded["write_atoms"], frozenset({"ebx.l"}))

    def test_mov_r8_imm8_names_the_high_byte_of_the_low_four(self):
        """`b7` is `mov bh, imm8`, not `mov edi, imm8`."""
        decoded = decode("b701")
        self.assertEqual(decoded["frozen"], frozenset({"ebx"}))
        self.assertEqual(decoded["write_atoms"], frozenset({"ebx.h"}))
        self.assertEqual(decoded["fields"], [])

    def test_a_dword_shift_by_immediate_reads_and_defines_its_operand(self):
        decoded = decode("c1e003")             # shl eax, 3
        self.assertEqual(decoded["reads"], frozenset({"eax"}))
        self.assertEqual(decoded["writes"], frozenset({"eax"}))
        self.assertEqual(decoded["frozen"], frozenset())
        self.assertEqual(decoded["fields"], [(1, 0)])

    def test_a_shift_by_cl_freezes_ecx(self):
        decoded = decode("d3e0")               # shl eax, cl
        self.assertEqual(decoded["reads"], frozenset({"eax", "ecx"}))
        self.assertEqual(decoded["writes"], frozenset({"eax"}))
        self.assertEqual(decoded["frozen"], frozenset({"ecx"}))
        self.assertEqual(decoded["fields"], [(1, 0)])

    def test_a_byte_shift_by_cl_freezes_both(self):
        decoded = decode("d2e2")               # shl dl, cl
        self.assertEqual(decoded["reads"], frozenset({"ecx", "edx"}))
        self.assertEqual(decoded["writes"], frozenset())
        self.assertEqual(decoded["frozen"], frozenset({"ecx", "edx"}))
        self.assertEqual(decoded["write_atoms"], frozenset({"edx.l"}))

    def test_the_rotate_through_carry_members_stay_refused(self):
        """RCL and RCR rotate through CF, and /6 is an undefined slot."""
        for encoding in ("c1d003", "c1d803", "c1f003", "d1d0", "d3d0",
                         "c0d003", "d0d0", "d2d0"):
            self.assertIn("outside the register-bijection table",
                          refusal(self, encoding))

    def test_inc_and_dec_r_m32_fall_through_and_write_memory(self):
        for encoding, base in (("ff4e0c", "esi"), ("ff470c", "edi")):
            decoded = decode(encoding)
            self.assertEqual(decoded["flow"], "fall", encoding)
            self.assertEqual(decoded["reads"], frozenset({base}), encoding)
            self.assertEqual(decoded["fields"], [(1, 0)], encoding)
            self.assertTrue(decoded["memory"]["read"], encoding)
            self.assertTrue(decoded["memory"]["write"], encoding)
            self.assertEqual(decoded["memory"]["width"], 4, encoding)

    def test_inc_r32_through_the_group_defines_the_register(self):
        decoded = decode("ffc1")               # inc ecx
        self.assertEqual(decoded["reads"], frozenset({"ecx"}))
        self.assertEqual(decoded["writes"], frozenset({"ecx"}))
        self.assertEqual(decoded["flow"], "fall")

    def test_the_other_ff_members_stay_refused(self):
        """/3 and /5 are far transfers and /6 is PUSH r/m32, whose store at
        [esp-4] this decoder does not describe."""
        for encoding in ("ff5e0c", "ff6e0c", "ff7508"):
            self.assertIn("outside the register-bijection table",
                          refusal(self, encoding))

    def test_the_indirect_call_and_computed_jump_are_unchanged(self):
        self.assertEqual(decode("ffd1")["flow"], "call")
        self.assertEqual(decode("ff24851c0f1010")["flow"], "exit")


class OperandSizePrefixTests(unittest.TestCase):
    """`66` widens a form only where a 16-bit write cannot be a false kill."""

    def test_a_sixteen_bit_load_kills_only_the_low_two_atoms(self):
        decoded = decode("668b4a24")           # mov cx, [edx+0x24]
        self.assertEqual(decoded["reads"], frozenset({"ecx", "edx"}))
        self.assertEqual(decoded["writes"], frozenset())
        self.assertEqual(decoded["write_atoms"],
                         frozenset({"ecx.l", "ecx.h"}))
        self.assertEqual(decoded["memory"]["width"], 2)
        self.assertEqual(sorted(decoded["fields"]), [(2, 0), (2, 3)])

    def test_the_xor_zero_idiom_is_refused_at_sixteen_bits(self):
        """`xor di, di` zeroes DI and leaves the upper half of EDI exactly as
        it was.  Crediting the idiom here would be a false kill of edi.u."""
        wide = decode("33ff")
        self.assertEqual(wide["reads"], frozenset())
        self.assertEqual(wide["write_atoms"],
                         frozenset({"edi.w"}) if False
                         else byte_identity.ia32_register_atoms({"edi"}))
        narrow = decode("6633ff")
        self.assertEqual(narrow["reads"], frozenset({"edi"}))
        self.assertEqual(narrow["writes"], frozenset())
        self.assertEqual(narrow["write_atoms"], frozenset())
        self.assertEqual(narrow["read_atoms"], frozenset({"edi.w"}))

    def test_inc_r16_kills_nothing_of_an_index_register(self):
        decoded = decode("6647")               # inc di
        self.assertEqual(decoded["writes"], frozenset())
        self.assertEqual(decoded["write_atoms"], frozenset())
        self.assertEqual(decoded["fields"], [(1, 0)])

    def test_inc_r16_kills_the_low_two_atoms_of_a_byte_register(self):
        decoded = decode("6643")               # inc bx
        self.assertEqual(decoded["writes"], frozenset())
        self.assertEqual(decoded["write_atoms"],
                         frozenset({"ebx.l", "ebx.h"}))

    def test_a_sixteen_bit_store_narrows_the_memory_descriptor(self):
        decoded = decode("66c7819c0000000100")
        self.assertEqual(decoded["memory"]["width"], 2)
        self.assertTrue(decoded["memory"]["write"])
        self.assertFalse(decoded["memory"]["read"])

    def test_a_sixteen_bit_group_one_compare_reads_only(self):
        decoded = decode("66837812ff")         # cmp word [eax+0x12], -1
        self.assertEqual(decoded["reads"], frozenset({"eax"}))
        self.assertEqual(decoded["write_atoms"], frozenset())
        self.assertEqual(decoded["memory"]["width"], 2)

    def test_a_sixteen_bit_accumulator_compare_is_admitted(self):
        decoded = decode("663d0100")           # cmp ax, 1
        self.assertEqual(decoded["reads"], frozenset({"eax"}))
        self.assertEqual(decoded["writes"], frozenset())
        self.assertEqual(decoded["frozen"], frozenset({"eax"}))

    def test_a_sixteen_bit_accumulator_that_writes_stays_refused(self):
        """`add ax, imm16` is a PARTIAL write, and the entry's declared
        definition of EAX is a full one; there is no field for the
        width-aware rule to work on, so the prefix is refused."""
        for encoding in ("66050100", "66250100", "662d0100", "660d0100"):
            self.assertIn("operand-size prefix is outside",
                          refusal(self, encoding))

    def test_a_sixteen_bit_push_stays_refused(self):
        """`push ax` moves ESP by two; the stack model describes four."""
        self.assertIn("operand-size prefix is outside", refusal(self, "6650"))
        self.assertIn("operand-size prefix is outside", refusal(self, "6658"))

    def test_a_sixteen_bit_group_three_stays_refused(self):
        """MUL/DIV share the opcode and their implicit pair at 16 bits is
        DX:AX, not EDX:EAX."""
        self.assertIn("operand-size prefix is outside",
                      refusal(self, "66f7d9"))

    def test_the_prefix_is_refused_on_the_transfer_members_of_ff(self):
        self.assertIn("operand-size prefix on extension /2",
                      refusal(self, "66ffd1"))
        self.assertIn("operand-size prefix on extension /4",
                      refusal(self, "66ff24851c0f1010"))

    def test_the_prefix_is_admitted_on_inc_and_dec_r_m16(self):
        decoded = decode("66ff86d4000000")     # inc word [esi+0xd4]
        self.assertEqual(decoded["memory"]["width"], 2)
        self.assertTrue(decoded["memory"]["write"])


class RepeatedStringFormTests(unittest.TestCase):
    """The four repeated string operations, and everything around them."""

    def test_rep_movsd_names_its_three_implicit_registers(self):
        decoded = decode("f3a5")
        self.assertEqual(decoded["reads"], frozenset({"ecx", "esi", "edi"}))
        self.assertEqual(decoded["writes"], frozenset({"ecx", "esi", "edi"}))
        self.assertEqual(decoded["frozen"], frozenset({"ecx", "esi", "edi"}))
        self.assertEqual(decoded["fields"], [])
        self.assertEqual(decoded["flow"], "fall")
        self.assertEqual(decoded["length"], 2)

    def test_rep_movsb_is_the_same_operand_set(self):
        self.assertEqual(decode("f3a4")["reads"], decode("f3a5")["reads"])
        self.assertEqual(decode("f3a4")["writes"], decode("f3a5")["writes"])

    def test_rep_stosd_reads_the_accumulator_and_never_writes_it(self):
        decoded = decode("f3ab")
        self.assertEqual(decoded["reads"], frozenset({"eax", "ecx", "edi"}))
        self.assertEqual(decoded["writes"], frozenset({"ecx", "edi"}))
        self.assertEqual(decoded["frozen"], frozenset({"eax", "ecx", "edi"}))
        self.assertNotIn("esi", decoded["reads"])

    def test_repne_scasb_reads_memory_and_never_writes_it(self):
        decoded = decode("f2ae")
        self.assertEqual(decoded["reads"], frozenset({"eax", "ecx", "edi"}))
        self.assertEqual(decoded["writes"], frozenset({"ecx", "edi"}))
        self.assertTrue(decoded["memory"]["read"])
        self.assertFalse(decoded["memory"]["write"])

    def test_repe_cmpsb_reads_through_both_pointers(self):
        decoded = decode("f3a6")
        self.assertEqual(decoded["reads"], frozenset({"ecx", "esi", "edi"}))
        self.assertTrue(decoded["memory"]["read"])
        self.assertFalse(decoded["memory"]["write"])

    def test_every_string_form_declares_its_memory_unknown(self):
        for encoding in ("f3a4", "f3a5", "f3aa", "f3ab", "f2ae", "f3ae",
                         "f2a6", "f3a6"):
            self.assertTrue(decode(encoding)["memory"]["unknown"], encoding)
            self.assertIsNone(decode(encoding)["memory"]["base"], encoding)
            self.assertEqual(decode(encoding)["memory"]["width"], 0, encoding)

    def test_an_ordinary_memory_operand_is_never_unknown(self):
        self.assertFalse(decode("8b4608")["memory"]["unknown"])

    def test_an_unknown_memory_span_is_refused_by_the_schedule_table(self):
        """The schedule certificate compares displacements against a base.
        A span whose extent is a runtime count has neither, so the class it
        would otherwise mislead refuses it -- twice over, because `F3 A5` is
        not in the schedule flag table either."""
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.ia32_schedule_instruction_facts(
                decode("f3a5"), "window")
        self.assertIn("outside the instruction-schedule table",
                      str(caught.exception))
        # and the gate behind it, reached by handing an opcode the schedule
        # table DOES admit a memory descriptor of unknown extent
        smuggled = dict(decode("8b4608"))
        smuggled["memory"] = dict(decode("f3a5")["memory"])
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.ia32_schedule_instruction_facts(smuggled, "window")
        self.assertIn("unknown extent", str(caught.exception))

    def test_a_string_opcode_without_a_repeat_prefix_stays_refused(self):
        for encoding in ("a4", "a5", "aa", "ab", "ae", "a6", "ac", "ad"):
            self.assertIn("outside the register-bijection table",
                          refusal(self, encoding))

    def test_a_repeat_prefix_on_a_non_string_opcode_stays_refused(self):
        for encoding in ("f390", "f38bc1", "f2c3", "f38b4608"):
            self.assertIn("outside the register-bijection table",
                          refusal(self, encoding))

    def test_repne_on_a_movs_stays_refused(self):
        """Only the prefix/opcode PAIRS in the table are admitted: REPNE MOVS
        is architecturally legal and semantically not what MOVS with REP is,
        so it is not guessed."""
        self.assertIn("outside the register-bijection table",
                      refusal(self, "f2a5"))
        self.assertIn("outside the register-bijection table",
                      refusal(self, "f2ab"))

    def test_the_lock_prefix_stays_refused(self):
        self.assertIn("prefixed instructions are outside",
                      refusal(self, "f00130"))

    def test_an_operand_size_prefix_on_a_string_form_stays_refused(self):
        for encoding in ("66f3a5", "f366a5", "66f3ab"):
            self.assertIn("repeated string operation",
                          refusal(self, encoding))

    def test_two_repeat_prefixes_are_refused(self):
        self.assertIn("unsupported repeated instruction prefix",
                      refusal(self, "f3f3a5"))


class AddressRegisterAtomTests(unittest.TestCase):
    """The regression the hardware probe found in the PRE-EXISTING decoder.

    A memory operand's base and index were recorded in the register-granular
    `reads` but not in the ATOM lattice, and the atom lattice is what the
    backward liveness fixpoint every certificate's boundary proof runs on.
    An address register was therefore invisible to that proof -- a read a
    proof may never miss.
    """

    def test_a_base_register_is_live_in_the_atom_lattice(self):
        decoded = decode("8b4608")             # mov eax, [esi+8]
        self.assertEqual(decoded["reads"], frozenset({"esi"}))
        self.assertEqual(decoded["read_atoms"], frozenset({"esi.w"}))

    def test_a_sib_base_and_index_are_both_live(self):
        decoded = decode("8b448f10")           # mov eax, [edi+ecx*4+0x10]
        self.assertEqual(decoded["reads"], frozenset({"ecx", "edi"}))
        self.assertEqual(
            decoded["read_atoms"],
            byte_identity.ia32_register_atoms({"ecx", "edi"}))

    def test_the_fixpoint_keeps_an_address_register_live(self):
        """The end-to-end statement: a body that loads through EBX before
        defining it must report EBX live on entry."""
        body = bytes.fromhex("8b03" "8bd8" "c3")   # mov eax,[ebx]; mov ebx,eax
        instructions = byte_identity.decode_ia32_bijection_body(body, "live")
        live, _ = byte_identity._register_bijection_live_sets(
            instructions, "live")
        self.assertLessEqual(byte_identity.ia32_register_atoms({"ebx"}),
                             live[0])


class OpcodeRegisterFieldTests(unittest.TestCase):
    """The 3-bit opcode field is accounted for at the form's own width."""

    def test_a_thirty_two_bit_opreg_is_unchanged(self):
        decoded = decode("40")                 # inc eax
        self.assertEqual(decoded["reads"], frozenset({"eax"}))
        self.assertEqual(decoded["writes"], frozenset({"eax"}))
        self.assertEqual(decoded["fields"], [(0, 0)])
        self.assertEqual(decoded["read_atoms"],
                         byte_identity.ia32_register_atoms({"eax"}))
        self.assertEqual(decoded["write_atoms"],
                         byte_identity.ia32_register_atoms({"eax"}))

    def test_push_and_pop_are_unchanged(self):
        push = decode("50")
        self.assertEqual(push["reads"], frozenset({"eax", "esp"}))
        self.assertEqual(push["writes"], frozenset({"esp"}))
        self.assertEqual(push["fields"], [(0, 0)])
        pop = decode("58")
        self.assertEqual(pop["reads"], frozenset({"esp"}))
        self.assertEqual(pop["writes"], frozenset({"eax", "esp"}))

    def test_mov_r32_imm32_is_unchanged(self):
        decoded = decode("b800000000")
        self.assertEqual(decoded["reads"], frozenset())
        self.assertEqual(decoded["writes"], frozenset({"eax"}))
        self.assertEqual(decoded["fields"], [(0, 0)])

    def test_mov_r16_imm16_is_a_partial_definition(self):
        decoded = decode("66b80100")
        self.assertEqual(decoded["reads"], frozenset({"eax"}))
        self.assertEqual(decoded["writes"], frozenset())
        self.assertEqual(decoded["write_atoms"],
                         frozenset({"eax.l", "eax.h"}))
        self.assertEqual(decoded["fields"], [(1, 0)])


class DeliberateRefusalTests(unittest.TestCase):
    """Forms this lane measured, considered, and did NOT add."""

    def test_add_r_m8_r8_stays_refused(self):
        """`00 00` is this linker's alignment filler.  Refusing opcode 0x00
        is what stops an unpinned data tail decoding silently as code -- the
        failure mode the web-recolour class had to fix once already."""
        self.assertIn("opcode 0x00 is outside", refusal(self, "0000"))
        body = bytes(16)
        with self.assertRaises(byte_identity.ByteIdentityError):
            byte_identity.decode_ia32_bijection_body(body, "zeros")

    def test_movzx_and_movsx_from_a_byte_source_stay_refused(self):
        """`0F B6`/`0F BE` have a 32-bit destination field and an 8-bit
        source field.  One `width` cannot describe both, and offering the
        r/m8 field for rewriting would be a bijection applied to AL..BH."""
        for encoding in ("0fb6c0", "0fbec0", "0fb64608", "0fbe06"):
            self.assertIn("outside the register-bijection table",
                          refusal(self, encoding))

    def test_the_word_source_move_extends_are_still_admitted(self):
        """`0F B7`/`0F BF` are the siblings that DO work: a mod 3 r/m16 is
        AX..DI, the same eight registers the 32-bit field numbers."""
        decoded = decode("0fb7c1")
        self.assertEqual(decoded["writes"], frozenset({"eax"}))
        self.assertEqual(sorted(decoded["fields"]), [(2, 0), (2, 3)])

    def test_imul_stays_refused_and_setcc_is_admitted(self):
        """`0F AF` is still not needed by any row, so it is not guessed.
        SETcc (`0F 90..9F`) became load-bearing on 2026-08-22: the
        BuildROIMap donor-rewriting pre-image decodes one, and the ISA
        defines its reg field as an ignored /0 extension with an r/m8
        write, which is exactly how the table admits it."""
        self.assertIn("outside the register-bijection table",
                      refusal(self, "0faf6c2478"))
        for encoding, register in (("0f94c0", "eax"), ("0f9cc1", "ecx")):
            decoded = decode(encoding)
            self.assertEqual(decoded["fields"], [])
            self.assertEqual(decoded["frozen"], frozenset({register}))
            self.assertEqual(decoded["write_atoms"],
                             frozenset({register + ".l"}))

    def test_the_flag_and_stack_transfer_forms_stay_refused(self):
        for encoding in ("9c", "9d", "9e", "9f", "60", "61"):
            self.assertIn("outside the register-bijection table",
                          refusal(self, encoding))

    def test_xchg_and_the_string_load_forms_stay_refused(self):
        for encoding in ("87c1", "86c1", "ac", "ad"):
            self.assertIn("outside the register-bijection table",
                          refusal(self, encoding))

    def test_the_three_byte_imul_forms_stay_refused(self):
        for encoding in ("6bc00a", "69c000000100"):
            self.assertIn("outside the register-bijection table",
                          refusal(self, encoding))

    def test_the_byte_divide_stays_refused(self):
        """`F6 /6` and `/7` divide AX by r/m8 -- an implicit pair the byte
        entry does not describe.  The DWORD siblings under `F7` are
        pre-existing entries and stay admitted with EDX:EAX frozen."""
        for encoding in ("f6f1", "f6f9", "f6e1", "f6e9"):
            self.assertIn("outside the register-bijection table",
                          refusal(self, encoding))
        decoded = decode("f7f1")
        self.assertEqual(decoded["frozen"], frozenset({"eax", "edx"}))


class TableIntegrityTests(unittest.TestCase):
    """A digest over the whole admitted table, so it cannot widen silently.

    Any change to which opcodes, extension digits or prefixes are admitted --
    or to any operand set -- moves this digest.  The constant may only be
    updated together with a fresh run of `$W/BF-probe`, whose three hardware
    obligations are what make an entry admissible in the first place.
    """

    DIGEST = None          # filled in below, next to the corpus that made it

    @staticmethod
    def corpus() -> list[str]:
        """A deterministic encoding corpus over the whole table."""
        modrm = [0xC1, 0xD3, 0xFE, 0x46, 0x51, 0x7B, 0x04, 0x8F]
        rows = []
        for opcode in sorted(byte_identity.IA32_BIJECTION_FORMS):
            for prefix in (b"", b"\x66"):
                for byte in modrm:
                    rows.append(prefix + bytes([opcode, byte])
                                + b"\x10\x5a\x5a\x5a\x5a\x5a")
                rows.append(prefix + bytes([opcode])
                            + b"\x5a\x5a\x5a\x5a\x5a\x5a")
        for opcode in sorted(byte_identity.IA32_BIJECTION_TWO_BYTE_FORMS):
            for byte in modrm:
                rows.append(bytes([0x0F, opcode, byte])
                            + b"\x10\x5a\x5a\x5a\x5a\x5a")
        for prefix, opcode in sorted(
                byte_identity.IA32_BIJECTION_REPEATED_STRING_FORMS):
            rows.append(bytes([prefix, opcode]))
        return [row.hex() for row in rows]

    def digest(self) -> str:
        digest = hashlib.sha256()
        for encoding in self.corpus():
            digest.update(encoding.encode())
            try:
                decoded = decode(encoding)
            except byte_identity.ByteIdentityError:
                digest.update(b"|refused")
                continue
            for key in ("length", "flow", "fields"):
                digest.update(f"|{decoded[key]}".encode())
            for key in ("reads", "writes", "read_atoms", "write_atoms",
                        "frozen"):
                digest.update(f"|{sorted(decoded[key])}".encode())
            digest.update(f"|{decoded['memory']}".encode())
        return digest.hexdigest()

    def test_the_admitted_table_matches_its_hardware_verified_digest(self):
        self.assertEqual(
            self.digest(),
            # Re-pinned 2026-08-22 for the deliberate SETcc admission; every
            # prior row of the corpus digests identically (only the sixteen
            # 0F 90..9F rows moved from refused to decoded).
            "5dc6ba5b570ae6cf8dba4118ee7f0b9fed4d9c5b5fd0eac1b1b2c6b209501e10")

    def test_the_corpus_covers_every_admitted_opcode(self):
        admitted = set()
        for encoding in self.corpus():
            try:
                decode(encoding)
            except byte_identity.ByteIdentityError:
                continue
            admitted.add(encoding[:2])
        self.assertGreater(len(admitted), 60)


if __name__ == "__main__":       # pragma: no cover
    unittest.main()
