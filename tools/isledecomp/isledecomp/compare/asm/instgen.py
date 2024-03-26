"""Pre-parser for x86 instructions. Will identify data/jump tables used with
switch statements and local jump/call destinations."""
import re
import bisect
import struct
from enum import Enum, auto
from collections import namedtuple
from typing import List, NamedTuple, Optional, Tuple, Union
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from .const import JUMP_MNEMONICS

disassembler = Cs(CS_ARCH_X86, CS_MODE_32)

DisasmLiteInst = namedtuple("DisasmLiteInst", "address, size, mnemonic, op_str")

displacement_regex = re.compile(r".*\+ (0x[0-9a-f]+)\]")


class SectionType(Enum):
    CODE = auto()
    DATA_TAB = auto()
    ADDR_TAB = auto()


class FuncSection(NamedTuple):
    type: SectionType
    contents: List[Union[DisasmLiteInst, Tuple[str, int]]]


class InstructGen:
    # pylint: disable=too-many-instance-attributes
    def __init__(self, blob: bytes, start: int) -> None:
        self.blob = blob
        self.start = start
        self.end = len(blob) + start
        self.section_end: int = self.end
        self.code_tracks: List[List[DisasmLiteInst]] = []

        # Todo: Could be refactored later
        self.cur_addr: int = 0
        self.cur_section_type: SectionType = SectionType.CODE
        self.section_start = start

        self.sections: List[FuncSection] = []

        self.confirmed_addrs = {}
        self.analysis()

    def _finish_section(self, type_: SectionType, stuff):
        sect = FuncSection(type_, stuff)
        self.sections.append(sect)

    def _insert_confirmed_addr(self, addr: int, type_: SectionType):
        # Ignore address outside the bounds of the function
        if not self.start <= addr < self.end:
            return

        self.confirmed_addrs[addr] = type_

        # This newly inserted address might signal the end of this section.
        # For example, a jump table at the end of the function means we should
        # stop reading instructions once we hit that address.
        # However, if there is a jump table in between code sections, we might
        # read a jump to an address back to the beginning of the function
        # (e.g. a loop that spans the entire function)
        # so ignore this address because we have already passed it.
        if type_ != self.cur_section_type and addr > self.cur_addr:
            self.section_end = min(self.section_end, addr)

    def _next_section(self, addr: int) -> Optional[SectionType]:
        """We have reached the start of a new section. Tell what kind of
        data we are looking at (code or other) and how much we should read."""

        # Assume the start of every function is code.
        if addr == self.start:
            self.section_end = self.end
            return SectionType.CODE

        # The start of a new section must be an address that we've seen.
        new_type = self.confirmed_addrs.get(addr)
        if new_type is None:
            return None

        self.cur_section_type = new_type

        # The confirmed addrs dict is sorted by insertion order
        # i.e. the order in which we read the addresses
        # So we have to sort and then find the next item
        # to see where this section should end.

        # If we are in a CODE section, ignore contiguous CODE addresses.
        # These are not the start of a new section.
        # However: if we are not in CODE, any upcoming address is a new section.
        # Do this so we can detect contiguous non-CODE sections.
        confirmed = [
            conf_addr
            for (conf_addr, conf_type) in sorted(self.confirmed_addrs.items())
            if self.cur_section_type != SectionType.CODE
            or conf_type != self.cur_section_type
        ]

        index = bisect.bisect_right(confirmed, addr)
        if index < len(confirmed):
            self.section_end = confirmed[index]
        else:
            self.section_end = self.end

        return new_type

    def _get_code_for(self, addr: int) -> List[DisasmLiteInst]:
        """Start disassembling at the given address."""
        # If we are reading a code block beyond the first, see if we already
        # have disassembled instructions beginning at the specified address.
        # For a CODE/ADDR/CODE function, we might get lucky and produce the
        # correct instruction after the jump table's junk instructions.
        for track in self.code_tracks:
            for i, inst in enumerate(track):
                if inst.address == addr:
                    return track[i:]

        # If we are here, we don't have the instructions.
        # Todo: Could try to be clever here and disassemble only
        # as much as we probably need (i.e. if a jump table is between CODE
        # blocks, there are probably only a few bad instructions after the
        # jump table is finished. We could disassemble up to the next verified
        # code address and stitch it together)

        blob_cropped = self.blob[addr - self.start :]
        instructions = [
            DisasmLiteInst(*inst)
            for inst in disassembler.disasm_lite(blob_cropped, addr)
        ]
        self.code_tracks.append(instructions)
        return instructions

    def _handle_jump(self, inst: DisasmLiteInst):
        # If this is a regular jump and its destination is within the
        # bounds of the binary data (i.e. presumed function size)
        # add it to our list of confirmed addresses.
        if inst.op_str[0] == "0":
            value = int(inst.op_str, 16)
            self._insert_confirmed_addr(value, SectionType.CODE)

        # If this is jumping into a table of addresses, save the destination
        elif (match := displacement_regex.match(inst.op_str)) is not None:
            value = int(match.group(1), 16)
            self._insert_confirmed_addr(value, SectionType.ADDR_TAB)

    def analysis(self):
        self.cur_addr = self.start

        while (sect_type := self._next_section(self.cur_addr)) is not None:
            self.section_start = self.cur_addr

            if sect_type == SectionType.CODE:
                instructions = self._get_code_for(self.cur_addr)

                # If we didn't get any instructions back, something is wrong.
                # i.e. We can only read part of the full instruction that is up next.
                if len(instructions) == 0:
                    # Nudge the current addr so we will eventually move on to the
                    # next section.
                    # Todo: Maybe we could just call it quits here
                    self.cur_addr += 1
                    break

                for inst in instructions:
                    # section_end is updated as we read instructions.
                    # If we are into a jump/data table and would read
                    # a junk instruction, stop here.
                    if self.cur_addr >= self.section_end:
                        break

                    # print(f"{inst.address:x} : {inst.mnemonic} {inst.op_str}")

                    if inst.mnemonic in JUMP_MNEMONICS:
                        self._handle_jump(inst)
                        # Todo: log calls too (unwind section)
                    elif inst.mnemonic == "mov":
                        # Todo: maintain pairing of data/jump tables
                        if (match := displacement_regex.match(inst.op_str)) is not None:
                            value = int(match.group(1), 16)
                            self._insert_confirmed_addr(value, SectionType.DATA_TAB)

                    # Do this instead of copying instruction address.
                    # If there is only one instruction, we would get stuck here.
                    self.cur_addr += inst.size

                # End of for loop on instructions.
                # We are at the end of the section or the entire function.
                # Cut out only the valid instructions for this section
                # and save it for later.

                # Todo: don't need to iter on every instruction here.
                # They are already in order.
                instruction_slice = [
                    inst for inst in instructions if inst.address < self.section_end
                ]
                self._finish_section(SectionType.CODE, instruction_slice)

            elif sect_type == SectionType.ADDR_TAB:
                # Clamp to multiple of 4 (dwords)
                read_size = ((self.section_end - self.cur_addr) // 4) * 4
                offsets = range(self.section_start, self.section_start + read_size, 4)
                dwords = self.blob[
                    self.cur_addr - self.start : self.cur_addr - self.start + read_size
                ]
                addrs = [addr for addr, in struct.iter_unpack("<L", dwords)]
                for addr in addrs:
                    # Todo: the fact that these are jump table destinations
                    # should factor into the label name.
                    self._insert_confirmed_addr(addr, SectionType.CODE)

                jump_table = list(zip(offsets, addrs))
                # for (t0,t1) in jump_table:
                #     print(f"{t0:x} : --> {t1:x}")

                self._finish_section(SectionType.ADDR_TAB, jump_table)
                self.cur_addr = self.section_end

            else:
                # Todo: variable data size?
                read_size = self.section_end - self.cur_addr
                offsets = range(self.section_start, self.section_start + read_size)
                bytes_ = self.blob[
                    self.cur_addr - self.start : self.cur_addr - self.start + read_size
                ]
                data = [b for b, in struct.iter_unpack("<B", bytes_)]

                data_table = list(zip(offsets, data))
                # for (t0,t1) in data_table:
                #     print(f"{t0:x} : value {t1:02x}")

                self._finish_section(SectionType.DATA_TAB, data_table)
                self.cur_addr = self.section_end
