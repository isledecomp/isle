"""Converts x86 machine code into text (i.e. assembly). The end goal is to
compare the code in the original and recomp binaries, using longest common
subsequence (LCS), i.e. difflib.SequenceMatcher.
The capstone library takes the raw bytes and gives us the mnemnonic
and operand(s) for each instruction. We need to "sanitize" the text further
so that virtual addresses are replaced by symbol name or a generic
placeholder string."""

import re
from typing import Callable, List, Optional, Tuple
from collections import namedtuple
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

disassembler = Cs(CS_ARCH_X86, CS_MODE_32)

ptr_replace_regex = re.compile(r"(?P<data_size>\w+) ptr \[(?P<addr>0x[0-9a-fA-F]+)\]")

DisasmLiteInst = namedtuple("DisasmLiteInst", "address, size, mnemonic, op_str")


def from_hex(string: str) -> Optional[int]:
    try:
        return int(string, 16)
    except ValueError:
        pass

    return None


def get_float_size(size_str: str) -> int:
    return 8 if size_str == "qword" else 4


class ParseAsm:
    def __init__(
        self,
        relocate_lookup: Optional[Callable[[int], bool]] = None,
        name_lookup: Optional[Callable[[int], str]] = None,
        float_lookup: Optional[Callable[[int, int], Optional[str]]] = None,
    ) -> None:
        self.relocate_lookup = relocate_lookup
        self.name_lookup = name_lookup
        self.float_lookup = float_lookup
        self.replacements = {}
        self.number_placeholders = True

    def reset(self):
        self.replacements = {}

    def is_relocated(self, addr: int) -> bool:
        if callable(self.relocate_lookup):
            return self.relocate_lookup(addr)

        return False

    def float_replace(self, addr: int, data_size: int) -> Optional[str]:
        if callable(self.float_lookup):
            float_str = self.float_lookup(addr, data_size)
            if float_str is not None:
                return f"{float_str} (FLOAT)"

        return None

    def lookup(self, addr: int) -> Optional[str]:
        """Return a replacement name for this address if we find one."""
        if (cached := self.replacements.get(addr, None)) is not None:
            return cached

        if callable(self.name_lookup):
            if (name := self.name_lookup(addr)) is not None:
                self.replacements[addr] = name
                return name

        return None

    def replace(self, addr: int) -> str:
        """Same function as lookup above, but here we return a placeholder
        if there is no better name to use."""
        if (name := self.lookup(addr)) is not None:
            return name

        # The placeholder number corresponds to the number of addresses we have
        # already replaced. This is so the number will be consistent across the diff
        # if we can replace some symbols with actual names in recomp but not orig.
        idx = len(self.replacements) + 1
        placeholder = f"<OFFSET{idx}>" if self.number_placeholders else "<OFFSET>"
        self.replacements[addr] = placeholder
        return placeholder

    def sanitize(self, inst: DisasmLiteInst) -> Tuple[str, str]:
        if len(inst.op_str) == 0:
            # Nothing to sanitize
            return (inst.mnemonic, "")

        # For jumps or calls, if the entire op_str is a hex number, the value
        # is a relative offset.
        # Otherwise (i.e. it looks like `dword ptr [address]`) it is an
        # absolute indirect that we will handle below.
        # Providing the starting address of the function to capstone.disasm has
        # automatically resolved relative offsets to an absolute address.
        # We will have to undo this for some of the jumps or they will not match.
        op_str_address = from_hex(inst.op_str)

        if op_str_address is not None:
            if inst.mnemonic == "call":
                return (inst.mnemonic, self.replace(op_str_address))

            if inst.mnemonic == "jmp":
                # The unwind section contains JMPs to other functions.
                # If we have a name for this address, use it. If not,
                # do not create a new placeholder. We will instead
                # fall through to generic jump handling below.
                potential_name = self.lookup(op_str_address)
                if potential_name is not None:
                    return (inst.mnemonic, potential_name)

            if inst.mnemonic.startswith("j"):
                # i.e. if this is any jump
                # Show the jump offset rather than the absolute address
                jump_displacement = op_str_address - (inst.address + inst.size)
                return (inst.mnemonic, hex(jump_displacement))

        def filter_out_ptr(match):
            """Helper for re.sub, see below"""
            offset = from_hex(match.group("addr"))

            if offset is not None:
                # We assume this is always an address to replace
                placeholder = self.replace(offset)
                return f'{match.group("data_size")} ptr [{placeholder}]'

            # Strict regex should ensure we can read the hex number.
            # But just in case: return the string with no changes
            return match.group(0)

        def float_ptr_replace(match):
            offset = from_hex(match.group("addr"))

            if offset is not None:
                # If we can find a variable name for this pointer, use it.
                placeholder = self.lookup(offset)

                # Read what's under the pointer and show the decimal value.
                if placeholder is None:
                    placeholder = self.float_replace(
                        offset, get_float_size(match.group("data_size"))
                    )

                # If we can't read the float, use a regular placeholder.
                if placeholder is None:
                    placeholder = self.replace(offset)

                return f'{match.group("data_size")} ptr [{placeholder}]'

            # Strict regex should ensure we can read the hex number.
            # But just in case: return the string with no changes
            return match.group(0)

        if inst.mnemonic.startswith("f"):
            # If floating point instruction
            op_str = ptr_replace_regex.sub(float_ptr_replace, inst.op_str)
        else:
            op_str = ptr_replace_regex.sub(filter_out_ptr, inst.op_str)

        # Performance hack:
        # Skip this step if there is nothing left to consider replacing.
        if "0x" in op_str:
            # Replace immediate values with name or placeholder (where appropriate)
            words = op_str.split(", ")
            for i, word in enumerate(words):
                try:
                    inttest = int(word, 16)
                    # If this value is a virtual address, it is referenced absolutely,
                    # which means it must be in the relocation table.
                    if self.is_relocated(inttest):
                        words[i] = self.replace(inttest)
                except ValueError:
                    pass
            op_str = ", ".join(words)

        return inst.mnemonic, op_str

    def parse_asm(self, data: bytes, start_addr: Optional[int] = 0) -> List[str]:
        asm = []

        for inst in disassembler.disasm_lite(data, start_addr):
            # Use heuristics to disregard some differences that aren't representative
            # of the accuracy of a function (e.g. global offsets)
            result = self.sanitize(DisasmLiteInst(*inst))
            # mnemonic + " " + op_str
            asm.append(" ".join(result))

        return asm
