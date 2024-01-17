import re

REGISTER_LIST = set(
    [
        "ax",
        "bp",
        "bx",
        "cx",
        "di",
        "dx",
        "eax",
        "ebp",
        "ebx",
        "ecx",
        "edi",
        "edx",
        "esi",
        "esp",
        "si",
        "sp",
    ]
)
WORDS = re.compile(r"\w+")


def get_registers(line: str):
    to_replace = []
    # use words regex to find all matching positions:
    for match in WORDS.finditer(line):
        reg = match.group(0)
        if reg in REGISTER_LIST:
            to_replace.append((reg, match.start()))
    return to_replace


def replace_register(
    lines: list[str], start_line: int, reg: str, replacement: str
) -> list[str]:
    return [
        line.replace(reg, replacement) if i >= start_line else line
        for i, line in enumerate(lines)
    ]


# Is it possible to make new_asm the same as original_asm by swapping registers?
def can_resolve_register_differences(original_asm, new_asm):
    # Split the ASM on spaces to get more granularity, and so
    # that we don't modify the original arrays passed in.
    original_asm = [part for line in original_asm for part in line.split()]
    new_asm = [part for line in new_asm for part in line.split()]

    # Swapping ain't gonna help if the lengths are different
    if len(original_asm) != len(new_asm):
        return False

    # Look for the mismatching lines
    for i, original_line in enumerate(original_asm):
        new_line = new_asm[i]
        if new_line != original_line:
            # Find all the registers to replace
            to_replace = get_registers(original_line)

            for replace in to_replace:
                (reg, reg_index) = replace
                replacing_reg = new_line[reg_index : reg_index + len(reg)]
                if replacing_reg in REGISTER_LIST:
                    if replacing_reg != reg:
                        # Do a three-way swap replacing in all the subsequent lines
                        temp_reg = "&" * len(reg)
                        new_asm = replace_register(new_asm, i, replacing_reg, temp_reg)
                        new_asm = replace_register(new_asm, i, reg, replacing_reg)
                        new_asm = replace_register(new_asm, i, temp_reg, reg)
                else:
                    # No replacement to do, different code, bail out
                    return False
    # Check if the lines are now the same
    for i, original_line in enumerate(original_asm):
        if new_asm[i] != original_line:
            return False
    return True
