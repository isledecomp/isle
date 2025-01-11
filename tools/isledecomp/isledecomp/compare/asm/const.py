# Duplicates removed, according to the mnemonics capstone uses.
# e.g. je and jz are the same instruction. capstone uses je.
# See: /arch/X86/X86GenAsmWriter.inc in the capstone repo.
JUMP_MNEMONICS = {
    "ja",
    "jae",
    "jb",
    "jbe",
    "jcxz",  # unused?
    "je",
    "jecxz",
    "jg",
    "jge",
    "jl",
    "jle",
    "jmp",
    "jne",
    "jno",
    "jnp",
    "jns",
    "jo",
    "jp",
    "js",
}

# Guaranteed to be a single operand.
SINGLE_OPERAND_INSTS = {"push", "call", *JUMP_MNEMONICS}
