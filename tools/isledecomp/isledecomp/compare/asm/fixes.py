from difflib import SequenceMatcher
from typing import List


ALLOWED_JUMP_SWAPS = (
    ("ja", "jb"),
    ("jae", "jbe"),
    ("jb", "ja"),
    ("jbe", "jae"),
    ("jg", "jl"),
    ("jge", "jle"),
    ("jl", "jg"),
    ("jle", "jge"),
    ("je", "je"),
    ("jne", "jne"),
)


def jump_swap_ok(a: str, b: str) -> bool:
    """For the instructions a,b, are they both jump instructions
    that are compatible with a swapped cmp operand order?"""
    # Grab the mnemonic
    (jmp_a, _, __) = a.partition(" ")
    (jmp_b, _, __) = b.partition(" ")

    return (jmp_a, jmp_b) in ALLOWED_JUMP_SWAPS


def is_operand_swap(a: str, b: str) -> bool:
    """This is a hack to avoid parsing the operands. It's not as simple as
    breaking on the comma because templates or string literals interfere
    with this. Instead we check:
        1. Do both strings use the exact same set of characters?
        2. If we do break on ', ', is the first token of each different?
    2 is needed to catch an edge case like:
        cmp eax, dword ptr [ecx + 0x1234]
        cmp ecx, dword ptr [eax + 0x1234]
    """
    return a.partition(", ")[0] != b.partition(", ")[0] and sorted(a) == sorted(b)


def can_cmp_swap(orig: List[str], recomp: List[str]) -> bool:
    # Make sure we have 1 cmp and 1 jmp for both
    if len(orig) != 2 or len(recomp) != 2:
        return False

    if not orig[0].startswith("cmp") or not recomp[0].startswith("cmp"):
        return False

    if not orig[1].startswith("j") or not recomp[1].startswith("j"):
        return False

    # Checking two things:
    # Are the cmp operands flipped?
    # Is the jump instruction compatible with a flip?
    return is_operand_swap(orig[0], recomp[0]) and jump_swap_ok(orig[1], recomp[1])


def patch_jump(a: str, b: str) -> str:
    """For jump instructions a, b, return `(mnemonic_a) (operand_b)`.
    The reason to do it this way (instead of just returning `a`) is that
    the jump instructions might use different displacement offsets
    or labels. If we just replace `b` with `a`, this diff would be
    incorrectly eliminated."""
    (mnemonic_a, _, __) = a.partition(" ")
    (_, __, operand_b) = b.partition(" ")

    return mnemonic_a + " " + operand_b


def patch_cmp_swaps(
    sm: SequenceMatcher, orig_asm: List[str], recomp_asm: List[str]
) -> bool:
    """Can we resolve the diffs between orig and recomp by patching
    swapped cmp instructions?
    For example:
        cmp eax, ebx            cmp ebx, eax
        je .label               je .label

        cmp eax, ebx            cmp ebx, eax
        ja .label               jb .label
    """

    # Copy the instructions so we can patch
    # TODO: If we change our strategy to allow multiple rounds of patching,
    # we should modify the recomp array directly.
    new_asm = recomp_asm[::]

    codes = sm.get_opcodes()

    for code, i1, i2, j1, j2 in codes:
        # To save us the trouble of finding "compatible" cmp instructions
        # use the diff information we already have.
        if code != "replace":
            continue

        # If the ranges in orig and recomp are not equal, use the shorter one
        for i, j in zip(range(i1, i2), range(j1, j2)):
            if can_cmp_swap(orig_asm[i : i + 2], recomp_asm[j : j + 2]):
                # Patch cmp
                new_asm[j] = orig_asm[i]

                # Patch the jump if necessary
                new_asm[j + 1] = patch_jump(orig_asm[i + 1], recomp_asm[j + 1])

    return orig_asm == new_asm
