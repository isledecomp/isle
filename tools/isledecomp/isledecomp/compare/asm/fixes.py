import re
from typing import List, Tuple, Set

DiffOpcode = Tuple[str, int, int, int, int]

REG_FIND = re.compile(r"(?: |\[)(e?[a-d]x|e?[s,d]i|[a-d][l,h]|e?[b,s]p)")

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
    codes: List[DiffOpcode], orig_asm: List[str], recomp_asm: List[str]
) -> Set[int]:
    """Can we resolve the diffs between orig and recomp by patching
    swapped cmp instructions?
    For example:
        cmp eax, ebx            cmp ebx, eax
        je .label               je .label

        cmp eax, ebx            cmp ebx, eax
        ja .label               jb .label
    """

    fixed_lines = set()

    for code, i1, i2, j1, j2 in codes:
        # To save us the trouble of finding "compatible" cmp instructions
        # use the diff information we already have.
        if code != "replace":
            continue

        # If the ranges in orig and recomp are not equal, use the shorter one
        for i, j in zip(range(i1, i2), range(j1, j2)):
            if can_cmp_swap(orig_asm[i : i + 2], recomp_asm[j : j + 2]):
                # Patch cmp
                fixed_lines.add(j)

                # Patch the jump if necessary
                patched = patch_jump(orig_asm[i + 1], recomp_asm[j + 1])
                # We only register a fix if it actually matches
                if orig_asm[i + 1] == patched:
                    fixed_lines.add(j + 1)

    return fixed_lines


def effective_match_possible(orig_asm: List[str], recomp_asm: List[str]) -> bool:
    # We can only declare an effective match based on the text
    # so you need the same amount of "stuff" in each
    if len(orig_asm) != len(recomp_asm):
        return False

    # mnemonic_orig = [inst.partition(" ")[0] for inst in orig_asm]
    # mnemonic_recomp = [inst.partition(" ")[0] for inst in recomp_asm]

    # Cannot change mnemonics. Must be same starting list
    # TODO: Fine idea but this will exclude jump swaps for cmp operand order
    # if sorted(mnemonic_orig) != sorted(mnemonic_recomp):
    #    return False

    return True


def find_regs_used(inst: str) -> List[str]:
    return REG_FIND.findall(inst)


def find_regs_changed(a: str, b: str) -> List[Tuple[str, str]]:
    """For instructions a, b, return the pairs of registers that were used.
    This is not a very precise way to compare the instructions, so it depends
    on the input being two instructions that would match *except* for
    the register choice."""
    return zip(REG_FIND.findall(a), REG_FIND.findall(b))


def bad_register_swaps(
    swaps: Set[int], orig_asm: List[str], recomp_asm: List[str]
) -> Set[int]:
    """The list of recomp indices in `swaps` tells which instructions are
    a match for orig except for the registers used. From that list, check
    whether a register swap should not be allowed.
    For now, this means checking for `push` instructions where the register
    was not used in any other register swaps on previous instructions."""
    rejects = set()

    # Foreach `push` instruction where we have excused the diff
    pushes = [j for j in swaps if recomp_asm[j].startswith("push")]

    for j in pushes:
        okay = False
        # Get the operands in each
        reg = (orig_asm[j].partition(" ")[2], recomp_asm[j].partition(" ")[2])
        # If this isn't a register at all, ignore it
        try:
            int(reg[0], 16)
            continue
        except ValueError:
            pass

        # For every other excused diff that is *not* a push:
        # Assumes same index in orig as in recomp, but so does our naive match
        for k in swaps.difference(pushes):
            changed_regs = find_regs_changed(orig_asm[k], recomp_asm[k])
            if reg in changed_regs or reg[::-1] in changed_regs:
                okay = True
                break

        if not okay:
            rejects.add(j)

    return rejects


# Instructions that result in a change to the first operand
MODIFIER_INSTRUCTIONS = ("adc", "add", "lea", "mov", "neg", "sbb", "sub", "pop", "xor")


def instruction_alters_regs(inst: str, regs: Set[str]) -> bool:
    (mnemonic, _, op_str) = inst.partition(" ")
    (first_operand, _, __) = op_str.partition(", ")

    return (mnemonic in MODIFIER_INSTRUCTIONS and first_operand in regs) or (
        mnemonic == "call" and "eax" in regs
    )


def relocate_instructions(
    codes: List[DiffOpcode], orig_asm: List[str], recomp_asm: List[str]
) -> Set[int]:
    """Collect the list of instructions deleted from orig and inserted
    into recomp, according to the diff opcodes. Using this list, match up
    any pairs of instructions that we assume to be relocated and return
    the indices in recomp where this has occurred.
    For now, we are checking only for an exact match on the instruction.
    We are not checking whether the given instruction can be moved from
    point A to B. (i.e. does this set a register that is used by the
    instructions between A and B?)"""
    deletes = {
        i for code, i1, i2, _, __ in codes for i in range(i1, i2) if code == "delete"
    }
    inserts = [
        j for code, _, __, j1, j2 in codes for j in range(j1, j2) if code == "insert"
    ]

    relocated = set()

    for j in inserts:
        line = recomp_asm[j]
        recomp_regs_used = set(find_regs_used(line))
        for i in deletes:
            # Check for exact match.
            # TODO: This will grab the first instruction that matches.
            # We should probably use the nearest index instead, if it matters
            if orig_asm[i] == line:
                # To account for a move in either direction
                reloc_start = min(i, j)
                reloc_end = max(i, j)
                if not any(
                    instruction_alters_regs(orig_asm[k], recomp_regs_used)
                    for k in range(reloc_start, reloc_end)
                ):
                    relocated.add(j)
                    deletes.remove(i)
                    break

    return relocated


DWORD_REGS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
WORD_REGS = ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp")
BYTE_REGS = ("ah", "al", "bh", "bl", "ch", "cl", "dh", "dl")


def naive_register_replacement(orig_asm: List[str], recomp_asm: List[str]) -> Set[int]:
    """Replace all registers of the same size with a placeholder string.
    After doing that, compare orig and recomp again.
    Return indices from recomp that are now equal to the same index in orig.
    This requires orig and recomp to have the same number of instructions,
    but this is already a requirement for effective match."""
    orig_raw = "\n".join(orig_asm)
    recomp_raw = "\n".join(recomp_asm)

    # TODO: hardly the most elegant way to do this.
    for rdw in DWORD_REGS:
        orig_raw = orig_raw.replace(rdw, "~reg4")
        recomp_raw = recomp_raw.replace(rdw, "~reg4")

    for rw in WORD_REGS:
        orig_raw = orig_raw.replace(rw, "~reg2")
        recomp_raw = recomp_raw.replace(rw, "~reg2")

    for rb in BYTE_REGS:
        orig_raw = orig_raw.replace(rb, "~reg1")
        recomp_raw = recomp_raw.replace(rb, "~reg1")

    orig_scrubbed = orig_raw.split("\n")
    recomp_scrubbed = recomp_raw.split("\n")

    return {
        j for j in range(len(recomp_scrubbed)) if orig_scrubbed[j] == recomp_scrubbed[j]
    }


def find_effective_match(
    codes: List[DiffOpcode], orig_asm: List[str], recomp_asm: List[str]
) -> bool:
    """Check whether the two sequences of instructions are an effective match.
    Meaning: do they differ only by instruction order or register selection?"""
    if not effective_match_possible(orig_asm, recomp_asm):
        return False

    already_equal = {
        j for code, _, __, j1, j2 in codes for j in range(j1, j2) if code == "equal"
    }

    # We need to come up with some answer for each of these lines
    recomp_lines_disputed = {
        j
        for code, _, __, j1, j2 in codes
        for j in range(j1, j2)
        if code in ("insert", "replace")
    }

    cmp_swaps = patch_cmp_swaps(codes, orig_asm, recomp_asm)
    # This naive result includes lines that already match, so remove those
    naive_swaps = naive_register_replacement(orig_asm, recomp_asm).difference(
        already_equal
    )
    relocates = relocate_instructions(codes, orig_asm, recomp_asm)

    bad_swaps = bad_register_swaps(naive_swaps, orig_asm, recomp_asm)

    corrections = set().union(
        naive_swaps.difference(bad_swaps),
        cmp_swaps,
        relocates,
    )

    return corrections.issuperset(recomp_lines_disputed)


def assert_fixup(asm: List[Tuple[str, str]]):
    """Detect assert calls and replace the code filename and line number
    values with macros (from assert.h)."""
    for i, (_, line) in enumerate(asm):
        if "_assert" in line and line.startswith("call"):
            try:
                asm[i - 3] = (asm[i - 3][0], "push __LINE__")
                asm[i - 2] = (asm[i - 2][0], "push __FILE__")
            except IndexError:
                continue
