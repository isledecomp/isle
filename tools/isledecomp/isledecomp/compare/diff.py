from difflib import SequenceMatcher
from typing import Dict, List, Tuple

CombinedDiffInput = List[Tuple[str, str]]
CombinedDiffOutput = Dict


def combined_diff(
    diff: SequenceMatcher,
    orig_combined: CombinedDiffInput,
    recomp_combined: CombinedDiffInput,
    context_size: int = 3,
) -> CombinedDiffOutput:
    """We want to diff the original and recomp assembly. The "combined" assembly
    input has two components: the address of the instruction and the assembly text.
    We have already diffed the text only. This is the SequenceMatcher object.
    The SequenceMatcher can generate "opcodes" that describe how to turn "Text A"
    into "Text B". These refer to list indices of the original arrays, so we can
    use those to create the final diff and include the address for each line of assembly.
    This is almost the same procedure as the difflib.unified_diff function, but we
    are reusing the already generated SequenceMatcher object.
    """

    unified_diff = []

    for group in diff.get_grouped_opcodes(context_size):
        diff_chunk = []

        for code, i1, i2, j1, j2 in group:
            if code == "equal":
                # The sections are equal, so the list slices are guaranteed
                # to have the same length. We only need the diffed value (asm text)
                # from one of the lists, but we need the addresses from both.
                # Use zip to put the two lists together and then take out what we want.
                both = [
                    (a, b, c)
                    for ((a, b), (c, _)) in zip(
                        orig_combined[i1:i2], recomp_combined[j1:j2]
                    )
                ]
                diff_chunk.append({"both": both})
            else:
                diff_chunk.append(
                    {
                        "orig": orig_combined[i1:i2],
                        "recomp": recomp_combined[j1:j2],
                    }
                )

        unified_diff.append(diff_chunk)

    return unified_diff
