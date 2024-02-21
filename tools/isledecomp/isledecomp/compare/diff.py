from difflib import SequenceMatcher
from typing import Dict, List, Tuple

CombinedDiffInput = List[Tuple[str, str]]
CombinedDiffOutput = List[Tuple[str, List[Dict[str, Tuple[str, str]]]]]


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
        subgroups = []

        # Keep track of the addresses we've seen in this diff group.
        # This helps create the "@@" line. (Does this have a name?)
        # Do it this way because not every line in each list will have an
        # address. If our context begins or ends on a line that does not
        # have one, we will have an incomplete range string.
        orig_addrs = set()
        recomp_addrs = set()

        first, last = group[0], group[-1]
        orig_range = len(orig_combined[first[1] : last[2]])
        recomp_range = len(recomp_combined[first[3] : last[4]])

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

                for orig_addr, _, recomp_addr in both:
                    if orig_addr is not None:
                        orig_addrs.add(orig_addr)

                    if recomp_addr is not None:
                        recomp_addrs.add(recomp_addr)

                subgroups.append({"both": both})
            else:
                for orig_addr, _ in orig_combined[i1:i2]:
                    if orig_addr is not None:
                        orig_addrs.add(orig_addr)

                for recomp_addr, _ in recomp_combined[j1:j2]:
                    if recomp_addr is not None:
                        recomp_addrs.add(recomp_addr)

                subgroups.append(
                    {
                        "orig": orig_combined[i1:i2],
                        "recomp": recomp_combined[j1:j2],
                    }
                )

        orig_sorted = sorted(orig_addrs)
        recomp_sorted = sorted(recomp_addrs)

        # We could get a diff group that has no original addresses.
        # This might happen for a stub function where we are not able to
        # produce even a single instruction from the original.
        # In that case, show the best slug line that we can.
        def peek_front(list_, default=""):
            try:
                return list_[0]
            except IndexError:
                return default

        orig_first = peek_front(orig_sorted)
        recomp_first = peek_front(recomp_sorted)

        diff_slug = f"@@ -{orig_first},{orig_range} +{recomp_first},{recomp_range} @@"

        unified_diff.append((diff_slug, subgroups))

    return unified_diff
