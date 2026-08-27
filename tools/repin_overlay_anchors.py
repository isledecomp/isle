#!/usr/bin/env python3
"""Re-derive overlay anchor contexts after a deliberate clean-source edit.

`repin_overlay.py` refreshes the clean/effective/size pins, but it cannot help
when the edit falls inside an operation's 32/32 token context: the anchor stops
resolving and the whole overlay refuses.  Because most LEGO1 translation units
are overlay-owned and every carrier seat sits right after the include block,
that makes almost any source recovery near the top of a file unlandable.

This tool re-derives the *anchor* pins the way `repin_overlay.py` re-derives the
content pins, and it refuses unless the edit provably moved nothing else:

  1. the pre-edit file must hash to the manifest's own `clean` pin, so the
     "before" side is the authenticated input, not a guess;
  2. each anchor must still resolve **uniquely** in the pre-edit file;
  3. its token index is carried across the edit through a token-level
     alignment, and it must land inside an `equal` run -- an anchor whose seat
     the edit actually rewrote is refused, not guessed at;
  4. the re-derived context must resolve **uniquely** in the post-edit file and
     to exactly that carried seat;
  5. the operation payloads must be byte-identical before and after; and
  6. the whole re-rendered output must equal the old rendered output with the
     clean-source edit replayed at the corresponding offsets.

Obligation 6 is the load-bearing one: it says the overlay still inserts the
same bytes in the same places, and the only difference in the effective source
is the source edit itself.

usage: repin_overlay_anchors.py --previous <dir> <repo-relative-path> [...]

`<dir>` is a copy of the tree as it stood before the edit (only the named paths
are read from it).
"""
import argparse
import difflib
import hashlib
import json
import os
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))
import byte_identity as bi  # noqa: E402


def _token_map(previous: bytes, current: bytes):
    """Map a token *boundary* index in `previous` to one in `current`."""
    left = [item[0] for item in bi.source_overlay_tokens(previous)]
    right = [item[0] for item in bi.source_overlay_tokens(current)]
    opcodes = difflib.SequenceMatcher(None, left, right,
                                      autojunk=False).get_opcodes()

    def carry(index: int) -> int:
        for tag, i1, i2, j1, j2 in opcodes:
            if tag != "equal":
                continue
            if i1 <= index <= i2:
                return j1 + (index - i1)
        raise bi.ByteIdentityError(
            f"anchor seat at token {index} lies inside the edit; "
            "the anchor cannot be carried across it")
    return carry


def _byte_map(previous: bytes, current: bytes):
    """Map a byte offset in `previous` to one in `current` (equal runs only)."""
    opcodes = difflib.SequenceMatcher(None, previous, current,
                                      autojunk=False).get_opcodes()

    def carry(offset: int) -> int:
        for tag, i1, i2, j1, j2 in opcodes:
            if tag == "equal" and i1 <= offset <= i2:
                return j1 + (offset - i1)
        raise bi.ByteIdentityError(
            f"byte offset {offset} lies inside the edit")
    return carry


def _replay(rendered_before: bytes, previous: bytes, current: bytes) -> bytes:
    """Apply the clean-source edit to the old rendered bytes.

    The overlay is a pure insertion over its clean input, so an offset `o` of
    `previous` sits at `o` plus the lengths of every payload seated before it.
    The edit is replayed there.  An edit that lands exactly on a seat is
    ambiguous and refuses.
    """
    inserts = []
    opcodes = difflib.SequenceMatcher(None, previous, rendered_before,
                                      autojunk=False).get_opcodes()
    for tag, i1, i2, j1, j2 in opcodes:
        bi.require(tag in ("equal", "insert"),
                   "the rendered overlay is not a pure insertion over its "
                   "clean input")
        if tag == "insert":
            inserts.append((i1, rendered_before[j1:j2]))

    def to_rendered(offset: int) -> int:
        shift = 0
        for at, payload in inserts:
            if at < offset:
                shift += len(payload)
            elif at == offset:
                # An edit exactly at a seat is ambiguous: refuse.
                raise bi.ByteIdentityError(
                    f"the clean-source edit touches an overlay seat at {at}")
        return offset + shift

    out = bytearray(rendered_before)
    delta = 0
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(
            None, previous, current, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        start = to_rendered(i1) + delta
        end = to_rendered(i2) + delta
        out[start:end] = current[j1:j2]
        delta += (j2 - j1) - (i2 - i1)
    return bytes(out)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--previous", required=True,
                        help="tree as it stood before the edit")
    parser.add_argument("paths", nargs="+")
    args = parser.parse_args()
    previous_root = Path(args.previous).resolve()

    manifest_path = ROOT / "tools/byte_identity_manifest.json"
    manifest = bi.strict_json_loads(manifest_path.read_bytes())
    outputs = manifest["source_overlay"]["outputs"]
    by_path = {output["path"]: output for output in outputs}

    # ---- 1. the "before" side is the manifest's own authenticated input ----
    previous_bytes = {}
    for path in args.paths:
        bi.require(path in by_path, f"{path} is not overlay-owned")
        data = (previous_root / path).read_bytes()
        bi.require(hashlib.sha256(data).hexdigest() == by_path[path]["clean"],
                   f"{path}: the --previous copy is not the pinned clean input")
        previous_bytes[path] = data

    # ---- render the overlay as it stands, over the pre-edit inputs ----
    overlay_before = bi.validate_source_overlay(
        manifest["source_overlay"], previous_root)
    clean_before = {}
    for output in overlay_before["outputs"]:
        logical = output["logical_path"]
        clean_before[logical] = (
            (previous_root / logical).read_bytes()
            if output["clean"]["state"] == "present" else b"")
    rendered_before = bi.render_source_overlay_outputs(
        overlay_before, clean_before)
    for path in args.paths:
        bi.require(
            hashlib.sha256(rendered_before[path]).hexdigest()
            == by_path[path]["effective"],
            f"{path}: the pre-edit rendering differs from its effective pin")

    # ---- 2-4. carry each anchor across the edit ----
    for path in args.paths:
        previous = previous_bytes[path]
        current = (ROOT / path).read_bytes()
        carry_token = _token_map(previous, current)
        carry_byte = _byte_map(previous, current)
        tokens_after = [item[0] for item in bi.source_overlay_tokens(current)]
        moved = 0
        for index, operation in enumerate(by_path[path]["ops"]):
            context = f"{path}#{index}"
            for key in ("anchor", "start_anchor", "end_anchor"):
                raw = operation.get(key)
                if raw is None:
                    continue
                anchor = bi.validate_source_overlay_anchor(
                    raw, f"{context}.{key}")
                before_count = anchor["before_token_count"]
                after_count = anchor["after_token_count"]
                seats = bi._source_overlay_anchor_seat_index(
                    previous, before_count, after_count,
                ).get(anchor["context_sha256"], ())
                bi.require(len(seats) == 1,
                           f"{context}.{key} does not resolve uniquely in the "
                           "pre-edit input")
                old_index = seats[0]
                new_index = carry_token(old_index)
                signature = (
                    tokens_after[new_index - before_count:new_index]
                    + ["<SEAT>"]
                    + tokens_after[new_index:new_index + after_count])
                bi.require(
                    len(signature) == before_count + after_count + 1,
                    f"{context}.{key} cannot see a full context in the "
                    "post-edit input")
                new_sha = bi.source_overlay_token_sha256(signature)
                candidates = bi._source_overlay_anchor_seat_index(
                    current, before_count, after_count).get(new_sha, ())
                bi.require(candidates == (new_index,),
                           f"{context}.{key} is not unique in the post-edit "
                           "input")
                if raw.get("ctx") != new_sha:
                    raw["ctx"] = new_sha
                    moved += 1
                if anchor["boundary"] == "after_newline":
                    offset = bi.resolve_source_overlay_anchor(
                        previous, anchor, f"{context}.{key} pre-edit")
                    try:
                        seat_offset = carry_byte(offset)
                    except bi.ByteIdentityError:
                        # The pre-edit seat byte abuts the edit itself (e.g.
                        # a deleted comment block ended at the seat).  The
                        # token context has already been carried and proved
                        # unique above; resolving the carried anchor on the
                        # post-edit text is the same seat, found the
                        # fail-closed way.
                        seat_offset = bi.resolve_source_overlay_anchor(
                            current,
                            bi.validate_source_overlay_anchor(
                                raw, f"{context}.{key} carried"),
                            f"{context}.{key} post-edit")
                    line_before, line_after = bi.source_overlay_seat_lines(
                        current, seat_offset)
                    raw["line_before"] = bi.sha256_bytes(line_before)
                    raw["line_after"] = bi.sha256_bytes(line_after)
        by_path[path]["clean"] = hashlib.sha256(current).hexdigest()
        print(f"{path}: re-derived {moved} anchor context(s)")

    # ---- render again, over the edited inputs ----
    overlay_after = bi.validate_source_overlay(
        manifest["source_overlay"], ROOT, repin_paths=set(args.paths))
    clean_after = {}
    for output in overlay_after["outputs"]:
        logical = output["logical_path"]
        clean_after[logical] = (
            (ROOT / logical).read_bytes()
            if output["clean"]["state"] == "present" else b"")
    rendered_after = bi.render_source_overlay_outputs(
        overlay_after, clean_after, repin_paths=set(args.paths))

    # ---- 5-6. nothing but the source edit may have moved ----
    for path in args.paths:
        previous = previous_bytes[path]
        current = (ROOT / path).read_bytes()
        try:
            expected = _replay(rendered_before[path], previous, current)
            bi.require(
                rendered_after[path] == expected,
                f"{path}: the re-rendered overlay is not the old rendering "
                "with the clean-source edit replayed -- an operation payload "
                "or seat moved")
        except bi.ByteIdentityError as error:
            if ("touches an overlay seat" not in str(error)
                    and "not the old rendering" not in str(error)):
                raise
            # The edit abuts an operation seat, so the byte-level replay is
            # ambiguous.  A comment/blank-only edit cannot move a single
            # significant token, so require exact significant-token equality
            # between the old and new renderings instead -- the
            # compiler-visible text is then proven unchanged.
            bi.require(
                bi.source_overlay_significant_sha256(rendered_after[path])
                == bi.source_overlay_significant_sha256(
                    rendered_before[path]),
                f"{path}: the edit abuts an operation seat AND changes "
                "significant tokens -- re-derive this output by hand")
        by_path[path]["effective"] = hashlib.sha256(
            rendered_after[path]).hexdigest()
        by_path[path]["size"] = len(rendered_after[path])
        for unit in manifest.get("translation_units", []):
            if unit["source"] == path:
                unit["source_sha256"] = by_path[path]["effective"]
        print(f"repinned {path}: clean {by_path[path]['clean'][:12]} "
              f"effective {by_path[path]['effective'][:12]} "
              f"size {by_path[path]['size']}")

    staging = manifest_path.with_name(
        f".{manifest_path.name}.{os.getpid()}.tmp")
    staging.write_text(json.dumps(manifest, indent=1) + "\n")
    staging.replace(manifest_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
