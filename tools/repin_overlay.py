#!/usr/bin/env python3
"""Re-pin overlay outputs after a deliberate clean-source edit.

For each given repo-relative path: update the output's clean-input pin to
the checked file's hash, re-render its operations over the new clean bytes
(every anchor must still seat uniquely - drift still refuses), and update
the effective pin to the freshly rendered bytes.  Also refreshes the
translation-unit source pin when the path owns one.
"""
import hashlib
import json
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))
import byte_identity  # noqa: E402


def main() -> int:
    paths = sys.argv[1:]
    if not paths:
        print("usage: repin_overlay.py <repo-relative-path> [...]",
              file=sys.stderr)
        return 2
    manifest_path = ROOT / "tools/byte_identity_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    outputs = manifest["source_overlay"]["outputs"]
    by_path = {o["path"]: o for o in outputs}
    for path in paths:
        if path not in by_path:
            print(f"repin_overlay: {path} is not overlay-owned",
                  file=sys.stderr)
            return 2
        by_path[path]["clean"] = hashlib.sha256(
            (ROOT / path).read_bytes()).hexdigest()
    overlay = byte_identity.validate_source_overlay(
        manifest["source_overlay"], ROOT, repin_paths=set(paths)
    )
    clean_inputs = {}
    for output in overlay["outputs"]:
        logical = output["logical_path"]
        clean_inputs[logical] = (
            (ROOT / logical).read_bytes()
            if output["clean"]["state"] == "present" else b""
        )
    rendered = byte_identity.render_source_overlay_outputs(
        overlay, clean_inputs, repin_paths=set(paths)
    )
    for path in paths:
        data = rendered[path]
        by_path[path]["effective"] = hashlib.sha256(data).hexdigest()
        by_path[path]["size"] = len(data)
        for unit in manifest.get("translation_units", []):
            if unit["source"] == path:
                unit["source_sha256"] = by_path[path]["clean"]
        print(f"repinned {path}: clean {by_path[path]['clean'][:12]} "
              f"effective {by_path[path]['effective'][:12]} "
              f"size {len(data)}")
    manifest_path.write_text(json.dumps(manifest, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
