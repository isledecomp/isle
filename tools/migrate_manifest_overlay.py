#!/usr/bin/env python3
"""One-shot migration of the byte-identity manifest's source_overlay section
from the v1 (rich canvas/fragment-pin) schema to the lean v2 schema.

The converter renders every operation of the OLD manifest with the OLD
renderer (both supplied explicitly), records each generator's semantic bytes
and seated body, and emits the equivalent lean record: single-tier anchors,
run-compressed identifier lists, canonical type strings, and residual layout
overrides only where the recorded canvas deviates from the new renderer's
canonical emission.  Every converted generator is re-rendered through the NEW
renderer and required to reproduce the recorded body byte-for-byte before the
manifest is written; the whole converted overlay is then validated and
rendered end-to-end as a final gate.

All sections other than source_overlay are carried over unchanged.

Usage:
  python3 tools/migrate_manifest_overlay.py \
      --old-code <path to v1 byte_identity.py> \
      --old-manifest <path to v1 byte_identity_manifest.json> \
      [--repo <checkout root>] [--output tools/byte_identity_manifest.json]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path

REPO_DEFAULT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


KIND_SHORT = {
    "line_reservation_v1": "lines",
    "include_dependency_v1": "include",
    "include_seat_v1": "include_seat",
    "empty_compound_statements_v1": "empty_scopes",
    "inline_budget_noop_statements_v1": "noop_assign",
    "compile_time_layout_assert_seat_v1": "size_asserts",
    "conditional_declarations_v1": "cond",
    "composed_typed_sequence_v1": "seq",
    "local_symbol_id_carrier_v1": "local_ids",
    "qualified_member_comdat_emission_probe_v1": "member_probe",
    "list_cursor_delete_emission_probe_v1": "cursor_probe",
    "discarded_console_crt_pull_v1": "console_pull",
    "discarded_import_library_probe_v1": "import_probe",
    "recursive_frame_texture_refresh_probe_v1": "texture_probe",
    "synthetic_crt_pull_v1": "crt_pull",
    "archive_pull_seed_function_v1": "seed_fn",
    "archive_pull_seed_sequence_v1": "seed_seq",
    "source_range_relocation_v1": "reloc",
    "synthetic_template_member_supplier_v1": "template_supplier",
    "synthetic_member_call_supplier_v1": "call_supplier",
    "synthetic_discarded_relocation_ring_v1": "reloc_ring",
    "record_header_v1": "record_header",
    "debug_assert_reseat_v1": "assert_reseat",
    "synthetic_constant_pool_tu_v1": "const_pool",
    "literal_first_use_alias_v1": "literal_alias",
}
SHAPE_SHORT = {
    "forward": "fwd",
    "forward_sequence": "fwd_seq",
    "empty_class": "empty_class",
    "enum": "enum",
    "typedef_builtin": "typedef",
    "function_prototype": "proto",
    "unused_class_void_member_sequence": "class",
}
DROP_CONST_PARAMS = {
    "content_role", "comment_policy", "composition_policy", "operator",
    "integer_literal_format",
}
BOUNDARY_SHORT = {
    "after_newline": None,
    "file_start": "start",
    "file_end": "end",
    "before_next_token": "before_token",
    "after_previous_token": "after_token",
}
NUMBER_TAIL_RE = re.compile(r"(.*?)(\d+)$")


class MigrationError(RuntimeError):
    pass


def check(condition: bool, message: str) -> None:
    if not condition:
        raise MigrationError(message)


def compress_types(new_module, value):
    """Replace every cpp_type AST with its canonical string, recursively."""
    if isinstance(value, dict):
        if value.get("kind") == "cpp_type":
            return new_module.render_source_overlay_cpp_type(value)
        return {key: compress_types(new_module, item)
                for key, item in value.items()}
    if isinstance(value, list):
        return [compress_types(new_module, item) for item in value]
    return value


def run_compress_names(names: list[str]) -> list:
    """Collapse stem+number runs (>=3) in an ordered name list."""
    out: list = []
    index = 0
    while index < len(names):
        match = NUMBER_TAIL_RE.fullmatch(names[index])
        if not match:
            out.append(names[index])
            index += 1
            continue
        stem, digits = match.group(1), match.group(2)
        width, first = len(digits), int(digits)
        stop = index + 1
        while stop < len(names):
            follow = NUMBER_TAIL_RE.fullmatch(names[stop])
            if not (follow and follow.group(1) == stem
                    and len(follow.group(2)) == width
                    and int(follow.group(2)) == first + (stop - index)):
                break
            stop += 1
        if stop - index >= 3 and stem:
            run = {"stem": stem, "first": first, "count": stop - index}
            if width != len(str(first)):
                run["width"] = width
            out.append(run)
        else:
            out.extend(names[index:stop])
        index = stop
    return out


def indentation_bytes(units: list[dict]) -> bytes:
    return b"".join(
        (b"\t" if item["unit"] == "tab" else b" ") * item["count"]
        for item in units
    )


def leading_units(line: bytes) -> list[dict]:
    """Decompose a leading whitespace run into canonical alternating units."""
    units: list[dict] = []
    for character in line[: len(line) - len(line.lstrip(b" \t"))]:
        unit = "tab" if character == 9 else "space"
        if units and units[-1]["unit"] == unit:
            units[-1]["count"] += 1
        else:
            units.append({"unit": unit, "count": 1})
    return units


def lean_anchor_from_tier(anchor: dict, tier: dict) -> dict:
    out = {"ctx": tier["context_sha256"]}
    if tier["before_token_count"] != 32:
        out["b"] = tier["before_token_count"]
    if tier["after_token_count"] != 32:
        out["a"] = tier["after_token_count"]
    boundary = anchor["structural_seat"]["byte_boundary"]["kind"]
    short = BOUNDARY_SHORT[boundary]
    if short:
        out["at"] = short
    if boundary == "after_newline":
        out["line_before"] = anchor["structural_seat"]["before_line_sha256"]
        out["line_after"] = anchor["structural_seat"]["after_line_sha256"]
    return out


class OverlayMigrator:
    def __init__(self, old_module, new_module, repo: Path):
        self.old = old_module
        self.new = new_module
        self.repo = repo
        self.records: dict[int, tuple[bytes, bytes]] = {}
        self.relocation_ranges: dict[tuple[str, str], bytes] = {}
        self.clean_inputs: dict[str, bytes] = {}
        self.anchor_offsets: dict[tuple[str, str, str], int] = {}
        self.stats = {
            "identity": 0, "override": 0, "override_bytes": 0,
            "fallback_tier_anchors": 0,
        }

    # ------------------------------------------------------------ old render
    def render_old(self, manifest_overlay: dict) -> dict:
        original_finish = self.old._finish_source_overlay_fragment
        records = self.records

        def recording_finish(generator, semantic):
            body = original_finish(generator, semantic)
            records[id(generator)] = (semantic, body)
            return body

        self.old._finish_source_overlay_fragment = recording_finish
        try:
            normalized = self.old.validate_source_overlay(
                manifest_overlay, self.repo
            )
        finally:
            self.old._finish_source_overlay_fragment = original_finish
        self.clean_inputs = self.old._read_source_overlay_clean_inputs(
            self.repo, normalized["outputs"]
        )
        for receipt in normalized["anchor_evidence"]:
            for record in receipt.get("anchor_evidence", []):
                key = (
                    record["logical_path"], record["operation_id"],
                    record["role"],
                )
                self.anchor_offsets[key] = record["selected_byte_offset"]
        for output in normalized["outputs"]:
            for operation in output["operations"]:
                generator = operation["generator"]
                if (operation["action"] == "delete"
                        and generator["kind"] == "source_range_relocation_v1"):
                    key = (
                        operation["id"],
                        generator["params"]["range_dependency_id"],
                    )
                    self.relocation_ranges[key] = self.records[id(generator)][1]
        return normalized

    # -------------------------------------------------------- lean synthesis
    def lean_generator(self, generator: dict) -> dict:
        kind = generator["kind"]
        if kind == "composed_typed_sequence_v1":
            return self.lean_composite(generator)
        candidate = self.lean_leaf_params(generator)
        if (kind == "source_range_relocation_v1"
                and "byte_destination" in generator["params"]):
            # Relocation producer: the pipeline never renders it as a
            # fragment -- the authenticated removed range itself is the body.
            return candidate
        _semantic_old, body_old = self.records[id(generator)]
        lean = self.fit_layout(candidate, body_old, generator)
        return lean

    def lean_leaf_params(self, generator: dict) -> dict:
        kind = generator["kind"]
        params = {
            key: item for key, item in generator["params"].items()
            if key != "renderer_layout" and key not in DROP_CONST_PARAMS
        }
        params = compress_types(self.new, params)
        if kind == "line_reservation_v1":
            return {"k": "lines", "n": params["physical_line_count"]}
        if kind != "declaration_sequence_v1":
            return {"k": KIND_SHORT[kind], **params}
        shape = params.pop("shape")
        out: dict = {"k": SHAPE_SHORT[shape]}
        if params.get("tag") == "class":
            params.pop("tag")
        if "identifier" in params:
            out["id"] = params.pop("identifier")
        if shape == "enum":
            out["members"] = run_compress_names(
                [item["identifier"] for item in params.pop("enumerators")]
            )
            if params.pop("trailing_comma"):
                out["trailing_comma"] = True
        elif shape == "forward_sequence":
            run = dict(params.pop("identifiers"))
            out["identifiers"] = run
        elif shape == "unused_class_void_member_sequence":
            members = params.pop("members")
            transitions = params.pop("access_transitions")
            all_definitions = all(
                member["kind"] == "empty_void_method_definition"
                for member in members
            )
            uniform_inline = len({
                member["inline_specifier"] for member in members
            }) == 1
            if all_definitions and uniform_inline:
                if members[0]["inline_specifier"]:
                    out["inline"] = True
                out["members"] = run_compress_names(
                    [member["identifier"] for member in members]
                )
            else:
                out["members"] = [
                    (
                        member["identifier"]
                        if member["kind"] == "empty_void_method_definition"
                        and not member["inline_specifier"]
                        else {"decl": member["identifier"]}
                        if member["kind"] == "void_method_declaration"
                        else {"id": member["identifier"], "inline": True}
                    )
                    for member in members
                ]
            if transitions:
                out["access"] = transitions
        out.update(params)
        return out

    def lean_composite(self, generator: dict) -> dict:
        params = generator["params"]
        _semantic_old, body_old = self.records[id(generator)]
        items = []
        for item in params["items"]:
            child = self.lean_generator(item["generator"])
            child["line"] = item["relative_lines"][0]
            items.append(child)
        items = self.collapse_forward_runs(items)
        lean = {
            "k": "seq", "lines": params["physical_line_count"],
            "items": items,
        }
        rendered = self.render_new(lean)
        check(rendered == body_old,
              "composite conversion does not reproduce the recorded body")
        return lean

    @staticmethod
    def collapse_forward_runs(items: list[dict]) -> list[dict]:
        out: list[dict] = []
        index = 0
        while index < len(items):
            item = items[index]
            match = None
            if item.get("k") == "fwd" and set(item) <= {"k", "id", "line", "tag"}:
                match = NUMBER_TAIL_RE.fullmatch(item["id"])
            if not match:
                out.append(item)
                index += 1
                continue
            stem, digits = match.group(1), match.group(2)
            width, first, line = len(digits), int(digits), item["line"]
            stop = index + 1
            while stop < len(items):
                follow = items[stop]
                if (follow.get("k") != "fwd"
                        or set(follow) - {"k", "id", "line", "tag"}
                        or follow.get("tag") != item.get("tag")):
                    break
                follow_match = NUMBER_TAIL_RE.fullmatch(follow.get("id", ""))
                if not (follow_match and follow_match.group(1) == stem
                        and len(follow_match.group(2)) == width
                        and int(follow_match.group(2)) == first + (stop - index)
                        and follow["line"] == line + (stop - index)):
                    break
                stop += 1
            if stop - index >= 3 and stem:
                run = {
                    "k": "fwd_run", "stem": stem, "first": first,
                    "count": stop - index, "line": line,
                }
                if width != len(str(first)):
                    run["width"] = width
                if item.get("tag"):
                    run["tag"] = item["tag"]
                out.append(run)
            else:
                out.extend(items[index:stop])
            index = stop
        return out

    # ------------------------------------------------------------ new render
    def render_new(self, lean: dict) -> bytes:
        normalized = self.new.validate_source_overlay_generator(
            lean, "migration.gen"
        )
        return self.new.render_source_overlay_generator(
            normalized, relocation_ranges=self.relocation_ranges
        )

    def fit_layout(self, candidate: dict, body_old: bytes,
                   generator: dict) -> dict:
        """Attach the minimal residual layout override set and verify it."""
        rendered = self.render_new(dict(candidate))
        if rendered == body_old:
            self.stats["identity"] += 1
            return candidate
        layout = generator["params"]["renderer_layout"]
        content = layout["content_lines"]
        semantic_lines = [
            line for line in rendered.split(b"\n") if line.strip(b" \t")
        ]
        check(len(semantic_lines) == len(content),
              f"semantic line count differs for {generator['kind']}")
        override: dict = {}
        positions = [item["relative_line"] for item in content]
        count = layout["physical_line_count"]
        if positions != list(range(1, len(content) + 1)) or count != len(content):
            override["lines"] = count
            override["at"] = positions
        indent = []
        for index, (item, line) in enumerate(zip(content, semantic_lines)):
            layout_indent = indentation_bytes(item["indentation_units"])
            own = line[: len(line) - len(line.lstrip(b" \t"))]
            if layout_indent != own:
                indent.append([index + 1, item["indentation_units"]])
        if indent:
            override["indent"] = indent
        blank = [
            [run["first"], run["count"], run["indentation_units"]]
            for run in layout["transparent_line_runs"]
            if run["indentation_units"]
        ]
        if blank:
            override["blank_indent"] = blank
        if layout["line_ending"] == "none":
            override["nl"] = False
        elif not layout["terminal_newline"]:
            override["nl"] = "open"
        with_override = dict(candidate)
        with_override.update(override)
        rendered = self.render_new(dict(with_override))
        check(rendered == body_old,
              f"layout override does not reproduce the recorded body "
              f"for {generator['kind']}")
        self.stats["override"] += 1
        self.stats["override_bytes"] += len(json.dumps(override))
        return with_override

    # -------------------------------------------------------------- lean ops
    def referenced_operation_ids(self, normalized: dict) -> set[str]:
        referenced: set[str] = set()

        def walk(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key in ("source_operation_id", "required_operation_ids"):
                        if isinstance(item, str):
                            referenced.add(item)
                        elif isinstance(item, list):
                            referenced.update(item)
                    walk(item)
            elif isinstance(value, list):
                for item in value:
                    walk(item)

        walk(normalized)
        return referenced

    def lean_anchor(self, anchor: dict, logical_path: str,
                    operation_id: str, role: str) -> dict:
        """Convert to the strongest single tier that resolves today.

        The v1 fallback chain tolerated clean-input drift by falling back to
        narrower contexts; the lean anchor stores exactly the tier that
        uniquely resolves on the pinned clean input, verified against the v1
        resolution's byte offset.
        """
        clean = self.clean_inputs[logical_path]
        expected_offset = self.anchor_offsets[
            (logical_path, operation_id, role)
        ]
        for index, tier in enumerate(anchor["tiers"]):
            candidate = lean_anchor_from_tier(anchor, tier)
            normalized = self.new.validate_source_overlay_anchor(
                candidate, "migration.anchor"
            )
            try:
                offset = self.new.resolve_source_overlay_anchor(
                    clean, normalized, "migration.anchor"
                )
            except self.new.ByteIdentityError:
                continue
            check(offset == expected_offset,
                  f"lean anchor resolves to a different seat: "
                  f"{logical_path}:{operation_id}:{role}")
            if index:
                self.stats["fallback_tier_anchors"] += 1
            return candidate
        raise MigrationError(
            f"no anchor tier resolves on the pinned clean input: "
            f"{logical_path}:{operation_id}:{role}"
        )

    def lean_operation(self, operation: dict, logical_path: str,
                       referenced: set[str]) -> dict:
        action = operation["action"]
        operation_id = operation["id"]
        out: dict = {}
        if action == "insert":
            out["op"] = "insert"
            out["anchor"] = self.lean_anchor(
                operation["start_anchor"], logical_path, operation_id,
                "insert",
            )
        elif action in ("delete", "replace"):
            out["op"] = action
            out["from"] = self.lean_anchor(
                operation["start_anchor"], logical_path, operation_id,
                "range_start",
            )
            out["to"] = self.lean_anchor(
                operation["end_anchor"], logical_path, operation_id,
                "range_end",
            )
            pin = operation["baseline_input_range"]
            out["removed"] = {
                "sha256": pin["baseline_sha256"],
                "size": pin["baseline_size"],
            }
        else:
            out["op"] = "append"
        if (operation["id"] in referenced
                or "required_graph_admission_ids" in operation):
            out["id"] = operation["id"]
        if "required_graph_admission_ids" in operation:
            out["needs"] = list(operation["required_graph_admission_ids"])
        out["gen"] = self.lean_generator(operation["generator"])
        return out

    def lean_overlay(self, normalized: dict) -> dict:
        referenced = self.referenced_operation_ids(normalized)
        # Generated-TU generation_operation_ids reach the CMake plan; keep
        # those operation ids stable across the migration.
        generated_paths = {
            unit["logical_path"]
            for unit in normalized["graph"]["generated_translation_units"]
        }
        for output in normalized["outputs"]:
            if output["logical_path"] in generated_paths:
                referenced.update(
                    operation["id"] for operation in output["operations"]
                )
        outputs = []
        for output in normalized["outputs"]:
            record: dict = {"path": output["logical_path"]}
            if output["clean"]["state"] == "present":
                record["clean"] = output["clean"]["baseline_sha256"]
            record["effective"] = output["effective"]["baseline_sha256"]
            record["size"] = output["effective"]["baseline_size"]
            record["ops"] = [
                self.lean_operation(
                    operation, output["logical_path"], referenced
                )
                for operation in output["operations"]
            ]
            outputs.append(record)
        graph = {
            "generated_tus": [
                {
                    "path": unit["logical_path"],
                    "ordinal": unit["source_ordinal"],
                    "after": unit["insert_after"],
                    **(
                        {"before": unit["insert_before"]}
                        if unit["insert_before"] is not None else {}
                    ),
                }
                for unit in normalized["graph"]["generated_translation_units"]
            ],
            "link_admissions": normalized["graph"]["link_admissions"],
        }
        return {"schema": 2, "outputs": outputs, "graph": graph}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old-code", required=True, type=Path)
    parser.add_argument("--old-manifest", required=True, type=Path)
    parser.add_argument("--repo", type=Path, default=REPO_DEFAULT)
    parser.add_argument("--output", type=Path,
                        default=REPO_DEFAULT / "tools/byte_identity_manifest.json")
    arguments = parser.parse_args()

    repo = arguments.repo.resolve()
    sys.path.insert(0, str(repo / "tools"))
    old_module = load_module("byte_identity_v1", arguments.old_code.resolve())
    new_module = load_module("byte_identity_lean", repo / "tools/byte_identity.py")

    raw = arguments.old_manifest.read_text(encoding="utf-8")
    manifest = json.loads(raw)

    migrator = OverlayMigrator(old_module, new_module, repo)
    print("rendering the v1 overlay with the v1 renderer ...")
    normalized_old = migrator.render_old(manifest["source_overlay"])
    print(f"  {len(normalized_old['outputs'])} outputs, "
          f"{sum(len(o['operations']) for o in normalized_old['outputs'])} ops, "
          f"{len(migrator.records)} rendered generators")

    print("converting to the lean schema (per-fragment verified) ...")
    lean_overlay = migrator.lean_overlay(normalized_old)
    print(f"  leaves: {migrator.stats['identity']} identity, "
          f"{migrator.stats['override']} with residual overrides "
          f"({migrator.stats['override_bytes']} override bytes); "
          f"{migrator.stats['fallback_tier_anchors']} anchors re-seated at "
          f"their resolving tier")

    print("validating and rendering the lean overlay end-to-end ...")
    lean_normalized = new_module.validate_source_overlay(
        json.loads(json.dumps(lean_overlay)), repo
    )
    for output in normalized_old["outputs"]:
        relative = output["logical_path"]
        actual = lean_normalized["effective_by_path"][relative]
        check(actual["sha256"] == output["effective"]["baseline_sha256"]
              and actual["size"] == output["effective"]["baseline_size"],
              f"lean effective view differs for {relative}")
    print("  every effective output matches its v1 pin")

    out_manifest = {
        key: (lean_overlay if key == "source_overlay" else value)
        for key, value in manifest.items()
    }
    arguments.output.write_text(
        json.dumps(out_manifest, indent=1) + "\n", encoding="utf-8"
    )
    new_size = arguments.output.stat().st_size
    print(f"wrote {arguments.output} ({new_size} bytes; "
          f"was {len(raw)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
