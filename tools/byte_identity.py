#!/usr/bin/env python3
"""Fail-closed planning and compiler-launch support for byte-identical builds.

This first production phase deliberately does not splice COMDATs.  It validates
and materializes reproducible non-emitting entropy recipes, then atomically
passes manifest-listed translation units through the configured compiler.  Its
audit records say ``pass_through_not_composed`` and can never claim that a donor
or final image is complete.  Any function splice request is fatal.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid


TOOLS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS_DIR))
# Importing the generator must not create tools/__pycache__ in the source tree.
sys.dont_write_bytecode = True
import entropy as entropy_generator  # noqa: E402


SCHEMA_VERSION = 1
PHASE = "pass_through_launcher_v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RECIPE_ID_RE = re.compile(r"^e_[0-9a-f]{12}$")
TARGET_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.+-]*$")
SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".C"}
SUPPORTED_GENERATORS = {"Ninja", "Unix Makefiles"}
SANITIZED_ENVIRONMENT = [
    "CL",
    "_CL_",
    "MSVC_CL_BIN",
    "WINE*",
]
FORBIDDEN_RECIPE_WORDS = (
    "opaque",
    "retail_payload",
    "retail-payload",
    "synthetic_padding",
    "emitted_padding",
    "rdata_pool",
    "discarded_reloc",
    "discarded-reloc",
    "crt_pull",
    "supplier_tu",
    "supplier-tu",
    "/include",
)
ACTIVE_LOCKS = []


class ByteIdentityError(RuntimeError):
    """A manifest, provenance, launch, or verification gate failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ByteIdentityError(message)


def unique_json_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, f"manifest contains duplicate key: {key}")
        result[key] = value
    return result


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    try:
        return sha256_bytes(path.read_bytes())
    except OSError as error:
        raise ByteIdentityError(f"cannot hash {path}: {error}") from error


def atomic_write(path: Path, data: bytes, *, if_changed: bool = False) -> None:
    """Atomically install data; optionally preserve mtime when unchanged."""
    if if_changed and path.is_file() and path.read_bytes() == data:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def atomic_json(path: Path, value: object) -> None:
    atomic_write(
        path,
        (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )


def exact_keys(value: dict, allowed: set[str], context: str) -> None:
    unknown = set(value) - allowed
    require(not unknown, f"{context} has unknown keys: {sorted(unknown)}")


def require_sha(value: object, context: str) -> str:
    require(isinstance(value, str) and SHA256_RE.fullmatch(value) is not None,
            f"{context} must be a lowercase SHA-256")
    return value


def resolve_relative(root: Path, relative: object, context: str) -> tuple[str, Path]:
    require(isinstance(relative, str) and relative, f"{context} must be a non-empty path")
    require("\\" not in relative and ";" not in relative, f"{context} must use a safe POSIX path")
    pure = PurePosixPath(relative)
    require(not pure.is_absolute() and ".." not in pure.parts, f"{context} must stay below the source tree")
    resolved_root = root.resolve()
    candidate = (resolved_root / Path(*pure.parts)).resolve()
    try:
        candidate.relative_to(resolved_root)
    except ValueError as error:
        raise ByteIdentityError(f"{context} escapes the source tree") from error
    require(candidate.is_file(), f"{context} does not exist: {relative}")
    return pure.as_posix(), candidate


def compiler_path(path: object) -> Path:
    require(isinstance(path, str) and path, "configured compiler path is missing")
    candidate = Path(path)
    if not candidate.is_absolute():
        located = shutil.which(path)
        require(located is not None, f"configured compiler is not executable: {path}")
        candidate = Path(located)
    candidate = candidate.resolve()
    require(candidate.is_file() and os.access(candidate, os.X_OK),
            f"configured compiler is not executable: {candidate}")
    return candidate


def declared_toolchain_path(root: Path, relative: object, context: str) -> tuple[str, Path]:
    require(isinstance(relative, str) and relative, f"{context} must be a non-empty path")
    require("\\" not in relative and ";" not in relative,
            f"{context} must use a safe POSIX path")
    pure = PurePosixPath(relative)
    require(not pure.is_absolute() and ".." not in pure.parts,
            f"{context} must stay below the compiler root")
    resolved_root = root.resolve()
    candidate = (resolved_root / Path(*pure.parts)).resolve()
    try:
        candidate.relative_to(resolved_root)
    except ValueError as error:
        raise ByteIdentityError(f"{context} escapes the compiler root") from error
    return pure.as_posix(), candidate


def recipe_output(build_dir: Path, header_sha256: str) -> Path:
    return build_dir.resolve() / "byte-identity/generated" / f"entropy_{header_sha256}.h"


def audit_object_path(build_dir: Path, target: str, source_relative: str) -> Path:
    source_id = hashlib.sha256(source_relative.encode("utf-8")).hexdigest()[:16]
    return build_dir.resolve() / "byte-identity/audit/objects" / target / f"{source_id}.json"


def audit_unlisted_path(build_dir: Path, target: str, source_relative: str) -> Path:
    source_id = hashlib.sha256(source_relative.encode("utf-8")).hexdigest()[:16]
    return (
        build_dir.resolve()
        / "byte-identity/audit/unlisted-pass-through"
        / target
        / f"{source_id}.json"
    )


def invalidate_framework_verdict(build_dir: Path) -> Path:
    verdict_path = build_dir.resolve() / "byte-identity/audit/framework-verdict.json"
    try:
        verdict_path.unlink()
    except FileNotFoundError:
        pass
    return verdict_path


def validate_manifest(
    manifest_path: Path,
    source_dir: Path,
    build_dir: Path,
    *,
    configured_compiler: str | None = None,
    compiler_id: str | None = None,
    compiler_version: str | None = None,
    generator: str | None = None,
) -> dict:
    """Load the fixed schema and return normalized, fully validated state."""
    source_root = source_dir.resolve()
    build_root = build_dir.resolve()
    require(source_root != build_root,
            "in-source byte-identity builds are forbidden")
    try:
        raw = manifest_path.read_bytes()
        manifest = json.loads(raw, object_pairs_hook=unique_json_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ByteIdentityError(f"cannot read manifest {manifest_path}: {error}") from error
    require(isinstance(manifest, dict), "manifest root must be an object")
    exact_keys(
        manifest,
        {"schema", "phase", "toolchain", "translation_units", "archives", "images"},
        "manifest",
    )
    require(manifest.get("schema") == SCHEMA_VERSION, "unsupported byte-identity schema")
    require(manifest.get("phase") == PHASE, f"manifest phase must be {PHASE}")

    toolchain = manifest.get("toolchain")
    require(isinstance(toolchain, dict), "toolchain must be an object")
    exact_keys(
        toolchain,
        {
            "compiler_sha256",
            "compiler_id",
            "compiler_version",
            "keep_compile_debug",
            "max_child_seconds",
            "provenance",
            "compiler_root_parent_levels",
            "compiler_support_files",
            "required_absent_toolchain_files",
            "runtime_executables",
            "sanitized_environment",
        },
        "toolchain",
    )
    expected_compiler_sha = require_sha(toolchain.get("compiler_sha256"), "compiler_sha256")
    require(toolchain.get("compiler_id") == "MSVC", "only the pinned MSVC toolchain is supported")
    require(toolchain.get("compiler_version") == "10.20", "only MSVC 4.20 is supported")
    require(toolchain.get("keep_compile_debug") == "/Zi", "byte-identity compiles must retain /Zi")
    timeout = toolchain.get("max_child_seconds")
    require(isinstance(timeout, int) and not isinstance(timeout, bool)
            and 1 <= timeout <= 900, "max_child_seconds is out of range")
    provenance = toolchain.get("provenance")
    require(isinstance(provenance, dict), "toolchain provenance must be an object")
    exact_keys(
        provenance,
        {
            "retail_use",
            "payload_source",
            "forbid_emitted_padding",
            "forbid_opaque_objects",
            "forbid_source_tree_writes",
        },
        "toolchain provenance",
    )
    require(
        provenance
        == {
            "retail_use": "oracle_only_no_payload_copy",
            "payload_source": "configured_compiler_output",
            "forbid_emitted_padding": True,
            "forbid_opaque_objects": True,
            "forbid_source_tree_writes": True,
        },
        "hard provenance policy changed",
    )

    root_parent_levels = toolchain.get("compiler_root_parent_levels")
    require(isinstance(root_parent_levels, int) and not isinstance(root_parent_levels, bool)
            and 0 <= root_parent_levels <= 6,
            "compiler_root_parent_levels is out of range")
    support_files = toolchain.get("compiler_support_files")
    require(isinstance(support_files, list), "compiler_support_files must be an array")
    normalized_support = []
    support_names = set()
    for support_index, support in enumerate(support_files):
        support_context = f"compiler_support_files[{support_index}]"
        require(isinstance(support, dict), f"{support_context} must be an object")
        exact_keys(support, {"path", "sha256"}, support_context)
        relative = support.get("path")
        require(isinstance(relative, str) and relative, f"{support_context}.path is invalid")
        pure = PurePosixPath(relative)
        require("\\" not in relative and ";" not in relative
                and not pure.is_absolute() and ".." not in pure.parts,
                f"{support_context}.path must stay below the compiler root")
        relative = pure.as_posix()
        require(relative not in support_names, f"duplicate compiler support file: {relative}")
        support_names.add(relative)
        normalized_support.append(
            {"path": relative, "sha256": require_sha(support.get("sha256"), f"{support_context}.sha256")}
        )
    required_absent = toolchain.get("required_absent_toolchain_files")
    require(isinstance(required_absent, list)
            and all(isinstance(item, str) and item for item in required_absent),
            "required_absent_toolchain_files must be strings")
    normalized_absent = []
    for absent_index, relative in enumerate(required_absent):
        pure = PurePosixPath(relative)
        require("\\" not in relative and ";" not in relative
                and not pure.is_absolute() and ".." not in pure.parts,
                f"required_absent_toolchain_files[{absent_index}] is unsafe")
        normalized_absent.append(pure.as_posix())
    require(len(set(normalized_absent)) == len(normalized_absent),
            "required_absent_toolchain_files contains duplicates")
    require(not set(normalized_absent).intersection(support_names),
            "toolchain files cannot be both required and absent")

    runtime_executables = toolchain.get("runtime_executables")
    require(isinstance(runtime_executables, list), "runtime_executables must be an array")
    normalized_runtimes = []
    runtime_names = set()
    for runtime_index, runtime in enumerate(runtime_executables):
        runtime_context = f"runtime_executables[{runtime_index}]"
        require(isinstance(runtime, dict), f"{runtime_context} must be an object")
        exact_keys(runtime, {"name", "sha256"}, runtime_context)
        name = runtime.get("name")
        require(isinstance(name, str) and TARGET_RE.fullmatch(name) is not None,
                f"{runtime_context}.name is invalid")
        require(name not in runtime_names, f"duplicate runtime executable: {name}")
        runtime_names.add(name)
        normalized_runtimes.append(
            {"name": name, "sha256": require_sha(runtime.get("sha256"), f"{runtime_context}.sha256")}
        )

    sanitized_environment = toolchain.get("sanitized_environment")
    require(sanitized_environment == SANITIZED_ENVIRONMENT,
            "sanitized_environment must match the hard compiler environment policy")
    toolchain_fingerprint = sha256_bytes(
        json.dumps(
            {
                "compiler_sha256": expected_compiler_sha,
                "root_parent_levels": root_parent_levels,
                "support_files": normalized_support,
                "required_absent": normalized_absent,
                "runtime_executables": normalized_runtimes,
                "sanitized_environment": SANITIZED_ENVIRONMENT,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    if configured_compiler is not None:
        configured = compiler_path(configured_compiler)
        require(sha256_file(configured) == expected_compiler_sha,
                f"configured compiler hash differs: {configured}")
        compiler_root = configured.parent
        for _ in range(root_parent_levels):
            compiler_root = compiler_root.parent
        for support in normalized_support:
            _, support_path = declared_toolchain_path(
                compiler_root, support["path"], f"compiler support file {support['path']}"
            )
            require(support_path.is_file(), f"compiler support file is absent: {support['path']}")
            require(sha256_file(support_path) == support["sha256"],
                    f"compiler support file hash differs: {support['path']}")
        for relative in normalized_absent:
            _, absent_path = declared_toolchain_path(
                compiler_root, relative, f"required absent toolchain file {relative}"
            )
            require(not absent_path.exists() and not absent_path.is_symlink(),
                    f"toolchain file must remain absent: {relative}")
        for runtime in normalized_runtimes:
            located = shutil.which(runtime["name"])
            require(located is not None,
                    f"runtime executable is absent from PATH: {runtime['name']}")
            require(sha256_file(Path(located).resolve()) == runtime["sha256"],
                    f"runtime executable hash differs: {runtime['name']}")
    if compiler_id is not None:
        require(compiler_id == toolchain["compiler_id"], "configured compiler ID differs")
    if compiler_version is not None:
        require(compiler_version == toolchain["compiler_version"], "configured compiler version differs")
    if generator is not None:
        require(generator in SUPPORTED_GENERATORS, f"unsupported CMake generator: {generator}")

    translation_units = manifest.get("translation_units")
    require(isinstance(translation_units, list) and translation_units,
            "translation_units must be a non-empty array")
    normalized_units = []
    owners = set()
    recipe_ids = set()
    for unit_index, unit in enumerate(translation_units):
        context = f"translation_units[{unit_index}]"
        require(isinstance(unit, dict), f"{context} must be an object")
        exact_keys(
            unit,
            {
                "target",
                "source",
                "source_sha256",
                "mode",
                "command_policy",
                "donors",
                "functions",
                "completion",
            },
            context,
        )
        target = unit.get("target")
        require(isinstance(target, str) and TARGET_RE.fullmatch(target) is not None,
                f"{context}.target is invalid")
        source_relative, source_path = resolve_relative(source_dir, unit.get("source"), f"{context}.source")
        source_sha = require_sha(unit.get("source_sha256"), f"{context}.source_sha256")
        require(sha256_file(source_path) == source_sha, f"source hash differs: {source_relative}")
        owner = (target, source_relative)
        require(owner not in owners, f"duplicate translation-unit owner: {owner}")
        owners.add(owner)
        require(unit.get("mode") == "pass_through", f"{context}: only pass_through is implemented")

        command_policy = unit.get("command_policy")
        require(isinstance(command_policy, dict), f"{context}.command_policy must be an object")
        exact_keys(
            command_policy,
            {"required_flags", "forbidden_prefixes", "allowed_force_includes"},
            f"{context}.command_policy",
        )
        required_flags = command_policy.get("required_flags")
        forbidden_prefixes = command_policy.get("forbidden_prefixes")
        require(isinstance(required_flags, list) and all(isinstance(item, str) for item in required_flags),
                f"{context}.required_flags must be strings")
        require(isinstance(forbidden_prefixes, list) and all(isinstance(item, str) for item in forbidden_prefixes),
                f"{context}.forbidden_prefixes must be strings")
        require("/Zi" in required_flags and any(item in required_flags for item in ("/c", "-c")),
                f"{context} must require /Zi and a compile-only flag")
        folded_forbidden = {item.casefold() for item in forbidden_prefixes}
        require({"/gl", "-gl", "/z7", "-z7"}.issubset(folded_forbidden),
                f"{context} must forbid alternate code/debug modes")
        allowed_force_includes = command_policy.get("allowed_force_includes")
        require(isinstance(allowed_force_includes, list),
                f"{context}.allowed_force_includes must be an array")
        normalized_force_includes = []
        for include_index, include in enumerate(allowed_force_includes):
            include_context = f"{context}.allowed_force_includes[{include_index}]"
            require(isinstance(include, dict), f"{include_context} must be an object")
            exact_keys(include, {"path", "sha256"}, include_context)
            include_relative, include_path = resolve_relative(
                source_dir, include.get("path"), f"{include_context}.path"
            )
            include_sha = require_sha(include.get("sha256"), f"{include_context}.sha256")
            require(sha256_file(include_path) == include_sha,
                    f"force-include hash differs: {include_relative}")
            normalized_force_includes.append(
                {"path": include_relative, "absolute_path": str(include_path), "sha256": include_sha}
            )

        functions = unit.get("functions")
        require(isinstance(functions, list), f"{context}.functions must be an array")
        if functions:
            requested = [
                item.get("splice_class", "<missing>") if isinstance(item, dict) else "<invalid>"
                for item in functions
            ]
            raise ByteIdentityError(
                f"{context} requests unsupported COMDAT splice classes {requested}; "
                "pass-through phase cannot claim a donor as complete"
            )

        completion = unit.get("completion")
        require(isinstance(completion, dict), f"{context}.completion must be an object")
        exact_keys(completion, {"state", "reason", "may_replace_compiler_output"}, f"{context}.completion")
        require(completion.get("state") == "planned_not_composed",
                f"{context} must remain planned_not_composed")
        require(completion.get("may_replace_compiler_output") is False,
                f"{context} may not claim a donor output")
        require(isinstance(completion.get("reason"), str) and len(completion["reason"]) >= 24,
                f"{context}.completion.reason is too weak")

        donors = unit.get("donors")
        require(isinstance(donors, list) and donors, f"{context}.donors must be a non-empty array")
        normalized_donors = []
        for donor_index, donor in enumerate(donors):
            donor_context = f"{context}.donors[{donor_index}]"
            require(isinstance(donor, dict), f"{donor_context} must be an object")
            exact_keys(donor, {"id", "status", "recipe"}, donor_context)
            recipe_id = donor.get("id")
            require(isinstance(recipe_id, str) and RECIPE_ID_RE.fullmatch(recipe_id) is not None,
                    f"{donor_context}.id is invalid")
            require(recipe_id not in recipe_ids, f"duplicate recipe id: {recipe_id}")
            recipe_ids.add(recipe_id)
            require(donor.get("status") == "planned_not_composed",
                    f"{donor_context} may not claim completion")
            recipe = donor.get("recipe")
            require(isinstance(recipe, dict), f"{donor_context}.recipe must be an object")
            exact_keys(
                recipe,
                {
                    "kind",
                    "seed",
                    "generated_header_sha256",
                    "emission_policy",
                    "authenticity_rationale",
                },
                f"{donor_context}.recipe",
            )
            serialized_recipe = json.dumps(recipe, sort_keys=True).casefold()
            require(not any(word in serialized_recipe for word in FORBIDDEN_RECIPE_WORDS),
                    f"{donor_context} contains forbidden provenance")
            require(recipe.get("kind") == "entropy", f"{donor_context}: only entropy is supported")
            seed = recipe.get("seed")
            require(isinstance(seed, int) and not isinstance(seed, bool)
                    and 0 <= seed <= 0x7FFFFFFF,
                    f"{donor_context}.seed is invalid")
            header_sha = require_sha(
                recipe.get("generated_header_sha256"),
                f"{donor_context}.generated_header_sha256",
            )
            require(recipe_id == f"e_{header_sha[:12]}",
                    f"{donor_context}.id is not the header content ID")
            generated = entropy_generator.generate(seed).encode("utf-8")
            require(sha256_bytes(generated) == header_sha,
                    f"{donor_context}: entropy generator/hash drift")
            require(recipe.get("emission_policy") == "non_emitting_declarations_only",
                    f"{donor_context}: entropy must be non-emitting declarations")
            rationale = recipe.get("authenticity_rationale")
            require(isinstance(rationale, str) and len(rationale) >= 32,
                    f"{donor_context}: authenticity rationale is too weak")
            normalized_donors.append(
                {
                    **donor,
                    "header_output": str(recipe_output(build_dir, header_sha)),
                }
            )

        normalized_units.append(
            {
                **unit,
                "source": source_relative,
                "source_path": str(source_path),
                "command_policy": {
                    **command_policy,
                    "allowed_force_includes": normalized_force_includes,
                },
                "donors": normalized_donors,
            }
        )

    require(manifest.get("archives") == [],
            "archive composition is unsupported in pass-through phase")
    require(manifest.get("images") == {},
            "image completion is unsupported in pass-through phase")
    return {
        "manifest": manifest,
        "manifest_path": str(manifest_path.resolve()),
        "manifest_sha256": sha256_bytes(raw),
        "source_dir": str(source_dir.resolve()),
        "build_dir": str(build_dir.resolve()),
        "translation_units": normalized_units,
        "compiler_sha256": expected_compiler_sha,
        "toolchain_fingerprint": toolchain_fingerprint,
        "framework_tool_sha256": sha256_file(Path(__file__).resolve()),
        "entropy_tool_sha256": sha256_file(Path(entropy_generator.__file__).resolve()),
        "sanitized_environment": list(SANITIZED_ENVIRONMENT),
        "max_child_seconds": timeout,
    }


def cmake_quote(value: str) -> str:
    require(";" not in value and "\n" not in value and "\r" not in value,
            "unsafe value for generated CMake plan")
    return value.replace("\\", "\\\\").replace('"', '\\"')


def render_plan(state: dict) -> bytes:
    lines = [
        "# Generated atomically by tools/byte_identity.py; do not edit.",
        f'set(ISLE_BYTE_IDENTITY_PHASE "{PHASE}")',
        'set(ISLE_BYTE_IDENTITY_COMPLETION "planned_not_composed")',
        f'set(ISLE_BYTE_IDENTITY_MANIFEST_SHA256 "{state["manifest_sha256"]}")',
    ]
    indices = [str(index) for index in range(len(state["translation_units"]))]
    lines.append(f'set(ISLE_BYTE_IDENTITY_TU_INDICES "{";".join(indices)}")')
    recipe_ids = []
    for index, unit in enumerate(state["translation_units"]):
        outputs = [donor["header_output"] for donor in unit["donors"]]
        ids = [donor["id"] for donor in unit["donors"]]
        recipe_ids.extend(ids)
        prefix = f"ISLE_BYTE_IDENTITY_TU_{index}"
        audit = audit_object_path(
            Path(state["build_dir"]), unit["target"], unit["source"]
        )
        lines.extend(
            [
                f'set({prefix}_TARGET "{cmake_quote(unit["target"])}")',
                f'set({prefix}_SOURCE "{cmake_quote(unit["source_path"])}")',
                f'set({prefix}_SOURCE_REL "{cmake_quote(unit["source"])}")',
                f'set({prefix}_OUTPUTS "{cmake_quote(";".join(outputs))}")',
                f'set({prefix}_RECIPE_IDS "{cmake_quote(";".join(ids))}")',
                f'set({prefix}_AUDIT "{cmake_quote(str(audit))}")',
            ]
        )
    lines.append(f'set(ISLE_BYTE_IDENTITY_RECIPE_IDS "{cmake_quote(";".join(recipe_ids))}")')
    for unit in state["translation_units"]:
        for donor in unit["donors"]:
            recipe_id = donor["id"]
            lines.append(
                f'set(ISLE_BYTE_IDENTITY_RECIPE_{recipe_id}_OUTPUT '
                f'"{cmake_quote(donor["header_output"])}")'
            )
    return ("\n".join(lines) + "\n").encode("utf-8")


def command_plan(arguments: argparse.Namespace) -> int:
    expected_plan = arguments.build_dir.resolve() / "byte-identity/plan.cmake"
    require(arguments.output.resolve() == expected_plan,
            "plan output must be the fixed build-tree byte-identity/plan.cmake")
    invalidate_framework_verdict(arguments.build_dir)
    state = validate_manifest(
        arguments.manifest,
        arguments.source_dir,
        arguments.build_dir,
        configured_compiler=arguments.compiler,
        compiler_id=arguments.compiler_id,
        compiler_version=arguments.compiler_version,
        generator=arguments.generator,
    )
    atomic_write(arguments.output, render_plan(state), if_changed=True)
    print(
        json.dumps(
            {
                "status": "PASS_THROUGH_PLAN_ONLY",
                "translation_units": len(state["translation_units"]),
                "recipes": sum(len(unit["donors"]) for unit in state["translation_units"]),
                "manifest_sha256": state["manifest_sha256"],
                "output": str(arguments.output),
            },
            sort_keys=True,
        )
    )
    return 0


def find_recipe(state: dict, recipe_id: str) -> tuple[dict, dict]:
    matches = [
        (unit, donor)
        for unit in state["translation_units"]
        for donor in unit["donors"]
        if donor["id"] == recipe_id
    ]
    require(len(matches) == 1, f"recipe is not uniquely declared: {recipe_id}")
    return matches[0]


def command_materialize(arguments: argparse.Namespace) -> int:
    invalidate_framework_verdict(arguments.build_dir)
    state = validate_manifest(arguments.manifest, arguments.source_dir, arguments.build_dir)
    unit, donor = find_recipe(state, arguments.recipe_id)
    audit_path = (
        arguments.build_dir.resolve()
        / "byte-identity/audit/materialization"
        / f"{donor['id']}.json"
    )
    try:
        audit_path.unlink()
    except FileNotFoundError:
        pass
    expected_output = Path(donor["header_output"])
    require(arguments.output.resolve() == expected_output.resolve(),
            "materialization output differs from the generated plan")
    recipe = donor["recipe"]
    data = entropy_generator.generate(recipe["seed"]).encode("utf-8")
    require(sha256_bytes(data) == recipe["generated_header_sha256"],
            "materialized entropy hash differs")
    atomic_write(expected_output, data, if_changed=True)
    audit = {
        "status": "MATERIALIZED_NON_EMITTING_DECLARATIONS",
        "manifest_sha256": state["manifest_sha256"],
        "recipe_id": donor["id"],
        "target": unit["target"],
        "source": unit["source"],
        "seed": recipe["seed"],
        "output": str(expected_output),
        "output_sha256": sha256_file(expected_output),
        "emission_policy": recipe["emission_policy"],
        "completion": "planned_not_composed",
    }
    atomic_json(audit_path, audit)
    print(json.dumps(audit, sort_keys=True))
    return 0


def resolved_argument_path(value: str, cwd: Path) -> Path:
    value = value.strip('"')
    path = Path(value)
    return (cwd / path).resolve() if not path.is_absolute() else path.resolve()


def option_value(arguments: list[str], option: str) -> tuple[int, str, bool]:
    """Return index, value, and whether an MSVC option uses a separate token."""
    matches = []
    folded_option = option.casefold()
    for index, value in enumerate(arguments):
        folded = value.casefold()
        if folded in (f"/{folded_option}", f"-{folded_option}"):
            require(index + 1 < len(arguments), f"missing value after {value}")
            matches.append((index, arguments[index + 1], True))
        elif folded.startswith(f"/{folded_option}") or folded.startswith(f"-{folded_option}"):
            matches.append((index, value[len(option) + 1 :], False))
    require(len(matches) == 1, f"expected one /{option}, found {len(matches)}")
    return matches[0]


def replace_option(arguments: list[str], option: str, new_value: Path) -> tuple[list[str], Path]:
    index, old_value, separate = option_value(arguments, option)
    result = list(arguments)
    if separate:
        result[index + 1] = str(new_value)
    else:
        prefix = result[index][: len(option) + 1]
        result[index] = prefix + str(new_value)
    return result, resolved_argument_path(old_value, Path.cwd())


def source_arguments(arguments: list[str], cwd: Path) -> list[Path]:
    result = []
    for value in arguments:
        stripped = value.strip('"')
        if Path(stripped).suffix in SOURCE_SUFFIXES:
            result.append(resolved_argument_path(stripped, cwd))
    return result


def force_include_arguments(arguments: list[str], cwd: Path) -> list[Path]:
    result = []
    index = 0
    while index < len(arguments):
        value = arguments[index]
        folded = value.casefold()
        if folded in ("/fi", "-fi"):
            require(index + 1 < len(arguments), f"missing value after {value}")
            result.append(resolved_argument_path(arguments[index + 1], cwd))
            index += 2
            continue
        if folded.startswith("/fi") or folded.startswith("-fi"):
            result.append(resolved_argument_path(value[3:], cwd))
        index += 1
    return result


def run_child(command: list[str], timeout: int, environment: dict[str, str]) -> tuple[int, bytes, bool]:
    # A real file avoids the classic communicate() hang where a detached
    # grandchild inherits the stdout pipe and keeps its write end open.
    with tempfile.TemporaryFile() as capture:
        process = subprocess.Popen(
            command,
            stdout=capture,
            stderr=subprocess.STDOUT,
            env=environment,
            start_new_session=True,
        )
        timed_out = False
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired as error:
                    raise ByteIdentityError(
                        "compiler process did not exit after SIGKILL"
                    ) from error
        capture.seek(0)
        output = capture.read()
    return process.returncode, output, timed_out


def acquire_build_lock(path: Path, owner: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a+b")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        handle.close()
        raise ByteIdentityError(f"another byte-identity compile owns {owner}") from error
    ACTIVE_LOCKS.append(handle)


def sanitized_child_environment(state: dict, temporary: Path) -> dict[str, str]:
    environment = dict(os.environ)
    for name in state["sanitized_environment"]:
        if name.endswith("*"):
            prefix = name[:-1]
            for variable in list(environment):
                if variable.startswith(prefix):
                    environment.pop(variable)
        else:
            environment.pop(name, None)
    environment.update(
        {"TMP": str(temporary), "TEMP": str(temporary), "TMPDIR": str(temporary)}
    )
    return environment


def compile_unlisted_atomically(
    *,
    arguments: argparse.Namespace,
    state: dict,
    child: list[str],
    configured: Path,
    source: Path,
    source_relative: str,
    expected_object: Path,
    expected_pdb: Path,
) -> int:
    """Run an unlisted TU through the same atomic/process-safety envelope.

    ``CXX_COMPILER_LAUNCHER`` is target-wide, so every source in a target that
    owns one manifest-listed TU passes through this program.  Unlisted sources
    do not receive entropy or claim composition, but they must not bypass the
    sanitized environment, private outputs, watchdog, or post-compile pins.
    """
    source_before = sha256_file(source)
    folded = [value.casefold() for value in child]
    require("/zi" in folded or "-zi" in folded,
            "unlisted byte-identity compile is missing /Zi")
    require("/c" in folded or "-c" in folded,
            "unlisted byte-identity compile is not compile-only")
    require(not any(
        value.startswith(prefix)
        for value in folded
        for prefix in ("/gl", "-gl", "/z7", "-z7")
    ), "unlisted byte-identity compile uses a forbidden code/debug mode")

    observed_force_includes = force_include_arguments(child, Path.cwd().resolve())
    target_policies = [
        [
            (Path(item["absolute_path"]).resolve(), item["sha256"])
            for item in unit["command_policy"]["allowed_force_includes"]
        ]
        for unit in state["translation_units"]
        if unit["target"] == arguments.target
    ]
    require(target_policies,
            "unlisted compile has no manifest policy for its target")
    require(all(policy == target_policies[0] for policy in target_policies[1:]),
            "manifest-listed TUs disagree on their target force-include policy")
    declared_force_includes = target_policies[0]
    require(
        observed_force_includes == [path for path, _ in declared_force_includes],
        "unlisted compiler force-include set/order differs from pinned policy",
    )
    for path, expected in declared_force_includes:
        require(sha256_file(path) == expected,
                f"unlisted force-include changed before compile: {path}")

    source_id = hashlib.sha256(source_relative.encode("utf-8")).hexdigest()[:16]
    work = (
        arguments.build_dir.resolve()
        / "byte-identity/work/unlisted-pass-through"
        / arguments.target
        / source_id
    )
    invocation = work / "runs" / f"run-{uuid.uuid4().hex}"
    temporary = work / "tmp"
    work.mkdir(parents=True, exist_ok=True)
    if temporary.exists():
        require(temporary.resolve().is_relative_to(work.resolve()),
                "unlisted temporary directory escapes its TU work directory")
        shutil.rmtree(temporary)
    temporary.mkdir(parents=True)
    private_object = work / "seed.obj"
    private_pdb = work / "seed.pdb"
    for private_output in (private_object, private_pdb):
        try:
            private_output.unlink()
        except FileNotFoundError:
            pass
    rewritten, final_object = replace_option(child, "Fo", private_object)
    rewritten, final_pdb = replace_option(rewritten, "Fd", private_pdb)
    require(final_object == expected_object and final_pdb == expected_pdb,
            "unlisted compiler output changed during validation")
    final_object.parent.mkdir(parents=True, exist_ok=True)
    final_pdb.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    returncode, output, timed_out = run_child(
        rewritten,
        state["max_child_seconds"],
        sanitized_child_environment(state, temporary),
    )
    atomic_write(invocation / "compile.log", output)
    sys.stdout.buffer.write(output)
    sys.stdout.buffer.flush()
    if timed_out:
        raise ByteIdentityError(
            f"compiler timed out after {state['max_child_seconds']} seconds"
        )
    require(returncode == 0, f"compiler exited with status {returncode}")
    require(private_object.is_file() and private_object.stat().st_size > 0,
            "compiler did not produce a private unlisted object")
    require(private_pdb.is_file() and private_pdb.stat().st_size > 0,
            "compiler did not produce a private unlisted PDB")

    post_state = validate_manifest(
        arguments.manifest,
        arguments.source_dir,
        arguments.build_dir,
        configured_compiler=arguments.configured_compiler,
    )
    require(
        post_state["manifest_sha256"] == state["manifest_sha256"]
        and post_state["toolchain_fingerprint"] == state["toolchain_fingerprint"]
        and post_state["framework_tool_sha256"] == state["framework_tool_sha256"]
        and post_state["entropy_tool_sha256"] == state["entropy_tool_sha256"],
        "manifest or toolchain changed during unlisted compilation",
    )
    require(sha256_file(source) == source_before,
            "unlisted source changed during compilation")
    for path, expected in declared_force_includes:
        require(sha256_file(path) == expected,
                f"unlisted force-include changed during compile: {path}")

    audit_path = audit_unlisted_path(
        arguments.build_dir, arguments.target, source_relative
    )
    audit = {
        "status": "unlisted_atomic_pass_through",
        "may_claim_byte_identity": False,
        "manifest_sha256": state["manifest_sha256"],
        "compiler_sha256": sha256_file(configured),
        "toolchain_fingerprint": state["toolchain_fingerprint"],
        "target": arguments.target,
        "source": source_relative,
        "source_sha256": source_before,
        "input_command_sha256": sha256_bytes(
            json.dumps(child, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        ),
        "executed_command_sha256": sha256_bytes(
            json.dumps(rewritten, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        ),
        "sanitized_environment": state["sanitized_environment"],
        "object": str(final_object),
        "object_sha256": sha256_file(private_object),
        "pdb": str(final_pdb),
        "pdb_sha256": sha256_file(private_pdb),
        "elapsed_seconds": round(time.monotonic() - started, 6),
    }
    try:
        os.replace(private_pdb, final_pdb)
        os.replace(private_object, final_object)
        atomic_json(audit_path, audit)
    except BaseException:
        for final_output in (final_object, final_pdb):
            try:
                final_output.unlink()
            except FileNotFoundError:
                pass
        raise
    return 0


def command_compile_launch(arguments: argparse.Namespace) -> int:
    child = list(arguments.child)
    if child and child[0] == "--":
        child.pop(0)
    require(child, "compile-launch received no compiler command")
    require(TARGET_RE.fullmatch(arguments.target) is not None,
            "compile-launch target is invalid")
    invalidate_framework_verdict(arguments.build_dir)
    cwd = Path.cwd().resolve()
    _, original_object_value, _ = option_value(child, "Fo")
    _, original_pdb_value, _ = option_value(child, "Fd")
    expected_object = resolved_argument_path(original_object_value, cwd)
    expected_pdb = resolved_argument_path(original_pdb_value, cwd)
    require(expected_object.is_relative_to(arguments.build_dir.resolve()),
            "compiler object output is outside the build tree")
    require(expected_pdb.is_relative_to(arguments.build_dir.resolve()),
            "compiler PDB output is outside the build tree")
    sources = source_arguments(child, cwd)
    lock_identity = str(sources[0]) if len(sources) == 1 else str(expected_object)
    lock_id = hashlib.sha256(lock_identity.encode("utf-8")).hexdigest()[:16]
    acquire_build_lock(
        arguments.build_dir.resolve()
        / "byte-identity/locks"
        / arguments.target
        / f"{lock_id}.lock",
        f"{arguments.target}:{lock_identity}",
    )
    # Remove previous outputs before any manifest/toolchain gate.  Therefore a
    # failed launcher invocation cannot leave an apparently up-to-date object
    # or a stale per-object PDB.
    for expected_output in (expected_object, expected_pdb):
        try:
            expected_output.unlink()
        except FileNotFoundError:
            pass
    state = validate_manifest(
        arguments.manifest,
        arguments.source_dir,
        arguments.build_dir,
        configured_compiler=arguments.configured_compiler,
    )
    configured = compiler_path(arguments.configured_compiler)
    compiler_positions = []
    for index, value in enumerate(child):
        try:
            if Path(value).exists() and Path(value).resolve() == configured:
                compiler_positions.append(index)
        except OSError:
            pass
    require(compiler_positions == [0],
            "child command must begin with the pinned compiler exactly once")

    require(len(sources) == 1, f"expected one compiler source, found {len(sources)}")
    try:
        source_relative = sources[0].relative_to(arguments.source_dir.resolve()).as_posix()
    except ValueError as error:
        raise ByteIdentityError("compiler source is outside the source tree") from error
    matches = [
        unit
        for unit in state["translation_units"]
        if unit["target"] == arguments.target and unit["source"] == source_relative
    ]
    if not matches:
        return compile_unlisted_atomically(
            arguments=arguments,
            state=state,
            child=child,
            configured=configured,
            source=sources[0],
            source_relative=source_relative,
            expected_object=expected_object,
            expected_pdb=expected_pdb,
        )
    require(len(matches) == 1, "manifest translation unit is not unique")
    unit = matches[0]
    audit_path = audit_object_path(arguments.build_dir, unit["target"], source_relative)
    try:
        audit_path.unlink()
    except FileNotFoundError:
        pass
    require(sha256_file(sources[0]) == unit["source_sha256"], "source changed before compile")
    folded = [value.casefold() for value in child]
    for required in unit["command_policy"]["required_flags"]:
        require(required.casefold() in folded, f"required compiler flag is absent: {required}")
    for prefix in unit["command_policy"]["forbidden_prefixes"]:
        require(not any(value.startswith(prefix.casefold()) for value in folded),
                f"forbidden compiler option is present: {prefix}")
    observed_force_includes = force_include_arguments(child, cwd)
    allowed_force_includes = [
        Path(item["absolute_path"]).resolve()
        for item in unit["command_policy"]["allowed_force_includes"]
    ]
    require(observed_force_includes == allowed_force_includes,
            "compiler force-include set/order differs from the pinned policy")
    for item in unit["command_policy"]["allowed_force_includes"]:
        require(sha256_file(Path(item["absolute_path"])) == item["sha256"],
                f"force-include changed before compile: {item['path']}")
    for donor in unit["donors"]:
        output = Path(donor["header_output"])
        require(output.is_file(), f"materialized entropy header is absent: {output}")
        require(sha256_file(output) == donor["recipe"]["generated_header_sha256"],
                f"materialized entropy header changed: {output}")

    source_id = hashlib.sha256(source_relative.encode("utf-8")).hexdigest()[:16]
    work_parent = (
        arguments.build_dir.resolve()
        / "byte-identity/work"
        / arguments.target
        / source_id
    )
    work = work_parent
    invocation = work / "runs" / f"run-{uuid.uuid4().hex}"
    work.mkdir(parents=True, exist_ok=True)
    temporary = work / "tmp"
    if temporary.exists():
        require(temporary.resolve().is_relative_to(work.resolve()),
                "compiler temporary directory escapes the TU work directory")
        shutil.rmtree(temporary)
    temporary.mkdir(parents=True)
    private_object = work / "seed.obj"
    private_pdb = work / "seed.pdb"
    for private_output in (private_object, private_pdb):
        try:
            private_output.unlink()
        except FileNotFoundError:
            pass
    rewritten, final_object = replace_option(child, "Fo", private_object)
    rewritten, final_pdb = replace_option(rewritten, "Fd", private_pdb)
    require(final_object == expected_object, "compiler object output changed during validation")
    require(final_pdb == expected_pdb, "compiler PDB output changed during validation")
    require(final_object.is_relative_to(arguments.build_dir.resolve()),
            "compiler object output is outside the build tree")
    require(final_pdb.is_relative_to(arguments.build_dir.resolve()),
            "compiler PDB output is outside the build tree")
    final_object.parent.mkdir(parents=True, exist_ok=True)
    final_pdb.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    returncode, output, timed_out = run_child(
        rewritten,
        state["max_child_seconds"],
        sanitized_child_environment(state, temporary),
    )
    atomic_write(invocation / "compile.log", output)
    sys.stdout.buffer.write(output)
    sys.stdout.buffer.flush()
    if timed_out:
        raise ByteIdentityError(f"compiler timed out after {state['max_child_seconds']} seconds")
    require(returncode == 0, f"compiler exited with status {returncode}")
    require(private_object.is_file() and private_object.stat().st_size > 0,
            "compiler did not produce a private object")
    require(private_pdb.is_file() and private_pdb.stat().st_size > 0,
            "compiler did not produce a private PDB")
    post_state = validate_manifest(
        arguments.manifest,
        arguments.source_dir,
        arguments.build_dir,
        configured_compiler=arguments.configured_compiler,
    )
    require(post_state["manifest_sha256"] == state["manifest_sha256"]
            and post_state["toolchain_fingerprint"] == state["toolchain_fingerprint"]
            and post_state["framework_tool_sha256"] == state["framework_tool_sha256"]
            and post_state["entropy_tool_sha256"] == state["entropy_tool_sha256"],
            "manifest or toolchain changed during compilation")
    post_matches = [
        candidate
        for candidate in post_state["translation_units"]
        if candidate["target"] == arguments.target
        and candidate["source"] == source_relative
    ]
    require(len(post_matches) == 1, "translation unit changed during compilation")
    post_unit = post_matches[0]
    require(sha256_file(sources[0]) == post_unit["source_sha256"],
            "source changed during compilation")
    for item in post_unit["command_policy"]["allowed_force_includes"]:
        require(sha256_file(Path(item["absolute_path"])) == item["sha256"],
                f"force-include changed during compile: {item['path']}")
    for donor in post_unit["donors"]:
        require(sha256_file(Path(donor["header_output"]))
                == donor["recipe"]["generated_header_sha256"],
                f"materialized entropy header changed during compile: {donor['header_output']}")
    audit = {
        "status": "pass_through_not_composed",
        "may_claim_byte_identity": False,
        "manifest_sha256": state["manifest_sha256"],
        "compiler_sha256": sha256_file(configured),
        "toolchain_fingerprint": state["toolchain_fingerprint"],
        "framework_tool_sha256": state["framework_tool_sha256"],
        "entropy_tool_sha256": state["entropy_tool_sha256"],
        "sanitized_environment": state["sanitized_environment"],
        "target": unit["target"],
        "source": source_relative,
        "source_sha256": sha256_file(sources[0]),
        "input_command_sha256": sha256_bytes(
            json.dumps(child, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        ),
        "executed_command_sha256": sha256_bytes(
            json.dumps(rewritten, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        ),
        "recipes": [donor["id"] for donor in unit["donors"]],
        "recipes_materialized_but_not_injected": True,
        "object": str(final_object),
        "object_sha256": sha256_file(private_object),
        "pdb": str(final_pdb),
        "pdb_sha256": sha256_file(private_pdb),
        "elapsed_seconds": round(time.monotonic() - started, 6),
        "completion": unit["completion"],
    }
    try:
        os.replace(private_pdb, final_pdb)
        os.replace(private_object, final_object)
        atomic_json(audit_path, audit)
    except BaseException:
        for final_output in (final_object, final_pdb):
            try:
                final_output.unlink()
            except FileNotFoundError:
                pass
        raise
    print(json.dumps({"byte_identity": audit}, sort_keys=True))
    return 0


def command_verify(arguments: argparse.Namespace) -> int:
    verdict_path = invalidate_framework_verdict(arguments.build_dir)
    state = validate_manifest(
        arguments.manifest,
        arguments.source_dir,
        arguments.build_dir,
        configured_compiler=arguments.compiler,
    )
    verified_recipes = []
    verified_units = []
    for unit in state["translation_units"]:
        for donor in unit["donors"]:
            output = Path(donor["header_output"])
            require(output.is_file(), f"materialized header is absent: {output}")
            require(sha256_file(output) == donor["recipe"]["generated_header_sha256"],
                    f"materialized header hash differs: {output}")
            materialization_audit_path = (
                arguments.build_dir.resolve()
                / "byte-identity/audit/materialization"
                / f"{donor['id']}.json"
            )
            try:
                materialization_audit = json.loads(materialization_audit_path.read_text())
            except (OSError, UnicodeError, json.JSONDecodeError) as error:
                raise ByteIdentityError(
                    f"cannot read materialization audit {materialization_audit_path}: {error}"
                ) from error
            require(isinstance(materialization_audit, dict),
                    f"materialization audit is not an object: {materialization_audit_path}")
            require(
                materialization_audit.get("status")
                == "MATERIALIZED_NON_EMITTING_DECLARATIONS"
                and materialization_audit.get("manifest_sha256") == state["manifest_sha256"]
                and materialization_audit.get("recipe_id") == donor["id"]
                and materialization_audit.get("target") == unit["target"]
                and materialization_audit.get("source") == unit["source"]
                and materialization_audit.get("seed") == donor["recipe"]["seed"]
                and Path(materialization_audit.get("output", "")).resolve()
                == output.resolve()
                and materialization_audit.get("output_sha256")
                == donor["recipe"]["generated_header_sha256"]
                and materialization_audit.get("emission_policy")
                == "non_emitting_declarations_only"
                and materialization_audit.get("completion") == "planned_not_composed",
                f"materialization audit differs: {materialization_audit_path}",
            )
            verified_recipes.append(donor["id"])
        audit_path = audit_object_path(arguments.build_dir, unit["target"], unit["source"])
        try:
            audit = json.loads(audit_path.read_text())
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ByteIdentityError(f"cannot read compiler audit {audit_path}: {error}") from error
        require(isinstance(audit, dict), f"compiler audit is not an object: {audit_path}")
        require(audit.get("status") == "pass_through_not_composed",
                f"compiler audit claims unsupported completion: {audit_path}")
        require(audit.get("may_claim_byte_identity") is False,
                f"compiler audit may claim byte identity: {audit_path}")
        require(audit.get("manifest_sha256") == state["manifest_sha256"],
                f"compiler audit is stale: {audit_path}")
        require(audit.get("source_sha256") == unit["source_sha256"],
                f"compiler audit source hash differs: {audit_path}")
        require(audit.get("target") == unit["target"] and audit.get("source") == unit["source"],
                f"compiler audit owner differs: {audit_path}")
        require(audit.get("compiler_sha256") == state["compiler_sha256"],
                f"compiler audit toolchain hash differs: {audit_path}")
        require(audit.get("toolchain_fingerprint") == state["toolchain_fingerprint"],
                f"compiler audit transitive toolchain differs: {audit_path}")
        require(audit.get("framework_tool_sha256") == state["framework_tool_sha256"],
                f"compiler audit framework tool differs: {audit_path}")
        require(audit.get("entropy_tool_sha256") == state["entropy_tool_sha256"],
                f"compiler audit entropy tool differs: {audit_path}")
        require(audit.get("sanitized_environment") == state["sanitized_environment"],
                f"compiler audit environment policy differs: {audit_path}")
        require(audit.get("recipes") == [donor["id"] for donor in unit["donors"]],
                f"compiler audit recipe set differs: {audit_path}")
        require(audit.get("recipes_materialized_but_not_injected") is True,
                f"compiler audit recipe disposition differs: {audit_path}")
        require(audit.get("completion") == unit["completion"],
                f"compiler audit completion differs: {audit_path}")
        object_path = Path(audit.get("object", ""))
        require(object_path.is_absolute()
                and object_path.resolve().is_relative_to(arguments.build_dir.resolve()),
                f"compiler audit object is outside the build tree: {audit_path}")
        require(object_path.is_file() and sha256_file(object_path) == audit.get("object_sha256"),
                f"compiler audit object differs: {audit_path}")
        pdb_path = Path(audit.get("pdb", ""))
        require(pdb_path.is_absolute()
                and pdb_path.resolve().is_relative_to(arguments.build_dir.resolve()),
                f"compiler audit PDB is outside the build tree: {audit_path}")
        require(pdb_path.is_file() and sha256_file(pdb_path) == audit.get("pdb_sha256"),
                f"compiler audit PDB differs: {audit_path}")
        verified_units.append(f"{unit['target']}:{unit['source']}")
    result = {
        "status": "PASS_THROUGH_FRAMEWORK_VERIFIED",
        "byte_identity_complete": False,
        "reason": (
            "COMDAT composition, full command/header-closure fingerprints, archive gates, "
            "diagnostic relink, provenance-safe timestamps, and final MD5 are not implemented"
        ),
        "manifest_sha256": state["manifest_sha256"],
        "recipes": verified_recipes,
        "translation_units": verified_units,
    }
    atomic_json(verdict_path, result)
    print(json.dumps(result, sort_keys=True))
    return 0


def command_invalidate(arguments: argparse.Namespace) -> int:
    invalidate_framework_verdict(arguments.build_dir)
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subcommands = result.add_subparsers(dest="command", required=True)

    plan = subcommands.add_parser("plan")
    plan.add_argument("--manifest", type=Path, required=True)
    plan.add_argument("--source-dir", type=Path, required=True)
    plan.add_argument("--build-dir", type=Path, required=True)
    plan.add_argument("--compiler", required=True)
    plan.add_argument("--compiler-id", required=True)
    plan.add_argument("--compiler-version", required=True)
    plan.add_argument("--generator", required=True)
    plan.add_argument("--output", type=Path, required=True)
    plan.set_defaults(handler=command_plan)

    materialize = subcommands.add_parser("materialize")
    materialize.add_argument("--manifest", type=Path, required=True)
    materialize.add_argument("--source-dir", type=Path, required=True)
    materialize.add_argument("--build-dir", type=Path, required=True)
    materialize.add_argument("--recipe-id", required=True)
    materialize.add_argument("--output", type=Path, required=True)
    materialize.set_defaults(handler=command_materialize)

    launch = subcommands.add_parser("compile-launch")
    launch.add_argument("--manifest", type=Path, required=True)
    launch.add_argument("--source-dir", type=Path, required=True)
    launch.add_argument("--build-dir", type=Path, required=True)
    launch.add_argument("--target", required=True)
    launch.add_argument("--configured-compiler", required=True)
    launch.add_argument("child", nargs=argparse.REMAINDER)
    launch.set_defaults(handler=command_compile_launch)

    verify = subcommands.add_parser("verify")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--source-dir", type=Path, required=True)
    verify.add_argument("--build-dir", type=Path, required=True)
    verify.add_argument("--compiler", required=True)
    verify.set_defaults(handler=command_verify)

    invalidate = subcommands.add_parser("invalidate")
    invalidate.add_argument("--build-dir", type=Path, required=True)
    invalidate.set_defaults(handler=command_invalidate)
    return result


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = parser().parse_args(argv)
        return arguments.handler(arguments)
    except (ByteIdentityError, OSError, ValueError) as error:
        print(f"byte_identity: refusing: {error}", file=sys.stderr)
        return 2
    finally:
        while ACTIVE_LOCKS:
            ACTIVE_LOCKS.pop().close()


if __name__ == "__main__":
    raise SystemExit(main())
