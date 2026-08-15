#!/usr/bin/env python3
"""Minimal byte-identity build runner.

Renders the typed entropy manifest into an effective source view, builds it
with the pinned MSVC 4.2 toolchain through the ordinary CMake graph, scores
the result with the pinned reccmp, and enforces the manifest row/MD5 gates.

Authenticity model: inputs (manifest + rendered sources), tools (compiler,
linker, reccmp) and outputs (objects, image, report) are hash-pinned; the
host environment is not modeled.  A misbehaving environment can only fail
the gates - acceptance is byte-equality against the retail oracle.

The runner is deliberately incremental: the effective source shadow is
synchronized (not rebuilt), CMake configure is reused, and make recompiles
only what changed, so an iterate loop runs in seconds.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))
import byte_identity  # noqa: E402

SHADOW_SUBSET = (
    "CMakeLists.txt",
    "reccmp-project.yml",
    "cmake",
    "LEGO1",
    "ISLE",
    "CONFIG",
    "3rdparty",
    "util",
)
POSIX_PROFILE = "posix_wine_virtual_z_v1"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def fail(message: str) -> "NoReturn":  # noqa: F821
    print(f"isle_build: refusing: {message}", file=sys.stderr)
    raise SystemExit(2)


def verify_pins(manifest: dict, compiler: Path) -> dict:
    """Hash-verify the tools that carry authenticity."""
    toolchain = manifest["toolchain"]
    if sha256_file(compiler) != toolchain["compiler_sha256"]:
        fail(f"compiler wrapper hash differs: {compiler}")
    profile = toolchain["backend_profiles"][POSIX_PROFILE]
    compiler_root = compiler.parents[profile["compiler_root_parent_levels"]]
    for item in profile["compiler_support_files"] + profile[
            "producer_support_files"]:
        target = compiler_root.joinpath(*item["path"].split("/"))
        if not target.is_file():
            fail(f"pinned toolchain file is absent: {target}")
        if sha256_file(target) != item["sha256"]:
            fail(f"pinned toolchain file differs: {target}")
    for item in profile.get("required_absent_toolchain_files", []):
        target = compiler_root.joinpath(*item.split("/"))
        if target.exists():
            fail(f"required-absent toolchain file exists: {target}")
    for archive in manifest["archives"]:
        source = ROOT / archive["source"]
        if sha256_file(source) != archive["source_sha256"]:
            fail(f"pinned third-party archive differs: {archive['identity']}")
    for identity, image in manifest["images"].items():
        original = ROOT / image["original"]
        if sha256_file(original) != image["original_sha256"]:
            fail(f"retail oracle differs from its pin: {identity}")
    return {"compiler_root": compiler_root,
            "image_gates": manifest["images"]}


def resolve_reccmp(manifest: dict) -> Path:
    reccmp = manifest["terminal_producers"]["reccmp"]
    profile = reccmp["backend_profiles"][POSIX_PROFILE]
    roots = byte_identity.manifest_host_roots()
    executable = byte_identity.manifest_host_path(
        profile["executable"], "reccmp executable", roots
    )
    if sha256_file(executable) != profile["executable_sha256"]:
        fail(f"pinned reccmp executable differs: {executable}")
    return executable


def render_overlay(manifest: dict) -> tuple[dict, dict[str, bytes]]:
    overlay = byte_identity.validate_source_overlay(
        manifest["source_overlay"], ROOT
    )
    # validate_source_overlay already rendered every output and checked it
    # against its effective pin; reuse that render instead of running the
    # whole overlay a second time.
    return overlay, overlay["rendered_by_path"]


def sync_shadow(shadow: Path, rendered: dict[str, bytes]) -> int:
    """Mirror the repo subset + effective outputs into the shadow tree.

    Only changed files are rewritten so make dependency tracking stays warm.
    """
    changed = 0
    wanted: set[Path] = set()

    def install(relative: str, data: bytes, mode: int) -> None:
        nonlocal changed
        destination = shadow / relative
        wanted.add(destination)
        if destination.exists() and destination.read_bytes() == data:
            return
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        destination.chmod(mode)
        changed += 1

    overlay_owned = set(rendered)
    for entry in SHADOW_SUBSET:
        source_root = ROOT / entry
        if source_root.is_file():
            install(entry, source_root.read_bytes(), 0o644)
            continue
        for source in sorted(source_root.rglob("*")):
            if not source.is_file() or source.is_symlink():
                continue
            relative = source.relative_to(ROOT).as_posix()
            if relative in overlay_owned:
                continue
            install(relative, source.read_bytes(),
                    source.stat().st_mode & 0o755)
    for relative, data in sorted(rendered.items()):
        install(relative, data, 0o644)
    # The scorer's project files live beside the sources and are rewritten
    # after each sync; keep them out of the prune.
    wanted.add(shadow / "reccmp-user.yml")
    # prune anything that fell out of the wanted view
    for existing in sorted(shadow.rglob("*"), reverse=True):
        if existing.is_file() and existing not in wanted:
            existing.unlink()
            changed += 1
        elif existing.is_dir():
            try:
                existing.rmdir()
            except OSError:
                pass
    return changed


def write_plan(plan_path: Path, overlay: dict) -> None:
    lines = [
        "# Generated by tools/isle_build.py - do not edit.",
        'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_ENABLED TRUE)',
        'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_MATERIALIZED TRUE)',
        'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_PREBUILT_SOURCE_ARTIFACTS'
        ' "forbidden")',
    ]
    outputs = ";".join(item["logical_path"] for item in overlay["outputs"])
    lines.append(
        f'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_OUTPUTS "{outputs}")'
    )
    generated = overlay["graph"]["generated_translation_units"]
    lines.append(
        'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_INDICES "'
        + ";".join(str(index) for index in range(len(generated))) + '")'
    )
    for index, unit in enumerate(generated):
        prefix = f"ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_{index}"
        pins = unit["generated_output"]
        values = {
            "PATH": unit["logical_path"],
            "LANGUAGE": unit["language"],
            "TARGET_FAMILY": unit["target_family"],
            "TARGETS": ";".join(unit["targets"]),
            "SOURCE_ORDINAL": str(unit["source_ordinal"]),
            "INSERT_AFTER": unit["insert_after"],
            "INSERT_BEFORE": unit.get("insert_before") or "",
            "GENERATION_OPERATION_IDS": ";".join(
                unit["generation_operation_ids"]
            ),
            "OUTPUT_SHA256": pins["baseline_sha256"],
            "OUTPUT_TOKEN_SHA256": pins[
                "baseline_significant_token_sha256"
            ],
            "OUTPUT_SIZE": str(pins["baseline_size"]),
            "OUTPUT_LINE_COUNT": str(pins["baseline_line_count"]),
        }
        for key, value in values.items():
            lines.append(f'set({prefix}_{key} "{value}")')
    admissions = overlay["graph"]["link_admissions"]
    lines.append(
        'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_LINK_INDICES "'
        + ";".join(str(index) for index in range(len(admissions))) + '")'
    )
    lines.append(
        'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_FORBIDDEN_INTERFACES '
        '"ISLE_INCLUDE_ENTROPY;ISLE_ENTROPY_FILENAME;'
        'ISLE_TU_ENTROPY_MANIFEST")'
    )
    plan_path.parent.mkdir(parents=True, exist_ok=True)
    plan_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_reccmp_project_files(build: Path, shadow: Path,
                               gates: dict) -> None:
    """Emit reccmp-build.yml (build dir) and reccmp-user.yml (shadow root)
    so target-mode reccmp discovers the shadow project with its per-target
    source roots and data-source annotation files."""
    build_lines = [f"project: {shadow}", "targets:"]
    user_lines = ["targets:"]
    for identity, gate in gates.items():
        recompiled = build / gate["recompiled"]
        build_lines += [
            f"  {identity}:",
            f"    path: {recompiled}",
            f"    pdb: {recompiled.with_suffix('.pdb')}",
        ]
        user_lines += [
            f"  {identity}:",
            f"    path: {ROOT / gate['original']}",
        ]
    for path, lines in (
        (build / "reccmp-build.yml", build_lines),
        (shadow / "reccmp-user.yml", user_lines),
    ):
        data = "\n".join(lines) + "\n"
        if not path.exists() or path.read_text() != data:
            path.write_text(data)


def run(command: list[str], *, cwd: Path | None = None,
        env: dict | None = None, log: Path | None = None) -> None:
    started = time.monotonic()
    result = subprocess.run(
        command, cwd=cwd, env=env, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if log is not None:
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_bytes(result.stdout)
    if result.returncode != 0:
        tail = result.stdout[-4000:].decode("utf-8", "replace")
        fail(
            f"command failed ({result.returncode}, "
            f"{time.monotonic() - started:.1f}s): {' '.join(command)}\n{tail}"
        )


def build_environment(compiler: Path) -> dict:
    environment = dict(os.environ)
    environment["PATH"] = (
        str(compiler.parent) + os.pathsep + environment.get("PATH", "")
    )
    return environment


def configure(build: Path, shadow: Path, plan: Path, compiler: Path,
              jobs: int, extra: list[str] | None = None) -> None:
    cache = build / "CMakeCache.txt"
    if cache.exists() and (build / "Makefile").exists():
        return
    if cache.exists():
        cache.unlink()
    run([
        "cmake", "-S", str(shadow), "-B", str(build),
        "-G", "Unix Makefiles",
        "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
        "-DCMAKE_SYSTEM_NAME=Windows",
        "-DCMAKE_CXX_COMPILER=cl",
        "-DCMAKE_RC_COMPILER=rc",
        f"-DISLE_BYTE_IDENTITY_PLAN={plan}",
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
        *(extra or []),
    ], env=build_environment(compiler), log=build / "configure.log")


def stamp_link_time(data: bytes, link_time: int,
                    resource_time: int) -> bytes:
    """Set the PE header, export directory, and resource directory
    timestamps to the manifest-pinned retail values.  These four-byte
    fields are the recorded 1997 build facts; every other byte is
    untouched."""
    stamped = bytearray(data)
    pe = int.from_bytes(data[0x3C:0x40], "little")
    stamped[pe + 8:pe + 12] = link_time.to_bytes(4, "little")
    for offset in byte_identity.pe_resource_directory_offsets(data):
        stamped[offset + 4:offset + 8] = resource_time.to_bytes(4, "little")
    optional = pe + 24
    export_rva = int.from_bytes(data[optional + 96:optional + 100], "little")
    if export_rva:
        section_count = int.from_bytes(data[pe + 6:pe + 8], "little")
        optional_size = int.from_bytes(data[pe + 20:pe + 22], "little")
        table = optional + optional_size
        for index in range(section_count):
            header = table + index * 40
            virtual, raw_size, raw_offset = (
                int.from_bytes(data[header + 12:header + 16], "little"),
                int.from_bytes(data[header + 16:header + 20], "little"),
                int.from_bytes(data[header + 20:header + 24], "little"),
            )
            if virtual <= export_rva < virtual + raw_size:
                offset = raw_offset + export_rva - virtual
                stamped[offset + 4:offset + 8] = link_time.to_bytes(
                    4, "little")
                break
    return bytes(stamped)


def terminal_lane(manifest: dict, gates: dict, build_root: Path,
                  shadow: Path, plan: Path, compiler: Path, jobs: int,
                  require_md5: bool) -> dict:
    """Configure and link the no-/debug terminal images, stamp the pinned
    retail link times, and report per-image MD5 and byte distance."""
    terminal_build = build_root / "terminal"
    terminal_build.mkdir(parents=True, exist_ok=True)
    configure(terminal_build, shadow, plan, compiler, jobs,
              extra=["-DISLE_BYTE_IDENTITY_TERMINAL=TRUE"])
    targets = [gates[identity]["target"] for identity in gates]
    run(["cmake", "--build", str(terminal_build), "--target", *targets,
         "-j", str(jobs)],
        env=build_environment(compiler),
        log=build_root / "terminal-build.log")
    compose_translation_units(manifest, terminal_build, shadow, compiler,
                              jobs)
    results = {}
    states = []
    for identity, gate in gates.items():
        image = terminal_build / gate["recompiled"]
        if not image.is_file():
            fail(f"terminal {gate['recompiled']} was not produced")
        stamped = stamp_link_time(image.read_bytes(), gate["link_time"],
                                  gate["resource_time"])
        stamped_path = terminal_build / f"stamped-{gate['recompiled']}"
        stamped_path.write_bytes(stamped)
        if gate.get("iat_order") == "retail_slot_order_v1":
            # Restore the recorded 1997 import-thunk ordering.  Only the
            # ordering comes from the retail image; every rewritten value is
            # the built image's own thunk, and the transform is fail-closed.
            run([sys.executable, str(ROOT / "tools/pe_iatorder.py"),
                 str(stamped_path), str(ROOT / gate["original"])],
                log=build_root / f"iatorder-{identity}.log")
            stamped = stamped_path.read_bytes()
        if gate.get("thunk_order") == "retail_adjacent_pair_swap_v1":
            stamped = byte_identity.restore_adjacent_thunk_pair_order(
                stamped, (ROOT / gate["original"]).read_bytes()
            )
            stamped_path.write_bytes(stamped)
        original = (ROOT / gate["original"]).read_bytes()
        md5 = hashlib.md5(stamped).hexdigest()
        identical = md5 == gate["original_md5"]
        if len(stamped) == len(original):
            distance = sum(1 for a, b in zip(stamped, original) if a != b)
            size_note = ""
        else:
            distance = None
            size_note = f" size {len(stamped)} vs retail {len(original)}"
        results[identity] = {
            "md5": md5,
            "retail_md5": gate["original_md5"],
            "identical": identical,
            "byte_distance": distance,
            "size": len(stamped),
            "retail_size": len(original),
        }
        state = ("IDENTICAL" if identical
                 else f"distance {distance}{size_note}")
        states.append(f"[isle_build] terminal {identity}: {state}")
        if require_md5 and not identical:
            print("\n".join(states))
            fail(f"terminal {identity} MD5 differs from retail: {md5}")
    # One print per lane: the terminal lane may overlap the image scoring,
    # so its report lines are emitted together.
    print("\n".join(states))
    return results


def gains_losses(report: dict, baseline_path: Path | None) -> str:
    if baseline_path is None or not baseline_path.exists():
        return ""
    try:
        baseline = json.loads(baseline_path.read_text())
    except (OSError, json.JSONDecodeError):
        return ""
    accepted_now = {
        row["address"]: row["name"] for row in report["data"]
        if row.get("matching") == 1.0
    }
    accepted_before = {
        row["address"]: row["name"] for row in baseline["data"]
        if row.get("matching") == 1.0
    }
    gained = sorted(set(accepted_now) - set(accepted_before))
    lost = sorted(set(accepted_before) - set(accepted_now))
    lines = []
    for address in lost:
        lines.append(f"  LOST  {address} {accepted_before[address]}")
    for address in gained:
        lines.append(f"  GAIN  {address} {accepted_now[address]}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--manifest", type=Path,
                        default=ROOT / "tools/byte_identity_manifest.json")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--terminal", action="store_true",
                        help="require complete rows and the retail MD5s")
    parser.add_argument("--md5-distance", action="store_true",
                        help="also link the no-/debug terminal images and "
                             "report byte distance to retail (no MD5 gate)")
    parser.add_argument("--baseline-report", type=Path,
                        default=Path("/tmp/lego1-4816-full.json"))
    arguments = parser.parse_args()

    manifest = byte_identity.strict_json_loads(
        arguments.manifest.read_bytes()
    )
    compiler = arguments.compiler.resolve()
    pins = verify_pins(manifest, compiler)
    reccmp = resolve_reccmp(manifest)

    build_root = arguments.build_dir.resolve()
    shadow = build_root / "src"
    build = build_root / "build"
    plan = build_root / "plan.cmake"
    build_root.mkdir(parents=True, exist_ok=True)

    started = time.monotonic()
    overlay, rendered = render_overlay(manifest)
    changed = sync_shadow(shadow, rendered)
    write_plan(plan, overlay)
    print(f"[isle_build] shadow synced ({changed} files changed, "
          f"{time.monotonic() - started:.1f}s)")

    configure(build, shadow, plan, compiler, arguments.jobs)
    gates = pins["image_gates"]
    targets = [gates[identity]["target"] for identity in gates]
    run(
        ["cmake", "--build", str(build), "--target", *targets,
         "-j", str(arguments.jobs)],
        env=build_environment(compiler), log=build_root / "build.log",
    )
    print(f"[isle_build] build complete ({time.monotonic() - started:.1f}s)")

    compose_translation_units(manifest, build, shadow, compiler,
                              arguments.jobs)

    verdict = {
        "status": ("BYTE_IDENTITY_COMPLETE" if arguments.terminal
                   else "ITERATION_GATES_PASSED_FINAL_GATES_INCOMPLETE"),
        "images": {},
        "manifest_sha256": sha256_file(arguments.manifest),
        "compiler_sha256": sha256_file(compiler),
    }
    summary = []
    # Target-mode reccmp: the project yml's per-target source roots and
    # data-sources (annotation csv files) only load through project
    # discovery, never through --paths.
    write_reccmp_project_files(build, shadow, gates)

    # The terminal lane operates on its own build tree and only reads the
    # shared shadow, so it can overlap the image scoring below.
    terminal_future = None
    terminal_pool = None
    if arguments.terminal or arguments.md5_distance:
        terminal_pool = ThreadPoolExecutor(max_workers=1)
        terminal_future = terminal_pool.submit(
            terminal_lane, manifest, gates, build_root, shadow, plan,
            compiler, arguments.jobs, arguments.terminal,
        )

    # The three image comparisons are independent processes; launch them
    # together and gate on each result in manifest order.
    scorers = {}
    for identity, gate in gates.items():
        image = build / gate["recompiled"]
        pdb = image.with_suffix(".pdb")
        if not image.is_file():
            fail(f"{gate['recompiled']} was not produced")
        if not pdb.is_file():
            fail(f"{pdb.name} was not produced "
                 "(diagnostic /debug link expected)")
        report_path = build_root / f"{identity}-report.json"
        scorers[identity] = (subprocess.Popen([
            str(reccmp), "--target", identity,
            "--json", str(report_path), "--json-diet", "--print-rec-addr",
            "--silent",
        ], cwd=build, stdout=subprocess.PIPE, stderr=subprocess.STDOUT),
            report_path, image, pdb)
    outputs = {
        identity: scorer.communicate()[0]
        for identity, (scorer, _, _, _) in scorers.items()
    }
    for identity, (scorer, report_path, image, pdb) in scorers.items():
        gate = gates[identity]
        (build_root / f"reccmp-{identity}.log").write_bytes(outputs[identity])
        if scorer.returncode != 0:
            tail = outputs[identity][-4000:].decode("utf-8", "replace")
            fail(f"command failed ({scorer.returncode}): "
                 f"{reccmp} --target {identity}\n{tail}")

        report_bytes = report_path.read_bytes()
        try:
            if arguments.terminal:
                result = byte_identity.validate_complete_reccmp_report(
                    report_bytes, gate
                )
            else:
                result = byte_identity.validate_iteration_reccmp_report(
                    report_bytes, gate
                )
        except byte_identity.ByteIdentityError as error:
            snapshot = byte_identity.validate_reccmp_report_snapshot(
                report_bytes, gate
            )
            delta = gains_losses(
                json.loads(report_bytes),
                arguments.baseline_report if identity == "LEGO1" else None,
            )
            print(f"[isle_build] {identity} rows "
                  f"{snapshot['raw_1_0_count']}"
                  f"/{snapshot['row_count']} at 1.0, "
                  f"{snapshot['address_aligned_row_count']} address-aligned")
            if delta:
                print(delta)
            fail(f"{identity}: {error}")

        verdict["images"][identity] = {
            "raw_1_0_count": result["raw_1_0_count"],
            "row_count": result["row_count"],
            "address_aligned_row_count": result["address_aligned_row_count"],
            "image_sha256": sha256_file(image),
            "pdb_sha256": sha256_file(pdb),
            "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
        }
        summary.append(f"{identity} {result['raw_1_0_count']}"
                       f"/{result['row_count']}")

    if terminal_future is not None:
        verdict["terminal"] = terminal_future.result()
        terminal_pool.shutdown()

    verdict["elapsed_seconds"] = round(time.monotonic() - started, 1)
    verdict_path = build_root / "verdict.json"
    verdict_path.write_text(json.dumps(verdict, indent=1) + "\n")
    print(f"[isle_build] {verdict['status']}: {', '.join(summary)} "
          f"rows at 1.0 in {verdict['elapsed_seconds']}s -> {verdict_path}")
    return 0


def compose_translation_units(manifest: dict, build: Path, shadow: Path,
                              compiler: Path, jobs: int) -> None:
    """Apply manifest-listed COMDAT compositions, then relink.

    Each listed TU is compiled once more with its non-emitting declaration
    donor force-included; the donor's byte-pinned COMDAT (body, lines, FPO,
    CodeView range) is composed into the seed object by the pure composer.
    """
    import shlex
    import entropy
    units = manifest.get("translation_units", [])
    if not units:
        return
    commands = {}
    for entry in json.loads((build / "compile_commands.json").read_text()):
        commands.setdefault(Path(entry["file"]).resolve(), []).append(entry)
    image_by_target = {
        image["target"]: image["recompiled"]
        for image in manifest.get("images", {}).values()
    }
    relink_targets = set()
    for unit in units:
        source = (shadow / unit["source"]).resolve()
        entries = commands.get(source)
        if not entries:
            fail(f"no compile command for listed TU: {unit['source']}")

        def lane(predicate, description):
            matches = [entry for entry in entries
                       if predicate(entry["command"])]
            if len(matches) != 1:
                fail(f"expected one {description} compile lane for "
                     f"{unit['source']}, found {len(matches)}")
            return matches[0]

        target_marker = f"CMakeFiles/{unit['target']}.dir/"
        seed_entry = lane(lambda command: target_marker in command,
                          unit["target"])
        child = shlex.split(seed_entry["command"])
        cwd = Path(seed_entry["directory"])
        parsed = byte_identity.validate_compile_arguments(child)
        seed_object = (cwd / parsed["Fo"][1]).resolve()
        seed_pdb = (cwd / parsed["Fd"][1]).resolve()
        if not seed_object.is_file():
            fail(f"listed TU object is absent: {seed_object}")
        marker = build / (
            "composed-" + unit["target"] + "-"
            + unit["source"].replace("/", "_") + ".json"
        )
        seed_bytes = seed_object.read_bytes()
        seed_sha = hashlib.sha256(seed_bytes).hexdigest()
        if marker.exists():
            state = json.loads(marker.read_text())
            if state.get("composed_sha") == seed_sha:
                continue
        # The object on disk is not attested as this unit's fresh seed (it
        # may hold a previous composition), so recompile it in place first.
        run(child, cwd=cwd, env=build_environment(compiler),
            log=build.parent / "seed-compile.log")
        seed_bytes = seed_object.read_bytes()
        seed_sha = hashlib.sha256(seed_bytes).hexdigest()

        donor_objects = {}
        if unit["mode"] == "swap_comdat_group_order":
            composed, detail = byte_identity.compose_swap_comdat_group_order(
                seed_bytes, unit["group_order"]
            )
            byte_identity.validate_first_party_object_directive(
                composed, "composed object"
            )
            seed_object.write_bytes(composed)
            marker.write_text(json.dumps({
                "seed_sha": seed_sha,
                "composed_sha": hashlib.sha256(composed).hexdigest(),
            }, indent=1) + "\n")
            print(f"[isle_build] swapped COMDAT group order in "
                  f"{unit['target']}:{unit['source']}")
            relink_targets.add(unit["target"])
            continue
        if unit["mode"] == "compose_equal_linked_span_fpo":
            donor = unit["donors"][0]
            recipe = donor["recipe"]
            header_bytes = entropy.generate_shape(
                recipe["classes"], recipe["functions"]
            ).encode("utf-8")
            header_sha = hashlib.sha256(header_bytes).hexdigest()
            if header_sha != recipe["generated_header_sha256"]:
                fail(f"donor header rendering differs: {unit['source']}")
            header = (build.parent / "generated"
                      / f"declaration_{header_sha}.h")
            header.parent.mkdir(parents=True, exist_ok=True)
            if not header.exists() or header.read_bytes() != header_bytes:
                header.write_bytes(header_bytes)
            donor_command = list(child)
            donor_command.insert(parsed["Fo"][0], f"/FI{header}")
            # Compile the donor with identical /Fo /Fd: hold the seed aside.
            seed_pdb_bytes = (seed_pdb.read_bytes()
                              if seed_pdb.is_file() else None)
            try:
                run(donor_command, cwd=cwd, env=build_environment(compiler),
                    log=build.parent / "donor-compile.log")
                donor_objects[donor["id"]] = seed_object.read_bytes()
            finally:
                seed_object.write_bytes(seed_bytes)
                if seed_pdb_bytes is not None:
                    seed_pdb.write_bytes(seed_pdb_bytes)
            identifiers = byte_identity.declaration_identifiers(header_bytes)
            composed = seed_bytes
            for function in unit["functions"]:
                composed, detail = byte_identity.compose_equal_linked_span_fpo(
                    composed, donor_objects[function["donor"]], function,
                    identifiers,
                )
        else:
            for donor in unit["donors"]:
                recipe = donor["recipe"]
                if recipe["kind"] == "declaration_shape":
                    run_bytes = entropy.generate_shape(
                        recipe["classes"], recipe["functions"]
                    ).encode("utf-8")
                    placement = "force_include"
                else:
                    run_bytes = entropy.generate_forward_run(
                        recipe["prefix"], recipe["count"], recipe["width"]
                    ).encode("utf-8")
                    placement = recipe["placement"]
                run_sha = hashlib.sha256(run_bytes).hexdigest()
                if run_sha != recipe["generated_header_sha256"]:
                    fail(f"donor carrier rendering differs: "
                         f"{unit['source']}")
                define = recipe["compile_lane"]["required_define"]
                lane_entry = lane(
                    lambda command: f"-D{define}" in shlex.split(command),
                    define,
                )
                lane_child = shlex.split(lane_entry["command"])
                lane_parsed = byte_identity.validate_compile_arguments(
                    lane_child
                )
                probe = build.parent / "donors" / donor["id"]
                probe.mkdir(parents=True, exist_ok=True)
                shadow_bytes = source.read_bytes()
                if placement == "prefix":
                    (probe / "s.cpp").write_bytes(run_bytes + shadow_bytes)
                    force_include = []
                elif placement == "suffix":
                    decls = run_bytes.rstrip(b"\n").split(b"\n")
                    lines = shadow_bytes.split(b"\n")
                    (probe / "s.cpp").write_bytes(b"\n".join(lines + decls))
                    force_include = []
                else:
                    (probe / "s.cpp").write_bytes(shadow_bytes)
                    (probe / "run.h").write_bytes(run_bytes)
                    force_include = ["/FIrun.h"]
                donor_command = []
                include_seated = False
                for index, token in enumerate(lane_child):
                    if not include_seated and token.startswith(("-I", "/I")):
                        donor_command.append(f"/I{source.parent}")
                        include_seated = True
                    if token.startswith(("/Fo", "-Fo")):
                        donor_command.extend(force_include)
                        donor_command.append("/Foo.obj")
                        continue
                    if token.startswith(("/Fd", "-Fd")):
                        donor_command.append("/Fdo.pdb")
                        continue
                    if index == len(lane_child) - 1:
                        donor_command.append("s.cpp")
                        continue
                    donor_command.append(token)
                run(donor_command, cwd=probe,
                    env=build_environment(compiler),
                    log=build.parent / "donor-compile.log")
                donor_objects[donor["id"]] = (probe / "o.obj").read_bytes()
            composed = seed_bytes
            for function in unit["functions"]:
                if function["splice_class"] == "same_slot_resize":
                    composed, detail = byte_identity.compose_same_slot_resize(
                        composed, donor_objects[function["donor"]], function
                    )
                else:
                    composed, detail = (
                        byte_identity.compose_equal_body_comdat(
                            composed, donor_objects[function["donor"]],
                            function,
                        ))
        byte_identity.validate_first_party_object_directive(
            composed, "composed object"
        )
        seed_object.write_bytes(composed)
        marker.write_text(json.dumps({
            "seed_sha": seed_sha,
            "composed_sha": hashlib.sha256(composed).hexdigest(),
        }, indent=1) + "\n")
        print(f"[isle_build] composed {len(unit['functions'])} function(s) "
              f"into {unit['target']}:{unit['source']}")
        relink_targets.add(unit["target"])
    # A composed library-member target relinks its library and the LEGO1
    # image that consumes it.
    if any(target not in image_by_target for target in relink_targets):
        relink_targets.add("lego1")
    for target in sorted(relink_targets):
        recompiled = image_by_target.get(target)
        image = build / recompiled if recompiled else None
        if image is not None and image.exists():
            image.unlink()
        run(["cmake", "--build", str(build), "--target", target,
             "-j", str(jobs)],
            env=build_environment(compiler),
            log=build.parent / "relink.log")


if __name__ == "__main__":
    raise SystemExit(main())
