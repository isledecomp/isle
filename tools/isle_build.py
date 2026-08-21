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
import atexit
import hashlib
import json
import os
import signal
import shutil
import subprocess
import sys
import threading
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


# Every child is placed in its own POSIX process group and registered before
# the caller can wait on it.  This is intentionally process-wide: the terminal
# lane and the reccmp lanes overlap in threads, and a failure in any one lane
# must not leave compiler, linker, or Wine wrapper descendants behind.
_ACTIVE_CHILDREN: set[subprocess.Popen] = set()
_ACTIVE_CHILDREN_LOCK = threading.RLock()


def _terminate_process_tree(process: subprocess.Popen,
                            grace_seconds: float = 2.0) -> bytes:
    """Terminate one runner-owned child tree and drain its combined output."""
    if process.poll() is None:
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGTERM)
            else:
                process.terminate()
        except (OSError, ProcessLookupError):
            pass
    try:
        output = process.communicate(timeout=grace_seconds)[0]
    except subprocess.TimeoutExpired:
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except (OSError, ProcessLookupError):
            pass
        output = process.communicate()[0]
    finally:
        with _ACTIVE_CHILDREN_LOCK:
            _ACTIVE_CHILDREN.discard(process)
    return output or b""


def cancel_owned_children(kill: bool = False) -> None:
    """Signal active groups without racing their owner threads for wait()."""
    with _ACTIVE_CHILDREN_LOCK:
        children = list(_ACTIVE_CHILDREN)
    for process in children:
        if process.poll() is not None:
            continue
        try:
            if os.name == "posix":
                os.killpg(
                    process.pid, signal.SIGKILL if kill else signal.SIGTERM
                )
            elif kill:
                process.kill()
            else:
                process.terminate()
        except (OSError, ProcessLookupError):
            pass


atexit.register(cancel_owned_children, True)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def fail(message: str) -> "NoReturn":  # noqa: F821
    # Owner threads remain solely responsible for communicate()/wait().
    # Cancellation only signals here, preventing concurrent pipe consumption.
    cancel_owned_children()
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


def start_owned(command: list[str], *, cwd: Path | None = None,
                env: dict | None = None) -> subprocess.Popen:
    """Launch one command under process-tree ownership."""
    process = subprocess.Popen(
        command, cwd=cwd, env=env, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=(os.name == "posix"),
    )
    with _ACTIVE_CHILDREN_LOCK:
        _ACTIVE_CHILDREN.add(process)
    return process


def finish_owned(process: subprocess.Popen, command: list[str], *,
                 timeout_seconds: float, log: Path | None = None,
                 timeout_label: float | None = None) -> bytes:
    """Wait for an owned child, enforcing its absolute lane deadline."""
    started = time.monotonic()
    try:
        output = process.communicate(timeout=max(0.001, timeout_seconds))[0]
        with _ACTIVE_CHILDREN_LOCK:
            _ACTIVE_CHILDREN.discard(process)
    except subprocess.TimeoutExpired:
        output = _terminate_process_tree(process)
        if log is not None:
            log.parent.mkdir(parents=True, exist_ok=True)
            log.write_bytes(output)
        declared = timeout_seconds if timeout_label is None else timeout_label
        tail = output[-4000:].decode("utf-8", "replace")
        fail(
            f"command timed out after {declared:g}s: "
            f"{' '.join(command)}\n{tail}"
        )
    except BaseException:
        _terminate_process_tree(process)
        raise
    if log is not None:
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_bytes(output)
    if process.returncode != 0:
        tail = output[-4000:].decode("utf-8", "replace")
        fail(
            f"command failed ({process.returncode}, "
            f"{time.monotonic() - started:.1f}s): {' '.join(command)}\n{tail}"
        )
    return output


def run(command: list[str], *, timeout_seconds: float,
        cwd: Path | None = None, env: dict | None = None,
        log: Path | None = None) -> None:
    process = start_owned(command, cwd=cwd, env=env)
    finish_owned(
        process, command, timeout_seconds=timeout_seconds, log=log,
    )


def build_environment(compiler: Path) -> dict:
    environment = dict(os.environ)
    environment["PATH"] = (
        str(compiler.parent) + os.pathsep + environment.get("PATH", "")
    )
    return environment


def configure(build: Path, shadow: Path, plan: Path, compiler: Path,
              jobs: int, timeout_seconds: float,
              extra: list[str] | None = None) -> None:
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
    ], timeout_seconds=timeout_seconds, env=build_environment(compiler),
        log=build / "configure.log")


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


def terminal_lane(manifest: dict, source_overlay: dict, gates: dict,
                  build_root: Path,
                  shadow: Path, plan: Path, compiler: Path, jobs: int,
                  require_identity: bool, compile_timeout: float,
                  link_timeout: float) -> dict:
    """Configure and link the no-/debug terminal images, stamp the pinned
    retail link times, and report per-image MD5 and byte distance."""
    terminal_build = build_root / "terminal"
    terminal_build.mkdir(parents=True, exist_ok=True)
    configure(terminal_build, shadow, plan, compiler, jobs, compile_timeout,
              extra=["-DISLE_BYTE_IDENTITY_TERMINAL=TRUE"])
    targets = [gates[identity]["target"] for identity in gates]
    run(["cmake", "--build", str(terminal_build), "--target", *targets,
         "-j", str(jobs)],
        # One CMake driver serially launches many manifest-bounded children.
        # Keep an outer anti-wedge ceiling without treating the per-child
        # producer limit as a cold whole-build deadline.
        timeout_seconds=max(compile_timeout, link_timeout) * 4,
        env=build_environment(compiler),
        log=build_root / "terminal-build.log")
    compose_translation_units(
        manifest, source_overlay, terminal_build, shadow, compiler,
        jobs, compile_timeout, link_timeout)
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
                timeout_seconds=link_timeout,
                log=build_root / f"iatorder-{identity}.log")
            stamped = stamped_path.read_bytes()
        if gate.get("thunk_order") == "retail_adjacent_pair_swap_v1":
            stamped = byte_identity.restore_adjacent_thunk_pair_order(
                stamped, (ROOT / gate["original"]).read_bytes()
            )
            stamped_path.write_bytes(stamped)
        original = (ROOT / gate["original"]).read_bytes()
        md5 = hashlib.md5(stamped).hexdigest()
        sha256 = hashlib.sha256(stamped).hexdigest()
        # Literal equality is the final address/layout proof.  MD5 and SHA-256
        # are reported and checked against their independent manifest pins,
        # but neither digest substitutes for comparing the actual bytes.
        identical = (
            stamped == original
            and md5 == gate["original_md5"]
            and sha256 == gate["original_sha256"]
        )
        if len(stamped) == len(original):
            distance = sum(1 for a, b in zip(stamped, original) if a != b)
            size_note = ""
        else:
            distance = None
            size_note = f" size {len(stamped)} vs retail {len(original)}"
        results[identity] = {
            "md5": md5,
            "retail_md5": gate["original_md5"],
            "sha256": sha256,
            "retail_sha256": gate["original_sha256"],
            "identical": identical,
            "byte_distance": distance,
            "size": len(stamped),
            "retail_size": len(original),
        }
        state = ("IDENTICAL" if identical
                 else f"distance {distance}{size_note}")
        states.append(f"[isle_build] terminal {identity}: {state}")
        if require_identity and not identical:
            print("\n".join(states))
            fail(
                f"terminal {identity} bytes differ from retail: "
                f"MD5 {md5}, SHA-256 {sha256}"
            )
    # One print per lane: the terminal lane may overlap the image scoring,
    # so its report lines are emitted together.
    print("\n".join(states))
    return results


def gains_losses(report: dict, baseline_bytes: bytes | None) -> str:
    if baseline_bytes is None:
        return ""
    try:
        baseline = json.loads(baseline_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError):
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
    # Per-object compiler PDBs (ISLE_PER_OBJECT_PDB) make parallel VC4.2
    # compiles safe.  Four children are the measured current ceiling: Wine's
    # server serializes most of this workload, so wider pools add contention.
    parser.add_argument("--jobs", type=int,
                        default=min(4, os.cpu_count() or 4))
    parser.add_argument("--terminal", action="store_true",
                        help="require complete rows and literal retail bytes")
    parser.add_argument("--md5-distance", action="store_true",
                        help="also link the no-/debug terminal images and "
                             "report byte distance to retail (no MD5 gate)")
    parser.add_argument(
        "--baseline-report", type=Path, required=True,
        help="last accepted current-HEAD LEGO1 report used to name gains/losses",
    )
    arguments = parser.parse_args()
    if not 1 <= arguments.jobs <= 4:
        parser.error("--jobs must be between 1 and 4")

    compiler = arguments.compiler.resolve()
    build_root = arguments.build_dir.resolve()
    build_root.mkdir(parents=True, exist_ok=True)
    try:
        validated = byte_identity.validate_manifest(
            arguments.manifest, ROOT, build_root,
            configured_compiler=str(compiler),
        )
    except byte_identity.ByteIdentityError as error:
        fail(f"manifest validation failed: {error}")
    manifest = validated["manifest"]
    pins = verify_pins(manifest, compiler)
    reccmp = resolve_reccmp(manifest)
    try:
        baseline_bytes = arguments.baseline_report.read_bytes()
        byte_identity.validate_iteration_reccmp_report(
            baseline_bytes, manifest["images"]["LEGO1"]
        )
    except (OSError, byte_identity.ByteIdentityError) as error:
        fail(f"baseline report is not the current accepted LEGO1 set: {error}")
    compile_timeout = validated["max_child_seconds"]
    link_timeout = validated["terminal_producers"]["link"][
        "max_child_seconds"
    ]
    reccmp_timeout = validated["terminal_producers"]["reccmp"][
        "max_child_seconds"
    ]

    shadow = build_root / "src"
    build = build_root / "build"
    plan = build_root / "plan.cmake"
    started = time.monotonic()
    overlay, rendered = render_overlay(manifest)
    changed = sync_shadow(shadow, rendered)
    write_plan(plan, overlay)
    print(f"[isle_build] shadow synced ({changed} files changed, "
          f"{time.monotonic() - started:.1f}s)")

    configure(build, shadow, plan, compiler, arguments.jobs, compile_timeout)
    gates = pins["image_gates"]
    targets = [gates[identity]["target"] for identity in gates]
    run(
        ["cmake", "--build", str(build), "--target", *targets,
         "-j", str(arguments.jobs)],
        timeout_seconds=max(compile_timeout, link_timeout) * 4,
        env=build_environment(compiler), log=build_root / "build.log",
    )
    print(f"[isle_build] build complete ({time.monotonic() - started:.1f}s)")

    compose_translation_units(
        manifest, validated["source_overlay"], build, shadow, compiler,
        arguments.jobs, compile_timeout, link_timeout)

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
            terminal_lane, manifest, validated["source_overlay"], gates,
            build_root, shadow, plan,
            compiler, arguments.jobs, arguments.terminal,
            compile_timeout, link_timeout,
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
        if report_path.exists():
            report_path.unlink()
        command = [
            str(reccmp), "--target", identity,
            "--json", str(report_path), "--json-diet", "--print-rec-addr",
            "--silent",
        ]
        scorers[identity] = (
            start_owned(command, cwd=build), time.monotonic(), command,
            report_path, image, pdb,
        )
    outputs = {}
    for identity, (scorer, launched, command, _, _, _) in scorers.items():
        remaining = reccmp_timeout - (time.monotonic() - launched)
        outputs[identity] = finish_owned(
            scorer, command, timeout_seconds=max(0.001, remaining),
            timeout_label=reccmp_timeout,
            log=build_root / f"reccmp-{identity}.log",
        )
    for identity, (scorer, _, _, report_path, image, pdb) in scorers.items():
        gate = gates[identity]

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
                baseline_bytes if identity == "LEGO1" else None,
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


def compose_translation_units(manifest: dict, source_overlay: dict,
                              build: Path, shadow: Path,
                              compiler: Path, jobs: int,
                              compile_timeout: float,
                              link_timeout: float) -> None:
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
    canonical_overlay_operations = {
        item["logical_path"]: item["operations"]
        for item in source_overlay.get("outputs", [])
    }

    def compose_unit(unit: dict) -> tuple[str | None, str | None]:
        """Compose one listed TU; returns (relink target, report line).

        Each unit owns its own seed object, per-object PDB, probe
        directories, logs and marker, so units are independent of one
        another and safe to run concurrently.
        """
        source = (shadow / unit["source"]).resolve()
        entries = commands.get(source)
        if not entries:
            fail(f"no compile command for listed TU: {unit['source']}")

        def lane(predicate, description, pool=None):
            matches = [entry for entry in (entries if pool is None else pool)
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
        unit_sha = hashlib.sha256(
            json.dumps(unit, sort_keys=True).encode()).hexdigest()
        if marker.exists():
            state = json.loads(marker.read_text())
            if (state.get("composed_sha") == seed_sha
                    and state.get("unit_sha") == unit_sha):
                return None, None
        # The object on disk is not attested as this unit's fresh seed (it
        # may hold a previous composition), so recompile it in place first.
        # The PDB is removed first: MSVC 4.2 /Zi carries CodeView type
        # indices that depend on what the PDB already holds, so a seed
        # compiled against an accumulated PDB (one this build dir happens to
        # have polluted with earlier donor-carrier types) produces different
        # `.debug$S` bytes -- and therefore a different pinned seed metadata
        # digest -- from the identical compile in a clean tree.  Starting
        # from no PDB makes the seed a function of the source alone, which is
        # what a pin has to be if a cold checkout is to reproduce it.
        stale_pdb = seed_pdb.read_bytes() if seed_pdb.is_file() else None
        if stale_pdb is not None:
            seed_pdb.unlink()
        try:
            run(child, timeout_seconds=compile_timeout, cwd=cwd,
                env=build_environment(compiler),
                log=build.parent / f"{marker.stem}-seed.log")
        except BaseException:
            # An interrupted seed compile must not leave the tree without a
            # PDB: the next link would fail with LNK1202 on an object CMake
            # still considers up to date.
            if stale_pdb is not None and not seed_pdb.is_file():
                seed_pdb.write_bytes(stale_pdb)
            raise
        seed_bytes = seed_object.read_bytes()
        seed_sha = hashlib.sha256(seed_bytes).hexdigest()

        donor_objects = {}
        donor_sources = {}
        if unit["mode"] in ("swap_comdat_group_order",
                            "restore_comdat_group_order"):
            if unit["mode"] == "swap_comdat_group_order":
                composed, detail = (
                    byte_identity.compose_swap_comdat_group_order(
                        seed_bytes, unit["group_order"]))
                verb = "swapped"
            else:
                composed = seed_bytes
                orders = unit["group_order"]
                if orders and isinstance(orders[0], list):
                    lists = orders
                else:
                    lists = [orders]
                for names in lists:
                    composed, detail = (
                        byte_identity.compose_restore_comdat_group_order(
                            composed, {"group_order": names}))
                verb = "restored"
            byte_identity.validate_first_party_object_directive(
                composed, "composed object"
            )
            seed_object.write_bytes(composed)
            marker.write_text(json.dumps({
                "seed_sha": seed_sha,
                "composed_sha": hashlib.sha256(composed).hexdigest(),
            "unit_sha": unit_sha,
            }, indent=1) + "\n")
            return unit["target"], (
                f"[isle_build] {verb} COMDAT group order in "
                f"{unit['target']}:{unit['source']}"
            )
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
                # The name is the content sha, so concurrent writers hold
                # identical bytes; stage + rename keeps readers whole.
                staging = header.with_name(
                    f"{header.name}.{os.getpid()}-{threading.get_ident()}"
                )
                staging.write_bytes(header_bytes)
                staging.replace(header)
            donor_command = list(child)
            donor_command.insert(parsed["Fo"][0], f"/FI{header}")
            # Compile the donor with identical /Fo /Fd: hold the seed aside.
            seed_pdb_bytes = (seed_pdb.read_bytes()
                              if seed_pdb.is_file() else None)
            try:
                run(donor_command, timeout_seconds=compile_timeout, cwd=cwd,
                    env=build_environment(compiler),
                    log=build.parent / f"{marker.stem}-donor.log")
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
                if (recipe["kind"]
                        == byte_identity.CLEAN_CURRENT_SOURCE_CROSS_TU_RECIPE):
                    # Compile an unmodified, explicitly pinned different TU
                    # through that TU's own ordinary command.  Only /Fo and
                    # /Fd are redirected into the private donor directory;
                    # no source overlay or generated carrier is admitted.
                    donor_relative = recipe["donor_source"]
                    donor_source_path = (shadow / donor_relative).resolve()
                    if (hashlib.sha256(donor_source_path.read_bytes())
                            .hexdigest() != recipe["source_sha256"]):
                        fail(f"clean cross-TU donor source differs: "
                             f"{donor_relative}")
                    donor_entries = commands.get(donor_source_path)
                    if not donor_entries:
                        fail(f"no compile command for donor source: "
                             f"{donor_relative}")
                    define = recipe["compile_lane"]["required_define"]
                    lane_entry = lane(
                        lambda command: f"-D{define}" in shlex.split(command),
                        define, donor_entries,
                    )
                    lane_child = shlex.split(lane_entry["command"])
                    lane_parsed = byte_identity.validate_compile_arguments(
                        lane_child)
                    lane_source = Path(lane_parsed["source_token"])
                    if not lane_source.is_absolute():
                        lane_source = Path(lane_entry["directory"]) / lane_source
                    if lane_source.resolve() != donor_source_path:
                        fail(f"cross-TU donor command source differs: "
                             f"{donor_relative}")
                    probe = (build.parent / "donors"
                             / f"{marker.stem}-{donor['id']}")
                    shutil.rmtree(probe, ignore_errors=True)
                    probe.mkdir(parents=True)
                    donor_command = []
                    for token in lane_child:
                        if token.startswith(("/Fo", "-Fo")):
                            donor_command.append("/Foo.obj")
                        elif token.startswith(("/Fd", "-Fd")):
                            donor_command.append("/Fdo.pdb")
                        else:
                            donor_command.append(token)
                    run(donor_command, timeout_seconds=compile_timeout,
                        cwd=probe, env=build_environment(compiler),
                        log=build.parent
                        / f"{marker.stem}-{donor['id']}.log")
                    donor_objects[donor["id"]] = (
                        probe / "o.obj").read_bytes()
                    continue
                if (recipe["kind"]
                        == byte_identity
                        .CROSS_TU_INSTRUCTION_SOURCE_RECIPE):
                    # The overlaid sibling.  Same shape as the clean cross-TU
                    # donor above -- that TU's own ordinary command, only /Fo
                    # and /Fd redirected, so the compile happens at the real
                    # shadow path in the real arena -- but the text it pins is
                    # the EFFECTIVE rendering, declared as such by the recipe,
                    # because that is the text this build actually compiles
                    # for that unit.  Pinning the checked-in text here would
                    # be a false statement about which source produced the
                    # bytes, and is what the clean recipe rightly refuses.
                    donor_relative = recipe["donor_source"]
                    donor_source_path = (shadow / donor_relative).resolve()
                    rendered = donor_source_path.read_bytes()
                    rendered_sha = hashlib.sha256(rendered).hexdigest()
                    if (rendered_sha
                            != recipe["donor_effective_source_sha256"]):
                        fail(f"overlaid cross-TU instruction donor source "
                             f"differs from its effective pin: "
                             f"{donor_relative}")
                    if (rendered_sha != recipe["rendered_source_sha256"]
                            or len(rendered)
                            != recipe["rendered_source_size"]
                            or rendered.count(b"\n")
                            != recipe["rendered_source_line_count"]):
                        fail(f"overlaid cross-TU instruction donor rendering "
                             f"differs from its pins: {donor_relative}")
                    donor_entries = commands.get(donor_source_path)
                    if not donor_entries:
                        fail(f"no compile command for donor source: "
                             f"{donor_relative}")
                    define = recipe["compile_lane"]["required_define"]
                    lane_entry = lane(
                        lambda command: f"-D{define}" in shlex.split(command),
                        define, donor_entries,
                    )
                    lane_child = shlex.split(lane_entry["command"])
                    lane_parsed = byte_identity.validate_compile_arguments(
                        lane_child)
                    lane_source = Path(lane_parsed["source_token"])
                    if not lane_source.is_absolute():
                        lane_source = Path(lane_entry["directory"]) / lane_source
                    if lane_source.resolve() != donor_source_path:
                        fail(f"overlaid cross-TU donor command source "
                             f"differs: {donor_relative}")
                    probe = (build.parent / "donors"
                             / f"{marker.stem}-{donor['id']}")
                    shutil.rmtree(probe, ignore_errors=True)
                    probe.mkdir(parents=True)
                    donor_command = []
                    for token in lane_child:
                        if token.startswith(("/Fo", "-Fo")):
                            donor_command.append("/Foo.obj")
                        elif token.startswith(("/Fd", "-Fd")):
                            donor_command.append("/Fdo.pdb")
                        else:
                            donor_command.append(token)
                    run(donor_command, timeout_seconds=compile_timeout,
                        cwd=probe, env=build_environment(compiler),
                        log=build.parent
                        / f"{marker.stem}-{donor['id']}.log")
                    donor_objects[donor["id"]] = (
                        probe / "o.obj").read_bytes()
                    continue
                if recipe["kind"] == "donor_source_overlay":
                    # Extension A.  Render the donor's private copies of the
                    # checked-in paths, stage them where ONLY this compile can
                    # see them, and compile.  A6c: the private include dir is
                    # seated on this command alone, so no other compile in the
                    # build can reach it.  A6b is carried by the shipped
                    # overlay's own pins, which this never touches.
                    probe = (build.parent / "donors"
                             / f"{marker.stem}-{donor['id']}")
                    shutil.rmtree(probe, ignore_errors=True)
                    (probe / "inc").mkdir(parents=True, exist_ok=True)
                    projection = recipe["compile_lane"].get(
                        "include_projection"
                    )
                    private_shadow = None
                    if projection == "source_root_mirror_v1":
                        # A flat -I override cannot shadow nested quoted
                        # includes: once a clean parent header is opened,
                        # its siblings win before -I is searched.  Mirror the
                        # already-rendered effective source tree privately so
                        # every include keeps its logical path and can see a
                        # rendered header override.  This copy is donor-only.
                        private_shadow = probe / "inc" / "source"
                        shutil.copytree(shadow, private_shadow)
                    rendered_donor = byte_identity.render_donor_source_overlay(
                        recipe, byte_identity.checked_source_root(),
                        canonical_operations=(
                            canonical_overlay_operations.get(unit["source"])
                            if recipe.get("canonical_overlay_replay")
                            == "owning_translation_unit_v1" else None
                        ),
                    )
                    donor_sources[donor["id"]] = rendered_donor.get(
                        unit["source"]
                    )
                    for path, payload in rendered_donor.items():
                        if path == unit["source"]:
                            (probe / "s.cpp").write_bytes(payload)
                        else:
                            (probe / "inc" / Path(path).name).write_bytes(
                                payload)
                            if private_shadow is not None:
                                projected = private_shadow / path
                                projected.parent.mkdir(
                                    parents=True, exist_ok=True
                                )
                                projected.write_bytes(payload)
                    define = recipe["compile_lane"]["required_define"]
                    lane_entry = lane(
                        lambda command: f"-D{define}" in shlex.split(command),
                        define,
                    )
                    lane_child = shlex.split(lane_entry["command"])
                    byte_identity.validate_compile_arguments(lane_child)
                    donor_command = []
                    include_seated = False
                    for index, token in enumerate(lane_child):
                        if not include_seated and token.startswith(("-I", "/I")):
                            donor_command.append(f"/I{probe / 'inc'}")
                            if private_shadow is not None:
                                donor_command.append(
                                    f"/I{private_shadow / source.parent.relative_to(shadow)}"
                                )
                            donor_command.append(f"/I{source.parent}")
                            include_seated = True
                        if (private_shadow is not None
                                and token.startswith(("-I", "/I"))):
                            include_path = Path(token[2:]).resolve()
                            try:
                                relative = include_path.relative_to(shadow)
                            except ValueError:
                                pass
                            else:
                                donor_command.append(
                                    f"{token[:2]}{private_shadow / relative}"
                                )
                        if token.startswith(("/Fo", "-Fo")):
                            donor_command.append("/Foo.obj")
                            continue
                        if token.startswith(("/Fd", "-Fd")):
                            donor_command.append("/Fdo.pdb")
                            continue
                        if index == len(lane_child) - 1:
                            donor_command.append("s.cpp")
                            continue
                        donor_command.append(token)
                    run(donor_command, timeout_seconds=compile_timeout,
                        cwd=probe,
                        env=build_environment(compiler),
                        log=build.parent / f"{marker.stem}-{donor['id']}.log")
                    donor_objects[donor["id"]] = (probe / "o.obj").read_bytes()
                    continue
                if (recipe["kind"] == byte_identity
                        .SAME_TU_DECLARATION_CARRIER_RECIPE):
                    run_bytes = (
                        entropy.generate_forward_run(
                            recipe["forward_prefix"],
                            recipe["forward_count"],
                            recipe["forward_width"],
                        ).encode("utf-8")
                        + entropy.generate_extern_run(
                            recipe["extern_prefix"],
                            recipe["extern_count"],
                            recipe["extern_width"],
                        ).encode("utf-8")
                    )
                    placement = "prefix_forward_after_includes_extern"
                elif recipe["kind"] == "declaration_shape":
                    run_bytes = entropy.generate_shape(
                        recipe["classes"], recipe["functions"]
                    ).encode("utf-8")
                    placement = "force_include"
                elif recipe["kind"] == "pad_shape":
                    run_bytes = entropy.generate_pad_shape(
                        recipe["classes"], recipe["functions_per_class"]
                    ).encode("utf-8")
                    placement = "force_include"
                elif recipe["kind"] == "extern_run_pair":
                    run_bytes = b"".join(
                        entropy.generate_extern_run(
                            prefix, count, recipe["width"]
                        ).encode("utf-8")
                        for prefix, count in (
                            (recipe["header_prefix"],
                             recipe["header_count"]),
                            (recipe["seat_prefix"], recipe["seat_count"]),
                        )
                        if count
                    )
                    placement = "extern_pair"
                elif recipe["kind"] == "declaration_run_triple":
                    run_bytes = b"".join(
                        entropy.generate_forward_run(
                            recipe[f"{seat}_prefix"],
                            recipe[f"{seat}_count"],
                            recipe["width"],
                        ).encode("utf-8")
                        for seat in ("pre", "post", "eof")
                        if recipe[f"{seat}_count"]
                    )
                    placement = "run_triple"
                elif recipe["kind"] == "extern_pair_with_pad":
                    run_bytes = b"".join(
                        entropy.generate_extern_run(
                            prefix, count, recipe["width"]
                        ).encode("utf-8")
                        for prefix, count in (
                            (recipe["header_prefix"],
                             recipe["header_count"]),
                            (recipe["seat_prefix"], recipe["seat_count"]),
                        )
                        if count
                    ) + entropy.generate_pad_shape(
                        recipe["classes"], recipe["functions_per_class"]
                    ).encode("utf-8")
                    placement = "extern_pair_with_pad"
                elif recipe["kind"] == "extern_pair_with_shape":
                    run_bytes = b"".join(
                        entropy.generate_extern_run(
                            prefix, count, recipe["width"]
                        ).encode("utf-8")
                        for prefix, count in (
                            (recipe["header_prefix"],
                             recipe["header_count"]),
                            (recipe["seat_prefix"], recipe["seat_count"]),
                        )
                        if count
                    ) + entropy.generate_shape(
                        recipe["classes"], recipe["functions"]
                    ).encode("utf-8")
                    placement = "extern_pair_with_shape"
                elif recipe["kind"] == "forward_run_with_shape":
                    run_bytes = (
                        entropy.generate_forward_run(
                            recipe["prefix"], recipe["count"],
                            recipe["width"],
                        ).encode("utf-8")
                        + entropy.generate_shape(
                            recipe["classes"], recipe["functions"]
                        ).encode("utf-8")
                    )
                    placement = "run_with_shape"
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
                # Class C donors name the TU they compile: another object's
                # copy of a multiply-defined COMDAT.  Everything else compiles
                # the unit's own source.
                cross_tu_complete = (
                    recipe.get("role_policy")
                    == byte_identity.CROSS_TU_COMPLETE_TARGET_RECIPE_POLICY
                )
                donor_relative = recipe.get("donor_source")
                if donor_relative:
                    donor_source_path = (shadow / donor_relative).resolve()
                    donor_entries = commands.get(donor_source_path)
                    if not donor_entries:
                        fail(f"no compile command for donor source: "
                             f"{donor_relative}")
                else:
                    donor_source_path, donor_entries = source, entries
                lane_entry = lane(
                    lambda command: f"-D{define}" in shlex.split(command),
                    define, donor_entries,
                )
                lane_child = shlex.split(lane_entry["command"])
                lane_parsed = byte_identity.validate_compile_arguments(
                    lane_child
                )
                if cross_tu_complete:
                    lane_source = Path(lane_parsed["source_token"])
                    if not lane_source.is_absolute():
                        lane_source = (
                            Path(lane_entry["directory"]) / lane_source
                        )
                    if lane_source.resolve() != donor_source_path:
                        fail(f"cross-TU complete-target command source "
                             f"differs: {donor_relative}")
                # Donor ids repeat across units, so the probe directory is
                # namespaced by unit to keep concurrent units independent.
                probe = (build.parent / "donors"
                         / f"{marker.stem}-{donor['id']}")
                probe.mkdir(parents=True, exist_ok=True)
                shadow_bytes = donor_source_path.read_bytes()
                if placement == "prefix_forward_after_includes_extern":
                    rendered_source = (
                        byte_identity.render_same_tu_declaration_carrier(
                            shadow_bytes, recipe,
                            f"same-TU carrier {donor['id']}",
                        )
                    )
                    if (hashlib.sha256(rendered_source).hexdigest()
                            != recipe["rendered_source_sha256"]
                            or len(rendered_source)
                            != recipe["rendered_source_size"]
                            or rendered_source.count(b"\n")
                            != recipe["rendered_source_line_count"]):
                        fail(f"same-TU donor rendering differs: "
                             f"{unit['source']}")
                    (probe / "s.cpp").write_bytes(rendered_source)
                    donor_sources[donor["id"]] = rendered_source
                    force_include = []
                elif placement == "prefix":
                    (probe / "s.cpp").write_bytes(run_bytes + shadow_bytes)
                    force_include = []
                elif placement == "suffix":
                    decls = run_bytes.rstrip(b"\n").split(b"\n")
                    lines = shadow_bytes.split(b"\n")
                    (probe / "s.cpp").write_bytes(b"\n".join(lines + decls))
                    force_include = []
                elif placement == "run_triple":
                    # pre-include at file start, post-include after the last
                    # #include, eof at end of file -- the three seats filled
                    # independently.
                    lines = shadow_bytes.split(b"\n")
                    insert_at = 0
                    for line_index, line in enumerate(lines):
                        if line.startswith(b"#include"):
                            insert_at = line_index + 1

                    def seat_lines(seat):
                        count = recipe[f"{seat}_count"]
                        if not count:
                            return []
                        return entropy.generate_forward_run(
                            recipe[f"{seat}_prefix"], count, recipe["width"],
                        ).encode("utf-8").rstrip(b"\n").split(b"\n")

                    (probe / "s.cpp").write_bytes(b"\n".join(
                        seat_lines("pre") + lines[:insert_at]
                        + seat_lines("post") + lines[insert_at:]
                        + seat_lines("eof")
                    ))
                    force_include = []
                elif placement == "after_includes":
                    # The bench's fwdP axis: the run seats immediately after
                    # the last #include, which is a different compiler state
                    # from seating it ahead of them.
                    decls = run_bytes.rstrip(b"\n").split(b"\n")
                    lines = shadow_bytes.split(b"\n")
                    insert_at = 0
                    for line_index, line in enumerate(lines):
                        if line.startswith(b"#include"):
                            insert_at = line_index + 1
                    (probe / "s.cpp").write_bytes(b"\n".join(
                        lines[:insert_at] + decls + lines[insert_at:]))
                    force_include = []
                elif placement == "run_with_shape":
                    # Stacked carrier: the forward-declaration run seats at
                    # its placement, the declaration shape is force-included.
                    forward_run = entropy.generate_forward_run(
                        recipe["prefix"], recipe["count"], recipe["width"],
                    ).encode("utf-8")
                    shape_run = entropy.generate_shape(
                        recipe["classes"], recipe["functions"]
                    ).encode("utf-8")
                    if cross_tu_complete:
                        rendered_source = (
                            byte_identity
                            .render_cross_tu_complete_target_source(
                                recipe, unit["source"], donor_relative,
                                shadow_bytes, forward_run,
                                f"cross-TU complete-target {donor['id']}",
                            )
                        )
                    elif recipe["placement"] == "prefix":
                        rendered_source = forward_run + shadow_bytes
                    else:
                        decls = forward_run.rstrip(b"\n").split(b"\n")
                        lines = shadow_bytes.split(b"\n")
                        rendered_source = b"\n".join(lines + decls)
                    (probe / "s.cpp").write_bytes(rendered_source)
                    (probe / "run.h").write_bytes(shape_run)
                    # A same-TU instruction hybrid may pair two of these
                    # stacked carriers, and its source-identity proof needs
                    # the rendering they actually compiled.
                    donor_sources[donor["id"]] = rendered_source
                    force_include = ["/FIrun.h"]
                elif placement in ("extern_pair_with_shape",
                                   "extern_pair_with_pad"):
                    # Both extern seats AND the force-included shape: the
                    # count lattice is 2-D, so the two seats and the shape
                    # can each be fixing a different byte.
                    header_run = entropy.generate_extern_run(
                        recipe["header_prefix"], recipe["header_count"],
                        recipe["width"],
                    ).encode("utf-8") if recipe["header_count"] else b""
                    seat_run = entropy.generate_extern_run(
                        recipe["seat_prefix"], recipe["seat_count"],
                        recipe["width"],
                    ).encode("utf-8") if recipe["seat_count"] else b""
                    lines = shadow_bytes.split(b"\n")
                    insert_at = 0
                    for line_index, line in enumerate(lines):
                        if line.startswith(b"#include"):
                            insert_at = line_index + 1
                    header_lines = (header_run.rstrip(b"\n").split(b"\n")
                                    if header_run else [])
                    seat_lines = (seat_run.rstrip(b"\n").split(b"\n")
                                  if seat_run else [])
                    (probe / "s.cpp").write_bytes(b"\n".join(
                        lines[:insert_at] + header_lines
                        + lines[insert_at:] + seat_lines
                    ))
                    (probe / "run.h").write_bytes(
                        entropy.generate_pad_shape(
                            recipe["classes"], recipe["functions_per_class"]
                        ).encode("utf-8")
                        if placement == "extern_pair_with_pad"
                        else entropy.generate_shape(
                            recipe["classes"], recipe["functions"]
                        ).encode("utf-8"))
                    force_include = ["/FIrun.h"]
                elif placement == "extern_pair":
                    # Header run seats after the last #include, seat run
                    # appends at EOF (the sweep bench's exact construction).
                    header_run = entropy.generate_extern_run(
                        recipe["header_prefix"], recipe["header_count"],
                        recipe["width"],
                    ).encode("utf-8") if recipe["header_count"] else b""
                    seat_run = entropy.generate_extern_run(
                        recipe["seat_prefix"], recipe["seat_count"],
                        recipe["width"],
                    ).encode("utf-8") if recipe["seat_count"] else b""
                    lines = shadow_bytes.split(b"\n")
                    insert_at = 0
                    for line_index, line in enumerate(lines):
                        if line.startswith(b"#include"):
                            insert_at = line_index + 1
                    header_lines = (header_run.rstrip(b"\n").split(b"\n")
                                    if header_run else [])
                    seat_lines = (seat_run.rstrip(b"\n").split(b"\n")
                                  if seat_run else [])
                    (probe / "s.cpp").write_bytes(b"\n".join(
                        lines[:insert_at] + header_lines
                        + lines[insert_at:] + seat_lines
                    ))
                    force_include = []
                else:
                    (probe / "s.cpp").write_bytes(shadow_bytes)
                    (probe / "run.h").write_bytes(run_bytes)
                    force_include = ["/FIrun.h"]
                donor_command = []
                include_seated = False
                for index, token in enumerate(lane_child):
                    if not include_seated and token.startswith(("-I", "/I")):
                        donor_command.append(f"/I{donor_source_path.parent}")
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
                run(donor_command, timeout_seconds=compile_timeout, cwd=probe,
                    env=build_environment(compiler),
                    log=build.parent / f"{marker.stem}-{donor['id']}.log")
                donor_objects[donor["id"]] = (probe / "o.obj").read_bytes()
            composed = seed_bytes
            for function in unit["functions"]:
                if (function["splice_class"]
                        == byte_identity
                        .CROSS_TU_COMPLETE_TARGET_RESIZE_CLASS):
                    retail = function["retail_oracle"]
                    target_donor = donor_objects[function["donor"]]
                    complete_donor = donor_objects[
                        function["complete_donor"]]
                    composed, detail = (
                        byte_identity
                        .compose_retail_exact_cross_tu_complete_target_resize(
                            composed, target_donor, complete_donor, function,
                            byte_identity.retail_image_body(
                                manifest, retail["image"],
                                int(retail["address"], 16), retail["length"],
                            ),
                        )
                    )
                    byte_identity.validate_donor_object_excluded(
                        composed, [target_donor, complete_donor])
                elif (function["splice_class"]
                        == byte_identity
                        .SAME_TU_INSTRUCTION_HYBRID_RESIZE_CLASS):
                    retail = function["retail_oracle"]
                    target_donor_id = function["donor"]
                    instruction_donor_id = function["instruction_donor"]
                    target_donor = donor_objects[target_donor_id]
                    instruction_donor = donor_objects[
                        instruction_donor_id]
                    target_source = donor_sources.get(target_donor_id)
                    instruction_source = donor_sources.get(
                        instruction_donor_id)
                    if target_source is None or instruction_source is None:
                        fail("same-TU instruction-hybrid donor omits its "
                             f"translation unit: {unit['source']}")
                    composed, detail = (
                        byte_identity
                        .compose_retail_exact_same_tu_instruction_hybrid_resize(
                            composed, target_donor, instruction_donor,
                            function,
                            byte_identity.retail_image_body(
                                manifest, retail["image"],
                                int(retail["address"], 16),
                                retail["length"],
                            ),
                            source.read_bytes(), target_source,
                            instruction_source,
                        )
                    )
                    byte_identity.validate_donor_object_excluded(
                        composed, [target_donor, instruction_donor])
                elif (function["splice_class"]
                        == byte_identity
                        .SOURCE_INSTRUCTION_HYBRID_RESIZE_CLASS):
                    retail = function["retail_oracle"]
                    target_donor = donor_objects[function["donor"]]
                    instruction_donor_id = function["instruction_donor"]
                    instruction_donor = donor_objects[
                        instruction_donor_id]
                    instruction_source = donor_sources.get(
                        instruction_donor_id)
                    if instruction_source is None:
                        fail("source instruction-hybrid donor omits its "
                             f"translation unit: {unit['source']}")
                    composed, detail = (
                        byte_identity
                        .compose_retail_exact_source_instruction_hybrid_resize(
                            composed, target_donor, instruction_donor,
                            function,
                            byte_identity.retail_image_body(
                                manifest, retail["image"],
                                int(retail["address"], 16),
                                retail["length"],
                            ),
                            source.read_bytes(), instruction_source,
                        )
                    )
                    byte_identity.validate_donor_object_excluded(
                        composed, [target_donor, instruction_donor])
                elif (function["splice_class"]
                        == byte_identity
                        .CROSS_TU_INSTRUCTION_HYBRID_RESIZE_CLASS):
                    retail = function["retail_oracle"]
                    target_donor = donor_objects[function["donor"]]
                    instruction_donor = donor_objects[
                        function["instruction_donor"]]
                    composed, detail = (
                        byte_identity
                        .compose_retail_exact_cross_tu_instruction_hybrid_resize(
                            composed, target_donor, instruction_donor,
                            function,
                            byte_identity.retail_image_body(
                                manifest, retail["image"],
                                int(retail["address"], 16),
                                retail["length"],
                            ),
                        )
                    )
                    byte_identity.validate_donor_object_excluded(
                        composed, [target_donor, instruction_donor])
                elif (function["splice_class"]
                        == "retail_exact_instruction_mosaic"):
                    retail = function["retail_oracle"]
                    retail_body = byte_identity.retail_image_body(
                        manifest, retail["image"],
                        int(retail["address"], 16), retail["length"],
                    )
                    if "target_source_refactor" in function:
                        donor_source = donor_sources.get(function["donor"])
                        if donor_source is None:
                            fail("source-mosaic donor omits its translation "
                                 f"unit: {unit['source']}")
                        composed, detail = (
                            byte_identity
                            .compose_retail_exact_source_instruction_mosaic(
                                composed, donor_objects[function["donor"]],
                                function, retail_body,
                                source.read_bytes(), donor_source,
                                {
                                    item["donor"]:
                                        donor_objects[item["donor"]]
                                    for item in
                                    function.get("donor_variants", [])
                                },
                            )
                        )
                    else:
                        composed, detail = (
                            byte_identity.compose_retail_exact_instruction_mosaic(
                                composed, donor_objects[function["donor"]],
                                function, retail_body,
                                {
                                    item["donor"]:
                                        donor_objects[item["donor"]]
                                    for item in
                                    function.get("donor_variants", [])
                                },
                            )
                        )
                    byte_identity.validate_donor_object_excluded(
                        composed,
                        [donor_objects[function["donor"]]] + [
                            donor_objects[item["donor"]]
                            for item in function.get("donor_variants", [])
                        ],
                    )
                elif function["splice_class"] in {
                    "retail_exact_target_closure",
                    "retail_exact_source_target_closure",
                }:
                    retail = function["retail_oracle"]
                    donor_source = donor_sources.get(function["donor"])
                    if donor_source is None:
                        fail(f"target-closure donor omits its translation unit: "
                             f"{unit['source']}")
                    composer = (
                        byte_identity.compose_retail_exact_target_closure
                        if function["splice_class"]
                        == "retail_exact_target_closure"
                        else byte_identity
                        .compose_retail_exact_source_target_closure
                    )
                    composed, detail = (
                        composer(
                            composed, donor_objects[function["donor"]],
                            function,
                            byte_identity.retail_image_body(
                                manifest, retail["image"],
                                int(retail["address"], 16), retail["length"],
                            ),
                            source.read_bytes(), donor_source,
                        ))
                    byte_identity.validate_donor_object_excluded(
                        composed, [donor_objects[function["donor"]]])
                elif function["splice_class"] == "retail_exact_reloc_divergent":
                    # B1's extraction lives here, in the build, because it is
                    # the build that already validates the retail image
                    # against images.LEGO1.original_sha256.  The composer is
                    # handed the bytes and enforces length and masked nd 0.
                    retail = function["retail_oracle"]
                    if "target_source_refactor" in function:
                        donor_source = donor_sources.get(function["donor"])
                        if donor_source is None:
                            fail("retail-exact source-refactor donor omits "
                                 f"its translation unit: {unit['source']}")
                        composed, detail = (
                            byte_identity.compose_retail_exact_source_refactor(
                                composed, donor_objects[function["donor"]],
                                function,
                                byte_identity.retail_image_body(
                                    manifest, retail["image"],
                                    int(retail["address"], 16),
                                    retail["length"],
                                ),
                                source.read_bytes(), donor_source,
                            )
                        )
                    else:
                        composed, detail = (
                            byte_identity.compose_retail_exact_reloc_divergent(
                            composed, donor_objects[function["donor"]],
                            function,
                            byte_identity.retail_image_body(
                                manifest, retail["image"],
                                int(retail["address"], 16), retail["length"],
                            ),
                            )
                        )
                    byte_identity.validate_donor_object_excluded(
                        composed, [donor_objects[function["donor"]]])
                elif function["splice_class"] == "comdat_selection_override":
                    # Class C.  As with B1, the retail extraction lives in the
                    # build because the build already validates the retail
                    # image against images.LEGO1.original_sha256.
                    retail = function["retail_oracle"]
                    composed, detail = (
                        byte_identity.compose_comdat_selection_override(
                            composed, donor_objects[function["donor"]],
                            function,
                            byte_identity.retail_image_body(
                                manifest, retail["image"],
                                int(retail["address"], 16), retail["length"],
                            ),
                        ))
                    byte_identity.validate_donor_object_excluded(
                        composed, [donor_objects[function["donor"]]])
                elif (function["splice_class"]
                        == byte_identity.RETAIL_EXACT_SOURCE_EQUAL_BODY_CLASS):
                    retail = function["retail_oracle"]
                    donor_source = donor_sources.get(function["donor"])
                    if donor_source is None:
                        fail("source equal-body donor omits its translation "
                             f"unit: {unit['source']}")
                    composed, detail = (
                        byte_identity.compose_retail_exact_source_equal_body(
                            composed, donor_objects[function["donor"]],
                            function,
                            byte_identity.retail_image_body(
                                manifest, retail["image"],
                                int(retail["address"], 16), retail["length"],
                            ),
                            source.read_bytes(), donor_source,
                        ))
                    byte_identity.validate_donor_object_excluded(
                        composed, [donor_objects[function["donor"]]])
                elif (function["splice_class"]
                        == byte_identity.INSTRUCTION_SCHEDULE_CLASS):
                    # The instruction-schedule certificate: the declared
                    # window reordering is applied to this donor's own
                    # compiler-produced body after being proved a topological
                    # order of the window's dependence DAG, and the result is
                    # refused unless it equals the pinned retail oracle.
                    retail = function["retail_oracle"]
                    composed, detail = (
                        byte_identity
                        .compose_retail_exact_instruction_schedule(
                            composed, donor_objects[function["donor"]],
                            function,
                            byte_identity.retail_image_body(
                                manifest, retail["image"],
                                int(retail["address"], 16), retail["length"],
                            ),
                        ))
                    byte_identity.validate_donor_object_excluded(
                        composed, [donor_objects[function["donor"]]])
                elif (function["splice_class"]
                        == byte_identity.WEB_RECOLOUR_CLASS):
                    # The web-recolour certificate: one def-use web is
                    # renamed on the SEED's own compiler-produced body, after
                    # any declared reordering, having proved the image
                    # register carries no live value over the web's range --
                    # the coalesce obligation.  The donor is a provenance
                    # witness and is required to reproduce the seed's body.
                    retail = function["retail_oracle"]
                    composed, detail = (
                        byte_identity
                        .compose_retail_exact_web_recolour(
                            composed, donor_objects[function["donor"]],
                            function,
                            byte_identity.retail_image_body(
                                manifest, retail["image"],
                                int(retail["address"], 16), retail["length"],
                            ),
                        ))
                    byte_identity.validate_donor_object_excluded(
                        composed, [donor_objects[function["donor"]]])
                elif (function["splice_class"]
                        == byte_identity.RELATIONAL_FORM_CLASS):
                    # The relational-form certificate: each declared compare
                    # is reversed and its branch condition replaced by the
                    # closed table's mirror, after a per-flag liveness
                    # fixpoint has proved that no flag the reversal changes
                    # is live at either successor, and the result is refused
                    # unless it equals the pinned retail oracle.
                    retail = function["retail_oracle"]
                    composed, detail = (
                        byte_identity
                        .compose_retail_exact_relational_form(
                            composed, donor_objects[function["donor"]],
                            function,
                            byte_identity.retail_image_body(
                                manifest, retail["image"],
                                int(retail["address"], 16), retail["length"],
                            ),
                        ))
                    byte_identity.validate_donor_object_excluded(
                        composed, [donor_objects[function["donor"]]])
                elif (function["splice_class"]
                        == byte_identity.COMPOSED_REWRITING_CLASS):
                    # Three certificates inside one entry: every declared
                    # window is reordered first, the regional bijections and
                    # the mirrored comparisons are then proved on the image
                    # the reordering produced, and the result is refused
                    # unless it equals the pinned retail oracle.  The donor
                    # is a provenance witness required to reproduce the
                    # seed's own body, which is the pre-image.
                    retail = function["retail_oracle"]
                    composed, detail = (
                        byte_identity
                        .compose_retail_exact_composed_rewriting(
                            composed, donor_objects[function["donor"]],
                            function,
                            byte_identity.retail_image_body(
                                manifest, retail["image"],
                                int(retail["address"], 16), retail["length"],
                            ),
                        ))
                    byte_identity.validate_donor_object_excluded(
                        composed, [donor_objects[function["donor"]]])
                elif (function["splice_class"]
                        == byte_identity.REGISTER_BIJECTION_CLASS):
                    # The register-bijection certificate: sigma is applied to
                    # this donor's own compiler-produced body and the result
                    # is refused unless it equals the pinned retail oracle.
                    retail = function["retail_oracle"]
                    composed, detail = (
                        byte_identity
                        .compose_retail_exact_register_bijection(
                            composed, donor_objects[function["donor"]],
                            function,
                            byte_identity.retail_image_body(
                                manifest, retail["image"],
                                int(retail["address"], 16), retail["length"],
                            ),
                        ))
                    byte_identity.validate_donor_object_excluded(
                        composed, [donor_objects[function["donor"]]])
                elif function["splice_class"] == "same_slot_resize":
                    composed, detail = byte_identity.compose_same_slot_resize(
                        composed, donor_objects[function["donor"]], function
                    )
                else:
                    composed, detail = (
                        byte_identity.compose_equal_body_comdat(
                            composed, donor_objects[function["donor"]],
                            function,
                        ))
        if unit.get("group_order"):
            orders = unit["group_order"]
            lists = orders if isinstance(orders[0], list) else [orders]
            for names in lists:
                composed, detail = (
                    byte_identity.compose_restore_comdat_group_order(
                        composed, {"group_order": names}))
        byte_identity.validate_first_party_object_directive(
            composed, "composed object"
        )
        seed_object.write_bytes(composed)
        marker.write_text(json.dumps({
            "seed_sha": seed_sha,
            "composed_sha": hashlib.sha256(composed).hexdigest(),
            "unit_sha": unit_sha,
        }, indent=1) + "\n")
        return unit["target"], (
            f"[isle_build] composed {len(unit['functions'])} function(s) "
            f"into {unit['target']}:{unit['source']}"
        )

    relink_targets = set()
    # Units are independent (own objects, PDBs, probes, markers), so the
    # donor/seed compiles run through a small pool; the relink stays serial.
    with ThreadPoolExecutor(
        max_workers=max(1, min(jobs, len(units)))
    ) as pool:
        futures = [pool.submit(compose_unit, unit) for unit in units]
        try:
            for future, unit in zip(futures, units):
                try:
                    target, message = future.result()
                except byte_identity.ByteIdentityError as error:
                    fail(f"composition refused for {unit['target']}:"
                         f"{unit['source']}: {error}")
                if message:
                    print(message)
                if target:
                    relink_targets.add(target)
        except BaseException:
            for pending in futures:
                pending.cancel()
            raise
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
            timeout_seconds=link_timeout,
            env=build_environment(compiler),
            log=build.parent / "relink.log")


if __name__ == "__main__":
    raise SystemExit(main())
