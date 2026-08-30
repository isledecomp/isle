"""TEMPORARY: bound one native compiler-entropy probe during ReproBit migration.

This is deliberately not project tooling.  It runs only after the native CI
verification has already failed, against that run's retained private drive.
Remove it with the migration diagnostics once Windows parity is established.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PureWindowsPath

import tomllib

NODE_ID = "compiler.lego1.0202"
TARGET = "?Read@LegoPartPresenter@@QAEJAAVMxDSChunk@@@Z"
VTABLES = (
    "??_7?$MxCollection@PAVLegoLOD@@@@6B@",
    "??_7?$MxList@PAVLegoLOD@@@@6B@",
    "??_7?$MxPtrList@VLegoLOD@@@@6B@",
    "??_7LegoLODList@@6B@",
    "??_7?$MxCollection@PAVLegoNamedPart@@@@6B@",
    "??_7?$MxList@PAVLegoNamedPart@@@@6B@",
    "??_7?$MxPtrList@VLegoNamedPart@@@@6B@",
    "??_7LegoNamedPartList@@6B@",
)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _file_fact(path: Path) -> dict[str, object] | None:
    if not path.is_file():
        return None
    payload = path.read_bytes()
    return {"bytes": len(payload), "sha256": _sha256(payload)}


def _logical_path(root: Path, value: str, drive: str) -> Path:
    logical = PureWindowsPath(value.replace("/", "\\"))
    if logical.drive.upper() != f"{drive}:":
        raise ValueError(f"logical path leaves {drive}: {value}")
    return root.joinpath(*logical.parts[1:])


def _rooted_without_drive(value: str) -> str:
    logical = PureWindowsPath(value.replace("/", "\\"))
    if not logical.drive:
        raise ValueError(f"path has no drive: {value}")
    return str(logical)[len(logical.drive) :]


def _materialize(token: str, paths: dict[str, str]) -> str:
    result = token
    for marker, name in (
        ("${SOURCE}", "source"),
        ("${BUILD}", "build"),
        ("${TOOLCHAIN}", "toolchain"),
    ):
        result = result.replace(marker, paths[name].rstrip("\\/"))
    if "${" in result:
        raise ValueError(f"unresolved producer argument: {token}")
    return result


def _coff_fact(path: Path) -> dict[str, object]:
    # The pinned ReproBit revision is already installed and authenticated by
    # the preceding workflow steps.  Reuse its strict COFF reader here rather
    # than carrying a second migration-only parser.
    from reprobit.classic.composition import instruction_mosaic_metadata_sha256
    from reprobit.coff import CoffObject, coff_body

    payload = path.read_bytes()
    coff = CoffObject(payload)
    primary = coff.function_section(TARGET)
    relocation_start = primary["relocation_offset"]
    relocation_end = relocation_start + primary["relocation_count"] * 10
    rows = []
    for name in VTABLES:
        matches = [symbol for symbol in coff.symbols.values() if symbol["name"] == name]
        if len(matches) != 1:
            raise ValueError(
                f"expected one vtable definition for {name}, got {len(matches)}"
            )
        symbol = matches[0]
        rows.append(
            {
                "name": name,
                "section": symbol["section"],
                "symbol_index": symbol["index"],
            }
        )
    return {
        "coff_timestamp": coff.timestamp,
        "object_bytes": len(payload),
        "object_sha256": _sha256(payload),
        "section_count": coff.section_count,
        "target_body_sha256": _sha256(coff_body(coff, primary)),
        "target_line_count": primary["line_count"],
        "target_metadata_sha256": instruction_mosaic_metadata_sha256(coff, primary),
        "target_relocation_count": primary["relocation_count"],
        "target_relocation_sha256": _sha256(payload[relocation_start:relocation_end]),
        "vtable_definitions": sorted(rows, key=lambda row: row["symbol_index"]),
        "vtable_section_order": [
            row["name"] for row in sorted(rows, key=lambda row: row["section"])
        ],
    }


@contextmanager
def _single_core(enabled: bool) -> Iterator[dict[str, object]]:
    detail: dict[str, object] = {"requested": enabled, "applied": False}
    if not enabled:
        yield detail
        return
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle_type = ctypes.c_void_p
    mask_type = ctypes.c_size_t
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = handle_type
    kernel32.GetProcessAffinityMask.argtypes = [
        handle_type,
        ctypes.POINTER(mask_type),
        ctypes.POINTER(mask_type),
    ]
    kernel32.GetProcessAffinityMask.restype = ctypes.c_int
    kernel32.SetProcessAffinityMask.argtypes = [handle_type, mask_type]
    kernel32.SetProcessAffinityMask.restype = ctypes.c_int
    handle = kernel32.GetCurrentProcess()
    current = mask_type()
    system = mask_type()
    if not kernel32.GetProcessAffinityMask(
        handle, ctypes.byref(current), ctypes.byref(system)
    ):
        raise OSError(ctypes.get_last_error(), "GetProcessAffinityMask failed")
    detail.update({"original_mask": current.value, "system_mask": system.value})
    if not kernel32.SetProcessAffinityMask(handle, 1):
        raise OSError(ctypes.get_last_error(), "SetProcessAffinityMask failed")
    detail.update({"applied": True, "probe_mask": 1})
    try:
        # The compiler process and its C1XX/C2 descendants inherit this mask.
        yield detail
    finally:
        if not kernel32.SetProcessAffinityMask(handle, current.value):
            detail["restore_error"] = ctypes.get_last_error()


def _native_environment(paths: dict[str, str], lane: str) -> dict[str, str]:
    toolchain = paths["toolchain"]
    tool_bin = str(PureWindowsPath(toolchain) / "bin")
    include = ";".join(
        _rooted_without_drive(str(PureWindowsPath(toolchain) / relative))
        for relative in ("include", "mfc/include")
    )
    libraries = ";".join(
        _rooted_without_drive(str(PureWindowsPath(toolchain) / relative))
        for relative in ("lib", "mfc/lib")
    )
    # Match ReproBit's compiler-visible profile exactly.  The directory is
    # shared by clean producer processes; /Brepro is responsible for removing
    # the compiler's process/time entropy, not a per-lane path spelling.
    temporary = str(
        PureWindowsPath(
            PureWindowsPath(paths["build"]).drive + "\\",
            "Users",
            "reprobit",
            "AppData",
            "Local",
            "Temp",
        )
    )
    environment = {
        "PATH": ";".join((_rooted_without_drive(tool_bin), tool_bin, os.defpath)),
        "INCLUDE": include,
        "LIB": libraries,
        "LIBPATH": libraries,
        "TMP": temporary,
        "TEMP": temporary,
        "LANG": "C",
        "LC_ALL": "C",
    }
    if "SYSTEMROOT" in os.environ:
        environment["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    return environment


def _subst_drive(drive: str, target: Path) -> None:
    listing = subprocess.run(
        ["subst.exe"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    ).stdout
    if re.search(rf"(?im)^{re.escape(drive)}:\\:", listing):
        raise RuntimeError(f"refusing to replace an existing {drive}: substitution")
    subprocess.run(
        ["subst.exe", f"{drive}:", str(target)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def _remove_subst(drive: str) -> None:
    subprocess.run(
        ["subst.exe", f"{drive}:", "/D"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def _create_owned_directory(path: Path) -> list[Path]:
    missing = []
    cursor = path
    while not cursor.exists():
        missing.append(cursor)
        cursor = cursor.parent
    for directory in reversed(missing):
        directory.mkdir()
    return missing


def _probe(args: argparse.Namespace) -> dict[str, object]:
    project = args.project.resolve(strict=True)
    run = args.run.resolve(strict=True)
    output = args.output.resolve(strict=False)
    output.mkdir(parents=True, exist_ok=True)

    with (project / "reprobit.toml").open("rb") as stream:
        manifest = tomllib.load(stream)
    paths = manifest["paths"]
    if not isinstance(paths, dict) or any(
        not isinstance(paths.get(name), str)
        for name in ("source", "build", "toolchain")
    ):
        raise ValueError("ReproBit path profile is invalid")
    drive = PureWindowsPath(paths["build"]).drive.rstrip(":").upper()
    if not drive or any(
        PureWindowsPath(paths[name]).drive.upper() != f"{drive}:"
        for name in ("source", "build", "toolchain")
    ):
        raise ValueError("ReproBit path profile does not use one logical drive")

    graph = json.loads(
        (project / "reprobit/producer-graph.json").read_text(encoding="utf-8")
    )
    nodes = [node for node in graph["nodes"] if node.get("id") == NODE_ID]
    if len(nodes) != 1:
        raise ValueError(f"expected one producer node {NODE_ID}, got {len(nodes)}")
    node = nodes[0]
    argv = [
        str(PureWindowsPath(paths["toolchain"]) / "bin" / "CL.EXE"),
        *(_materialize(token, paths) for token in node["arguments"]),
    ]
    object_tokens = [token[3:] for token in argv if token[:3].casefold() == "/fo"]
    pdb_tokens = [token[3:] for token in argv if token[:3].casefold() == "/fd"]
    if len(object_tokens) != 1 or len(pdb_tokens) != 1:
        raise ValueError("producer command does not bind exactly one /Fo and /Fd")

    logical_root = run / "classic/logical-drive"
    if not logical_root.is_dir():
        raise ValueError("retained run has no logical-drive workspace")
    physical_object = _logical_path(logical_root, object_tokens[0], drive)
    physical_pdb = _logical_path(logical_root, pdb_tokens[0], drive)
    logical_cwd = paths["build"]
    environment = _native_environment(paths, "lane-0000")
    physical_temp = _logical_path(logical_root, environment["TMP"], drive)
    physical_temp.mkdir(parents=True, exist_ok=True)

    original_object = physical_object.read_bytes()
    original_pdb = physical_pdb.read_bytes()
    original_dir = output / "original"
    original_dir.mkdir(exist_ok=True)
    (original_dir / "seed.obj").write_bytes(original_object)
    (original_dir / "seed.pdb").write_bytes(original_pdb)

    wine_temp = Path(r"C:\users\reprobit\AppData\Local\Temp")
    owned_wine_temp_directories = _create_owned_directory(wine_temp)
    wine_temp_initial = sorted(path.name for path in wine_temp.iterdir())
    # id, __COMPAT_LAYER, inherited single-core affinity, legacy C: TEMP,
    # compiler-owned reproducibility mode.
    variants = (
        ("control-00", None, False, False, False),
        ("control-01", None, False, False, False),
        ("brepro-00", None, False, False, True),
        ("brepro-01", None, False, False, True),
        ("compat-win95", "WIN95", False, False, False),
        ("compat-win98", "WIN98", False, False, False),
        ("compat-emulateheap", "EmulateHeap", False, False, False),
        ("compat-winnt4sp5", "WINNT4SP5", False, False, False),
        ("compat-winxpsp3", "WINXPSP3", False, False, False),
        ("single-core", None, True, False, False),
        ("legacy-c-temp", None, False, True, False),
    )
    result: dict[str, object] = {
        "schema_version": 1,
        "temporary_transition_probe": True,
        "node_id": NODE_ID,
        "target": TARGET,
        "logical_cwd": logical_cwd,
        "argv": argv,
        "environment": environment,
        "execution_boundary": {
            "kind": "transition-only direct native subprocess",
            "drive_mapping": "subst in the workflow process logon session",
            "production_difference": "does not claim the fresh-LUID/Job boundary",
        },
        "host": {
            "platform": platform.platform(),
            "python": sys.version,
            "number_of_processors": os.environ.get("NUMBER_OF_PROCESSORS"),
            "processor_identifier": os.environ.get("PROCESSOR_IDENTIFIER"),
            "runner_image": os.environ.get("ImageOS"),
        },
        "original": {
            "object": _coff_fact(physical_object),
            "pdb": _file_fact(physical_pdb),
        },
        "wine_visible_temp": {
            "path": str(wine_temp),
            "initial_entries": wine_temp_initial,
            "created_directories": [str(path) for path in owned_wine_temp_directories],
        },
        "omitted": [
            {
                "kind": "persistent_process_mitigation",
                "reason": "Set-ProcessMitigation would change runner-global image policy",
            }
        ],
        "runs": [],
    }

    mapped = False
    restore_error: str | None = None
    try:
        _subst_drive(drive, logical_root)
        mapped = True
        for run_id, compat_layer, single_core, use_wine_temp, use_brepro in variants:
            record: dict[str, object] = {
                "id": run_id,
                "compat_layer": compat_layer,
                "single_core": single_core,
                "wine_temp": use_wine_temp,
                "brepro": use_brepro,
            }
            record["started_unix"] = time.time()
            run_environment = dict(environment)
            if compat_layer is not None:
                run_environment["__COMPAT_LAYER"] = compat_layer
            if use_wine_temp:
                run_environment.update({"TMP": str(wine_temp), "TEMP": str(wine_temp)})
            record["environment_delta"] = {
                "__COMPAT_LAYER": run_environment.get("__COMPAT_LAYER"),
                "TEMP": run_environment["TEMP"],
                "TMP": run_environment["TMP"],
            }
            physical_object.unlink(missing_ok=True)
            physical_pdb.unlink(missing_ok=True)
            log = output / f"{run_id}.log"
            try:
                with _single_core(single_core) as affinity:
                    completed = subprocess.run(
                        [argv[0], *(["/Brepro"] if use_brepro else []), *argv[1:]],
                        cwd=logical_cwd,
                        env=run_environment,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        timeout=300,
                        check=False,
                    )
                record["affinity"] = affinity
                record["returncode"] = completed.returncode
                log.write_bytes(completed.stdout[-65536:])
                record["compile_succeeded"] = completed.returncode == 0
                if physical_object.is_file():
                    try:
                        record["object"] = _coff_fact(physical_object)
                    except Exception as error:  # noqa: BLE001 - preserve raw output on parser bugs
                        record["object"] = _file_fact(physical_object)
                        record["analysis_error"] = f"{type(error).__name__}: {error}"
                else:
                    record["object"] = None
                record["pdb"] = _file_fact(physical_pdb)
                if (
                    physical_object.is_file()
                    and physical_object.stat().st_size <= 2 * 1024 * 1024
                ):
                    shutil.copyfile(physical_object, output / f"{run_id}.obj")
                if (
                    physical_pdb.is_file()
                    and physical_pdb.stat().st_size <= 2 * 1024 * 1024
                ):
                    shutil.copyfile(physical_pdb, output / f"{run_id}.pdb")
            except subprocess.TimeoutExpired as error:
                payload = (error.stdout or b"") + (error.stderr or b"")
                log.write_bytes(payload[-65536:])
                record.update(
                    {"compile_succeeded": False, "error": "timeout after 300s"}
                )
            except Exception as error:  # noqa: BLE001 - keep every other A/B result available
                record.update(
                    {
                        "compile_succeeded": False,
                        "error": f"{type(error).__name__}: {error}",
                    }
                )
            record["elapsed_seconds"] = round(
                time.time() - float(record["started_unix"]), 6
            )
            result["runs"].append(record)
    finally:
        try:
            physical_object.write_bytes(original_object)
            physical_pdb.write_bytes(original_pdb)
            if (
                physical_object.read_bytes() != original_object
                or physical_pdb.read_bytes() != original_pdb
            ):
                raise RuntimeError("restored seed bytes differ from their backup")
        except Exception as error:  # noqa: BLE001 - restoration must be reported, not mask evidence
            restore_error = f"{type(error).__name__}: {error}"
        if mapped:
            try:
                _remove_subst(drive)
            except Exception as error:  # noqa: BLE001 - preserve the probe report for upload
                result["drive_cleanup_error"] = f"{type(error).__name__}: {error}"
        result["wine_visible_temp"]["entries_after"] = sorted(
            path.name for path in wine_temp.iterdir()
        )
        cleanup_errors = []
        for directory in owned_wine_temp_directories:
            try:
                directory.rmdir()
            except OSError as error:
                cleanup_errors.append(f"{directory}: {error}")
                break
        result["wine_visible_temp"]["cleanup_errors"] = cleanup_errors
    result["restore"] = {"succeeded": restore_error is None, "error": restore_error}
    result["temporary_directory_after"] = sorted(
        path.name for path in physical_temp.iterdir()
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    destination = args.output / "probe.json"
    try:
        result = _probe(args)
    except Exception as error:  # noqa: BLE001 - always leave a bounded failure report
        result = {
            "schema_version": 1,
            "temporary_transition_probe": True,
            "fatal_error": f"{type(error).__name__}: {error}",
        }
        destination.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(result["fatal_error"], file=sys.stderr)
        return 1
    destination.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        f"wrote {len(result['runs'])} bounded native compiler probes to {destination}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
