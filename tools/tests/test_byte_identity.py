#!/usr/bin/env python3
"""Native-only tests for the fail-closed byte-identity framework phase."""

from __future__ import annotations

import argparse
import ast
import hashlib
import inspect
import json
import os
from contextlib import ExitStack, contextmanager
from pathlib import Path, PurePosixPath
import re
import signal
import shlex
import shutil
import socket
import stat
import struct
import subprocess
import sys
import sysconfig
import tempfile
import time
import unittest
from unittest import mock


TOOLS = Path(__file__).resolve().parents[1]
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))
import byte_identity as byte_identity  # noqa: E402
import entropy  # noqa: E402


FAKE_COMPILER = r'''#!/usr/bin/env python3
try:
    import fcntl
except ImportError:  # Native Windows backend uses Win32 LockFileEx.
    fcntl = None
import json
import os
from pathlib import Path
import shutil
import subprocess
import struct
import sys
import time

if os.name == "nt":
    import msvcrt

def lock_stream(stream):
    if os.name == "nt":
        stream.seek(0)
        msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK, 1)
    else:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)

def unlock_stream(stream):
    if os.name == "nt":
        stream.seek(0)
        msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

control_path = Path(__file__).with_suffix(".control.json")
control = json.loads(control_path.read_text()) if control_path.is_file() else {}
virtual_z_value = os.environ.get("ISLE_BYTE_IDENTITY_VIRTUAL_Z_ROOT")
virtual_z = Path(virtual_z_value) if virtual_z_value else None
if virtual_z is not None:
    logical_cwd = Path("/").joinpath(*Path.cwd().relative_to(virtual_z).parts)
else:
    logical_cwd = Path.cwd()

def logical_path(value):
    candidate = Path(value)
    return candidate if candidate.is_absolute() else logical_cwd / candidate

def physical_path(value):
    logical = logical_path(value)
    if virtual_z is None:
        return logical
    return virtual_z.joinpath(*logical.parts[1:])

if control.get("COUNT_FILE"):
    count_path = Path(control["COUNT_FILE"])
    count_path.parent.mkdir(parents=True, exist_ok=True)
    with count_path.open("a+", encoding="ascii") as stream:
        lock_stream(stream)
        stream.seek(0)
        old = stream.read().strip()
        stream.seek(0)
        stream.truncate()
        stream.write(str((int(old) if old else 0) + 1))
        stream.flush()
        os.fsync(stream.fileno())
        unlock_stream(stream)
if control.get("CALL_LOG"):
    call_log = Path(control["CALL_LOG"])
    call_log.parent.mkdir(parents=True, exist_ok=True)
    with call_log.open("a+", encoding="utf-8") as stream:
        lock_stream(stream)
        stream.write(json.dumps({
            "argv": sys.argv,
            "cwd": str(Path.cwd()),
            "virtual_z": virtual_z_value,
        }, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
        unlock_stream(stream)
if control.get("ENV_CAPTURE"):
    Path(control["ENV_CAPTURE"]).write_text(
        json.dumps(dict(sorted(os.environ.items())), sort_keys=True)
    )
if control.get("PID_FILE"):
    Path(control["PID_FILE"]).write_text(str(os.getpid()))
if control.get("CHILD_PID_FILE"):
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    Path(control["CHILD_PID_FILE"]).write_text(str(child.pid))
if control.get("STARTED"):
    Path(control["STARTED"]).write_text("started\n")
if control.get("SLEEP"):
    time.sleep(float(control["SLEEP"]))
if control.get("FAIL"):
    print("intentional fake compiler failure")
    raise SystemExit(7)
if control.get("ORPHAN"):
    subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])

concurrency_state = control.get("CONCURRENCY_STATE")
if concurrency_state:
    state_path = Path(concurrency_state)
    state_path.parent.mkdir(parents=True, exist_ok=True)

    def update_concurrency(delta):
        with state_path.open("a+", encoding="ascii") as stream:
            lock_stream(stream)
            stream.seek(0)
            values = stream.read().split()
            active, maximum = map(int, values) if values else (0, 0)
            active += delta
            maximum = max(maximum, active)
            stream.seek(0)
            stream.truncate()
            stream.write(f"{active} {maximum}\n")
            stream.flush()
            os.fsync(stream.fileno())
            unlock_stream(stream)

    update_concurrency(1)
    try:
        time.sleep(float(control.get("CONCURRENCY_SLEEP", "0.25")))
    finally:
        update_concurrency(-1)

all_force_includes = []
physical_force_includes = []
generated_force_includes = []
for index, value in enumerate(sys.argv[1:]):
    if value in ("/FI", "-FI"):
        if index + 2 >= len(sys.argv):
            raise SystemExit(9)
        candidate = sys.argv[index + 2]
    elif value.startswith(("/FI", "-FI")):
        candidate = value[3:]
    else:
        continue
    all_force_includes.append(logical_path(candidate))
    physical_force_includes.append(physical_path(candidate))
    if "declaration_" in candidate.casefold():
        generated_force_includes.append(physical_path(candidate))
if any(not path.is_absolute() or not path.is_file()
       for path in generated_force_includes):
    print("generated declaration /FI must be an existing absolute path")
    raise SystemExit(9)

if any(value.casefold() in ("/p", "-p") for value in sys.argv[1:]):
    outputs = [
        value[3:] for value in sys.argv[1:]
        if value.casefold().startswith(("/fi", "-fi"))
        and not value.casefold().startswith(("/fi/", "-fi/"))
    ]
    # Distinguish attached /Fi (preprocessor output) from uppercase /FI
    # force-includes using the exact raw spelling.
    outputs = [
        value[3:] for value in sys.argv[1:]
        if value.startswith(("/Fi", "-Fi")) and len(value) > 3
    ]
    if len(outputs) != 1:
        raise SystemExit(12)
    source = logical_path(sys.argv[-1])
    lines = [f'#line 1 "{source}"']
    lines.extend(f'#line 1 "{path}"' for path in all_force_includes)
    lines.append(f'#line 2 "{source}"')
    dependency_output = physical_path(outputs[0])
    if not dependency_output.parent.is_dir():
        raise SystemExit(13)
    dependency_output.write_text("\n".join(lines) + "\n")
    print("fake dependency compiler success")
    raise SystemExit(0)

def option(name):
    matches = []
    for index, value in enumerate(sys.argv[1:]):
        folded = value.casefold()
        if folded in ("/" + name.casefold(), "-" + name.casefold()):
            matches.append(sys.argv[index + 2])
        elif folded.startswith("/" + name.casefold()) or folded.startswith("-" + name.casefold()):
            matches.append(value[len(name) + 1:])
    if len(matches) != 1:
        raise SystemExit(8)
    return logical_path(matches[0])

logical_obj = option("Fo")
logical_pdb = option("Fd")
obj = physical_path(logical_obj)
pdb = physical_path(logical_pdb)
source_candidates = []
for value in sys.argv[1:]:
    candidate = physical_path(value)
    try:
        resolved = candidate.resolve()
    except OSError:
        continue
    if (candidate.is_file() and resolved not in [p.resolve() for p in physical_force_includes]
            and resolved not in (obj.resolve(), pdb.resolve())):
        source_candidates.append(candidate)
if len(source_candidates) != 1:
    raise SystemExit(10)
source = source_candidates[0]
if not obj.parent.is_dir() or not pdb.parent.is_dir():
    raise SystemExit(13)
if control.get("SEED_OBJ"):
    generated_shape = any(
        value.casefold().startswith(("/fi", "-fi"))
        and "declaration_" in value.casefold()
        for value in sys.argv[1:]
    )
    if generated_shape:
        donor_map = control.get("DONOR_MAP", {})
        matching = [
            path for marker, path in donor_map.items()
            if any(marker in str(header) for header in generated_force_includes)
        ]
        fixture = matching[0] if len(matching) == 1 else control["DONOR_OBJ"]
    else:
        fixture = control["SEED_OBJ"]
    shutil.copyfile(fixture, obj)
else:
    fixture_body = (
        b"FAKE-OBJ\0"
        + source.read_bytes()
        + os.environ.get("CL", "").encode()
        + os.environ.get("WINEDEBUG", "").encode()
    )
    fixture_directive = b"-defaultlib:LIBCMT -defaultlib:OLDNAMES "
    table_size = 20 + 2 * 40
    directive_offset = table_size + len(fixture_body)
    symbol_offset = directive_offset + len(fixture_directive)
    header = struct.pack("<HHIIIHH", 0x14C, 2, 0, symbol_offset, 0, 0, 0)
    body_section = (
        b".data\0\0\0" + struct.pack(
            "<IIIIIIHHI", 0, 0, len(fixture_body), table_size,
            0, 0, 0, 0, 0xC0300040,
        )
    )
    directive_section = (
        b".drectve" + struct.pack(
            "<IIIIIIHHI", 0, 0, len(fixture_directive), directive_offset,
            0, 0, 0, 0, 0x00100A00,
        )
    )
    obj.write_bytes(
        header + body_section + directive_section + fixture_body
        + fixture_directive + struct.pack("<I", 4)
    )
if control.get("INCREMENTAL_STATE"):
    idb = obj.with_suffix(".idb")
    prior = idb.read_bytes() if idb.is_file() else b""
    if prior:
        obj.write_bytes(obj.read_bytes() + b"\0PRIOR-IDB\0" + prior)
    idb.write_bytes(b"FRESH-IDB\0" + source.read_bytes())
if control.get("EMIT_SBR"):
    Path(str(obj) + ".sbr").write_bytes(b"FRESH-SBR\0" + source.read_bytes())
if control.get("EXTRA_PRIVATE_OUTPUT"):
    (obj.parent / control["EXTRA_PRIVATE_OUTPUT"]).write_bytes(b"UNEXPECTED")
# Model VC4 /Zi's embedded type-server path. For strict COFF fixtures, append
# it to the string table and update the declared size; for pass-through fake
# bytes, a NUL-delimited absolute path is sufficient for the launcher parser.
object_data = obj.read_bytes()
reference_path = logical_path(
    control.get("WRONG_PDB_REFERENCE", str(logical_pdb))
)
reference = str(reference_path).encode("ascii") + b"\0"
if len(object_data) >= 20:
    try:
        symbol_offset, symbol_count = struct.unpack_from("<II", object_data, 8)
        string_offset = symbol_offset + symbol_count * 18
        string_size, = struct.unpack_from("<I", object_data, string_offset)
        if string_offset + string_size == len(object_data):
            updated = bytearray(object_data + reference)
            struct.pack_into("<I", updated, string_offset, string_size + len(reference))
            object_data = bytes(updated)
        else:
            object_data += b"\0" + reference
    except (struct.error, IndexError):
        object_data += b"\0" + reference
else:
    object_data += b"\0" + reference
obj.write_bytes(object_data)
pdb.write_bytes(b"FAKE-PDB\0" + os.environ["TMP"].encode())
if control.get("MUTATE_VIRTUAL_INPUT"):
    source.chmod(0o600)
    source.write_bytes(source.read_bytes() + b"\nMUTATED-VIRTUAL-INPUT\n")
if control.get("MUTATE_PREFIX"):
    prefix = Path(os.environ["WINEPREFIX"])
    (prefix / "attacker-state.reg").write_bytes(b"MUTATED-PREFIX")
if control.get("MUTATE_RUNTIME_SNAPSHOT"):
    # The held runtime executes in place: never write through the symlink
    # (that would corrupt the real host interpreter).  Model the attacker by
    # redirecting the strict runtime-bin entry to a mutated private copy.
    link = Path(os.environ["PATH"]) / "python3"
    target = link.resolve(strict=True)
    mutated = Path(os.environ["TMP"]) / "mutated-python3"
    mutated.write_bytes(target.read_bytes() + b"\nMUTATED-RUNTIME\n")
    mutated.chmod(0o700)
    link.unlink()
    link.symlink_to(mutated)
if control.get("LEAK_VIRTUAL_Z") and virtual_z is not None:
    leaked = str(virtual_z).encode("utf-8")
    obj.write_bytes(obj.read_bytes() + b"\0" + leaked)
    pdb.write_bytes(pdb.read_bytes() + b"\0" + leaked)
print("fake compiler success")
'''


def fake_msvc_wrapper(variable: str) -> bytes:
    return (
        "#!/usr/bin/env bash\n"
        "set -e\n"
        ". \"$(dirname \"$0\")/msvcenv.sh\"\n"
        f'"$(dirname "$0")/wine-msvc.sh" "${{{variable}}}" "$@"\n'
    ).encode("utf-8")


FAKE_WINE_MSVC = b'''#!/usr/bin/env bash
set -e
EXE=$1
shift
for a; do
    path=
    case "$a" in
    [-/][A-Za-z]/*) path=${a#??} ;;
    [-/][A-Za-z][A-Za-z]/*) path=${a#???} ;;
    /*) path=$a ;;
    *) ;;
    esac
    if [ -n "$path" ] && [ -d "$(dirname "$path")" ] && [ "$(dirname "$path")" != "/" ]; then
        :
    fi
done
case "$EXE" in
*CL.EXE) exec python3 "$(dirname "$0")/fake-cl.py" "$@" ;;
*) exit 0 ;;
esac
'''


FAKE_OUTER_CMAKE = r'''#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

if "--fail" in sys.argv:
    raise SystemExit(17)
python = os.environ["ISLE_BYTE_IDENTITY_PYTHON"]
nonce = os.environ["ISLE_BYTE_IDENTITY_SESSION_NONCE"]
controller = Path(os.environ["ISLE_BYTE_IDENTITY_CONTROLLER_ROOT"])
framework = controller / "framework/tools/byte_identity.py"
backend_tool = controller / "framework/tools/byte_identity_backend.py"
if "--build" in sys.argv:
    build = Path(sys.argv[sys.argv.index("--build") + 1])
    audit = build / "byte-identity/audit"
    audit.mkdir(parents=True, exist_ok=True)
    sha = "1" * 64
    verdict = {
        "status": "OBJECT_COMPOSITION_VERIFIED_FINAL_GATES_INCOMPLETE",
        "byte_identity_complete": False,
        "reason": "Fake native outer-driver fixture remains explicitly incomplete.",
        "manifest_sha256": sha,
        "inventory_sha256": sha,
        "policy_sha256": sha,
        "command_inventory_sha256": sha,
        "command_policy_sha256": sha,
        "execution_backend": (
            "windows_native_z_v1" if os.name == "nt"
            else "posix_wine_virtual_z_v1"
        ),
        "backend_tool_sha256": hashlib.sha256(
            Path(backend_tool).read_bytes()
        ).hexdigest(),
        "source_overlay_enabled": False,
        "source_overlay_policy_sha256": None,
        "source_overlay_actual_records_sha256": None,
        "source_overlay_receipt_sha256": None,
        "source_overlay_output_count": 0,
        "outer_session_nonce": nonce,
        "compiler_semaphore_max": 4,
        "recipes": [],
        "archives": [],
        "iteration_images": [],
        "final_images": [],
        "translation_units": [],
        "unlisted_translation_units": [],
    }
    (audit / "framework-verdict.json").write_text(
        json.dumps(verdict, indent=2, sort_keys=True) + "\n"
    )
else:
    source = Path(sys.argv[sys.argv.index("-S") + 1])
    build = Path(sys.argv[sys.argv.index("-B") + 1])
    result = subprocess.run([
        python, "-I", "-B", framework, "preconfigure-check",
        "--source-dir", str(source), "--build-dir", str(build),
        "--cmake", str(Path(__file__).resolve()), "--nonce", nonce,
    ])
    raise SystemExit(result.returncode)
'''


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


TARGET_SYMBOL = "?Target@@YAXXZ"
SECOND_TARGET_SYMBOL = "?SecondTarget@@YAXXZ"
CMAKE_C_CXX_SOURCE_EXTENSIONS = {
    "C", "M", "c++", "cc", "cpp", "cxx", "m", "mm", "mpp", "CPP",
    "ixx", "cppm", "ccm", "cxxm", "c++m", "c",
}


def _section_aux(length, relocations, lines, selection, associated=0, checksum=0):
    result = bytearray(18)
    struct.pack_into("<IHHI", result, 0, length, relocations, lines, checksum)
    struct.pack_into("<H", result, 12, associated & 0xFFFF)
    result[14] = selection
    struct.pack_into("<H", result, 16, associated >> 16)
    return bytes(result)


def _function_aux(total_size, line_pointer):
    result = bytearray(18)
    struct.pack_into("<II", result, 4, total_size, line_pointer)
    return bytes(result)


def _marker_aux(line, next_function=0):
    result = bytearray(18)
    struct.pack_into("<H", result, 4, line)
    struct.pack_into("<I", result, 12, next_function)
    return bytes(result)


FIXTURE_DIRECTIVE = b"-defaultlib:LIBCMT -defaultlib:OLDNAMES "


def make_fpo_coff(
    *, donor=False, external_symbol="?External@@YAXXZ",
    closure_f_name=".debug$F", shape_symbol=False,
    directive_payload=FIXTURE_DIRECTIVE,
):
    """Build a tiny classic-i386 COFF object with one complete FPO closure."""
    target_size = 31 if donor else 30
    target_body = bytearray(
        ((index * 7 + (13 if donor else 3)) & 0xFF)
        for index in range(target_size)
    )
    relocation_offset = 2 if donor else 1
    target_body[relocation_offset:relocation_offset + 4] = b"\0" * 4
    target_line_rows = [(3, 21), (20, 22)] if donor else [(4, 11)]

    debug_s = bytearray(40)
    struct.pack_into("<H", debug_s, 2, 0x0205)
    struct.pack_into(
        "<III", debug_s, 16, target_size,
        2 if donor else 1, 29 if donor else 28,
    )
    debug_f = bytearray(16)
    struct.pack_into("<I", debug_f, 4, target_size)
    struct.pack_into("<I", debug_f, 8, 3 if donor else 2)
    struct.pack_into("<H", debug_f, 12, 2)
    debug_f[14] = 5 if donor else 4
    debug_f[15] = 0x54 if donor else 0x14
    other_body = b"OTHER-FN"

    # Symbol indices include auxiliary records.
    target_index = 2
    external_index = 8
    other_index = 15
    target_lines = bytearray(struct.pack("<IH", target_index, 0))
    for offset, line in target_line_rows:
        target_lines.extend(struct.pack("<IH", offset, line))
    other_lines = struct.pack("<IH", other_index, 0) + struct.pack("<IH", 1, 77)

    section_inputs = [
        {
            "name": ".text", "raw": bytes(target_body),
            "relocations": [(relocation_offset, external_index, 0x14)],
            "lines": bytes(target_lines), "characteristics": 0x60501020,
        },
        {
            "name": ".debug$S", "raw": bytes(debug_s),
            "relocations": [(28, target_index, 0x000B), (32, target_index, 0x000A)],
            "lines": b"", "characteristics": 0x42101048,
        },
        {
            "name": closure_f_name, "raw": bytes(debug_f),
            "relocations": [(0, target_index, 0x0007)],
            "lines": b"", "characteristics": 0x42101048,
        },
        {
            "name": ".text", "raw": other_body,
            "relocations": [], "lines": other_lines,
            "characteristics": 0x60501020,
        },
        {
            "name": ".drectve", "raw": directive_payload,
            "relocations": [], "lines": b"", "characteristics": 0x00100A00,
        },
    ]
    cursor = 20 + len(section_inputs) * 40
    payload = bytearray()
    sections = []
    for item in section_inputs:
        raw_offset = cursor
        payload.extend(item["raw"])
        cursor += len(item["raw"])
        relocation_table = b"".join(
            struct.pack("<IIH", *row) for row in item["relocations"]
        )
        relocation_table_offset = cursor if relocation_table else 0
        payload.extend(relocation_table)
        cursor += len(relocation_table)
        line_offset = cursor if item["lines"] else 0
        payload.extend(item["lines"])
        cursor += len(item["lines"])
        sections.append(
            {
                **item,
                "raw_offset": raw_offset,
                "relocation_offset": relocation_table_offset,
                "line_offset": line_offset,
            }
        )

    symbols = [
        (".text", 0, 1, 0, 3, _section_aux(
            target_size, 1, 1 + len(target_line_rows), 2,
            checksum=int.from_bytes(hashlib.sha256(target_body).digest()[:4], "little"),
        )),
        (TARGET_SYMBOL, 0, 1, 0x20, 2, _function_aux(target_size, sections[0]["line_offset"])),
        (".bf", 0, 1, 0, 101, _marker_aux(20 if donor else 10)),
        (".ef", target_size, 1, 0, 101, _marker_aux(41 if donor else 31)),
        (external_symbol, 0, 0, 0x20, 2, None),
        (".debug$S", 0, 2, 0, 3, _section_aux(40, 2, 0, 5, associated=1)),
        (closure_f_name, 0, 3, 0, 3, _section_aux(16, 1, 0, 5, associated=1)),
        (".text", 0, 4, 0, 3, _section_aux(8, 0, 2, 2, checksum=0x12345678)),
        ("?Other@@YAXXZ", 0, 4, 0x20, 2, _function_aux(8, sections[3]["line_offset"])),
        (".bf", 0, 4, 0, 101, _marker_aux(70)),
        (".ef", 8, 4, 0, 101, _marker_aux(71)),
    ]
    if shape_symbol:
        symbols.append(("ClassAaaaaa", 0, 4, 0, 2, None))

    string_offsets = {}
    strings = bytearray(b"\0\0\0\0")

    def encoded_name(name):
        raw = name.encode("ascii")
        if len(raw) <= 8:
            return raw.ljust(8, b"\0")
        if name not in string_offsets:
            string_offsets[name] = len(strings)
            strings.extend(raw + b"\0")
        return b"\0\0\0\0" + struct.pack("<I", string_offsets[name])

    symbol_table = bytearray()
    symbol_count = 0
    for name, value, section, symbol_type, storage, auxiliary in symbols:
        symbol_table.extend(
            encoded_name(name)
            + struct.pack(
                "<IhHBB", value, section, symbol_type, storage,
                1 if auxiliary is not None else 0,
            )
        )
        symbol_count += 1
        if auxiliary is not None:
            assert len(auxiliary) == 18
            symbol_table.extend(auxiliary)
            symbol_count += 1
    struct.pack_into("<I", strings, 0, len(strings))
    symbol_offset = cursor

    section_headers = bytearray()
    for item in sections:
        section_headers.extend(item["name"].encode("ascii").ljust(8, b"\0"))
        section_headers.extend(
            struct.pack(
                "<IIIIIIHHI",
                0, 0, len(item["raw"]), item["raw_offset"],
                item["relocation_offset"], item["line_offset"],
                len(item["relocations"]), len(item["lines"]) // 6,
                item["characteristics"],
            )
        )
    header = struct.pack(
        "<HHIIIHH", 0x14C, len(sections), 0x1234, symbol_offset,
        symbol_count, 0, 0,
    )
    return bytes(header + section_headers + payload + symbol_table + strings)


def make_two_fpo_coff(*, first_variant=False, second_variant=False):
    """Build two independent select-any FPO COMDAT closures in one COFF."""
    families = []
    definitions = (
        (TARGET_SYMBOL, 1, 2, 8, 30, first_variant),
        (SECOND_TARGET_SYMBOL, 4, 15, 21, 45, second_variant),
    )
    for ordinal, (symbol, section, function_index, external_index, base_size, variant) in enumerate(definitions):
        size = base_size + (1 if variant else 0)
        body = bytearray(
            ((index * (7 + ordinal * 2) + (19 if variant else 5 + ordinal)) & 0xFF)
            for index in range(size)
        )
        relocation_offset = 2 + ordinal + (1 if variant else 0)
        body[relocation_offset:relocation_offset + 4] = b"\0" * 4
        lines = [(3 + ordinal, 31 + ordinal), (size - 2, 41 + ordinal)] if variant else [(4 + ordinal, 21 + ordinal)]
        debug_s = bytearray(40)
        struct.pack_into("<H", debug_s, 2, 0x0205)
        struct.pack_into("<III", debug_s, 16, size, 2 + ordinal, size - 2)
        debug_f = bytearray(16)
        struct.pack_into("<I", debug_f, 4, size)
        struct.pack_into("<I", debug_f, 8, 2 + ordinal)
        struct.pack_into("<H", debug_f, 12, 1 + ordinal)
        debug_f[14] = 3 + ordinal
        debug_f[15] = 0x14 + ordinal + (0x40 if variant else 0)
        families.append(
            {
                "symbol": symbol,
                "section": section,
                "function_index": function_index,
                "external_index": external_index,
                "size": size,
                "body": bytes(body),
                "relocation_offset": relocation_offset,
                "lines": lines,
                "debug_s": bytes(debug_s),
                "debug_f": bytes(debug_f),
                "variant": variant,
            }
        )

    section_inputs = []
    for family in families:
        line_bytes = bytearray(struct.pack("<IH", family["function_index"], 0))
        for offset, line in family["lines"]:
            line_bytes.extend(struct.pack("<IH", offset, line))
        section_inputs.extend(
            [
                {
                    "name": ".text", "raw": family["body"],
                    "relocations": [(
                        family["relocation_offset"], family["external_index"], 0x14
                    )],
                    "lines": bytes(line_bytes), "characteristics": 0x60501020,
                },
                {
                    "name": ".debug$S", "raw": family["debug_s"],
                    "relocations": [
                        (28, family["function_index"], 0x000B),
                        (32, family["function_index"], 0x000A),
                    ],
                    "lines": b"", "characteristics": 0x42101048,
                },
                {
                    "name": ".debug$F", "raw": family["debug_f"],
                    "relocations": [(0, family["function_index"], 0x0007)],
                    "lines": b"", "characteristics": 0x42101048,
                },
            ]
        )
    section_inputs.append(
        {
            "name": ".drectve", "raw": FIXTURE_DIRECTIVE,
            "relocations": [], "lines": b"", "characteristics": 0x00100A00,
        }
    )
    cursor = 20 + len(section_inputs) * 40
    payload = bytearray()
    sections = []
    for item in section_inputs:
        raw_offset = cursor
        payload.extend(item["raw"])
        cursor += len(item["raw"])
        relocation_table = b"".join(
            struct.pack("<IIH", *row) for row in item["relocations"]
        )
        relocation_offset = cursor if relocation_table else 0
        payload.extend(relocation_table)
        cursor += len(relocation_table)
        line_offset = cursor if item["lines"] else 0
        payload.extend(item["lines"])
        cursor += len(item["lines"])
        sections.append(
            {
                **item,
                "raw_offset": raw_offset,
                "relocation_offset": relocation_offset,
                "line_offset": line_offset,
            }
        )

    symbols = []
    for ordinal, family in enumerate(families):
        primary_number = 1 + ordinal * 3
        primary = sections[primary_number - 1]
        symbols.extend(
            [
                (".text", 0, primary_number, 0, 3, _section_aux(
                    family["size"], 1, 1 + len(family["lines"]), 2,
                    checksum=int.from_bytes(
                        hashlib.sha256(family["body"]).digest()[:4], "little"
                    ),
                )),
                (family["symbol"], 0, primary_number, 0x20, 2,
                 _function_aux(family["size"], primary["line_offset"])),
                (".bf", 0, primary_number, 0, 101,
                 _marker_aux(30 + ordinal * 10 + (1 if family["variant"] else 0))),
                (".ef", family["size"], primary_number, 0, 101,
                 _marker_aux(60 + ordinal * 10 + (1 if family["variant"] else 0))),
                (f"?External{ordinal + 1}@@YAXXZ", 0, 0, 0x20, 2, None),
                (".debug$S", 0, primary_number + 1, 0, 3,
                 _section_aux(40, 2, 0, 5, associated=primary_number)),
                (".debug$F", 0, primary_number + 2, 0, 3,
                 _section_aux(16, 1, 0, 5, associated=primary_number)),
            ]
        )
    symbols.append((
        ".drectve", 0, 7, 0, 3,
        _section_aux(len(FIXTURE_DIRECTIVE), 0, 0, 2),
    ))

    string_offsets = {}
    strings = bytearray(b"\0\0\0\0")

    def encoded_name(name):
        raw = name.encode("ascii")
        if len(raw) <= 8:
            return raw.ljust(8, b"\0")
        if name not in string_offsets:
            string_offsets[name] = len(strings)
            strings.extend(raw + b"\0")
        return b"\0\0\0\0" + struct.pack("<I", string_offsets[name])

    symbol_table = bytearray()
    symbol_count = 0
    for name, value, section, symbol_type, storage, auxiliary in symbols:
        symbol_table.extend(
            encoded_name(name)
            + struct.pack(
                "<IhHBB", value, section, symbol_type, storage,
                1 if auxiliary is not None else 0,
            )
        )
        symbol_count += 1
        if auxiliary is not None:
            symbol_table.extend(auxiliary)
            symbol_count += 1
    struct.pack_into("<I", strings, 0, len(strings))
    symbol_offset = cursor
    section_headers = bytearray()
    for item in sections:
        section_headers.extend(item["name"].encode("ascii").ljust(8, b"\0"))
        section_headers.extend(
            struct.pack(
                "<IIIIIIHHI",
                0, 0, len(item["raw"]), item["raw_offset"],
                item["relocation_offset"], item["line_offset"],
                len(item["relocations"]), len(item["lines"]) // 6,
                item["characteristics"],
            )
        )
    header = struct.pack(
        "<HHIIIHH", 0x14C, len(sections), 0x5678, symbol_offset,
        symbol_count, 0, 0,
    )
    return bytes(header + section_headers + payload + symbol_table + strings)


def make_fwd_xdata_payload_coff(
    *, reverse_symbols=False, first_offset_delta=0,
    first_type=0x0006, first_addend=0, target_value_delta=0,
):
    """Build a 128-byte xdata payload with 12 resolved local relocations."""
    text = bytes((index * 5 + 3) & 0xFF for index in range(64))
    xdata = bytearray(128)
    relocation_offsets = [index * 8 for index in range(12)]
    relocation_offsets[0] += first_offset_delta
    xdata[relocation_offsets[0]:relocation_offsets[0] + 4] = (
        first_addend.to_bytes(4, "little")
    )

    local_names = [f"$T{index + 1}" for index in range(12)]
    symbol_order = list(reversed(local_names)) if reverse_symbols else local_names
    # The first section symbol owns one auxiliary record, so ordinary symbols
    # begin at raw COFF index two.
    symbol_indices = {
        name: index + 2 for index, name in enumerate(symbol_order)
    }
    relocations = [
        (
            offset,
            symbol_indices[name],
            first_type if ordinal == 0 else 0x0006,
        )
        for ordinal, (offset, name) in enumerate(
            zip(relocation_offsets, local_names)
        )
    ]

    section_count = 2
    cursor = 20 + section_count * 40
    text_offset = cursor
    cursor += len(text)
    xdata_offset = cursor
    cursor += len(xdata)
    relocation_offset = cursor
    relocation_table = b"".join(
        struct.pack("<IIH", *row) for row in relocations
    )
    cursor += len(relocation_table)

    symbols = [
        (".text", 0, 1, 0, 3, _section_aux(64, 0, 0, 2)),
        *[
            (
                name,
                local_names.index(name) * 4 + target_value_delta,
                1,
                0,
                3,
                None,
            )
            for name in symbol_order
        ],
        (
            ".xdata$x", 0, 2, 0, 3,
            _section_aux(128, len(relocations), 0, 2),
        ),
    ]
    symbol_table = bytearray()
    symbol_count = 0
    for name, value, section, symbol_type, storage, auxiliary in symbols:
        symbol_table.extend(
            name.encode("ascii").ljust(8, b"\0")
            + struct.pack(
                "<IhHBB", value, section, symbol_type, storage,
                1 if auxiliary is not None else 0,
            )
        )
        symbol_count += 1
        if auxiliary is not None:
            symbol_table.extend(auxiliary)
            symbol_count += 1

    section_headers = bytearray()
    section_headers.extend(b".text\0\0\0")
    section_headers.extend(
        struct.pack(
            "<IIIIIIHHI", 0, 0, len(text), text_offset,
            0, 0, 0, 0, 0x60501020,
        )
    )
    section_headers.extend(b".xdata$x")
    section_headers.extend(
        struct.pack(
            "<IIIIIIHHI", 0, 0, len(xdata), xdata_offset,
            relocation_offset, 0, len(relocations), 0, 0x40301040,
        )
    )
    header = struct.pack(
        "<HHIIIHH", 0x14C, section_count, 0x81C0, cursor,
        symbol_count, 0, 0,
    )
    strings = struct.pack("<I", 4)
    return bytes(
        header + section_headers + text + xdata + relocation_table
        + symbol_table + strings
    )


def fixture_fpo_record(object_bytes, section_number):
    coff = byte_identity.CoffObject(object_bytes)
    definitions = byte_identity.section_definitions(coff)
    associated = byte_identity.associated_sections(
        coff, definitions, section_number
    )
    debug_sections = [
        coff.sections[number - 1]
        for number, name in associated if name == ".debug$F"
    ]
    if len(debug_sections) != 1:
        raise AssertionError("fixture has no unique .debug$F")
    return byte_identity.parse_fpo_data(
        byte_identity.coff_body(coff, debug_sections[0]),
        expected_proc_size=coff.sections[section_number - 1]["raw_size"],
    )


def fpo_function_record(donor_bytes):
    return {
        "mangled": TARGET_SYMBOL,
        "donor": "d_fixture",
        "splice_class": "equal_linked_span_fpo",
        "expected_section_number": 1,
        "expected_seed_length": 30,
        "expected_donor_length": 31,
        "expected_linked_span": 32,
        "expected_characteristics": 0x60501020,
        "expected_selection": 2,
        "expected_relocation_count": 1,
        "expected_seed_line_count": 2,
        "expected_donor_line_count": 3,
        "expected_local_symbol_updates": 0,
        "compiler_output_body_sha256": digest(
            byte_identity.coff_body(
                byte_identity.CoffObject(donor_bytes),
                byte_identity.CoffObject(donor_bytes).sections[0],
            )
        ),
        "expected_donor_fpo": fixture_fpo_record(donor_bytes, 1),
        "retail_oracle": {
            "image": "LEGO1.DLL",
            "address": "0x10001000",
            "verdict": "MATCH",
            "length": 31,
        },
    }


def two_fpo_function_record(
    donor_bytes, *, mangled, donor, section, seed_length, donor_length,
    linked_span, address,
):
    donor_coff = byte_identity.CoffObject(donor_bytes)
    return {
        "mangled": mangled,
        "donor": donor,
        "splice_class": "equal_linked_span_fpo",
        "expected_section_number": section,
        "expected_seed_length": seed_length,
        "expected_donor_length": donor_length,
        "expected_linked_span": linked_span,
        "expected_characteristics": 0x60501020,
        "expected_selection": 2,
        "expected_relocation_count": 1,
        "expected_seed_line_count": 2,
        "expected_donor_line_count": 3,
        "expected_local_symbol_updates": 0,
        "compiler_output_body_sha256": digest(
            byte_identity.coff_body(
                donor_coff, donor_coff.sections[section - 1]
            )
        ),
        "expected_donor_fpo": fixture_fpo_record(donor_bytes, section),
        "retail_oracle": {
            "image": "LEGO1.DLL",
            "address": address,
            "verdict": "MATCH",
            "length": donor_length,
        },
    }


def make_directive_coff(raw: bytes) -> bytes:
    header = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0, 0)
    section = bytearray(40)
    section[:8] = b".drectve"
    struct.pack_into("<II", section, 16, len(raw), 60)
    return header + bytes(section) + raw


def make_archive_member(name: str, payload: bytes) -> bytes:
    encoded = (name + "/").encode("ascii")
    if len(encoded) > 16:
        raise ValueError("fixture archive member name is too long")
    header = (
        encoded.ljust(16, b" ")
        + b"0".ljust(12, b" ")
        + b"0".ljust(6, b" ")
        + b"0".ljust(6, b" ")
        + b"100644".ljust(8, b" ")
        + str(len(payload)).encode("ascii").ljust(10, b" ")
        + b"`\n"
    )
    return header + payload + (b"\n" if len(payload) & 1 else b"")


def make_third_party_archive(identity: str) -> bytes:
    if identity == "SmartHeap":
        payload = make_directive_coff(
            byte_identity.SMARTHEAP_DIRECTIVE_MEMBERS["iowinapi.obj"]
        )
        return b"!<arch>\n" + make_archive_member("iowinapi.obj", payload)
    if identity == "Smacker":
        return b"!<arch>\n" + make_archive_member("smacker.obj", b"fixture")
    raise ValueError(identity)


class ByteIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name).resolve()
        self.source_dir = self.directory / "source"
        self.build_dir = self.directory / "build"
        self.source = self.source_dir / "src/unit.cpp"
        self.include = self.source_dir / "include/pinned.h"
        self.compiler = self.directory / "wine/x86/cl"
        self.compiler_backend = self.directory / "wine/x86/fake-cl.py"
        self.compiler_support = self.directory / "fake-support"
        self.msvc_environment_script = (
            self.directory / "wine/x86/msvcenv.sh"
        )
        self.manifest = self.source_dir / "tools/byte_identity_manifest.json"
        self.cmake_module = self.source_dir / "cmake/byte_identity.cmake"
        self.plan = self.build_dir / "byte-identity/plan.cmake"
        self.source.parent.mkdir(parents=True)
        self.include.parent.mkdir(parents=True)
        self.manifest.parent.mkdir(parents=True)
        self.cmake_module.parent.mkdir(parents=True)
        self.build_dir.mkdir()
        self.original_cwd = Path.cwd()
        os.chdir(self.build_dir)
        self.source.write_text("int unit() { return 7; }\n")
        self.include.write_text("#define PINNED_HEADER 1\n")
        self.compiler.parent.mkdir(parents=True)
        control_path = self.compiler.with_suffix(".control.json")
        backend = FAKE_COMPILER.replace(
            'control_path = Path(__file__).with_suffix(".control.json")',
            f"control_path = Path({str(control_path)!r})",
        )
        self.compiler_backend.write_text(backend)
        self.compiler_backend.chmod(0o555)
        wrapper_variables = {
            "cl": "MSVC_CL_BIN", "rc": "MSVC_RC_BIN",
            "lib": "MSVC_LIB_BIN", "link": "MSVC_LINK_BIN",
        }
        self.msvc_wrappers = {}
        for name, variable in wrapper_variables.items():
            wrapper = self.directory / f"wine/x86/{name}"
            wrapper.write_bytes(fake_msvc_wrapper(variable))
            wrapper.chmod(0o755)
            self.msvc_wrappers[name] = wrapper
        self.compiler.chmod(0o755)
        self.compiler_support.write_text("pinned fake compiler support\n")
        self.msvc_environment_script.write_bytes(
            b"#!/usr/bin/env bash\nset -e\n"
            + byte_identity.MSVC_ENVIRONMENT_ROOT_DERIVATION_LINE
            + b"MSVC_ROOT=${MSVC_ROOT//\\//\\\\}\n"
            + b"MSVC_CL_BIN=$MSVC_ROOT\\\\bin\\\\CL.EXE\n"
            + b"MSVC_RC_BIN=$MSVC_ROOT\\\\bin\\\\RC.EXE\n"
            + b"MSVC_LIB_BIN=$MSVC_ROOT\\\\bin\\\\LIB.EXE\n"
            + b"MSVC_LINK_BIN=$MSVC_ROOT\\\\bin\\\\LINK.EXE\n"
        )
        self.msvc_environment_script.chmod(0o755)
        self.wine_msvc_script = self.directory / "wine/x86/wine-msvc.sh"
        self.wine_msvc_script.write_bytes(FAKE_WINE_MSVC)
        self.wine_msvc_script.chmod(0o755)
        self.fake_msvc_include = self.directory / "fake-msvc-include"
        self.fake_mfc_include = self.directory / "fake-mfc-include"
        self.fake_wine_bin = self.directory / "fake-wine/bin"
        self.fake_wine_lib = self.directory / "fake-wine/lib"
        self.fake_wine_share = self.directory / "fake-wine/share/wine"
        self.fake_prefix_template = self.directory / "fake-prefix-template"
        for tree, name in (
            (self.fake_msvc_include, "stdio.h"),
            (self.fake_mfc_include, "afx.h"),
            (self.fake_wine_bin, "wine-loader"),
            (self.fake_wine_lib, "runtime.dylib"),
            (self.fake_wine_share, "runtime.dat"),
        ):
            tree.mkdir(parents=True)
            (tree / name).write_text(f"pinned fixture {name}\n")
        self.fake_prefix_template.mkdir()
        for name in (".update-timestamp", "system.reg", "user.reg", "userdef.reg"):
            path = self.fake_prefix_template / name
            path.write_text(
                f"pinned fixture Wine prefix {name}\n"
            )
            path.chmod(0o444)
        self.fake_prefix_template.chmod(0o555)
        shutil.copy2(ROOT / "cmake/byte_identity.cmake", self.cmake_module)
        self.original_path_environment = os.environ.get("PATH")
        runtime_alias_root = self.directory / "host-runtime-aliases"
        runtime_alias_root.mkdir()
        fake_wine_runtime = self.directory / "fake-wine-runtime"
        fake_wine_runtime.write_text("#!/bin/sh\nexit 0\n")
        fake_wine_runtime.chmod(0o755)
        for name in ("wine", "winepath", "wineserver"):
            (runtime_alias_root / name).symlink_to(fake_wine_runtime)
        os.environ["PATH"] = (
            str(runtime_alias_root) + os.pathsep
            + (self.original_path_environment or "")
        )
        python_path = Path(sys.executable).resolve()
        runtime_paths = {
            name: Path(shutil.which(name)).resolve()
            for name in (
                "python3", "bash", "dirname", "sed", "grep",
                "wine", "winepath", "wineserver",
            )
        }
        shape_classes = 2
        shape_functions = 3
        header_sha = digest(
            entropy.generate_shape(shape_classes, shape_functions).encode("utf-8")
        )
        self.recipe_id = f"d_{header_sha[:12]}"
        self.document = {
            "schema": 2,
            "phase": "compiler_output_comdat_v1",
            "diagnostic_policy": (
                byte_identity.NATIVE_DIAGNOSTIC_MANIFEST_POLICY
            ),
            "toolchain": {
                "compiler_sha256": byte_identity.sha256_file(self.compiler),
                "compiler_id": "MSVC",
                "compiler_version": "10.20",
                "python_sha256": byte_identity.sha256_file(python_path),
                "python_version": ".".join(
                    str(value) for value in sys.version_info[:3]
                ),
                "keep_compile_debug": "/Zi",
                "max_child_seconds": 3,
                "compiler_root_parent_levels": 2,
                "compiler_support_files": [
                    {
                        "path": "fake-support",
                        "sha256": byte_identity.sha256_file(self.compiler_support),
                    },
                    {
                        "path": "wine/x86/msvcenv.sh",
                        "sha256": byte_identity.sha256_file(
                            self.msvc_environment_script
                        ),
                    },
                    {
                        "path": "wine/x86/wine-msvc.sh",
                        "sha256": byte_identity.sha256_file(
                            self.wine_msvc_script
                        ),
                    },
                    {
                        "path": "wine/x86/fake-cl.py",
                        "sha256": byte_identity.sha256_file(
                            self.compiler_backend
                        ),
                    },
                    *(
                        {
                            "path": f"wine/x86/{name}",
                            "sha256": byte_identity.sha256_file(path),
                        }
                        for name, path in self.msvc_wrappers.items()
                        if name != "cl"
                    ),
                ],
                "producer_support_files": [],
                "required_absent_toolchain_files": [],
                "runtime_executables": [
                    {
                        "name": name,
                        "sha256": byte_identity.sha256_file(path),
                    }
                    for name, path in runtime_paths.items()
                ],
                "sealed_include_trees": [
                    {
                        "role": role,
                        "path": tree.relative_to(self.directory).as_posix(),
                        "entry_count": snapshot["entry_count"],
                        "max_depth": snapshot["max_depth"],
                        "membership_sha256": snapshot["membership_sha256"],
                        "content_sha256": snapshot["content_sha256"],
                    }
                    for role, tree, snapshot in (
                        (
                            "msvc_include", self.fake_msvc_include,
                            byte_identity.canonical_tree_snapshot(
                                self.fake_msvc_include, hash_files=True
                            ),
                        ),
                        (
                            "mfc_include", self.fake_mfc_include,
                            byte_identity.canonical_tree_snapshot(
                                self.fake_mfc_include, hash_files=True
                            ),
                        ),
                    )
                ],
                "runtime_closure": {
                    "schema": "wine_runtime_closure_v1",
                    "membership_roots": [
                        {
                            "role": role,
                            "path": str(tree),
                            "entry_count": snapshot["entry_count"],
                            "max_depth": snapshot["max_depth"],
                            "membership_sha256": snapshot["membership_sha256"],
                            "content_sha256": snapshot["content_sha256"],
                        }
                        for role, tree, snapshot in (
                            (
                                "wine_bin", self.fake_wine_bin,
                                byte_identity.canonical_tree_snapshot(
                                    self.fake_wine_bin, hash_files=True
                                ),
                            ),
                            (
                                "wine_lib", self.fake_wine_lib,
                                byte_identity.canonical_tree_snapshot(
                                    self.fake_wine_lib, hash_files=True
                                ),
                            ),
                            (
                                "wine_share", self.fake_wine_share,
                                byte_identity.canonical_tree_snapshot(
                                    self.fake_wine_share, hash_files=True
                                ),
                            ),
                        )
                    ],
                    "loaded_files": [
                        {
                            "role": "fake_wine_loader",
                            "path": str(self.fake_wine_bin / "wine-loader"),
                            "sha256": byte_identity.sha256_file(
                                self.fake_wine_bin / "wine-loader"
                            ),
                        }
                    ],
                    "host_identity": byte_identity.current_host_runtime_identity(),
                    "system_imports": list(
                        byte_identity.EXPECTED_DYLD_IMPORT_IDENTITIES
                    ),
                    "resolution_policy": "casefold_unique_first_match_v1",
                },
                "transport": {
                    "schema": "wine_virtual_z_v1",
                    "copy_policy": "independent_regular_files_no_hardlinks_v1",
                    "runtime_snapshot_policy": (
                        "selected_loaded_closure_with_full_root_content_merkle_v1"
                    ),
                    "prefix_template_files": [
                        {
                            "name": name,
                            "path": str(self.fake_prefix_template / name),
                            "sha256": byte_identity.sha256_file(
                                self.fake_prefix_template / name
                            ),
                            "mode": 0o444,
                        }
                        for name in (
                            ".update-timestamp", "system.reg",
                            "user.reg", "userdef.reg",
                        )
                    ],
                    "prefix_directories": [
                        "drive_c", "drive_c/windows",
                        "drive_c/windows/temp", "drive_c/users",
                        "drive_c/users/fixture", "drive_c/users/fixture/Temp",
                    ],
                    "dosdevices": ["c:", "z:"],
                    "server_shutdown": "prefix_scoped_kill_wait_bounded_v1",
                    "msvc_environment": {
                        "root_transform": {
                            "schema": (
                                byte_identity.
                                MSVC_ENVIRONMENT_ROOT_TRANSFORM_SCHEMA
                            ),
                            "script": "wine/x86/msvcenv.sh",
                        },
                        "wrapper_invocation_transform": {
                            "schema": (
                                byte_identity.
                                MSVC_WRAPPER_INVOCATION_TRANSFORM_SCHEMA
                            ),
                            "scripts": list(
                                byte_identity.MSVC_WRAPPER_TRANSFORM_SCRIPTS
                            ),
                        },
                        "argument_path_transform": {
                            "schema": (
                                byte_identity.
                                MSVC_WINE_ARGUMENT_TRANSFORM_SCHEMA
                            ),
                            "script": "wine/x86/wine-msvc.sh",
                        },
                        "include_order": [
                            "fake-msvc-include",
                            "fake-mfc-include",
                        ],
                        "winepath_order": [
                            "bin",
                            "bin/winnt",
                        ],
                        "winedlloverrides": "msvcrt40=n;msvcrt20=n",
                    },
                },
                "child_environment": byte_identity.CHILD_ENVIRONMENT_POLICY,
                "provenance": {
                    "retail_use": "oracle_only_no_payload_copy",
                    "payload_source": "configured_compiler_output",
                    "forbid_emitted_padding": True,
                    "forbid_opaque_objects": True,
                    "forbid_source_tree_writes": True,
                },
            },
            "target_policies": [
                {
                    "target": "fixture",
                    "allowed_force_includes": [
                        {
                            "path": "include/pinned.h",
                            "sha256": byte_identity.sha256_file(self.include),
                        }
                    ],
                }
            ],
            "translation_units": [
                {
                    "target": "fixture",
                    "source": "src/unit.cpp",
                    "source_sha256": byte_identity.sha256_file(self.source),
                    "mode": "pass_through",
                    "command_policy": {
                        "required_flags": ["/Zi", "-c"],
                        "forbidden_prefixes": ["/GL", "-GL", "/Z7", "-Z7"],
                    },
                    "donors": [
                        {
                            "id": self.recipe_id,
                            "status": "planned_not_composed",
                            "authenticity": "synthetic_baseline_only",
                            "recipe": {
                                "kind": "declaration_shape",
                                "classes": shape_classes,
                                "functions": shape_functions,
                                "generated_header_sha256": header_sha,
                                "emission_policy": "non_emitting_declarations_only",
                                "authenticity_rationale": (
                                    "Framework-generated synthetic declaration-only compiler-state "
                                    "input that emits no linker payload."
                                ),
                            },
                        }
                    ],
                    "functions": [],
                    "completion": {
                        "state": "planned_not_composed",
                        "reason": "The native fixture intentionally exercises only the atomic pass-through phase.",
                        "may_replace_compiler_output": False,
                    },
                }
            ],
            "archives": [],
            "images": {},
            "terminal_producers": {},
        }
        self.write_manifest()
        self.attested_commands = {}
        self.attested_directories = {}
        self.diagnostic_projection_receipts = {}
        self.diagnostic_projection_authorities = {}

    def tearDown(self):
        os.chdir(self.original_cwd)
        if self.original_path_environment is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = self.original_path_environment
        if self.fake_prefix_template.exists() and not self.fake_prefix_template.is_symlink():
            self.fake_prefix_template.chmod(0o755)
            for path in self.fake_prefix_template.iterdir():
                if path.is_file() and not path.is_symlink():
                    path.chmod(0o644)
        self.temporary.cleanup()

    def write_manifest(self):
        self.manifest.write_text(json.dumps(self.document, indent=2) + "\n")

    @staticmethod
    def source_overlay_fragment(
        data: bytes, structural_effect: str, *, declared=(), referenced=(),
        emitted=(),
    ):
        return {
            "baseline_sha256": byte_identity.sha256_bytes(data),
            "baseline_size": len(data),
            "baseline_line_count": data.count(b"\n"),
            "baseline_significant_token_sha256":
                byte_identity.source_overlay_significant_sha256(data),
            "declared_identifiers": sorted(declared),
            "referenced_identifiers": sorted(referenced),
            "emitted_identifiers": sorted(emitted),
            "structural_effect": structural_effect,
        }

    def source_overlay_line_reservation(self, count=1):
        rendered = b"\n" * count
        return {
            "kind": "line_reservation_v1",
            "emission_class": "source_layout_only",
            "params": {
                "content_role": "renderer_owned_layout_comment",
                "physical_line_count": count,
                "renderer_layout": {
                    "kind": "typed_line_canvas_v1",
                    "physical_line_count": count,
                    "content_lines": [],
                    "transparent_line_runs": [{
                        "first": 1, "count": count,
                        "indentation_units": [],
                    }],
                    "line_ending": "lf", "terminal_newline": True,
                },
            },
            "baseline_fragment": self.source_overlay_fragment(
                rendered, "physical_line_reservation"
            ),
        }

    def source_overlay_literal_use(self):
        rendered = b"configAppName"
        return {
            "kind": "literal_first_use_alias_v1",
            "emission_class": "compiler_state_only",
            "params": {
                "literal": "config", "local_identifier": "configAppName",
                "owner_function": "CConfigApp::InitInstance",
                "use_ordinal": 1,
                "renderer_layout": {
                    "kind": "typed_line_canvas_v1",
                    "physical_line_count": 1,
                    "content_lines": [{
                        "semantic_line": 1, "relative_line": 1,
                        "indentation_units": [],
                    }],
                    "transparent_line_runs": [],
                    "line_ending": "none", "terminal_newline": False,
                },
            },
            "baseline_fragment": self.source_overlay_fragment(
                rendered, "literal_first_use_reseat",
                referenced=("configAppName",),
            ),
        }

    @staticmethod
    def source_overlay_anchor(
        data: bytes, relative: str, operation_id: str, offset: int,
        boundary_kind: str,
    ):
        matches = byte_identity.source_overlay_tokens(data)
        token_boundary = None
        for index in range(len(matches) + 1):
            lower = matches[index - 1][2] if index else 0
            upper = matches[index][1] if index < len(matches) else len(data)
            if lower <= offset <= upper:
                token_boundary = index
                break
        if token_boundary is None:
            raise AssertionError("fixture offset is outside every token gap")
        tokens = [item[0] for item in matches]
        tiers = []
        for width in (32, 16, 8):
            before_count = min(width, token_boundary)
            after_count = min(width, len(tokens) - token_boundary)
            signature = (
                tokens[token_boundary - before_count:token_boundary]
                + ["<SEAT>"]
                + tokens[token_boundary:token_boundary + after_count]
            )
            context_sha = byte_identity.source_overlay_token_sha256(signature)
            occurrences = 0
            for candidate in range(len(tokens) + 1):
                if (candidate < before_count
                        or len(tokens) - candidate < after_count):
                    continue
                candidate_signature = (
                    tokens[candidate - before_count:candidate]
                    + ["<SEAT>"]
                    + tokens[candidate:candidate + after_count]
                )
                if (byte_identity.source_overlay_token_sha256(
                        candidate_signature) == context_sha):
                    occurrences += 1
            tiers.append({
                "context_tokens_each_side": width,
                "before_token_count": before_count,
                "after_token_count": after_count,
                "context_sha256": context_sha,
                "occurrences": occurrences,
            })
        boundary = {"kind": boundary_kind}
        return {
            "anchor_kind": "significant_token_context_v1",
            "logical_path": relative,
            "operation_ids": [operation_id],
            "policy": byte_identity.SOURCE_OVERLAY_ANCHOR_POLICY,
            "structural_seat": byte_identity.source_overlay_structural_seat(
                data, offset, boundary
            ),
            "tiers": tiers,
        }

    @staticmethod
    def source_overlay_payload(outputs):
        paths = sorted(item["logical_path"] for item in outputs)
        return {
            "schema": byte_identity.SOURCE_OVERLAY_SCHEMA,
            "status": byte_identity.SOURCE_OVERLAY_STATUS,
            "renderer": byte_identity.SOURCE_OVERLAY_RENDERER,
            "generator_registry_sha256":
                byte_identity.SOURCE_OVERLAY_GENERATOR_REGISTRY_SHA256,
            "closed_universe": {
                "physical_output_count": len(paths),
                "sorted_logical_paths_sha256": byte_identity.sha256_bytes(
                    "".join(path + "\n" for path in paths).encode("utf-8")
                ),
            },
            "drift_contract": byte_identity.SOURCE_OVERLAY_DRIFT_CONTRACT,
            "runtime_trust": byte_identity.SOURCE_OVERLAY_RUNTIME_TRUST,
            "outputs": sorted(outputs, key=lambda item: item["logical_path"]),
            "graph": {
                "generated_translation_units": [],
                "link_admissions": [],
                "forbidden_legacy_interfaces": [
                    "ISLE_INCLUDE_ENTROPY", "ISLE_ENTROPY_FILENAME",
                    "ISLE_TU_ENTROPY_MANIFEST",
                ],
                "prebuilt_source_artifacts": "forbidden",
            },
        }

    def test_source_overlay_renderer_layout_is_the_only_byte_authority(self):
        raw = self.source_overlay_line_reservation()
        generator = byte_identity.validate_source_overlay_generator(
            raw, "fixture.generator"
        )
        self.assertEqual(
            byte_identity.render_source_overlay_generator(generator), b"\n"
        )
        self.assertEqual(
            byte_identity.render_source_overlay_generator(generator), b"\n"
        )

        different_layout = json.loads(json.dumps(generator))
        different_layout["params"]["renderer_layout"] = {
            "kind": "typed_line_canvas_v1",
            "physical_line_count": 1,
            "content_lines": [],
            "transparent_line_runs": [{
                "first": 1, "count": 1,
                "indentation_units": [{"unit": "space", "count": 1}],
            }],
            "line_ending": "lf", "terminal_newline": True,
        }
        self.assertEqual(
            byte_identity._seat_source_overlay_fragment(
                different_layout, b""
            ),
            b" \n",
        )

        wrong_pin = json.loads(json.dumps(generator))
        wrong_pin["baseline_fragment"]["baseline_sha256"] = "0" * 64
        self.assertEqual(
            byte_identity._seat_source_overlay_fragment(wrong_pin, b""),
            b"\n",
        )
        with self.assertRaisesRegex(
            byte_identity.ByteIdentityError, "canonical pins"
        ):
            byte_identity.render_source_overlay_generator(wrong_pin)

        unknown = json.loads(json.dumps(raw))
        unknown["params"]["literal_payload"] = "free-form text"
        with self.assertRaisesRegex(
            byte_identity.ByteIdentityError, "schema differs"
        ):
            byte_identity.validate_source_overlay_generator(
                unknown, "fixture.generator"
            )

    def test_source_overlay_after_newline_boundary_handles_drift_fail_closed(self):
        relative = "src/anchor.cpp"
        operation_id = "op_anchor_fixture"
        unique = b"int a;\n\nint b;\n"
        anchor = self.source_overlay_anchor(
            unique, relative, operation_id,
            unique.index(b"\n") + 1, "after_newline",
        )
        normalized = byte_identity.validate_source_overlay_anchor(
            anchor, "fixture.anchor", logical_path=relative,
            operation_id=operation_id,
        )
        harmless_blank_drift = b"int a;\n\n\nint b;\n"
        self.assertEqual(
            byte_identity.resolve_source_overlay_anchor(
                harmless_blank_drift, normalized, "fixture harmless drift"
            ),
            harmless_blank_drift.index(b"\n") + 1,
        )

        ambiguous_base = b"int a;\n\n\nint b;\n"
        middle = ambiguous_base.index(b"\n") + 2
        ambiguous_anchor = self.source_overlay_anchor(
            ambiguous_base, relative, operation_id,
            middle, "after_newline",
        )
        normalized_ambiguous = byte_identity.validate_source_overlay_anchor(
            ambiguous_anchor, "fixture.ambiguous_anchor",
            logical_path=relative, operation_id=operation_id,
        )
        with self.assertRaisesRegex(
            byte_identity.ByteIdentityError,
            "no unique after-newline structural seat",
        ):
            byte_identity.resolve_source_overlay_anchor(
                b"int a;\n\n\n\nint b;\n", normalized_ambiguous,
                "fixture ambiguous drift",
            )

    def test_source_overlay_present_drift_and_generated_absence_are_exact(self):
        relative = "overlay/example.h"
        path = self.source_dir / relative
        path.parent.mkdir()
        clean = b"int baseline;\n"
        path.write_bytes(clean)
        generator = self.source_overlay_line_reservation()
        operation_id = "op_fixture_insert"
        effective = clean + b"\n"
        output = {
            "logical_path": relative,
            "clean": {
                "state": "present",
                "baseline_sha256": byte_identity.sha256_bytes(clean),
                "baseline_size": len(clean),
            },
            "effective": {
                "mode": byte_identity.SOURCE_OVERLAY_EFFECTIVE_MODE,
                "baseline_sha256": byte_identity.sha256_bytes(effective),
                "baseline_size": len(effective),
                "baseline_line_count": effective.count(b"\n"),
                "baseline_significant_token_sha256":
                    byte_identity.source_overlay_significant_sha256(effective),
            },
            "operations": [{
                "id": operation_id, "action": "insert",
                "start_anchor": self.source_overlay_anchor(
                    clean, relative, operation_id, len(clean), "file_end"
                ),
                "generator": generator,
            }],
        }
        payload = self.source_overlay_payload([output])
        baseline = byte_identity.validate_source_overlay(
            payload, self.source_dir
        )
        self.assertTrue(baseline["actual_records"][0]["clean_baseline_match"])

        drift = b"// harmless unrelated comment\n" + clean
        path.write_bytes(drift)
        accepted = byte_identity.validate_source_overlay(
            payload, self.source_dir
        )
        self.assertFalse(accepted["actual_records"][0]["clean_baseline_match"])
        self.assertEqual(
            accepted["effective_by_path"][relative]["sha256"],
            byte_identity.sha256_bytes(drift + b"\n"),
        )

        generated_relative = "overlay/generated.h"
        generated_output = {
            "logical_path": generated_relative,
            "clean": {"state": "absent"},
            "effective": {
                "mode": byte_identity.SOURCE_OVERLAY_EFFECTIVE_MODE,
                "baseline_sha256": byte_identity.sha256_bytes(b"\n"),
                "baseline_size": 1, "baseline_line_count": 1,
                "baseline_significant_token_sha256":
                    byte_identity.source_overlay_significant_sha256(b"\n"),
            },
            "operations": [{
                "id": "op_fixture_generated", "action": "whole_file_append",
                "generator": self.source_overlay_line_reservation(),
            }],
        }
        generated_payload = self.source_overlay_payload([generated_output])
        byte_identity.validate_source_overlay(
            generated_payload, self.source_dir
        )
        generated_path = self.source_dir / generated_relative
        generated_path.write_text("preexisting\n")
        with self.assertRaisesRegex(
            byte_identity.ByteIdentityError,
            "generated-only clean source path unexpectedly exists",
        ):
            byte_identity.validate_source_overlay(
                generated_payload, self.source_dir
            )
        generated_path.unlink()
        redirected_parent = self.source_dir / "redirected-overlay"
        redirected_target = self.directory / "redirected-overlay-target"
        redirected_target.mkdir()
        redirected_parent.symlink_to(redirected_target, target_is_directory=True)
        redirected_output = json.loads(json.dumps(generated_output))
        redirected_output["logical_path"] = "redirected-overlay/generated.h"
        redirected_payload = self.source_overlay_payload([redirected_output])
        with self.assertRaisesRegex(
            byte_identity.ByteIdentityError,
            "source overlay parent is redirected",
        ):
            byte_identity.validate_source_overlay(
                redirected_payload, self.source_dir
            )

    def test_source_overlay_destructive_range_and_literal_roles_are_exact(self):
        relative = "overlay/config.cpp"
        path = self.source_dir / relative
        path.parent.mkdir()
        clean = (
            b"int before;\n\n"
            b'/* authenticated seat */ "config"\n\n'
            b"int after;\n"
        )
        path.write_bytes(clean)
        operation_id = "op_fixture_replace"
        start = clean.index(b"\n") + 1
        end = clean.index(b"int after")
        removed = clean[start:end]
        fragment = b"configAppName"
        effective = clean[:start] + fragment + clean[end:]
        generator = self.source_overlay_literal_use()
        output = {
            "logical_path": relative,
            "clean": {
                "state": "present",
                "baseline_sha256": byte_identity.sha256_bytes(clean),
                "baseline_size": len(clean),
            },
            "effective": {
                "mode": byte_identity.SOURCE_OVERLAY_EFFECTIVE_MODE,
                "baseline_sha256": byte_identity.sha256_bytes(effective),
                "baseline_size": len(effective),
                "baseline_line_count": effective.count(b"\n"),
                "baseline_significant_token_sha256":
                    byte_identity.source_overlay_significant_sha256(effective),
            },
            "operations": [{
                "id": operation_id, "action": "replace",
                "start_anchor": self.source_overlay_anchor(
                    clean, relative, operation_id, start,
                    "after_newline",
                ),
                "end_anchor": self.source_overlay_anchor(
                    clean, relative, operation_id, end,
                    "before_next_token",
                ),
                "generator": generator,
                "baseline_input_range": {
                    "baseline_sha256": byte_identity.sha256_bytes(removed),
                    "baseline_size": len(removed),
                    "baseline_line_count": removed.count(b"\n"),
                    "baseline_significant_token_sha256":
                        byte_identity.source_overlay_significant_sha256(removed),
                },
            }],
        }
        payload = self.source_overlay_payload([output])
        accepted = byte_identity.validate_source_overlay(
            payload, self.source_dir
        )
        evidence = accepted["anchor_evidence"][0]
        self.assertEqual(
            evidence["actual_removed_range_sha256"],
            byte_identity.sha256_bytes(removed),
        )

        wrong_role = json.loads(json.dumps(generator))
        wrong_role["baseline_fragment"]["declared_identifiers"] = [
            "configAppName"
        ]
        wrong_role["baseline_fragment"]["referenced_identifiers"] = []
        with self.assertRaisesRegex(
            byte_identity.ByteIdentityError, "literal alias census differs"
        ):
            byte_identity.validate_source_overlay_generator(
                wrong_role, "fixture.literal_use"
            )

        path.write_bytes(clean.replace(
            b"authenticated seat", b"tampered range bytes"
        ))
        with self.assertRaisesRegex(
            byte_identity.ByteIdentityError,
            "authenticated input-range pins",
        ):
            byte_identity.validate_source_overlay(payload, self.source_dir)

    def test_source_overlay_composite_child_and_output_pins_are_exact(self):
        rendered = b"\n\n"
        child = self.source_overlay_line_reservation(2)
        composite = {
            "kind": "composed_typed_sequence_v1",
            "emission_class": "composed",
            "params": {
                "physical_line_count": 2,
                "comment_policy": "strip_prose_preserve_physical_lines_v1",
                "composition_policy":
                    "line_overlay_disjoint_nonblank_conflict_reject_v2",
                "items": [{
                    "index": 0, "relative_lines": [1, 2],
                    "transparent_relative_lines": [1, 2],
                    "generator": child,
                }],
                "renderer_layout": {
                    "kind": "typed_line_canvas_v1",
                    "physical_line_count": 2,
                    "content_lines": [],
                    "transparent_line_runs": [{
                        "first": 1, "count": 2,
                        "indentation_units": [],
                    }],
                    "line_ending": "lf", "terminal_newline": True,
                },
            },
            "baseline_fragment": self.source_overlay_fragment(
                rendered, "line_indexed_nonblank_overlay"
            ),
        }
        normalized = byte_identity.validate_source_overlay_generator(
            composite, "fixture.composite"
        )
        self.assertEqual(
            byte_identity.render_source_overlay_generator(normalized), rendered
        )

        child_tamper = json.loads(json.dumps(normalized))
        child_tamper["params"]["items"][0]["generator"][
            "baseline_fragment"
        ]["baseline_sha256"] = "0" * 64
        with self.assertRaisesRegex(
            byte_identity.ByteIdentityError, "canonical pins"
        ):
            byte_identity.render_source_overlay_generator(child_tamper)

        parent_tamper = json.loads(json.dumps(normalized))
        parent_tamper["baseline_fragment"]["baseline_sha256"] = "0" * 64
        with self.assertRaisesRegex(
            byte_identity.ByteIdentityError, "canonical pins"
        ):
            byte_identity.render_source_overlay_generator(parent_tamper)

        relative = "overlay/composite.h"
        (self.source_dir / "overlay").mkdir(exist_ok=True)
        output = {
            "logical_path": relative,
            "clean": {"state": "absent"},
            "effective": {
                "mode": byte_identity.SOURCE_OVERLAY_EFFECTIVE_MODE,
                "baseline_sha256": byte_identity.sha256_bytes(rendered),
                "baseline_size": len(rendered),
                "baseline_line_count": rendered.count(b"\n"),
                "baseline_significant_token_sha256":
                    byte_identity.source_overlay_significant_sha256(rendered),
            },
            "operations": [{
                "id": "op_fixture_composite",
                "action": "whole_file_append", "generator": composite,
            }],
        }
        byte_identity.validate_source_overlay(
            self.source_overlay_payload([output]), self.source_dir
        )
        output["effective"]["baseline_sha256"] = "0" * 64
        with self.assertRaisesRegex(
            byte_identity.ByteIdentityError,
            "baseline source overlay output differs",
        ):
            byte_identity.validate_source_overlay(
                self.source_overlay_payload([output]), self.source_dir
            )

    def test_source_overlay_receipt_requires_same_transaction_memory_authority(self):
        policy_sha = byte_identity.sha256_bytes(b"fixture overlay policy")
        actual_sha = byte_identity.sha256_bytes(b"fixture actual records")
        anchor_sha = byte_identity.sha256_bytes(b"fixture anchor evidence")
        manifest_sha = byte_identity.sha256_bytes(b"fixture manifest")
        state = {
            "build_dir": str(self.build_dir),
            "manifest_sha256": manifest_sha,
            "source_overlay": {
                "enabled": True, "policy_sha256": policy_sha,
                "actual_records_sha256": actual_sha,
                "anchor_evidence_sha256": anchor_sha,
                "outputs": [{"logical_path": "overlay/example.h"}],
            },
        }
        receipt = {
            "schema": 1,
            "status": "TYPED_SOURCE_OVERLAY_MATERIALIZED",
            "manifest_sha256": manifest_sha,
            "renderer": byte_identity.SOURCE_OVERLAY_RENDERER,
            "policy_sha256": policy_sha,
            "actual_records_sha256": actual_sha,
            "anchor_evidence_sha256": anchor_sha,
            "physical_output_count": 1,
        }
        path = byte_identity.source_overlay_receipt_path(self.build_dir)
        with byte_identity.build_transaction(
            self.build_dir, exclusive=True, bootstrap_outer_session=True,
        ) as authority:
            authority.mkdirs(path.parent)
            receipt_bytes = byte_identity.atomic_json(path, receipt)
            evidence = {
                "source_overlay_enabled": True,
                "source_overlay_policy_sha256": policy_sha,
                "source_overlay_actual_records_sha256": actual_sha,
                "source_overlay_receipt_sha256":
                    byte_identity.sha256_bytes(receipt_bytes),
                "source_overlay_output_count": 1,
            }
            authority.execution_projection = {
                "source_overlay_receipt": receipt
            }
            self.assertEqual(
                byte_identity.validate_execution_projection_source_overlay_evidence(
                    state, evidence, "same transaction fixture"
                ),
                path,
            )
            authority.execution_projection = None
            with self.assertRaisesRegex(
                byte_identity.ByteIdentityError,
                "materialization receipt differs",
            ):
                byte_identity.validate_execution_projection_source_overlay_evidence(
                    state, evidence, "disk-only fixture"
                )

    def test_source_overlay_receipt_is_in_the_exact_audit_namespace(self):
        inventory = {"entries": [], "inputs": [], "targets": []}
        disabled = {
            "source_overlay": {"enabled": False},
            "recipes": [], "archives": [], "images": {},
        }
        enabled = {
            **disabled,
            "source_overlay": {"enabled": True},
        }
        self.assertNotIn(
            "source-overlay.json",
            byte_identity.expected_top_level_audit_namespace(
                disabled, inventory
            ),
        )
        self.assertEqual(
            byte_identity.expected_top_level_audit_namespace(
                enabled, inventory
            )["source-overlay.json"],
            "file",
        )
        audit_root = self.build_dir / "byte-identity/audit"
        receipt_path = audit_root / "source-overlay.json"
        with byte_identity.build_transaction(
            self.build_dir, exclusive=True, bootstrap_outer_session=True,
        ) as authority:
            authority.mkdirs(audit_root)
            byte_identity.require_exact_build_namespace(
                authority, audit_root, {}, "disabled overlay audit fixture"
            )
            authority.atomic_write(receipt_path, b"{}\n")
            with self.assertRaisesRegex(
                byte_identity.ByteIdentityError, "missing or extra"
            ):
                byte_identity.require_exact_build_namespace(
                    authority, audit_root, {},
                    "disabled overlay audit fixture", replace_pin=True,
                )
            byte_identity.require_exact_build_namespace(
                authority, audit_root, {"source-overlay.json": "file"},
                "enabled overlay audit fixture", replace_pin=True,
            )
            authority.unlink(receipt_path)
            with self.assertRaisesRegex(
                byte_identity.ByteIdentityError, "missing or extra"
            ):
                byte_identity.require_exact_build_namespace(
                    authority, audit_root,
                    {"source-overlay.json": "file"},
                    "enabled overlay audit fixture", replace_pin=True,
                )

    def test_source_overlay_terminal_projection_mutation_publishes_nothing(self):
        relative = self.include.relative_to(self.source_dir).as_posix()
        clean = self.include.read_bytes()
        effective = clean + b"\n"
        operation_id = "op_fixture_projected_header"
        output = {
            "logical_path": relative,
            "clean": {
                "state": "present",
                "baseline_sha256": byte_identity.sha256_bytes(clean),
                "baseline_size": len(clean),
            },
            "effective": {
                "mode": byte_identity.SOURCE_OVERLAY_EFFECTIVE_MODE,
                "baseline_sha256": byte_identity.sha256_bytes(effective),
                "baseline_size": len(effective),
                "baseline_line_count": effective.count(b"\n"),
                "baseline_significant_token_sha256":
                    byte_identity.source_overlay_significant_sha256(effective),
            },
            "operations": [{
                "id": operation_id, "action": "insert",
                "start_anchor": self.source_overlay_anchor(
                    clean, relative, operation_id, len(clean), "file_end"
                ),
                "generator": self.source_overlay_line_reservation(),
            }],
        }
        self.document["source_overlay"] = self.source_overlay_payload([output])
        self.document["target_policies"][0]["allowed_force_includes"][0][
            "sha256"
        ] = byte_identity.sha256_bytes(effective)
        self.write_manifest()
        self.ensure_inventory()
        object_path = self.build_dir / "objects/overlay-terminal.obj"
        pdb_path = self.build_dir / "objects/overlay-terminal.pdb"
        self.attest_command(
            self.launch_args(object_path, pdb_path, ensure_inventory=False)
        )
        projection_root = None
        with self.assertRaisesRegex(
            byte_identity.ByteIdentityError,
            "transaction execution projection changed",
        ):
            with byte_identity.build_transaction(
                self.build_dir, exclusive=True,
                bootstrap_outer_session=True,
            ) as authority:
                state = byte_identity.validate_manifest(
                    self.manifest, self.source_dir, self.build_dir,
                    configured_compiler=str(self.compiler),
                )
                projection = self.materialize_resident_projection_fixture(
                    state
                )
                projection_root = Path(projection["root"])
                self.assertTrue(
                    byte_identity.source_overlay_receipt_path(
                        self.build_dir
                    ).is_file()
                )
                projected = byte_identity.absolute_snapshot_seat(
                    Path(projection["z"]), self.include
                )
                projected.chmod(0o600)
                projected.write_bytes(projected.read_bytes() + b"mutation")
                byte_identity.finalize_execution_projection(authority)
        self.assertIsNotNone(projection_root)
        self.assertFalse(projection_root.exists())
        self.assertFalse(
            byte_identity.source_overlay_receipt_path(self.build_dir).exists()
        )
        self.assertFalse(
            byte_identity.execution_projection_finalization_path(
                self.build_dir
            ).exists()
        )
        self.assertFalse(
            (self.build_dir
             / "byte-identity/audit/framework-verdict.json").exists()
        )

    def test_native_reccmp_source_snapshot_requires_effective_overlay_bytes(self):
        relative = "overlay/effective.cpp"
        clean = b"int clean;\n"
        effective = b"int effective;\n"
        state = {
            "source_overlay": {
                "enabled": True,
                "outputs": [{"logical_path": relative}],
                "effective_by_path": {
                    relative: {
                        "sha256": byte_identity.sha256_bytes(effective),
                        "size": len(effective),
                    }
                },
            }
        }
        snapshot = {
            "records": [
                {"path": ".", "type": "directory"},
                {
                    "path": relative, "type": "file",
                    "sha256": byte_identity.sha256_bytes(effective),
                    "size": len(effective),
                },
            ]
        }
        byte_identity.validate_reccmp_effective_source_snapshot(
            state, snapshot, "fixture effective reccmp source"
        )
        snapshot["records"][1].update({
            "sha256": byte_identity.sha256_bytes(clean),
            "size": len(clean),
        })
        with self.assertRaisesRegex(
            byte_identity.ByteIdentityError,
            "lacks the typed effective source",
        ):
            byte_identity.validate_reccmp_effective_source_snapshot(
                state, snapshot, "fixture clean reccmp source"
            )

    def make_fake_cmake_install(
        self, name: str, *, resource_names: tuple[str, ...] = ("cmake",),
        resource_files: bool = True,
    ) -> Path:
        root = self.directory / name
        binary = root / "bin/cmake"
        binary.parent.mkdir(parents=True)
        binary.write_text(FAKE_OUTER_CMAKE)
        binary.chmod(0o755)
        for resource_name in resource_names:
            resource = root / "share" / resource_name
            resource.mkdir(parents=True)
            if resource_files:
                module = resource / "Modules/CMake.cmake"
                module.parent.mkdir(parents=True)
                module.write_text("# pinned fake CMake resource\n")
        return binary

    @contextmanager
    def fake_control(self, **values):
        path = self.compiler.with_suffix(".control.json")
        previous = path.read_bytes() if path.is_file() else None
        path.write_text(json.dumps(values, sort_keys=True))
        try:
            yield
        finally:
            if previous is None:
                path.unlink(missing_ok=True)
            else:
                path.write_bytes(previous)

    @contextmanager
    def active_outer_session(self):
        """Install a live exact outer-session fixture for terminal gates."""
        nonce = hashlib.sha256(os.urandom(64)).hexdigest()
        python = Path(sys.executable).resolve(strict=True)
        framework = Path(byte_identity.__file__).resolve(strict=True)
        backend_tool = Path(
            byte_identity.execution_backend_module.__file__
        ).resolve(strict=True)
        cmake = self.compiler.resolve(strict=True)
        marker = {
            "schema": 1,
            "status": "BYTE_IDENTITY_OUTER_DRIVER_REQUIRED",
            "source_root": str(self.source_dir.resolve()),
            "build_root": str(self.build_dir.resolve()),
            "python": str(python),
            "python_sha256": byte_identity.sha256_file(python),
            "framework_sha256": byte_identity.sha256_file(framework),
            "backend": byte_identity.selected_backend(),
            "backend_tool": str(backend_tool),
            "backend_tool_sha256": byte_identity.sha256_file(backend_tool),
        }
        active = {
            "schema": 1,
            "status": "BYTE_IDENTITY_OUTER_SESSION_ACTIVE",
            "nonce": nonce,
            "mode": "build",
            "driver_pid": os.getpid(),
            "source_root": marker["source_root"],
            "build_root": marker["build_root"],
            "cmake": str(cmake),
            "cmake_sha256": byte_identity.sha256_file(cmake),
            "python": marker["python"],
            "python_sha256": marker["python_sha256"],
            "framework_sha256": marker["framework_sha256"],
            "backend": marker["backend"],
            "backend_tool": marker["backend_tool"],
            "backend_tool_sha256": marker["backend_tool_sha256"],
            "started_monotonic": float(time.monotonic()),
        }
        marker_path = byte_identity.hard_mode_marker_path(self.build_dir)
        active_path = byte_identity.active_session_path(self.build_dir)
        marker_path.parent.mkdir(parents=True, exist_ok=True)
        marker_path.write_text(json.dumps(marker, sort_keys=True) + "\n")
        active_path.write_text(json.dumps(active, sort_keys=True) + "\n")
        previous = os.environ.get(byte_identity.SESSION_NONCE_ENV)
        os.environ[byte_identity.SESSION_NONCE_ENV] = nonce
        try:
            yield nonce
        finally:
            active_path.unlink(missing_ok=True)
            marker_path.unlink(missing_ok=True)
            if previous is None:
                os.environ.pop(byte_identity.SESSION_NONCE_ENV, None)
            else:
                os.environ[byte_identity.SESSION_NONCE_ENV] = previous

    @contextmanager
    def standalone_producer_diagnostic(self):
        """Exercise one producer without granting terminal authority.

        Production compile/resource/archive/link producers are resident-only.
        Native unit tests still need their narrow producer mechanics, so this
        context supplies only a mocked live-session answer and a stable active
        file for the producer-state cache.  It deliberately creates neither a
        hard-mode marker nor a durable resident receipt; a later standalone
        ``verify`` must therefore refuse the on-disk projection receipt.
        """
        nonce = digest(os.urandom(64))
        session = {
            "schema": 1,
            "status": "BYTE_IDENTITY_OUTER_SESSION_ACTIVE",
            "nonce": nonce,
            "mode": "iterate",
            "driver_pid": os.getpid(),
            "source_root": str(self.source_dir),
            "build_root": str(self.build_dir),
        }
        active = byte_identity.active_session_path(self.build_dir)
        previous_bytes = active.read_bytes() if active.is_file() else None
        active.parent.mkdir(parents=True, exist_ok=True)
        active.write_text(json.dumps(session, sort_keys=True) + "\n")
        previous_nonce = os.environ.get(byte_identity.SESSION_NONCE_ENV)
        os.environ[byte_identity.SESSION_NONCE_ENV] = nonce
        held_state = None

        def diagnostic_state(arguments):
            nonlocal held_state
            state = byte_identity.validate_manifest(
                arguments.manifest, arguments.source_dir,
                arguments.build_dir,
                configured_compiler=arguments.configured_compiler,
            )
            # The fake compiler's control plane is intentionally a sibling of
            # its executable.  Once production execution maps argv[0] to the
            # held toolchain seat, authenticate and copy that test-only sibling
            # into the same seat as well; the child must never fall back to the
            # mutable external compiler directory for its behavior.
            control = Path(state["compiler_path"]).with_suffix(
                ".control.json"
            )
            if control.is_file():
                state["compiler_support_files"].append({
                    "path": control.name,
                    "absolute_path": str(control.resolve(strict=True)),
                    "sha256": byte_identity.sha256_file(control),
                })
            byte_identity.materialize_runtime_bin(
                state, arguments.build_dir
            )
            inventory = byte_identity.load_inventory(
                state, arguments.build_dir
            )
            command_inventory = byte_identity.load_command_inventory(
                state, inventory, arguments.build_dir
            )
            state["inventory"] = inventory
            state["inventory_sha256"] = byte_identity.sha256_file(
                byte_identity.inventory_path(arguments.build_dir)
            )
            state["command_inventory"] = command_inventory
            state["command_inventory_sha256"] = byte_identity.sha256_file(
                byte_identity.command_inventory_path(arguments.build_dir)
            )
            state["command_policy_sha256"] = command_inventory[
                "policy_sha256"
            ]
            state["outer_session"] = session
            held_state = (state, command_inventory, arguments.build_dir)
            return state, inventory, command_inventory, session

        def diagnostic_postflight(_arguments, before):
            return (
                before, before["inventory"],
                before["command_inventory"], session,
            )

        original_finalize = byte_identity.finalize_execution_projection

        def capture_projection_receipt(authority):
            try:
                if held_state is not None:
                    state, command_inventory, build_dir = held_state
                    byte_identity.finalize_command_snapshot_validation(
                        command_inventory["entries"], build_dir,
                        command_inventory["transport_snapshot"],
                    )
                    byte_identity.finalize_toolchain_snapshot_validation(
                        state, build_dir
                    )
                original_finalize(authority)
            except BaseException:
                # A resident failure invalidates the whole causal publication.
                # Preserve the older standalone mechanics tests' stronger local
                # cleanup assertion by retracting this diagnostic producer's
                # exact output/audit triplet before re-raising.
                if held_state is not None:
                    state, _command_inventory, build_dir = held_state
                    command = list(state["command_entry"]["argv"])
                    parsed = byte_identity.validate_compile_arguments(command)
                    cwd = Path(state["command_entry"]["directory"])
                    object_path = byte_identity.lexical_argument_path(
                        parsed["Fo"][1], cwd
                    )
                    pdb_path = byte_identity.lexical_argument_path(
                        parsed["Fd"][1], cwd
                    )
                    source_relative = state["inventory_entry"]["source"]
                    byte_identity.invalidate_build_paths([
                        object_path,
                        pdb_path,
                        byte_identity.audit_object_path(
                            build_dir, state["inventory_entry"]["target"],
                            source_relative,
                        ),
                        byte_identity.audit_unlisted_path(
                            build_dir, state["inventory_entry"]["target"],
                            source_relative,
                        ),
                    ])
                raise
            receipt = authority.execution_projection_receipt
            if receipt is not None:
                key = (
                    receipt["projection_root"],
                    receipt["projection_descriptor_sha256"],
                )
                self.diagnostic_projection_receipts[key] = json.loads(
                    json.dumps(receipt)
                )
                # Preserve the actual terminal in-memory projection record.
                # Downstream diagnostic verification runs through a fresh
                # command transaction, but models the same long-lived resident
                # authority; a disk receipt alone must never mint this state.
                self.diagnostic_projection_authorities[key] = (
                    authority.execution_projection
                )

        try:
            with (
                mock.patch.object(
                    byte_identity, "load_producer_state",
                    side_effect=diagnostic_state,
                ),
                mock.patch.object(
                    byte_identity, "validate_producer_state_postflight",
                    side_effect=diagnostic_postflight,
                ),
                mock.patch.object(
                    byte_identity, "finalize_execution_projection",
                    side_effect=capture_projection_receipt,
                ),
            ):
                yield session
        finally:
            if previous_bytes is None:
                active.unlink(missing_ok=True)
            else:
                active.write_bytes(previous_bytes)
            if previous_nonce is None:
                os.environ.pop(byte_identity.SESSION_NONCE_ENV, None)
            else:
                os.environ[byte_identity.SESSION_NONCE_ENV] = previous_nonce

    def run_standalone_producer_diagnostic(self, arguments):
        """Run one producer mechanic without creating terminal authority."""
        with self.standalone_producer_diagnostic():
            return byte_identity.main(arguments)

    @contextmanager
    def resident_verifier_diagnostic(self):
        """Bind downstream verifier tests to captured in-memory receipts.

        This is deliberately test-only. Each receipt was returned by an actual
        producer transaction and retained in this test process; production
        verification still requires the receipt held by its one resident
        authority and never trusts the last global JSON file.
        """
        def validate_captured_receipt(
            root_value, descriptor_sha_value, build_dir, context,
        ):
            descriptor_sha = byte_identity.require_sha(
                descriptor_sha_value,
                f"{context} execution projection descriptor SHA-256",
            )
            key = (root_value, descriptor_sha)
            receipt = self.diagnostic_projection_receipts.get(key)
            byte_identity.require(
                receipt is not None,
                f"{context} has no captured resident projection receipt",
            )
            projection = self.diagnostic_projection_authorities.get(key)
            byte_identity.require(
                isinstance(projection, dict),
                f"{context} has no captured resident projection authority",
            )
            byte_identity.active_build_authority().execution_projection = (
                projection
            )
            byte_identity.exact_audit_keys(
                receipt,
                byte_identity.EXECUTION_PROJECTION_FINALIZATION_KEYS,
                f"{context} captured execution projection receipt",
            )
            byte_identity.require(
                receipt["status"]
                == "EXECUTION_PROJECTION_FINALIZED_AND_REMOVED"
                and receipt["backend"] == byte_identity.selected_backend()
                and receipt["projection_root"] == root_value
                and receipt["projection_descriptor_sha256"] == descriptor_sha
                and receipt["immutable_records_sha256"]
                == receipt["terminal_immutable_records_sha256"]
                and receipt["projection_materialization_count"] == 1
                and receipt["seat_capacity"] == 1
                and receipt["lease_count"] > 0
                and receipt["writable_build_branch_empty"] is True
                and receipt["projection_removed"] is True,
                f"{context} captured execution projection receipt differs",
            )
            byte_identity.active_build_authority().assert_absent(
                Path(root_value)
            )
            return receipt

        with mock.patch.object(
            byte_identity,
            "validate_execution_projection_evidence",
            side_effect=validate_captured_receipt,
        ):
            yield

    def run_resident_verifier_diagnostic(self, arguments=None):
        """Exercise downstream verification with captured resident receipts."""
        if arguments is None:
            arguments = self.verify_args()
        with self.resident_verifier_diagnostic():
            return byte_identity.main(arguments)

    def inventory_args(self, entries=None, target_entries=None):
        if entries is None:
            entries = [
                ("fixture", path, "C" if path.name.endswith(".c") else "CXX")
                for path in sorted(self.source_dir.rglob("*"))
                if path.is_file()
                and path.name.rsplit(".", 1)[-1]
                in CMAKE_C_CXX_SOURCE_EXTENSIONS
            ]
        result = [
            "inventory",
            "--manifest", str(self.manifest),
            "--source-dir", str(self.source_dir),
            "--build-dir", str(self.build_dir),
            "--compiler", str(self.compiler),
            "--cmake-module", str(self.cmake_module),
            "--output", str(byte_identity.inventory_path(self.build_dir)),
            "--cmake-output", str(byte_identity.inventory_plan_path(self.build_dir)),
            "--policy-stamp", str(byte_identity.policy_stamp_path(self.build_dir)),
        ]
        if target_entries is None:
            target_entries = [
                (policy["target"], "NATIVE_TEST_OBJECTS_ONLY", "TRUE")
                for policy in self.document["target_policies"]
            ]
        for target_entry in target_entries:
            result.extend(["--target-entry", *target_entry])
            for property_name in byte_identity.NORMAL_TARGET_LINK_PROPERTIES:
                result.extend([
                    "--graph-count", target_entry[0], property_name, "0",
                ])
        link = self.document.get("terminal_producers", {}).get("link")
        if link is not None:
            standard = link["generator_standard_libraries"]
            result.extend([
                "--standard-library-configuration",
                standard["configuration"],
                "--standard-library-base-count", str(len(standard["base"])),
                "--standard-library-config-count",
                str(len(standard["configuration_specific"])),
            ])
            for item in standard["base"]:
                result.extend(["--standard-library-base-item", item])
            for item in standard["configuration_specific"]:
                result.extend(["--standard-library-config-item", item])
        for entry in entries:
            target, source, *language = entry
            result.extend([
                "--entry", target, str(source),
                language[0] if language else "CXX",
            ])
        return result

    def ensure_inventory(self, entries=None, target_entries=None):
        self.assertEqual(
            byte_identity.main(self.inventory_args(entries, target_entries)), 0
        )
        return json.loads(byte_identity.inventory_path(self.build_dir).read_text())

    def mock_private_macho_relocation(
        self, path, _changes, *, expected_input, install_id=None,
    ):
        """Return the causal post-transform receipt used by native fixtures."""
        del install_id
        observed = byte_identity.resident_produced_file_receipt(
            Path(path), "mock private runtime Mach-O relocation"
        )
        self.assertEqual(observed, expected_input)
        return observed

    def materialize_native_reccmp_fixture(self, state):
        """Build the native analysis snapshot in the current authority."""
        with (
            mock.patch.object(
                byte_identity, "relocate_private_macho",
                side_effect=self.mock_private_macho_relocation,
            ),
            mock.patch.object(
                byte_identity, "macho_loader_dependencies", return_value=[]
            ),
        ):
            return byte_identity.materialize_native_reccmp_snapshot(
                state, self.build_dir
            )

    def materialize_resident_projection_fixture(self, state):
        """Establish the held command/toolchain projection for native tests."""
        authority = byte_identity.active_build_authority()
        byte_identity.materialize_runtime_bin(state, self.build_dir)
        inventory = byte_identity.load_inventory(state, self.build_dir)
        state["inventory"] = inventory
        command_document = byte_identity.strict_json_loads(
            authority.read_bytes(
                byte_identity.command_inventory_path(self.build_dir)
            )
        )
        byte_identity.materialize_command_snapshot(
            state, inventory, command_document["entries"], self.build_dir
        )
        state["command_inventory"] = byte_identity.load_command_inventory(
            state, inventory, self.build_dir
        )
        return byte_identity.materialize_execution_projection(
            state, self.build_dir
        )

    def ensure_inventory_current(self):
        expected = {
            ("fixture", path.relative_to(self.source_dir).as_posix())
            for path in self.source_dir.rglob("*")
            if path.is_file()
            and path.name.rsplit(".", 1)[-1]
            in CMAKE_C_CXX_SOURCE_EXTENSIONS
        }
        path = byte_identity.inventory_path(self.build_dir)
        if path.is_file():
            try:
                inventory = json.loads(path.read_text())
                observed = {
                    (entry["target"], entry["source"])
                    for entry in inventory["entries"]
                }
                if (observed == expected
                        and inventory["manifest_sha256"]
                        == byte_identity.sha256_file(self.manifest)):
                    return inventory
            except (KeyError, TypeError, json.JSONDecodeError):
                pass
        return self.ensure_inventory()

    def plan_args(self):
        return [
            "plan",
            "--manifest", str(self.manifest),
            "--source-dir", str(self.source_dir),
            "--build-dir", str(self.build_dir),
            "--compiler", str(self.compiler),
            "--compiler-id", "MSVC",
            "--compiler-version", "10.20",
            "--generator", "Ninja",
            "--output", str(self.plan),
        ]

    def materialized_header(self):
        header_sha = self.document["translation_units"][0]["donors"][0]["recipe"][
            "generated_header_sha256"
        ]
        return byte_identity.recipe_output(
            self.build_dir, self.recipe_id, header_sha
        )

    def enable_composer_fixture(self):
        seed_bytes = make_fpo_coff()
        donor_bytes = make_fpo_coff(donor=True)
        self.seed_fixture = self.directory / "fixture-seed.obj"
        self.donor_fixture = self.directory / "fixture-donor.obj"
        self.seed_fixture.write_bytes(seed_bytes)
        self.donor_fixture.write_bytes(donor_bytes)
        header = entropy.generate_shape(1, 1).encode("utf-8")
        header_sha = digest(header)
        self.recipe_id = f"d_{header_sha[:12]}"
        unit = self.document["translation_units"][0]
        unit["mode"] = "compose_equal_linked_span_fpo"
        unit["donors"] = [
            {
                "id": self.recipe_id,
                "status": "compiler_generated_current_source",
                "authenticity": "synthetic_baseline_only",
                "recipe": {
                    "kind": "declaration_shape",
                    "classes": 1,
                    "functions": 1,
                    "generated_header_sha256": header_sha,
                    "emission_policy": "non_emitting_declarations_only",
                    "authenticity_rationale": (
                        "Framework-generated synthetic declaration-only compiler-state "
                        "input that emits no linker payload."
                    ),
                },
            }
        ]
        function = fpo_function_record(donor_bytes)
        function["donor"] = self.recipe_id
        unit["functions"] = [function]
        unit["completion"] = {
            "state": "object_composition_enabled_final_gates_incomplete",
            "reason": (
                "The fixture composes one FPO object while archive, image, "
                "reccmp, and final-MD5 gates remain incomplete."
            ),
            "may_replace_compiler_output": True,
        }
        self.write_manifest()
        return seed_bytes, donor_bytes

    def enable_authoritative_composer_fixture(self):
        """Promote the native diagnostic fixture to an outer-driver manifest."""
        result = self.enable_composer_fixture()
        self.document.pop("diagnostic_policy", None)
        self.write_manifest()
        return result

    def enable_two_composer_fixture(self):
        seed_bytes = make_two_fpo_coff()
        first_donor_bytes = make_two_fpo_coff(first_variant=True)
        second_donor_bytes = make_two_fpo_coff(
            first_variant=True, second_variant=True
        )
        self.seed_fixture = self.directory / "fixture-two-seed.obj"
        self.first_donor_fixture = self.directory / "fixture-first-donor.obj"
        self.second_donor_fixture = self.directory / "fixture-second-donor.obj"
        self.seed_fixture.write_bytes(seed_bytes)
        self.first_donor_fixture.write_bytes(first_donor_bytes)
        self.second_donor_fixture.write_bytes(second_donor_bytes)

        first_header = entropy.generate_shape(1, 1).encode("utf-8")
        second_header = entropy.generate_shape(2, 2).encode("utf-8")
        first_sha = digest(first_header)
        second_sha = digest(second_header)
        self.recipe_id = f"d_{first_sha[:12]}"
        self.second_recipe_id = f"d_{second_sha[:12]}"
        self.assertNotEqual(self.recipe_id, self.second_recipe_id)

        def donor(recipe_id, classes, functions, header_sha):
            return {
                "id": recipe_id,
                "status": "compiler_generated_current_source",
                "authenticity": "synthetic_baseline_only",
                "recipe": {
                    "kind": "declaration_shape",
                    "classes": classes,
                    "functions": functions,
                    "generated_header_sha256": header_sha,
                    "emission_policy": "non_emitting_declarations_only",
                    "authenticity_rationale": (
                        "Unused period-plausible declarations perturb compiler "
                        "state while emitting no linker contribution."
                    ),
                },
            }

        unit = self.document["translation_units"][0]
        unit["mode"] = "compose_equal_linked_span_fpo"
        unit["donors"] = [
            donor(self.recipe_id, 1, 1, first_sha),
            donor(self.second_recipe_id, 2, 2, second_sha),
        ]
        unit["functions"] = [
            two_fpo_function_record(
                first_donor_bytes,
                mangled=TARGET_SYMBOL,
                donor=self.recipe_id,
                section=1,
                seed_length=30,
                donor_length=31,
                linked_span=32,
                address="0x10001000",
            ),
            two_fpo_function_record(
                second_donor_bytes,
                mangled=SECOND_TARGET_SYMBOL,
                donor=self.second_recipe_id,
                section=4,
                seed_length=45,
                donor_length=46,
                linked_span=48,
                address="0x10001020",
            ),
        ]
        unit["completion"] = {
            "state": "object_composition_enabled_final_gates_incomplete",
            "reason": (
                "The fixture composes two ordered FPO closures while archive, "
                "image, reccmp, and final-MD5 gates remain incomplete."
            ),
            "may_replace_compiler_output": True,
        }
        self.write_manifest()
        return seed_bytes, first_donor_bytes, second_donor_bytes

    def add_shared_recipe_unit(self, name="shared.cpp"):
        shared_source = self.source.with_name(name)
        shared_source.write_text("int shared() { return 13; }\n")
        shared_unit = json.loads(
            json.dumps(self.document["translation_units"][0])
        )
        shared_unit["source"] = shared_source.relative_to(
            self.source_dir
        ).as_posix()
        shared_unit["source_sha256"] = byte_identity.sha256_file(shared_source)
        address_base = 0x10002000 + len(self.document["translation_units"]) * 0x100
        for function_index, function in enumerate(shared_unit["functions"]):
            function["retail_oracle"]["address"] = (
                f"0x{address_base + function_index * 0x20:08x}"
            )
        self.document["translation_units"].append(shared_unit)
        self.write_manifest()
        return shared_source

    def add_distinct_shape_recipe(self, unit_index=0, classes=2, functions=2):
        unit = self.document["translation_units"][unit_index]
        self.assertEqual(unit["mode"], "compose_equal_linked_span_fpo")
        header_sha = digest(
            entropy.generate_shape(classes, functions).encode("utf-8")
        )
        recipe_id = f"d_{header_sha[:12]}"
        self.assertNotEqual(recipe_id, self.recipe_id)
        unit["donors"].append(
            {
                "id": recipe_id,
                "status": "compiler_generated_current_source",
                "authenticity": "synthetic_baseline_only",
                "recipe": {
                    "kind": "declaration_shape",
                    "classes": classes,
                    "functions": functions,
                    "generated_header_sha256": header_sha,
                    "emission_policy": "non_emitting_declarations_only",
                    "authenticity_rationale": (
                        "A second unused period-plausible declaration family "
                        "tests deterministic content-addressed list handling."
                    ),
                },
            }
        )
        second_function = json.loads(json.dumps(unit["functions"][0]))
        second_function["mangled"] = "?SecondTarget@@YAXXZ"
        second_function["donor"] = recipe_id
        second_function["expected_section_number"] = (
            max(function["expected_section_number"] for function in unit["functions"])
            + 1
        )
        second_function["retail_oracle"]["address"] = "0x10001020"
        unit["functions"].append(second_function)
        self.write_manifest()
        return recipe_id, header_sha

    def materialize(self):
        output = self.materialized_header()
        return self.materialize_recipe(self.recipe_id, output)

    def materialize_recipe(self, recipe_id, output):
        result = byte_identity.main(
            [
                "materialize",
                "--manifest", str(self.manifest),
                "--source-dir", str(self.source_dir),
                "--build-dir", str(self.build_dir),
                "--recipe-id", recipe_id,
                "--output", str(output),
            ]
        )
        self.assertEqual(result, 0)
        return output

    def configure_fixture(
        self, source_names, build_name, *, before_enable=(), extra_targets=(),
        after_enable=(),
    ):
        fixture_tools = self.source_dir / "tools"
        fixture_cmake = self.source_dir / "cmake"
        fixture_cmake.mkdir(exist_ok=True)
        shutil.copy2(TOOLS / "byte_identity.py", fixture_tools / "byte_identity.py")
        shutil.copy2(
            TOOLS / "byte_identity_backend.py",
            fixture_tools / "byte_identity_backend.py",
        )
        shutil.copy2(TOOLS / "entropy.py", fixture_tools / "entropy.py")
        shutil.copy2(
            ROOT / "cmake/byte_identity.cmake",
            fixture_cmake / "byte_identity.cmake",
        )
        cmake_lines = [
            "cmake_minimum_required(VERSION 3.19 FATAL_ERROR)",
            "set(CMAKE_EXPORT_COMPILE_COMMANDS ON)",
            'set(CMAKE_SYSTEM_NAME "Generic")',
            'set(CMAKE_TRY_COMPILE_TARGET_TYPE "STATIC_LIBRARY")',
            'set(CMAKE_OSX_ARCHITECTURES "" CACHE STRING "" FORCE)',
            "project(byte_identity_native_fixture C CXX)",
            f'add_library(fixture STATIC {" ".join(source_names)})',
            'target_compile_options(fixture PRIVATE '
            '"/FI${PROJECT_SOURCE_DIR}/include/pinned.h")',
            *extra_targets,
            "set(ISLE_BYTE_IDENTICAL ON)",
            "set(ISLE_PER_OBJECT_PDB ON)",
            f"set(CMAKE_BUILD_TYPE {byte_identity.RESIDENT_CMAKE_BUILD_TYPE})",
            'set(CMAKE_C_FLAGS "")',
            'set(CMAKE_CXX_FLAGS "")',
            'set(CMAKE_DEPFILE_FLAGS_C "")',
            'set(CMAKE_DEPFILE_FLAGS_CXX "")',
            'set(CMAKE_C_DEPENDS_USE_COMPILER FALSE)',
            'set(CMAKE_CXX_DEPENDS_USE_COMPILER FALSE)',
            'set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "/Zi /O2 /D NDEBUG")',
            'set(CMAKE_CXX_COMPILE_OBJECT "<CMAKE_CXX_COMPILER>  /nologo /TP '
            '<DEFINES> <INCLUDES> <FLAGS> /Fo<OBJECT> /Fd<OBJECT>.pdb '
            '-c <SOURCE>")',
            "set(ISLE_INCLUDE_ENTROPY OFF)",
            'set(ISLE_TU_ENTROPY_MANIFEST "")',
            "set(MSVC_FOR_DECOMP TRUE)",
            f'set(CMAKE_C_COMPILER "{self.compiler}")',
            f'set(CMAKE_CXX_COMPILER "{self.compiler}")',
            'set(CMAKE_C_COMPILER_ID "MSVC")',
            'set(CMAKE_CXX_COMPILER_ID "MSVC")',
            'set(CMAKE_C_COMPILER_VERSION "10.20")',
            'set(CMAKE_CXX_COMPILER_VERSION "10.20")',
            'set(CMAKE_C_FLAGS_RELWITHDEBINFO "/Zi /O2 /D NDEBUG")',
            'set(CMAKE_C_COMPILE_OBJECT "<CMAKE_C_COMPILER>  /nologo '
            '<DEFINES> <INCLUDES> <FLAGS> /Fo<OBJECT> /Fd<OBJECT>.pdb '
            '-c <SOURCE>")',
            *before_enable,
            'include("${PROJECT_SOURCE_DIR}/cmake/byte_identity.cmake")',
            "isle_enable_byte_identity(",
            '  "${PROJECT_SOURCE_DIR}/tools/byte_identity_manifest.json")',
            *after_enable,
            "",
        ]
        (self.source_dir / "CMakeLists.txt").write_text(
            "\n".join(
                cmake_lines
            )
        )
        cmake_build = self.directory / build_name
        generator = "Ninja" if shutil.which("ninja") else "Unix Makefiles"
        result = subprocess.run(
            [
                "cmake", "-S", str(self.source_dir), "-B", str(cmake_build),
                "-G", generator,
            ],
            capture_output=True,
            text=True,
        )
        return cmake_build, result

    def configure_and_materialize(self, source_names, build_name):
        cmake_build, result = self.configure_fixture(source_names, build_name)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        build_result = subprocess.run(
            [
                "cmake", "--build", str(cmake_build), "--target",
                "byte-identity-materialize",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            build_result.returncode,
            0,
            build_result.stdout + build_result.stderr,
        )
        return cmake_build

    def assert_cmake_configure_rejected(
        self, *, build_name, before_enable=(), extra_targets=(),
        after_enable=(), expected
    ):
        _, result = self.configure_fixture(
            ["src/unit.cpp"],
            build_name,
            before_enable=before_enable,
            extra_targets=extra_targets,
            after_enable=after_enable,
        )
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0, output)
        self.assertIn(expected, output)

    def launch_args(
        self, output, pdb, *, source=None, target="fixture",
        force_include=None, ensure_inventory=True
    ):
        if ensure_inventory:
            self.ensure_inventory_current()
        if source is None:
            source = self.source
        if force_include is None:
            force_include = self.include
        result = [
            "compile-launch",
            "--manifest", str(self.manifest),
            "--source-dir", str(self.source_dir),
            "--build-dir", str(self.build_dir),
            "--target", target,
            "--configured-compiler", str(self.compiler),
            "--",
            str(self.compiler),
            "/Zi",
            "/O2",
            "/D", "NDEBUG",
            f"/FI{force_include}",
            f"/Fo{output}",
            f"/Fd{pdb}",
            "-c",
            str(source),
        ]
        if ensure_inventory:
            self.attest_command(result)
        return result

    def attest_command(self, launch_arguments, *, directory=None):
        separator = launch_arguments.index("--")
        child = launch_arguments[separator + 1:]
        parsed = byte_identity.validate_compile_arguments(child)
        source = Path(parsed["source_token"]).resolve()
        target = launch_arguments[launch_arguments.index("--target") + 1]
        source_relative = source.relative_to(self.source_dir).as_posix()
        self.attested_commands[(target, source_relative)] = child
        if directory is not None:
            self.attested_directories[(target, source_relative)] = Path(directory)
        inventory = json.loads(
            byte_identity.inventory_path(self.build_dir).read_text()
        )
        policies = {
            item["target"]: item for item in self.document["target_policies"]
        }
        database = []
        for entry in inventory["entries"]:
            owner = (entry["target"], entry["source"])
            command = self.attested_commands.get(owner)
            if command is None:
                fallback_object = (
                    self.build_dir / "CMakeFiles" / f"{entry['target']}.dir"
                    / f"{entry['source']}.obj"
                )
                command = [
                    str(self.compiler), "/Zi", "/O2", "/D", "NDEBUG"
                ]
                if entry["language"] == "CXX":
                    command.append("/TP")
                for include in policies[entry["target"]]["allowed_force_includes"]:
                    command.append(f"/FI{self.source_dir / include['path']}")
                command.extend([
                    f"/Fo{fallback_object}", f"/Fd{fallback_object}.pdb",
                    "-c", entry["source_path"],
                ])
                self.attested_commands[owner] = command
            command_parsed = byte_identity.validate_compile_arguments(command)
            command_output = byte_identity.lexical_argument_path(
                command_parsed["Fo"][1], self.build_dir
            )
            database.append(
                {
                    "directory": str(
                        self.attested_directories.get(owner, self.build_dir)
                    ),
                    "command": shlex.join(command),
                    "file": entry["source_path"],
                    "output": str(command_output),
                }
            )
        compile_commands = self.build_dir / "compile_commands.json"
        compile_commands.write_text(json.dumps(database, indent=2) + "\n")
        result = byte_identity.main(
            [
                "attest-commands",
                "--manifest", str(self.manifest),
                "--source-dir", str(self.source_dir),
                "--build-dir", str(self.build_dir),
                "--compiler", str(self.compiler),
                "--compile-commands", str(compile_commands),
                "--output", str(byte_identity.command_inventory_path(self.build_dir)),
                "--policy-stamp", str(byte_identity.command_policy_stamp_path(self.build_dir)),
            ]
        )
        self.assertEqual(result, 0)

    def launcher_process_args(self, source, output, pdb):
        result = [
            sys.executable,
            str(TOOLS / "byte_identity.py"),
            "compile-launch",
            "--manifest", str(self.manifest),
            "--source-dir", str(self.source_dir),
            "--build-dir", str(self.build_dir),
            "--target", "fixture",
            "--configured-compiler", str(self.compiler),
            "--",
            str(self.compiler),
            "/Zi",
            "/O2",
            "/D", "NDEBUG",
            f"/FI{self.include}",
            f"/Fo{output}",
            f"/Fd{pdb}",
            "-c",
            str(source),
        ]
        self.ensure_inventory_current()
        self.attest_command(result[2:])
        return result

    def verify_args(self):
        return [
            "verify",
            "--manifest", str(self.manifest),
            "--source-dir", str(self.source_dir),
            "--build-dir", str(self.build_dir),
            "--compiler", str(self.compiler),
        ]

    def complete_args(self):
        result = self.verify_args()
        result[0] = "complete"
        return result

    def enable_final_image_fixture(self):
        original = self.source_dir / "legobin/LEGO1.DLL"
        original.parent.mkdir(parents=True, exist_ok=True)
        image_bytes = b"MZ" + bytes(range(256)) * 4
        original.write_bytes(image_bytes)
        rows = []
        for index in range(4933):
            address = f"0x{0x10001000 + index * 0x10:08x}"
            row = {
                "address": address,
                "name": f"FixtureRow{index:04d}",
                "matching": 1.0,
                "recomp": address,
                "type": 1 if index < 4487 else 5,
            }
            if index == 17:
                row["effective"] = True
            rows.append(row)
        identity_bytes = (
            "\n".join(
                json.dumps(
                    [row["address"], row["name"], row["type"]],
                    separators=(",", ":"),
                    ensure_ascii=True,
                )
                for row in rows
            ) + "\n"
        ).encode("utf-8")
        accepted_bytes = (
            "\n".join(
                json.dumps(
                    [row["address"], row["name"], row["type"]],
                    separators=(",", ":"),
                    ensure_ascii=True,
                )
                for row in rows[:4816]
            ) + "\n"
        ).encode("utf-8")
        self.document["images"] = {
            "LEGO1": {
                "kind": "final_image_identity_gate",
                "target": "lego1",
                "original": "legobin/LEGO1.DLL",
                "original_sha256": digest(image_bytes),
                "original_md5": byte_identity.md5_bytes(image_bytes),
                "original_size": len(image_bytes),
                "recompiled": "LEGO1.DLL",
                "reccmp_report": "byte-identity/final/LEGO1.json",
                "reccmp_schema": "reccmp_json_diet_exact_rows_v1",
                "required_row_count": 4933,
                "row_identity_sha256": digest(identity_bytes),
                "iteration_baseline": {
                    "state": "accepted_raw_score_set_pinned_v1",
                    "exact_raw_1_0_count": 4816,
                    "accepted_row_identity_sha256": digest(accepted_bytes),
                    "require_zero_losses": True,
                },
                "completion": {
                    "state": "required_for_byte_identity_complete",
                    "require_all_rows_raw_1_0": True,
                    "require_recompiled_md5_equal_original": True,
                    "require_recompiled_sha256_equal_original": True,
                    "require_recompiled_address_equal_retail": True,
                },
            }
        }
        self.enable_terminal_producer_fixture()
        self.write_manifest()
        image_output = self.build_dir / "LEGO1.DLL"
        image_output.write_bytes(image_bytes)
        report = byte_identity.final_report_path(self.build_dir, "LEGO1")
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps({
            "file": "LEGO1.DLL",
            "format": 1,
            "timestamp": 1.0,
            "data": rows,
        }, separators=(",", ":")) + "\n")
        return original, image_output, report, rows

    def enable_terminal_producer_fixture(self):
        reccmp_executable = self.directory / "fake-reccmp"
        reccmp_interpreter = self.directory / "fake-reccmp-interpreter"
        private_app = self.directory / "fake-private-python-app"
        private_framework = self.directory / "fake-private-Python"
        private_dylib = self.directory / "fake-private-libfixture.dylib"
        for path, data, mode in (
            (reccmp_executable, b"#!/bin/sh\nexit 0\n", 0o755),
            (reccmp_interpreter, b"#!/bin/sh\nexit 0\n", 0o755),
            (private_app, b"fixture private Python app\n", 0o755),
            (private_framework, b"fixture private Python framework\n", 0o644),
            (private_dylib, b"fixture private dylib\n", 0o644),
        ):
            path.write_bytes(data)
            path.chmod(mode)
        self.fake_reccmp_closure = self.directory / "fake-reccmp-closure"
        self.fake_reccmp_closure.mkdir()
        (self.fake_reccmp_closure / "runtime.dat").write_text(
            "pinned fixture reccmp closure\n"
        )
        (self.fake_reccmp_closure / "ambient-escape.pth").write_text(
            "import os; open(os.environ['PTH_MARKER'], 'w').write('escaped')\n"
        )
        self.fake_reccmp_source = self.directory / "fake-reccmp-source"
        self.fake_reccmp_source.mkdir()
        (self.fake_reccmp_source / "__init__.py").write_text(
            "PRIVATE_RECCMP_FIXTURE = True\n"
        )
        (self.fake_reccmp_source / "types.py").write_text(
            "raise RuntimeError('package-local types shadowed stdlib')\n"
        )
        tool_roles = (
            "link_wrapper", "link_binary", "lib_wrapper", "lib_binary",
            "rc_wrapper", "rc_binary",
        )
        tools = []
        for role in tool_roles:
            name = role.split("_", 1)[0]
            if role.endswith("_wrapper"):
                path = self.msvc_wrappers[name]
            else:
                path = self.directory / f"bin/{name.upper()}.EXE"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(("fixture " + role + "\n").encode("ascii"))
                path.chmod(0o644)
            tools.append({
                "role": role,
                "path": path.relative_to(self.directory).as_posix(),
                "sha256": byte_identity.sha256_file(path),
            })
        producer_support = []
        for name, roles in (
            ("fake-resource-support.dll", ["resource"]),
            ("fake-archive-support.exe", ["archive"]),
            ("fake-archive-link-support.err", ["archive", "link"]),
        ):
            path = self.directory / name
            path.write_bytes(("pinned " + name + "\n").encode("ascii"))
            path.chmod(0o444)
            producer_support.append({
                "path": name,
                "sha256": byte_identity.sha256_file(path),
                "roles": roles,
            })
        self.document["toolchain"]["producer_support_files"] = (
            producer_support
        )
        library_trees = []
        for role, relative in (("msvc_lib", "fake-lib"),
                               ("mfc_lib", "fake-mfc-lib")):
            root = self.directory / relative
            root.mkdir()
            (root / f"{role}.lib").write_bytes(b"!<arch>\nFIXTURE")
            snapshot = byte_identity.canonical_tree_snapshot(
                root, hash_files=True
            )
            library_trees.append({
                "role": role, "path": relative,
                "entry_count": snapshot["entry_count"],
                "max_depth": snapshot["max_depth"],
                "membership_sha256": snapshot["membership_sha256"],
                "content_sha256": snapshot["content_sha256"],
            })
        archive_records = []
        for identity, source, imported in (
            ("SmartHeap", "3rdparty/smartheap/SHLW32MT.LIB",
             "SmartHeap::SmartHeap"),
            ("Smacker", "3rdparty/smacker/smackw32.lib",
             "Smacker::Smacker"),
        ):
            path = self.source_dir / source
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(make_third_party_archive(identity))
            archive_records.append({
                "kind": "third_party_reconstructed_archive",
                "identity": identity,
                "source": source,
                "source_sha256": byte_identity.sha256_file(path),
                "payload_policy": byte_identity.THIRD_PARTY_RETAIL_ARCHIVE_POLICY,
                "imported_target": imported,
                "link_contract": [{
                    "target": "fixture",
                    "direct_link_sequence": [imported, "libcmt"],
                    "occurrences": 1,
                }],
                "completion": {
                    "state": "authorized_exact_archive_materialization_enabled",
                    "reason": "Exact named third-party fixture archive.",
                    "may_supply_linker_payload": True,
                },
            })
        closure = byte_identity.canonical_tree_snapshot(
            self.fake_reccmp_closure, hash_files=True
        )
        source_closure = byte_identity.canonical_tree_snapshot(
            self.fake_reccmp_source, hash_files=True
        )
        project_sdk_libraries = []
        for relative in sorted(byte_identity.REQUIRED_PROJECT_SDK_LIBRARIES):
            path = self.source_dir / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"!<arch>\nFIXTURE-DX5-" + path.name.encode("ascii"))
            project_sdk_libraries.append({
                "path": relative,
                "sha256": byte_identity.sha256_file(path),
            })
        for relative in (
            "3rdparty/dx5/inc", "3rdparty/smacker", "3rdparty/smartheap",
            "3rdparty/vec",
        ):
            (self.source_dir / relative).mkdir(parents=True, exist_ok=True)
        (self.source_dir / "3rdparty/smartheap/SMRTHEAP.HPP").write_text(
            "// fixture\n"
        )
        empty_surfaces = {
            name: [] for name in byte_identity.IMPORTED_TARGET_INTERFACE_PROPERTIES
        }
        imported_targets = []
        for name, target_type, location, include, options, link_dirs in (
            (
                "DirectX5::DirectX5", "INTERFACE_LIBRARY", None,
                "<SOURCE_ROOT>/3rdparty/dx5/inc", [],
                ["<SOURCE_ROOT>/3rdparty/dx5/lib"],
            ),
            (
                "Smacker::Smacker", "STATIC_LIBRARY",
                "<SOURCE_ROOT>/3rdparty/smacker/smackw32.lib",
                "<SOURCE_ROOT>/3rdparty/smacker", [], [],
            ),
            (
                "SmartHeap::SmartHeap", "STATIC_LIBRARY",
                "<SOURCE_ROOT>/3rdparty/smartheap/SHLW32MT.LIB",
                "<SOURCE_ROOT>/3rdparty/smartheap",
                ["/FI<SOURCE_ROOT>/3rdparty/smartheap/SMRTHEAP.HPP"], [],
            ),
            (
                "Vec::Vec", "INTERFACE_LIBRARY", None,
                "<SOURCE_ROOT>/3rdparty/vec", [], [],
            ),
        ):
            properties = {key: list(value) for key, value in empty_surfaces.items()}
            properties["INTERFACE_INCLUDE_DIRECTORIES"] = [include]
            properties["INTERFACE_COMPILE_OPTIONS"] = options
            properties["INTERFACE_LINK_DIRECTORIES"] = link_dirs
            imported_targets.append({
                "name": name, "type": target_type, "global": False,
                "location": location, "properties": properties,
            })
        self.document["archives"] = archive_records
        self.document["terminal_producers"] = {
            "link": {
                "schema": "msvc42_dual_link_map_pdb_v1",
                "tools": tools,
                "library_trees": library_trees,
                "project_sdk_libraries": project_sdk_libraries,
                "imported_targets": imported_targets,
                "release_required_options": ["/MAP", "/VERBOSE:LIB"],
                "analysis_added_options": ["/DEBUG"],
                "generator_standard_libraries": {
                    "configuration": "RelWithDebInfo",
                    "base": ["libcmt.lib"],
                    "configuration_specific": [],
                },
                "verified_nonterminal_leaf_audits": [],
                "ordered_library_occurrence_count": 1,
                "ordered_library_identity_sha256": digest(b"libcmt.lib\n"),
                "map_evidence": [
                    {"symbol": "??3@YAXPAX@Z", "address": "0x10086260",
                     "library": "SHLW32MT.LIB", "member": "shnew.obj"},
                    {"symbol": "_SmackGetSizeDeltas", "address": "0x100d1f2c",
                     "library": "smackw32.lib", "member": "smackw32.obj"},
                    {"symbol": "_strstr", "address": "0x100d21f0",
                     "library": "libcmt.lib", "member": "strstr.obj"},
                ],
                "member_evidence": [
                    {"symbol": "??3@YAXPAX@Z", "referenced_in": "unit.cpp.obj",
                     "library": "SHLW32MT.LIB", "member": "shnew.obj"},
                    {"symbol": "_SmackGetSizeDeltas",
                     "referenced_in": "fixture.lib(unit.cpp.obj)",
                     "library": "smackw32.lib", "member": "smackw32.obj"},
                    {"symbol": "_strstr",
                     "referenced_in": "fixture.lib(unit.cpp.obj)",
                     "library": "libcmt.lib", "member": "strstr.obj"},
                ],
                "max_child_seconds": 3,
            },
            "reccmp": {
                "schema": "reccmp_paths_json_diet_producer_v1",
                "executable": str(reccmp_executable),
                "executable_sha256": byte_identity.sha256_file(
                    reccmp_executable
                ),
                "interpreter": str(reccmp_interpreter),
                "interpreter_sha256": byte_identity.sha256_file(
                    reccmp_interpreter
                ),
                "private_runtime": {
                    "schema": "darwin_relocated_cpython312_v1",
                    "app_binary": str(private_app),
                    "app_binary_sha256": byte_identity.sha256_file(private_app),
                    "framework_dylib": str(private_framework),
                    "framework_dylib_sha256": byte_identity.sha256_file(
                        private_framework
                    ),
                    "stdlib": {
                        "path": str(self.fake_reccmp_closure),
                        "entry_count": closure["entry_count"],
                        "max_depth": closure["max_depth"],
                        "membership_sha256": closure["membership_sha256"],
                        "content_sha256": closure["content_sha256"],
                    },
                    "external_dylibs": [{
                        "path": str(private_dylib),
                        "private_name": "libfixture.dylib",
                        "sha256": byte_identity.sha256_file(
                            private_dylib
                        ),
                        "install_names": [str(private_dylib)],
                    }],
                },
                "closure_roots": [
                    {
                        "role": "reccmp_source",
                        "path": str(self.fake_reccmp_source),
                        "entry_count": source_closure["entry_count"],
                        "max_depth": source_closure["max_depth"],
                        "membership_sha256": source_closure[
                            "membership_sha256"
                        ],
                        "content_sha256": source_closure["content_sha256"],
                    },
                    {
                        "role": "reccmp_environment",
                        "path": str(self.fake_reccmp_closure),
                        "entry_count": closure["entry_count"],
                        "max_depth": closure["max_depth"],
                        "membership_sha256": closure["membership_sha256"],
                        "content_sha256": closure["content_sha256"],
                    },
                ],
                "argv_template": [
                    "--paths", "<ORIGINAL>", "<IMAGE>", "<PDB>",
                    "<SOURCE_ROOT>", "--json", "<REPORT>", "--json-diet",
                    "--print-rec-addr", "--silent",
                ],
                "max_child_seconds": 3,
            },
        }

    def test_plan_and_materialize_are_deterministic(self):
        self.assertEqual(byte_identity.main(self.plan_args()), 0)
        first = self.plan.read_bytes()
        first_mtime = self.plan.stat().st_mtime_ns
        time.sleep(0.01)
        self.assertEqual(byte_identity.main(self.plan_args()), 0)
        self.assertEqual(self.plan.read_bytes(), first)
        self.assertEqual(self.plan.stat().st_mtime_ns, first_mtime)
        output = self.materialize()
        expected = self.document["translation_units"][0]["donors"][0]["recipe"][
            "generated_header_sha256"
        ]
        self.assertEqual(byte_identity.sha256_file(output), expected)
        self.assertIn("planned_not_composed", self.plan.read_text())

    def test_retail_payload_exception_is_exactly_smartheap_or_smacker_archive(self):
        smartheap = self.source_dir / "3rdparty/smartheap/SHLW32MT.LIB"
        smartheap.parent.mkdir(parents=True)
        smartheap.write_bytes(make_third_party_archive("SmartHeap"))
        record = {
            "kind": "third_party_reconstructed_archive",
            "identity": "SmartHeap",
            "source": "3rdparty/smartheap/SHLW32MT.LIB",
            "source_sha256": byte_identity.sha256_file(smartheap),
            "payload_policy": byte_identity.THIRD_PARTY_RETAIL_ARCHIVE_POLICY,
            "imported_target": "SmartHeap::SmartHeap",
            "link_contract": [
                {
                    "target": "fixture",
                    "direct_link_sequence": [
                        "SmartHeap::SmartHeap", "libcmt",
                    ],
                    "occurrences": 1,
                }
            ],
            "completion": {
                "state": "authorized_exact_archive_materialization_enabled",
                "reason": (
                    "The named third-party exception is copied byte-exactly "
                    "into the held build authority before linker consumption."
                ),
                "may_supply_linker_payload": True,
            },
        }
        self.document["archives"] = [record]
        self.write_manifest()
        state = byte_identity.validate_manifest(
            self.manifest,
            self.source_dir,
            self.build_dir,
            configured_compiler=str(self.compiler),
            compiler_id="MSVC",
            compiler_version="10.20",
            generator="Ninja",
        )
        self.assertEqual(state["archives"][0]["identity"], "SmartHeap")
        self.assertEqual(
            state["archives"][0]["source_size"], smartheap.stat().st_size
        )

        self.assertEqual(byte_identity.main(self.plan_args()), 0)
        rendered_plan = self.plan.read_text()
        self.assertIn('ISLE_BYTE_IDENTITY_ARCHIVE_0_IDENTITY "SmartHeap"', rendered_plan)
        self.assertIn(
            'ISLE_BYTE_IDENTITY_ARCHIVE_0_IMPORTED_TARGET "SmartHeap::SmartHeap"',
            rendered_plan,
        )
        archive_output = Path(state["archives"][0]["output"])
        self.assertEqual(
            byte_identity.main([
                "materialize-archive",
                "--manifest", str(self.manifest),
                "--source-dir", str(self.source_dir),
                "--build-dir", str(self.build_dir),
                "--identity", "SmartHeap",
                "--output", str(archive_output),
            ]),
            0,
        )
        self.assertEqual(archive_output.read_bytes(), smartheap.read_bytes())
        archive_audit = json.loads(
            byte_identity.archive_audit_path(
                self.build_dir, "SmartHeap"
            ).read_text()
        )
        self.assertEqual(
            archive_audit["copy_policy"],
            "byte_exact_independent_build_authority_copy_v1",
        )
        self.assertEqual(archive_audit["link_contract"], record["link_contract"])

        mutations = [
            ("kind", "retail_object_copy"),
            ("identity", "FirstParty"),
            ("source", "LEGO1/first-party.lib"),
            ("payload_policy", "retail_bytes_allowed"),
            ("imported_target", "FirstParty::FirstParty"),
            ("completion.may_supply_linker_payload", False),
        ]
        for field, replacement in mutations:
            with self.subTest(field=field):
                candidate = json.loads(json.dumps(record))
                if field.startswith("completion."):
                    candidate["completion"][field.split(".", 1)[1]] = replacement
                else:
                    candidate[field] = replacement
                self.document["archives"] = [candidate]
                self.write_manifest()
                with self.assertRaises(byte_identity.ByteIdentityError):
                    byte_identity.validate_manifest(
                        self.manifest,
                        self.source_dir,
                        self.build_dir,
                        configured_compiler=str(self.compiler),
                        compiler_id="MSVC",
                        compiler_version="10.20",
                        generator="Ninja",
                    )

        self.document["archives"] = [record]
        self.write_manifest()
        verdict = self.build_dir / "byte-identity/audit/framework-verdict.json"
        verdict.parent.mkdir(parents=True, exist_ok=True)
        verdict.write_text('{"stale":true}\n')
        smartheap.write_bytes(smartheap.read_bytes() + b"CHANGED")
        self.assertEqual(
            byte_identity.main([
                "materialize-archive",
                "--manifest", str(self.manifest),
                "--source-dir", str(self.source_dir),
                "--build-dir", str(self.build_dir),
                "--identity", "SmartHeap",
                "--output", str(archive_output),
            ]),
            2,
        )
        self.assertFalse(archive_output.exists())
        self.assertFalse(
            byte_identity.archive_audit_path(
                self.build_dir, "SmartHeap"
            ).exists()
        )
        self.assertFalse(verdict.exists())

    def test_smartheap_directive_pin_preserves_one_trailing_space(self):
        raw = byte_identity.SMARTHEAP_DIRECTIVE_MEMBERS["iowinapi.obj"]
        self.assertEqual(raw, b"-defaultlib:user32.lib ")
        self.assertEqual(len(raw), 23)
        self.assertEqual(
            raw.hex(),
            "2d64656661756c746c69623a7573657233322e6c696220",
        )
        archive = make_third_party_archive("SmartHeap")
        byte_identity.validate_third_party_archive_directives(
            "SmartHeap", archive, "SmartHeap exact directive fixture"
        )
        loaded, member = byte_identity._archive_directive_for_loaded_member(
            data=archive,
            member="iowinapi.obj",
            role="authorized_third_party_archive",
            identity="SmartHeap",
            context="SmartHeap loaded-member fixture",
        )
        self.assertEqual(member, "iowinapi.obj")
        self.assertEqual(loaded, raw)

        for label, candidate in (
            ("missing", b"-defaultlib:user32.lib"),
            ("double", b"-defaultlib:user32.lib  "),
        ):
            with self.subTest(trailing_space=label):
                mismatched = b"!<arch>\n" + make_archive_member(
                    "iowinapi.obj", make_directive_coff(candidate)
                )
                with self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "exact archive-member .drectve allowlist differs",
                ):
                    byte_identity.validate_third_party_archive_directives(
                        "SmartHeap", mismatched,
                        f"SmartHeap {label}-space fixture",
                    )
                with self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "directive differs from its exact allowlist",
                ):
                    byte_identity._archive_directive_for_loaded_member(
                        data=mismatched,
                        member="iowinapi.obj",
                        role="authorized_third_party_archive",
                        identity="SmartHeap",
                        context=f"SmartHeap loaded {label}-space fixture",
                    )

    def test_cmake_materializes_archive_and_attests_direct_link_sequence(self):
        smartheap = self.source_dir / "3rdparty/smartheap/SHLW32MT.LIB"
        smartheap.parent.mkdir(parents=True)
        smartheap.write_bytes(make_third_party_archive("SmartHeap"))
        self.document["archives"] = [{
            "kind": "third_party_reconstructed_archive",
            "identity": "SmartHeap",
            "source": "3rdparty/smartheap/SHLW32MT.LIB",
            "source_sha256": digest(smartheap.read_bytes()),
            "payload_policy": byte_identity.THIRD_PARTY_RETAIL_ARCHIVE_POLICY,
            "imported_target": "SmartHeap::SmartHeap",
            "link_contract": [{
                "target": "fixture",
                "direct_link_sequence": ["SmartHeap::SmartHeap", "libcmt"],
                "occurrences": 1,
            }],
            "completion": {
                "state": "authorized_exact_archive_materialization_enabled",
                "reason": (
                    "The fixture authorizes only this byte-exact archive copy "
                    "and its declared direct linker sequence."
                ),
                "may_supply_linker_payload": True,
            },
        }]
        self.write_manifest()
        cmake_build, configure = self.configure_fixture(
            ["src/unit.cpp"],
            "cmake-archive-contract",
            extra_targets=(
                "add_library(SmartHeap::SmartHeap STATIC IMPORTED GLOBAL)",
                (
                    'set_property(TARGET SmartHeap::SmartHeap PROPERTY '
                    f'IMPORTED_LOCATION "{smartheap}")'
                ),
                (
                    "target_link_libraries(fixture PRIVATE "
                    "SmartHeap::SmartHeap libcmt)"
                ),
            ),
        )
        self.assertEqual(
            configure.returncode, 0, configure.stdout + configure.stderr
        )
        materialize = subprocess.run(
            [
                "cmake", "--build", str(cmake_build), "--target",
                "byte-identity-materialize",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            materialize.returncode, 0, materialize.stdout + materialize.stderr
        )
        copied = byte_identity.archive_output(
            cmake_build, "SmartHeap", "3rdparty/smartheap/SHLW32MT.LIB"
        )
        self.assertEqual(copied.read_bytes(), smartheap.read_bytes())
        self.assertTrue(
            byte_identity.archive_audit_path(
                cmake_build, "SmartHeap"
            ).is_file()
        )
        self.document["archives"][0]["link_contract"][0]["occurrences"] = 2
        self.write_manifest()
        _, rejected = self.configure_fixture(
            ["src/unit.cpp"],
            "cmake-archive-contract-rejected",
            extra_targets=(
                "add_library(SmartHeap::SmartHeap STATIC IMPORTED GLOBAL)",
                (
                    'set_property(TARGET SmartHeap::SmartHeap PROPERTY '
                    f'IMPORTED_LOCATION "{smartheap}")'
                ),
                (
                    "target_link_libraries(fixture PRIVATE "
                    "SmartHeap::SmartHeap libcmt)"
                ),
            ),
        )
        self.assertNotEqual(rejected.returncode, 0)
        rejection_output = rejected.stdout + rejected.stderr
        self.assertIn("occurs 1 times", rejection_output)
        self.assertIn("requires 2", rejection_output)

    def test_outer_driver_bootstraps_configure_and_rejects_injected_verdict(self):
        self.enable_authoritative_composer_fixture()
        fake_cmake = self.make_fake_cmake_install("fake-cmake-install")
        base = [
            "drive-cmake",
            "--source-dir", str(self.source_dir),
            "--build-dir", str(self.build_dir),
            "--cmake", str(fake_cmake),
            "--compiler", str(self.compiler),
            "--max-seconds", "15",
        ]
        environment = {
            "FAKE_BYTE_IDENTITY_FRAMEWORK": str(TOOLS / "byte_identity.py"),
            "FAKE_BYTE_IDENTITY_BACKEND_TOOL": str(
                TOOLS / "byte_identity_backend.py"
            ),
        }
        previous = {key: os.environ.get(key) for key in environment}
        os.environ.update(environment)
        try:
            self.assertEqual(
                byte_identity.main([*base, "--mode", "configure"]), 0
            )
            snapshots = list(
                (self.build_dir / "byte-identity/controller-snapshots").glob(
                    "*/snapshot.json"
                )
            )
            self.assertEqual(len(snapshots), 1)
            controller = json.loads(snapshots[0].read_text())
            trusted = controller["trusted_controller_inputs"]
            self.assertEqual(
                trusted["model"], byte_identity.CONTROLLER_TRUST_MODEL
            )
            self.assertTrue(trusted["python_runtime_files"])
            if sys.platform == "darwin":
                loader_files = {
                    str(Path(item).resolve())
                    for item in trusted["python_loader_dependencies"]
                    if item.startswith("/") and Path(item).is_file()
                    and not item.startswith(("/usr/lib/", "/System/"))
                }
                self.assertTrue(loader_files)
                self.assertLessEqual(
                    {
                        str(Path(record["path"]).resolve())
                        for record in trusted["python_runtime_files"]
                    },
                    loader_files,
                )
            pristine_descriptor = snapshots[0].read_bytes()
            for label, mutate in (
                (
                    "zero-runtime-hash",
                    lambda value: value["trusted_controller_inputs"][
                        "python_runtime_files"
                    ][0].__setitem__("sha256", "0" * 64),
                ),
                (
                    "nonexistent-runtime-path",
                    lambda value: value["trusted_controller_inputs"][
                        "python_runtime_files"
                    ][0].__setitem__(
                        "path", str(self.directory / "absent-python-runtime")
                    ),
                ),
            ):
                with self.subTest(controller_descriptor=label):
                    candidate = json.loads(pristine_descriptor)
                    mutate(candidate)
                    encoded = (
                        json.dumps(candidate, indent=2, sort_keys=True) + "\n"
                    ).encode("utf-8")
                    snapshots[0].write_bytes(encoded)
                    try:
                        with byte_identity.build_transaction(
                            self.build_dir,
                            exclusive=True,
                            bootstrap_outer_session=True,
                        ) as authority:
                            with self.assertRaises(
                                (byte_identity.ByteIdentityError, OSError)
                            ):
                                byte_identity.load_controller_snapshot(
                                    authority,
                                    snapshots[0].parent,
                                    digest(encoded),
                                )
                    finally:
                        snapshots[0].write_bytes(pristine_descriptor)
            self.assertFalse(
                byte_identity.active_session_path(self.build_dir).exists()
            )
            verdict = (
                self.build_dir / "byte-identity/audit/framework-verdict.json"
            )
            self.assertEqual(
                byte_identity.main(
                    [*base, "--mode", "configure", "--", "--fail"]
                ),
                2,
            )
            self.assertFalse(verdict.exists())
            self.assertFalse(
                byte_identity.active_session_path(self.build_dir).exists()
            )
            self.assertFalse(
                byte_identity.completed_session_path(self.build_dir).exists()
            )
            self.assertFalse(
                byte_identity.preconfigure_seal_path(self.build_dir).exists()
            )
            self.assertEqual(
                byte_identity.main([*base, "--mode", "build"]), 2
            )
            self.assertFalse(verdict.exists())
            self.assertFalse(
                byte_identity.completed_session_path(self.build_dir).exists()
            )
            self.assertEqual(
                byte_identity.main(
                    [*base, "--mode", "build", "--", "--fail"]
                ),
                2,
            )
            self.assertFalse(verdict.exists())
            self.assertFalse(
                byte_identity.active_session_path(self.build_dir).exists()
            )
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_successive_outer_sessions_retain_only_current_controller(self):
        self.enable_authoritative_composer_fixture()
        fake_cmake = self.make_fake_cmake_install(
            "bounded-controller-cmake-install"
        )
        arguments = [
            "drive-cmake",
            "--source-dir", str(self.source_dir),
            "--build-dir", str(self.build_dir),
            "--cmake", str(fake_cmake),
            "--compiler", str(self.compiler),
            "--max-seconds", "15",
            "--mode", "configure",
        ]
        environment = {
            "FAKE_BYTE_IDENTITY_FRAMEWORK": str(TOOLS / "byte_identity.py"),
            "FAKE_BYTE_IDENTITY_BACKEND_TOOL": str(
                TOOLS / "byte_identity_backend.py"
            ),
        }
        previous = {key: os.environ.get(key) for key in environment}
        os.environ.update(environment)
        try:
            self.assertEqual(byte_identity.main(arguments), 0)
            snapshot_parent = (
                self.build_dir / "byte-identity/controller-snapshots"
            )
            roots = sorted(
                path.parent for path in snapshot_parent.glob(
                    "*/snapshot.json"
                )
            )
            self.assertEqual(len(roots), 1)
            first_root = roots[0]
            completed_path = byte_identity.completed_session_path(
                self.build_dir
            )
            completed_bytes = completed_path.read_bytes()

            active_path = byte_identity.active_session_path(self.build_dir)
            active_bytes = b'{"refusal-fixture":"active"}\n'
            active_path.write_bytes(active_bytes)
            try:
                self.assertEqual(byte_identity.main(arguments), 2)
                self.assertEqual(active_path.read_bytes(), active_bytes)
                self.assertEqual(completed_path.read_bytes(), completed_bytes)
                self.assertTrue(first_root.is_dir())
            finally:
                active_path.unlink(missing_ok=True)

            verdict = (
                self.build_dir
                / "byte-identity/audit/framework-verdict.json"
            )
            verdict.parent.mkdir(parents=True, exist_ok=True)
            verdict.write_text('{"forged":"stale"}\n')
            parked = first_root.with_name(first_root.name + "-parked")
            first_root.rename(parked)
            try:
                self.assertEqual(byte_identity.main(arguments), 2)
                self.assertFalse(verdict.exists())
                self.assertEqual(completed_path.read_bytes(), completed_bytes)
                self.assertTrue(parked.is_dir())
            finally:
                parked.rename(first_root)

            malformed = json.loads(completed_bytes)
            malformed["controller_root"] = str(
                byte_identity.controller_snapshot_path(
                    self.build_dir, "f" * 64
                )
            )
            completed_path.write_text(
                json.dumps(malformed, sort_keys=True) + "\n"
            )
            verdict.write_text('{"forged":"stale-again"}\n')
            try:
                self.assertEqual(byte_identity.main(arguments), 2)
                self.assertFalse(verdict.exists())
                self.assertTrue(first_root.is_dir())
            finally:
                completed_path.write_bytes(completed_bytes)

            self.assertEqual(byte_identity.main(arguments), 0)
            current = json.loads(completed_path.read_text())
            roots = sorted(
                path.parent for path in snapshot_parent.glob(
                    "*/snapshot.json"
                )
            )
            self.assertEqual(len(roots), 1)
            self.assertNotEqual(roots[0], first_root)
            self.assertFalse(first_root.exists())
            self.assertEqual(Path(current["controller_root"]), roots[0])
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_prior_completed_controller_is_journaled_before_retirement(self):
        self.enable_authoritative_composer_fixture()
        fake_cmake = self.make_fake_cmake_install(
            "prior-controller-recovery-cmake-install"
        )
        arguments = argparse.Namespace(
            source_dir=self.source_dir,
            build_dir=self.build_dir,
            cmake=fake_cmake,
            compiler=self.compiler,
            manifest=self.manifest,
            mode="configure",
            max_seconds=15,
            cmake_args=[],
        )
        environment = {
            "FAKE_BYTE_IDENTITY_FRAMEWORK": str(TOOLS / "byte_identity.py"),
            "FAKE_BYTE_IDENTITY_BACKEND_TOOL": str(
                TOOLS / "byte_identity_backend.py"
            ),
        }
        previous = {key: os.environ.get(key) for key in environment}
        os.environ.update(environment)
        try:
            self.assertEqual(byte_identity.command_drive_cmake(arguments), 0)
            completed = json.loads(
                byte_identity.completed_session_path(
                    self.build_dir
                ).read_text()
            )
            prior = Path(completed["controller_root"])
            prior_sha = completed["controller_descriptor_sha256"]
            sibling = byte_identity.controller_snapshot_path(
                self.build_dir, "e" * 64
            )
            with byte_identity.build_transaction(
                self.build_dir, exclusive=True, bootstrap_outer_session=True,
            ) as authority:
                authority.mkdir_exclusive(sibling)
                authority.atomic_write(sibling / "sentinel", b"preserve\n")

            real_rollback = byte_identity.rollback_exact_private_run
            removal_calls = []

            def partial_remove_then_fail(authority, root):
                if Path(root) == prior:
                    removal_calls.append(Path(root))
                    copied_resources = prior / "cmake-resources"
                    if authority.lstat(copied_resources) is not None:
                        authority.remove_tree(copied_resources)
                    raise byte_identity.ByteIdentityError(
                        "forced prior-controller partial deletion"
                    )
                return real_rollback(authority, root)

            with (
                mock.patch.object(
                    byte_identity, "rollback_exact_private_run",
                    side_effect=partial_remove_then_fail,
                ),
                self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "forced prior-controller partial deletion",
                ),
            ):
                byte_identity.command_drive_cmake(arguments)
            marker_path = byte_identity.outer_session_recovery_path(
                self.build_dir
            )
            marker = json.loads(marker_path.read_text())
            self.assertEqual(marker["phase"], "prior-controller-removing")
            self.assertEqual(marker["prior_controller_root"], str(prior))
            self.assertEqual(
                marker["prior_controller_descriptor_sha256"], prior_sha
            )
            self.assertFalse(
                byte_identity.completed_session_path(self.build_dir).exists()
            )
            self.assertTrue(prior.is_dir())

            for _attempt in range(3):
                with byte_identity.build_transaction(
                    self.build_dir, exclusive=True,
                    bootstrap_outer_session=True,
                ):
                    with (
                        mock.patch.object(
                            byte_identity,
                            "terminate_outer_session_processes",
                        ),
                        mock.patch.object(
                            byte_identity, "rollback_exact_private_run",
                            side_effect=partial_remove_then_fail,
                        ),
                        self.assertRaisesRegex(
                            byte_identity.ByteIdentityError,
                            "forced prior-controller partial deletion",
                        ),
                    ):
                        byte_identity.recover_outer_session_if_needed(
                            self.build_dir
                        )
                self.assertTrue(marker_path.is_file())
                self.assertTrue(prior.is_dir())
                self.assertEqual(
                    [path.name for path in prior.parent.iterdir()
                     if path != sibling],
                    [prior.name],
                )

            with byte_identity.build_transaction(
                self.build_dir, exclusive=True, bootstrap_outer_session=True,
            ):
                with mock.patch.object(
                    byte_identity, "terminate_outer_session_processes"
                ):
                    byte_identity.recover_outer_session_if_needed(
                        self.build_dir
                    )
            self.assertGreaterEqual(len(removal_calls), 4)
            self.assertFalse(prior.exists())
            self.assertFalse(marker_path.exists())
            self.assertEqual(
                (sibling / "sentinel").read_bytes(), b"preserve\n"
            )
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_controller_snapshot_requires_one_cmake_resource_root(self):
        fake_cmake = self.make_fake_cmake_install(
            "real-shape-cmake-install"
        )
        resource = fake_cmake.parent.parent / "share/cmake"
        nonce = digest(b"unversioned-cmake-resource")
        with byte_identity.build_transaction(
            self.build_dir, exclusive=True, bootstrap_outer_session=True,
        ) as authority:
            descriptor = byte_identity.materialize_controller_snapshot(
                build_dir=self.build_dir,
                source_dir=self.source_dir,
                cmake=fake_cmake,
                nonce=nonce,
                manifest=self.manifest,
            )
            self.assertEqual(len(descriptor["cmake_resources"]), 1)
            copied = descriptor["cmake_resources"][0]
            self.assertEqual(copied["source"], str(resource))
            self.assertEqual(
                copied["snapshot"],
                str(Path(descriptor["root"]) / "cmake/share/cmake"),
            )
            self.assertTrue(
                (Path(copied["snapshot"]) / "Modules/CMake.cmake").is_file()
            )
            byte_identity.validate_controller_snapshot(authority, descriptor)

        module = resource / "Modules/CMake.cmake"
        original = module.read_bytes()
        module.write_bytes(original + b"# persistent mutation\n")
        try:
            with byte_identity.build_transaction(
                self.build_dir, exclusive=True,
                bootstrap_outer_session=True,
            ) as authority:
                with self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "trusted CMake resource changed",
                ):
                    byte_identity.validate_controller_snapshot(
                        authority, descriptor
                    )
        finally:
            module.write_bytes(original)

        rejected = (
            ("missing", (), True, "no readable resource share"),
            ("empty", ("cmake",), False, "resource directory is empty"),
            (
                "ambiguous", ("cmake", "cmake-4.3"), True,
                "ambiguous resource directory",
            ),
        )
        for label, resource_names, resource_files, message in rejected:
            with self.subTest(layout=label):
                candidate = self.make_fake_cmake_install(
                    f"rejected-{label}-cmake-install",
                    resource_names=resource_names,
                    resource_files=resource_files,
                )
                with byte_identity.build_transaction(
                    self.build_dir, exclusive=True,
                    bootstrap_outer_session=True,
                ):
                    with self.assertRaisesRegex(
                        byte_identity.ByteIdentityError, message
                    ):
                        byte_identity.materialize_controller_snapshot(
                            build_dir=self.build_dir,
                            source_dir=self.source_dir,
                            cmake=candidate,
                            nonce=digest(label.encode("ascii")),
                            manifest=self.manifest,
                        )

    def test_controller_snapshot_copy_failure_rolls_back_exact_nonce_root(self):
        fake_cmake = self.make_fake_cmake_install(
            "symlinked-cmake-resource-install"
        )
        resource = fake_cmake.parent.parent / "share/cmake"
        (resource / "Modules/ZAlias.cmake").symlink_to("CMake.cmake")
        nonce = digest(b"controller-copy-failure")
        root = byte_identity.controller_snapshot_path(self.build_dir, nonce)
        sibling_nonce = digest(b"unrelated-controller-snapshot")
        sibling = byte_identity.controller_snapshot_path(
            self.build_dir, sibling_nonce
        )
        with byte_identity.build_transaction(
            self.build_dir, exclusive=True, bootstrap_outer_session=True,
        ) as authority:
            authority.mkdir_exclusive(sibling)
            authority.atomic_write(sibling / "sentinel", b"preserved\n")
            with self.assertRaisesRegex(
                byte_identity.ByteIdentityError,
                "virtual-Z input snapshot forbids symlink",
            ):
                byte_identity.materialize_controller_snapshot(
                    build_dir=self.build_dir,
                    source_dir=self.source_dir,
                    cmake=fake_cmake,
                    nonce=nonce,
                    manifest=self.manifest,
                )
            self.assertIsNone(authority.lstat(root))
            self.assertEqual(
                authority.read_bytes(sibling / "sentinel"), b"preserved\n"
            )

        self.assertFalse(os.path.lexists(root))
        self.assertFalse(
            byte_identity.active_session_path(self.build_dir).exists()
        )
        self.assertFalse(
            byte_identity.completed_session_path(self.build_dir).exists()
        )
        self.assertFalse(
            byte_identity.preconfigure_seal_path(self.build_dir).exists()
        )

    def test_controller_copy_baseline_refuses_resource_and_stdlib_mutation(self):
        fake_cmake = self.make_fake_cmake_install(
            "poisoned-controller-cmake-install"
        )
        stdlib = Path(sysconfig.get_path("stdlib")).resolve(strict=True)
        stdlib_leaf = stdlib / "os.py"
        self.assertTrue(stdlib_leaf.is_file())
        snapshot_parent = (
            self.build_dir / "byte-identity/controller-snapshots"
        )
        sibling = snapshot_parent / "session-sibling/sentinel"
        original_snapshot = byte_identity.canonical_tree_snapshot

        for label in ("cmake-resource", "python-stdlib"):
            with self.subTest(copied_tree=label):
                nonce = digest(f"controller-{label}".encode("ascii"))
                root = byte_identity.controller_snapshot_path(
                    self.build_dir, nonce
                )
                resource_root = root / "cmake/share/cmake"
                stdlib_root = root / "python/lib" / stdlib.name
                observed_root = (
                    resource_root if label == "cmake-resource"
                    else stdlib_root
                )
                copied_leaf = (
                    resource_root / "Modules/CMake.cmake"
                    if label == "cmake-resource"
                    else stdlib_root / "os.py"
                )
                injected = False

                def poison_controller(destination, *args, **kwargs):
                    nonlocal injected
                    if Path(destination) == observed_root and not injected:
                        injected = True
                        authority = byte_identity.active_build_authority()
                        mode = stat.S_IMODE(
                            authority.lstat(copied_leaf).st_mode
                        )
                        authority.atomic_write(
                            copied_leaf,
                            b"persistent controller poison\n",
                            mode=mode,
                        )
                    return original_snapshot(destination, *args, **kwargs)

                with byte_identity.build_transaction(
                    self.build_dir,
                    exclusive=True,
                    bootstrap_outer_session=True,
                ) as authority:
                    authority.mkdirs(sibling.parent)
                    authority.atomic_write(
                        sibling, b"preserve", mode=0o400
                    )
                    with (
                        mock.patch.object(
                            byte_identity, "canonical_tree_snapshot",
                            side_effect=poison_controller,
                        ),
                        self.assertRaisesRegex(
                            byte_identity.ByteIdentityError,
                            "differs from authenticated copied inputs",
                        ),
                    ):
                        byte_identity.materialize_controller_snapshot(
                            build_dir=self.build_dir,
                            source_dir=self.source_dir,
                            cmake=fake_cmake,
                            nonce=nonce,
                            manifest=self.manifest,
                        )
                    self.assertTrue(injected)
                    self.assertFalse(root.exists())
                    self.assertEqual(sibling.read_bytes(), b"preserve")
                    for path in (
                        byte_identity.active_session_path(self.build_dir),
                        byte_identity.completed_session_path(self.build_dir),
                        byte_identity.preconfigure_seal_path(self.build_dir),
                        self.build_dir
                        / "byte-identity/audit/framework-verdict.json",
                    ):
                        self.assertFalse(path.exists(), str(path))

    def test_outer_bootstrap_failures_remove_exact_session_and_preserve_sibling(self):
        original_atomic_json = byte_identity.atomic_json
        original_urandom = os.urandom
        fixed_random = (b"outer-bootstrap-atomicity" * 4)[:64]
        nonce = digest(fixed_random)

        for phase in ("controller", "hard-marker", "active", "preconfigure"):
            with self.subTest(phase=phase):
                build = self.directory / f"outer-bootstrap-{phase}"
                build.mkdir()
                sibling = byte_identity.controller_snapshot_path(
                    build, digest(f"sibling-{phase}".encode())
                )
                with byte_identity.build_transaction(
                    build, exclusive=True, bootstrap_outer_session=True,
                ) as authority:
                    authority.mkdir_exclusive(sibling)
                    authority.atomic_write(sibling / "sentinel", b"preserve\n")

                def materialize(**kwargs):
                    authority = byte_identity.active_build_authority()
                    root = byte_identity.controller_snapshot_path(
                        build, kwargs["nonce"]
                    )
                    authority.mkdir_exclusive(root)
                    descriptor = root / "snapshot.json"
                    authority.atomic_write(descriptor, b"{}\n")
                    return {
                        "root": str(root),
                        "descriptor_sha256": digest(b"{}\n"),
                        "python_path": str(Path(sys.executable).resolve()),
                        "python": {"sha256": digest(b"python")},
                        "tool_path": str((TOOLS / "byte_identity.py").resolve()),
                        "backend_path": str(
                            (TOOLS / "byte_identity_backend.py").resolve()
                        ),
                        "framework": {
                            "tool": {"sha256": digest(b"framework")},
                            "backend": {"sha256": digest(b"backend")},
                        },
                        "cmake_path": str(self.compiler),
                        "cmake": {"sha256": byte_identity.sha256_file(self.compiler)},
                    }

                def atomic_json_then_fail(path, value):
                    if (phase == "hard-marker"
                            and Path(path) == byte_identity.active_session_path(build)):
                        raise byte_identity.ByteIdentityError(
                            "forced failure after hard marker"
                        )
                    return original_atomic_json(path, value)

                patches = [
                    mock.patch.object(
                        byte_identity, "validate_manifest",
                        return_value={"terminal_producers": {}, "host_roots": {}},
                    ),
                    mock.patch.object(
                        byte_identity, "materialize_controller_snapshot",
                        side_effect=materialize,
                    ),
                    mock.patch.object(
                        os, "urandom",
                        side_effect=lambda size: (
                            fixed_random if size == 64
                            else original_urandom(size)
                        ),
                    ),
                    mock.patch.object(
                        byte_identity, "atomic_json",
                        side_effect=atomic_json_then_fail,
                    ),
                ]
                if phase == "controller":
                    patches.append(mock.patch.object(
                        byte_identity, "render_configure_init",
                        side_effect=byte_identity.ByteIdentityError(
                            "forced failure after controller"
                        ),
                    ))
                elif phase == "active":
                    patches.append(mock.patch.object(
                        byte_identity, "invalidate_terminal_outputs",
                        side_effect=byte_identity.ByteIdentityError(
                            "forced failure after active marker"
                        ),
                    ))
                elif phase == "preconfigure":
                    patches.append(mock.patch.object(
                        byte_identity, "_outer_cmake_commands",
                        side_effect=byte_identity.ByteIdentityError(
                            "forced failure after preconfigure seal"
                        ),
                    ))

                with ExitStack() as stack:
                    for patch in patches:
                        stack.enter_context(patch)
                    with self.assertRaises(byte_identity.ByteIdentityError):
                        byte_identity.command_drive_cmake(argparse.Namespace(
                            source_dir=self.source_dir,
                            build_dir=build,
                            cmake=self.compiler,
                            compiler=self.compiler,
                            manifest=self.manifest,
                            mode=("iterate" if phase in {
                                "active", "preconfigure"
                            } else "configure"),
                            max_seconds=15,
                            cmake_args=[],
                        ))
                self.assertEqual((sibling / "sentinel").read_bytes(), b"preserve\n")
                self.assertFalse(
                    byte_identity.controller_snapshot_path(build, nonce).exists()
                )
                for path in (
                    byte_identity.configure_init_path(build),
                    byte_identity.hard_mode_marker_path(build),
                    byte_identity.active_session_path(build),
                    byte_identity.completed_session_path(build),
                    byte_identity.preconfigure_seal_path(build),
                    build / "byte-identity/audit/framework-verdict.json",
                ):
                    self.assertFalse(path.exists(), str(path))
        self.assertFalse(
            (
                self.build_dir
                / "byte-identity/audit/framework-verdict.json"
            ).exists()
        )

    def test_outer_recovery_precedes_current_manifest_and_resumes_cleanup(self):
        """A prior bounded epoch is retired before current-state validation."""

        def seed(build, nonce):
            controller = byte_identity.controller_snapshot_path(build, nonce)
            plan = byte_identity.resident_plan_path(build, nonce)
            sibling = byte_identity.controller_snapshot_path(
                build, digest(("sibling-" + nonce).encode("ascii"))
            )
            document = {
                "schema": 1,
                "status": "OUTER_SESSION_RECOVERY_ACTIVE",
                "nonce": nonce,
                "phase": "controller-reserved",
                "build_root": str(build),
                "controller_root": str(controller),
                "controller_descriptor_sha256": None,
                "resident_plan_root": str(plan),
                "prior_controller_root": None,
                "prior_controller_descriptor_sha256": None,
            }
            with byte_identity.build_transaction(
                build, exclusive=True, bootstrap_outer_session=True,
            ) as authority:
                authority.mkdir_exclusive(controller)
                authority.atomic_write(controller / "partial", b"partial\n")
                authority.mkdir_exclusive(plan)
                authority.atomic_write(plan / "partial", b"partial\n")
                authority.mkdir_exclusive(sibling)
                authority.atomic_write(sibling / "sentinel", b"preserve\n")
                byte_identity.update_outer_session_recovery_marker(
                    document, build, "controller-reserved"
                )
            return controller, plan, sibling

        build = self.directory / "outer-recovery-before-current-manifest"
        build.mkdir()
        nonce = "a" * 64
        controller, plan, sibling = seed(build, nonce)
        validation_observed = []

        def reject_current_manifest(*_args, **_kwargs):
            validation_observed.append(True)
            self.assertFalse(controller.exists())
            self.assertFalse(plan.exists())
            self.assertFalse(
                byte_identity.outer_session_recovery_path(build).exists()
            )
            self.assertEqual(
                (sibling / "sentinel").read_bytes(), b"preserve\n"
            )
            raise byte_identity.ByteIdentityError(
                "current manifest reached after bounded recovery"
            )

        arguments = argparse.Namespace(
            source_dir=self.source_dir,
            build_dir=build,
            cmake=self.compiler,
            compiler=self.compiler,
            manifest=self.manifest,
            mode="configure",
            max_seconds=15,
            cmake_args=[],
        )
        with (
            mock.patch.object(
                byte_identity, "terminate_outer_session_processes"
            ) as terminate,
            mock.patch.object(
                byte_identity, "validate_manifest",
                side_effect=reject_current_manifest,
            ),
            self.assertRaisesRegex(
                byte_identity.ByteIdentityError,
                "current manifest reached after bounded recovery",
            ),
        ):
            byte_identity.command_drive_cmake(arguments)
        terminate.assert_called_once_with(nonce, controller)
        self.assertEqual(validation_observed, [True])

        retry_build = self.directory / "outer-recovery-resume"
        retry_build.mkdir()
        retry_nonce = "b" * 64
        retry_controller, retry_plan, retry_sibling = seed(
            retry_build, retry_nonce
        )
        real_rollback = byte_identity.rollback_exact_private_run
        failed_once = []

        def fail_controller_once(authority, root):
            if Path(root) == retry_controller and not failed_once:
                failed_once.append(True)
                raise byte_identity.ByteIdentityError(
                    "forced controller removal cut"
                )
            return real_rollback(authority, root)

        with byte_identity.build_transaction(
            retry_build, exclusive=True, bootstrap_outer_session=True,
        ):
            with (
                mock.patch.object(
                    byte_identity, "rollback_exact_private_run",
                    side_effect=fail_controller_once,
                ),
                self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "forced controller removal cut",
                ),
            ):
                byte_identity.recover_outer_session_if_needed(retry_build)
            marker = json.loads(
                byte_identity.outer_session_recovery_path(
                    retry_build
                ).read_text()
            )
            self.assertEqual(marker["phase"], "controller-removing")
            self.assertTrue(retry_controller.is_dir())
            self.assertFalse(retry_plan.exists())
            byte_identity.recover_outer_session_if_needed(retry_build)
        self.assertFalse(retry_controller.exists())
        self.assertFalse(
            byte_identity.outer_session_recovery_path(retry_build).exists()
        )
        self.assertEqual(
            (retry_sibling / "sentinel").read_bytes(), b"preserve\n"
        )

    def test_outer_terminal_failures_aggregate_cleanup_and_preserve_sibling(self):
        self.enable_authoritative_composer_fixture()
        original_invalidate = byte_identity.invalidate_framework_verdict
        original_urandom = os.urandom

        for failure in ("child", "timeout", "resident"):
            with self.subTest(failure=failure):
                build = self.directory / f"outer-terminal-{failure}"
                build.mkdir()
                fake_cmake = self.make_fake_cmake_install(
                    f"outer-terminal-{failure}-cmake-install"
                )
                fixed_random = (
                    (f"outer-terminal-{failure}".encode("ascii") * 8)[:64]
                )
                self.assertEqual(len(fixed_random), 64)
                nonce = digest(fixed_random)
                failed_root = byte_identity.controller_snapshot_path(
                    build, nonce
                )
                sibling = byte_identity.controller_snapshot_path(
                    build, digest(f"terminal-sibling-{failure}".encode())
                )
                with byte_identity.build_transaction(
                    build, exclusive=True, bootstrap_outer_session=True,
                ) as authority:
                    authority.mkdir_exclusive(sibling)
                    authority.atomic_write(
                        sibling / "sentinel", b"preserve-terminal-sibling\n"
                    )

                cleanup_armed = {"value": False}
                cleanup_faults = []

                def run_child(*_args, **_kwargs):
                    cleanup_armed["value"] = True
                    if failure == "child":
                        return 19, b"", False
                    if failure == "timeout":
                        return 0, b"", True
                    return 0, b"", False

                def invalidate_with_first_cleanup_fault(path):
                    if cleanup_armed["value"] and not cleanup_faults:
                        cleanup_faults.append(Path(path))
                        raise byte_identity.ByteIdentityError(
                            "forced first terminal cleanup fault"
                        )
                    return original_invalidate(path)

                patches = (
                    mock.patch.object(
                        byte_identity, "_outer_cmake_commands",
                        return_value=[(str(self.compiler),)],
                    ),
                    mock.patch.object(
                        byte_identity, "run_child", side_effect=run_child,
                    ),
                    mock.patch.object(
                        byte_identity, "resident_rederive_inventory_locked",
                        side_effect=byte_identity.ByteIdentityError(
                            "forced resident production failure"
                        ),
                    ),
                    mock.patch.object(
                        byte_identity, "invalidate_framework_verdict",
                        side_effect=invalidate_with_first_cleanup_fault,
                    ),
                    mock.patch.object(
                        os, "urandom",
                        side_effect=lambda size: (
                            fixed_random if size == 64
                            else original_urandom(size)
                        ),
                    ),
                )
                with ExitStack() as stack:
                    for patch in patches:
                        stack.enter_context(patch)
                    with self.assertRaisesRegex(
                        byte_identity.ByteIdentityError,
                        "outer bootstrap rollback failed: framework verdict: "
                        "forced first terminal cleanup fault",
                    ) as raised:
                        byte_identity.command_drive_cmake(argparse.Namespace(
                            source_dir=self.source_dir,
                            build_dir=build,
                            cmake=fake_cmake,
                            compiler=self.compiler,
                            manifest=self.manifest,
                            mode=(
                                "iterate" if failure == "resident"
                                else "configure"
                            ),
                            max_seconds=15,
                            cmake_args=[],
                        ))

                self.assertEqual(len(cleanup_faults), 1)
                self.assertIsNotNone(raised.exception.__cause__)
                expected_original = (
                    "outer CMake invocation exited with status 19"
                    if failure == "child"
                    else (
                        "outer CMake invocation timed out"
                        if failure == "timeout"
                        else "forced resident production failure"
                    )
                )
                self.assertIn(
                    expected_original, str(raised.exception.__cause__)
                )
                self.assertEqual(
                    (sibling / "sentinel").read_bytes(),
                    b"preserve-terminal-sibling\n",
                )
                self.assertFalse(failed_root.exists())
                for path in (
                    byte_identity.configure_init_path(build),
                    byte_identity.hard_mode_marker_path(build),
                    byte_identity.active_session_path(build),
                    byte_identity.completed_session_path(build),
                    byte_identity.preconfigure_seal_path(build),
                    build / "byte-identity/audit/framework-verdict.json",
                ):
                    self.assertFalse(path.exists(), str(path))

    def test_configure_init_pins_all_tools_and_executes_zero_probes(self):
        cmake = shutil.which("cmake")
        if cmake is None:
            self.skipTest("native CMake is unavailable")
        source = self.directory / "zero-probe-source"
        build = self.directory / "zero-probe-build"
        source.mkdir()
        marker = self.directory / "unexpected-producer-action"
        tools = {}
        for role in ("compiler", "rc", "lib", "link"):
            path = self.directory / f"zero-probe-{role}"
            path.write_text(
                "#!/bin/sh\n"
                f"echo '{role}:' \"$@\" >> '{marker}'\n"
                "exit 97\n"
            )
            path.chmod(0o755)
            tools[role] = str(path)
        (source / "CMakeLists.txt").write_text(
            "cmake_minimum_required(VERSION 3.20)\n"
            "set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE BOOL \"\" FORCE)\n"
            "project(zero_probe LANGUAGES CXX)\n"
            "if(CMAKE_CXX_COMPILE_OBJECT MATCHES "
            "\"/Fd<TARGET_COMPILE_PDB>\")\n"
            "  string(REPLACE \"/Fd<TARGET_COMPILE_PDB>\" "
            "\"/Fd<OBJECT>.pdb\" CMAKE_CXX_COMPILE_OBJECT "
            "\"${CMAKE_CXX_COMPILE_OBJECT}\")\n"
            "endif()\n"
            "file(WRITE \"${CMAKE_BINARY_DIR}/raw-cxx-rule.txt\" "
            "\"${CMAKE_CXX_COMPILE_OBJECT}\")\n"
            "if(FORCE_LIVE_BUILD_TYPE_DEBUG)\n"
            "  set(CMAKE_BUILD_TYPE Debug)\n"
            "endif()\n"
            'set(CMAKE_CXX_FLAGS "/W3 /GX /D \\"WIN32\\"")\n'
            'set(CMAKE_CXX_FLAGS_RELEASE "/O2 /D \\"NDEBUG\\"")\n'
            'set(CMAKE_CXX_FLAGS_RELWITHDEBINFO '
            '"/Zi /O2 /D \\"NDEBUG\\"")\n'
            'set(CMAKE_EXE_LINKER_FLAGS "/machine:I386")\n'
            'set(CMAKE_EXE_LINKER_FLAGS_RELEASE "/incremental:no")\n'
            'set(CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO '
            '"/incremental:no /debug")\n'
            'set(CMAKE_SHARED_LINKER_FLAGS "/machine:I386")\n'
            'set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "/incremental:no")\n'
            'set(CMAKE_SHARED_LINKER_FLAGS_RELWITHDEBINFO '
            '"/incremental:no /debug")\n'
            "foreach(_cfg \"\" _DEBUG _RELEASE _RELWITHDEBINFO _MINSIZEREL)\n"
            "  foreach(_kind EXE SHARED STATIC)\n"
            '    string(REPLACE "/debug" "" '
            'CMAKE_${_kind}_LINKER_FLAGS${_cfg} '
            '"${CMAKE_${_kind}_LINKER_FLAGS${_cfg}}")\n'
            "  endforeach()\n"
            "endforeach()\n"
            f'include("{ROOT / "cmake/byte_identity.cmake"}")\n'
            "_isle_validate_byte_identity_compile_link_flags()\n"
            "add_executable(zero_exe zero.cpp)\n"
            "add_library(zero_shared SHARED zero.cpp)\n"
        )
        (source / "zero.cpp").write_text("int zero() { return 0; }\n")
        init = self.directory / "zero-probe-init.cmake"
        init.write_bytes(byte_identity.render_configure_init(tools))
        environment = dict(os.environ)
        for name in ("CC", "CXX", "RC", "AR", "LD"):
            environment.pop(name, None)
        outer_arguments = argparse.Namespace(
            mode="configure", cmake_args=[], source_dir=source,
            build_dir=build,
        )
        controller = {
            "cmake_path": cmake,
            "python_path": sys.executable,
            "root": str(self.directory / "zero-probe-controller"),
            "configure_init": str(init),
        }
        command = byte_identity._outer_cmake_commands(
            outer_arguments, controller
        )[0]
        build_type = (
            f"-DCMAKE_BUILD_TYPE={byte_identity.RESIDENT_CMAKE_BUILD_TYPE}"
        )
        self.assertEqual(command.count(build_type), 1)
        self.assertNotIn("-DCMAKE_BUILD_TYPE=Release", command)
        for mode in ("iterate", "build"):
            outer_arguments.mode = mode
            regenerate = byte_identity._outer_cmake_commands(
                outer_arguments, controller
            )[0]
            self.assertEqual(regenerate.count(build_type), 1)
            self.assertNotIn("-DCMAKE_BUILD_TYPE=Release", regenerate)
        outer_arguments.mode = "configure"
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=30, check=False, env=environment,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertFalse(
            marker.exists(),
            result.stdout + (marker.read_text() if marker.exists() else ""),
        )
        raw_rule = (build / "raw-cxx-rule.txt").read_bytes()
        expected_raw_rule = (
            b"<CMAKE_CXX_COMPILER>  /nologo /TP <DEFINES> <INCLUDES> "
            b"<FLAGS> /Fo<OBJECT> /Fd<OBJECT>.pdb -c <SOURCE>"
        )
        self.assertEqual(raw_rule, expected_raw_rule)
        self.assertEqual(len(raw_rule), 102)
        self.assertEqual(
            hashlib.sha256(raw_rule).hexdigest(),
            "cd7abe210ad8a1866e2d78d70f4c0a23309d824014106053fdf90406f77a173f",
        )
        self.assertEqual(
            raw_rule.hex(),
            "3c434d414b455f4358585f434f4d50494c45523e20202f6e6f6c6f676f20"
            "2f5450203c444546494e45533e203c494e434c554445533e203c464c414753"
            "3e202f466f3c4f424a4543543e202f46643c4f424a4543543e2e706462202d"
            "63203c534f555243453e",
        )
        with byte_identity.build_transaction(build, exclusive=True):
            metadata = byte_identity.validate_resident_configure_metadata(
                build, Path(tools["compiler"]), tools
            )
        self.assertEqual(metadata["probe_policy"],
                         "zero_compiler_actions_forced_manifest_facts_v1")
        compile_commands = json.loads(
            (build / "compile_commands.json").read_text()
        )
        self.assertEqual(len(compile_commands), 2)
        for entry in compile_commands:
            tokens = shlex.split(entry["command"])
            self.assertIn("/Zi", tokens)
            self.assertIn("/O2", tokens)
            self.assertIn("NDEBUG", tokens)
        for target in ("zero_exe", "zero_shared"):
            link_command = (
                build / f"CMakeFiles/{target}.dir/link.txt"
            ).read_text().lower()
            self.assertIn("/incremental:no", shlex.split(link_command))
            self.assertNotRegex(
                link_command, r"(^|\s)[/-]debug(?:[ :\s]|$)"
            )

        release_build = self.directory / "zero-probe-release-build"
        release_command = [
            "-DCMAKE_BUILD_TYPE=Release" if token == build_type else token
            for token in command
        ]
        release_command[release_command.index(str(build))] = str(release_build)
        rejected = subprocess.run(
            release_command,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=30, check=False, env=environment,
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout)
        self.assertIn(
            "requires live CMAKE_BUILD_TYPE exactly RelWithDebInfo",
            rejected.stdout,
        )
        self.assertFalse(
            marker.exists(),
            rejected.stdout + (marker.read_text() if marker.exists() else ""),
        )
        live_debug_build = self.directory / "zero-probe-live-debug-build"
        live_debug_command = list(command)
        live_debug_command[
            live_debug_command.index(str(build))
        ] = str(live_debug_build)
        live_debug_command.insert(
            live_debug_command.index("-S"),
            "-DFORCE_LIVE_BUILD_TYPE_DEBUG=ON",
        )
        live_debug = subprocess.run(
            live_debug_command,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=30, check=False, env=environment,
        )
        self.assertNotEqual(live_debug.returncode, 0, live_debug.stdout)
        self.assertIn(
            "requires live CMAKE_BUILD_TYPE exactly RelWithDebInfo",
            live_debug.stdout,
        )
        cache = (live_debug_build / "CMakeCache.txt").read_text()
        self.assertIn("CMAKE_BUILD_TYPE:STRING=RelWithDebInfo", cache)
        self.assertFalse(
            marker.exists(),
            live_debug.stdout + (marker.read_text() if marker.exists() else ""),
        )
        outer_arguments.cmake_args = ["--", "-DCMAKE_BUILD_TYPE=Release"]
        with self.assertRaisesRegex(
            byte_identity.ByteIdentityError,
            "may not override the resident toolchain/init",
        ):
            byte_identity._outer_cmake_commands(outer_arguments, controller)

    def test_resident_receipt_ledger_requires_exact_causal_inputs(self):
        receipt_build = self.directory / "receipt-build"
        receipt_build.mkdir()
        root_a = receipt_build / "inputs/a"
        root_b = receipt_build / "inputs/b"
        produced = receipt_build / "outputs/product"
        terminal = receipt_build / "outputs/terminal"
        for path, data in (
            (root_a, b"authenticated-a"),
            (root_b, b"authenticated-b"),
            (produced, b"resident-product"),
            (terminal, b"resident-terminal"),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        unreceipted = receipt_build / "inputs/unreceipted"
        unreceipted.write_bytes(b"unreceipted")
        with byte_identity.build_transaction(
            receipt_build, exclusive=True, bootstrap_outer_session=True,
        ):
            with byte_identity.resident_receipt_scope("a" * 64) as ledger:
                ledger.record_root(root_a, role="root-a")
                ledger.record_root(root_b, role="root-b")
                with self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "authenticated root inputs may have an empty causal chain",
                ):
                    ledger.record_produced(
                        produced, stage="vendor-archive", role="rootless", inputs=[]
                    )
                with self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "unreceipted input",
                ):
                    ledger.record_produced(
                        produced, stage="vendor-archive", role="forged",
                        inputs=[root_a, unreceipted],
                    )
                ledger.record_produced(
                    produced, stage="vendor-archive", role="product",
                    inputs=[root_a, root_b],
                )
                ledger.record_produced(
                    terminal, stage="reccmp-audit", role="terminal",
                    inputs=[produced],
                )
                ledger.finalize(
                    expected_stage_counts={
                        **{name: 0 for name in byte_identity.RESIDENT_PRODUCER_STAGES},
                        "vendor-archive": 1, "reccmp-audit": 1,
                    },
                    required_root_roles={"root-a", "root-b"},
                    terminal_inputs=[terminal],
                )
                produced.write_bytes(b"mutated-after-receipt")
                with self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "identity changed after admission|changed after production",
                ):
                    ledger.require_current(produced)
            unknown = receipt_build / "outputs/unknown"
            unknown.write_bytes(b"unknown-stage")
            with byte_identity.resident_receipt_scope("b" * 64) as ledger:
                ledger.record_root(root_a, role="root-a")
                ledger.record_produced(
                    unknown, stage="unplanned-stage", role="unknown",
                    inputs=[root_a],
                )
                with self.assertRaisesRegex(
                    byte_identity.ByteIdentityError, "unknown producer stage",
                ):
                    ledger.finalize(
                        expected_stage_counts={
                            name: 0
                            for name in byte_identity.RESIDENT_PRODUCER_STAGES
                        },
                        required_root_roles={"root-a"},
                        terminal_inputs=[unknown],
                    )

    def test_checked_manifest_uses_explicit_depersonalized_host_roots(self):
        manifest_text = (
            ROOT / "tools/byte_identity_manifest.json"
        ).read_text()
        checked_manifest = json.loads(manifest_text)
        self.assertNotIn("/Users/", manifest_text)
        self.assertNotIn("/Applications/", manifest_text)
        self.assertNotIn("/opt/homebrew", manifest_text)
        for token in byte_identity.MANIFEST_HOST_ROOT_ENV:
            self.assertIn(f"<{token}>", manifest_text)
        prefix_pins = {
            item["name"]: (item["sha256"], item["mode"])
            for item in checked_manifest["toolchain"]["backend_profiles"][
                byte_identity.POSIX_WINE_BACKEND
            ]["transport"]["prefix_template_files"]
        }
        self.assertEqual(prefix_pins, {
            ".update-timestamp": (
                "54b166ec2572855673701503796c7111f934df4e06c25b6c23f9bbd5a308fe97",
                0o444,
            ),
            "system.reg": (
                "98ce82a642c2ebbbcb4a849aa3511b702bb88d99eb466050dd25be8c753e54a1",
                0o444,
            ),
            "user.reg": (
                "f4f051d3b916c14a832b6d54733f787823ebc66c83a80b1ea24f08ba9082f0e9",
                0o444,
            ),
            "userdef.reg": (
                "e0d0c2f81ad979111ad2799d1634f8edd34f0927a86fd2a8083d03c600b730cb",
                0o444,
            ),
        })
        host_root = self.directory / "relocatable-host-root"
        host_root.mkdir()
        environment_name = byte_identity.MANIFEST_HOST_ROOT_ENV["WINE_BUNDLE"]
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(
                byte_identity.ByteIdentityError, environment_name
            ):
                byte_identity.manifest_host_path(
                    "<WINE_BUNDLE>/Contents/Info.plist", "fixture", {}
                )
            os.environ[environment_name] = str(host_root)
            roots = byte_identity.manifest_host_roots()
            self.assertEqual(roots, {"WINE_BUNDLE": str(host_root)})
            self.assertEqual(
                byte_identity.manifest_host_path(
                    "<WINE_BUNDLE>/Contents/Info.plist", "fixture", roots
                ),
                host_root / "Contents/Info.plist",
            )
            os.environ[environment_name] = "relative/path"
            with self.assertRaisesRegex(
                byte_identity.ByteIdentityError, "absolute host path"
            ):
                byte_identity.manifest_host_roots()
        self.assertTrue(byte_identity.private_reccmp_macho_dependency_allowed(
            "@loader_path/libcrypto.3.dylib"
        ))
        self.assertTrue(byte_identity.private_reccmp_macho_dependency_allowed(
            "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
        ))
        self.assertFalse(byte_identity.private_reccmp_macho_dependency_allowed(
            "/custom/package-manager/lib/libcrypto.3.dylib"
        ))

    def test_windows_toolchain_profile_defers_before_posix_host_resolution(self):
        checked_manifest = ROOT / "tools/byte_identity_manifest.json"
        deferred_build = self.directory / "windows-deferred-build"
        deferred_build.mkdir()
        with (
            mock.patch.object(
                byte_identity, "selected_backend",
                return_value=byte_identity.WINDOWS_NATIVE_BACKEND,
            ),
            mock.patch.object(
                byte_identity, "manifest_host_roots",
                side_effect=AssertionError(
                    "Windows selection touched POSIX host roots"
                ),
            ) as host_roots,
            mock.patch.object(
                byte_identity, "current_host_runtime_identity",
                side_effect=AssertionError(
                    "Windows selection touched Darwin runtime identity"
                ),
            ) as host_identity,
            self.assertRaisesRegex(
                byte_identity.ByteIdentityError,
                "toolchain backend is explicitly deferred: windows_native_z_v1",
            ),
        ):
            byte_identity.validate_manifest(
                checked_manifest,
                ROOT,
                deferred_build,
            )
        host_roots.assert_not_called()
        host_identity.assert_not_called()

    def test_prefix_template_rejects_extra_alias_or_mutable_root(self):
        byte_identity.validate_manifest(
            self.manifest, self.source_dir, self.build_dir,
            configured_compiler=str(self.compiler),
        )
        root = self.fake_prefix_template
        root.chmod(0o755)
        extra = root / "unexpected.reg"
        extra.write_text("unexpected\n")
        extra.chmod(0o444)
        root.chmod(0o555)
        try:
            with self.assertRaisesRegex(
                byte_identity.ByteIdentityError,
                "maximum entries|extra or missing",
            ):
                byte_identity.validate_manifest(
                    self.manifest, self.source_dir, self.build_dir,
                    configured_compiler=str(self.compiler),
                )
        finally:
            root.chmod(0o755)
            extra.unlink()
            root.chmod(0o555)

        system = root / "system.reg"
        pristine = system.read_bytes()
        root.chmod(0o755)
        system.chmod(0o644)
        system.unlink()
        system.symlink_to("user.reg")
        root.chmod(0o555)
        try:
            with self.assertRaisesRegex(
                byte_identity.ByteIdentityError, "leaf differs"
            ):
                byte_identity.validate_manifest(
                    self.manifest, self.source_dir, self.build_dir,
                    configured_compiler=str(self.compiler),
                )
        finally:
            root.chmod(0o755)
            system.unlink()
            system.write_bytes(pristine)
            system.chmod(0o444)
            root.chmod(0o555)

        root.chmod(0o755)
        try:
            with self.assertRaisesRegex(
                byte_identity.ByteIdentityError, "not mode 0555"
            ):
                byte_identity.validate_manifest(
                    self.manifest, self.source_dir, self.build_dir,
                    configured_compiler=str(self.compiler),
                )
        finally:
            root.chmod(0o555)

    def test_canonical_tree_multichunk_digest_matches_hashlib(self):
        root = self.directory / "multichunk-tree"
        root.mkdir()
        payload = (
            bytes(range(256)) * (2 * 1024 * 1024 // 256)
            + b"incremental-tail"
        )
        leaf = root / "large.bin"
        leaf.write_bytes(payload)
        snapshot = byte_identity.canonical_tree_snapshot(
            root, hash_files=True
        )
        record = next(
            item for item in snapshot["records"]
            if item["path"] == "large.bin"
        )
        self.assertEqual(record["size"], len(payload))
        self.assertEqual(
            record["sha256"], hashlib.sha256(payload).hexdigest()
        )

    def test_msvc_environment_transform_is_exact_and_rejects_ambiguity(self):
        source_path = self.directory / "real-shaped-msvcenv.sh"
        source = (
            b"#!/usr/bin/env bash\nset -e\n"
            + byte_identity.MSVC_ENVIRONMENT_ROOT_DERIVATION_LINE
            + b"MSVC_ROOT=${MSVC_ROOT//\\//\\\\}\n"
            + b"export INCLUDE=fixture\n"
        )
        source_path.write_bytes(source)
        rendered = byte_identity.render_msvc_environment_root_transform(
            source, source_path=source_path,
            source_sha256=digest(source),
            logical_root=Path("/logical toolchains/MSVC420"),
            source_mode=0o755,
        )
        replacement = b"MSVC_ROOT='/logical toolchains/MSVC420'\n"
        self.assertEqual(
            rendered["data"],
            source.replace(
                byte_identity.MSVC_ENVIRONMENT_ROOT_DERIVATION_LINE,
                replacement,
            ),
        )
        self.assertEqual(rendered["record"]["mode"], 0o555)
        self.assertEqual(
            rendered["receipt"], {
                "schema": (
                    byte_identity.MSVC_ENVIRONMENT_ROOT_TRANSFORM_SCHEMA
                ),
                "source_path": str(source_path),
                "source_sha256": digest(source),
                "generator_version": (
                    byte_identity.MSVC_ENVIRONMENT_ROOT_TRANSFORM_GENERATOR
                ),
                "logical_root": "/logical toolchains/MSVC420",
                "output_sha256": digest(rendered["data"]),
                "output_size": len(rendered["data"]),
            },
        )
        for malformed in (
            source.replace(
                byte_identity.MSVC_ENVIRONMENT_ROOT_DERIVATION_LINE, b""
            ),
            source + byte_identity.MSVC_ENVIRONMENT_ROOT_DERIVATION_LINE,
        ):
            with self.assertRaisesRegex(
                byte_identity.ByteIdentityError,
                "one exact root derivation line",
            ):
                byte_identity.render_msvc_environment_root_transform(
                    malformed, source_path=source_path,
                    source_sha256=digest(malformed),
                    logical_root=Path("/logical/MSVC420"),
                    source_mode=0o755,
                )
        with self.assertRaisesRegex(
            byte_identity.ByteIdentityError, "source hash differs"
        ):
            byte_identity.render_msvc_environment_root_transform(
                source + b"# mutation\n", source_path=source_path,
                source_sha256=digest(source),
                logical_root=Path("/logical/MSVC420"),
                source_mode=0o755,
            )
        for unsafe in (Path("/logical/quote'root"), Path("/logical/new\nline")):
            with self.assertRaisesRegex(
                byte_identity.ByteIdentityError, "safely representable"
            ):
                byte_identity.render_msvc_environment_root_transform(
                    source, source_path=source_path,
                    source_sha256=digest(source), logical_root=unsafe,
                    source_mode=0o755,
                )

        wine_source_path = self.directory / "real-shaped-wine-msvc.sh"
        wine_source = (
            b"#!/usr/bin/env bash\npath=$1\n"
            + byte_identity.MSVC_WINE_ARGUMENT_DIRECTORY_PREDICATE
            + b"; then printf '%s\\n' \"$path\"; fi\n"
        )
        wine_source_path.write_bytes(wine_source)
        wine_transform = byte_identity.render_msvc_wine_argument_transform(
            wine_source, source_path=wine_source_path,
            source_sha256=digest(wine_source), source_mode=0o755,
        )
        self.assertNotEqual(wine_transform["data"], wine_source)
        self.assertNotIn(
            byte_identity.MSVC_WINE_ARGUMENT_DIRECTORY_PREDICATE,
            wine_transform["data"],
        )
        self.assertIn(
            b"ISLE_BYTE_IDENTITY_VIRTUAL_Z_ROOT",
            wine_transform["data"],
        )
        self.assertEqual(
            wine_transform["receipt"]["output_sha256"],
            digest(wine_transform["data"]),
        )
        for malformed in (
            wine_source.replace(
                byte_identity.MSVC_WINE_ARGUMENT_DIRECTORY_PREDICATE, b""
            ),
            wine_source
            + byte_identity.MSVC_WINE_ARGUMENT_DIRECTORY_PREDICATE,
        ):
            with self.assertRaisesRegex(
                byte_identity.ByteIdentityError,
                "one exact directory predicate",
            ):
                byte_identity.render_msvc_wine_argument_transform(
                    malformed, source_path=wine_source_path,
                    source_sha256=digest(malformed), source_mode=0o755,
                )
        with self.assertRaisesRegex(
            byte_identity.ByteIdentityError, "source hash differs"
        ):
            byte_identity.render_msvc_wine_argument_transform(
                wine_source + b"# mutation\n", source_path=wine_source_path,
                source_sha256=digest(wine_source), source_mode=0o755,
            )

    def test_projected_real_msvc_wrappers_use_logical_root_and_held_bash(self):
        compiler_root = (ROOT.parent / "MSVC420").resolve()
        wrapper_root = compiler_root / "wine/x86"
        required = [
            wrapper_root / name
            for name in ("cl", "rc", "lib", "link", "msvcenv.sh", "wine-msvc.sh")
        ]
        required.extend(
            compiler_root / "bin" / name
            for name in ("CL.EXE", "RC.EXE", "LIB.EXE", "LINK.EXE")
        )
        if not all(path.is_file() for path in required):
            self.skipTest("real pinned MSVC420 wrapper fixture is unavailable")

        production = json.loads(
            (ROOT / "tools/byte_identity_manifest.json").read_text()
        )
        profile = production["toolchain"]["backend_profiles"][
            byte_identity.POSIX_WINE_BACKEND
        ]
        support_pins = {
            item["path"]: item["sha256"]
            for item in profile["compiler_support_files"]
        }
        terminal_pins = {
            item["role"]: item["sha256"]
            for item in production["terminal_producers"]["link"]["tools"]
        }
        self.assertEqual(
            support_pins["wine/x86/msvcenv.sh"],
            byte_identity.sha256_file(wrapper_root / "msvcenv.sh"),
        )
        self.assertEqual(
            support_pins["wine/x86/wine-msvc.sh"],
            byte_identity.sha256_file(wrapper_root / "wine-msvc.sh"),
        )

        projection = self.directory / (
            "byte-identity/execution-projections/"
            "session-0123456789abcdef0123456789abcdef"
        )
        z_root = projection / "z"
        projected_wrapper_root = byte_identity.absolute_snapshot_seat(
            z_root, wrapper_root
        )
        projected_wrapper_root.mkdir(parents=True)
        source_environment = (wrapper_root / "msvcenv.sh").read_bytes()
        transformed = byte_identity.render_msvc_environment_root_transform(
            source_environment, source_path=wrapper_root / "msvcenv.sh",
            source_sha256=support_pins["wine/x86/msvcenv.sh"],
            logical_root=compiler_root,
            source_mode=stat.S_IMODE(
                (wrapper_root / "msvcenv.sh").stat().st_mode
            ),
        )
        (projected_wrapper_root / "msvcenv.sh").write_bytes(
            transformed["data"]
        )
        (projected_wrapper_root / "msvcenv.sh").chmod(
            transformed["record"]["mode"]
        )
        held_bash = self.directory / "held-runtime/bash"
        held_bash.parent.mkdir()
        held_bash.symlink_to(Path(shutil.which("bash")).resolve())
        binary_roles = {
            "cl": ("compiler_binary", "CL.EXE"),
            "rc": ("rc_binary", "RC.EXE"),
            "lib": ("lib_binary", "LIB.EXE"),
            "link": ("link_binary", "LINK.EXE"),
        }
        wrapper_pins = {
            "cl": production["toolchain"]["compiler_sha256"],
            "rc": terminal_pins["rc_wrapper"],
            "lib": terminal_pins["lib_wrapper"],
            "link": terminal_pins["link_wrapper"],
            "wine-msvc.sh": support_pins["wine/x86/wine-msvc.sh"],
        }
        argument_transform = None
        for name in ("cl", "rc", "lib", "link", "wine-msvc.sh"):
            self.assertEqual(
                byte_identity.sha256_file(wrapper_root / name),
                wrapper_pins[name],
            )
            destination = projected_wrapper_root / name
            if name in binary_roles:
                source = (wrapper_root / name).read_bytes()
                wrapper_transform = (
                    byte_identity.render_msvc_wrapper_invocation_transform(
                        source, source_path=wrapper_root / name,
                        source_sha256=wrapper_pins[name],
                        script=f"wine/x86/{name}",
                        source_mode=stat.S_IMODE(
                            (wrapper_root / name).stat().st_mode
                        ),
                        held_bash=held_bash,
                    )
                )
                self.assertNotEqual(
                    wrapper_transform["record"]["sha256"],
                    wrapper_pins[name],
                )
                destination.write_bytes(wrapper_transform["data"])
                destination.chmod(wrapper_transform["record"]["mode"])
            else:
                source = (wrapper_root / name).read_bytes()
                argument_transform = (
                    byte_identity.render_msvc_wine_argument_transform(
                        source, source_path=wrapper_root / name,
                        source_sha256=wrapper_pins[name],
                        source_mode=stat.S_IMODE(
                            (wrapper_root / name).stat().st_mode
                        ),
                    )
                )
                self.assertNotEqual(
                    argument_transform["record"]["sha256"],
                    wrapper_pins[name],
                )
                destination.write_bytes(argument_transform["data"])
                destination.chmod(argument_transform["record"]["mode"])
        self.assertIsNotNone(argument_transform)
        self.assertEqual(
            argument_transform["receipt"]["environment_variable"],
            "ISLE_BYTE_IDENTITY_VIRTUAL_Z_ROOT",
        )
        projected_compiler_root = byte_identity.absolute_snapshot_seat(
            z_root, compiler_root
        )
        for relative in (
            "bin/winnt", "include", "mfc/include", "lib", "mfc/lib"
        ):
            projected_compiler_root.joinpath(
                *PurePosixPath(relative).parts
            ).mkdir(parents=True, exist_ok=True)
        for role, binary_name in binary_roles.values():
            source = compiler_root / "bin" / binary_name
            destination = projected_compiler_root / "bin" / binary_name
            shutil.copy2(source, destination)
            expected_sha = (
                support_pins["bin/CL.EXE"]
                if role == "compiler_binary" else terminal_pins[role]
            )
            self.assertEqual(byte_identity.sha256_file(destination), expected_sha)

        fake_bin = self.directory / "wrapper-runtime-bin"
        fake_bin.mkdir()
        capture_program = fake_bin / "wine"
        capture_program.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys\n"
            "from pathlib import Path\n"
            "Path(os.environ['CAPTURE']).write_text(json.dumps({"
            "'argv': sys.argv[1:], 'INCLUDE': os.environ.get('INCLUDE'), "
            "'LIB': os.environ.get('LIB'), 'LIBPATH': os.environ.get('LIBPATH'), "
            "'WINEPATH': os.environ.get('WINEPATH'), "
            "'WINEDLLOVERRIDES': os.environ.get('WINEDLLOVERRIDES')}))\n"
        )
        capture_program.chmod(0o755)
        system_dirname = Path(shutil.which("dirname")).resolve()
        (fake_bin / "dirname").symlink_to(system_dirname)
        environment = {
            "PATH": str(fake_bin),
            "WINE_MSVC_RAW_STDOUT": "1",
            "ISLE_BYTE_IDENTITY_VIRTUAL_Z_ROOT": str(z_root),
            "LANG": "C", "LC_ALL": "C",
        }

        logical_parent = Path("/__byte_identity_absent_wrapper_fixture__")
        self.assertFalse(logical_parent.exists())
        logical_source = logical_parent / "source/unit.cpp"
        logical_include = logical_parent / "include"
        logical_output = logical_parent / "output"
        for path in (
            logical_source.parent, logical_include, logical_output,
        ):
            byte_identity.absolute_snapshot_seat(
                z_root, path
            ).mkdir(parents=True, exist_ok=True)
        byte_identity.absolute_snapshot_seat(
            z_root, logical_source
        ).write_bytes(b"int projected_fixture;\n")

        win_root = str(compiler_root).replace("/", "\\")
        expected_environment = {
            "INCLUDE": f"{win_root}\\include;{win_root}\\mfc\\include",
            "LIB": f"{win_root}\\lib;{win_root}\\mfc\\lib",
            "LIBPATH": f"{win_root}\\lib;{win_root}\\mfc\\lib",
            "WINEPATH": f"{win_root}\\bin;{win_root}\\bin\\winnt",
            "WINEDLLOVERRIDES": "msvcrt40=n;msvcrt20=n",
        }
        selected = {}
        for wrapper_name, (_role, binary_name) in binary_roles.items():
            wrapper = projected_wrapper_root / wrapper_name
            capture = self.directory / f"{wrapper_name}-capture.json"
            invocation_environment = {
                **environment, "CAPTURE": str(capture)
            }
            # A direct shebang launch can see only our PATH, which deliberately
            # contains no `bash`; this makes ambient /usr/bin/env observable.
            forwarded = [
                f"/I{logical_include}",
                f"/Fo{logical_output / (wrapper_name + '.obj')}",
                str(logical_source),
            ]
            direct = subprocess.run(
                [str(wrapper), *forwarded], env=invocation_environment,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                check=False,
            )
            self.assertNotEqual(direct.returncode, 0)
            self.assertFalse(capture.exists())
            invoked = subprocess.run(
                [str(held_bash), str(wrapper), *forwarded],
                env=invocation_environment,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                check=False,
            )
            self.assertEqual(invoked.returncode, 0, invoked.stdout.decode())
            observed = json.loads(capture.read_text())
            self.assertEqual(
                {key: observed[key] for key in expected_environment},
                expected_environment,
            )
            self.assertEqual(observed["argv"][1:], [
                f"/Iz:{logical_include}",
                f"/Foz:{logical_output / (wrapper_name + '.obj')}",
                f"z:{logical_source}",
            ])
            expected_binary = f"{win_root}\\bin\\{binary_name}"
            self.assertEqual(observed["argv"][0], expected_binary)
            selected[wrapper_name] = observed["argv"][0]
            self.assertNotIn(str(projection), json.dumps(observed))

        missing_parent = byte_identity.absolute_snapshot_seat(
            z_root, logical_output
        )
        shutil.rmtree(missing_parent)
        refused_capture = self.directory / "missing-projected-parent.json"
        refused = subprocess.run(
            [
                str(held_bash), str(projected_wrapper_root / "link"),
                f"/Fo{logical_output / 'refused.exe'}",
            ],
            env={**environment, "CAPTURE": str(refused_capture)},
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
        )
        self.assertEqual(refused.returncode, 97, refused.stdout.decode())
        self.assertFalse(refused_capture.exists())

        probe = (
            'source "$1"\n'
            'printf "%s\\n" "$MSVC_CL_BIN" "$MSVC_RC_BIN" '
            '"$MSVC_LIB_BIN" "$MSVC_LINK_BIN"\n'
        )
        probed = subprocess.run(
            [str(held_bash), "-c", probe, "probe",
             str(projected_wrapper_root / "msvcenv.sh")],
            env=environment, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, check=False,
        )
        self.assertEqual(probed.returncode, 0, probed.stdout.decode())
        self.assertEqual(
            probed.stdout.decode().splitlines(),
            [selected[name] for name in ("cl", "rc", "lib", "link")],
        )

        def mapped(value: str) -> Path:
            logical = value.replace("\\", "/")
            self.assertTrue(logical.startswith("/"), logical)
            return byte_identity.absolute_snapshot_seat(
                z_root, Path(logical)
            )

        for value in selected.values():
            self.assertTrue(mapped(value).is_file(), value)
        for key in ("INCLUDE", "LIB", "LIBPATH", "WINEPATH"):
            for value in expected_environment[key].split(";"):
                self.assertTrue(mapped(value).is_dir(), value)

    def test_msvc_transport_transform_policy_universe_is_exact(self):
        original = json.loads(json.dumps(self.document))
        scripts = list(byte_identity.MSVC_WRAPPER_TRANSFORM_SCRIPTS)
        cases = {
            "deleted-role": scripts[:-1],
            "duplicate-role": [scripts[0], scripts[0], *scripts[2:]],
            "wrong-role-order": [scripts[1], scripts[0], *scripts[2:]],
            "wrong-path": [*scripts[:-1], "wine/x86/wine-msvc.sh"],
        }
        for label, candidate in cases.items():
            with self.subTest(label=label):
                self.document = json.loads(json.dumps(original))
                self.document["toolchain"]["transport"][
                    "msvc_environment"
                ]["wrapper_invocation_transform"]["scripts"] = candidate
                self.write_manifest()
                with (
                    byte_identity.build_transaction(
                        self.build_dir, exclusive=True,
                        bootstrap_outer_session=True,
                    ),
                    self.assertRaisesRegex(
                        byte_identity.ByteIdentityError,
                        "wrapper invocation transform differs",
                    ),
                ):
                    byte_identity.validate_manifest(
                        self.manifest, self.source_dir, self.build_dir,
                        configured_compiler=str(self.compiler),
                    )
        self.document = original
        self.write_manifest()

    def test_required_absent_toolchain_leaf_cannot_enter_command_snapshot(self):
        absent_relative = "wine/x86/msvctricks.exe"
        absent = self.directory / absent_relative
        self.assertFalse(absent.exists())
        self.document["toolchain"]["required_absent_toolchain_files"] = [
            absent_relative
        ]
        self.write_manifest()
        self.ensure_inventory()
        output = self.build_dir / "objects/required-absent.obj"
        pdb = self.build_dir / "objects/required-absent.pdb"
        self.attest_command(
            self.launch_args(output, pdb, ensure_inventory=False)
        )
        original_copy = byte_identity.copy_command_tree_to_snapshot
        injected = []

        def inject_absent(source, destination, expected):
            result = original_copy(source, destination, expected)
            if not injected:
                authority = byte_identity.active_build_authority()
                seat = byte_identity.absolute_snapshot_seat(
                    byte_identity.command_snapshot_path(self.build_dir) / "z",
                    absent,
                )
                authority.mkdirs(seat.parent)
                authority.atomic_write(seat, b"forbidden branch switch\n")
                injected.append(seat)
            return result

        with byte_identity.build_transaction(
            self.build_dir, exclusive=True, bootstrap_outer_session=True,
        ) as authority:
            state = byte_identity.validate_manifest(
                self.manifest, self.source_dir, self.build_dir,
                configured_compiler=str(self.compiler),
            )
            byte_identity.materialize_runtime_bin(state, self.build_dir)
            inventory = byte_identity.load_inventory(state, self.build_dir)
            command = byte_identity.strict_json_loads(authority.read_bytes(
                byte_identity.command_inventory_path(self.build_dir)
            ))
            with (
                mock.patch.object(
                    byte_identity, "copy_command_tree_to_snapshot",
                    side_effect=inject_absent,
                ),
                self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "required-absent toolchain file entered command inputs",
                ),
            ):
                byte_identity.materialize_command_snapshot(
                    state, inventory, command["entries"], self.build_dir
                )
            self.assertTrue(injected)
            self.assertFalse(
                byte_identity.command_snapshot_path(self.build_dir).exists()
            )

    def test_producer_support_closure_is_role_specific_and_held(self):
        self.enable_final_image_fixture()
        with byte_identity.build_transaction(
            self.build_dir, exclusive=True, bootstrap_outer_session=True,
        ) as authority:
            state = byte_identity.validate_manifest(
                self.manifest, self.source_dir, self.build_dir,
                configured_compiler=str(self.compiler),
            )
            z_root = self.build_dir / "producer-support-z"
            authority.mkdirs(z_root)
            immutable = {}
            for item in state["producer_support_files"]:
                source = Path(item["absolute_path"])
                physical = byte_identity.absolute_snapshot_seat(
                    z_root, source
                )
                data = authority.read_external_bytes(source)
                authority.atomic_write(physical, data, mode=0o400)
                relative = PurePosixPath(*source.parts[1:]).as_posix()
                immutable[relative] = {
                    "path": relative, "type": "file", "mode": 0o400,
                    "executable": False, "size": len(data),
                    "sha256": item["sha256"],
                }
            observed = {
                role: byte_identity.bind_producer_support_to_projection(
                    state, role, z_root, immutable
                )
                for role in sorted(byte_identity.PRODUCER_SUPPORT_ROLES)
            }
            self.assertEqual(
                {
                    role: [Path(item["path"]).name for item in audit["files"]]
                    for role, audit in observed.items()
                },
                {
                    "archive": [
                        "fake-archive-link-support.err",
                        "fake-archive-support.exe",
                    ],
                    "link": ["fake-archive-link-support.err"],
                    "resource": ["fake-resource-support.dll"],
                },
            )
            for role, audit in observed.items():
                byte_identity.validate_producer_support_audit(
                    state, role, audit, f"fixture {role} support"
                )
                forged = json.loads(json.dumps(audit))
                forged["files"][0]["sha256"] = "0" * 64
                with self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "differs from the manifest role closure",
                ):
                    byte_identity.validate_producer_support_audit(
                        state, role, forged, f"fixture {role} support"
                    )
            resource_leaf = Path(observed["resource"]["files"][0]["path"])
            physical = byte_identity.absolute_snapshot_seat(
                z_root, resource_leaf
            )
            authority.atomic_write(physical, b"tampered support\n", mode=0o400)
            with self.assertRaisesRegex(
                byte_identity.ByteIdentityError,
                "producer support closure leaf differs",
            ):
                byte_identity.bind_producer_support_to_projection(
                    state, "resource", z_root, immutable
                )

    def test_resident_nonterminal_leaf_audit_universe_is_exact(self):
        compiles = []
        compiler_audits = {}
        for target, count in (("config", 7), ("isle", 1), ("lego1", 1),
                              ("misc", 1)):
            for ordinal in range(count):
                output = f"/build/{target}/{ordinal}.obj"
                compiles.append({
                    "target": target, "target_ordinal": ordinal,
                    "object": output,
                })
                compiler_audits[output] = Path(output + ".audit.json")
        resources = []
        resource_audits = {}
        for target, ordinal in (("config", 7), ("isle", 1), ("lego1", 1)):
            output = f"/build/{target}/{ordinal}.res"
            resources.append({
                "target": target, "target_ordinal": ordinal,
                "output": output,
            })
            resource_audits[output] = Path(output + ".audit.json")
        plan = {
            "compiles": compiles, "resources": resources,
            "archives": [{
                "target": "misc", "ordered_inputs": ["/build/misc/0.obj"],
            }],
            "link": {"direct_inputs": [
                "/build/lego1/0.obj", "/build/lego1/1.res",
            ]},
        }
        policy = [
            {"target": "config", "compiler_audit_count": 7,
             "resource_audit_count": 1},
            {"target": "isle", "compiler_audit_count": 1,
             "resource_audit_count": 1},
        ]
        state = {"terminal_producers": {"link": {
            "verified_nonterminal_leaf_audits": policy,
        }}}
        leaves = byte_identity.resident_nonterminal_leaf_audits(
            state, plan, compiler_audits, resource_audits
        )
        self.assertEqual(len(leaves), 10)
        self.assertEqual(
            {path.parts[2] for path in leaves}, {"config", "isle"}
        )
        for mutation in (
            policy[:-1],
            [{**policy[0], "compiler_audit_count": 6}, policy[1]],
            [*policy, {"target": "extra", "compiler_audit_count": 0,
                       "resource_audit_count": 1}],
        ):
            forged = json.loads(json.dumps(state))
            forged["terminal_producers"]["link"][
                "verified_nonterminal_leaf_audits"
            ] = mutation
            with self.assertRaisesRegex(
                byte_identity.ByteIdentityError,
                "verified nonterminal leaf-audit universe differs",
            ):
                byte_identity.resident_nonterminal_leaf_audits(
                    forged, plan, compiler_audits, resource_audits
                )

    def test_resident_plan_derives_and_executes_mocked_iteration(self):
        resident_build = self.directory / "resident-plan-build"
        resident_build.mkdir()
        controller_root = self.directory / "resident-controller"
        controller_root.mkdir()
        controller_snapshot = controller_root / "snapshot.json"
        controller_snapshot.write_text("{}\n")
        session = {
            "nonce": "b" * 64,
            "python": str(Path(sys.executable).resolve()),
            "framework": str((TOOLS / "byte_identity.py").resolve()),
            "controller_root": str(controller_root),
            "source_root": str(self.source_dir),
            "build_root": str(resident_build),
            "configure_tools": {
                "compiler": str(self.compiler),
                "rc": str(self.compiler),
                "lib": str(self.compiler),
                "link": str(self.compiler),
            },
        }
        controller = {
            "root": str(controller_root),
            "tool_path": str((TOOLS / "byte_identity.py").resolve()),
            "backend_path": str((TOOLS / "execution_backends.py").resolve()),
            "entropy_path": str((TOOLS / "entropy.py").resolve()),
        }
        verification = argparse.Namespace(
            manifest=self.manifest,
            source_dir=self.source_dir,
            build_dir=resident_build,
            compiler=str(self.compiler),
        )
        inventory = {
            "targets": [], "link_graph": [], "entries": [], "inputs": [],
            "generator_standard_libraries": {
                "configuration": "RelWithDebInfo", "base": [],
                "configuration_specific": [],
            },
        }
        command_inventory = {"entries": []}
        compiler_cache = resident_build / "CMakeCache.txt"
        compiler_metadata = (
            resident_build / "CMakeFiles/fixture/CMakeCXXCompiler.cmake"
        )
        compile_database = resident_build / "compile_commands.json"
        link_directory = resident_build / "CMakeFiles/lego1.dir"
        link_directory.mkdir(parents=True)
        compile_database.write_text("[]\n")
        compiler_cache.write_text("fixture cache\n")
        compiler_metadata.parent.mkdir(parents=True)
        compiler_metadata.write_text("fixture compiler facts\n")
        link_rsp = link_directory / "objects1.rsp"
        link_rsp.write_text("")
        prefix = byte_identity._resident_expected_producer_prefix(
            session, "link-launch", "lego1", str(self.compiler),
            identity="LEGO1",
        )
        (link_directory / "link.txt").write_text(
            shlex.join([*prefix, "fixture-link"]) + "\n"
        )
        for path in (
            byte_identity.configure_init_path(resident_build),
            byte_identity.inventory_path(resident_build),
            byte_identity.policy_stamp_path(resident_build),
            byte_identity.command_inventory_path(resident_build),
            byte_identity.command_policy_stamp_path(resident_build),
            byte_identity.toolchain_snapshot_path(resident_build) / "snapshot.json",
            byte_identity.command_snapshot_path(resident_build) / "snapshot.json",
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"fixture {path.name}\n")
        logical_link_wrapper = self.directory / "logical-link-wrapper"
        logical_link_binary = self.directory / "logical-link-binary"
        logical_reccmp = self.directory / "logical-reccmp"
        original = self.source_dir / "LEGO1.DLL"
        original.write_bytes(b"retail-oracle-fixture")
        state = {
            "manifest_sha256": "c" * 64,
            "source_overlay": byte_identity.validate_source_overlay(
                None, self.source_dir
            ),
            "execution_backend": {
                "id": byte_identity.POSIX_WINE_BACKEND,
            },
            "recipes": [],
            "archives": [],
            "translation_units": [],
            "terminal_producers": {
                "link": {
                    "tools": [
                        {"role": "link_wrapper",
                         "absolute_path": str(logical_link_wrapper)},
                        {"role": "link_binary",
                         "absolute_path": str(logical_link_binary)},
                    ],
                    "ordered_library_occurrence_count": 0,
                    "ordered_library_identity_sha256": digest(b"\n"),
                    "generator_standard_libraries": {
                        "configuration": "RelWithDebInfo", "base": [],
                        "configuration_specific": [],
                    },
                    "verified_nonterminal_leaf_audits": [],
                },
                "reccmp": {
                    "backend": byte_identity.POSIX_WINE_BACKEND,
                    "transport_schema":
                        "darwin_native_python_private_cvdump_wine_v1",
                    "executable_path": str(logical_reccmp),
                },
            },
            "images": [{"original_path": str(original)}],
        }
        metadata = {
            "cache": str(compiler_cache),
            "compiler_metadata": str(compiler_metadata),
        }

        class RecordingLedger:
            def __init__(self):
                self.nonce = session["nonce"]
                self.records = {}
                self.finalized = None

            @staticmethod
            def key(path):
                return str(Path(path))

            def record_root_once(self, path, *, role):
                key = self.key(path)
                old = self.records.get(key)
                if old is not None:
                    testcase.assertEqual(old["role"], role)
                    return old
                record = {
                    "kind": "authenticated_input", "role": role,
                    "stage": "authenticated-root", "path": key,
                }
                self.records[key] = record
                return record

            def require_exact_inputs(self, paths):
                testcase.assertTrue(paths)
                testcase.assertTrue(
                    all(self.key(path) in self.records for path in paths)
                )

            def record_produced(self, path, *, stage, role, inputs):
                self.require_exact_inputs(inputs)
                key = self.key(path)
                testcase.assertNotIn(key, self.records)
                record = {
                    "kind": "resident_produced", "role": role,
                    "stage": stage, "path": key,
                    "inputs": [self.key(path) for path in inputs],
                }
                self.records[key] = record
                return record

            def finalize(self, **kwargs):
                testcase.assertTrue(kwargs["terminal_inputs"])
                self.finalized = kwargs

            def mark_retired_roots(self, roots, receipt):
                testcase.assertTrue(roots)
                testcase.assertTrue(receipt)
                self.retired_roots = tuple(map(str, roots))
                self.retirement_receipt = receipt

            def require_surviving_current(self):
                testcase.assertTrue(self.retired_roots)

        testcase = self
        ledger = RecordingLedger()
        link_artifacts = {
            name: resident_build / f"resident-link-{name}"
            for name in (
                "image", "analysis_image", "pdb", "map", "analysis_map",
                "import_library", "export_file", "analysis_import_library",
                "analysis_export_file", "verbose_log", "analysis_verbose_log",
            )
        }
        link_audit_path = byte_identity.final_link_audit_path(
            resident_build, "LEGO1"
        )
        link_audit = {
            name: str(path) for name, path in link_artifacts.items()
        }
        definition_snapshot = resident_build / "sealed/link/lego1.def"
        definition_snapshot.parent.mkdir(parents=True)
        definition_snapshot.write_text("EXPORTS\n")

        def write_link_outputs(_arguments):
            terminal_trace.append("link")
            authority = byte_identity.active_build_authority()
            for name, path in link_artifacts.items():
                authority.atomic_write(path, f"fixture-{name}\n".encode())
            authority.atomic_write(link_audit_path, b"{}\n")

        def write_reccmp_outputs(_arguments):
            terminal_trace.append("reccmp")
            authority = byte_identity.active_build_authority()
            for path, data in (
                (byte_identity.final_report_path(resident_build, "LEGO1"), b"[]\n"),
                (byte_identity.final_reccmp_log_path(resident_build, "LEGO1"), b"ok\n"),
                (byte_identity.final_reccmp_audit_path(resident_build, "LEGO1"), b"{}\n"),
            ):
                authority.atomic_write(path, data)

        parsed_link = {
            "direct": [], "libraries": [], "response_paths": [link_rsp],
        }
        iteration = {
            "schema": 1, "status": "FINAL_GATES_INCOMPLETE",
            "byte_identity_complete": False,
        }
        terminal_trace = []

        def write_projection_finalization(authority):
            terminal_trace.append("projection-finalization")
            root = (
                resident_build / "byte-identity/execution-projections"
                / ("session-" + "e" * 32)
            )
            receipt = {
                "schema": 1,
                "status": "EXECUTION_PROJECTION_FINALIZED_AND_REMOVED",
                "backend": byte_identity.POSIX_WINE_BACKEND,
                "transport_schema": "wine_virtual_z_v1",
                "projection_root": str(root),
                "projection_descriptor_sha256": "1" * 64,
                "toolchain_snapshot_sha256": byte_identity.sha256_file(
                    byte_identity.toolchain_snapshot_path(resident_build)
                    / "snapshot.json"
                ),
                "command_snapshot_sha256": byte_identity.sha256_file(
                    byte_identity.command_snapshot_path(resident_build)
                    / "snapshot.json"
                ),
                "immutable_entry_count": 1,
                "immutable_records_sha256": "2" * 64,
                "terminal_immutable_records_sha256": "2" * 64,
                "source_record_count": 1,
                "unique_record_install_count": 1,
                "projection_materialization_count": 1,
                "seat_capacity": 1,
                "lease_count": 1,
                "writable_build_branch_empty": True,
                "projection_removed": True,
            }
            byte_identity.atomic_json(
                byte_identity.execution_projection_finalization_path(
                    resident_build
                ),
                receipt,
            )
            authority.execution_projection_receipt = receipt

        def record_iteration(arguments):
            terminal_trace.append("verification")
            return iteration

        def retire_mocked_inputs(_state, _build):
            terminal_trace.append("input-retirement")
            return ({"status": "mock-resident-input-retirement"}, [
                byte_identity.runtime_bin_path(resident_build),
                byte_identity.toolchain_snapshot_path(resident_build),
                byte_identity.command_snapshot_path(resident_build),
                byte_identity.native_reccmp_snapshot_path(resident_build),
            ])

        native_reccmp = byte_identity.native_reccmp_snapshot_path(
            resident_build
        )

        def materialize_native_at_terminal(_state, _build):
            terminal_trace.append("native-materialization")
            for path in (
                native_reccmp / "snapshot.json",
                native_reccmp / "tool/reccmp.py",
                native_reccmp / "interpreter/pinned-interpreter",
                native_reccmp / "runtime/bin/python3.12",
                native_reccmp / "runtime/lib/Python",
            ):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"sealed native reccmp fixture\n")
            return {"status": "mock-resident-native-snapshot"}

        with byte_identity.build_transaction(
            resident_build, exclusive=True, bootstrap_outer_session=True,
        ):
            with (
                mock.patch.object(byte_identity, "validate_manifest",
                                  return_value=state),
                mock.patch.object(byte_identity, "load_inventory",
                                  return_value=inventory),
                mock.patch.object(byte_identity, "load_command_inventory",
                                  return_value=command_inventory),
                mock.patch.object(
                    byte_identity, "validate_resident_configure_metadata",
                    return_value=metadata,
                ),
                mock.patch.object(byte_identity, "parse_link_command",
                                  return_value=parsed_link),
                mock.patch.object(
                    byte_identity, "terminal_link_graph_authority",
                    return_value=(set(), set(), set()),
                ),
            ):
                plan = byte_identity.derive_resident_closed_plan(
                    argparse.Namespace(), verification, controller, session
                )
            self.assertEqual(plan["status"], "RESIDENT_CLOSED_PRODUCER_PLAN")
            self.assertEqual(plan["compiles"], [])
            self.assertEqual(plan["link"]["argv"], ["fixture-link"])

            sealed_z = (
                byte_identity.toolchain_snapshot_path(resident_build) / "z"
            )
            for logical in (
                self.compiler, logical_link_wrapper, logical_link_binary,
            ):
                seat = byte_identity.absolute_snapshot_seat(sealed_z, logical)
                seat.parent.mkdir(parents=True, exist_ok=True)
                seat.write_bytes(b"sealed tool fixture\n")
            self.assertFalse(native_reccmp.exists())
            with (
                mock.patch.object(byte_identity, "validate_manifest",
                                  return_value=state),
                mock.patch.object(byte_identity, "load_inventory",
                                  return_value=inventory),
                mock.patch.object(byte_identity, "load_command_inventory",
                                  return_value=command_inventory),
                mock.patch.object(byte_identity, "parse_link_command",
                                  return_value=parsed_link),
                mock.patch.object(
                    byte_identity, "terminal_link_ordered_inputs",
                    return_value=[{
                        "role": "linker_definition",
                        "path": str(self.source_dir / "lego1.def"),
                        "snapshot_path": str(definition_snapshot),
                    }],
                ),
                mock.patch.object(
                    byte_identity, "command_link_launch_locked",
                    side_effect=write_link_outputs,
                ),
                mock.patch.object(byte_identity, "read_unique_audit",
                                  return_value=link_audit),
                mock.patch.object(
                    byte_identity, "command_reccmp_launch_locked",
                    side_effect=write_reccmp_outputs,
                ),
                mock.patch.object(
                    byte_identity, "materialize_native_reccmp_snapshot",
                    side_effect=materialize_native_at_terminal,
                ) as native_materialize,
                mock.patch.object(byte_identity, "command_iteration_locked",
                                  side_effect=record_iteration) as iterate,
                mock.patch.object(byte_identity, "command_complete_locked") as complete,
                mock.patch.object(
                    byte_identity, "seed_resident_producer_state_cache",
                ),
                mock.patch.object(
                    byte_identity, "finalize_resident_producer_authority",
                    side_effect=lambda _arguments:
                        terminal_trace.append("shared-input-finalization"),
                ),
                mock.patch.object(
                    byte_identity, "finalize_execution_projection",
                    side_effect=write_projection_finalization,
                ),
                mock.patch.object(
                    byte_identity, "finalize_native_reccmp_snapshot_validation",
                    side_effect=lambda _state, _build:
                        terminal_trace.append("native-reccmp-finalization"),
                ),
                mock.patch.object(
                    byte_identity, "retire_resident_input_snapshots",
                    side_effect=retire_mocked_inputs,
                ),
                mock.patch.object(
                    byte_identity,
                    "validate_resident_input_retirement_evidence",
                    return_value={"status": "mock-resident-input-retirement"},
                ),
            ):
                result, holders = byte_identity.execute_resident_closed_plan(
                    verification, controller, session, plan, ledger,
                    terminal=False,
                )
            for holder in reversed(plan.get("_resident_holders", [plan["holder"]])):
                if isinstance(holder, byte_identity.HeldBuildDirectories):
                    holder.close()
            byte_identity.rollback_exact_private_run(
                byte_identity.active_build_authority(), Path(plan["root"])
            )
            self.assertFalse(Path(plan["root"]).exists())
        self.assertFalse(result["byte_identity_complete"])
        self.assertTrue(holders)
        self.assertIsNotNone(ledger.finalized)
        self.assertEqual(
            set(ledger.finalized["expected_stage_counts"]),
            byte_identity.RESIDENT_PRODUCER_STAGES,
        )
        native_descriptor = str(native_reccmp / "snapshot.json")
        link_receipts = [
            record for record in ledger.records.values()
            if record.get("role", "").startswith("link:")
        ]
        reccmp_receipts = [
            record for record in ledger.records.values()
            if record.get("role") == "reccmp:report"
        ]
        self.assertTrue(link_receipts)
        self.assertEqual(len(reccmp_receipts), 1)
        self.assertTrue(all(
            native_descriptor not in record.get("inputs", [])
            for record in link_receipts
        ))
        self.assertIn(native_descriptor, reccmp_receipts[0]["inputs"])
        native_materialize.assert_called_once_with(state, resident_build)
        self.assertEqual(
            terminal_trace,
            [
                "link",
                "native-materialization",
                "reccmp",
                "shared-input-finalization",
                "native-reccmp-finalization",
                "projection-finalization",
                "verification",
                "input-retirement",
            ],
        )
        iterate.assert_called_once_with(verification)
        complete.assert_not_called()

    def test_resident_plan_failure_rolls_back_only_its_nonce_root(self):
        resident_build = self.directory / "resident-plan-rollback-build"
        resident_build.mkdir()
        session = {"nonce": "d" * 64}
        verification = argparse.Namespace(
            manifest=self.manifest,
            source_dir=self.source_dir,
            build_dir=resident_build,
            compiler=str(self.compiler),
        )
        with byte_identity.build_transaction(
            resident_build, exclusive=True, bootstrap_outer_session=True,
        ):
            authority = byte_identity.active_build_authority()
            sibling = resident_build / "byte-identity/resident-plans/sibling"
            authority.mkdirs(sibling)
            sentinel = sibling / "sentinel"
            authority.atomic_write(sentinel, b"preserve\n")
            with (
                mock.patch.object(
                    byte_identity, "validate_manifest",
                    side_effect=byte_identity.ByteIdentityError(
                        "forced resident plan derivation failure"
                    ),
                ),
                self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "forced resident plan derivation failure",
                ),
            ):
                byte_identity.derive_resident_closed_plan(
                    argparse.Namespace(), verification, {}, session
                )
            self.assertEqual(sentinel.read_bytes(), b"preserve\n")
            self.assertEqual(
                sorted(path.name for path in sibling.parent.iterdir()),
                ["sibling"],
            )

    def test_authentic_vc42_verbose_library_fixture_has_exact_grammar(self):
        fixture = ROOT.parent / "isle-tools/s22-link/verbose-HEAD.txt"
        if not fixture.is_file():
            self.skipTest("local pinned VC4.2 verbose fixture is unavailable")
        data = fixture.read_bytes()
        self.assertEqual(len(data), 310829)
        self.assertEqual(
            digest(data),
            "3f8fd09d7d1cedc9df87152de266a2422c469fac26dc68d6ee7d4c478656c295",
        )
        parsed = byte_identity.parse_vc42_verbose_library_log(data)
        self.assertEqual(parsed["schema"], "vc42_verbose_library_log_v1")
        self.assertEqual(parsed["start_pass2_line"], 6343)
        self.assertEqual(len(parsed["flat"]), 34)
        self.assertIn(
            "libcpmt",
            [item["value"] for item in parsed["events"]
             if item["kind"] == "processed"],
        )
        with self.assertRaises(byte_identity.ByteIdentityError):
            byte_identity.parse_vc42_verbose_library_log(
                data.replace(b"Start Pass2", b"Start PassX", 1)
            )

    def test_outer_driver_detects_persistent_controller_mutation_pre_and_post(self):
        self.enable_authoritative_composer_fixture()
        original_materialize = byte_identity.materialize_controller_snapshot
        original_run_child = byte_identity.run_child
        for phase in ("pre", "post"):
            with self.subTest(phase=phase):
                fake_cmake = self.make_fake_cmake_install(
                    f"fake-cmake-{phase}-install"
                )
                pristine = FAKE_OUTER_CMAKE.encode("utf-8")
                fake_cmake.write_bytes(pristine)
                fake_cmake.chmod(0o755)
                build = self.directory / f"controller-mutation-{phase}"
                base = [
                    "drive-cmake",
                    "--source-dir", str(self.source_dir),
                    "--build-dir", str(build),
                    "--cmake", str(fake_cmake),
                    "--compiler", str(self.compiler),
                    "--max-seconds", "15",
                    "--mode", "configure",
                ]
                mutated = False

                def materialize_then_mutate(**kwargs):
                    nonlocal mutated
                    result = original_materialize(**kwargs)
                    if phase == "pre":
                        fake_cmake.write_bytes(pristine + b"\n# PERSISTENT-PRE\n")
                        fake_cmake.chmod(0o755)
                        mutated = True
                    return result

                def run_then_mutate(*args, **kwargs):
                    nonlocal mutated
                    result = original_run_child(*args, **kwargs)
                    if phase == "post":
                        fake_cmake.write_bytes(pristine + b"\n# PERSISTENT-POST\n")
                        fake_cmake.chmod(0o755)
                        mutated = True
                    return result

                byte_identity.materialize_controller_snapshot = (
                    materialize_then_mutate
                )
                byte_identity.run_child = run_then_mutate
                try:
                    self.assertEqual(byte_identity.main(base), 2)
                finally:
                    byte_identity.materialize_controller_snapshot = (
                        original_materialize
                    )
                    byte_identity.run_child = original_run_child
                    fake_cmake.write_bytes(pristine)
                    fake_cmake.chmod(0o755)
                self.assertTrue(mutated)
                self.assertFalse(
                    (build / "byte-identity/audit/framework-verdict.json").exists()
                )
                self.assertFalse(
                    byte_identity.active_session_path(build).exists()
                )
                self.assertFalse(
                    byte_identity.completed_session_path(build).exists()
                )

    def test_target_dispatcher_routes_all_production_rc_and_forwards_cpp_exactly(self):
        cmake_text = (ROOT / "CMakeLists.txt").read_text()
        resources = (
            ("lego1", "LEGO1/res/lego1.rc"),
            ("isle", "ISLE/res/isle.rc"),
            ("config", "CONFIG/res/config.rc"),
        )
        self.assertEqual(
            {match.replace("\\", "/") for match in re.findall(
                r"[A-Za-z0-9_/.-]+[.]rc", cmake_text, flags=re.IGNORECASE
            )},
            {source for _, source in resources},
        )
        routed = []
        original_resource = byte_identity.command_resource_launch
        original_run_child = byte_identity.run_child

        def capture_resource(arguments):
            routed.append(arguments)
            return 0

        forwarded = []

        def capture_child(argv, timeout, environment, cwd=None):
            forwarded.append((list(argv), timeout, dict(environment), Path(cwd)))
            return 0, b"dispatcher-forwarded\n", False

        byte_identity.command_resource_launch = capture_resource
        byte_identity.run_child = capture_child
        try:
            for target, source in resources:
                source_path = ROOT / source
                self.assertTrue(source_path.is_file())
                self.assertEqual(byte_identity.main([
                    "compile-dispatch",
                    "--manifest", str(self.manifest),
                    "--source-dir", str(self.source_dir),
                    "--build-dir", str(self.build_dir),
                    "--target", target,
                    "--configured-compiler", str(self.compiler),
                    "--", "rc", "/fo", str(self.build_dir / f"{target}.res"),
                    str(source_path),
                ]), 0)

            nested = [
                str(Path(sys.executable).resolve()), "-I", "-B",
                str(Path(byte_identity.__file__).resolve()), "compile-launch",
                "--manifest", str(self.manifest),
                "--source-dir", str(self.source_dir),
                "--build-dir", str(self.build_dir),
                "--target", "fixture",
                "--configured-compiler", str(self.compiler),
                "--", str(self.compiler), "/Zi",
                f"/Fo{self.build_dir / 'dispatcher.obj'}",
                f"/Fd{self.build_dir / 'dispatcher.pdb'}",
                "-c", str(self.source),
            ]
            self.assertEqual(byte_identity.main([
                "compile-dispatch",
                "--manifest", str(self.manifest),
                "--source-dir", str(self.source_dir),
                "--build-dir", str(self.build_dir),
                "--target", "fixture",
                "--configured-compiler", str(self.compiler),
                "--", *nested,
            ]), 0)
        finally:
            byte_identity.command_resource_launch = original_resource
            byte_identity.run_child = original_run_child
        self.assertEqual(
            [(item.target, item.child[1:]) for item in routed],
            [
                (
                    target,
                    ["rc", "/fo", str(self.build_dir / f"{target}.res"),
                     str(ROOT / source)],
                )
                for target, source in resources
            ],
        )
        self.assertEqual(len(forwarded), 1)
        self.assertEqual(forwarded[0][0], nested)
        self.assertEqual(forwarded[0][3], Path.cwd().resolve())

    def test_command_database_keeps_rc_dispatcher_out_of_raw_projection(self):
        resource = self.source_dir / "src/fixture.rc"
        resource.write_text("1 VERSIONINFO\n")
        arguments = self.inventory_args()
        arguments.extend([
            "--input-entry", "fixture", str(resource), "RC",
        ])
        self.assertEqual(byte_identity.main(arguments), 0)
        output = self.build_dir / "CMakeFiles/fixture.dir/src/unit.cpp.obj"
        child = [
            str(self.compiler), "/nologo", "/TP", "/Zi", "/O2",
            "/D", "NDEBUG",
            f"/FI{self.include}", f"/Fo{output}", f"/Fd{output}.pdb",
            "-c", str(self.source),
        ]
        database = [{
            "directory": str(self.build_dir),
            "command": shlex.join(child),
            "file": str(self.source),
            "output": str(output),
        }]
        compile_commands = self.build_dir / "compile_commands.json"
        compile_commands.write_text(json.dumps(database, indent=2) + "\n")
        attest = [
            "attest-commands",
            "--manifest", str(self.manifest),
            "--source-dir", str(self.source_dir),
            "--build-dir", str(self.build_dir),
            "--compiler", str(self.compiler),
            "--compile-commands", str(compile_commands),
            "--output", str(byte_identity.command_inventory_path(self.build_dir)),
            "--policy-stamp", str(byte_identity.command_policy_stamp_path(
                self.build_dir
            )),
        ]
        self.assertEqual(byte_identity.main(attest), 0)
        inventory = json.loads(
            byte_identity.command_inventory_path(self.build_dir).read_text()
        )
        self.assertEqual(inventory["entries"][0]["launcher_prefix"], [])
        dispatcher = [
            str(Path(sys.executable).resolve()), "-I", "-B",
            str(Path(byte_identity.__file__).resolve()), "compile-dispatch",
            "--manifest", str(self.manifest),
            "--source-dir", str(self.source_dir),
            "--build-dir", str(self.build_dir),
            "--target", "fixture",
            "--configured-compiler", str(self.compiler), "--",
        ]
        database[0]["command"] = shlex.join([*dispatcher, *child])
        compile_commands.write_text(json.dumps(database, indent=2) + "\n")
        self.assertEqual(byte_identity.main(attest), 2)

    def test_plan_renders_two_distinct_recipes_in_one_tu_itemwise(self):
        self.enable_composer_fixture()
        second_id, second_sha = self.add_distinct_shape_recipe()
        self.assertEqual(byte_identity.main(self.plan_args()), 0)
        plan = self.plan.read_text()
        for variable in (
            "ISLE_BYTE_IDENTITY_TU_0_OUTPUTS",
            "ISLE_BYTE_IDENTITY_TU_0_RECIPE_IDS",
            "ISLE_BYTE_IDENTITY_RECIPE_IDS",
        ):
            self.assertIn(f"set({variable})", plan)
            self.assertEqual(plan.count(f"list(APPEND {variable} "), 2)
        self.assertNotIn(f'"{self.recipe_id};{second_id}"', plan)
        state = byte_identity.validate_manifest(
            self.manifest, self.source_dir, self.build_dir
        )
        self.assertEqual(
            [recipe["id"] for recipe in state["recipes"]],
            [self.recipe_id, second_id],
        )
        self.materialize()
        second_output = byte_identity.recipe_output(
            self.build_dir, second_id, second_sha
        )
        self.materialize_recipe(second_id, second_output)
        self.assertTrue(second_output.is_file())

    def test_plan_deduplicates_shared_recipe_alongside_second_unique_recipe(self):
        self.enable_composer_fixture()
        self.add_shared_recipe_unit()
        second_id, second_sha = self.add_distinct_shape_recipe(unit_index=1)
        self.assertEqual(byte_identity.main(self.plan_args()), 0)
        state = byte_identity.validate_manifest(
            self.manifest, self.source_dir, self.build_dir
        )
        self.assertEqual(
            [recipe["id"] for recipe in state["recipes"]],
            [self.recipe_id, second_id],
        )
        self.assertEqual(len(state["recipes"][0]["users"]), 2)
        self.assertEqual(len(state["recipes"][1]["users"]), 1)
        plan = self.plan.read_text()
        self.assertEqual(
            plan.count(
                f'list(APPEND ISLE_BYTE_IDENTITY_RECIPE_IDS "{self.recipe_id}")'
            ),
            1,
        )
        self.assertEqual(
            plan.count(
                f'list(APPEND ISLE_BYTE_IDENTITY_RECIPE_IDS "{second_id}")'
            ),
            1,
        )
        self.materialize()
        self.materialize_recipe(
            second_id,
            byte_identity.recipe_output(self.build_dir, second_id, second_sha),
        )

    def test_declaration_shape_matches_exhaustive_search_bytes(self):
        self.assertEqual(
            digest(entropy.generate_shape(2, 3).encode("utf-8")),
            "fcac8dfe7db78fdfbe3d9f1942feb51de8fc0f14885b8e4c23b695da2b4dff27",
        )

    def test_identical_content_addressed_recipe_is_global_and_shared(self):
        self.enable_composer_fixture()
        shared_source = self.add_shared_recipe_unit()
        self.assertEqual(byte_identity.main(self.plan_args()), 0)
        plan = self.plan.read_text()
        self.assertIn("set(ISLE_BYTE_IDENTITY_RECIPE_IDS)", plan)
        self.assertIn(
            f'list(APPEND ISLE_BYTE_IDENTITY_RECIPE_IDS "{self.recipe_id}")',
            plan,
        )
        self.assertEqual(
            plan.count(f"ISLE_BYTE_IDENTITY_RECIPE_{self.recipe_id}_OUTPUT"), 1
        )
        state = byte_identity.validate_manifest(
            self.manifest, self.source_dir, self.build_dir
        )
        self.assertEqual(len(state["recipes"]), 1)
        self.assertEqual(len(state["recipes"][0]["users"]), 2)
        self.materialize()
        audit = json.loads(
            (
                self.build_dir
                / f"byte-identity/audit/materialization/{self.recipe_id}.json"
            ).read_text()
        )
        self.assertEqual(audit["users"], state["recipes"][0]["users"])
        previous = Path.cwd()
        with self.fake_control(
            SEED_OBJ=str(self.seed_fixture), DONOR_OBJ=str(self.donor_fixture)
        ):
            try:
                os.chdir(self.build_dir)
                commands = []
                for index, source in enumerate((self.source, shared_source)):
                    output = self.build_dir / f"objects/shared-{index}.obj"
                    pdb = self.build_dir / f"objects/shared-{index}.pdb"
                    output.parent.mkdir(parents=True, exist_ok=True)
                    arguments = self.launch_args(output, pdb, source=source)
                    commands.append(arguments)
                for arguments in commands:
                    self.assertEqual(
                        self.run_standalone_producer_diagnostic(arguments), 0
                    )
            finally:
                os.chdir(previous)
        self.assertEqual(
            byte_identity.main(
                [
                    "verify",
                    "--manifest", str(self.manifest),
                    "--source-dir", str(self.source_dir),
                    "--build-dir", str(self.build_dir),
                    "--compiler", str(self.compiler),
                ]
            ),
            2,
        )
        self.assertFalse(
            (self.build_dir / "byte-identity/audit/framework-verdict.json")
            .exists()
        )

    def test_two_listed_tus_authenticate_distinct_fpo_recipe_hashes(self):
        self.enable_composer_fixture()
        shared_source = self.add_shared_recipe_unit("distinct-tu.cpp")
        second_header = entropy.generate_shape(2, 2).encode("utf-8")
        second_sha = digest(second_header)
        second_id = f"d_{second_sha[:12]}"
        first_sha = self.document["translation_units"][0]["donors"][0][
            "recipe"
        ]["generated_header_sha256"]
        self.assertNotEqual(second_id, self.recipe_id)
        second_unit = self.document["translation_units"][1]
        second_unit["donors"] = [{
            "id": second_id,
            "status": "compiler_generated_current_source",
            "authenticity": "synthetic_baseline_only",
            "recipe": {
                "kind": "declaration_shape",
                "classes": 2,
                "functions": 2,
                "generated_header_sha256": second_sha,
                "emission_policy": "non_emitting_declarations_only",
                "authenticity_rationale": (
                    "A distinct non-emitting declaration family proves that "
                    "recipe and compiler-output hashes are owned per listed TU."
                ),
            },
        }]
        second_unit["functions"][0]["donor"] = second_id
        self.write_manifest()

        self.assertEqual(byte_identity.main(self.plan_args()), 0)
        first_output = self.materialize()
        second_output = byte_identity.recipe_output(
            self.build_dir, second_id, second_sha
        )
        self.materialize_recipe(second_id, second_output)
        state = byte_identity.validate_manifest(
            self.manifest, self.source_dir, self.build_dir
        )
        self.assertEqual(
            [recipe["id"] for recipe in state["recipes"]],
            [self.recipe_id, second_id],
        )
        self.assertEqual(
            [
                recipe["recipe"]["generated_header_sha256"]
                for recipe in state["recipes"]
            ],
            [first_sha, second_sha],
        )

        commands = []
        outputs = []
        for index, source in enumerate((self.source, shared_source)):
            output = self.build_dir / f"objects/distinct-tu-{index}.obj"
            pdb = self.build_dir / f"objects/distinct-tu-{index}.pdb"
            output.parent.mkdir(parents=True, exist_ok=True)
            commands.append(self.launch_args(output, pdb, source=source))
            outputs.append(output)
        previous = Path.cwd()
        with self.fake_control(
            SEED_OBJ=str(self.seed_fixture),
            DONOR_OBJ=str(self.donor_fixture),
            DONOR_MAP={
                first_output.name: str(self.donor_fixture),
                second_output.name: str(self.donor_fixture),
            },
        ):
            try:
                os.chdir(self.build_dir)
                for command in commands:
                    self.assertEqual(
                        self.run_standalone_producer_diagnostic(command), 0
                    )
            finally:
                os.chdir(previous)

        expected = (
            (self.source, self.recipe_id, first_sha),
            (shared_source, second_id, second_sha),
        )
        for source, recipe_id, header_sha in expected:
            audit = json.loads(byte_identity.audit_object_path(
                self.build_dir, "fixture",
                source.relative_to(self.source_dir).as_posix(),
            ).read_text())
            self.assertEqual(audit["recipes"], [recipe_id])
            self.assertEqual(len(audit["donors"]), 1)
            donor = audit["donors"][0]
            self.assertEqual(donor["recipe_id"], recipe_id)
            self.assertEqual(donor["header_sha256"], header_sha)
            self.assertEqual(
                donor["object_sha256"],
                byte_identity.sha256_file(Path(donor["object"])),
            )
            self.assertEqual(
                audit["composition"][0]["recipe_id"], recipe_id
            )
        self.assertEqual(byte_identity.main(self.verify_args()), 2)
        self.assertFalse(
            (self.build_dir / "byte-identity/audit/framework-verdict.json")
            .exists()
        )

    def test_reused_recipe_requires_identical_definition(self):
        self.enable_composer_fixture()
        self.add_shared_recipe_unit()
        self.document["translation_units"][1]["donors"][0]["recipe"][
            "authenticity_rationale"
        ] += " Conflicting duplicate definition."
        self.write_manifest()
        self.assertEqual(byte_identity.main(self.plan_args()), 2)
        self.assertFalse(self.plan.exists())

    def test_native_fpo_composer_reconstructs_complete_closure(self):
        seed = make_fpo_coff()
        donor = make_fpo_coff(donor=True)
        header = entropy.generate_shape(1, 1).encode("utf-8")
        output, detail = byte_identity.compose_equal_linked_span_fpo(
            seed,
            donor,
            fpo_function_record(donor),
            byte_identity.declaration_identifiers(header),
        )
        seed_coff = byte_identity.CoffObject(seed)
        donor_coff = byte_identity.CoffObject(donor)
        output_coff = byte_identity.CoffObject(output)
        self.assertEqual(len(output), len(seed) + 7)
        self.assertEqual(
            byte_identity.coff_body(output_coff, output_coff.sections[0]),
            byte_identity.coff_body(donor_coff, donor_coff.sections[0]),
        )
        self.assertEqual(
            byte_identity.coff_body(output_coff, output_coff.sections[3]),
            byte_identity.coff_body(seed_coff, seed_coff.sections[3]),
        )
        self.assertEqual(detail["retail_payload_bytes_read"], 0)
        self.assertEqual(detail["coff_line_rows"], 3)
        self.assertEqual(detail["fpo_policy"], "whole_donor_debug_F_record")

    def test_native_fpo_composer_pins_every_fpo_data_field_and_raw_record(self):
        seed = make_fpo_coff()
        donor = make_fpo_coff(donor=True)
        mutations = {
            "ulOffStart": 1,
            "cbProcSize": 32,
            "cdwLocals": 4,
            "cdwParams": 3,
            "cbProlog": 6,
            "cbRegs": 3,
            "fHasSEH": 1,
            "fUseBP": 0,
            "reserved": 1,
            "cbFrame": 2,
            "raw_sha256": "0" * 64,
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                function = fpo_function_record(donor)
                function["expected_donor_fpo"][field] = replacement
                with self.assertRaises(byte_identity.ByteIdentityError):
                    byte_identity.compose_equal_linked_span_fpo(
                        seed,
                        donor,
                        function,
                        {"ClassAlpha", "FunctionAlpha"},
                    )

    def test_two_donor_two_comdat_diagnostic_compile_has_no_terminal_claim(self):
        seed, first_donor, second_donor = self.enable_two_composer_fixture()
        self.assertEqual(byte_identity.main(self.plan_args()), 0)
        first_output = self.materialize()
        second_sha = self.document["translation_units"][0]["donors"][1][
            "recipe"
        ]["generated_header_sha256"]
        second_output = byte_identity.recipe_output(
            self.build_dir, self.second_recipe_id, second_sha
        )
        self.materialize_recipe(self.second_recipe_id, second_output)

        output = self.build_dir / "objects/two-comdat.obj"
        pdb = self.build_dir / "objects/two-comdat.pdb"
        count = self.directory / "two-comdat-count.txt"
        output.parent.mkdir(parents=True)
        launch_arguments = self.launch_args(output, pdb)
        previous = Path.cwd()
        with (
            self.fake_control(
                SEED_OBJ=str(self.seed_fixture),
                DONOR_OBJ=str(self.first_donor_fixture),
                DONOR_MAP={
                    first_output.name: str(self.first_donor_fixture),
                    second_output.name: str(self.second_donor_fixture),
                },
                COUNT_FILE=str(count),
            ),
            self.standalone_producer_diagnostic(),
        ):
            try:
                os.chdir(self.build_dir)
                result = byte_identity.main(launch_arguments)
            finally:
                os.chdir(previous)
        self.assertEqual(result, 0)
        # One preauthenticated-projection dependency pass plus one seed and
        # two donor compiles are resident producer actions.
        self.assertEqual(count.read_text(), "4")

        audit_path = byte_identity.audit_object_path(
            self.build_dir, "fixture", "src/unit.cpp"
        )
        audit = json.loads(audit_path.read_text())
        self.assertEqual(
            audit["recipes"], [self.recipe_id, self.second_recipe_id]
        )
        self.assertEqual(
            [item["recipe_id"] for item in audit["donors"]],
            [self.recipe_id, self.second_recipe_id],
        )
        self.assertEqual(
            [item["mangled"] for item in audit["composition"]],
            [TARGET_SYMBOL, SECOND_TARGET_SYMBOL],
        )
        self.assertEqual(
            [item["recipe_id"] for item in audit["composition"]],
            [self.recipe_id, self.second_recipe_id],
        )
        self.assertEqual(
            len(output.read_bytes()), len(Path(audit["seed_object"]).read_bytes()) + 14
        )
        self.assertEqual(
            byte_identity.coff_body(
                byte_identity.CoffObject(output.read_bytes()),
                byte_identity.CoffObject(output.read_bytes()).sections[0],
            ),
            byte_identity.coff_body(
                byte_identity.CoffObject(first_donor),
                byte_identity.CoffObject(first_donor).sections[0],
            ),
        )
        self.assertEqual(
            byte_identity.coff_body(
                byte_identity.CoffObject(output.read_bytes()),
                byte_identity.CoffObject(output.read_bytes()).sections[3],
            ),
            byte_identity.coff_body(
                byte_identity.CoffObject(second_donor),
                byte_identity.CoffObject(second_donor).sections[3],
            ),
        )
        seed_pdb = Path(audit["seed_pdb"])
        self.assertTrue(seed_pdb.is_file())
        self.assertEqual(pdb.read_bytes(), seed_pdb.read_bytes())
        for donor in audit["donors"]:
            donor_pdb = Path(donor["pdb"])
            self.assertTrue(donor_pdb.is_file())
            self.assertEqual(
                byte_identity.embedded_pdb_references(
                    Path(donor["object"]), pdb
                ),
                donor["embedded_pdb_references"],
            )
        with self.standalone_producer_diagnostic():
            self.assertEqual(byte_identity.main(self.verify_args()), 2)
        self.assertFalse(
            (self.build_dir / "byte-identity/audit/framework-verdict.json")
            .exists()
        )

    def test_native_fpo_composer_rejects_semantic_relocation_mismatch(self):
        seed = make_fpo_coff()
        donor = make_fpo_coff(donor=True, external_symbol="?Different@@YAXXZ")
        with self.assertRaises(byte_identity.ByteIdentityError):
            byte_identity.compose_equal_linked_span_fpo(
                seed,
                donor,
                fpo_function_record(donor),
                byte_identity.declaration_identifiers(
                    entropy.generate_shape(1, 1).encode("utf-8")
                ),
            )

    def test_native_fpo_composer_rejects_xdata_closure(self):
        seed = make_fpo_coff(closure_f_name=".xdata")
        donor = make_fpo_coff(donor=True, closure_f_name=".xdata")
        with self.assertRaisesRegex(byte_identity.ByteIdentityError, "xdata"):
            byte_identity.compose_equal_linked_span_fpo(
                seed,
                donor,
                fpo_function_record(make_fpo_coff(donor=True)),
                byte_identity.declaration_identifiers(
                    entropy.generate_shape(1, 1).encode("utf-8")
                ),
            )

    def test_native_fpo_composer_rejects_emitted_shape_symbol(self):
        seed = make_fpo_coff()
        donor = make_fpo_coff(donor=True, shape_symbol=True)
        with self.assertRaisesRegex(byte_identity.ByteIdentityError, "emitted COFF symbols"):
            byte_identity.compose_equal_linked_span_fpo(
                seed,
                donor,
                fpo_function_record(donor),
                byte_identity.declaration_identifiers(
                    entropy.generate_shape(1, 1).encode("utf-8")
                ),
            )

    def test_native_fpo_composer_rejects_function_aux_index_drift(self):
        seed = make_fpo_coff()
        donor = bytearray(make_fpo_coff(donor=True))
        donor_coff = byte_identity.CoffObject(bytes(donor))
        function_index, function_symbol = byte_identity.function_symbol(
            donor_coff, TARGET_SYMBOL, 1
        )
        self.assertEqual(function_symbol["aux_count"], 1)
        struct.pack_into(
            "<I", donor,
            donor_coff.symbol_offset + (function_index + 1) * 18 + 12,
            0x1234,
        )
        donor = bytes(donor)
        with self.assertRaisesRegex(byte_identity.ByteIdentityError, "tag/next-function"):
            byte_identity.compose_equal_linked_span_fpo(
                seed,
                donor,
                fpo_function_record(donor),
                byte_identity.declaration_identifiers(
                    entropy.generate_shape(1, 1).encode("utf-8")
                ),
            )

    def test_native_fpo_composer_rejects_ef_aux_index_drift(self):
        seed = make_fpo_coff()
        donor = bytearray(make_fpo_coff(donor=True))
        donor_coff = byte_identity.CoffObject(bytes(donor))
        end_index, end_symbol = byte_identity.marker_symbol(donor_coff, ".ef", 1)
        self.assertEqual(end_symbol["aux_count"], 1)
        struct.pack_into(
            "<I", donor,
            donor_coff.symbol_offset + (end_index + 1) * 18 + 12,
            0x1234,
        )
        donor = bytes(donor)
        with self.assertRaisesRegex(byte_identity.ByteIdentityError, "tag/next-function"):
            byte_identity.compose_equal_linked_span_fpo(
                seed,
                donor,
                fpo_function_record(donor),
                byte_identity.declaration_identifiers(
                    entropy.generate_shape(1, 1).encode("utf-8")
                ),
            )

    def test_native_fpo_composer_rejects_linker_directive_payload(self):
        seed = make_fpo_coff()
        donor = make_fpo_coff(donor=True, directive_payload=b"/DEFAULTLIB:changed")
        with self.assertRaisesRegex(byte_identity.ByteIdentityError, "directive/import/CRT"):
            byte_identity.compose_equal_linked_span_fpo(
                seed,
                donor,
                fpo_function_record(donor),
                byte_identity.declaration_identifiers(
                    entropy.generate_shape(1, 1).encode("utf-8")
                ),
            )

    def test_linker_payload_accepts_only_raw_relocation_symbol_index_drift(self):
        seed = byte_identity.CoffObject(make_fwd_xdata_payload_coff())
        donor = byte_identity.CoffObject(
            make_fwd_xdata_payload_coff(reverse_symbols=True)
        )
        seed_xdata = seed.sections[1]
        donor_xdata = donor.sections[1]
        self.assertNotEqual(
            byte_identity.coff_table(seed, seed_xdata, "relocations"),
            byte_identity.coff_table(donor, donor_xdata, "relocations"),
        )
        seed_rows = byte_identity.detailed_relocations(seed, seed_xdata)
        donor_rows = byte_identity.detailed_relocations(donor, donor_xdata)
        self.assertNotEqual(
            [row["symbol_index"] for row in seed_rows],
            [row["symbol_index"] for row in donor_rows],
        )
        semantic_fields = (
            "ordinal", "offset", "type", "width", "addend", "target",
            "target_section", "target_value", "target_type", "target_storage",
        )
        self.assertEqual(
            [tuple(row[field] for field in semantic_fields) for row in seed_rows],
            [tuple(row[field] for field in semantic_fields) for row in donor_rows],
        )
        self.assertEqual(
            byte_identity.coff_body(seed, seed_xdata),
            byte_identity.coff_body(donor, donor_xdata),
        )
        self.assertEqual(
            byte_identity.linker_payload_multiset(seed),
            byte_identity.linker_payload_multiset(donor),
        )

    def test_linker_payload_rejects_resolved_xdata_semantic_drift(self):
        seed = byte_identity.CoffObject(make_fwd_xdata_payload_coff())
        cases = {
            "offset": {"first_offset_delta": 1},
            "type": {"first_type": 0x0007},
            "addend": {"first_addend": 7},
            # S81b fwd03's body was unchanged while all twelve local xdata
            # relocation targets moved by three. This must remain fatal.
            "fwd03-target-value": {"target_value_delta": 3},
        }
        for label, options in cases.items():
            with self.subTest(label=label):
                donor = byte_identity.CoffObject(
                    make_fwd_xdata_payload_coff(
                        reverse_symbols=True, **options
                    )
                )
                if label == "fwd03-target-value":
                    self.assertEqual(
                        byte_identity.coff_body(seed, seed.sections[1]),
                        byte_identity.coff_body(donor, donor.sections[1]),
                    )
                    seed_values = [
                        row["target_value"] for row in
                        byte_identity.detailed_relocations(seed, seed.sections[1])
                    ]
                    donor_values = [
                        row["target_value"] for row in
                        byte_identity.detailed_relocations(
                            donor, donor.sections[1]
                        )
                    ]
                    self.assertEqual(
                        donor_values, [value + 3 for value in seed_values]
                    )
                self.assertNotEqual(
                    byte_identity.linker_payload_multiset(seed),
                    byte_identity.linker_payload_multiset(donor),
                )

    def test_invalidate_removes_stale_framework_verdict(self):
        verdict = self.build_dir / "byte-identity/audit/framework-verdict.json"
        verdict.parent.mkdir(parents=True)
        verdict.write_text('{"byte_identity_complete": false}\n')
        self.assertEqual(
            byte_identity.main(["invalidate", "--build-dir", str(self.build_dir)]),
            0,
        )
        self.assertFalse(verdict.exists())

    def test_final_completion_rejects_copied_retail_image_and_synthetic_report(self):
        _, image_output, report, rows = self.enable_final_image_fixture()
        self.materialize()
        state = byte_identity.validate_manifest(
            self.manifest, self.source_dir, self.build_dir,
            configured_compiler=str(self.compiler),
        )
        for archive in state["archives"]:
            self.assertEqual(byte_identity.main([
                "materialize-archive",
                "--manifest", str(self.manifest),
                "--source-dir", str(self.source_dir),
                "--build-dir", str(self.build_dir),
                "--identity", archive["identity"],
                "--output", archive["output"],
            ]), 0)
        # A byte-for-byte retail DLL and a synthetically perfect JSON report
        # are deliberately insufficient: neither has the nonce-bound
        # LINK->PDB/MAP->reccmp producer chain.
        verdict_path = self.build_dir / "byte-identity/audit/framework-verdict.json"
        self.assertEqual(byte_identity.main(self.complete_args()), 2)
        self.assertFalse(verdict_path.exists())

        malformed = json.loads(report.read_text())
        malformed["data"][37]["matching"] = 1
        report.write_text(
            json.dumps(malformed, separators=(",", ":")) + "\n"
        )
        self.assertEqual(byte_identity.main(self.complete_args()), 2)
        self.assertFalse(verdict_path.exists())

        report.write_text(json.dumps({
            "file": "LEGO1.DLL", "format": 1, "timestamp": 1.0,
            "data": rows,
        }, separators=(",", ":")) + "\n")
        image_output.write_bytes(image_output.read_bytes() + b"NOT-RETAIL")
        self.assertEqual(byte_identity.main(self.complete_args()), 2)
        self.assertFalse(verdict_path.exists())

    def test_iteration_report_requires_exact_4816_score_set_with_zero_losses(self):
        _, _, _, complete_rows = self.enable_final_image_fixture()
        rows = json.loads(json.dumps(complete_rows))
        for row in rows[4816:]:
            row["matching"] = 0.5
        state = byte_identity.validate_manifest(
            self.manifest, self.source_dir, self.build_dir,
            configured_compiler=str(self.compiler),
            compiler_id="MSVC", compiler_version="10.20",
            generator="Ninja",
        )
        report_data = json.dumps({
            "file": "LEGO1.DLL", "format": 1, "timestamp": 1.0,
            "data": rows,
        }, separators=(",", ":")).encode("utf-8")
        result = byte_identity.validate_iteration_reccmp_report(
            report_data, state["images"][0]
        )
        self.assertEqual(result["row_count"], 4933)
        self.assertEqual(result["raw_1_0_count"], 4816)
        changed_set = json.loads(json.dumps(rows))
        changed_set[0]["matching"] = 0.5
        changed_set[4816]["matching"] = 1.0
        with self.assertRaises(byte_identity.ByteIdentityError):
            byte_identity.validate_iteration_reccmp_report(
                json.dumps({
                    "file": "LEGO1.DLL", "format": 1, "timestamp": 1.0,
                    "data": changed_set,
                }, separators=(",", ":")).encode("utf-8"),
                state["images"][0],
            )
        loss = json.loads(json.dumps(rows))
        loss[0]["matching"] = 0.5
        with self.assertRaises(byte_identity.ByteIdentityError):
            byte_identity.validate_iteration_reccmp_report(
                json.dumps({
                    "file": "LEGO1.DLL", "format": 1, "timestamp": 1.0,
                    "data": loss,
                }, separators=(",", ":")).encode("utf-8"),
                state["images"][0],
            )

    def test_final_image_manifest_is_exactly_typed_and_pinned(self):
        self.enable_final_image_fixture()
        state = byte_identity.validate_manifest(
            self.manifest,
            self.source_dir,
            self.build_dir,
            configured_compiler=str(self.compiler),
            compiler_id="MSVC",
            compiler_version="10.20",
            generator="Ninja",
        )
        self.assertEqual(state["images"][0]["required_row_count"], 4933)
        mutations = (
            ("required_row_count", True),
            ("required_row_count", 4932),
            ("original_md5", "0" * 32),
            ("row_identity_sha256", "0" * 63),
            ("reccmp_report", "elsewhere/LEGO1.json"),
        )
        original = json.loads(json.dumps(self.document["images"]["LEGO1"]))
        for field, replacement in mutations:
            with self.subTest(field=field, replacement=replacement):
                candidate = json.loads(json.dumps(original))
                candidate[field] = replacement
                self.document["images"]["LEGO1"] = candidate
                self.write_manifest()
                with self.assertRaises(byte_identity.ByteIdentityError):
                    byte_identity.validate_manifest(
                        self.manifest,
                        self.source_dir,
                        self.build_dir,
                        configured_compiler=str(self.compiler),
                        compiler_id="MSVC",
                        compiler_version="10.20",
                        generator="Ninja",
                    )

    def test_final_image_requires_the_exact_two_archive_exception_set(self):
        self.enable_final_image_fixture()
        complete = json.loads(json.dumps(self.document["archives"]))
        self.assertEqual({item["identity"] for item in complete},
                         {"SmartHeap", "Smacker"})
        for label, subset in (("empty", []), ("smartheap-only", complete[:1]),
                              ("smacker-only", complete[1:])):
            with self.subTest(label=label):
                self.document["archives"] = subset
                self.write_manifest()
                with self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "exactly SmartHeap and Smacker",
                ):
                    byte_identity.validate_manifest(
                        self.manifest,
                        self.source_dir,
                        self.build_dir,
                        configured_compiler=str(self.compiler),
                        compiler_id="MSVC",
                        compiler_version="10.20",
                        generator="Ninja",
                    )

    def test_first_party_archive_rejects_hash_matching_scratch_and_external_objects(self):
        authentic = self.build_dir / "objects/authenticated.obj"
        scratch = self.build_dir / "scratch/hash-matching.obj"
        external = self.directory / "external-hash-matching.obj"
        for path in (authentic, scratch, external):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"IDENTICAL-FIRST-PARTY-OBJECT-BYTES")
        output = self.build_dir / "archives/fixture.lib"
        output.parent.mkdir(parents=True, exist_ok=True)
        with byte_identity.build_transaction(
            self.build_dir, exclusive=True, bootstrap_outer_session=True,
        ):
            expected = [
                byte_identity.producer_input_record(
                    authentic, "compiler_object"
                )
            ]
            self.assertEqual(
                expected[0]["sha256"], byte_identity.sha256_file(scratch)
            )
            self.assertEqual(
                expected[0]["sha256"], byte_identity.sha256_file(external)
            )
            self.assertEqual(
                byte_identity.ordered_first_party_archive_inputs(
                    [authentic], expected, "fixture archive"
                ),
                expected,
            )
            with self.assertRaisesRegex(
                byte_identity.ByteIdentityError,
                "exact audited target object/resource sequence",
            ):
                byte_identity.ordered_first_party_archive_inputs(
                    [scratch], expected, "fixture archive"
                )
            with self.assertRaises(byte_identity.ByteIdentityError):
                byte_identity.parse_archive_command(
                    [
                        str(self.compiler), f"/OUT:{output}", str(external),
                    ],
                    self.build_dir,
                )

    def test_terminal_link_rejects_hash_matching_scratch_first_party_archives(self):
        authentic = self.build_dir / "archives/authenticated-fixture.lib"
        scratch = self.build_dir / "scratch/hash-matching-fixture.lib"
        external = self.directory / "external/hash-matching-fixture.lib"
        for path in (authentic, scratch, external):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"!<arch>\nIDENTICAL-FIRST-PARTY-ARCHIVE")
        imported_names = sorted(byte_identity.REQUIRED_IMPORTED_TARGETS)
        imported = [
            {
                "name": name,
                "properties": {"INTERFACE_LINK_LIBRARIES": []},
            }
            for name in imported_names
        ]
        sdk = [
            {
                "absolute_path": str(self.source_dir / relative),
                "sha256": "1" * 64,
            }
            for relative in sorted(byte_identity.REQUIRED_PROJECT_SDK_LIBRARIES)
        ]
        direct = self.build_dir / "objects/lego1.obj"
        direct.parent.mkdir(parents=True, exist_ok=True)
        direct.write_bytes(b"fixture-direct-object")
        direct_record = {
            "role": "compiler_object", "path": str(direct),
            "sha256": byte_identity.sha256_file(direct),
            "size": direct.stat().st_size, "target": "lego1",
            "source": "src/lego1.cpp", "target_ordinal": 0,
            "audit": str(self.build_dir / "audit-lego1.json"),
            "audit_sha256": "5" * 64,
        }
        state = {
            "build_dir": str(self.build_dir),
            "images": [{"original_path": str(self.source_dir / "retail.dll")}],
            "archives": [
                {
                    "identity": "SmartHeap",
                    "imported_target": "SmartHeap::SmartHeap",
                },
                {
                    "identity": "Smacker",
                    "imported_target": "Smacker::Smacker",
                },
            ],
            "terminal_producers": {"link": {
                "imported_targets": imported,
                "project_sdk_libraries": sdk,
                "library_trees": [
                    {"absolute_path": str(self.directory / "sealed-msvc-lib")},
                    {"absolute_path": str(self.directory / "sealed-mfc-lib")},
                ],
                "ordered_library_occurrence_count": 1,
                "ordered_library_identity_sha256": digest(
                    b"hash-matching-fixture.lib\n"
                ),
                "generator_standard_libraries": {
                    "configuration": "RelWithDebInfo", "base": [],
                    "configuration_specific": [],
                },
            }},
        }
        inventory = {"entries": [], "inputs": [], "link_graph": [
            {
                "target": "lego1",
                "resolved_links": ["fixture", *imported_names],
            },
            {"target": "fixture", "resolved_links": []},
        ], "targets": [], "generator_standard_libraries": {
            "configuration": "RelWithDebInfo", "base": [],
            "configuration_specific": [],
        }}
        authentic_record = {
            "role": "first_party_archive", "path": str(authentic),
            "sha256": byte_identity.sha256_file(authentic),
            "size": authentic.stat().st_size, "target": "fixture",
            "audit": str(self.build_dir / "audit-fixture.json"),
            "audit_sha256": "2" * 64,
        }
        authorized = [
            {
                "role": "authorized_third_party_archive",
                "path": str(self.build_dir / f"archives/{identity}.lib"),
                "sha256": "3" * 64, "size": 8, "identity": identity,
                "audit": str(self.build_dir / f"audit-{identity}.json"),
                "audit_sha256": "4" * 64,
            }
            for identity in ("SmartHeap", "Smacker")
        ]
        originals = {
            name: getattr(byte_identity, name)
            for name in (
                "compiler_output_records", "resource_output_records",
                "first_party_archive_records", "authorized_archive_records",
                "sealed_producer_input_record",
            )
        }
        byte_identity.compiler_output_records = (
            lambda *_args, **_kwargs: [direct_record]
        )
        byte_identity.resource_output_records = lambda *_args, **_kwargs: []
        byte_identity.first_party_archive_records = (
            lambda *_args, **_kwargs: [authentic_record]
        )
        byte_identity.authorized_archive_records = (
            lambda *_args, **_kwargs: authorized
        )
        byte_identity.sealed_producer_input_record = (
            lambda logical, _snapshot, role: {
                "role": role, "path": str(logical), "snapshot_path": "sealed",
                "sha256": "1" * 64, "size": 1,
            }
        )
        try:
            with byte_identity.build_transaction(
                self.build_dir, exclusive=True, bootstrap_outer_session=True,
            ):
                for candidate in (scratch, external):
                    with self.subTest(candidate=candidate):
                        self.assertEqual(
                            authentic_record["sha256"],
                            byte_identity.sha256_file(candidate),
                        )
                        with self.assertRaisesRegex(
                            byte_identity.ByteIdentityError,
                            "outside every exact manifest pin",
                        ):
                            byte_identity.terminal_link_ordered_inputs(
                                state,
                                inventory,
                                {"nonce": "fixture"},
                                {
                                    "direct": [direct], "libraries": [candidate],
                                    "definition": self.source_dir / "fixture.def",
                                },
                            )
        finally:
            for name, value in originals.items():
                setattr(byte_identity, name, value)

    def test_terminal_link_graph_recurses_only_through_attested_targets(self):
        def graph_entry(target, resolved):
            return {
                "target": target,
                "properties": {
                    name: []
                    for name in byte_identity.NORMAL_TARGET_LINK_PROPERTIES
                },
                "resolved_links": resolved,
            }

        imported = [
            {
                "name": name,
                "properties": {"INTERFACE_LINK_LIBRARIES": []},
            }
            for name in sorted(byte_identity.REQUIRED_IMPORTED_TARGETS)
        ]
        state = {"terminal_producers": {"link": {
            "imported_targets": imported,
            "generator_standard_libraries": {
                "configuration": "RelWithDebInfo", "base": [],
                "configuration_specific": [],
            },
        }}}
        inventory = {"link_graph": [
            graph_entry("lego1", [
                "omni", "SmartHeap::SmartHeap", "Smacker::Smacker",
                "DirectX5::DirectX5", "Vec::Vec", "libcmt",
            ]),
            graph_entry("omni", ["roi", "mfc42"]),
            graph_entry("roi", []),
        ], "generator_standard_libraries": {
            "configuration": "RelWithDebInfo", "base": [],
            "configuration_specific": [],
        }}
        normal, imported_reachable, libraries = (
            byte_identity.terminal_link_graph_authority(state, inventory)
        )
        self.assertEqual(normal, {"lego1", "omni", "roi"})
        self.assertEqual(
            imported_reachable, byte_identity.REQUIRED_IMPORTED_TARGETS
        )
        self.assertEqual(libraries, {"libcmt.lib", "mfc42.lib"})

        forged = json.loads(json.dumps(state))
        forged["terminal_producers"]["link"]["imported_targets"][0][
            "properties"
        ]["INTERFACE_LINK_LIBRARIES"] = ["Scratch::Opaque"]
        with self.assertRaisesRegex(
            byte_identity.ByteIdentityError,
            "not a target or a simple library name",
        ):
            byte_identity.terminal_link_graph_authority(forged, inventory)

    def test_live_generator_standard_library_tail_is_exactly_pinned(self):
        checked = json.loads((TOOLS / "byte_identity_manifest.json").read_text())
        contract = checked["terminal_producers"]["link"][
            "generator_standard_libraries"
        ]
        expected = [
            "user32.lib", "gdi32.lib", "winspool.lib", "comdlg32.lib",
            "advapi32.lib", "shell32.lib", "ole32.lib", "oleaut32.lib",
            "uuid.lib", "odbc32.lib", "odbccp32.lib",
        ]
        self.assertEqual(contract, {
            "configuration": "RelWithDebInfo", "base": expected,
            "configuration_specific": [],
        })
        self.assertNotIn("kernel32.lib", expected)
        state = {"terminal_producers": {"link": {
            "generator_standard_libraries": contract,
        }}}
        observed = byte_identity.normalized_generator_standard_libraries(
            state, "RelWithDebInfo", "11", expected, "0", []
        )
        inventory = {"generator_standard_libraries": observed}
        byte_identity.require_terminal_generator_standard_library_suffix(
            state, inventory, ["fixture.lib", *expected], "fixture"
        )
        with self.assertRaisesRegex(
            byte_identity.ByteIdentityError, "live generator standard-library",
        ):
            byte_identity.normalized_generator_standard_libraries(
                state, "RelWithDebInfo", "12",
                ["kernel32.lib", *expected], "0", [],
            )
        with self.assertRaisesRegex(
            byte_identity.ByteIdentityError, "live generator standard-library",
        ):
            byte_identity.normalized_generator_standard_libraries(
                state, "RelWithDebInfo", "11", expected, "1", ["user32.lib"],
            )
        with self.assertRaisesRegex(
            byte_identity.ByteIdentityError,
            "generator standard-library suffix differs",
        ):
            byte_identity.require_terminal_generator_standard_library_suffix(
                state, inventory,
                ["fixture.lib", "kernel32.lib", *expected[:-1]], "fixture",
            )

    def test_terminal_project_sdk_libraries_are_an_exact_hash_pinned_set(self):
        self.enable_final_image_fixture()
        complete = json.loads(json.dumps(
            self.document["terminal_producers"]["link"][
                "project_sdk_libraries"
            ]
        ))
        self.assertEqual(
            {item["path"] for item in complete},
            set(byte_identity.REQUIRED_PROJECT_SDK_LIBRARIES),
        )
        mutations = (
            complete[:-1],
            [*complete, {"path": "3rdparty/dx5/lib/opaque.lib",
                         "sha256": "0" * 64}],
        )
        for index, replacement in enumerate(mutations):
            with self.subTest(mutation=index):
                self.document["terminal_producers"]["link"][
                    "project_sdk_libraries"
                ] = replacement
                self.write_manifest()
                with self.assertRaises(byte_identity.ByteIdentityError):
                    byte_identity.validate_manifest(
                        self.manifest,
                        self.source_dir,
                        self.build_dir,
                        configured_compiler=str(self.compiler),
                    )

    def test_terminal_link_tool_roles_apply_host_permissions_exactly(self):
        self.enable_final_image_fixture()
        state = byte_identity.validate_manifest(
            self.manifest, self.source_dir, self.build_dir,
            configured_compiler=str(self.compiler),
        )
        tools = {
            item["role"]: Path(item["absolute_path"])
            for item in state["terminal_producers"]["link"]["tools"]
        }
        for role, path in tools.items():
            self.assertEqual(
                stat.S_IMODE(path.stat().st_mode),
                0o755 if role.endswith("_wrapper") else 0o644,
            )

        wrapper = tools["link_wrapper"]
        wrapper.chmod(0o644)
        try:
            with self.assertRaisesRegex(
                byte_identity.ByteIdentityError, "wrapper is not executable"
            ):
                byte_identity.validate_manifest(
                    self.manifest, self.source_dir, self.build_dir,
                    configured_compiler=str(self.compiler),
                )
        finally:
            wrapper.chmod(0o755)

        binary = tools["link_binary"]
        pristine = binary.read_bytes()
        binary.write_bytes(pristine + b"mutated")
        binary.chmod(0o644)
        try:
            with self.assertRaisesRegex(
                byte_identity.ByteIdentityError, "tool hash differs"
            ):
                byte_identity.validate_manifest(
                    self.manifest, self.source_dir, self.build_dir,
                    configured_compiler=str(self.compiler),
                )
        finally:
            binary.write_bytes(pristine)
            binary.chmod(0o644)

    def test_command_snapshot_seals_exact_directx_and_definition_inputs(self):
        self.enable_final_image_fixture()
        definition = self.source_dir / "LEGO1/lego1.def"
        definition.parent.mkdir(parents=True, exist_ok=True)
        definition.write_text("LIBRARY LEGO1\nEXPORTS\n")
        inventory_arguments = self.inventory_args()
        inventory_arguments.extend([
            "--input-entry", "fixture", str(definition), "LINKER_DEF",
        ])
        with (
            mock.patch.object(
                byte_identity, "relocate_private_macho",
                side_effect=self.mock_private_macho_relocation,
            ),
            mock.patch.object(
                byte_identity, "macho_loader_dependencies", return_value=[]
            ),
        ):
            self.assertEqual(byte_identity.main(inventory_arguments), 0)
        output = self.build_dir / "objects/unit.obj"
        pdb = self.build_dir / "objects/unit.pdb"
        self.attest_command(
            self.launch_args(output, pdb, ensure_inventory=False)
        )
        command_inventory = json.loads(
            byte_identity.command_inventory_path(self.build_dir).read_text()
        )
        generated = command_inventory["transport_snapshot"][
            "generated_external_inputs"
        ]
        expected_paths = {
            str(self.source_dir / relative)
            for relative in byte_identity.REQUIRED_PROJECT_SDK_LIBRARIES
        } | {str(definition)}
        self.assertEqual(
            {item["logical_path"] for item in generated}, expected_paths
        )
        self.assertEqual(
            [item["role"] for item in generated].count("linker_definition"), 1
        )
        self.assertEqual(
            [item["role"] for item in generated].count(
                "sealed_project_sdk_library"
            ),
            len(byte_identity.REQUIRED_PROJECT_SDK_LIBRARIES),
        )
        for item in generated:
            logical = Path(item["logical_path"])
            snapshot = Path(item["snapshot_path"])
            self.assertTrue(snapshot.is_relative_to(self.build_dir))
            self.assertEqual(snapshot.read_bytes(), logical.read_bytes())
            self.assertEqual(byte_identity.sha256_file(snapshot), item["sha256"])

    def test_command_snapshot_deduplicates_identity_not_search_order(self):
        shared = self.source_dir / "include/shared-command-root"
        other = self.source_dir / "include/other-command-root"
        shared.mkdir(parents=True)
        other.mkdir(parents=True)
        (shared / "shared.h").write_text("#define SHARED_COMMAND_ROOT 1\n")
        (other / "other.h").write_text("#define OTHER_COMMAND_ROOT 1\n")
        shared_pin = byte_identity.command_input_tree_identity(
            byte_identity.canonical_tree_snapshot(shared, hash_files=True)
        )
        other_pin = byte_identity.command_input_tree_identity(
            byte_identity.canonical_tree_snapshot(other, hash_files=True)
        )
        entries = [
            {"input_trees": [
                {"ordinal": 0, **shared_pin},
                {"ordinal": 3, **other_pin},
            ]},
            {"input_trees": [
                {"ordinal": 1, **other_pin},
                {"ordinal": 5, **shared_pin},
            ]},
        ]
        original_entries = json.loads(json.dumps(entries))
        state = {
            "manifest_sha256": digest(b"command-dedup-manifest"),
            "toolchain_fingerprint": digest(b"command-dedup-toolchain"),
            "build_dir": str(self.build_dir),
            "compiler_root": str(self.source_dir / "toolchain"),
            "required_absent_toolchain_files": [],
            "terminal_producers": {},
        }
        inventory = {
            "policy_sha256": digest(b"command-dedup-inventory-policy"),
            "inputs": [],
        }
        copied = []
        original_copy = byte_identity.copy_command_tree_to_snapshot

        def counted_copy(source, destination, expected):
            copied.append(str(source))
            return original_copy(source, destination, expected)

        with byte_identity.build_transaction(
            self.build_dir, exclusive=True, bootstrap_outer_session=True,
        ) as authority:
            with mock.patch.object(
                byte_identity, "copy_command_tree_to_snapshot",
                side_effect=counted_copy,
            ):
                document = byte_identity.materialize_command_snapshot(
                    state, inventory, entries, self.build_dir
                )
            self.assertEqual(copied.count(str(shared)), 1)
            self.assertEqual(copied.count(str(other)), 1)
            self.assertEqual(len(document["input_trees"]), 2)
            self.assertEqual(
                document["input_trees"],
                sorted((shared_pin, other_pin), key=lambda item: item["root"]),
            )
            self.assertEqual(entries, original_entries)
            byte_identity.validate_command_snapshot(
                entries, self.build_dir, document,
                state=state, inventory=inventory,
            )

            authority.atomic_write(
                byte_identity.inventory_path(self.build_dir),
                b"command-dedup-inventory\n",
            )
            payload = byte_identity.command_attestation_payload(
                state, inventory, digest(b"compile-database"),
                entries, document,
            )
            self.assertEqual(payload["entries"], original_entries)
            ordered_sha = digest(json.dumps(
                payload, sort_keys=True, separators=(",", ":")
            ).encode("utf-8"))
            reordered = json.loads(json.dumps(entries))
            reordered[0]["input_trees"].reverse()
            reordered_payload = byte_identity.command_attestation_payload(
                state, inventory, digest(b"compile-database"),
                reordered, document,
            )
            self.assertNotEqual(
                ordered_sha,
                digest(json.dumps(
                    reordered_payload, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")),
            )
            reordinaled = json.loads(json.dumps(entries))
            reordinaled[1]["input_trees"][1]["ordinal"] = 6
            reordinaled_payload = byte_identity.command_attestation_payload(
                state, inventory, digest(b"compile-database"),
                reordinaled, document,
            )
            self.assertNotEqual(
                ordered_sha,
                digest(json.dumps(
                    reordinaled_payload, sort_keys=True,
                    separators=(",", ":")
                ).encode("utf-8")),
            )

            for field in byte_identity.COMMAND_INPUT_TREE_IDENTITY_KEYS[1:]:
                with self.subTest(conflicting_duplicate_field=field):
                    conflicting = json.loads(json.dumps(entries))
                    candidate = conflicting[1]["input_trees"][1]
                    candidate[field] = (
                        candidate[field] + 1
                        if isinstance(candidate[field], int)
                        else digest(field.encode("ascii"))
                    )
                    with self.assertRaisesRegex(
                        byte_identity.ByteIdentityError,
                        "command snapshot input tree has conflicting pins",
                    ):
                        byte_identity.materialize_command_snapshot(
                            state, inventory, conflicting, self.build_dir
                        )
                    self.assertFalse(
                        byte_identity.command_snapshot_path(
                            self.build_dir
                        ).exists()
                    )

            for field in (
                "membership_sha256", "content_sha256", "metadata_sha256",
            ):
                with self.subTest(source_pin_field=field):
                    mismatched = json.loads(json.dumps(entries[:1]))
                    mismatched[0]["input_trees"][0][field] = digest(
                        f"source-{field}".encode("ascii")
                    )
                    with self.assertRaisesRegex(
                        byte_identity.ByteIdentityError,
                        "command snapshot source tree differs before copy",
                    ):
                        byte_identity.materialize_command_snapshot(
                            state, inventory, mismatched, self.build_dir
                        )
                    self.assertFalse(
                        byte_identity.command_snapshot_path(
                            self.build_dir
                        ).exists()
                    )

    def test_reccmp_tool_and_closure_are_consumed_from_run_private_snapshot(self):
        self.enable_final_image_fixture()
        with (
            mock.patch.object(
                byte_identity, "relocate_private_macho",
                side_effect=self.mock_private_macho_relocation,
            ),
            mock.patch.object(
                byte_identity, "macho_loader_dependencies", return_value=[]
            ),
        ):
            self.ensure_inventory()
        output = self.build_dir / "objects/unit.obj"
        pdb = self.build_dir / "objects/unit.pdb"
        self.attest_command(
            self.launch_args(output, pdb, ensure_inventory=False)
        )
        with (
            byte_identity.build_transaction(
                self.build_dir, exclusive=True, bootstrap_outer_session=True,
            ),
            byte_identity.resident_receipt_scope("7" * 64),
        ):
            state = byte_identity.validate_manifest(
                self.manifest,
                self.source_dir,
                self.build_dir,
                configured_compiler=str(self.compiler),
            )
            self.materialize_native_reccmp_fixture(state)
            projection = self.materialize_resident_projection_fixture(state)
            inventory = state["inventory"]
            command_inventory = state["command_inventory"]
            state["inventory_sha256"] = byte_identity.sha256_file(
                byte_identity.inventory_path(self.build_dir)
            )
            state["command_inventory_sha256"] = byte_identity.sha256_file(
                byte_identity.command_inventory_path(self.build_dir)
            )
            with (
                mock.patch.object(
                    byte_identity, "relocate_private_macho",
                    side_effect=self.mock_private_macho_relocation,
                ),
                mock.patch.object(
                    byte_identity, "macho_loader_dependencies", return_value=[]
                ),
            ):
                closure = byte_identity.terminal_reccmp_closure(state)
            self.assertTrue(closure)
            self.assertTrue(all(
                Path(item["snapshot_path"]).is_relative_to(
                    byte_identity.native_reccmp_snapshot_path(self.build_dir)
                )
                for item in closure
            ))
            toolchain_z = (
                byte_identity.toolchain_snapshot_path(self.build_dir) / "z"
            )
            self.assertFalse((toolchain_z / "__byte_identity_reccmp__").exists())
            for key in ("executable_path", "interpreter_path"):
                self.assertFalse(byte_identity.absolute_snapshot_seat(
                    toolchain_z, Path(
                        state["terminal_producers"]["reccmp"][key]
                    )
                ).exists())
            live_closure = self.fake_reccmp_closure / "runtime.dat"
            original_live = live_closure.read_bytes()
            live_closure.write_bytes(b"TRANSIENT-HOST-RECCMP-MUTATION")
            try:
                self.assertEqual(
                    byte_identity.terminal_reccmp_closure(state), closure
                )
                source_snapshot = self.build_dir / "sealed-reccmp-source"
                byte_identity.active_build_authority().mkdirs(source_snapshot)
                byte_identity.active_build_authority().atomic_write(
                    source_snapshot / "unit.cpp", b"int fixture;\n", mode=0o400
                )
                source_pin = byte_identity.canonical_tree_snapshot(
                    source_snapshot, hash_files=True
                )
                policy = state["terminal_producers"]["reccmp"]
                run = byte_identity.prepare_native_reccmp_run(
                    state=state,
                    build_dir=self.build_dir,
                    executable=Path(policy["executable_path"]),
                    source_snapshot=source_snapshot,
                    source_pin=source_pin,
                    generated_inputs=[
                        (
                            "retail_oracle",
                            self.source_dir / "legobin/LEGO1.DLL",
                            b"MZ-retail-fixture",
                        ),
                        (
                            "recompiled_image", self.build_dir / "LEGO1.DLL",
                            b"MZ-recompiled-fixture",
                        ),
                    ],
                )
                try:
                    self.assertEqual(
                        run["run"], Path(projection["root"]) / "native-reccmp"
                    )
                    self.assertTrue(run["interpreter"].is_relative_to(run["run"]))
                    self.assertTrue(run["executable"].is_relative_to(run["run"]))
                    self.assertTrue(
                        run["source_interpreter"].is_relative_to(run["run"])
                    )
                    self.assertEqual(
                        byte_identity.sha256_file(run["interpreter"]),
                        byte_identity.sha256_file(
                            byte_identity.native_reccmp_snapshot_path(
                                self.build_dir
                            ) / "runtime/bin/python3.12"
                        ),
                    )
                    self.assertEqual(
                        byte_identity.sha256_file(run["executable"]),
                        policy["executable_sha256"],
                    )
                    self.assertEqual(
                        byte_identity.sha256_file(run["source_interpreter"]),
                        policy["interpreter_sha256"],
                    )
                    sealed_native = byte_identity.native_reccmp_snapshot_path(
                        self.build_dir
                    )
                    self.assertNotEqual(
                        run["executable"].stat().st_ino,
                        (sealed_native / "tool/reccmp.py").stat().st_ino,
                    )
                    self.assertNotEqual(
                        run["interpreter"].stat().st_ino,
                        (sealed_native / "runtime/bin/python3.12").stat().st_ino,
                    )
                    environment = byte_identity.native_reccmp_environment(run)
                    self.assertEqual(
                        environment["WINEPREFIX"], str(run["prefix"])
                    )
                    self.assertEqual(
                        environment["PATH"],
                        str(run["wine_transport"]["bin"]),
                    )
                    self.assertEqual(environment["WINEDEBUG"], "-all")
                    self.assertNotIn(
                        "ISLE_BYTE_IDENTITY_VIRTUAL_Z_ROOT", environment
                    )
                    source_record = next(
                        item for item in run["closure_records"]
                        if item["role"] == "reccmp_source"
                    )
                    self.assertEqual(
                        Path(source_record["private_path"]),
                        run["pythonpath"] / "reccmp",
                    )
                    self.assertEqual(
                        environment["PYTHONPATH"].split(os.pathsep)[0],
                        str(run["pythonpath"]),
                    )
                    operands = {item["role"]: item for item in run["inputs"]}
                    for role in ("retail_oracle", "recompiled_image"):
                        physical = Path(operands[role]["physical"])
                        self.assertEqual(physical.name, "LEGO1.DLL")
                        self.assertEqual(physical.parent.name, role)
                    marker = self.directory / "editable-pth-executed"
                    probe_environment = dict(environment)
                    probe_environment.pop("PYTHONHOME")
                    probe_environment.pop("DYLD_PRINT_LIBRARIES")
                    probe_environment["PTH_MARKER"] = str(marker)
                    probe = subprocess.run(
                        [
                            sys.executable, "-S", "-c",
                            "import json,types,reccmp; "
                            "print(json.dumps([types.__file__,reccmp.__file__]))",
                        ],
                        capture_output=True, text=True,
                        env=probe_environment, cwd=run["cwd"],
                    )
                    self.assertEqual(
                        probe.returncode, 0, probe.stdout + probe.stderr
                    )
                    types_path, reccmp_path = json.loads(probe.stdout)
                    self.assertFalse(
                        Path(types_path).is_relative_to(
                            run["pythonpath"] / "reccmp"
                        )
                    )
                    self.assertTrue(
                        Path(reccmp_path).is_relative_to(
                            run["pythonpath"] / "reccmp"
                        )
                    )
                    self.assertFalse(marker.exists())
                    with mock.patch.object(
                        byte_identity, "run_child", return_value=(0, b"", False)
                    ) as drained:
                        byte_identity.drain_run_private_wineserver(
                            run, state, environment, phase="preflight"
                        )
                        byte_identity.drain_run_private_wineserver(
                            run, state, environment, phase="postflight"
                        )
                    self.assertEqual(drained.call_count, 4)
                    self.assertTrue(run["server_preflight_clear"])
                    self.assertTrue(run["server_postflight_clear"])
                    run["holder"].revalidate()
                finally:
                    byte_identity.cleanup_native_reccmp_run(run)
            finally:
                live_closure.write_bytes(original_live)

    def test_native_reccmp_snapshot_tamper_rejects_before_private_run(self):
        self.enable_final_image_fixture()
        with (
            mock.patch.object(
                byte_identity, "relocate_private_macho",
                side_effect=self.mock_private_macho_relocation,
            ),
            mock.patch.object(
                byte_identity, "macho_loader_dependencies", return_value=[]
            ),
        ):
            self.ensure_inventory()
        projected_object = self.build_dir / "objects/native-tamper.obj"
        projected_pdb = self.build_dir / "objects/native-tamper.pdb"
        self.attest_command(
            self.launch_args(
                projected_object, projected_pdb, ensure_inventory=False
            )
        )
        with (
            byte_identity.build_transaction(
                self.build_dir, exclusive=True, bootstrap_outer_session=True,
            ),
            byte_identity.resident_receipt_scope("8" * 64),
        ):
            state = byte_identity.validate_manifest(
                self.manifest, self.source_dir, self.build_dir,
                configured_compiler=str(self.compiler),
            )
            projection = self.materialize_resident_projection_fixture(state)
            self.materialize_native_reccmp_fixture(state)
            byte_identity.validate_native_reccmp_snapshot(
                state, self.build_dir
            )
            native = byte_identity.native_reccmp_snapshot_path(self.build_dir)
            byte_identity.active_build_authority().atomic_write(
                native / "tool/reccmp.py", b"tampered tool", mode=0o400
            )
            source = self.build_dir / "tamper-source"
            byte_identity.active_build_authority().mkdirs(source)
            byte_identity.active_build_authority().atomic_write(
                source / "unit.cpp", b"int fixture;\n", mode=0o400
            )
            source_pin = byte_identity.canonical_tree_snapshot(
                source, hash_files=True
            )
            with self.assertRaisesRegex(
                byte_identity.ByteIdentityError,
                "held compiler output was replaced|sealed reccmp executable changed",
            ):
                byte_identity.prepare_native_reccmp_run(
                    state=state, build_dir=self.build_dir,
                    executable=Path(
                        state["terminal_producers"]["reccmp"]["executable_path"]
                    ),
                    source_snapshot=source, source_pin=source_pin,
                    generated_inputs=[(
                        "image", self.build_dir / "LEGO1.DLL", b"MZ-fixture"
                    )],
                )
            self.assertFalse(
                (Path(projection["root"]) / "native-reccmp").exists()
            )
            native_runs = (
                self.build_dir / "byte-identity/native-runs/reccmp"
            )
            self.assertFalse(native_runs.exists() and any(
                path.name.startswith("run-") for path in native_runs.iterdir()
            ))

    def test_native_reccmp_run_is_transaction_owned_and_cold_recovered(self):
        self.enable_final_image_fixture()
        with (
            mock.patch.object(
                byte_identity, "relocate_private_macho",
                side_effect=self.mock_private_macho_relocation,
            ),
            mock.patch.object(
                byte_identity, "macho_loader_dependencies", return_value=[]
            ),
        ):
            self.ensure_inventory()
        output = self.build_dir / "objects/native-owned.obj"
        pdb = self.build_dir / "objects/native-owned.pdb"
        self.attest_command(
            self.launch_args(output, pdb, ensure_inventory=False)
        )
        nonce = "c" * 64
        marker_path = byte_identity.execution_projection_recovery_path(
            self.build_dir
        )
        sibling = (
            self.build_dir
            / "byte-identity/execution-projections/session-sibling/sentinel"
        )
        with (
            byte_identity.build_transaction(
                self.build_dir, exclusive=True, bootstrap_outer_session=True,
            ) as authority,
            byte_identity.resident_receipt_scope(nonce),
        ):
            authority.mkdirs(sibling.parent)
            authority.atomic_write(sibling, b"preserve-native-sibling\n")
            state = byte_identity.validate_manifest(
                self.manifest, self.source_dir, self.build_dir,
                configured_compiler=str(self.compiler),
            )
            projection = self.materialize_resident_projection_fixture(state)
            self.materialize_native_reccmp_fixture(state)
            source = self.build_dir / "native-owned-source"
            authority.mkdirs(source)
            authority.atomic_write(
                source / "unit.cpp", b"int fixture;\n", mode=0o400
            )
            source_pin = byte_identity.canonical_tree_snapshot(
                source, hash_files=True
            )
            policy = state["terminal_producers"]["reccmp"]
            run = byte_identity.prepare_native_reccmp_run(
                state=state, build_dir=self.build_dir,
                executable=Path(policy["executable_path"]),
                source_snapshot=source, source_pin=source_pin,
                generated_inputs=[
                    (
                        "retail_oracle",
                        self.source_dir / "legobin/LEGO1.DLL",
                        b"MZ-retail-fixture",
                    ),
                    (
                        "recompiled_image", self.build_dir / "LEGO1.DLL",
                        b"MZ-recompiled-fixture",
                    ),
                ],
            )
            transaction_root = Path(projection["root"])
            self.assertEqual(
                transaction_root,
                self.build_dir
                / f"byte-identity/execution-projections/session-{nonce}",
            )
            self.assertEqual(run["run"], transaction_root / "native-reccmp")
            self.assertIs(projection["native_reccmp_run"], run)
            self.assertFalse(
                (self.build_dir / "byte-identity/native-runs/reccmp").exists()
            )
            marker = json.loads(marker_path.read_text())
            self.assertEqual(marker["phase"], "child-may-have-started")
            self.assertEqual(marker["native_reccmp_prefix"], str(run["prefix"]))

            # Simulate process death: neither in-memory holder survives, while
            # the prepublished marker retains the one exact transaction root.
            run["holder"].close()
            projection["holder"].close()
            authority.execution_projection = None
            projection["native_reccmp_run"] = None
            drain_calls = []

            def fail_native_once(**kwargs):
                drain_calls.append(Path(kwargs["prefix"]))
                if Path(kwargs["prefix"]) == Path(run["prefix"]):
                    raise byte_identity.ByteIdentityError(
                        "forced native prefix recovery cut"
                    )

            with (
                mock.patch.object(
                    byte_identity, "terminate_execution_transaction_processes"
                ),
                mock.patch.object(
                    byte_identity, "drain_recovered_wine_prefix",
                    side_effect=fail_native_once,
                ),
                self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "forced native prefix recovery cut",
                ),
            ):
                byte_identity.recover_execution_projection_if_needed(
                    self.build_dir,
                    current_manifest=Path(state["manifest_path"]),
                )
            self.assertEqual(
                drain_calls, [Path(projection["prefix"]), Path(run["prefix"])]
            )
            self.assertTrue(transaction_root.is_dir())
            self.assertTrue(marker_path.is_file())
            self.assertEqual(
                [path.name for path in transaction_root.parent.iterdir()
                 if path.name == f"session-{nonce}"],
                [f"session-{nonce}"],
            )
            with (
                mock.patch.object(
                    byte_identity, "terminate_execution_transaction_processes"
                ),
                mock.patch.object(
                    byte_identity, "drain_recovered_wine_prefix"
                ) as drain,
            ):
                byte_identity.recover_execution_projection_if_needed(
                    self.build_dir,
                    current_manifest=Path(state["manifest_path"]),
                )
            self.assertEqual(drain.call_count, 2)
            self.assertFalse(transaction_root.exists())
            self.assertFalse(marker_path.exists())
            self.assertEqual(
                sibling.read_bytes(), b"preserve-native-sibling\n"
            )

    def test_native_reccmp_validator_requires_session_owned_operand_layout(self):
        nonce = "f" * 64
        expected_root = byte_identity.native_reccmp_transaction_path(
            self.build_dir, nonce
        )
        expected = expected_root / "inputs/retail_oracle/LEGO1.DLL"
        old = (
            self.build_dir
            / "byte-identity/native-runs/reccmp"
            / ("run-" + "1" * 32)
            / "inputs/retail_oracle/LEGO1.DLL"
        )
        wrong_session = (
            self.build_dir
            / "byte-identity/execution-projections"
            / ("session-" + "0" * 64)
            / "native-reccmp/inputs/retail_oracle/LEGO1.DLL"
        )
        with byte_identity.build_transaction(
            self.build_dir, exclusive=True, bootstrap_outer_session=True,
        ):
            parts, root_parts = (
                byte_identity.validate_native_reccmp_transaction_operand(
                    expected, self.build_dir, nonce,
                    "real-shaped native reccmp operand",
                )
            )
            self.assertEqual(
                byte_identity.active_build_authority().path(root_parts),
                expected_root,
            )
            self.assertEqual(parts[-3:], (
                "inputs", "retail_oracle", "LEGO1.DLL"
            ))
            for rejected in (old, wrong_session):
                with self.subTest(rejected=rejected), self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "outside its run-private snapshot",
                ):
                    byte_identity.validate_native_reccmp_transaction_operand(
                        rejected, self.build_dir, nonce,
                        "real-shaped native reccmp operand",
                    )

    def test_native_reccmp_snapshot_requires_same_resident_authority(self):
        self.enable_final_image_fixture()
        with (
            mock.patch.object(
                byte_identity, "materialize_command_snapshot",
                wraps=byte_identity.materialize_command_snapshot,
            ) as configure_commands,
            mock.patch.object(
                byte_identity, "materialize_runtime_bin",
                wraps=byte_identity.materialize_runtime_bin,
            ) as configure_toolchain,
            mock.patch.object(
                byte_identity, "materialize_toolchain_snapshot",
                wraps=byte_identity.materialize_toolchain_snapshot,
            ) as configure_toolchain_snapshot,
            mock.patch.object(
                byte_identity, "materialize_native_reccmp_snapshot",
                wraps=byte_identity.materialize_native_reccmp_snapshot,
            ) as configure_native,
            mock.patch.object(
                byte_identity, "materialize_private_reccmp_runtime",
                wraps=byte_identity.materialize_private_reccmp_runtime,
            ) as configure_runtime,
        ):
            self.ensure_inventory()
        configure_commands.assert_not_called()
        configure_toolchain.assert_not_called()
        configure_toolchain_snapshot.assert_not_called()
        configure_native.assert_not_called()
        configure_runtime.assert_not_called()
        self.assertFalse(
            byte_identity.toolchain_snapshot_path(self.build_dir).exists()
        )
        self.assertFalse(byte_identity.runtime_bin_path(self.build_dir).exists())
        self.assertFalse(
            byte_identity.command_snapshot_path(self.build_dir).exists()
        )
        native_root = byte_identity.native_reccmp_snapshot_path(
            self.build_dir
        )
        self.assertFalse(native_root.exists())

        # Transaction A may construct and use the snapshot only while it keeps
        # the source-derived descriptor and holders in memory.
        with byte_identity.build_transaction(
            self.build_dir, exclusive=True, bootstrap_outer_session=True,
        ):
            state = byte_identity.validate_manifest(
                self.manifest, self.source_dir, self.build_dir,
                configured_compiler=str(self.compiler),
            )
            with byte_identity.resident_receipt_scope("b" * 64):
                document = self.materialize_native_reccmp_fixture(state)
                self.assertEqual(
                    byte_identity.validate_native_reccmp_snapshot(
                        state, self.build_dir
                    ),
                    document,
                )

        # Forge a self-consistent runtime/closure descriptor after A closes.
        # A fresh authority must not promote this disk-only state to trust.
        document = json.loads(json.dumps(document))
        runtime_root = native_root / "runtime"
        runtime_leaf = next(
            runtime_root / record["path"]
            for record in document["runtime"]["records"]
            if record["type"] == "file"
        )
        runtime_mode = stat.S_IMODE(runtime_leaf.stat().st_mode)
        runtime_leaf.unlink()
        runtime_leaf.write_bytes(b"forged resident runtime\n")
        runtime_leaf.chmod(runtime_mode)
        runtime_snapshot = byte_identity.canonical_tree_snapshot(
            runtime_root, hash_files=True
        )
        document["runtime"]["tree"] = byte_identity._tree_pin(
            runtime_snapshot
        )
        document["runtime"]["records"] = runtime_snapshot["records"]

        closure = document["closures"][0]
        closure_root = Path(closure["snapshot_path"])
        closure_leaf = next(
            closure_root / record["path"]
            for record in closure["records"]
            if record["type"] == "file"
        )
        closure_mode = stat.S_IMODE(closure_leaf.stat().st_mode)
        closure_leaf.unlink()
        closure_leaf.write_bytes(b"forged resident closure\n")
        closure_leaf.chmod(closure_mode)
        closure_snapshot = byte_identity.canonical_tree_snapshot(
            closure_root, hash_files=True
        )
        closure["tree"] = byte_identity._tree_pin(closure_snapshot)
        closure["records"] = closure_snapshot["records"]
        (native_root / "snapshot.json").write_bytes(
            byte_identity.canonical_json_bytes(document)
        )

        with byte_identity.build_transaction(
            self.build_dir, exclusive=True, bootstrap_outer_session=True,
        ) as authority:
            state = byte_identity.validate_manifest(
                self.manifest, self.source_dir, self.build_dir,
                configured_compiler=str(self.compiler),
            )
            with self.assertRaisesRegex(
                byte_identity.ByteIdentityError,
                "same-transaction materialization authority",
            ):
                byte_identity.validate_native_reccmp_snapshot(
                    state, self.build_dir
                )
            self.assertNotIn(
                byte_identity._native_reccmp_cache_key(self.build_dir),
                authority.snapshot_validation_cache,
            )

            # Resident inventory owns the expensive shared toolchain exactly
            # once but only retires the forged native bundle.  The native
            # CPython/reccmp closure remains lazy until the terminal reccmp
            # stage, where it is rebuilt and retained in this same authority.
            arguments = byte_identity.parser().parse_args(
                self.inventory_args()
            )
            with (
                byte_identity.resident_receipt_scope("c" * 64),
                mock.patch.object(
                    byte_identity, "materialize_runtime_bin",
                    wraps=byte_identity.materialize_runtime_bin,
                ) as resident_toolchain,
                mock.patch.object(
                    byte_identity, "materialize_native_reccmp_snapshot",
                    wraps=byte_identity.materialize_native_reccmp_snapshot,
                ) as resident_native,
                mock.patch.object(
                    byte_identity, "relocate_private_macho",
                    side_effect=self.mock_private_macho_relocation,
                ),
                mock.patch.object(
                    byte_identity, "macho_loader_dependencies",
                    return_value=[],
                ),
            ):
                byte_identity.command_inventory_locked(arguments)
                resident_toolchain.assert_called_once()
                resident_native.assert_not_called()
                self.assertFalse(native_root.exists())
                self.materialize_native_reccmp_fixture(state)
                resident_native.assert_called_once()
                rebuilt = byte_identity.validate_native_reccmp_snapshot(
                    state, self.build_dir
                )
            self.assertEqual(
                rebuilt["tool"]["sha256"],
                state["terminal_producers"]["reccmp"]["executable_sha256"],
            )
            self.assertNotEqual(
                runtime_leaf.read_bytes(),
                b"forged resident runtime\n",
            )

    def test_native_and_virtual_run_preparation_roll_back_exact_nonce(self):
        self.enable_final_image_fixture()
        with (
            mock.patch.object(
                byte_identity, "relocate_private_macho",
                side_effect=self.mock_private_macho_relocation,
            ),
            mock.patch.object(
                byte_identity, "macho_loader_dependencies", return_value=[]
            ),
        ):
            self.ensure_inventory()
        self.attest_command(self.launch_args(
            self.build_dir / "objects/rollback.obj",
            self.build_dir / "objects/rollback.pdb",
            ensure_inventory=False,
        ))
        nonce = "9" * 64
        with (
            byte_identity.build_transaction(
                self.build_dir, exclusive=True, bootstrap_outer_session=True,
            ),
            byte_identity.resident_receipt_scope(nonce),
        ):
            authority = byte_identity.active_build_authority()
            state = byte_identity.validate_manifest(
                self.manifest, self.source_dir, self.build_dir,
                configured_compiler=str(self.compiler),
            )
            projection = self.materialize_resident_projection_fixture(state)
            state["inventory_entry"] = next(
                entry for entry in state["inventory"]["entries"]
                if entry["target"] == "fixture"
                and entry["source"] == "src/unit.cpp"
            )
            state["command_entry"] = next(
                entry for entry in state["command_inventory"]["entries"]
                if entry["target"] == "fixture"
                and entry["source"] == "src/unit.cpp"
            )
            self.materialize_native_reccmp_fixture(state)
            state["inventory_sha256"] = byte_identity.sha256_file(
                byte_identity.inventory_path(self.build_dir)
            )
            state["command_inventory_sha256"] = byte_identity.sha256_file(
                byte_identity.command_inventory_path(self.build_dir)
            )
            source_snapshot = self.build_dir / "rollback-source"
            authority.mkdirs(source_snapshot)
            authority.atomic_write(
                source_snapshot / "unit.cpp", b"int rollback;\n", mode=0o400
            )
            source_pin = byte_identity.canonical_tree_snapshot(
                source_snapshot, hash_files=True
            )

            native_root = Path(projection["root"]) / "native-reccmp"
            sibling = (
                self.build_dir
                / "byte-identity/execution-projections/session-sibling/sentinel"
            )
            authority.mkdirs(sibling.parent)
            authority.atomic_write(
                sibling, b"preserved", mode=0o400,
            )
            with (
                mock.patch.object(
                    byte_identity, "_native_reccmp_tree_copy",
                    side_effect=byte_identity.ByteIdentityError(
                        "forced native copy failure"
                    ),
                ),
                self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "forced native copy failure",
                ),
            ):
                byte_identity.prepare_native_reccmp_run(
                    state=state, build_dir=self.build_dir,
                    executable=Path(state["terminal_producers"]["reccmp"][
                        "executable_path"
                    ]),
                    source_snapshot=source_snapshot, source_pin=source_pin,
                    generated_inputs=[(
                        "image", self.build_dir / "LEGO1.DLL", b"MZ-fixture"
                    )],
                )
            self.assertFalse(native_root.exists())
            self.assertEqual(sibling.read_bytes(), b"preserved")

            original_native_copy = byte_identity._native_reccmp_tree_copy
            poisoned_copy = False

            def copy_then_poison(*args, **kwargs):
                nonlocal poisoned_copy
                copied = original_native_copy(*args, **kwargs)
                if not poisoned_copy:
                    poisoned_copy = True
                    destination = Path(args[1])
                    leaf = next(
                        path for path in destination.rglob("*")
                        if path.is_file() and not path.is_symlink()
                    )
                    mode = stat.S_IMODE(leaf.stat().st_mode)
                    authority.atomic_write(
                        leaf, b"post-copy private-run poison\n", mode=mode
                    )
                return copied

            with (
                mock.patch.object(
                    byte_identity, "_native_reccmp_tree_copy",
                    side_effect=copy_then_poison,
                ),
                self.assertRaises(byte_identity.ByteIdentityError),
            ):
                byte_identity.prepare_native_reccmp_run(
                    state=state, build_dir=self.build_dir,
                    executable=Path(state["terminal_producers"]["reccmp"][
                        "executable_path"
                    ]),
                    source_snapshot=source_snapshot, source_pin=source_pin,
                    generated_inputs=[(
                        "image", self.build_dir / "LEGO1.DLL", b"MZ-fixture"
                    )],
                )
            self.assertTrue(poisoned_copy)
            self.assertFalse(native_root.exists())
            self.assertEqual(sibling.read_bytes(), b"preserved")

            virtual_hex = "b" * 32
            with (
                mock.patch.object(
                    byte_identity.uuid, "uuid4",
                    return_value=mock.Mock(hex=virtual_hex),
                ),
                mock.patch.object(
                    byte_identity, "expected_projection_writable_membership",
                    side_effect=byte_identity.ByteIdentityError(
                        "forced virtual late-preparation failure"
                    ),
                ),
                self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "forced virtual late-preparation failure",
                ),
            ):
                byte_identity.prepare_virtual_z_run(
                    state=state, build_dir=self.build_dir, target="fixture",
                    source_relative="src/unit.cpp", role="seed",
                    cwd=self.build_dir,
                    logical_outputs=[self.build_dir / "unit.obj"],
                    temporary=self.build_dir / "tmp",
                )
            source_id = hashlib.sha256(b"src/unit.cpp").hexdigest()[:16]
            failed_virtual = Path(projection["runs_root"]) / (
                f"fixture-{source_id}-seed-{virtual_hex}"
            )
            self.assertFalse(failed_virtual.exists())
            self.assertEqual(sibling.read_bytes(), b"preserved")
            byte_identity.abort_execution_projection(authority)

    def test_cleanup_retries_drain_and_preserves_uncontrolled_prefix(self):
        with byte_identity.build_transaction(
            self.build_dir, exclusive=True, bootstrap_outer_session=True,
        ):
            authority = byte_identity.active_build_authority()

            def make_run(name):
                root = self.build_dir / "byte-identity/guest-runs/test" / name
                prefix = root / "prefix"
                authority.mkdirs(prefix)
                return {
                    "run": root, "prefix": prefix, "cwd": root,
                    "_wine_drain_attempted": True,
                    "_wine_state": {"runtime_executables": []},
                    "_wine_environment": {},
                    "server_postflight_clear": False,
                }

            recovered = make_run("retry-success")

            def successful_retry(run, _state, _environment, *, phase):
                self.assertEqual(phase, "postflight")
                run["server_postflight_clear"] = True

            with (
                mock.patch.object(
                    byte_identity, "drain_run_private_wineserver",
                    side_effect=successful_retry,
                ) as retry,
            ):
                byte_identity.cleanup_native_reccmp_run(recovered)
            retry.assert_called_once()
            self.assertFalse(recovered["run"].exists())

            retained = make_run("retry-failure")
            with (
                mock.patch.object(
                    byte_identity, "drain_run_private_wineserver",
                    side_effect=byte_identity.ByteIdentityError(
                        "forced drain failure"
                    ),
                ),
                self.assertRaisesRegex(
                    byte_identity.ByteIdentityError, "forced drain failure"
                ),
            ):
                byte_identity.cleanup_native_reccmp_run(retained)
            self.assertTrue(retained["run"].is_dir())
            self.assertTrue(retained["prefix"].is_dir())
            retained["_wine_drain_attempted"] = False
            byte_identity.cleanup_native_reccmp_run(retained)

    def test_wineserver_status_one_accepts_only_quiescent_private_seat(self):
        with byte_identity.build_transaction(
            self.build_dir, exclusive=True, bootstrap_outer_session=True,
        ):
            authority = byte_identity.active_build_authority()
            state = {
                "build_dir": str(self.build_dir),
                "max_child_seconds": 3,
                "runtime_executables": [{"name": "wineserver"}],
            }

            def make_run(name):
                root = self.build_dir / "byte-identity/guest-runs/test" / name
                prefix = root / "prefix"
                authority.mkdirs(prefix)
                return {
                    "run": root, "prefix": prefix, "cwd": root,
                    "server_preflight_clear": False,
                    "server_postflight_clear": False,
                }

            for state_name in ("absent", "lock_only"):
                with self.subTest(server_seat=state_name):
                    run = make_run(f"status-one-{state_name}")
                    seat = self.directory / "wine-seats" / state_name
                    if state_name == "lock_only":
                        seat.mkdir(parents=True)
                        lock = seat / "lock"
                        lock.write_bytes(b"")
                        lock.chmod(0o600)
                    with (
                        mock.patch.object(
                            byte_identity,
                            "validate_runtime_executable_for_recovery",
                            return_value=self.compiler,
                        ),
                        mock.patch.object(
                            byte_identity, "expected_wine_server_seat",
                            return_value=seat,
                        ),
                        mock.patch.object(
                            byte_identity, "run_child",
                            side_effect=[
                                (1, b"", False), (0, b"", False),
                            ],
                        ) as child,
                    ):
                        byte_identity.drain_run_private_wineserver(
                            run, state, {}, phase="postflight"
                        )
                        self.assertTrue(run["server_postflight_clear"])
                        self.assertEqual(
                            run["server_seat_postflight"]["state"], state_name
                        )
                        self.assertEqual(
                            [call.args[0][-1] for call in child.call_args_list],
                            ["-k", "-w"],
                        )
                        byte_identity.cleanup_native_reccmp_run(run)
                    self.assertFalse(run["run"].exists())
                    if state_name == "lock_only":
                        self.assertTrue((seat / "lock").is_file())

    def test_wineserver_status_one_rejects_nonquiescent_seat_and_failures(self):
        with byte_identity.build_transaction(
            self.build_dir, exclusive=True, bootstrap_outer_session=True,
        ):
            authority = byte_identity.active_build_authority()
            state = {
                "build_dir": str(self.build_dir),
                "max_child_seconds": 3,
                "runtime_executables": [{"name": "wineserver"}],
            }

            def make_run(name):
                root = self.build_dir / "byte-identity/guest-runs/test" / name
                prefix = root / "prefix"
                authority.mkdirs(prefix)
                return {
                    "run": root, "prefix": prefix, "cwd": root,
                    "server_preflight_clear": False,
                    "server_postflight_clear": False,
                }

            for entry_kind in ("socket", "undeclared"):
                with self.subTest(server_seat_entry=entry_kind):
                    run = make_run(f"status-one-{entry_kind}")
                    seat = self.directory / "wine-seats" / entry_kind
                    seat.mkdir(parents=True)
                    listener = None
                    entry = seat / entry_kind
                    if entry_kind == "socket":
                        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                        listener.bind(str(entry))
                    else:
                        entry.write_bytes(b"undeclared")
                    try:
                        with (
                            mock.patch.object(
                                byte_identity,
                                "validate_runtime_executable_for_recovery",
                                return_value=self.compiler,
                            ),
                            mock.patch.object(
                                byte_identity, "expected_wine_server_seat",
                                return_value=seat,
                            ),
                            mock.patch.object(
                                byte_identity, "run_child",
                                return_value=(1, b"", False),
                            ) as child,
                            self.assertRaisesRegex(
                                byte_identity.ByteIdentityError,
                                "retains a socket or undeclared entry",
                            ),
                        ):
                            byte_identity.drain_run_private_wineserver(
                                run, state, {}, phase="postflight"
                            )
                        child.assert_called_once()
                        self.assertFalse(run["server_postflight_clear"])
                    finally:
                        if listener is not None:
                            listener.close()
                        entry.unlink()
                        seat.rmdir()
                        byte_identity.rollback_exact_private_run(
                            authority, run["run"]
                        )

            failure_cases = {
                "timeout": [(1, b"", True)],
                "other_status": [(2, b"", False)],
                "status_one_output": [(1, b"unexpected output\n", False)],
                "wait_status_one": [
                    (0, b"", False), (1, b"", False),
                ],
            }
            for name, results in failure_cases.items():
                with self.subTest(failure=name):
                    run = make_run(f"failure-{name}")
                    seat = self.directory / "wine-seats" / f"absent-{name}"
                    with (
                        mock.patch.object(
                            byte_identity,
                            "validate_runtime_executable_for_recovery",
                            return_value=self.compiler,
                        ),
                        mock.patch.object(
                            byte_identity, "expected_wine_server_seat",
                            return_value=seat,
                        ),
                        mock.patch.object(
                            byte_identity, "run_child", side_effect=results,
                        ),
                        self.assertRaisesRegex(
                            byte_identity.ByteIdentityError,
                            "run-private wineserver postflight",
                        ),
                    ):
                        byte_identity.drain_run_private_wineserver(
                            run, state, {}, phase="postflight"
                        )
                    self.assertFalse(run["server_postflight_clear"])
                    byte_identity.rollback_exact_private_run(
                        authority, run["run"]
                    )

    def test_reccmp_cleanup_failure_invalidates_publication_bundle(self):
        with byte_identity.build_transaction(
            self.build_dir, exclusive=True, bootstrap_outer_session=True,
        ):
            authority = byte_identity.active_build_authority()
            run_root = self.build_dir / "byte-identity/native-runs/reccmp/run-test"
            authority.mkdirs(run_root / "prefix")
            report = byte_identity.final_report_path(self.build_dir, "LEGO1")
            log = byte_identity.final_reccmp_log_path(self.build_dir, "LEGO1")
            audit_path = byte_identity.final_reccmp_audit_path(
                self.build_dir, "LEGO1"
            )
            sibling = report.parent / "sibling-preserved"
            for path in (report, log, audit_path, sibling):
                authority.atomic_write(path, b"stale", mode=0o600)
            audit = {
                "native_transport": {
                    "run_private_namespace_removed": False,
                }
            }
            with (
                mock.patch.object(
                    byte_identity, "cleanup_native_reccmp_run",
                    side_effect=byte_identity.ByteIdentityError(
                        "forced cleanup failure"
                    ),
                ),
                self.assertRaisesRegex(
                    byte_identity.ByteIdentityError, "forced cleanup failure"
                ),
            ):
                byte_identity.publish_native_reccmp_outputs_after_cleanup(
                    run={"run": run_root}, report_path=report,
                    report=b"new report", log_path=log, log=b"new log",
                    audit_path=audit_path, audit=audit,
                )
            self.assertFalse(report.exists())
            self.assertFalse(log.exists())
            self.assertFalse(audit_path.exists())
            self.assertEqual(sibling.read_bytes(), b"stale")

    def test_reccmp_preexecution_rollback_cleans_run_when_invalidation_fails(self):
        with byte_identity.build_transaction(
            self.build_dir, exclusive=True, bootstrap_outer_session=True,
        ):
            authority = byte_identity.active_build_authority()
            parent = self.build_dir / "byte-identity/native-runs/reccmp"
            run_root = parent / "run-failed"
            sibling = parent / "run-sibling/sentinel"
            authority.mkdirs(run_root)
            authority.mkdirs(sibling.parent)
            authority.atomic_write(run_root / "private-input", b"owned")
            authority.atomic_write(sibling, b"preserve")
            installed = [
                byte_identity.final_report_path(self.build_dir, "LEGO1"),
                byte_identity.final_reccmp_log_path(self.build_dir, "LEGO1"),
                byte_identity.final_reccmp_audit_path(self.build_dir, "LEGO1"),
            ]

            def cleanup(run):
                byte_identity.rollback_exact_private_run(
                    authority, Path(run["run"])
                )

            with (
                mock.patch.object(
                    byte_identity, "invalidate_build_paths",
                    side_effect=byte_identity.ByteIdentityError(
                        "forced publication invalidation failure"
                    ),
                ),
                mock.patch.object(
                    byte_identity, "cleanup_native_reccmp_run",
                    side_effect=cleanup,
                ) as cleanup_call,
                self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "published paths: forced publication invalidation failure",
                ),
            ):
                byte_identity.rollback_failed_native_reccmp_invocation(
                    {"run": run_root}, installed
                )
            cleanup_call.assert_called_once()
            self.assertFalse(run_root.exists())
            self.assertEqual(sibling.read_bytes(), b"preserve")
            self.assertTrue(all(not path.exists() for path in installed))

    def test_mkdir_exclusive_rolls_back_a_post_create_failure(self):
        with byte_identity.build_transaction(
            self.build_dir, exclusive=True, bootstrap_outer_session=True,
        ):
            authority = byte_identity.active_build_authority()
            parent = self.build_dir / "byte-identity/exclusive-fixture"
            target = parent / "owned"
            sibling = parent / "sibling/sentinel"
            authority.mkdirs(sibling.parent)
            authority.atomic_write(sibling, b"preserved", mode=0o400)
            target_parts = authority.parts(target)
            original_record = authority._record_directory
            injected = False

            def fail_after_create(parts, descriptor):
                nonlocal injected
                if parts == target_parts and not injected:
                    injected = True
                    raise byte_identity.ByteIdentityError(
                        "forced post-create check failure"
                    )
                return original_record(parts, descriptor)

            with (
                mock.patch.object(
                    authority, "_record_directory",
                    side_effect=fail_after_create,
                ),
                self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "forced post-create check failure",
                ),
            ):
                authority.mkdir_exclusive(target)
            self.assertFalse(target.exists())
            self.assertEqual(sibling.read_bytes(), b"preserved")

    def test_snapshot_materializers_roll_back_their_exact_roots(self):
        self.enable_final_image_fixture()
        with byte_identity.build_transaction(
            self.build_dir, exclusive=True, bootstrap_outer_session=True,
        ):
            state = byte_identity.validate_manifest(
                self.manifest, self.source_dir, self.build_dir,
                configured_compiler=str(self.compiler),
            )
            with (
                mock.patch.object(
                    byte_identity, "validate_runtime_bin",
                    side_effect=byte_identity.ByteIdentityError(
                        "forced runtime validation failure"
                    ),
                ),
                self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "forced runtime validation failure",
                ),
            ):
                byte_identity.materialize_runtime_bin(state, self.build_dir)
            self.assertFalse(
                byte_identity.toolchain_snapshot_path(self.build_dir).exists()
            )
            self.assertFalse(
                byte_identity.runtime_bin_path(self.build_dir).exists()
            )
            with (
                mock.patch.object(
                    byte_identity, "materialize_private_reccmp_runtime",
                    side_effect=byte_identity.ByteIdentityError(
                        "forced private runtime failure"
                    ),
                ),
                self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "forced private runtime failure",
                ),
            ):
                byte_identity.materialize_native_reccmp_snapshot(
                    state, self.build_dir
                )
            self.assertFalse(
                byte_identity.native_reccmp_snapshot_path(
                    self.build_dir
                ).exists()
            )

        with (
            mock.patch.object(
                byte_identity, "relocate_private_macho",
                side_effect=self.mock_private_macho_relocation,
            ),
            mock.patch.object(
                byte_identity, "macho_loader_dependencies", return_value=[]
            ),
        ):
            self.ensure_inventory()
        self.attest_command(self.launch_args(
            self.build_dir / "objects/snapshot.obj",
            self.build_dir / "objects/snapshot.pdb",
            ensure_inventory=False,
        ))
        with byte_identity.build_transaction(
            self.build_dir, exclusive=True, bootstrap_outer_session=True,
        ):
            state = byte_identity.validate_manifest(
                self.manifest, self.source_dir, self.build_dir,
                configured_compiler=str(self.compiler),
            )
            byte_identity.materialize_runtime_bin(state, self.build_dir)
            inventory = byte_identity.load_inventory(state, self.build_dir)
            commands = byte_identity.load_command_inventory(
                state, inventory, self.build_dir
            )
            with (
                mock.patch.object(
                    byte_identity, "copy_command_tree_to_snapshot",
                    side_effect=byte_identity.ByteIdentityError(
                        "forced command snapshot failure"
                    ),
                ),
                self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "forced command snapshot failure",
                ),
            ):
                byte_identity.materialize_command_snapshot(
                    state, inventory, commands["entries"], self.build_dir
                )
            self.assertFalse(
                byte_identity.command_snapshot_path(self.build_dir).exists()
            )

    def test_copy_derived_snapshot_baselines_refuse_persistent_mutation(self):
        shared = self.source_dir / "include/copied-baseline"
        shared.mkdir(parents=True)
        shared_leaf = shared / "baseline.h"
        shared_leaf.write_bytes(b"authenticated command input\n")
        shared_pin = byte_identity.command_input_tree_identity(
            byte_identity.canonical_tree_snapshot(shared, hash_files=True)
        )
        entries = [{"input_trees": [{"ordinal": 0, **shared_pin}]}]
        command_state = {
            "manifest_sha256": digest(b"baseline-command-manifest"),
            "toolchain_fingerprint": digest(b"baseline-command-toolchain"),
            "build_dir": str(self.build_dir),
            "compiler_root": str(self.source_dir / "toolchain"),
            "required_absent_toolchain_files": [],
            "terminal_producers": {},
        }
        command_inventory = {
            "policy_sha256": digest(b"baseline-command-policy"),
            "inputs": [],
        }
        sibling = (
            self.build_dir
            / "byte-identity/input-snapshots/unrelated/sentinel"
        )

        with byte_identity.build_transaction(
            self.build_dir, exclusive=True, bootstrap_outer_session=True,
        ) as authority:
            authority.mkdirs(sibling.parent)
            authority.atomic_write(sibling, b"preserve", mode=0o400)
            command_root = byte_identity.command_snapshot_path(self.build_dir)
            command_z = command_root / "z"
            copied_leaf = byte_identity.absolute_snapshot_seat(
                command_z, shared_leaf
            )
            original_snapshot = byte_identity.canonical_tree_snapshot
            injected = False

            def poison_command(root, *args, **kwargs):
                nonlocal injected
                if Path(root) == command_z and not injected:
                    injected = True
                    authority.atomic_write(
                        copied_leaf, b"persistent command poison\n", mode=0o400
                    )
                return original_snapshot(root, *args, **kwargs)

            with (
                mock.patch.object(
                    byte_identity, "canonical_tree_snapshot",
                    side_effect=poison_command,
                ),
                self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "differs from authenticated copied inputs",
                ),
            ):
                byte_identity.materialize_command_snapshot(
                    command_state, command_inventory, entries, self.build_dir
                )
            self.assertTrue(injected)
            self.assertFalse(command_root.exists())
            self.assertEqual(sibling.read_bytes(), b"preserve")

        self.enable_final_image_fixture()
        with byte_identity.build_transaction(
            self.build_dir, exclusive=True, bootstrap_outer_session=True,
        ) as authority:
            state = byte_identity.validate_manifest(
                self.manifest, self.source_dir, self.build_dir,
                configured_compiler=str(self.compiler),
            )
            toolchain_root = byte_identity.toolchain_snapshot_path(
                self.build_dir
            )
            observed_roots_and_leaves = (
                (
                    toolchain_root / "z",
                    byte_identity.absolute_snapshot_seat(
                        toolchain_root / "z", Path(state["compiler_path"])
                    ),
                ),
                (
                    toolchain_root / "host",
                    byte_identity.absolute_snapshot_seat(
                        toolchain_root / "host",
                        Path(state["runtime_closure"]["loaded_files"][0]["path"]),
                    ),
                ),
                (
                    toolchain_root / "prefix-template",
                    toolchain_root / "prefix-template"
                    / state["transport"]["prefix_template_files"][0]["name"],
                ),
            )
            for observed_root, copied_leaf in observed_roots_and_leaves:
                with self.subTest(toolchain_tree=observed_root.name):
                    injected = False
                    original_snapshot = byte_identity.canonical_tree_snapshot

                    def poison_toolchain(root, *args, **kwargs):
                        nonlocal injected
                        if Path(root) == observed_root and not injected:
                            injected = True
                            parent = copied_leaf.parent
                            parent_mode = stat.S_IMODE(
                                authority.lstat(parent).st_mode
                            )
                            authority.chmod_directory(parent, 0o700)
                            try:
                                leaf_mode = stat.S_IMODE(
                                    authority.lstat(copied_leaf).st_mode
                                )
                                authority.atomic_write(
                                    copied_leaf,
                                    b"persistent toolchain poison\n",
                                    mode=leaf_mode,
                                )
                            finally:
                                authority.chmod_directory(parent, parent_mode)
                        return original_snapshot(root, *args, **kwargs)

                    with (
                        mock.patch.object(
                            byte_identity, "canonical_tree_snapshot",
                            side_effect=poison_toolchain,
                        ),
                        self.assertRaisesRegex(
                            byte_identity.ByteIdentityError,
                            "differs from authenticated copied inputs",
                        ),
                    ):
                        byte_identity.materialize_runtime_bin(
                            state, self.build_dir
                        )
                    self.assertTrue(injected)
                    self.assertFalse(toolchain_root.exists())
                    self.assertFalse(
                        byte_identity.runtime_bin_path(self.build_dir).exists()
                    )
                    self.assertEqual(sibling.read_bytes(), b"preserve")

            native_root = byte_identity.native_reccmp_snapshot_path(
                self.build_dir
            )
            original_snapshot = byte_identity.canonical_tree_snapshot
            injected = False

            def poison_native_aggregate(root, *args, **kwargs):
                nonlocal injected
                if Path(root) == native_root and not injected:
                    injected = True
                    tool = native_root / "tool/reccmp.py"
                    authority.atomic_write(
                        tool, b"persistent native tool poison\n", mode=0o400
                    )
                return original_snapshot(root, *args, **kwargs)

            with (
                byte_identity.resident_receipt_scope("d" * 64),
                mock.patch.object(
                    byte_identity, "canonical_tree_snapshot",
                    side_effect=poison_native_aggregate,
                ),
                mock.patch.object(
                    byte_identity, "relocate_private_macho",
                    side_effect=self.mock_private_macho_relocation,
                ),
                mock.patch.object(
                    byte_identity, "macho_loader_dependencies", return_value=[]
                ),
                self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "differs from authenticated copied inputs",
                ),
            ):
                byte_identity.materialize_native_reccmp_snapshot(
                    state, self.build_dir
                )
            self.assertTrue(injected)
            self.assertFalse(native_root.exists())
            self.assertEqual(sibling.read_bytes(), b"preserve")

            transformed = False

            def poison_after_relocation(
                path, changes, *, expected_input, install_id=None,
            ):
                nonlocal transformed
                receipt = self.mock_private_macho_relocation(
                    path, changes, expected_input=expected_input,
                    install_id=install_id,
                )
                if not transformed:
                    transformed = True
                    authority.atomic_write(
                        Path(path), b"post-transform poison\n",
                        mode=receipt["mode"],
                    )
                return receipt

            with (
                byte_identity.resident_receipt_scope("e" * 64),
                mock.patch.object(
                    byte_identity, "relocate_private_macho",
                    side_effect=poison_after_relocation,
                ),
                mock.patch.object(
                    byte_identity, "macho_loader_dependencies", return_value=[]
                ),
                self.assertRaises(byte_identity.ByteIdentityError),
            ):
                byte_identity.materialize_native_reccmp_snapshot(
                    state, self.build_dir
                )
            self.assertTrue(transformed)
            self.assertFalse(native_root.exists())
            self.assertEqual(sibling.read_bytes(), b"preserve")

    def test_inventory_and_command_attestation_publish_as_bundles(self):
        inventory_output = byte_identity.inventory_path(self.build_dir)
        inventory_plan = byte_identity.inventory_plan_path(self.build_dir)
        inventory_stamp = byte_identity.policy_stamp_path(self.build_dir)
        self.ensure_inventory()
        inventory_bundle = {
            path: path.read_bytes()
            for path in (inventory_output, inventory_plan, inventory_stamp)
        }
        wrong_inventory = self.inventory_args()
        wrong_inventory[
            wrong_inventory.index("--output") + 1
        ] = str(self.build_dir / "byte-identity/configure/wrong.json")
        self.assertEqual(byte_identity.main(wrong_inventory), 2)
        self.assertEqual(
            {path: path.read_bytes() for path in inventory_bundle},
            inventory_bundle,
        )

        original_atomic_write = byte_identity.atomic_write

        def fail_inventory_stamp(path, data, *, if_changed=False):
            if Path(path) == inventory_stamp:
                raise byte_identity.ByteIdentityError(
                    "forced inventory publication failure"
                )
            return original_atomic_write(path, data, if_changed=if_changed)

        with mock.patch.object(
            byte_identity, "atomic_write", side_effect=fail_inventory_stamp
        ):
            self.assertEqual(byte_identity.main(self.inventory_args()), 2)
        for path in (inventory_output, inventory_plan, inventory_stamp):
            self.assertFalse(path.exists())
        for root in (
            byte_identity.runtime_bin_path(self.build_dir),
            byte_identity.toolchain_snapshot_path(self.build_dir),
            byte_identity.native_reccmp_snapshot_path(self.build_dir),
        ):
            self.assertFalse(root.exists(), str(root))

        self.ensure_inventory()
        launch = self.launch_args(
            self.build_dir / "objects/bundle.obj",
            self.build_dir / "objects/bundle.pdb",
            ensure_inventory=False,
        )
        command_output = byte_identity.command_inventory_path(self.build_dir)
        self.attest_command(launch)
        command_stamp = byte_identity.command_policy_stamp_path(self.build_dir)
        command_snapshot = byte_identity.command_snapshot_path(self.build_dir)
        command_bundle = {
            path: path.read_bytes() for path in (command_output, command_stamp)
        }
        command_snapshot_pin = byte_identity.canonical_tree_snapshot(
            command_snapshot, hash_files=True
        )
        command_args = [
            "attest-commands",
            "--manifest", str(self.manifest),
            "--source-dir", str(self.source_dir),
            "--build-dir", str(self.build_dir),
            "--compiler", str(self.compiler),
            "--compile-commands", str(self.build_dir / "compile_commands.json"),
            "--output", str(command_output),
            "--policy-stamp", str(command_stamp),
        ]
        wrong_commands = list(command_args)
        wrong_commands[
            wrong_commands.index("--output") + 1
        ] = str(self.build_dir / "byte-identity/configure/wrong-commands.json")
        self.assertEqual(byte_identity.main(wrong_commands), 2)
        self.assertEqual(
            {path: path.read_bytes() for path in command_bundle},
            command_bundle,
        )
        self.assertEqual(
            byte_identity.canonical_tree_snapshot(
                command_snapshot, hash_files=True
            ),
            command_snapshot_pin,
        )

        def fail_command_stamp(path, data, *, if_changed=False):
            if Path(path) == command_stamp:
                raise byte_identity.ByteIdentityError(
                    "forced command publication failure"
                )
            return original_atomic_write(path, data, if_changed=if_changed)

        with mock.patch.object(
            byte_identity, "atomic_write", side_effect=fail_command_stamp
        ):
            self.assertEqual(byte_identity.main(command_args), 2)
        self.assertFalse(command_output.exists())
        self.assertFalse(command_stamp.exists())
        self.assertFalse(command_snapshot.exists())

    def test_native_reccmp_loader_trace_binds_private_cvdump_wine(self):
        with byte_identity.build_transaction(
            self.build_dir, exclusive=True, bootstrap_outer_session=True,
        ):
            authority = byte_identity.active_build_authority()
            runtime = self.build_dir / "trace-run/runtime"
            wine = self.build_dir / "trace-run/wine-runtime"
            authority.mkdirs(runtime / "lib")
            authority.mkdirs(wine / "lib")
            python_image = runtime / "lib/Python"
            wine_image = wine / "lib/libwine-fixture.dylib"
            authority.atomic_write(python_image, b"private-python", mode=0o400)
            authority.atomic_write(wine_image, b"private-wine", mode=0o400)
            run = {
                "runtime": runtime, "closure_records": [],
                "wine_transport": {"runtime_snapshot": wine},
            }
            program, images = byte_identity.split_native_reccmp_loader_trace(
                (
                    f"dyld[41]: {python_image}\n"
                    f"dyld[41]: {wine_image}\n"
                    "producer output\n"
                ).encode(),
                run,
            )
            self.assertEqual(program, b"producer output\n")
            self.assertEqual(
                [item["scope"] for item in images],
                ["private_runtime", "private_cvdump_wine_runtime"],
            )
            ambient = self.directory / "ambient-unpinned.dylib"
            ambient.write_bytes(b"ambient")
            with self.assertRaisesRegex(
                byte_identity.ByteIdentityError,
                "loaded an ambient non-system image",
            ):
                byte_identity.split_native_reccmp_loader_trace(
                    (
                        f"dyld[41]: {python_image}\n"
                        f"dyld[41]: {ambient}\n"
                    ).encode(),
                    run,
                )

    def test_held_snapshot_cache_bounds_shared_tree_rescans(self):
        self.enable_final_image_fixture()
        with (
            mock.patch.object(
                byte_identity, "relocate_private_macho",
                side_effect=self.mock_private_macho_relocation,
            ),
            mock.patch.object(
                byte_identity, "macho_loader_dependencies", return_value=[]
            ),
        ):
            self.ensure_inventory()
        with byte_identity.build_transaction(
            self.build_dir, exclusive=True, bootstrap_outer_session=True,
        ):
            state = byte_identity.validate_manifest(
                self.manifest, self.source_dir, self.build_dir,
                configured_compiler=str(self.compiler),
            )
            toolchain = byte_identity.toolchain_snapshot_path(self.build_dir)
            native = byte_identity.native_reccmp_snapshot_path(self.build_dir)
            shared = {
                str(toolchain / "z"), str(toolchain / "host"),
                str(toolchain / "prefix-template"), str(native),
                str(native / "runtime"),
                *(
                    str(native / "closures" / item["role"])
                    for item in state["terminal_producers"]["reccmp"][
                        "closure_roots"
                    ]
                ),
            }
            counts = {path: 0 for path in shared}
            original_snapshot = byte_identity.canonical_tree_snapshot

            def counting_snapshot(root, *args, **kwargs):
                key = str(Path(root))
                if key in counts:
                    counts[key] += 1
                return original_snapshot(root, *args, **kwargs)

            with (
                mock.patch.object(
                    byte_identity, "canonical_tree_snapshot",
                    side_effect=counting_snapshot,
                ),
                mock.patch.object(
                    byte_identity, "relocate_private_macho",
                    side_effect=self.mock_private_macho_relocation,
                ),
                mock.patch.object(
                    byte_identity, "macho_loader_dependencies", return_value=[]
                ),
            ):
                with byte_identity.resident_receipt_scope("a" * 64):
                    byte_identity.materialize_runtime_bin(
                        state, self.build_dir
                    )
                    byte_identity.materialize_native_reccmp_snapshot(
                        state, self.build_dir
                    )
                    initial_counts = dict(counts)
                    for _ in range(4):
                        byte_identity.validate_toolchain_snapshot(
                            state, self.build_dir
                        )
                        byte_identity.validate_native_reccmp_snapshot(
                            state, self.build_dir
                        )
                    self.assertEqual(counts, initial_counts)
                    byte_identity.finalize_toolchain_snapshot_validation(
                        state, self.build_dir
                    )
                    byte_identity.finalize_native_reccmp_snapshot_validation(
                        state, self.build_dir
                    )
            terminal_rescans = {
                str(toolchain / "z"), str(toolchain / "host"),
                str(toolchain / "prefix-template"), str(native),
            }
            self.assertEqual(counts, {
                path: value + (1 if path in terminal_rescans else 0)
                for path, value in initial_counts.items()
            })

    def test_execution_projection_merges_unique_inputs_once_and_refuses_aliases(self):
        first = self.build_dir / "projection-merge-first"
        second = self.build_dir / "projection-merge-second"
        first.mkdir()
        second.mkdir()
        (first / "shared").mkdir()
        (second / "shared").mkdir()
        (first / "shared/same.h").write_bytes(b"identical\n")
        (second / "shared/same.h").write_bytes(b"identical\n")
        (first / "only-first.h").write_bytes(b"first\n")
        (second / "only-second.h").write_bytes(b"second\n")
        first_records = byte_identity.canonical_tree_snapshot(
            first, hash_files=True
        )["records"]
        second_records = byte_identity.canonical_tree_snapshot(
            second, hash_files=True
        )["records"]
        # Directory st_size is host/filesystem-dependent and overlapping
        # directories intentionally have the union of both source memberships.
        for record in second_records:
            if record["path"] == "shared":
                record["size"] = record.get("size", 0) + 4096
        build_relative = PurePosixPath("private/build")
        merged = byte_identity.merged_execution_projection_records(
            [(first, first_records), (second, second_records)],
            build_relative,
        )
        self.assertEqual(
            [item["path"] for item in merged].count("shared/same.h"), 1
        )
        with byte_identity.build_transaction(
            self.build_dir, exclusive=True, bootstrap_outer_session=True,
        ) as authority:
            destination = self.build_dir / "projection-merge-output"
            writes = []
            original_write = authority.atomic_write

            def counted_write(path, data, *, mode=0o600):
                writes.append(Path(path))
                return original_write(path, data, mode=mode)

            with mock.patch.object(
                authority, "atomic_write", side_effect=counted_write
            ):
                byte_identity.copy_merged_execution_projection(
                    destination, merged
                )
            self.assertEqual(
                sum(path.name == "same.h" for path in writes), 1
            )

        by_path = {
            record["path"]: record for record in second_records
        }
        for field, replacement in (
            ("mode", 0o600),
            ("sha256", digest(b"different")),
        ):
            with self.subTest(conflicting_leaf=field):
                candidate = json.loads(json.dumps(second_records))
                record = next(
                    item for item in candidate
                    if item["path"] == "shared/same.h"
                )
                record[field] = replacement
                with self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "input snapshots conflict",
                ):
                    byte_identity.merged_execution_projection_records(
                        [(first, first_records), (second, candidate)],
                        build_relative,
                    )

        alias_cases = (
            (
                "casefold collision",
                [{
                    **by_path["shared/same.h"],
                    "path": "SHARED/SAME.H",
                }],
            ),
            (
                "file shadows a descendant",
                [{
                    **by_path["shared/same.h"], "path": "leaf",
                }, {
                    **by_path["shared/same.h"], "path": "leaf/child",
                }],
            ),
            (
                "overlaps the writable build branch",
                [{
                    **by_path["shared/same.h"],
                    "path": "private/build/escape.h",
                }],
            ),
            (
                "path is unsafe",
                [{
                    **by_path["shared/same.h"], "path": "shared//same.h",
                }],
            ),
        )
        for message, records in alias_cases:
            with self.subTest(alias=message):
                sources = [(first, first_records), (second, records)]
                if message == "casefold collision":
                    sources = [
                        (first, first_records),
                        (second, [by_path["shared/same.h"], *records]),
                    ]
                with self.assertRaisesRegex(
                    byte_identity.ByteIdentityError, message
                ):
                    byte_identity.merged_execution_projection_records(
                        sources, build_relative
                    )

        class CountedPath(str):
            startswith_calls = 0

            def startswith(self, *args, **kwargs):
                type(self).startswith_calls += 1
                return super().startswith(*args, **kwargs)

        large_count = 2000
        large_records = [{
            "path": CountedPath(f"large/leaf-{index:04d}.h"),
            "type": "file", "mode": 0o400, "executable": False,
            "size": 1, "sha256": digest(bytes([index & 0xff])),
        } for index in range(large_count)]
        large = byte_identity.merged_execution_projection_records(
            [(first, large_records)], build_relative
        )
        self.assertEqual(len(large), large_count)
        # A former descendant search called startswith for every pair.  The
        # ancestor-map implementation is bounded by records/path depth.
        self.assertLess(
            CountedPath.startswith_calls, large_count * 8,
            CountedPath.startswith_calls,
        )

    def test_execution_projection_scans_and_installs_base_once_per_transaction(self):
        self.ensure_inventory()
        output = self.build_dir / "objects/unit.obj"
        pdb = self.build_dir / "objects/unit.pdb"
        self.attest_command(
            self.launch_args(output, pdb, ensure_inventory=False)
        )
        projection_roots = []
        scans = []
        command_snapshot_scans = []
        with byte_identity.build_transaction(
            self.build_dir, exclusive=True, bootstrap_outer_session=True,
        ) as authority:
            state = byte_identity.validate_manifest(
                self.manifest, self.source_dir, self.build_dir,
                configured_compiler=str(self.compiler),
            )
            byte_identity.materialize_runtime_bin(state, self.build_dir)
            inventory = byte_identity.load_inventory(state, self.build_dir)
            command_inventory = byte_identity.load_command_inventory(
                state, inventory, self.build_dir
            )
            state["inventory"] = inventory
            state["command_inventory"] = command_inventory
            original_snapshot = byte_identity.canonical_tree_snapshot

            def counted_snapshot(root, *args, **kwargs):
                path = Path(root)
                if path == byte_identity.command_snapshot_path(
                    self.build_dir
                ) / "z":
                    command_snapshot_scans.append(str(path))
                if (path.name == "z"
                        and path.parent.name.startswith("session-")
                        and path.parent.parent.name == "execution-projections"):
                    scans.append(str(path))
                return original_snapshot(root, *args, **kwargs)

            with mock.patch.object(
                byte_identity, "canonical_tree_snapshot",
                side_effect=counted_snapshot,
            ):
                projection = byte_identity.materialize_execution_projection(
                    state, self.build_dir
                )
                projection_roots.append(Path(projection["root"]))
                for index, role in enumerate(
                    ("dependencies", "seed", "donor", "release", "analysis")
                ):
                    held, token = byte_identity.acquire_execution_projection(
                        state, self.build_dir,
                        role=role,
                        run_root=self.build_dir / f"synthetic-run-{index}",
                    )
                    self.assertIs(held, projection)
                    authority.atomic_write(
                        Path(projection["writable_build_root"])
                        / f"temporary-{index}",
                        b"temporary\n",
                    )
                    run = {
                        "projection": projection,
                        "projection_lease": token,
                        "prefix": projection["prefix"],
                    }
                    byte_identity.release_execution_projection(run)
                    self.assertTrue(run["projection_lease_released"])
                byte_identity.finalize_execution_projection(authority)
            self.assertEqual(scans, [str(Path(projection["z"]))] * 2)
            self.assertEqual(command_snapshot_scans, [])
            self.assertEqual(projection["lease_count"], 5)
            receipt = authority.execution_projection_receipt
            self.assertEqual(receipt["projection_materialization_count"], 1)
            self.assertEqual(
                receipt["unique_record_install_count"],
                projection["unique_record_install_count"],
            )
            self.assertTrue(receipt["projection_removed"])
            self.assertIsNone(authority.lstat(projection_roots[0]))
            receipt_root = receipt["projection_root"]
            receipt_descriptor = receipt["projection_descriptor_sha256"]
            self.assertEqual(
                byte_identity.validate_execution_projection_evidence(
                    receipt_root, receipt_descriptor, self.build_dir,
                    "same resident transaction",
                ),
                receipt,
            )
        with byte_identity.build_transaction(
            self.build_dir, exclusive=True, bootstrap_outer_session=True,
        ):
            with self.assertRaisesRegex(
                byte_identity.ByteIdentityError,
                "was not produced by this resident transaction",
            ):
                byte_identity.validate_execution_projection_evidence(
                    receipt_root, receipt_descriptor, self.build_dir,
                    "fresh standalone verifier",
                )

    def test_resident_terminal_cold_rescans_command_snapshot_and_rejects_mutation(self):
        self.ensure_inventory()
        output = self.build_dir / "objects/unit.obj"
        pdb = self.build_dir / "objects/unit.pdb"
        self.attest_command(
            self.launch_args(output, pdb, ensure_inventory=False)
        )
        arguments = argparse.Namespace(
            manifest=self.manifest,
            source_dir=self.source_dir,
            build_dir=self.build_dir,
            compiler=str(self.compiler),
            configured_compiler=str(self.compiler),
        )
        session = {
            "nonce": digest(b"resident-terminal-command-snapshot"),
            "driver_pid": os.getpid(),
        }
        command_z = (
            byte_identity.command_snapshot_path(self.build_dir) / "z"
        )

        def exercise_terminal(*, mutate):
            scans = []
            session_checks = 0
            original_snapshot = byte_identity.canonical_tree_snapshot

            def counted_snapshot(root, *args, **kwargs):
                if Path(root) == command_z:
                    scans.append(str(Path(root)))
                return original_snapshot(root, *args, **kwargs)

            def terminal_session_once(_authority, nonce=None):
                nonlocal session_checks
                session_checks += 1
                return session if session_checks == 1 else None

            with byte_identity.build_transaction(
                self.build_dir, exclusive=True,
                bootstrap_outer_session=True,
            ) as authority:
                authority.atomic_write(
                    byte_identity.active_session_path(self.build_dir),
                    b"resident terminal fixture\n",
                )
                with mock.patch.object(
                    byte_identity, "canonical_tree_snapshot",
                    side_effect=counted_snapshot,
                ):
                    state = byte_identity.validate_manifest(
                        self.manifest, self.source_dir, self.build_dir,
                        configured_compiler=str(self.compiler),
                    )
                    byte_identity.materialize_runtime_bin(
                        state, self.build_dir
                    )
                    inventory = byte_identity.load_inventory(
                        state, self.build_dir
                    )
                    commands = byte_identity.load_command_inventory(
                        state, inventory, self.build_dir
                    )
                    byte_identity.seed_resident_producer_state_cache(
                        arguments, state, inventory, commands, session
                    )
                    if mutate:
                        leaf = byte_identity.absolute_snapshot_seat(
                            command_z, self.include
                        )
                        pristine = leaf.read_bytes()
                        self.assertTrue(pristine)
                        mode = stat.S_IMODE(leaf.stat().st_mode)
                        leaf.chmod(0o600)
                        with leaf.open("r+b") as stream:
                            stream.write(bytes([pristine[0] ^ 1]))
                            stream.flush()
                            os.fsync(stream.fileno())
                        leaf.chmod(mode)
                    with (
                        mock.patch.object(
                            byte_identity,
                            "validate_active_session_authority",
                            side_effect=terminal_session_once,
                        ),
                        mock.patch.object(
                            byte_identity, "load_inventory",
                            return_value=inventory,
                        ),
                        mock.patch.object(
                            byte_identity,
                            "finalize_toolchain_snapshot_validation",
                        ),
                    ):
                        if mutate:
                            with self.assertRaisesRegex(
                                byte_identity.ByteIdentityError,
                                "held command snapshot changed before completion",
                            ):
                                byte_identity.finalize_resident_producer_authority(
                                    arguments
                                )
                            cache = authority.snapshot_validation_cache[
                                byte_identity.command_snapshot_cache_key(
                                    self.build_dir
                                )
                            ]
                            self.assertFalse(cache["finalized"])
                            self.assertIsNone(
                                authority.execution_projection_receipt
                            )
                            self.assertFalse(
                                byte_identity.execution_projection_finalization_path(
                                    self.build_dir
                                ).exists()
                            )
                            self.assertFalse(
                                (self.build_dir
                                 / "byte-identity/audit/framework-verdict.json").exists()
                            )
                        else:
                            byte_identity.finalize_resident_producer_authority(
                                arguments
                            )
                            cache = authority.snapshot_validation_cache[
                                byte_identity.command_snapshot_cache_key(
                                    self.build_dir
                                )
                            ]
                            self.assertTrue(cache["finalized"])
                self.assertEqual(scans, [str(command_z), str(command_z)])
                self.assertEqual(session_checks, 2)

        exercise_terminal(mutate=False)
        exercise_terminal(mutate=True)

    def test_execution_projection_refuses_mutation_before_initial_baseline(self):
        self.ensure_inventory()
        output = self.build_dir / "objects/unit.obj"
        pdb = self.build_dir / "objects/unit.pdb"
        self.attest_command(
            self.launch_args(output, pdb, ensure_inventory=False)
        )
        mutated_root = None
        scans = []
        original_copy = byte_identity.copy_merged_execution_projection
        original_snapshot = byte_identity.canonical_tree_snapshot

        def copy_then_mutate(destination, merged):
            nonlocal mutated_root
            original_copy(destination, merged)
            mutated_root = Path(destination).parent
            item = next(
                entry for entry in merged
                if entry["identity"]["type"] == "file"
                and entry["identity"]["size"] > 0
            )
            target = Path(destination).joinpath(
                *PurePosixPath(item["path"]).parts
            )
            pristine = target.read_bytes()
            target.chmod(0o600)
            with target.open("r+b") as stream:
                stream.write(bytes([pristine[0] ^ 1]))
                stream.flush()
                os.fsync(stream.fileno())
            target.chmod(item["identity"]["mode"])

        def counted_snapshot(root, *args, **kwargs):
            path = Path(root)
            if (path.name == "z"
                    and path.parent.name.startswith("session-")
                    and path.parent.parent.name == "execution-projections"):
                scans.append(str(path))
            return original_snapshot(root, *args, **kwargs)

        with byte_identity.build_transaction(
            self.build_dir, exclusive=True, bootstrap_outer_session=True,
        ) as authority:
            state = byte_identity.validate_manifest(
                self.manifest, self.source_dir, self.build_dir,
                configured_compiler=str(self.compiler),
            )
            byte_identity.materialize_runtime_bin(state, self.build_dir)
            inventory = byte_identity.load_inventory(state, self.build_dir)
            state["inventory"] = inventory
            state["command_inventory"] = byte_identity.load_command_inventory(
                state, inventory, self.build_dir
            )
            sibling = (
                self.build_dir
                / "byte-identity/execution-projections/sibling/sentinel"
            )
            authority.mkdirs(sibling.parent)
            authority.atomic_write(sibling, b"preserve\n")
            with (
                mock.patch.object(
                    byte_identity, "copy_merged_execution_projection",
                    side_effect=copy_then_mutate,
                ),
                mock.patch.object(
                    byte_identity, "canonical_tree_snapshot",
                    side_effect=counted_snapshot,
                ),
                self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "projection differs from authenticated inputs",
                ),
            ):
                byte_identity.materialize_execution_projection(
                    state, self.build_dir
                )
            self.assertIsNotNone(mutated_root)
            self.assertFalse(mutated_root.exists())
            self.assertEqual(sibling.read_bytes(), b"preserve\n")
            self.assertIsNone(authority.execution_projection)
            self.assertIsNone(authority.execution_projection_receipt)
            self.assertFalse(
                byte_identity.execution_projection_finalization_path(
                    self.build_dir
                ).exists()
            )
            self.assertFalse(
                (self.build_dir
                 / "byte-identity/audit/framework-verdict.json").exists()
            )
            self.assertEqual(scans, [str(mutated_root / "z")])

    def test_execution_projection_refuses_unplanned_writable_topology(self):
        self.ensure_inventory()
        output = self.build_dir / "objects/unit.obj"
        pdb = self.build_dir / "objects/unit.pdb"
        self.attest_command(
            self.launch_args(output, pdb, ensure_inventory=False)
        )
        original_expected = (
            byte_identity.expected_projection_writable_membership
        )
        original_membership = byte_identity._projection_writable_membership
        with byte_identity.build_transaction(
            self.build_dir, exclusive=True, bootstrap_outer_session=True,
        ) as authority:
            state = byte_identity.validate_manifest(
                self.manifest, self.source_dir, self.build_dir,
                configured_compiler=str(self.compiler),
            )
            byte_identity.materialize_runtime_bin(state, self.build_dir)
            inventory = byte_identity.load_inventory(state, self.build_dir)
            state["inventory"] = inventory
            command_document = byte_identity.strict_json_loads(
                authority.read_bytes(
                    byte_identity.command_inventory_path(self.build_dir)
                )
            )
            byte_identity.materialize_command_snapshot(
                state, inventory, command_document["entries"], self.build_dir
            )
            state["command_inventory"] = (
                byte_identity.load_command_inventory(
                    state, inventory, self.build_dir
                )
            )
            for kind in ("file", "directory", "symlink", "casefold"):
                with self.subTest(injected_entry=kind):
                    injected = False

                    def inject_unplanned(build_seat, *args, **kwargs):
                        nonlocal injected
                        expected = original_expected(
                            build_seat, *args, **kwargs
                        )
                        injected = True
                        if kind == "file":
                            authority.atomic_write(
                                Path(build_seat) / "ambient.lib",
                                b"unplanned\n", mode=0o400,
                            )
                        elif kind == "directory":
                            authority.mkdirs(
                                Path(build_seat) / "ambient-directory"
                            )
                        elif kind == "symlink":
                            authority.atomic_symlink(
                                Path(build_seat) / "ambient-alias",
                                Path("objects"),
                            )
                        return expected

                    with ExitStack() as stack:
                        stack.enter_context(mock.patch.object(
                            byte_identity,
                            "expected_projection_writable_membership",
                            side_effect=inject_unplanned,
                        ))
                        if kind == "casefold":
                            def report_case_alias(path):
                                return [
                                    *original_membership(path),
                                    ("Objects", "directory"),
                                ]

                            stack.enter_context(mock.patch.object(
                                byte_identity,
                                "_projection_writable_membership",
                                side_effect=report_case_alias,
                            ))
                        stack.enter_context(
                            self.assertRaises(byte_identity.ByteIdentityError)
                        )
                        byte_identity.prepare_virtual_z_run(
                            state=state, build_dir=self.build_dir,
                            target="fixture", source_relative="src/unit.cpp",
                            role=f"topology-{kind}", cwd=self.build_dir,
                            logical_outputs=[output, pdb],
                            temporary=self.build_dir / "tmp",
                        )
                    self.assertTrue(injected)
                    projection = authority.execution_projection
                    self.assertIsNotNone(projection)
                    self.assertIsNone(projection["lease"])
                    self.assertEqual(
                        byte_identity._projection_writable_membership(
                            Path(projection["writable_build_root"])
                        ),
                        [(".", "directory")],
                    )
                    guest_runs = (
                        self.build_dir / "byte-identity/guest-runs/fixture"
                    )
                    self.assertFalse(
                        guest_runs.exists()
                        and any(guest_runs.rglob(f"topology-{kind}-*"))
                    )
            byte_identity.abort_execution_projection(authority)
            self.assertIsNone(authority.execution_projection_receipt)
            self.assertFalse(
                byte_identity.execution_projection_finalization_path(
                    self.build_dir
                ).exists()
            )
            self.assertFalse(
                (self.build_dir
                 / "byte-identity/audit/framework-verdict.json").exists()
            )

    def test_execution_projection_terminal_mutation_publishes_nothing(self):
        self.ensure_inventory()
        output = self.build_dir / "objects/unit.obj"
        pdb = self.build_dir / "objects/unit.pdb"
        self.attest_command(
            self.launch_args(output, pdb, ensure_inventory=False)
        )

        def projection_state():
            state = byte_identity.validate_manifest(
                self.manifest, self.source_dir, self.build_dir,
                configured_compiler=str(self.compiler),
            )
            byte_identity.materialize_runtime_bin(state, self.build_dir)
            inventory = byte_identity.load_inventory(state, self.build_dir)
            state["inventory"] = inventory
            state["command_inventory"] = byte_identity.load_command_inventory(
                state, inventory, self.build_dir
            )
            return state

        mutated_root = None
        with self.assertRaisesRegex(
            byte_identity.ByteIdentityError,
            "transaction execution projection changed",
        ):
            with byte_identity.build_transaction(
                self.build_dir, exclusive=True,
                bootstrap_outer_session=True,
            ) as authority:
                projection = byte_identity.materialize_execution_projection(
                    projection_state(), self.build_dir
                )
                mutated_root = Path(projection["root"])
                leaf = next(
                    item for item in projection["immutable_records"]
                    if item["type"] == "file"
                )
                physical = Path(projection["z"]).joinpath(
                    *PurePosixPath(leaf["path"]).parts
                )
                os.chmod(physical, 0o600)
                physical.write_bytes(physical.read_bytes() + b"mutation")
                byte_identity.finalize_execution_projection(authority)
        self.assertIsNotNone(mutated_root)
        self.assertFalse(mutated_root.exists())
        self.assertFalse(
            byte_identity.execution_projection_finalization_path(
                self.build_dir
            ).exists()
        )

    def test_producer_prelaunch_cutpoint_rejects_post_drain_mutation(self):
        self.enable_final_image_fixture()
        self.ensure_inventory()
        compiler_object = self.build_dir / "objects/prelaunch.obj"
        compiler_pdb = self.build_dir / "objects/prelaunch.pdb"
        compiler_arguments = self.launch_args(
            compiler_object, compiler_pdb, ensure_inventory=False
        )
        self.attest_command(compiler_arguments)
        self.materialize()

        compiler_injected = False

        def inject_compiler_topology(run, state, environment, *, phase):
            nonlocal compiler_injected
            run["_wine_drain_attempted"] = True
            run["_wine_state"] = state
            run["_wine_environment"] = dict(environment)
            run[f"server_{phase}_clear"] = True
            if phase == "preflight" and not compiler_injected:
                compiler_injected = True
                byte_identity.active_build_authority().atomic_write(
                    Path(run["projection"]["writable_build_root"])
                    / "post-drain-compiler-input.lib",
                    b"unplanned compiler input\n", mode=0o400,
                )

        with (
            self.standalone_producer_diagnostic(),
            mock.patch.object(
                byte_identity, "drain_run_private_wineserver",
                side_effect=inject_compiler_topology,
            ),
            # Prefix initialization legitimately runs wineboot/wineserver
            # children before the cutpoint; only a COMPILER launch is
            # forbidden after the injected mutation.
            mock.patch.object(
                byte_identity, "run_child", return_value=(0, b"", False)
            ) as compiler_child,
        ):
            self.assertEqual(byte_identity.main(compiler_arguments), 2)
        self.assertTrue(compiler_injected)
        for call in compiler_child.call_args_list:
            self.assertNotIn(
                str(self.compiler), " ".join(map(str, call.args[0]))
            )
        self.assertFalse(compiler_object.exists())
        self.assertFalse(compiler_pdb.exists())
        self.assertFalse(
            byte_identity.audit_object_path(
                self.build_dir, "fixture", "src/unit.cpp"
            ).exists()
        )

        tool_roles = {
            "resource": "rc_wrapper",
            "archive": "lib_wrapper",
            "release-link": "link_wrapper",
        }
        for run_role, tool_role in tool_roles.items():
            with self.subTest(run_role=run_role):
                with byte_identity.build_transaction(
                    self.build_dir, exclusive=True,
                    bootstrap_outer_session=True,
                ) as authority:
                    state = byte_identity.validate_manifest(
                        self.manifest, self.source_dir, self.build_dir,
                        configured_compiler=str(self.compiler),
                    )
                    byte_identity.materialize_runtime_bin(
                        state, self.build_dir
                    )
                    inventory = byte_identity.load_inventory(
                        state, self.build_dir,
                        require_runtime_authority=True,
                    )
                    state["inventory"] = inventory
                    state["command_inventory"] = (
                        byte_identity.load_command_inventory(
                            state, inventory, self.build_dir
                        )
                    )
                    tool = next(
                        item for item in state["terminal_producers"]["link"][
                            "tools"
                        ]
                        if item["role"] == tool_role
                    )
                    generated = (
                        self.build_dir / "prelaunch-inputs"
                        / f"{run_role}.bin"
                    )
                    authority.atomic_write(
                        generated, f"{run_role} input\n".encode("ascii")
                    )
                    output = (
                        self.build_dir / "prelaunch-outputs"
                        / f"{run_role}.out"
                    )
                    temporary = (
                        self.build_dir / "prelaunch-temporary" / run_role
                    )
                    run = byte_identity.prepare_virtual_z_run(
                        state=state, build_dir=self.build_dir,
                        target="fixture", source_relative="src/unit.cpp",
                        role=run_role, cwd=self.build_dir,
                        logical_outputs=[output], temporary=temporary,
                        generated_inputs=[generated],
                    )
                    injected = False

                    def inject_after_drain(
                        current, current_state, environment, *, phase,
                    ):
                        nonlocal injected
                        current["_wine_drain_attempted"] = True
                        current["_wine_state"] = current_state
                        current["_wine_environment"] = dict(environment)
                        current[f"server_{phase}_clear"] = True
                        if phase != "preflight" or injected:
                            return
                        injected = True
                        if run_role == "resource":
                            authority.atomic_write(
                                Path(current["projection"][
                                    "writable_build_root"
                                ]) / "post-drain-resource-input.lib",
                                b"unplanned resource input\n", mode=0o400,
                            )
                        elif run_role == "archive":
                            record = current["generated_inputs"][0]
                            authority.atomic_write(
                                Path(record["physical"]),
                                b"post-drain archive mutation\n",
                                mode=record["mode"],
                            )
                        else:
                            snapshotted = byte_identity.snapshotted_tool_path(
                                current, current_state, tool
                            )
                            os.chmod(snapshotted, 0o600)

                    try:
                        with (
                            mock.patch.object(
                                byte_identity, "drain_run_private_wineserver",
                                side_effect=inject_after_drain,
                            ),
                            mock.patch.object(
                                byte_identity, "run_child"
                            ) as producer_child,
                            self.assertRaises(
                                byte_identity.ByteIdentityError
                            ),
                        ):
                            byte_identity.execute_virtual_z_producer(
                                state=state, run=run,
                                argv=[tool["absolute_path"], "/fixture"],
                                tool=tool, timeout=3,
                                use_compiler_slot=False,
                                logical_temporary=temporary,
                            )
                        self.assertTrue(injected)
                        producer_child.assert_not_called()
                        self.assertFalse(output.exists())
                    finally:
                        byte_identity.cleanup_virtual_z_run(run)
                        byte_identity.abort_execution_projection(authority)
                    self.assertFalse(Path(run["run"]).exists())
                    self.assertFalse(
                        byte_identity.execution_projection_finalization_path(
                            self.build_dir
                        ).exists()
                    )

    def test_dependency_pass_is_single_and_ledger_causality_is_coarse_then_fine(self):
        source = inspect.getsource(
            byte_identity._capture_compiler_dependencies
        )
        tree = ast.parse(source)
        child_calls = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "run_child"
        ]
        self.assertEqual(len(child_calls), 1)
        self.assertNotIn("dependencies-rederive", source)
        command = [
            str(self.compiler), "/Zi", "/O2", "/D", "NDEBUG",
            f"/FI{self.include}",
            f"/Fo{self.build_dir / 'unit.obj'}",
            f"/Fd{self.build_dir / 'unit.pdb'}",
            "-c", str(self.source),
        ]
        dependency_command = byte_identity.derive_dependency_command(
            command, self.build_dir / "dependencies.i"
        )
        self.assertEqual(
            [token.casefold() for token in dependency_command].count("/p"),
            1,
        )

        with byte_identity.build_transaction(
            self.build_dir, exclusive=True, bootstrap_outer_session=True,
        ) as authority:
            inputs = self.build_dir / "ledger-fixture"
            authority.mkdirs(inputs)
            manifest = inputs / "manifest.json"
            plan = inputs / "plan.json"
            compiler = inputs / "compiler"
            discovered_leaf = inputs / "discovered.h"
            dependency = inputs / "dependencies.i"
            seed = inputs / "seed.obj"
            for path, data in (
                (manifest, b"manifest\n"),
                (plan, b"plan\n"),
                (compiler, b"compiler\n"),
                (discovered_leaf, b"header\n"),
                (dependency, b"#line dependency\n"),
                (seed, b"seed\n"),
            ):
                authority.atomic_write(path, data)
            ledger = byte_identity.ResidentReceiptLedger(digest(b"ledger"))
            coarse = (manifest, plan, compiler)
            for index, path in enumerate(coarse):
                ledger.record_root(path, role=f"coarse:{index}")
            # The leaf set becomes known only after the one /P child.  It is
            # authenticated before /c, but is deliberately not represented as
            # an input that caused the already-produced dependency output.
            ledger.record_root(discovered_leaf, role="compiler_dependency:leaf")
            dependency_receipt = ledger.record_produced(
                dependency, stage="compiler-dependency",
                role="dependency:fixture:src/unit.cpp", inputs=list(coarse),
            )
            seed_receipt = ledger.record_produced(
                seed, stage="compiler-seed-object",
                role="seed:fixture:src/unit.cpp",
                inputs=[*coarse, discovered_leaf, dependency],
            )
            self.assertNotIn(
                str(discovered_leaf), dependency_receipt["inputs"]
            )
            self.assertIn(str(discovered_leaf), seed_receipt["inputs"])
            self.assertIn(str(dependency), seed_receipt["inputs"])
        self.assertFalse(
            (self.build_dir / "byte-identity/audit/framework-verdict.json")
            .exists()
        )

    def test_resident_input_retirement_removes_exact_roots_and_preserves_sibling(self):
        roots = byte_identity.resident_input_snapshot_roots(self.build_dir)
        sibling = (
            self.build_dir
            / "byte-identity/input-snapshots/unrelated-sibling/sentinel"
        )
        projection_receipt = (
            byte_identity.execution_projection_finalization_path(
                self.build_dir
            )
        )
        with byte_identity.build_transaction(
            self.build_dir, exclusive=True, bootstrap_outer_session=True,
        ) as authority:
            for index, root in enumerate(roots):
                authority.mkdirs(root)
                authority.atomic_write(
                    root / "payload", f"root {index}\n".encode("ascii")
                )
            authority.mkdirs(sibling.parent)
            authority.atomic_write(sibling, b"preserved\n")
            authority.atomic_write(
                projection_receipt,
                byte_identity.canonical_json_bytes({"projection": "held"}),
            )
            runtime = {
                "targets": [{
                    "name": "env", "target": "/fixture/env",
                    "sha256": "1" * 64,
                }],
            }
            authority.snapshot_validation_cache.update({
                "toolchain:" + str(
                    byte_identity.toolchain_snapshot_path(self.build_dir)
                ): {
                    "finalized": True,
                    "descriptor_sha256": "2" * 64,
                    "runtime_bin": runtime,
                },
                byte_identity.command_snapshot_cache_key(self.build_dir): {
                    "finalized": True,
                    "descriptor_sha256": "3" * 64,
                },
                byte_identity._native_reccmp_cache_key(self.build_dir): {
                    "finalized": True,
                    "descriptor_sha256": "4" * 64,
                },
            })
            state = {
                "manifest_sha256": "5" * 64,
                "toolchain_fingerprint": "6" * 64,
            }
            with mock.patch.object(
                byte_identity, "validate_runtime_bin", return_value=runtime
            ) as validate_runtime:
                receipt, retired = (
                    byte_identity.retire_resident_input_snapshots(
                        state, self.build_dir
                    )
                )
            validate_runtime.assert_called_once_with(state, self.build_dir)
            self.assertEqual(retired, roots)
            self.assertTrue(receipt["roots_removed"])
            self.assertEqual(sibling.read_bytes(), b"preserved\n")
            for root in roots:
                self.assertFalse(root.exists())
            self.assertEqual(
                byte_identity.validate_resident_input_retirement_evidence(
                    authority, self.build_dir
                ),
                receipt,
            )

            # Even when one exact-root remover reports a late failure, every
            # independent cleanup lane runs, the compact receipt is retracted,
            # and no unrelated sibling is swept.
            for index, root in enumerate(roots):
                authority.mkdirs(root)
                authority.atomic_write(
                    root / "payload",
                    f"failure root {index}\n".encode("ascii"),
                )
            original_rollback = byte_identity.rollback_exact_private_run
            calls = []

            def remove_then_report_failure(current_authority, root):
                original_rollback(current_authority, root)
                calls.append(Path(root))
                if len(calls) == 1:
                    raise byte_identity.ByteIdentityError(
                        "forced late exact-root cleanup failure"
                    )

            with (
                mock.patch.object(
                    byte_identity, "rollback_exact_private_run",
                    side_effect=remove_then_report_failure,
                ),
                self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "forced late exact-root cleanup failure",
                ),
            ):
                byte_identity.discard_resident_input_snapshots(
                    authority, self.build_dir, invalidate_receipt=True
                )
            self.assertEqual(calls, roots)
            for root in roots:
                self.assertFalse(root.exists())
            self.assertFalse(
                byte_identity.resident_input_retirement_path(
                    self.build_dir
                ).exists()
            )
            self.assertEqual(sibling.read_bytes(), b"preserved\n")

    def test_execution_projection_poison_abort_cleans_exact_never_launched_run(self):
        self.ensure_inventory()
        output = self.build_dir / "objects/unit.obj"
        pdb = self.build_dir / "objects/unit.pdb"
        self.attest_command(
            self.launch_args(output, pdb, ensure_inventory=False)
        )

        def projection_state():
            state = byte_identity.validate_manifest(
                self.manifest, self.source_dir, self.build_dir,
                configured_compiler=str(self.compiler),
            )
            byte_identity.materialize_runtime_bin(state, self.build_dir)
            inventory = byte_identity.load_inventory(state, self.build_dir)
            state["inventory"] = inventory
            state["command_inventory"] = byte_identity.load_command_inventory(
                state, inventory, self.build_dir
            )
            return state

        poisoned_root = None
        original_clear = byte_identity._clear_execution_projection_writable_branch
        clear_calls = []

        def fail_once(projection):
            clear_calls.append(Path(projection["root"]))
            if len(clear_calls) == 1:
                raise byte_identity.ByteIdentityError(
                    "forced writable-seat clear failure"
                )
            return original_clear(projection)

        with self.assertRaisesRegex(
            byte_identity.ByteIdentityError,
            "forced transaction abort after poisoned seat",
        ):
            with mock.patch.object(
                byte_identity,
                "_clear_execution_projection_writable_branch",
                side_effect=fail_once,
            ):
                with byte_identity.build_transaction(
                    self.build_dir, exclusive=True,
                    bootstrap_outer_session=True,
                ) as authority:
                    state = projection_state()
                    projection = byte_identity.materialize_execution_projection(
                        state, self.build_dir
                    )
                    poisoned_root = Path(projection["root"])
                    never_launched = Path(projection["runs_root"]) / "never-launched"
                    held, token = byte_identity.acquire_execution_projection(
                        state, self.build_dir, role="dependencies",
                        run_root=never_launched,
                    )
                    held["owned_run"] = {
                        "run": never_launched,
                        "prefix": held["prefix"],
                        "projection": held,
                        "projection_lease": token,
                        "_wine_drain_attempted": False,
                        "producer_child_started": False,
                    }
                    authority.mkdirs(Path(held["owned_run"]["run"]))
                    with self.assertRaisesRegex(
                        byte_identity.ByteIdentityError,
                        "forced writable-seat clear failure",
                    ):
                        byte_identity.release_execution_projection({
                            "projection": held,
                            "projection_lease": token,
                            "prefix": held["prefix"],
                        })
                    self.assertTrue(held["poisoned"])
                    with self.assertRaisesRegex(
                        byte_identity.ByteIdentityError,
                        "execution projection authority differs",
                    ):
                        byte_identity.acquire_execution_projection(
                            state, self.build_dir, role="seed",
                            run_root=self.build_dir / "forbidden-reacquire",
                        )
                    with self.assertRaisesRegex(
                        byte_identity.ByteIdentityError,
                        "cannot finalize while leased or poisoned",
                    ):
                        byte_identity.finalize_execution_projection(authority)
                    raise byte_identity.ByteIdentityError(
                        "forced transaction abort after poisoned seat"
                    )
        self.assertEqual(len(clear_calls), 2)
        self.assertFalse(poisoned_root.exists())
        self.assertFalse(never_launched.exists())
        self.assertFalse(
            byte_identity.execution_projection_finalization_path(
                self.build_dir
            ).exists()
        )

    def test_execution_transaction_marker_is_o1_and_recovery_is_bounded(self):
        self.ensure_inventory()
        output = self.build_dir / "objects/unit.obj"
        pdb = self.build_dir / "objects/unit.pdb"
        self.attest_command(
            self.launch_args(output, pdb, ensure_inventory=False)
        )
        nonce = "9" * 64
        marker_path = byte_identity.execution_projection_recovery_path(
            self.build_dir
        )
        marker_writes = []
        prefix_scans = []
        recover_calls = []
        real_atomic_json = byte_identity.atomic_json
        real_prefix_scan = byte_identity.snapshot_run_prefix
        real_recover = byte_identity.recover_execution_projection_if_needed

        def track_json(path, document, *args, **kwargs):
            if Path(path) == marker_path:
                marker_writes.append(document["phase"])
            return real_atomic_json(path, document, *args, **kwargs)

        def track_prefix(*args, **kwargs):
            prefix_scans.append(Path(args[0]))
            return real_prefix_scan(*args, **kwargs)

        def track_recover(*args, **kwargs):
            recover_calls.append(True)
            return real_recover(*args, **kwargs)

        with byte_identity.build_transaction(
            self.build_dir, exclusive=True, bootstrap_outer_session=True,
        ) as authority, byte_identity.resident_receipt_scope(nonce):
            state = byte_identity.validate_manifest(
                self.manifest, self.source_dir, self.build_dir,
                configured_compiler=str(self.compiler),
            )
            byte_identity.materialize_runtime_bin(state, self.build_dir)
            inventory = byte_identity.load_inventory(state, self.build_dir)
            state["inventory"] = inventory
            command_document = byte_identity.strict_json_loads(
                authority.read_bytes(
                    byte_identity.command_inventory_path(self.build_dir)
                )
            )
            byte_identity.materialize_command_snapshot(
                state, inventory, command_document["entries"], self.build_dir
            )
            state["command_inventory"] = (
                byte_identity.load_command_inventory(
                    state, inventory, self.build_dir
                )
            )
            with (
                mock.patch.object(
                    byte_identity, "atomic_json", side_effect=track_json
                ),
                mock.patch.object(
                    byte_identity, "snapshot_run_prefix",
                    side_effect=track_prefix,
                ),
                mock.patch.object(
                    byte_identity, "recover_execution_projection_if_needed",
                    side_effect=track_recover,
                ),
            ):
                projection = byte_identity.materialize_execution_projection(
                    state, self.build_dir
                )
                prefix_identity = projection["prefix"].stat().st_ino
                for index in range(5):
                    run_root = Path(projection["runs_root"]) / f"run-{index}"
                    authority.mkdir_exclusive(run_root)
                    held, token = byte_identity.acquire_execution_projection(
                        state, self.build_dir, role=f"role-{index}",
                        run_root=run_root,
                    )
                    run = {
                        "run": run_root, "prefix": held["prefix"],
                        "projection": held, "projection_lease": token,
                    }
                    byte_identity.mark_virtual_z_child_started(run)
                    held["prefix_quiescent"] = True
                    byte_identity.release_execution_projection(run)
                    authority.remove_tree(run_root)
                    authority.assert_absent(run_root)
                    self.assertEqual(
                        held["prefix"].stat().st_ino, prefix_identity
                    )
                byte_identity.finalize_execution_projection(authority)

        self.assertEqual(recover_calls, [True])
        self.assertEqual(
            marker_writes,
            [
                "projection-reserved", "projection-ready",
                "child-may-have-started", "root-removing", "root-removed",
            ],
        )
        self.assertEqual(len(prefix_scans), 2)
        self.assertFalse(marker_path.exists())

        sibling = (
            self.build_dir
            / "byte-identity/execution-projections/session-sibling/sentinel"
        )
        with byte_identity.build_transaction(
            self.build_dir, exclusive=True, bootstrap_outer_session=True,
        ) as authority, byte_identity.resident_receipt_scope(nonce):
            authority.mkdirs(sibling.parent)
            authority.atomic_write(sibling, b"preserved\n")
            state = byte_identity.validate_manifest(
                self.manifest, self.source_dir, self.build_dir,
                configured_compiler=str(self.compiler),
            )
            byte_identity.materialize_runtime_bin(state, self.build_dir)
            inventory = byte_identity.load_inventory(state, self.build_dir)
            state["inventory"] = inventory
            command_document = byte_identity.strict_json_loads(
                authority.read_bytes(
                    byte_identity.command_inventory_path(self.build_dir)
                )
            )
            byte_identity.materialize_command_snapshot(
                state, inventory, command_document["entries"], self.build_dir
            )
            state["command_inventory"] = (
                byte_identity.load_command_inventory(
                    state, inventory, self.build_dir
                )
            )
            projection = byte_identity.materialize_execution_projection(
                state, self.build_dir
            )
            byte_identity.update_execution_transaction_marker(
                projection, "child-may-have-started"
            )
            root = Path(projection["root"])
            projection["holder"].close()
            authority.execution_projection = None
            with (
                mock.patch.object(
                    byte_identity, "drain_recovered_wine_prefix",
                    side_effect=byte_identity.ByteIdentityError(
                        "forced retained recovery drain"
                    ),
                ),
                self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "forced retained recovery drain",
                ),
            ):
                byte_identity.recover_execution_projection_if_needed(
                    self.build_dir,
                    current_manifest=Path(state["manifest_path"]),
                )
            self.assertTrue(root.is_dir())
            self.assertTrue(marker_path.is_file())
            byte_identity.discard_resident_input_snapshots(
                authority, self.build_dir, invalidate_receipt=True
            )
            self.assertTrue(
                byte_identity.toolchain_snapshot_path(self.build_dir).is_dir()
            )
            with mock.patch.object(
                byte_identity, "drain_recovered_wine_prefix"
            ) as drain:
                byte_identity.recover_execution_projection_if_needed(
                    self.build_dir,
                    current_manifest=Path(state["manifest_path"]),
                )
            drain.assert_called_once()
            self.assertFalse(root.exists())
            self.assertFalse(marker_path.exists())
            self.assertEqual(sibling.read_bytes(), b"preserved\n")

    def test_terminal_map_and_member_pull_evidence_is_independent(self):
        policy = {
            "map_evidence": [
                {"symbol": "??3@YAXPAX@Z", "address": "0x10086260",
                 "library": "SHLW32MT.LIB", "member": "shnew.obj"},
                {"symbol": "_SmackGetSizeDeltas", "address": "0x100d1f2c",
                 "library": "smackw32.lib", "member": "smackw32.obj"},
                {"symbol": "_strstr", "address": "0x100d21f0",
                 "library": "libcmt.lib", "member": "strstr.obj"},
            ],
            "member_evidence": [
                {"symbol": "??3@YAXPAX@Z",
                 "referenced_in": "helicopter.cpp.obj",
                 "library": "SHLW32MT.LIB", "member": "shnew.obj"},
                {"symbol": "_SmackGetSizeDeltas",
                 "referenced_in": "omni.lib(mxsmk.cpp.obj)",
                 "library": "smackw32.lib", "member": "smackw32.obj"},
                {"symbol": "_strstr",
                 "referenced_in": "omni.lib(mxutilities.cpp.obj)",
                 "library": "libcmt.lib", "member": "strstr.obj"},
            ],
        }
        map_data = (
            b" 0001:00085260 ??3@YAXPAX@Z 10086260 f SHLW32MT:shnew.obj\n"
            b" 0001:000d0f2c _SmackGetSizeDeltas 100d1f2c f "
            b"smackw32:smackw32.obj\n"
            b" 0001:000d11f0 _strstr 100d21f0 f libcmt:strstr.obj\n"
        )
        verbose = (
            b"Found ??3@YAXPAX@Z\n"
            b" Referenced in helicopter.cpp.obj\n"
            b" Loaded SHLW32MT.LIB(shnew.obj)\n"
            b"Found _SmackGetSizeDeltas\n"
            b" Referenced in omni.lib(mxsmk.cpp.obj)\n"
            b" Loaded smackw32.lib(smackw32.obj)\n"
            b"Found _strstr\n"
            b" Referenced in omni.lib(mxutilities.cpp.obj)\n"
            b" Loaded libcmt.lib(strstr.obj)\n"
        )
        maps, members = byte_identity.validate_link_evidence(
            map_data, verbose, policy
        )
        self.assertEqual(maps, policy["map_evidence"])
        self.assertEqual(members, policy["member_evidence"])

        stale_causality = json.loads(json.dumps(policy))
        stale_causality["member_evidence"][2]["referenced_in"] = (
            "omni.lib(mxsmk.cpp.obj)"
        )
        with self.assertRaisesRegex(
            byte_identity.ByteIdentityError, "member-pull evidence is absent"
        ):
            byte_identity.validate_link_evidence(
                map_data, verbose, stale_causality
            )

    def test_invalidate_removes_verdict_symlink_without_touching_target(self):
        verdict = self.build_dir / "byte-identity/audit/framework-verdict.json"
        verdict.parent.mkdir(parents=True)
        outside = self.directory / "outside-verdict.json"
        outside.write_bytes(b"OUTSIDE-VERDICT-SENTINEL")
        verdict.symlink_to(outside)
        self.assertEqual(
            byte_identity.main(["invalidate", "--build-dir", str(self.build_dir)]),
            0,
        )
        self.assertFalse(verdict.exists())
        self.assertFalse(verdict.is_symlink())
        self.assertEqual(outside.read_bytes(), b"OUTSIDE-VERDICT-SENTINEL")

    def test_transitive_compiler_support_hash_is_pinned(self):
        self.compiler_support.write_text("mutated compiler support\n")
        self.assertEqual(byte_identity.main(self.plan_args()), 2)
        self.assertFalse(self.plan.exists())

    def test_stale_source_hash_refuses_without_plan(self):
        self.document["translation_units"][0]["source_sha256"] = "0" * 64
        self.write_manifest()
        self.assertEqual(byte_identity.main(self.plan_args()), 2)
        self.assertFalse(self.plan.exists())

    def test_plan_refuses_source_tree_output(self):
        arguments = self.plan_args()
        arguments[arguments.index(str(self.plan))] = str(self.source_dir / "plan.cmake")
        self.assertEqual(byte_identity.main(arguments), 2)

    def test_transaction_lock_never_follows_build_namespace_symlink(self):
        state = self.build_dir / "byte-identity"
        state.mkdir()
        outside = self.directory / "outside-locks"
        outside.mkdir()
        (state / "locks").symlink_to(outside, target_is_directory=True)
        self.assertEqual(byte_identity.main(self.plan_args()), 2)
        self.assertFalse((outside / "transaction.lock").exists())
        self.assertFalse(self.plan.exists())

    def test_transaction_lock_parent_swap_is_detected_after_open(self):
        locks = self.build_dir / "byte-identity/locks"
        detached = self.build_dir / "byte-identity/locks-detached"
        outside = self.directory / "outside-lock-swap"
        outside.mkdir()
        sentinel = outside / "sentinel.bin"
        sentinel.write_bytes(b"OUTSIDE-LOCK-SENTINEL")
        real_stat = byte_identity.os.stat
        swapped = False

        def swapping_stat(path, *args, dir_fd=None, **kwargs):
            nonlocal swapped
            if (
                not swapped
                and path == "transaction.lock"
                and dir_fd is not None
                and kwargs.get("follow_symlinks") is False
            ):
                locks.rename(detached)
                locks.symlink_to(outside, target_is_directory=True)
                swapped = True
            return real_stat(path, *args, dir_fd=dir_fd, **kwargs)

        byte_identity.os.stat = swapping_stat
        try:
            result = byte_identity.main(self.plan_args())
        finally:
            byte_identity.os.stat = real_stat
        self.assertEqual(result, 2)
        self.assertTrue(swapped)
        self.assertEqual(sentinel.read_bytes(), b"OUTSIDE-LOCK-SENTINEL")
        self.assertFalse((outside / "transaction.lock").exists())
        self.assertFalse(self.plan.exists())

    def test_materialize_refuses_generated_ancestor_source_tree_escape(self):
        output = self.materialize()
        generated = output.parent
        detached = generated.with_name("generated-detached")
        generated.rename(detached)
        source_sentinel = self.source_dir / output.name
        source_sentinel.write_bytes(b"SOURCE-TREE-SENTINEL")
        generated.symlink_to(self.source_dir, target_is_directory=True)
        verdict = self.build_dir / "byte-identity/audit/framework-verdict.json"
        self.assertEqual(
            byte_identity.main([
                "materialize",
                "--manifest", str(self.manifest),
                "--source-dir", str(self.source_dir),
                "--build-dir", str(self.build_dir),
                "--recipe-id", self.recipe_id,
                "--output", str(output),
            ]),
            2,
        )
        self.assertEqual(source_sentinel.read_bytes(), b"SOURCE-TREE-SENTINEL")
        self.assertFalse(verdict.exists())

    def test_normal_launch_cleanup_is_stable_across_ancestor_swap(self):
        self.materialize()
        output_directory = self.build_dir / "objects/normal-cleanup-swap"
        output_directory.mkdir(parents=True)
        output = output_directory / "unit.obj"
        pdb = output_directory / "unit.pdb"
        output.write_bytes(b"STALE-OBJECT")
        pdb.write_bytes(b"STALE-PDB")
        arguments = self.launch_args(output, pdb)
        outside = self.directory / "outside-normal-cleanup"
        outside.mkdir()
        outside_object = outside / output.name
        outside_pdb = outside / pdb.name
        outside_object.write_bytes(b"OUTSIDE-OBJECT")
        outside_pdb.write_bytes(b"OUTSIDE-PDB")
        detached = output_directory.with_name("normal-cleanup-detached")
        started = self.directory / "normal-cleanup.started"
        real_unlink = byte_identity.os.unlink
        swapped = False

        def swapping_unlink(path, *args, dir_fd=None, **kwargs):
            nonlocal swapped
            if not swapped and path == output.name and dir_fd is not None:
                output_directory.rename(detached)
                output_directory.symlink_to(outside, target_is_directory=True)
                swapped = True
            return real_unlink(path, *args, dir_fd=dir_fd, **kwargs)

        with (
            self.fake_control(STARTED=str(started)),
            self.standalone_producer_diagnostic(),
        ):
            previous = Path.cwd()
            byte_identity.os.unlink = swapping_unlink
            try:
                os.chdir(self.build_dir)
                result = byte_identity.main(arguments)
            finally:
                os.chdir(previous)
                byte_identity.os.unlink = real_unlink
        self.assertEqual(result, 2)
        self.assertTrue(swapped)
        self.assertFalse(started.exists())
        self.assertEqual(outside_object.read_bytes(), b"OUTSIDE-OBJECT")
        self.assertEqual(outside_pdb.read_bytes(), b"OUTSIDE-PDB")
        self.assertFalse(
            byte_identity.audit_object_path(
                self.build_dir, "fixture", "src/unit.cpp"
            ).exists()
        )
        self.assertFalse(
            (self.build_dir / "byte-identity/audit/framework-verdict.json").exists()
        )

    def test_normal_launch_install_is_stable_across_ancestor_swap(self):
        self.materialize()
        output_directory = self.build_dir / "objects/normal-install-swap"
        output_directory.mkdir(parents=True)
        output = output_directory / "unit.obj"
        pdb = output_directory / "unit.pdb"
        arguments = self.launch_args(output, pdb)
        outside = self.directory / "outside-normal-install"
        outside.mkdir()
        outside_object = outside / output.name
        outside_pdb = outside / pdb.name
        outside_object.write_bytes(b"OUTSIDE-INSTALL-OBJECT")
        outside_pdb.write_bytes(b"OUTSIDE-INSTALL-PDB")
        detached = output_directory.with_name("normal-install-detached")
        real_rename = byte_identity.os.rename
        swapped = False

        def swapping_rename(source, destination, *args, **kwargs):
            nonlocal swapped
            if (not swapped and destination == pdb.name
                    and kwargs.get("dst_dir_fd") is not None):
                output_directory.rename(detached)
                output_directory.symlink_to(outside, target_is_directory=True)
                swapped = True
            return real_rename(source, destination, *args, **kwargs)

        previous = Path.cwd()
        byte_identity.os.rename = swapping_rename
        try:
            with self.standalone_producer_diagnostic():
                os.chdir(self.build_dir)
                result = byte_identity.main(arguments)
        finally:
            os.chdir(previous)
            byte_identity.os.rename = real_rename
        self.assertEqual(result, 2)
        self.assertTrue(swapped)
        self.assertEqual(outside_object.read_bytes(), b"OUTSIDE-INSTALL-OBJECT")
        self.assertEqual(outside_pdb.read_bytes(), b"OUTSIDE-INSTALL-PDB")
        self.assertFalse(
            byte_identity.audit_object_path(
                self.build_dir, "fixture", "src/unit.cpp"
            ).exists()
        )
        self.assertFalse(
            (self.build_dir / "byte-identity/audit/framework-verdict.json").exists()
        )

    def test_private_compiler_directory_swap_is_detected_before_install(self):
        self.materialize()
        output = self.build_dir / "objects/private-directory-swap.obj"
        pdb = self.build_dir / "objects/private-directory-swap.pdb"
        output.parent.mkdir(parents=True)
        arguments = self.launch_args(output, pdb)
        outside = self.directory / "outside-private-directory"
        outside.mkdir()
        outside_sentinel = outside / "sentinel.bin"
        outside_sentinel.write_bytes(b"OUTSIDE-PRIVATE-SENTINEL")
        real_run_child = byte_identity.run_child
        swapped = False

        def swapping_run_child(*args, **kwargs):
            nonlocal swapped
            result = real_run_child(*args, **kwargs)
            environment = args[2]
            if (not swapped
                    and "ISLE_BYTE_IDENTITY_VIRTUAL_Z_ROOT" in environment
                    and any(token == f"/Fo{output}" for token in args[0])):
                z_root = Path(environment["ISLE_BYTE_IDENTITY_VIRTUAL_Z_ROOT"])
                physical_directory = z_root.joinpath(*output.parent.parts[1:])
                detached = physical_directory.with_name(
                    physical_directory.name + "-detached"
                )
                # Model a same-user active namespace attacker. The production
                # parent is readonly, so the test must first exercise that
                # extra authority before attempting a swap.
                physical_directory.parent.chmod(0o700)
                physical_directory.rename(detached)
                physical_directory.symlink_to(outside, target_is_directory=True)
                swapped = True
            return result

        previous = Path.cwd()
        byte_identity.run_child = swapping_run_child
        try:
            with self.standalone_producer_diagnostic():
                os.chdir(self.build_dir)
                result = byte_identity.main(arguments)
        finally:
            os.chdir(previous)
            byte_identity.run_child = real_run_child
        self.assertEqual(result, 2)
        self.assertTrue(swapped)
        self.assertEqual(
            outside_sentinel.read_bytes(), b"OUTSIDE-PRIVATE-SENTINEL"
        )
        self.assertFalse((outside / "output.obj").exists())
        self.assertFalse((outside / "output.pdb").exists())
        self.assertFalse(output.exists())
        self.assertFalse(pdb.exists())
        self.assertFalse(
            byte_identity.audit_object_path(
                self.build_dir, "fixture", "src/unit.cpp"
            ).exists()
        )
        self.assertFalse(
            (self.build_dir / "byte-identity/audit/framework-verdict.json").exists()
        )

    def test_virtual_z_transport_rejects_input_prefix_runtime_and_path_leaks(self):
        self.materialize()
        original_source = self.source.read_bytes()
        cases = [
            ("virtual-input", {"MUTATE_VIRTUAL_INPUT": True}),
            ("prefix-state", {"MUTATE_PREFIX": True}),
            ("physical-path-leak", {"LEAK_VIRTUAL_Z": True}),
            # Runtime mutation is last because it deliberately poisons the
            # shared session snapshot; every earlier case starts from a fresh
            # inventory/materialization snapshot as well.
            ("runtime-snapshot", {"MUTATE_RUNTIME_SNAPSHOT": True}),
        ]
        for index, (label, control) in enumerate(cases):
            with self.subTest(label=label):
                self.ensure_inventory()
                output = self.build_dir / f"objects/transport-{index}.obj"
                pdb = self.build_dir / f"objects/transport-{index}.pdb"
                output.parent.mkdir(parents=True, exist_ok=True)
                arguments = self.launch_args(
                    output, pdb, ensure_inventory=False
                )
                self.attest_command(arguments)
                previous = Path.cwd()
                with (
                    self.fake_control(**control),
                    self.standalone_producer_diagnostic(),
                ):
                    try:
                        os.chdir(self.build_dir)
                        result = byte_identity.main(arguments)
                    finally:
                        os.chdir(previous)
                self.assertEqual(result, 2)
                self.assertEqual(self.source.read_bytes(), original_source)
                self.assertFalse(output.exists())
                self.assertFalse(pdb.exists())
                self.assertFalse(
                    byte_identity.audit_object_path(
                        self.build_dir, "fixture", "src/unit.cpp"
                    ).exists()
                )
                self.assertFalse(
                    (self.build_dir / "byte-identity/audit/framework-verdict.json").exists()
                )
                guest_root = self.build_dir / "byte-identity/guest-runs"
                if guest_root.is_dir():
                    self.assertEqual(list(guest_root.glob("*/*/*")), [])

    def test_verify_audit_read_swap_cannot_publish_stale_verdict(self):
        self.materialize()
        output = self.build_dir / "objects/verify-read-swap.obj"
        pdb = self.build_dir / "objects/verify-read-swap.pdb"
        output.parent.mkdir(parents=True)
        previous = Path.cwd()
        try:
            os.chdir(self.build_dir)
            self.assertEqual(
                self.run_standalone_producer_diagnostic(
                    self.launch_args(output, pdb)
                ),
                0,
            )
            self.assertEqual(self.run_resident_verifier_diagnostic(), 0)
        finally:
            os.chdir(previous)
        audit = byte_identity.audit_object_path(
            self.build_dir, "fixture", "src/unit.cpp"
        )
        outside = self.directory / "outside-verify-audit"
        outside.mkdir()
        outside_audit = outside / audit.name
        outside_audit.write_text('{"object":"OUTSIDE","pdb":"OUTSIDE"}\n')
        detached = audit.parent.with_name("verify-audit-detached")
        real_open = byte_identity.os.open
        swapped = False

        def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal swapped
            if (not swapped and path == audit.name and dir_fd is not None
                    and not flags & byte_identity.os.O_DIRECTORY):
                audit.parent.rename(detached)
                audit.parent.symlink_to(outside, target_is_directory=True)
                swapped = True
            return real_open(path, flags, mode, dir_fd=dir_fd)

        byte_identity.os.open = swapping_open
        try:
            result = self.run_resident_verifier_diagnostic()
        finally:
            byte_identity.os.open = real_open
        self.assertEqual(result, 2)
        self.assertTrue(swapped)
        self.assertEqual(
            outside_audit.read_text(),
            '{"object":"OUTSIDE","pdb":"OUTSIDE"}\n',
        )
        self.assertFalse(
            (self.build_dir / "byte-identity/audit/framework-verdict.json").exists()
        )

    def test_verify_rejects_audit_leaf_replacement_after_enumeration(self):
        self.materialize()
        output = self.build_dir / "objects/verify-leaf-swap.obj"
        pdb = self.build_dir / "objects/verify-leaf-swap.pdb"
        output.parent.mkdir(parents=True)
        previous = Path.cwd()
        try:
            os.chdir(self.build_dir)
            self.assertEqual(
                self.run_standalone_producer_diagnostic(
                    self.launch_args(output, pdb)
                ),
                0,
            )
            self.assertEqual(self.run_resident_verifier_diagnostic(), 0)
        finally:
            os.chdir(previous)
        audit = byte_identity.audit_object_path(
            self.build_dir, "fixture", "src/unit.cpp"
        )
        original = audit.read_bytes()
        replaced = audit.with_suffix(".replaced")
        real_read_unique_audit = byte_identity.read_unique_audit
        swapped = False

        def swapping_read_unique_audit(path, *args, **kwargs):
            nonlocal swapped
            if not swapped and path.name == audit.name:
                audit.rename(replaced)
                audit.write_bytes(original)
                swapped = True
            return real_read_unique_audit(path, *args, **kwargs)

        byte_identity.read_unique_audit = swapping_read_unique_audit
        try:
            result = self.run_resident_verifier_diagnostic()
        finally:
            byte_identity.read_unique_audit = real_read_unique_audit
        self.assertEqual(result, 2)
        self.assertTrue(swapped)
        self.assertFalse(
            (self.build_dir / "byte-identity/audit/framework-verdict.json").exists()
        )

    def test_verdict_publication_swap_removes_redirect_not_outside_state(self):
        self.materialize()
        output = self.build_dir / "objects/verdict-swap.obj"
        pdb = self.build_dir / "objects/verdict-swap.pdb"
        output.parent.mkdir(parents=True)
        previous = Path.cwd()
        try:
            os.chdir(self.build_dir)
            self.assertEqual(
                self.run_standalone_producer_diagnostic(
                    self.launch_args(output, pdb)
                ),
                0,
            )
        finally:
            os.chdir(previous)
        audit_root = self.build_dir / "byte-identity/audit"
        detached = audit_root.with_name("audit-publication-detached")
        outside = self.directory / "outside-verdict-publication"
        outside.mkdir()
        outside_verdict = outside / "framework-verdict.json"
        outside_verdict.write_bytes(b"OUTSIDE-VERDICT")
        real_rename = byte_identity.os.rename
        swapped = False

        def swapping_rename(source, destination, *args, **kwargs):
            nonlocal swapped
            if (not swapped and destination == "framework-verdict.json"
                    and kwargs.get("dst_dir_fd") is not None):
                audit_root.rename(detached)
                audit_root.symlink_to(outside, target_is_directory=True)
                swapped = True
            return real_rename(source, destination, *args, **kwargs)

        byte_identity.os.rename = swapping_rename
        try:
            result = self.run_resident_verifier_diagnostic()
        finally:
            byte_identity.os.rename = real_rename
        self.assertEqual(result, 2)
        self.assertTrue(swapped)
        self.assertEqual(outside_verdict.read_bytes(), b"OUTSIDE-VERDICT")
        self.assertFalse(audit_root.exists())
        self.assertFalse(audit_root.is_symlink())
        self.assertFalse(
            (self.build_dir / "byte-identity/audit/framework-verdict.json").exists()
        )

    def test_manifest_rejects_duplicate_section_and_retail_seats(self):
        self.enable_composer_fixture()
        self.add_distinct_shape_recipe()
        functions = self.document["translation_units"][0]["functions"]
        functions[1]["expected_section_number"] = functions[0][
            "expected_section_number"
        ]
        self.write_manifest()
        self.assertEqual(byte_identity.main(self.plan_args()), 2)

        self.enable_composer_fixture()
        self.add_shared_recipe_unit()
        units = self.document["translation_units"]
        units[1]["functions"][0]["retail_oracle"] = json.loads(
            json.dumps(units[0]["functions"][0]["retail_oracle"])
        )
        self.write_manifest()
        self.assertEqual(byte_identity.main(self.plan_args()), 2)
        self.assertFalse((self.source_dir / "plan.cmake").exists())

    def test_opaque_recipe_is_forbidden(self):
        recipe = self.document["translation_units"][0]["donors"][0]["recipe"]
        recipe["kind"] = "opaque_obj"
        self.write_manifest()
        self.assertEqual(byte_identity.main(self.plan_args()), 2)

    def test_authoritative_manifest_rejects_diagnostic_pass_through(self):
        self.document.pop("diagnostic_policy")
        self.write_manifest()
        self.assertEqual(byte_identity.main(self.plan_args()), 2)
        self.assertFalse(self.plan.exists())

    def test_legacy_entropy_recipe_and_seed_are_forbidden(self):
        recipe = self.document["translation_units"][0]["donors"][0]["recipe"]
        recipe.clear()
        recipe.update({"kind": "entropy", "seed": "retired-seed"})
        self.write_manifest()
        self.assertEqual(byte_identity.main(self.plan_args()), 2)
        self.assertFalse(self.plan.exists())

    def test_donor_authenticity_is_exact(self):
        donor = self.document["translation_units"][0]["donors"][0]
        donor["authenticity"] = "period_plausible"
        self.write_manifest()
        self.assertEqual(byte_identity.main(self.plan_args()), 2)
        self.assertFalse(self.plan.exists())

    def test_duplicate_manifest_key_is_forbidden(self):
        raw = self.manifest.read_text()
        self.manifest.write_text(raw.replace('"schema": 2,', '"schema": 2,\n  "schema": 2,', 1))
        self.assertEqual(byte_identity.main(self.plan_args()), 2)

    def test_unsupported_splice_class_is_fatal(self):
        self.document["translation_units"][0]["functions"] = [
            {"mangled": "?Function@@YAXXZ", "splice_class": "same_slot_xdata"}
        ]
        self.write_manifest()
        self.assertEqual(byte_identity.main(self.plan_args()), 2)

    def test_atomic_launcher_diagnostic_has_no_terminal_authority(self):
        self.materialize()
        output = self.build_dir / "objects/unit.obj"
        pdb = self.build_dir / "objects/unit.pdb"
        output.parent.mkdir(parents=True)
        output.write_bytes(b"STALE")
        pdb.write_bytes(b"STALE-PDB")
        launch_arguments = self.launch_args(output, pdb)
        previous = Path.cwd()
        old_cl = os.environ.get("CL")
        os.environ["CL"] = "/DPOISONED_BY_PARENT_ENVIRONMENT"
        try:
            with self.standalone_producer_diagnostic():
                os.chdir(self.build_dir)
                result = byte_identity.main(launch_arguments)
                self.assertEqual(byte_identity.main(self.verify_args()), 2)
        finally:
            os.chdir(previous)
            if old_cl is None:
                os.environ.pop("CL", None)
            else:
                os.environ["CL"] = old_cl
        self.assertEqual(result, 0)
        self.assertIn(b"FAKE-OBJ\0", output.read_bytes())
        self.assertNotIn(b"POISONED_BY_PARENT_ENVIRONMENT", output.read_bytes())
        self.assertTrue(pdb.read_bytes().startswith(b"FAKE-PDB\0"))
        audit_path = byte_identity.audit_object_path(
            self.build_dir, "fixture", "src/unit.cpp"
        )
        audit = json.loads(audit_path.read_text())
        self.assertEqual(audit["status"], "pass_through_not_composed")
        self.assertFalse(audit["may_claim_byte_identity"])
        self.assertTrue(audit["recipes_materialized_but_not_injected"])
        private_pdb = Path(audit["seed_pdb"])
        self.assertTrue(private_pdb.is_file())
        self.assertEqual(private_pdb.read_bytes(), pdb.read_bytes())
        self.assertEqual(
            byte_identity.embedded_pdb_references(output, pdb),
            audit["seed_embedded_pdb_references"],
        )
        self.assertFalse(
            (self.build_dir / "byte-identity/audit/framework-verdict.json")
            .exists()
        )
        output.write_bytes(b"TAMPERED")
        self.assertEqual(
            byte_identity.main(
                [
                    "verify",
                    "--manifest", str(self.manifest),
                    "--source-dir", str(self.source_dir),
                    "--build-dir", str(self.build_dir),
                    "--compiler", str(self.compiler),
                ]
            ),
            2,
        )
        self.assertFalse(
            (self.build_dir / "byte-identity/audit/framework-verdict.json").exists()
        )

    def test_verify_requires_exact_inventory_audit_universe_and_unique_outputs(self):
        self.materialize()
        other = self.source.with_name("inventory-unlisted.cpp")
        other.write_text("int inventory_unlisted() { return 37; }\n")
        listed_object = self.build_dir / "objects/inventory-listed.obj"
        listed_pdb = self.build_dir / "objects/inventory-listed.pdb"
        other_object = self.build_dir / "objects/inventory-unlisted.obj"
        other_pdb = self.build_dir / "objects/inventory-unlisted.pdb"
        listed_object.parent.mkdir(parents=True)
        other_arguments = self.launch_args(
            other_object, other_pdb, source=other
        )
        previous = Path.cwd()
        try:
            os.chdir(self.build_dir)
            self.assertEqual(
                self.run_standalone_producer_diagnostic(
                    self.launch_args(listed_object, listed_pdb)
                ),
                0,
            )
            self.assertEqual(
                self.run_standalone_producer_diagnostic(other_arguments), 0
            )
            self.assertEqual(self.run_resident_verifier_diagnostic(), 0)
        finally:
            os.chdir(previous)

        listed_audit_path = byte_identity.audit_object_path(
            self.build_dir, "fixture", "src/unit.cpp"
        )
        other_audit_path = byte_identity.audit_unlisted_path(
            self.build_dir, "fixture", "src/inventory-unlisted.cpp"
        )
        other_audit_bytes = other_audit_path.read_bytes()

        other_audit_path.unlink()
        self.assertEqual(self.run_resident_verifier_diagnostic(), 2)
        other_audit_path.write_bytes(other_audit_bytes)

        extra_audit = other_audit_path.with_name("unexpected.json")
        extra_audit.write_bytes(other_audit_bytes)
        self.assertEqual(self.run_resident_verifier_diagnostic(), 2)
        extra_audit.unlink()

        wrong_owner = json.loads(other_audit_bytes)
        wrong_owner["source"] = "src/wrong-output.cpp"
        other_audit_path.write_text(json.dumps(wrong_owner))
        self.assertEqual(self.run_resident_verifier_diagnostic(), 2)
        other_audit_path.write_bytes(other_audit_bytes)

        listed_audit = json.loads(listed_audit_path.read_text())
        duplicate_output = json.loads(other_audit_bytes)
        duplicate_output["object"] = listed_audit["object"]
        duplicate_output["object_sha256"] = listed_audit["object_sha256"]
        other_audit_path.write_text(json.dumps(duplicate_output))
        self.assertEqual(self.run_resident_verifier_diagnostic(), 2)

    def test_inventory_rejects_duplicate_target_source_owner(self):
        arguments = self.inventory_args(
            [("fixture", self.source), ("fixture", self.source)]
        )
        self.assertEqual(byte_identity.main(arguments), 2)
        self.assertFalse(byte_identity.inventory_path(self.build_dir).exists())

    def test_strict_child_environment_ignores_parent_and_pins_runtime_bin(self):
        self.materialize()
        output = self.build_dir / "objects/strict-env.obj"
        pdb = self.build_dir / "objects/strict-env.pdb"
        capture = self.directory / "strict-env.json"
        output.parent.mkdir(parents=True)
        poison = {
            "CL": "/DPOISONED_CL",
            "_CL_": "/DPOISONED__CL_",
            "PYTHONPATH": "/poison/python",
            "PYTHONHOME": "/poison/home",
            "CPATH": "/poison/cpath",
            "INCLUDE": "/poison/include",
            "LIB": "/poison/lib",
            "DYLD_INSERT_LIBRARIES": "/poison/dylib",
            "WINEDEBUG": "POISONED_WINEDEBUG",
            "__CF_USER_TEXT_ENCODING": "POISONED_CF_ENCODING",
        }
        old = {key: os.environ.get(key) for key in poison}
        os.environ.update(poison)
        previous = Path.cwd()
        try:
            with (
                self.fake_control(ENV_CAPTURE=str(capture)),
                self.standalone_producer_diagnostic(),
            ):
                os.chdir(self.build_dir)
                result = byte_identity.main(self.launch_args(output, pdb))
        finally:
            os.chdir(previous)
            for key, value in old.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        self.assertEqual(result, 0)
        environment = json.loads(capture.read_text())
        allowed = {
            "PATH", "HOME", "TEMP", "TMP", "TMPDIR", "WINEPREFIX",
            "ISLE_BYTE_IDENTITY_VIRTUAL_Z_ROOT",
            "LANG", "LC_ALL", "WINEDEBUG", "PWD", "SHLVL",
        }
        # macOS CoreFoundation inserts this process-local bookkeeping key when
        # the Python fake compiler starts. It is not present in the exact env
        # map passed to exec, and its generated value must not preserve parent
        # input. Linux has no such runtime-added key.
        self.assertTrue(
            set(environment).issubset(allowed | {"__CF_USER_TEXT_ENCODING"})
        )
        self.assertTrue(allowed.issubset(environment))
        self.assertNotIn("POISONED_CF_ENCODING", environment.values())
        self.assertEqual(environment["PATH"], str(
            byte_identity.runtime_bin_path(self.build_dir)
        ))
        self.assertEqual(environment["LANG"], "C")
        self.assertEqual(environment["LC_ALL"], "C")
        self.assertEqual(environment["WINEDEBUG"], "-all")
        self.assertEqual(environment["SHLVL"], "1")
        self.assertEqual(environment["TEMP"], environment["TMP"])
        self.assertEqual(environment["TMP"], environment["TMPDIR"])
        for name in (
            "HOME", "TEMP", "WINEPREFIX",
            "ISLE_BYTE_IDENTITY_VIRTUAL_Z_ROOT", "PWD",
        ):
            path = Path(environment[name])
            self.assertTrue(path.is_absolute())
            self.assertTrue(path.is_relative_to(self.build_dir.resolve()))
        self.assertTrue(Path(environment["TEMP"]).is_dir())
        self.assertFalse(Path(environment["HOME"]).exists())
        self.assertFalse(Path(environment["WINEPREFIX"]).exists())
        self.assertFalse(
            Path(environment["ISLE_BYTE_IDENTITY_VIRTUAL_Z_ROOT"]).exists()
        )
        inventory = json.loads(
            byte_identity.inventory_path(self.build_dir).read_text()
        )
        runtime_bin = byte_identity.runtime_bin_path(self.build_dir)
        self.assertEqual(
            {path.name for path in runtime_bin.iterdir()},
            {item["name"] for item in inventory["runtime_executables"]},
        )
        for runtime in inventory["runtime_executables"]:
            link = runtime_bin / runtime["name"]
            self.assertTrue(link.is_symlink())
            # The pinned host runtime executes in place; authenticity is the
            # per-entry hash pin, re-verified against the real target.
            self.assertEqual(
                link.resolve(), Path(runtime["absolute_path"]).resolve()
            )
            self.assertEqual(
                byte_identity.sha256_file(link.resolve()), runtime["sha256"]
            )

    def test_tampered_runtime_bin_rejects_before_compiler_start(self):
        self.materialize()
        self.ensure_inventory_current()
        output = self.build_dir / "objects/tampered-runtime.obj"
        pdb = self.build_dir / "objects/tampered-runtime.pdb"
        output.parent.mkdir(parents=True)
        arguments = self.launch_args(output, pdb)
        runtime = byte_identity.runtime_bin_path(self.build_dir) / "python3"
        started = self.directory / "tampered-runtime.started"
        previous = Path.cwd()
        original_materialize = byte_identity.materialize_runtime_bin
        tampered = False

        def materialize_then_tamper(state, build_dir):
            nonlocal tampered
            result = original_materialize(state, build_dir)
            if not tampered:
                tampered = True
                runtime.unlink()
                runtime.symlink_to(Path("/bin/false"))
            return result

        with (
            self.fake_control(STARTED=str(started)),
            self.standalone_producer_diagnostic(),
            mock.patch.object(
                byte_identity, "materialize_runtime_bin",
                side_effect=materialize_then_tamper,
            ),
        ):
            try:
                os.chdir(self.build_dir)
                result = byte_identity.main(arguments)
            finally:
                os.chdir(previous)
        self.assertEqual(result, 2)
        self.assertTrue(tampered)
        self.assertFalse(started.exists())
        self.assertFalse(output.exists())
        self.assertFalse(pdb.exists())

    def test_wine_runtime_copier_preserves_only_confined_pinned_aliases(self):
        shaped_bin = self.directory / "shaped-wine-bin"
        shaped_lib = self.directory / "shaped-wine-lib"
        shaped_bin.mkdir()
        shaped_lib.mkdir()
        (shaped_bin / "wine").write_bytes(b"pinned multicall loader")
        (shaped_bin / "wine").chmod(0o755)
        bin_aliases = [
            "regsvr32", "wineboot", "msidb", "wineconsole", "winefile",
            "msiexec", "regedit", "winecfg", "winedbg", "winepath",
            "winemine", "notepad",
        ]
        for name in bin_aliases:
            (shaped_bin / name).symlink_to("wine")
        (shaped_lib / "libfixture.1.0.dylib").write_bytes(b"pinned dylib")
        (shaped_lib / "libfixture.1.0.dylib").chmod(0o644)
        for index in range(55):
            (shaped_lib / f"libfixture-{index}.dylib").symlink_to(
                "libfixture.1.0.dylib"
            )
        # Wine compares the prefix seed `.update-timestamp` against wine.inf's
        # mtime: the held copies must present the pinned bundle's timestamps.
        pinned_mtime_ns = 1_776_347_837_000_000_000
        os.utime(shaped_bin / "wine", ns=(pinned_mtime_ns, pinned_mtime_ns))
        bin_pin = byte_identity.canonical_tree_snapshot(
            shaped_bin, hash_files=True
        )
        lib_pin = byte_identity.canonical_tree_snapshot(
            shaped_lib, hash_files=True
        )
        with byte_identity.build_transaction(
            self.build_dir, exclusive=True, bootstrap_outer_session=True,
        ):
            copied_bin = self.build_dir / "runtime-copy/bin"
            copied_lib = self.build_dir / "runtime-copy/lib"
            byte_identity.copy_wine_runtime_tree_to_snapshot(
                shaped_bin, copied_bin, bin_pin
            )
            byte_identity.copy_wine_runtime_tree_to_snapshot(
                shaped_lib, copied_lib, lib_pin
            )
            self.assertEqual(
                sum(path.is_symlink() for path in copied_bin.iterdir()), 12
            )
            self.assertEqual(
                sum(path.is_symlink() for path in copied_lib.iterdir()), 55
            )
            self.assertEqual(os.readlink(copied_bin / "wineboot"), "wine")
            self.assertEqual(
                os.readlink(copied_lib / "libfixture-0.dylib"),
                "libfixture.1.0.dylib",
            )
            self.assertEqual(
                (copied_bin / "wine").stat().st_mtime_ns, pinned_mtime_ns
            )
            self.assertEqual(
                (copied_lib / "libfixture.1.0.dylib").stat().st_mtime_ns,
                (shaped_lib / "libfixture.1.0.dylib").stat().st_mtime_ns,
            )

    def test_wine_runtime_copier_rejects_unsafe_or_mutating_aliases(self):
        def valid_root(name):
            root = self.directory / name
            root.mkdir()
            (root / "target").write_bytes(b"stable target")
            (root / "alias").symlink_to("target")
            return root

        with byte_identity.build_transaction(
            self.build_dir, exclusive=True, bootstrap_outer_session=True,
        ):
            for kind, target, message in (
                ("absolute", "/bin/false", "escapes"),
                ("escaping", "../outside", "escapes"),
            ):
                with self.subTest(kind=kind):
                    root = valid_root(f"unsafe-{kind}")
                    pin = byte_identity.canonical_tree_snapshot(
                        root, hash_files=True
                    )
                    (root / "alias").unlink()
                    (root / "alias").symlink_to(target)
                    with self.assertRaisesRegex(
                        byte_identity.ByteIdentityError, message
                    ):
                        byte_identity.copy_wine_runtime_tree_to_snapshot(
                            root, self.build_dir / f"copy-{kind}", pin
                        )

            dangling = self.directory / "unsafe-dangling"
            dangling.mkdir()
            (dangling / "alias").symlink_to("missing")
            dangling_pin = byte_identity.canonical_tree_snapshot(
                dangling, hash_files=True
            )
            with self.assertRaisesRegex(
                byte_identity.ByteIdentityError, "dangling"
            ):
                byte_identity.copy_wine_runtime_tree_to_snapshot(
                    dangling, self.build_dir / "copy-dangling", dangling_pin
                )

            collision = self.directory / "unsafe-collision"
            collision.mkdir()
            (collision / "Wine").write_bytes(b"one")
            collision_pin = byte_identity.canonical_tree_snapshot(
                collision, hash_files=True
            )
            collision_inode = collision.stat().st_ino
            original_listdir = os.listdir

            def inject_casefold_collision(value):
                if isinstance(value, int) and os.fstat(value).st_ino == collision_inode:
                    return ["Wine", "wine"]
                return original_listdir(value)

            with (
                mock.patch.object(
                    byte_identity.os, "listdir",
                    side_effect=inject_casefold_collision,
                ),
                self.assertRaisesRegex(
                    byte_identity.ByteIdentityError, "casefold collision"
                ),
            ):
                byte_identity.copy_wine_runtime_tree_to_snapshot(
                    collision, self.build_dir / "copy-collision",
                    collision_pin,
                )

            mutating = valid_root("unsafe-mutating")
            mutating_pin = byte_identity.canonical_tree_snapshot(
                mutating, hash_files=True
            )
            destination = self.build_dir / "copy-mutating"
            original_symlink = byte_identity.BuildRootAuthority.atomic_symlink
            changed = False

            def mutate_target(authority, path, target):
                nonlocal changed
                original_symlink(authority, path, target)
                if not changed and Path(path) == destination / "alias":
                    changed = True
                    (mutating / "target").write_bytes(b"changed target bytes")

            with (
                mock.patch.object(
                    byte_identity.BuildRootAuthority, "atomic_symlink",
                    new=mutate_target,
                ),
                self.assertRaisesRegex(
                    byte_identity.ByteIdentityError, "changed while copied"
                ),
            ):
                byte_identity.copy_wine_runtime_tree_to_snapshot(
                    mutating, destination, mutating_pin
                )

    def test_python_hash_and_version_are_exact_manifest_pins(self):
        for field, value in (
            ("python_sha256", "0" * 64),
            ("python_version", "0.0.0"),
        ):
            with self.subTest(field=field):
                original = self.document["toolchain"][field]
                self.document["toolchain"][field] = value
                self.write_manifest()
                self.assertEqual(byte_identity.main(self.plan_args()), 2)
                self.assertFalse(self.plan.exists())
                self.document["toolchain"][field] = original
                self.write_manifest()

    def test_embedded_pdb_mismatch_is_rejected_before_install(self):
        self.materialize()
        output = self.build_dir / "objects/wrong-pdb.obj"
        pdb = self.build_dir / "objects/wrong-pdb.pdb"
        output.parent.mkdir(parents=True)
        previous = Path.cwd()
        with (
            self.fake_control(
                WRONG_PDB_REFERENCE=str(self.build_dir / "wrong/type-server.pdb")
            ),
            self.standalone_producer_diagnostic(),
        ):
            try:
                os.chdir(self.build_dir)
                result = byte_identity.main(self.launch_args(output, pdb))
            finally:
                os.chdir(previous)
        self.assertEqual(result, 2)
        self.assertFalse(output.exists())
        self.assertFalse(pdb.exists())

    def test_embedded_pdb_non_host_wine_drive_is_rejected(self):
        expected = self.build_dir / "private/type-server.pdb"
        object_path = self.build_dir / "objects/non-host-drive.obj"
        object_path.parent.mkdir(parents=True)
        dos_reference = ("C:" + str(expected)).replace("/", "\\")
        object_path.write_bytes(b"OBJECT\0" + dos_reference.encode("ascii") + b"\0")
        with self.assertRaisesRegex(
            byte_identity.ByteIdentityError, "non-host Wine PDB path"
        ):
            byte_identity.embedded_pdb_references(object_path, expected)

    def test_standalone_rebuild_cannot_replay_diagnostic_verdict(self):
        self.materialize()
        output = self.build_dir / "objects/transaction.obj"
        pdb = self.build_dir / "objects/transaction.pdb"
        output.parent.mkdir(parents=True)
        previous = Path.cwd()
        try:
            os.chdir(self.build_dir)
            self.assertEqual(
                self.run_standalone_producer_diagnostic(
                    self.launch_args(output, pdb)
                ),
                0,
            )
            self.assertEqual(self.run_resident_verifier_diagnostic(), 0)
        finally:
            os.chdir(previous)
        verdict = self.build_dir / "byte-identity/audit/framework-verdict.json"
        self.assertTrue(verdict.is_file())
        started = self.directory / "failed-rebuild.started"
        environment = dict(os.environ)
        environment.update(
            {
                "FAKE_STARTED": str(started),
                "FAKE_SLEEP": "0.8",
                "FAKE_FAIL": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
            }
        )
        control_path = self.compiler.with_suffix(".control.json")
        control_path.write_text(json.dumps({
            "STARTED": str(started), "SLEEP": "0.8", "FAIL": True,
        }))
        rebuild = subprocess.Popen(
            self.launcher_process_args(self.source, output, pdb),
            cwd=self.build_dir,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            rebuild_output, _ = rebuild.communicate(timeout=10)
            self.assertEqual(rebuild.returncode, 2, rebuild_output)
        finally:
            if rebuild.poll() is None:
                rebuild.kill()
            rebuild.wait(timeout=5)
            if rebuild.stdout is not None:
                rebuild.stdout.close()
            control_path.unlink(missing_ok=True)
        self.assertFalse(started.exists())
        self.assertEqual(byte_identity.main(self.verify_args()), 2)
        self.assertFalse(verdict.exists())

    def test_atomic_launcher_compiles_seed_and_donor_then_reconstructs(self):
        seed_bytes, donor_bytes = self.enable_composer_fixture()
        self.materialize()
        output = self.build_dir / "objects/composed.obj"
        pdb = self.build_dir / "objects/composed.pdb"
        output.parent.mkdir(parents=True)
        output.write_bytes(b"STALE")
        pdb.write_bytes(b"STALE-PDB")
        launch_arguments = self.launch_args(output, pdb)
        previous = Path.cwd()
        with (
            self.fake_control(
                SEED_OBJ=str(self.seed_fixture), DONOR_OBJ=str(self.donor_fixture)
            ),
            self.standalone_producer_diagnostic(),
        ):
            try:
                os.chdir(self.build_dir)
                result = byte_identity.main(launch_arguments)
            finally:
                os.chdir(previous)
        self.assertEqual(result, 0)
        audit_path = byte_identity.audit_object_path(
            self.build_dir, "fixture", "src/unit.cpp"
        )
        audit = json.loads(audit_path.read_text())
        expected, _ = byte_identity.compose_equal_linked_span_fpo(
            Path(audit["seed_object"]).read_bytes(),
            Path(audit["donors"][0]["object"]).read_bytes(),
            fpo_function_record(donor_bytes),
            byte_identity.declaration_identifiers(
                entropy.generate_shape(1, 1).encode("utf-8")
            ),
        )
        self.assertEqual(output.read_bytes(), expected)
        self.assertEqual(audit["status"], "compiler_output_fpo_composed")
        self.assertTrue(audit["recipes_compiled_and_injected"])
        self.assertEqual(len(audit["donors"]), 1)
        self.assertEqual(len(audit["composition"]), 1)
        self.assertEqual(audit["retail_payload_bytes_read"], 0)
        with self.standalone_producer_diagnostic():
            self.assertEqual(byte_identity.main(self.verify_args()), 2)
        self.assertFalse(
            (self.build_dir / "byte-identity/audit/framework-verdict.json")
            .exists()
        )

    def test_composer_shape_fi_is_absolute_across_cmake_wine_cwd_mismatch(self):
        self.enable_composer_fixture()
        self.materialize()
        output = self.build_dir / "objects/composed.obj"
        pdb = self.build_dir / "objects/composed.pdb"
        output.parent.mkdir(parents=True)
        unrelated_cwd = self.build_dir / "cmake-launch-cwd"
        unrelated_cwd.mkdir()
        arguments = self.launch_args(output, pdb, ensure_inventory=False)
        self.ensure_inventory_current()
        self.attest_command(arguments, directory=unrelated_cwd)
        previous = Path.cwd()
        with (
            self.fake_control(
                SEED_OBJ=str(self.seed_fixture), DONOR_OBJ=str(self.donor_fixture)
            ),
            self.standalone_producer_diagnostic(),
        ):
            try:
                os.chdir(unrelated_cwd)
                result = byte_identity.main(arguments)
            finally:
                os.chdir(previous)
        self.assertEqual(result, 0)
        self.assertTrue(output.is_file())
        self.assertTrue(pdb.is_file())

    def test_failed_compiler_removes_stale_expected_object(self):
        self.materialize()
        output = self.build_dir / "objects/unit.obj"
        pdb = self.build_dir / "objects/unit.pdb"
        output.parent.mkdir(parents=True)
        output.write_bytes(b"STALE")
        pdb.write_bytes(b"STALE-PDB")
        previous = Path.cwd()
        with (
            self.fake_control(FAIL=True),
            self.standalone_producer_diagnostic(),
        ):
            try:
                os.chdir(self.build_dir)
                result = byte_identity.main(self.launch_args(output, pdb))
            finally:
                os.chdir(previous)
        self.assertEqual(result, 2)
        self.assertFalse(output.exists())
        self.assertFalse(pdb.exists())
        self.assertFalse(
            byte_identity.audit_object_path(
                self.build_dir, "fixture", "src/unit.cpp"
            ).exists()
        )

    def test_timeout_kills_only_child_group_and_leaves_no_object(self):
        self.document["toolchain"]["max_child_seconds"] = 1
        self.write_manifest()
        self.materialize()
        output = self.build_dir / "objects/unit.obj"
        pdb = self.build_dir / "objects/unit.pdb"
        output.parent.mkdir(parents=True)
        output.write_bytes(b"STALE")
        pdb.write_bytes(b"STALE-PDB")
        previous = Path.cwd()
        with (
            self.fake_control(SLEEP="2"),
            self.standalone_producer_diagnostic(),
        ):
            try:
                os.chdir(self.build_dir)
                result = byte_identity.main(self.launch_args(output, pdb))
            finally:
                os.chdir(previous)
        self.assertEqual(result, 2)
        self.assertFalse(output.exists())
        self.assertFalse(pdb.exists())

    def test_postflight_kills_owned_compiler_descendant_and_fails_closed(self):
        self.materialize()
        output = self.build_dir / "objects/unit.obj"
        pdb = self.build_dir / "objects/unit.pdb"
        output.parent.mkdir(parents=True)
        output.write_bytes(b"STALE")
        pdb.write_bytes(b"STALE-PDB")
        previous = Path.cwd()
        with (
            self.fake_control(ORPHAN=True),
            self.standalone_producer_diagnostic(),
        ):
            try:
                os.chdir(self.build_dir)
                result = byte_identity.main(self.launch_args(output, pdb))
            finally:
                os.chdir(previous)
        self.assertEqual(result, 2)
        self.assertFalse(output.exists())
        self.assertFalse(pdb.exists())

    def test_sigint_and_sigterm_cancel_and_reap_owned_compiler_tree(self):
        for signum in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signum=signum):
                source = self.source.with_name(f"cancel-{signum}.cpp")
                source.write_text(f"int cancel_{signum}() {{ return {signum}; }}\n")
                output = self.build_dir / f"objects/cancel-{signum}.obj"
                pdb = self.build_dir / f"objects/cancel-{signum}.pdb"
                output.parent.mkdir(parents=True, exist_ok=True)
                started = self.directory / f"cancel-{signum}.started"
                pid_file = self.directory / f"cancel-{signum}.pid"
                child_pid_file = self.directory / f"cancel-{signum}.child-pid"
                environment = dict(os.environ)
                environment.update(
                    {
                        "FAKE_STARTED": str(started),
                        "FAKE_PID_FILE": str(pid_file),
                        "FAKE_CHILD_PID_FILE": str(child_pid_file),
                        "FAKE_SLEEP": "30",
                        "PYTHONDONTWRITEBYTECODE": "1",
                    }
                )
                control_path = self.compiler.with_suffix(".control.json")
                control_path.write_text(json.dumps({
                    "STARTED": str(started),
                    "PID_FILE": str(pid_file),
                    "CHILD_PID_FILE": str(child_pid_file),
                    "SLEEP": "30",
                }))
                wrapper = (
                    "import os,sys;from pathlib import Path;"
                    f"sys.path.insert(0,{str(ROOT)!r});"
                    "from tools import byte_identity;"
                    "command=sys.argv[1:5];"
                    "\ntry:\n"
                    " byte_identity.run_child(command,60,dict(os.environ),"
                    "cwd=Path(sys.argv[5]))\n"
                    "except byte_identity.CompilerCancellation:\n"
                    " raise SystemExit(2)\n"
                )
                launcher = subprocess.Popen(
                    [
                        sys.executable, "-c", wrapper, str(self.compiler),
                        f"/Fo{output}", f"/Fd{pdb}", str(source),
                        str(self.build_dir),
                    ],
                    cwd=self.build_dir,
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                try:
                    deadline = time.monotonic() + 5
                    while (not started.exists() or not pid_file.exists()
                           or not child_pid_file.exists()):
                        self.assertLess(time.monotonic(), deadline)
                        time.sleep(0.02)
                    owned_pids = [
                        int(pid_file.read_text()),
                        int(child_pid_file.read_text()),
                    ]
                    launcher.send_signal(signum)
                    output_text, _ = launcher.communicate(timeout=10)
                    self.assertEqual(launcher.returncode, 2, output_text)
                finally:
                    if launcher.poll() is None:
                        launcher.kill()
                    launcher.wait(timeout=5)
                    if launcher.stdout is not None:
                        launcher.stdout.close()
                    control_path.unlink(missing_ok=True)
                self.assertFalse(output.exists())
                self.assertFalse(pdb.exists())
                deadline = time.monotonic() + 3
                for owned_pid in owned_pids:
                    while time.monotonic() < deadline:
                        try:
                            os.kill(owned_pid, 0)
                        except ProcessLookupError:
                            break
                        time.sleep(0.02)
                    else:
                        self.fail(f"owned cancellation PID survived: {owned_pid}")

    def test_standalone_parallel_launchers_refuse_without_resident_authority(self):
        self.assertEqual(byte_identity.MAX_COMPILER_PROCESSES, 4)
        # The resident owns the shared execution projection and its single
        # writable seat. Independent launcher processes must refuse before the
        # fake compiler can contend for the legacy max-four compiler slots.
        state_path = self.directory / "compiler-concurrency.txt"
        environment = dict(os.environ)
        environment["FAKE_CONCURRENCY_STATE"] = str(state_path)
        environment["FAKE_CONCURRENCY_SLEEP"] = "0.6"
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        control_path = self.compiler.with_suffix(".control.json")
        control_path.write_text(json.dumps({
            "CONCURRENCY_STATE": str(state_path),
            "CONCURRENCY_SLEEP": "0.6",
        }))
        processes = []
        outputs = []
        jobs = []
        for index in range(8):
            source = self.source.with_name(f"parallel-{index}.cpp")
            source.write_text(f"int parallel_{index}() {{ return {index}; }}\n")
            output = self.build_dir / f"objects/parallel-{index}.obj"
            pdb = self.build_dir / f"objects/parallel-{index}.pdb"
            output.parent.mkdir(parents=True, exist_ok=True)
            outputs.extend((output, pdb))
            jobs.append((source, output, pdb))
        self.ensure_inventory_current()
        launchers = [
            self.launcher_process_args(source, output, pdb)
            for source, output, pdb in jobs
        ]
        try:
            for launcher in launchers:
                processes.append(
                    subprocess.Popen(
                        launcher,
                        cwd=self.build_dir,
                        env=environment,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                    )
                )
            for process in processes:
                output_text, _ = process.communicate(timeout=15)
                self.assertEqual(process.returncode, 2, output_text)
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.wait()
                if process.stdout is not None:
                    process.stdout.close()
            control_path.unlink(missing_ok=True)
        self.assertFalse(state_path.exists())
        self.assertTrue(all(not path.exists() for path in outputs))
        self.assertFalse(
            (self.build_dir / "byte-identity/audit/framework-verdict.json")
            .exists()
        )

    def test_full_compiler_semaphore_times_out_before_launch_and_fails_closed(self):
        self.document["toolchain"]["max_child_seconds"] = 1
        self.write_manifest()
        slot_directory = (
            self.build_dir / "byte-identity/locks/compiler-slots"
        )
        slot_directory.mkdir(parents=True)
        holder_code = (
            "import fcntl,sys,time; "
            "stream=open(sys.argv[1],'a+b'); "
            "fcntl.flock(stream.fileno(),fcntl.LOCK_EX); "
            "print('ready',flush=True); time.sleep(10)"
        )
        holders = []
        try:
            for index in range(byte_identity.MAX_COMPILER_PROCESSES):
                holder = subprocess.Popen(
                    [
                        sys.executable,
                        "-c",
                        holder_code,
                        str(slot_directory / f"slot-{index}.lock"),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                holders.append(holder)
                self.assertEqual(holder.stdout.readline().strip(), "ready")
            source = self.source.with_name("semaphore-blocked.cpp")
            source.write_text("int semaphore_blocked() { return 17; }\n")
            output = self.build_dir / "objects/semaphore-blocked.obj"
            pdb = self.build_dir / "objects/semaphore-blocked.pdb"
            output.parent.mkdir(parents=True)
            output.write_bytes(b"STALE")
            pdb.write_bytes(b"STALE-PDB")
            started = time.monotonic()
            previous = Path.cwd()
            try:
                with self.standalone_producer_diagnostic():
                    os.chdir(self.build_dir)
                    result = byte_identity.main(
                        self.launcher_process_args(source, output, pdb)[2:]
                    )
            finally:
                os.chdir(previous)
            self.assertEqual(result, 2)
            self.assertLess(time.monotonic() - started, 2.5)
            self.assertFalse(output.exists())
            self.assertFalse(pdb.exists())
        finally:
            for holder in holders:
                if holder.poll() is None:
                    holder.terminate()
                holder.wait(timeout=5)
                if holder.stdout is not None:
                    holder.stdout.close()

    def test_unpinned_force_include_refuses_and_removes_stale_object(self):
        self.materialize()
        output = self.build_dir / "objects/unit.obj"
        pdb = self.build_dir / "objects/unit.pdb"
        output.parent.mkdir(parents=True)
        output.write_bytes(b"STALE")
        pdb.write_bytes(b"STALE-PDB")
        arguments = self.launch_args(output, pdb)
        arguments[arguments.index(f"/FI{self.include}")] = "/FI/unpinned/header.h"
        previous = Path.cwd()
        try:
            with self.standalone_producer_diagnostic():
                os.chdir(self.build_dir)
                result = byte_identity.main(arguments)
        finally:
            os.chdir(previous)
        self.assertEqual(result, 2)
        self.assertFalse(output.exists())
        self.assertFalse(pdb.exists())

    def test_response_file_rejection_invalidates_valid_prior_universe(self):
        self.materialize()
        other = self.source.with_name("response-unlisted.cpp")
        other.write_text("int response_unlisted() { return 43; }\n")
        listed_object = self.build_dir / "objects/response-listed.obj"
        listed_pdb = self.build_dir / "objects/response-listed.pdb"
        other_object = self.build_dir / "objects/response-unlisted.obj"
        other_pdb = self.build_dir / "objects/response-unlisted.pdb"
        listed_object.parent.mkdir(parents=True)
        verdict = self.build_dir / "byte-identity/audit/framework-verdict.json"
        listed_audit = byte_identity.audit_object_path(
            self.build_dir, "fixture", "src/unit.cpp"
        )
        other_audit = byte_identity.audit_unlisted_path(
            self.build_dir, "fixture", "src/response-unlisted.cpp"
        )

        def establish_valid_prior_state():
            other_arguments = self.launch_args(
                other_object, other_pdb, source=other
            )
            previous = Path.cwd()
            try:
                os.chdir(self.build_dir)
                self.assertEqual(
                    self.run_standalone_producer_diagnostic(
                        self.launch_args(listed_object, listed_pdb)
                    ),
                    0,
                )
                self.assertEqual(
                    self.run_standalone_producer_diagnostic(other_arguments), 0
                )
                self.assertEqual(self.run_resident_verifier_diagnostic(), 0)
            finally:
                os.chdir(previous)
            self.assertTrue(verdict.is_file())
            self.assertTrue(listed_audit.is_file())
            self.assertTrue(other_audit.is_file())
            self.assertTrue(all(path.is_file() for path in (
                listed_object, listed_pdb, other_object, other_pdb,
            )))

        for label in ("visible-outputs", "fully-hidden"):
            with self.subTest(label=label):
                establish_valid_prior_state()
                response = self.directory / f"response-{label}.rsp"
                started = self.directory / f"response-{label}.started"
                if label == "visible-outputs":
                    visible_object = self.build_dir / "objects/visible-orphan.obj"
                    visible_pdb = self.build_dir / "objects/visible-orphan.pdb"
                    visible_object.write_bytes(b"VISIBLE-STALE-OBJ")
                    visible_pdb.write_bytes(b"VISIBLE-STALE-PDB")
                    arguments = self.launch_args(visible_object, visible_pdb)
                    response.write_text("/GL\n")
                else:
                    visible_object = None
                    visible_pdb = None
                    arguments = self.launch_args(listed_object, listed_pdb)
                    for hidden in (
                        str(self.source),
                        f"/Fo{listed_object}",
                        f"/Fd{listed_pdb}",
                    ):
                        arguments.remove(hidden)
                    response.write_text(
                        f"/Fo{listed_object}\n/Fd{listed_pdb}\n"
                        f"{self.source}\n/GL\n"
                    )
                arguments.append(f"  @{response}")
                previous = Path.cwd()
                with (
                    self.fake_control(STARTED=str(started)),
                    self.standalone_producer_diagnostic(),
                ):
                    try:
                        os.chdir(self.build_dir)
                        result = byte_identity.main(arguments)
                    finally:
                        os.chdir(previous)
                self.assertEqual(result, 2)
                self.assertFalse(started.exists())
                self.assertFalse(verdict.exists())
                self.assertFalse(listed_audit.exists())
                self.assertFalse(other_audit.exists())
                self.assertTrue(all(not path.exists() for path in (
                    listed_object, listed_pdb, other_object, other_pdb,
                )))
                if visible_object is not None and visible_pdb is not None:
                    self.assertFalse(visible_object.exists())
                    self.assertFalse(visible_pdb.exists())
                self.assertEqual(self.run_resident_verifier_diagnostic(), 2)
                self.assertFalse(verdict.exists())

    def test_response_file_cleanup_never_follows_symlinked_paths(self):
        self.materialize()
        listed_object = self.build_dir / "objects/symlink-listed.obj"
        listed_pdb = self.build_dir / "objects/symlink-listed.pdb"
        listed_object.parent.mkdir(parents=True)
        previous = Path.cwd()
        try:
            os.chdir(self.build_dir)
            self.assertEqual(
                self.run_standalone_producer_diagnostic(
                    self.launch_args(listed_object, listed_pdb)
                ),
                0,
            )
            self.assertEqual(self.run_resident_verifier_diagnostic(), 0)
        finally:
            os.chdir(previous)

        listed_audit = byte_identity.audit_object_path(
            self.build_dir, "fixture", "src/unit.cpp"
        )
        verdict = self.build_dir / "byte-identity/audit/framework-verdict.json"
        outside = self.directory / "outside-audit-root"
        outside.mkdir()
        outside_object = outside / "outside.obj"
        outside_pdb = outside / "outside.pdb"
        outside_audit = outside / "outside.json"
        outside_object.write_bytes(b"OUTSIDE-OBJECT")
        outside_pdb.write_bytes(b"OUTSIDE-PDB")
        outside_audit.write_text(json.dumps({
            "object": str(outside_object),
            "pdb": str(outside_pdb),
        }))
        redirected_root = (
            self.build_dir / "byte-identity/audit/unlisted-pass-through"
        )
        redirected_root.parent.mkdir(parents=True, exist_ok=True)
        redirected_root.symlink_to(outside, target_is_directory=True)

        in_build_sentinel = self.build_dir / "sentinel/keep.obj"
        in_build_sentinel.parent.mkdir(parents=True)
        in_build_sentinel.write_bytes(b"IN-BUILD-SENTINEL")
        visible_object = self.build_dir / "objects/visible-link.obj"
        visible_pdb = self.build_dir / "objects/visible-link.pdb"
        visible_object.symlink_to(in_build_sentinel)
        visible_pdb.symlink_to(outside_pdb)
        response = self.directory / "symlink-response.rsp"
        response.write_text("/GL\n")
        started = self.directory / "symlink-response.started"
        # Response-file rejection precedes command-policy lookup.  Preserve
        # the valid prior attestation and exercise cleanup directly without
        # attempting a new attestation through the deliberately symlinked
        # audit namespace.
        arguments = self.launch_args(
            visible_object, visible_pdb, ensure_inventory=False
        )
        arguments.append(f"@{response}")
        with (
            self.fake_control(STARTED=str(started)),
            self.standalone_producer_diagnostic(),
        ):
            previous = Path.cwd()
            try:
                os.chdir(self.build_dir)
                result = byte_identity.main(arguments)
            finally:
                os.chdir(previous)

        self.assertEqual(result, 2)
        self.assertFalse(started.exists())
        self.assertFalse(verdict.exists())
        self.assertFalse(listed_audit.exists())
        self.assertFalse(listed_object.exists())
        self.assertFalse(listed_pdb.exists())
        self.assertFalse(visible_object.exists())
        self.assertFalse(visible_pdb.exists())
        self.assertFalse(redirected_root.exists())
        self.assertFalse(redirected_root.is_symlink())
        self.assertEqual(in_build_sentinel.read_bytes(), b"IN-BUILD-SENTINEL")
        self.assertEqual(outside_object.read_bytes(), b"OUTSIDE-OBJECT")
        self.assertEqual(outside_pdb.read_bytes(), b"OUTSIDE-PDB")
        self.assertTrue(outside_audit.is_file())
        self.assertEqual(self.run_resident_verifier_diagnostic(), 2)
        self.assertFalse(verdict.exists())

    def test_response_cleanup_output_unlink_is_stable_across_ancestor_swap(self):
        self.materialize()
        output_directory = self.build_dir / "objects/ancestor-swap"
        output_directory.mkdir(parents=True)
        listed_object = output_directory / "stable.obj"
        listed_pdb = output_directory / "stable.pdb"
        previous = Path.cwd()
        try:
            os.chdir(self.build_dir)
            self.assertEqual(
                self.run_standalone_producer_diagnostic(
                    self.launch_args(listed_object, listed_pdb)
                ),
                0,
            )
            self.assertEqual(self.run_resident_verifier_diagnostic(), 0)
        finally:
            os.chdir(previous)

        listed_audit = byte_identity.audit_object_path(
            self.build_dir, "fixture", "src/unit.cpp"
        )
        verdict = self.build_dir / "byte-identity/audit/framework-verdict.json"
        outside = self.directory / "outside-output-swap"
        outside.mkdir()
        outside_object = outside / listed_object.name
        outside_pdb = outside / listed_pdb.name
        outside_object.write_bytes(b"OUTSIDE-SWAP-OBJECT")
        outside_pdb.write_bytes(b"OUTSIDE-SWAP-PDB")
        detached = output_directory.with_name("ancestor-swap-detached")
        response = self.directory / "ancestor-swap.rsp"
        response.write_text(
            f"/Fo{listed_object}\n/Fd{listed_pdb}\n{self.source}\n/GL\n"
        )
        started = self.directory / "ancestor-swap.started"
        arguments = self.launch_args(listed_object, listed_pdb)
        for hidden in (
            str(self.source), f"/Fo{listed_object}", f"/Fd{listed_pdb}",
        ):
            arguments.remove(hidden)
        arguments.append(f"@{response}")

        real_unlink = byte_identity.os.unlink
        swapped = False

        def swapping_unlink(path, *args, dir_fd=None, **kwargs):
            nonlocal swapped
            if (not swapped and path == listed_object.name
                    and dir_fd is not None):
                output_directory.rename(detached)
                output_directory.symlink_to(outside, target_is_directory=True)
                swapped = True
            return real_unlink(
                path, *args, dir_fd=dir_fd, **kwargs
            )

        with (
            self.fake_control(STARTED=str(started)),
            self.standalone_producer_diagnostic(),
        ):
            previous = Path.cwd()
            byte_identity.os.unlink = swapping_unlink
            try:
                os.chdir(self.build_dir)
                result = byte_identity.main(arguments)
            finally:
                os.chdir(previous)
                byte_identity.os.unlink = real_unlink

        self.assertEqual(result, 2)
        self.assertTrue(swapped)
        self.assertFalse(started.exists())
        self.assertFalse(verdict.exists())
        self.assertFalse(listed_audit.exists())
        self.assertFalse((detached / listed_object.name).exists())
        self.assertEqual(outside_object.read_bytes(), b"OUTSIDE-SWAP-OBJECT")
        self.assertEqual(outside_pdb.read_bytes(), b"OUTSIDE-SWAP-PDB")
        self.assertEqual(self.run_resident_verifier_diagnostic(), 2)
        self.assertFalse(verdict.exists())

    def test_response_cleanup_audit_read_is_stable_across_ancestor_swap(self):
        self.materialize()
        listed_object = self.build_dir / "objects/audit-swap.obj"
        listed_pdb = self.build_dir / "objects/audit-swap.pdb"
        listed_object.parent.mkdir(parents=True)
        previous = Path.cwd()
        try:
            os.chdir(self.build_dir)
            self.assertEqual(
                self.run_standalone_producer_diagnostic(
                    self.launch_args(listed_object, listed_pdb)
                ),
                0,
            )
            self.assertEqual(self.run_resident_verifier_diagnostic(), 0)
        finally:
            os.chdir(previous)

        listed_audit = byte_identity.audit_object_path(
            self.build_dir, "fixture", "src/unit.cpp"
        )
        verdict = self.build_dir / "byte-identity/audit/framework-verdict.json"
        outside = self.directory / "outside-audit-swap"
        outside.mkdir()
        outside_object = outside / "outside.obj"
        outside_pdb = outside / "outside.pdb"
        outside_audit = outside / listed_audit.name
        outside_object.write_bytes(b"OUTSIDE-AUDIT-OBJECT")
        outside_pdb.write_bytes(b"OUTSIDE-AUDIT-PDB")
        outside_audit.write_text(json.dumps({
            "object": str(outside_object),
            "pdb": str(outside_pdb),
        }))
        detached = listed_audit.parent.with_name("fixture-detached")
        response = self.directory / "audit-ancestor-swap.rsp"
        response.write_text(
            f"/Fo{listed_object}\n/Fd{listed_pdb}\n{self.source}\n/GL\n"
        )
        started = self.directory / "audit-ancestor-swap.started"
        arguments = self.launch_args(listed_object, listed_pdb)
        for hidden in (
            str(self.source), f"/Fo{listed_object}", f"/Fd{listed_pdb}",
        ):
            arguments.remove(hidden)
        arguments.append(f"@{response}")

        real_open = byte_identity.os.open
        swapped = False

        def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal swapped
            if (not swapped and path == listed_audit.name
                    and dir_fd is not None
                    and not flags & byte_identity.os.O_DIRECTORY):
                listed_audit.parent.rename(detached)
                listed_audit.parent.symlink_to(
                    outside, target_is_directory=True
                )
                swapped = True
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with (
            self.fake_control(STARTED=str(started)),
            self.standalone_producer_diagnostic(),
        ):
            previous = Path.cwd()
            byte_identity.os.open = swapping_open
            try:
                os.chdir(self.build_dir)
                result = byte_identity.main(arguments)
            finally:
                os.chdir(previous)
                byte_identity.os.open = real_open

        self.assertEqual(result, 2)
        self.assertTrue(swapped)
        self.assertFalse(started.exists())
        self.assertFalse(verdict.exists())
        self.assertFalse((detached / listed_audit.name).exists())
        self.assertFalse(listed_object.exists())
        self.assertFalse(listed_pdb.exists())
        self.assertEqual(outside_object.read_bytes(), b"OUTSIDE-AUDIT-OBJECT")
        self.assertEqual(outside_pdb.read_bytes(), b"OUTSIDE-AUDIT-PDB")
        self.assertTrue(outside_audit.is_file())
        self.assertEqual(self.run_resident_verifier_diagnostic(), 2)
        self.assertFalse(verdict.exists())

    def test_verify_rejects_duplicate_keys_in_every_audit_kind(self):
        self.materialize()
        other = self.source.with_name("duplicate-unlisted.cpp")
        other.write_text("int duplicate_unlisted() { return 47; }\n")
        listed_object = self.build_dir / "objects/duplicate-listed.obj"
        listed_pdb = self.build_dir / "objects/duplicate-listed.pdb"
        other_object = self.build_dir / "objects/duplicate-unlisted.obj"
        other_pdb = self.build_dir / "objects/duplicate-unlisted.pdb"
        listed_object.parent.mkdir(parents=True)
        other_arguments = self.launch_args(
            other_object, other_pdb, source=other
        )
        previous = Path.cwd()
        try:
            os.chdir(self.build_dir)
            self.assertEqual(
                self.run_standalone_producer_diagnostic(
                    self.launch_args(listed_object, listed_pdb)
                ),
                0,
            )
            self.assertEqual(
                self.run_standalone_producer_diagnostic(other_arguments), 0
            )
            self.assertEqual(self.run_resident_verifier_diagnostic(), 0)
        finally:
            os.chdir(previous)

        audits = (
            self.build_dir / "byte-identity/audit/materialization"
            / f"{self.recipe_id}.json",
            byte_identity.audit_object_path(
                self.build_dir, "fixture", "src/unit.cpp"
            ),
            byte_identity.audit_unlisted_path(
                self.build_dir, "fixture", "src/duplicate-unlisted.cpp"
            ),
        )
        verdict = self.build_dir / "byte-identity/audit/framework-verdict.json"
        for audit_path in audits:
            with self.subTest(audit=audit_path):
                original = audit_path.read_text()
                audit_path.write_text(
                    '{"status":"DUPLICATE-KEY-SENTINEL",' + original[1:]
                )
                self.assertEqual(self.run_resident_verifier_diagnostic(), 2)
                self.assertFalse(verdict.exists())
                audit_path.write_text(original)
                self.assertEqual(self.run_resident_verifier_diagnostic(), 0)

    def test_hidden_response_cleans_duplicate_key_prior_audit_and_continues(self):
        self.materialize()
        other = self.source.with_name("duplicate-response-unlisted.cpp")
        other.write_text("int duplicate_response_unlisted() { return 53; }\n")
        listed_object = self.build_dir / "objects/duplicate-response-listed.obj"
        listed_pdb = self.build_dir / "objects/duplicate-response-listed.pdb"
        other_object = self.build_dir / "objects/duplicate-response-unlisted.obj"
        other_pdb = self.build_dir / "objects/duplicate-response-unlisted.pdb"
        listed_object.parent.mkdir(parents=True)
        other_arguments = self.launch_args(
            other_object, other_pdb, source=other
        )
        previous = Path.cwd()
        try:
            os.chdir(self.build_dir)
            self.assertEqual(
                self.run_standalone_producer_diagnostic(
                    self.launch_args(listed_object, listed_pdb)
                ),
                0,
            )
            self.assertEqual(
                self.run_standalone_producer_diagnostic(other_arguments), 0
            )
            self.assertEqual(self.run_resident_verifier_diagnostic(), 0)
        finally:
            os.chdir(previous)

        listed_audit = byte_identity.audit_object_path(
            self.build_dir, "fixture", "src/unit.cpp"
        )
        other_audit = byte_identity.audit_unlisted_path(
            self.build_dir, "fixture", "src/duplicate-response-unlisted.cpp"
        )
        original = listed_audit.read_text()
        listed_audit.write_text(
            '{"status":"DUPLICATE-KEY-SENTINEL",' + original[1:]
        )
        verdict = self.build_dir / "byte-identity/audit/framework-verdict.json"
        response = self.directory / "duplicate-hidden-response.rsp"
        response.write_text(
            f"/Fo{listed_object}\n/Fd{listed_pdb}\n{self.source}\n/GL\n"
        )
        started = self.directory / "duplicate-hidden-response.started"
        arguments = self.launch_args(listed_object, listed_pdb)
        for hidden in (
            str(self.source), f"/Fo{listed_object}", f"/Fd{listed_pdb}",
        ):
            arguments.remove(hidden)
        arguments.append(f"@{response}")
        with (
            self.fake_control(STARTED=str(started)),
            self.standalone_producer_diagnostic(),
        ):
            previous = Path.cwd()
            try:
                os.chdir(self.build_dir)
                result = byte_identity.main(arguments)
            finally:
                os.chdir(previous)

        self.assertEqual(result, 2)
        self.assertFalse(started.exists())
        self.assertFalse(verdict.exists())
        self.assertFalse(listed_audit.exists())
        self.assertFalse(other_audit.exists())
        self.assertTrue(all(not path.exists() for path in (
            listed_object, listed_pdb, other_object, other_pdb,
        )))
        self.assertEqual(self.run_resident_verifier_diagnostic(), 2)
        self.assertFalse(verdict.exists())

    def test_preprocess_and_assembly_options_reject_before_compiler_start(self):
        for index, option in enumerate(
            (
                "/E", "/EP", "/P", "/FA", "/FAcs", "-e", "-fafoo",
                "/showIncludes",
            )
        ):
            with self.subTest(option=option):
                output = self.build_dir / f"objects/convenience-{index}.obj"
                pdb = self.build_dir / f"objects/convenience-{index}.pdb"
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(b"STALE")
                pdb.write_bytes(b"STALE-PDB")
                started = self.directory / f"convenience-{index}.started"
                arguments = self.launch_args(output, pdb)
                arguments.append(option)
                previous = Path.cwd()
                with (
                    self.fake_control(STARTED=str(started)),
                    self.standalone_producer_diagnostic(),
                ):
                    try:
                        os.chdir(self.build_dir)
                        result = byte_identity.main(arguments)
                    finally:
                        os.chdir(previous)
                self.assertEqual(result, 2)
                self.assertFalse(started.exists())
                self.assertFalse(output.exists())
                self.assertFalse(pdb.exists())

    def test_closed_case_aware_output_grammar_rejects_before_child(self):
        self.materialize()
        forbidden_root = self.source_dir / "forbidden-compiler-output"
        cases = [
            ("force-include-case", "replace-fi", f"/Fi{forbidden_root}.i"),
            ("pdb-case", "replace-fd", f"/FD{forbidden_root}.pdb"),
            ("object-case", "replace-fo", f"/FO{forbidden_root}.obj"),
            ("compile-case", "replace-c", "-C"),
            ("debug-case", "replace-zi", "/ZI"),
            ("preprocessor-output", "append", f"/Fi{forbidden_root}.i"),
            ("browser-lower", "append", f"/Fr{forbidden_root}.sbr"),
            ("browser-upper", "append", f"/FR{forbidden_root}.sbr"),
            ("pch-output", "append", f"/Fp{forbidden_root}.pch"),
            ("pch-create", "append", f"/Yc{self.include}"),
            ("pch-use", "append", f"/Yu{self.include}"),
            ("pch-auto", "append", "/YX"),
            ("pch-debug", "append", "/Yd"),
            ("pch-disable", "append", "/Y-"),
            ("exe-output", "append", f"/Fe{forbidden_root}.exe"),
            ("map-output", "append", f"/Fm{forbidden_root}.map"),
            ("source-c", "append", f"/Tc{self.source}"),
            ("source-cxx", "append", f"/Tp{self.source}"),
            ("wrong-wide-language", "append", "/TC"),
            ("dll-link", "append", "/LD"),
            ("syntax-only", "append", "/Zs"),
            ("link-tail", "append", "/link"),
            ("managed-input", "append", f"/FU{self.include}"),
            ("xml-doc", "append", f"/doc{forbidden_root}.xml"),
            ("source-deps", "append", f"/sourceDependencies{forbidden_root}.json"),
            ("duplicate-object", "append", f"/Fo{forbidden_root}.obj"),
            ("duplicate-pdb", "append", f"/Fd{forbidden_root}.pdb"),
            ("separated-object", "split-fo", str(
                self.build_dir / "objects/separated.obj"
            )),
            ("separated-pdb", "split-fd", str(
                self.build_dir / "objects/separated.pdb"
            )),
            ("separated-include", "split-fi", str(self.include)),
            ("duplicate-compile", "append", "/c"),
            ("duplicate-debug", "append", "/Zi"),
        ]
        for index, (label, operation, value) in enumerate(cases):
            with self.subTest(label=label):
                output = self.build_dir / f"objects/closed-{index}.obj"
                pdb = self.build_dir / f"objects/closed-{index}.pdb"
                output.parent.mkdir(parents=True, exist_ok=True)
                started = self.directory / f"closed-{index}.started"
                arguments = self.launch_args(output, pdb)
                if operation == "replace-fi":
                    arguments[arguments.index(f"/FI{self.include}")] = value
                elif operation == "replace-fd":
                    arguments[arguments.index(f"/Fd{pdb}")] = value
                elif operation == "replace-fo":
                    arguments[arguments.index(f"/Fo{output}")] = value
                elif operation == "replace-c":
                    arguments[arguments.index("-c")] = value
                elif operation == "replace-zi":
                    arguments[arguments.index("/Zi")] = value
                elif operation == "split-fo":
                    position = arguments.index(f"/Fo{output}")
                    arguments[position:position + 1] = ["/Fo", value]
                elif operation == "split-fd":
                    position = arguments.index(f"/Fd{pdb}")
                    arguments[position:position + 1] = ["/Fd", value]
                elif operation == "split-fi":
                    position = arguments.index(f"/FI{self.include}")
                    arguments[position:position + 1] = ["/FI", value]
                else:
                    arguments.insert(-1, value)
                previous = Path.cwd()
                with (
                    self.fake_control(STARTED=str(started)),
                    self.standalone_producer_diagnostic(),
                ):
                    try:
                        os.chdir(self.build_dir)
                        result = byte_identity.main(arguments)
                    finally:
                        os.chdir(previous)
                self.assertEqual(result, 2)
                self.assertFalse(started.exists())
                self.assertFalse(output.exists())
                self.assertFalse(
                    byte_identity.audit_object_path(
                        self.build_dir, "fixture", "src/unit.cpp"
                    ).exists()
                )
        self.assertFalse(any(
            path.name.startswith("forbidden-compiler-output")
            for path in self.source_dir.iterdir()
        ))

    def test_role_lexer_accepts_only_intentional_joined_and_separated_operands(self):
        self.materialize()
        output = self.build_dir / "objects/role-operands.obj"
        pdb = self.build_dir / "objects/role-operands.pdb"
        output.parent.mkdir(parents=True)
        arguments = self.launch_args(output, pdb)
        insertion = arguments.index(f"/Fo{output}")
        arguments[insertion:insertion] = [
            "/DJOINED_DEFINE=1",
            "/D", "SEPARATED_DEFINE=2",
            "/UJOINED_UNDEFINE",
            "/U", "SEPARATED_UNDEFINE",
            f"/I{self.include.parent}",
            "/I", str(self.include.parent),
        ]
        self.attest_command(arguments)
        previous = Path.cwd()
        try:
            with self.standalone_producer_diagnostic():
                os.chdir(self.build_dir)
                self.assertEqual(byte_identity.main(arguments), 0)
        finally:
            os.chdir(previous)
        self.assertTrue(output.is_file())
        self.assertTrue(
            byte_identity.audit_object_path(
                self.build_dir, "fixture", "src/unit.cpp"
            ).is_file()
        )

    def test_source_role_confusion_and_extra_positional_input_never_start_child(self):
        self.materialize()
        self.ensure_inventory_current()
        evil = self.source.with_name("extra-positional.cpp")
        evil.write_text("int extra_positional() { return 109; }\n")
        cases = (
            ("source-as-include", ["/I", str(self.source)]),
            ("extra-positional", [str(evil)]),
        )
        for label, injected in cases:
            with self.subTest(label=label):
                output = self.build_dir / f"objects/{label}.obj"
                pdb = self.build_dir / f"objects/{label}.pdb"
                output.parent.mkdir(parents=True, exist_ok=True)
                started = self.directory / f"{label}.started"
                arguments = self.launch_args(
                    output, pdb, ensure_inventory=False
                )
                insertion = arguments.index(f"/Fo{output}")
                arguments[insertion:insertion] = injected
                previous = Path.cwd()
                with (
                    self.fake_control(STARTED=str(started)),
                    self.standalone_producer_diagnostic(),
                ):
                    try:
                        os.chdir(self.build_dir)
                        result = byte_identity.main(arguments)
                    finally:
                        os.chdir(previous)
                self.assertEqual(result, 2)
                self.assertFalse(started.exists())
                self.assertFalse(output.exists())
                self.assertFalse(pdb.exists())

    def test_unattributable_final_source_globally_invalidates_prior_claims(self):
        other = self.source.with_name("prior-unlisted.cpp")
        other.write_text("int prior_unlisted() { return 113; }\n")
        self.materialize()
        self.ensure_inventory_current()
        listed_object = self.build_dir / "objects/prior-listed.obj"
        listed_pdb = self.build_dir / "objects/prior-listed.pdb"
        other_object = self.build_dir / "objects/prior-unlisted.obj"
        other_pdb = self.build_dir / "objects/prior-unlisted.pdb"
        listed_object.parent.mkdir(parents=True)
        prior_paths = (listed_object, listed_pdb, other_object, other_pdb)
        listed_arguments = self.launch_args(listed_object, listed_pdb)
        other_arguments = self.launch_args(
            other_object, other_pdb, source=other
        )
        previous = Path.cwd()
        try:
            os.chdir(self.build_dir)
            self.assertEqual(
                self.run_standalone_producer_diagnostic(listed_arguments),
                0,
            )
            self.assertEqual(
                self.run_standalone_producer_diagnostic(other_arguments),
                0,
            )
            self.assertEqual(self.run_resident_verifier_diagnostic(), 0)
        finally:
            os.chdir(previous)

        unconfigured = self.source.with_name("evil-unconfigured.cpp")
        unconfigured.write_text("int evil_unconfigured() { return 127; }\n")
        rejected_object = self.build_dir / "objects/unconfigured.obj"
        rejected_pdb = self.build_dir / "objects/unconfigured.pdb"
        arguments = self.launch_args(
            rejected_object,
            rejected_pdb,
            source=unconfigured,
            ensure_inventory=False,
        )
        # This is the malicious `/I <configured-source> evil.cpp` shape: the
        # final token is not inventoried and source attribution is unknowable.
        insertion = arguments.index(f"/Fo{rejected_object}")
        arguments[insertion:insertion] = ["/I", str(self.source)]
        started = self.directory / "unattributable.started"
        previous = Path.cwd()
        with (
            self.fake_control(STARTED=str(started)),
            self.standalone_producer_diagnostic(),
        ):
            try:
                os.chdir(self.build_dir)
                result = byte_identity.main(arguments)
            finally:
                os.chdir(previous)
        self.assertEqual(result, 2)
        self.assertFalse(started.exists())
        self.assertTrue(all(not path.exists() for path in prior_paths))
        self.assertFalse(rejected_object.exists())
        self.assertFalse(rejected_pdb.exists())
        compiler_audits = [
            *(self.build_dir / "byte-identity/audit/objects").rglob("*.json"),
            *(self.build_dir / "byte-identity/audit/unlisted-pass-through").rglob(
                "*.json"
            ),
        ]
        self.assertEqual(compiler_audits, [])
        verdict = self.build_dir / "byte-identity/audit/framework-verdict.json"
        self.assertFalse(verdict.exists())
        self.assertEqual(self.run_resident_verifier_diagnostic(), 2)
        self.assertFalse(verdict.exists())

    def test_final_absolute_yellow_source_is_not_parsed_as_y_option(self):
        parsed = byte_identity.validate_compile_arguments([
            "cl", "/Zi", "/Fooutput.obj", "/Fdoutput.pdb", "-c",
            "/yellow/project/source.cpp",
        ])
        self.assertEqual(parsed["source_token"], "/yellow/project/source.cpp")

    def test_attested_233_command_vc42_grammar_corpus_is_source_last(self):
        corpus = []
        for index in range(233):
            command = ["cl", "/nologo", "/TP"]
            if index % 2:
                command.extend(["/D", f"SEPARATED_{index}=1"])
            else:
                command.append(f"/DJOINED_{index}=1")
            command.append(f"/I/include/corpus-{index % 5}")
            if index < 226:
                command.append(f"/FI/include/pinned-{index % 7}.h")
            command.extend(["/W3", "/GX", "/Zi"])
            if index % 11:
                command.extend(["/O2", "-MT"])
            else:
                command.extend(["/Gm", "/Od", "-MTd"])
            command.extend([
                f"/Foobjects/corpus-{index}.obj",
                f"/Fdobjects/corpus-{index}.obj.pdb",
                "-c",
                f"/source/corpus-{index}.cpp",
            ])
            corpus.append(command)
        self.assertEqual(len(corpus), 233)
        self.assertEqual(
            sum(
                any(token.startswith("/FI") for token in command)
                for command in corpus
            ),
            226,
        )
        for index, command in enumerate(corpus):
            parsed = byte_identity.validate_compile_arguments(command)
            self.assertEqual(
                parsed["source_token"], f"/source/corpus-{index}.cpp"
            )
            self.assertEqual(parsed["language_mode"], "CXX")

    def test_unlisted_target_source_is_atomic_and_sanitized(self):
        # A different target may legitimately have a different baseline force
        # include.  The target-wide launcher must not union policies across the
        # whole manifest when it handles an unlisted source.
        other_include = self.include.with_name("other-target.h")
        other_include.write_text("#define OTHER_TARGET_HEADER 1\n")
        self.document["target_policies"].append(
            {
                "target": "other_target",
                "allowed_force_includes": [
                    {
                        "path": "include/other-target.h",
                        "sha256": byte_identity.sha256_file(other_include),
                    }
                ],
            }
        )
        self.write_manifest()
        self.materialize()
        other = self.source.with_name("other.cpp")
        other.write_text("int other() { return 11; }\n")
        output = self.build_dir / "objects/other.obj"
        pdb = self.build_dir / "objects/other.pdb"
        output.parent.mkdir(parents=True)
        output.write_bytes(b"STALE")
        pdb.write_bytes(b"STALE-PDB")
        self.ensure_inventory([
            ("fixture", self.source, "CXX"),
            ("other_target", other, "CXX"),
        ])
        arguments = self.launch_args(
            output, pdb, source=other, target="other_target",
            force_include=other_include, ensure_inventory=False,
        )
        self.attest_command(arguments)
        previous = Path.cwd()
        old_cl = os.environ.get("CL")
        old_wine = os.environ.get("WINEDEBUG")
        os.environ["CL"] = "/DPOISONED_UNLISTED_CL"
        os.environ["WINEDEBUG"] = "POISONED_UNLISTED_WINE"
        try:
            with self.standalone_producer_diagnostic():
                os.chdir(self.build_dir)
                result = byte_identity.main(arguments)
        finally:
            os.chdir(previous)
            if old_cl is None:
                os.environ.pop("CL", None)
            else:
                os.environ["CL"] = old_cl
            if old_wine is None:
                os.environ.pop("WINEDEBUG", None)
            else:
                os.environ["WINEDEBUG"] = old_wine
        self.assertEqual(result, 0)
        self.assertIn(b"FAKE-OBJ\0", output.read_bytes())
        self.assertNotIn(b"POISONED_UNLISTED", output.read_bytes())
        self.assertTrue(pdb.read_bytes().startswith(b"FAKE-PDB\0"))
        audit = json.loads(
            byte_identity.audit_unlisted_path(
                self.build_dir, "other_target", "src/other.cpp"
            ).read_text()
        )
        self.assertEqual(audit["status"], "unlisted_atomic_pass_through")
        self.assertFalse(audit["may_claim_byte_identity"])

    def test_launcher_attributes_arbitrary_extension_only_from_inventory(self):
        self.materialize()
        arbitrary = self.source.with_name("configured-source.dat")
        arbitrary.write_text("int configured_dat() { return 89; }\n")
        unconfigured = self.source.with_name("unconfigured-source.dat")
        unconfigured.write_text("int unconfigured_dat() { return 97; }\n")
        self.ensure_inventory([
            ("fixture", self.source, "CXX"),
            ("fixture", arbitrary, "CXX"),
        ])

        rejected_output = self.build_dir / "objects/unconfigured-dat.obj"
        rejected_pdb = self.build_dir / "objects/unconfigured-dat.pdb"
        started = self.directory / "unconfigured-dat.started"
        rejected = self.launch_args(
            rejected_output,
            rejected_pdb,
            source=unconfigured,
            ensure_inventory=False,
        )
        previous = Path.cwd()
        with (
            self.fake_control(STARTED=str(started)),
            self.standalone_producer_diagnostic(),
        ):
            try:
                os.chdir(self.build_dir)
                result = byte_identity.main(rejected)
            finally:
                os.chdir(previous)
        self.assertEqual(result, 2)
        self.assertFalse(started.exists())
        self.assertFalse(rejected_output.exists())
        self.assertFalse(rejected_pdb.exists())

        output = self.build_dir / "objects/configured-dat.obj"
        pdb = self.build_dir / "objects/configured-dat.pdb"
        arguments = self.launch_args(
            output, pdb, source=arbitrary, ensure_inventory=False
        )
        started = self.directory / "configured-dat-without-mode.started"
        previous = Path.cwd()
        with (
            self.fake_control(STARTED=str(started)),
            self.standalone_producer_diagnostic(),
        ):
            try:
                os.chdir(self.build_dir)
                self.assertEqual(byte_identity.main(arguments), 2)
            finally:
                os.chdir(previous)
        self.assertFalse(started.exists())
        self.assertFalse(output.exists())
        self.assertFalse(pdb.exists())
        arguments.insert(arguments.index(f"/Fo{output}"), "/TP")
        self.attest_command(arguments)
        previous = Path.cwd()
        try:
            with self.standalone_producer_diagnostic():
                os.chdir(self.build_dir)
                result = byte_identity.main(arguments)
        finally:
            os.chdir(previous)
        self.assertEqual(result, 0)
        audit_path = byte_identity.audit_unlisted_path(
            self.build_dir, "fixture", "src/configured-source.dat"
        )
        audit = json.loads(audit_path.read_text())
        self.assertEqual(audit["source"], "src/configured-source.dat")
        inventory = json.loads(
            byte_identity.inventory_path(self.build_dir).read_text()
        )
        entry = next(
            item for item in inventory["entries"]
            if item["source"] == "src/configured-source.dat"
        )
        self.assertEqual(entry["language"], "CXX")

    def test_arbitrary_c_inventory_requires_exact_tc_mode(self):
        self.materialize()
        arbitrary = self.source.with_name("configured-c-source.dat")
        arbitrary.write_text("int configured_c_dat(void) { return 131; }\n")
        self.ensure_inventory([
            ("fixture", self.source, "CXX"),
            ("fixture", arbitrary, "C"),
        ])
        output = self.build_dir / "objects/configured-c-dat.obj"
        pdb = self.build_dir / "objects/configured-c-dat.pdb"
        output.parent.mkdir(parents=True)
        arguments = self.launch_args(
            output, pdb, source=arbitrary, ensure_inventory=False
        )
        started = self.directory / "configured-c-without-mode.started"
        previous = Path.cwd()
        with (
            self.fake_control(STARTED=str(started)),
            self.standalone_producer_diagnostic(),
        ):
            try:
                os.chdir(self.build_dir)
                self.assertEqual(byte_identity.main(arguments), 2)
            finally:
                os.chdir(previous)
        self.assertFalse(started.exists())
        arguments.insert(arguments.index(f"/Fo{output}"), "/TC")
        self.attest_command(arguments)
        previous = Path.cwd()
        try:
            with self.standalone_producer_diagnostic():
                os.chdir(self.build_dir)
                self.assertEqual(byte_identity.main(arguments), 0)
        finally:
            os.chdir(previous)
        self.assertTrue(
            byte_identity.audit_unlisted_path(
                self.build_dir, "fixture", "src/configured-c-source.dat"
            ).is_file()
        )

    def test_generated_cxx_profile_is_bound_by_command_inventory(self):
        output = self.build_dir / "objects/profile.obj"
        pdb = self.build_dir / "objects/profile.pdb"
        output.parent.mkdir(parents=True)
        launch = self.launch_args(output, pdb)
        separator = launch.index("--")
        baseline = list(launch[separator + 1:])
        insertion = baseline.index(f"/Fo{output}")
        baseline[insertion:insertion] = ["/W4", "/D", "FEATURE_FLAG=1"]
        positive = [*launch[:separator + 1], *baseline]
        self.attest_command(positive)

        compile_commands = self.build_dir / "compile_commands.json"
        attest = [
            "attest-commands",
            "--manifest", str(self.manifest),
            "--source-dir", str(self.source_dir),
            "--build-dir", str(self.build_dir),
            "--compiler", str(self.compiler),
            "--compile-commands", str(compile_commands),
            "--output", str(byte_identity.command_inventory_path(self.build_dir)),
            "--policy-stamp", str(byte_identity.command_policy_stamp_path(
                self.build_dir
            )),
        ]

        def reject(child):
            compile_commands.write_text(json.dumps([{
                "directory": str(self.build_dir),
                "command": shlex.join(child),
                "file": str(self.source),
                "output": str(output),
            }], indent=2) + "\n")
            self.assertEqual(byte_identity.main(attest), 2)

        mutations = {}
        for label, old, replacement in (
            ("missing-zi", ["/Zi"], []),
            ("nonliteral-zi", ["/Zi"], ["-Zi"]),
            ("missing-o2", ["/O2"], []),
            ("nonliteral-o2", ["/O2"], ["-O2"]),
            ("missing-ndebug", ["/D", "NDEBUG"], []),
            ("wrong-case-ndebug", ["NDEBUG"], ["ndebug"]),
        ):
            child = list(baseline)
            position = next(
                index for index in range(len(child) - len(old) + 1)
                if child[index:index + len(old)] == old
            )
            child[position:position + len(old)] = replacement
            mutations[label] = child
        for label, token in (
            ("duplicate-zi", "/Zi"),
            ("duplicate-o2", "/O2"),
            ("forbidden-od", "-Od"),
            ("forbidden-gm", "-Gm"),
        ):
            child = list(baseline)
            child.insert(child.index(f"/Fo{output}"), token)
            mutations[label] = child
        debug = list(baseline)
        position = debug.index(f"/Fo{output}")
        debug[position:position] = ["/D", "_dEbUg=1"]
        mutations["forbidden-debug-definition"] = debug
        duplicate_ndebug = list(baseline)
        position = duplicate_ndebug.index(f"/Fo{output}")
        duplicate_ndebug[position:position] = ["/DNDEBUG"]
        mutations["duplicate-ndebug"] = duplicate_ndebug
        undefine = list(baseline)
        position = undefine.index(f"/Fo{output}")
        undefine[position:position] = ["/U", "nDeBuG"]
        mutations["forbidden-ndebug-undefinition"] = undefine

        for label, child in mutations.items():
            with self.subTest(label=label):
                reject(child)
        self.assertFalse(output.exists())
        self.assertFalse(pdb.exists())

    def test_verify_requires_every_private_tmp_namespace_to_remain_empty(self):
        other = self.source.with_name("tmp-unlisted.cpp")
        other.write_text("int tmp_unlisted() { return 137; }\n")
        self.materialize()
        self.ensure_inventory_current()
        listed_object = self.build_dir / "objects/tmp-listed.obj"
        listed_pdb = self.build_dir / "objects/tmp-listed.pdb"
        unlisted_object = self.build_dir / "objects/tmp-unlisted.obj"
        unlisted_pdb = self.build_dir / "objects/tmp-unlisted.pdb"
        listed_object.parent.mkdir(parents=True)
        listed_arguments = self.launch_args(listed_object, listed_pdb)
        unlisted_arguments = self.launch_args(
            unlisted_object, unlisted_pdb, source=other
        )
        previous = Path.cwd()
        with mock.patch.object(
            byte_identity,
            "validate_generated_cxx_semantic_profile",
            wraps=byte_identity.validate_generated_cxx_semantic_profile,
        ) as profile_validator:
            try:
                os.chdir(self.build_dir)
                self.assertEqual(
                    self.run_standalone_producer_diagnostic(listed_arguments),
                    0,
                )
                self.assertEqual(
                    self.run_standalone_producer_diagnostic(unlisted_arguments),
                    0,
                )
                self.assertEqual(self.run_resident_verifier_diagnostic(), 0)
            finally:
                os.chdir(previous)
        self.assertEqual(
            [
                call.args[0]["source_token"]
                for call in profile_validator.call_args_list
                if call.args[1] == "runtime generated CXX command"
            ],
            [str(self.source), str(other)],
        )
        listed_audit = json.loads(
            byte_identity.audit_object_path(
                self.build_dir, "fixture", "src/unit.cpp"
            ).read_text()
        )
        unlisted_audit = json.loads(
            byte_identity.audit_unlisted_path(
                self.build_dir, "fixture", "src/tmp-unlisted.cpp"
            ).read_text()
        )
        tmp_directories = (
            Path(listed_audit["seed_object"]).parent / "tmp",
            Path(unlisted_audit["private_object"]).parent / "tmp",
        )
        verdict = self.build_dir / "byte-identity/audit/framework-verdict.json"
        for index, temporary in enumerate(tmp_directories):
            with self.subTest(private_kind=index):
                injected = temporary / "late-injected.tmp"
                injected.write_bytes(b"UNDECLARED-TEMPORARY-STATE")
                self.assertEqual(self.run_resident_verifier_diagnostic(), 2)
                self.assertFalse(verdict.exists())
                injected.unlink()
                self.assertEqual(self.run_resident_verifier_diagnostic(), 0)
                self.assertTrue(verdict.is_file())

    def test_private_compiler_area_rejects_undeclared_outputs(self):
        other = self.source.with_name("unexpected-unlisted.cpp")
        other.write_text("int unexpected_unlisted() { return 103; }\n")
        self.materialize()
        self.ensure_inventory_current()
        cases = [
            (self.source, "src/unit.cpp", False),
            (other, "src/unexpected-unlisted.cpp", True),
        ]
        for index, (source, relative, unlisted) in enumerate(cases):
            with self.subTest(source=relative):
                output = self.build_dir / f"objects/unexpected-{index}.obj"
                pdb = self.build_dir / f"objects/unexpected-{index}.pdb"
                arguments = self.launch_args(output, pdb, source=source)
                previous = Path.cwd()
                with (
                    self.fake_control(EXTRA_PRIVATE_OUTPUT="undeclared.bin"),
                    self.standalone_producer_diagnostic(),
                ):
                    try:
                        os.chdir(self.build_dir)
                        result = byte_identity.main(arguments)
                    finally:
                        os.chdir(previous)
                self.assertEqual(result, 2)
                self.assertFalse(output.exists())
                self.assertFalse(pdb.exists())
                audit = (
                    byte_identity.audit_unlisted_path(
                        self.build_dir, "fixture", relative
                    )
                    if unlisted else
                    byte_identity.audit_object_path(
                        self.build_dir, "fixture", relative
                    )
                )
                self.assertFalse(audit.exists())

    def test_failed_unlisted_compile_removes_stale_outputs(self):
        self.materialize()
        other = self.source.with_name("other.cpp")
        other.write_text("int other() { return 11; }\n")
        output = self.build_dir / "objects/other.obj"
        pdb = self.build_dir / "objects/other.pdb"
        output.parent.mkdir(parents=True)
        output.write_bytes(b"STALE")
        pdb.write_bytes(b"STALE-PDB")
        arguments = self.launch_args(output, pdb, source=other)
        previous = Path.cwd()
        with (
            self.fake_control(FAIL=True),
            self.standalone_producer_diagnostic(),
        ):
            try:
                os.chdir(self.build_dir)
                result = byte_identity.main(arguments)
            finally:
                os.chdir(previous)
        self.assertEqual(result, 2)
        self.assertFalse(output.exists())
        self.assertFalse(pdb.exists())
        self.assertFalse(
            byte_identity.audit_unlisted_path(
                self.build_dir, "fixture", "src/other.cpp"
            ).exists()
        )

    def test_unlisted_private_pdb_path_and_copy_are_verified(self):
        self.materialize()
        listed_object = self.build_dir / "objects/listed.obj"
        listed_pdb = self.build_dir / "objects/listed.pdb"
        listed_object.parent.mkdir(parents=True)
        other = self.source.with_name("verified-unlisted.cpp")
        other.write_text("int verified_unlisted() { return 29; }\n")
        unlisted_object = self.build_dir / "objects/verified-unlisted.obj"
        unlisted_pdb = self.build_dir / "objects/verified-unlisted.pdb"
        unlisted_arguments = self.launch_args(
            unlisted_object, unlisted_pdb, source=other
        )
        previous = Path.cwd()
        try:
            os.chdir(self.build_dir)
            self.assertEqual(
                self.run_standalone_producer_diagnostic(
                    self.launch_args(listed_object, listed_pdb)
                ),
                0,
            )
            self.assertEqual(
                self.run_standalone_producer_diagnostic(unlisted_arguments), 0
            )
            self.assertEqual(
                self.run_resident_verifier_diagnostic(
                    [
                        "verify",
                        "--manifest", str(self.manifest),
                        "--source-dir", str(self.source_dir),
                        "--build-dir", str(self.build_dir),
                        "--compiler", str(self.compiler),
                    ]
                ),
                0,
            )
        finally:
            os.chdir(previous)
        audit_path = byte_identity.audit_unlisted_path(
            self.build_dir, "fixture", "src/verified-unlisted.cpp"
        )
        audit = json.loads(audit_path.read_text())
        private_pdb = Path(audit["private_pdb"])
        self.assertTrue(private_pdb.is_file())
        self.assertEqual(private_pdb.read_bytes(), unlisted_pdb.read_bytes())
        verdict = json.loads(
            (self.build_dir / "byte-identity/audit/framework-verdict.json").read_text()
        )
        self.assertEqual(
            verdict["unlisted_translation_units"],
            ["fixture:src/verified-unlisted.cpp"],
        )
        private_pdb.write_bytes(b"TAMPERED")
        self.assertEqual(
            self.run_resident_verifier_diagnostic(
                [
                    "verify",
                    "--manifest", str(self.manifest),
                    "--source-dir", str(self.source_dir),
                    "--build-dir", str(self.build_dir),
                    "--compiler", str(self.compiler),
                ]
            ),
            2,
        )

    def test_unlisted_recompile_removes_audit_before_manifest_gate(self):
        self.materialize()
        other = self.source.with_name("stale-unlisted.cpp")
        other.write_text("int stale_unlisted() { return 19; }\n")
        output = self.build_dir / "objects/stale-unlisted.obj"
        pdb = self.build_dir / "objects/stale-unlisted.pdb"
        output.parent.mkdir(parents=True)
        arguments = self.launch_args(output, pdb, source=other)
        previous = Path.cwd()
        try:
            with self.standalone_producer_diagnostic():
                os.chdir(self.build_dir)
                self.assertEqual(byte_identity.main(arguments), 0)
        finally:
            os.chdir(previous)
        audit_path = byte_identity.audit_unlisted_path(
            self.build_dir, "fixture", "src/stale-unlisted.cpp"
        )
        self.assertTrue(audit_path.is_file())
        self.document["toolchain"]["compiler_support_files"][0]["sha256"] = "0" * 64
        self.write_manifest()
        previous = Path.cwd()
        try:
            with self.standalone_producer_diagnostic():
                os.chdir(self.build_dir)
                result = byte_identity.main(arguments)
        finally:
            os.chdir(previous)
        self.assertEqual(result, 2)
        self.assertFalse(output.exists())
        self.assertFalse(pdb.exists())
        self.assertFalse(audit_path.exists())

    def test_repository_manifest_and_cmake_module_are_native_valid(self):
        repository_manifest = ROOT / "tools/byte_identity_manifest.json"
        module_text = (ROOT / "cmake/byte_identity.cmake").read_text()
        self.assertIn("if(NOT CMAKE_HOST_UNIX)", module_text)
        self.assertNotIn("if(NOT UNIX)", module_text)
        self.assertNotIn('file(MAKE_DIRECTORY "${_state_dir}")', module_text)
        self.assertNotIn('file(REMOVE "${_plan}")', module_text)
        self.assertNotIn('file(REMOVE "${_inventory}"', module_text)
        self.assertIn(
            '"${_tool}" verify',
            module_text,
        )
        self.assertIn("--no-publish", module_text)
        self.assertNotIn(
            'BYPRODUCTS "${_state_dir}/audit/framework-verdict.json"',
            module_text,
        )
        self.assertIn(
            "Deferring terminal verdict publication to the resident outer driver",
            module_text,
        )
        document = byte_identity.strict_json_loads(
            repository_manifest.read_bytes()
        )
        configured_roots = byte_identity.manifest_host_roots()
        if set(configured_roots) == set(byte_identity.MANIFEST_HOST_ROOT_ENV):
            with tempfile.TemporaryDirectory() as build:
                state = byte_identity.validate_manifest(
                    repository_manifest, ROOT, Path(build)
                )
        else:
            # The checked manifest intentionally contains no physical host
            # seats. Full pin validation occurs when the explicit local roots
            # are bound; schema/content-independent repository assertions
            # remain native and relocatable here.
            state = document
        self.assertEqual(state["translation_units"][0]["source"],
                         "LEGO1/lego/legoomni/src/paths/legopathboundary.cpp")
        self.assertEqual(
            [policy["target"] for policy in state["target_policies"]],
            [
                "3dmanager", "anim", "config", "geom", "isle", "lego1",
                "misc", "mxdirectx", "omni", "realtime", "roi", "shape",
                "tglrl", "viewmanager",
            ],
        )
        smartheap_targets = {
            "3dmanager", "anim", "geom", "isle", "lego1", "misc",
            "mxdirectx", "omni", "realtime", "roi", "shape", "tglrl",
            "viewmanager",
        }
        expected_force_include = {
            "path": "3rdparty/smartheap/SMRTHEAP.HPP",
            "sha256": (
                "a1217eb2a0dd61218962341d74bf028f9215c92855c0e8753b9b79c513d520ad"
            ),
        }
        observed_force_include_policy = {
            policy["target"]: [
                {"path": item["path"], "sha256": item["sha256"]}
                for item in policy["allowed_force_includes"]
            ]
            for policy in state["target_policies"]
        }
        self.assertEqual(
            observed_force_include_policy,
            {
                target: (
                    [expected_force_include] if target in smartheap_targets
                    else []
                )
                for target in observed_force_include_policy
            },
        )
        self.assertEqual(
            byte_identity.sha256_file(
                ROOT / expected_force_include["path"]
            ),
            expected_force_include["sha256"],
        )
        posix_toolchain = document["toolchain"]["backend_profiles"][
            byte_identity.POSIX_WINE_BACKEND
        ]
        compiler_data = {
            item["path"]: item["sha256"]
            for item in posix_toolchain["compiler_support_files"]
            if item["path"] in {
                "bin/CL.ERR", "bin/CL32.MSG", "bin/C1.ERR", "bin/C23.ERR",
            }
        }
        self.assertEqual(compiler_data, {
            "bin/CL.ERR": (
                "02fc2947df2cd2ef3fa8d0ad8ea27490aa612061a51b3ae0c608640ec989aae9"
            ),
            "bin/CL32.MSG": (
                "113f7d498d674d8a8b94983481988f166dec74719534c3d87e522a3d29545faf"
            ),
            "bin/C1.ERR": (
                "813dbead1c37305dfec3b2628c2fff945502c76f32a2bb02330a44098c26275c"
            ),
            "bin/C23.ERR": (
                "31af2a48ed27e1f663d15181c4876857cc4679d773d7890e6ca6c2a6c2960f90"
            ),
        })
        self.assertEqual(
            {
                item["path"]: (item["sha256"], item["roles"])
                for item in posix_toolchain["producer_support_files"]
            },
            {
                "bin/RCDLL.DLL": (
                    "21d47edc33dccba245fa5a4c00688fe4539f160cbecff650352b5f2dcf9a14b8",
                    ["resource"],
                ),
                "bin/msvcrt20.dll": (
                    "72a46bd99188b67d48270a1bf40ffd6cd9bc5814818066a743eaffb8d64d88e8",
                    ["resource"],
                ),
                "bin/LINK.EXE": (
                    "6ca5a19155e4170e8df08247769b4586fa951743f09f1d8fcec838fc4eb9750e",
                    ["archive"],
                ),
                "bin/CVTRES.EXE": (
                    "7d66e9e5437b8d983432d8addedd7ea342bb814a34b1ffdebbc30018485004e8",
                    ["archive", "link"],
                ),
                "bin/CVTRES.ERR": (
                    "c2d246a342f3aa9dddbb7145a2c06477a446935bc3d0e92afa31cee4d9d37fbb",
                    ["archive", "link"],
                ),
                "bin/CVPACK.EXE": (
                    "73335ab475f1c9d9027a75c137024e0897f8187a1d83f308ec9e79e794921420",
                    ["archive", "link"],
                ),
                "bin/CVPACK.ERR": (
                    "b13db1db1c6e66f497b569cfe4c039bf64eb3437acfb158ab531d9dbace6021f",
                    ["archive", "link"],
                ),
            },
        )
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "check.cmake"
            script.write_text(
                f'include("{ROOT / "cmake/byte_identity.cmake"}")\n'
            )
            subprocess.run(["cmake", "-P", str(script)], check=True,
                           capture_output=True, text=True)

    def test_smartheap_force_include_propagates_by_target_output(self):
        cmake = shutil.which("cmake")
        if cmake is None:
            self.skipTest("native CMake is unavailable")

        source = self.directory / "smartheap-propagation-source"
        build = self.directory / "smartheap-propagation-build"
        (source / "src").mkdir(parents=True)
        smartheap = source / "3rdparty/smartheap"
        smartheap.mkdir(parents=True)
        shared_sources = (source / "src/shared.cpp", source / "src/second.cpp")
        for index, path in enumerate(shared_sources):
            path.write_text(f"int shared_{index}() {{ return {index}; }}\n")
        header = smartheap / "SMRTHEAP.HPP"
        header.write_text("#define SMARTHEAP_PROPAGATION_FIXTURE 1\n")
        (smartheap / "SHLW32MT.LIB").write_bytes(b"fixture archive seat\n")

        producer_marker = self.directory / "smartheap-producer-started"
        configure_tools = {}
        for role in ("compiler", "rc", "lib", "link"):
            path = self.directory / f"smartheap-{role}"
            path.write_text(
                "#!/bin/sh\n"
                f"printf '%s\\n' {shlex.quote(role)} >> "
                f"{shlex.quote(str(producer_marker))}\n"
                "exit 97\n"
            )
            path.chmod(0o755)
            configure_tools[role] = str(path)

        smartheap_targets = (
            "3dmanager", "anim", "geom", "isle", "lego1", "misc",
            "mxdirectx", "omni", "realtime", "roi", "shape", "tglrl",
            "viewmanager",
        )
        all_targets = (*smartheap_targets, "config")
        target_lines = []
        for target in (
            "3dmanager", "anim", "geom", "lego1", "misc", "mxdirectx",
            "omni", "realtime", "roi", "shape", "tglrl", "viewmanager",
        ):
            target_lines.extend((
                f"  add_library({target} STATIC src/shared.cpp src/second.cpp)",
                f"  target_link_libraries({target} PRIVATE ${{ARG_LINK_LIBRARIES}})",
            ))
        (source / "CMakeLists.txt").write_text(
            "\n".join((
                "cmake_minimum_required(VERSION 3.20 FATAL_ERROR)",
                "set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE BOOL \"\" FORCE)",
                "project(smartheap_force_include LANGUAGES CXX)",
                "add_library(SmartHeap::SmartHeap STATIC IMPORTED GLOBAL)",
                "set_property(TARGET SmartHeap::SmartHeap PROPERTY "
                "IMPORTED_LOCATION \"${PROJECT_SOURCE_DIR}/3rdparty/"
                "smartheap/SHLW32MT.LIB\")",
                "set_property(TARGET SmartHeap::SmartHeap PROPERTY "
                "INTERFACE_COMPILE_OPTIONS \"/FI${PROJECT_SOURCE_DIR}/"
                "3rdparty/smartheap/SMRTHEAP.HPP\")",
                "function(add_lego_libraries)",
                "  cmake_parse_arguments(ARG \"\" \"\" \"LINK_LIBRARIES\" "
                "${ARGN})",
                *target_lines,
                "endfunction()",
                "add_lego_libraries(LINK_LIBRARIES SmartHeap::SmartHeap)",
                "add_library(isle STATIC src/shared.cpp src/second.cpp)",
                "target_link_libraries(isle PRIVATE SmartHeap::SmartHeap)",
                "add_library(config STATIC src/shared.cpp src/second.cpp)",
                "",
            ))
        )
        init = self.directory / "smartheap-propagation-init.cmake"
        init.write_bytes(byte_identity.render_configure_init(configure_tools))
        environment = dict(os.environ)
        for name in ("CC", "CXX", "RC", "AR", "LD"):
            environment.pop(name, None)
        configured = subprocess.run(
            [
                cmake, "-C", str(init), "-S", str(source), "-B", str(build),
                "-G", "Unix Makefiles",
                f"-DCMAKE_BUILD_TYPE={byte_identity.RESIDENT_CMAKE_BUILD_TYPE}",
            ],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=30, check=False, env=environment,
        )
        self.assertEqual(configured.returncode, 0, configured.stdout)
        self.assertFalse(
            producer_marker.exists(),
            configured.stdout + (
                producer_marker.read_text() if producer_marker.exists() else ""
            ),
        )

        raw_database = json.loads((build / "compile_commands.json").read_text())
        by_target_output = {}
        for index, record in enumerate(raw_database):
            output = record.get("output")
            self.assertIsInstance(output, str, (index, record))
            match = re.search(
                r"(?:^|/)CMakeFiles/([^/]+)\.dir/",
                output.replace("\\", "/"),
            )
            self.assertIsNotNone(match, (index, output))
            owner = (match.group(1), output)
            self.assertNotIn(owner, by_target_output)
            by_target_output[owner] = record

        self.assertEqual(
            {target for target, _output in by_target_output},
            set(all_targets),
        )
        self.assertEqual(len(by_target_output), len(all_targets) * 2)
        manifest = byte_identity.strict_json_loads(
            (ROOT / "tools/byte_identity_manifest.json").read_bytes()
        )
        manifest_force_includes = {
            policy["target"]: [item["path"] for item in policy["allowed_force_includes"]]
            for policy in manifest["target_policies"]
        }
        expected_relative = "3rdparty/smartheap/SMRTHEAP.HPP"
        self.assertEqual(
            manifest_force_includes,
            {
                target: ([expected_relative] if target in smartheap_targets else [])
                for target in all_targets
            },
        )

        source_owners = {}
        for (target, output), record in by_target_output.items():
            source_path = Path(record["file"]).resolve()
            source_owners.setdefault(source_path, {})[target] = output
            tokens = byte_identity._command_database_tokens(
                record["command"], f"SmartHeap propagation {target} {output}"
            )
            force_includes = []
            cursor = 0
            while cursor < len(tokens):
                token = tokens[cursor]
                folded = token.casefold()
                if folded in {"/fi", "-fi"}:
                    self.assertLess(cursor + 1, len(tokens))
                    force_includes.append(tokens[cursor + 1])
                    cursor += 2
                    continue
                if folded.startswith(("/fi", "-fi")):
                    force_includes.append(token[3:])
                cursor += 1
            self.assertEqual(
                force_includes,
                [str(header.resolve())] if target in smartheap_targets else [],
                (target, record),
            )

        self.assertEqual(set(source_owners), {path.resolve() for path in shared_sources})
        for owners in source_owners.values():
            self.assertEqual(set(owners), set(all_targets))
            self.assertNotEqual(owners["mxdirectx"], owners["config"])

    def test_cmake_singleton_zero_indices_wire_every_terminal_producer(self):
        source = self.directory / "zero-index-source"
        build = self.directory / "zero-index-build"
        controller_root = source / "controller"
        tools = controller_root / "framework/tools"
        cmake_dir = source / "cmake"
        src = source / "src"
        resources = source / "resources"
        for directory in (tools, cmake_dir, src, resources):
            directory.mkdir(parents=True)
        shutil.copy2(
            ROOT / "cmake/byte_identity.cmake",
            cmake_dir / "byte_identity.cmake",
        )
        (tools / "byte_identity_backend.py").write_text("# fixture backend\n")
        (tools / "entropy.py").write_text("# fixture entropy\n")
        (tools / "byte_identity_manifest.json").write_text("{}\n")
        (src / "shared.cpp").write_text("int shared() { return 1; }\n")
        (src / "lego1.cpp").write_text("int main() { return 0; }\n")
        (resources / "lego1.rc").write_text("1 RCDATA { 0 }\n")
        vendor = source / "vendor.lib"
        vendor.write_bytes(b"!<arch>\\nZERO-INDEX-FIXTURE")

        producer_marker = self.directory / "zero-index-producer-started"
        raw_tools = {}
        for role in ("rc", "lib", "link"):
            path = self.directory / f"raw-{role}-wrapper"
            path.write_text(
                "#!/bin/sh\n"
                f"printf '%s\\n' {shlex.quote(role)} > "
                f"{shlex.quote(str(producer_marker))}\n"
                "exit 97\n"
            )
            path.chmod(0o755)
            raw_tools[role] = path

        controller = tools / "byte_identity.py"
        controller.write_text(
            "#!/usr/bin/env python3\n"
            "from pathlib import Path\n"
            "import sys\n"
            f"unexpected = Path({str(producer_marker)!r})\n"
            "argv = sys.argv[1:]\n"
            "command = argv[0] if argv else ''\n"
            "def value(flag):\n"
            "    return argv[argv.index(flag) + 1]\n"
            "def cmake(value):\n"
            "    return str(value).replace('\\\\', '/').replace('\\\"', '\\\\\"')\n"
            "if command == 'invalidate':\n"
            "    raise SystemExit(0)\n"
            "if command == 'plan':\n"
            "    source = Path(value('--source-dir'))\n"
            "    build = Path(value('--build-dir'))\n"
            "    archive_source = source / 'vendor.lib'\n"
            "    archive_output = build / 'byte-identity/archives/vendor.lib'\n"
            "    archive_audit = build / 'byte-identity/audit/vendor.json'\n"
            "    targets = ('tglrl', 'realtime', 'viewmanager', 'mxdirectx', "
            "               'roi', 'geom', 'shape', 'anim', 'misc', "
            "               '3dmanager', 'omni', 'lego1')\n"
            "    target_list = ';'.join(targets)\n"
            "    lines = [\n"
            "        'set(ISLE_BYTE_IDENTITY_PLAN_COMPLETE TRUE)',\n"
            "        'set(ISLE_BYTE_IDENTITY_PHASE \\\"compiler_output_comdat_v1\\\")',\n"
            "        'set(ISLE_BYTE_IDENTITY_EXECUTION_BACKEND \\\"posix_wine_virtual_z_v1\\\")',\n"
            "        'set(ISLE_BYTE_IDENTITY_COMPLETION \\\"planned_not_composed\\\")',\n"
            "        'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_ENABLED FALSE)',\n"
            "        'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_POLICY_SHA256 \\\"\\\")',\n"
            "        'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_OUTPUTS)',\n"
            "        'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_INDICES)',\n"
            "        'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_LINK_INDICES)',\n"
            "        'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_FORBIDDEN_INTERFACES)',\n"
            "        'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_PREBUILT_SOURCE_ARTIFACTS \\\"forbidden\\\")',\n"
            "        f'set(ISLE_BYTE_IDENTITY_POLICY_INPUTS \\\"{cmake(archive_source)}\\\")',\n"
            "        f'set(ISLE_BYTE_IDENTITY_TARGETS \\\"{target_list}\\\")',\n"
            "        'set(ISLE_BYTE_IDENTITY_TU_INDICES)',\n"
            "        'set(ISLE_BYTE_IDENTITY_RECIPE_IDS)',\n"
            "        'set(ISLE_BYTE_IDENTITY_IMAGE_INDICES)',\n"
            "        'list(APPEND ISLE_BYTE_IDENTITY_IMAGE_INDICES \\\"0\\\")',\n"
            "        'set(ISLE_BYTE_IDENTITY_IMAGE_0_IDENTITY \\\"LEGO1\\\")',\n"
            "        'set(ISLE_BYTE_IDENTITY_IMAGE_0_TARGET \\\"lego1\\\")',\n"
            "        'set(ISLE_BYTE_IDENTITY_IMPORTED_TARGET_INDICES)',\n"
            "        'list(APPEND ISLE_BYTE_IDENTITY_IMPORTED_TARGET_INDICES \\\"0\\\")',\n"
            "        'set(ISLE_BYTE_IDENTITY_IMPORTED_TARGET_0_NAME \\\"Vendor::Archive\\\")',\n"
            "        'set(ISLE_BYTE_IDENTITY_IMPORTED_TARGET_0_TYPE \\\"STATIC_LIBRARY\\\")',\n"
            "        'set(ISLE_BYTE_IDENTITY_IMPORTED_TARGET_0_GLOBAL \\\"FALSE\\\")',\n"
            "        f'set(ISLE_BYTE_IDENTITY_IMPORTED_TARGET_0_LOCATION \\\"{cmake(archive_source)}\\\")',\n"
            "        'set(ISLE_BYTE_IDENTITY_ARCHIVE_INDICES)',\n"
            "        'list(APPEND ISLE_BYTE_IDENTITY_ARCHIVE_INDICES \\\"0\\\")',\n"
            "        'set(ISLE_BYTE_IDENTITY_ARCHIVE_0_IDENTITY \\\"SmartHeap\\\")',\n"
            "        'set(ISLE_BYTE_IDENTITY_ARCHIVE_0_IMPORTED_TARGET \\\"Vendor::Archive\\\")',\n"
            "        f'set(ISLE_BYTE_IDENTITY_ARCHIVE_0_SOURCE \\\"{cmake(archive_source)}\\\")',\n"
            "        f'set(ISLE_BYTE_IDENTITY_ARCHIVE_0_OUTPUT \\\"{cmake(archive_output)}\\\")',\n"
            "        f'set(ISLE_BYTE_IDENTITY_ARCHIVE_0_AUDIT \\\"{cmake(archive_audit)}\\\")',\n"
            "        'set(ISLE_BYTE_IDENTITY_ARCHIVE_0_CONTRACT_INDICES)',\n"
            "    ]\n"
            "    for surface in (\n"
            "        'INTERFACE_LINK_LIBRARIES',\n"
            "        'INTERFACE_LINK_LIBRARIES_DIRECT',\n"
            "        'INTERFACE_LINK_LIBRARIES_DIRECT_EXCLUDE',\n"
            "        'INTERFACE_LINK_OPTIONS',\n"
            "        'INTERFACE_LINK_DIRECTORIES',\n"
            "        'INTERFACE_INCLUDE_DIRECTORIES',\n"
            "        'INTERFACE_SYSTEM_INCLUDE_DIRECTORIES',\n"
            "        'INTERFACE_COMPILE_OPTIONS',\n"
            "        'INTERFACE_COMPILE_DEFINITIONS',\n"
            "        'INTERFACE_COMPILE_FEATURES',\n"
            "        'INTERFACE_SOURCES',\n"
            "    ):\n"
            "        lines.append(\n"
            "            f'set(ISLE_BYTE_IDENTITY_IMPORTED_TARGET_0_{surface})'\n"
            "        )\n"
            "    fragment = '\\n'.join(lines) + '\\n'\n"
            "    output = Path(value('--output'))\n"
            "    output.parent.mkdir(parents=True, exist_ok=True)\n"
            "    output.write_text(fragment)\n"
            "    sys.stdout.write(fragment)\n"
            "    raise SystemExit(0)\n"
            "if command == 'inventory':\n"
            "    count = sum(item == '--entry' for item in argv)\n"
            "    lines = [\n"
            "        'set(ISLE_BYTE_IDENTITY_INVENTORY_COMPLETE TRUE)',\n"
            "        'set(ISLE_BYTE_IDENTITY_INVENTORY_INDICES)',\n"
            "    ]\n"
            "    lines.extend(\n"
            "        f'list(APPEND ISLE_BYTE_IDENTITY_INVENTORY_INDICES \\\"{index}\\\")'\n"
            "        for index in range(count)\n"
            "    )\n"
            "    fragment = '\\n'.join(lines) + '\\n'\n"
            "    output = Path(value('--output'))\n"
            "    cmake_output = Path(value('--cmake-output'))\n"
            "    stamp = Path(value('--policy-stamp'))\n"
            "    for path in (output, cmake_output, stamp):\n"
            "        path.parent.mkdir(parents=True, exist_ok=True)\n"
            "    output.write_text('{}\\n')\n"
            "    cmake_output.write_text(fragment)\n"
            "    stamp.write_text('fixture-policy\\n')\n"
            "    sys.stdout.write(fragment)\n"
            "    raise SystemExit(0)\n"
            "unexpected.write_text(command + '\\n')\n"
            "raise SystemExit(91)\n"
        )
        controller.chmod(0o755)

        static_targets = (
            "tglrl", "realtime", "viewmanager", "mxdirectx", "roi",
            "geom", "shape", "anim", "misc", "3dmanager", "omni",
        )
        cmake_lines = [
            "cmake_minimum_required(VERSION 3.21 FATAL_ERROR)",
            "set(CMAKE_EXPORT_COMPILE_COMMANDS ON)",
            'set(CMAKE_SYSTEM_NAME "Generic")',
            'set(CMAKE_TRY_COMPILE_TARGET_TYPE "STATIC_LIBRARY")',
            f'set(CMAKE_C_COMPILER "{self.compiler}" CACHE FILEPATH "" FORCE)',
            f'set(CMAKE_CXX_COMPILER "{self.compiler}" CACHE FILEPATH "" FORCE)',
            f'set(CMAKE_RC_COMPILER "{raw_tools["rc"]}" CACHE FILEPATH "" FORCE)',
            f'set(Python3_EXECUTABLE "{Path(sys.executable).resolve()}")',
            'set(CMAKE_C_COMPILER_FORCED TRUE CACHE BOOL "" FORCE)',
            'set(CMAKE_CXX_COMPILER_FORCED TRUE CACHE BOOL "" FORCE)',
            'set(CMAKE_C_COMPILER_ID "MSVC" CACHE STRING "" FORCE)',
            'set(CMAKE_CXX_COMPILER_ID "MSVC" CACHE STRING "" FORCE)',
            'set(CMAKE_C_COMPILER_ID_RUN TRUE CACHE BOOL "" FORCE)',
            'set(CMAKE_CXX_COMPILER_ID_RUN TRUE CACHE BOOL "" FORCE)',
            'set(CMAKE_C_COMPILER_VERSION "10.20" CACHE STRING "" FORCE)',
            'set(CMAKE_CXX_COMPILER_VERSION "10.20" CACHE STRING "" FORCE)',
            "project(zero_index_terminal_producers C CXX RC)",
            f'set(CMAKE_AR "{raw_tools["lib"]}")',
            f'set(CMAKE_LINKER "{raw_tools["link"]}")',
            'set(CMAKE_BUILD_TYPE "RelWithDebInfo")',
            'set(CMAKE_C_FLAGS "")',
            'set(CMAKE_CXX_FLAGS "")',
            'set(CMAKE_C_FLAGS_RELWITHDEBINFO "/Zi /O2 /D NDEBUG")',
            'set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "/Zi /O2 /D NDEBUG")',
            'set(CMAKE_EXE_LINKER_FLAGS "")',
            'set(CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO "/incremental:no")',
            'set(CMAKE_SHARED_LINKER_FLAGS "")',
            'set(CMAKE_SHARED_LINKER_FLAGS_RELWITHDEBINFO "/incremental:no")',
            'set(CMAKE_C_COMPILE_OBJECT "<CMAKE_C_COMPILER>  /nologo '
            '<DEFINES> <INCLUDES> <FLAGS> /Fo<OBJECT> /Fd<OBJECT>.pdb '
            '-c <SOURCE>")',
            'set(CMAKE_CXX_COMPILE_OBJECT "<CMAKE_CXX_COMPILER>  /nologo /TP '
            '<DEFINES> <INCLUDES> <FLAGS> /Fo<OBJECT> /Fd<OBJECT>.pdb '
            '-c <SOURCE>")',
            'set(CMAKE_RC_COMPILE_OBJECT "<CMAKE_RC_COMPILER> <DEFINES> '
            '<INCLUDES> <FLAGS> /fo <OBJECT> <SOURCE>")',
            'set(CMAKE_CXX_CREATE_STATIC_LIBRARY "<CMAKE_AR> /nologo '
            '/out:<TARGET> <OBJECTS>")',
            'set(CMAKE_CXX_LINK_EXECUTABLE "<CMAKE_LINKER> /nologo '
            '<LINK_FLAGS> <OBJECTS> /out:<TARGET> <LINK_LIBRARIES>")',
            *(
                f"add_library({target} STATIC src/shared.cpp)"
                for target in static_targets
            ),
            "add_executable(lego1 src/lego1.cpp resources/lego1.rc)",
            "add_library(Vendor::Archive STATIC IMPORTED)",
            f'set_property(TARGET Vendor::Archive PROPERTY IMPORTED_LOCATION "{vendor}")',
            "set(ISLE_BYTE_IDENTICAL ON)",
            "set(ISLE_PER_OBJECT_PDB ON)",
            "set(ISLE_INCLUDE_ENTROPY OFF)",
            'set(ISLE_TU_ENTROPY_MANIFEST "")',
            "set(MSVC_FOR_DECOMP TRUE)",
            'include("${PROJECT_SOURCE_DIR}/cmake/byte_identity.cmake")',
            f'isle_enable_byte_identity("{tools / "byte_identity_manifest.json"}")',
            "",
        ]
        (source / "CMakeLists.txt").write_text("\n".join(cmake_lines))
        configure_environment = dict(os.environ)
        configure_environment["ISLE_BYTE_IDENTITY_CONTROLLER_ROOT"] = str(
            controller_root
        )
        configured = subprocess.run(
            [
                "cmake", "-S", str(source), "-B", str(build),
                "-G", "Unix Makefiles",
            ],
            capture_output=True,
            text=True,
            env=configure_environment,
        )
        self.assertEqual(
            configured.returncode, 0, configured.stdout + configured.stderr
        )
        self.assertFalse(producer_marker.exists())

        plan = (build / "byte-identity/plan.cmake").read_text()
        self.assertIn(
            'list(APPEND ISLE_BYTE_IDENTITY_IMAGE_INDICES "0")', plan
        )
        self.assertIn(
            'list(APPEND ISLE_BYTE_IDENTITY_IMPORTED_TARGET_INDICES "0")',
            plan,
        )
        resource_make = (build / "CMakeFiles/lego1.dir/build.make").read_text()
        resource_lines = [
            line for line in resource_make.splitlines()
            if str(raw_tools["rc"]) in line
        ]
        self.assertEqual(len(resource_lines), 1, resource_lines)
        self.assertIn("compile-dispatch", resource_lines[0])
        self.assertLess(
            resource_lines[0].index("compile-dispatch"),
            resource_lines[0].index(str(raw_tools["rc"])),
        )

        raw_database = json.loads((build / "compile_commands.json").read_text())
        lego1_database = [
            item for item in raw_database
            if Path(item["file"]).resolve() == (src / "lego1.cpp").resolve()
        ]
        self.assertEqual(len(lego1_database), 1)
        raw_tokens = byte_identity._command_database_tokens(
            lego1_database[0]["command"], "zero-index raw compile database"
        )
        self.assertEqual(Path(raw_tokens[0]).resolve(), self.compiler.resolve())
        self.assertNotIn("compile-dispatch", raw_tokens)
        self.assertNotIn("compile-launch", raw_tokens)
        inventory_entry = {
            "target": "lego1", "source": "src/lego1.cpp",
            "source_path": str((src / "lego1.cpp").resolve()),
            "language": "CXX", "target_ordinal": 0,
        }
        resource_input = {
            "target": "lego1", "source": "resources/lego1.rc",
            "source_path": str((resources / "lego1.rc").resolve()),
            "source_sha256": byte_identity.sha256_file(
                resources / "lego1.rc"
            ),
            "kind": "RC", "emission": "resource_compiler_output",
            "target_ordinal": 1,
            "audit": str(build / "byte-identity/audit/resources/lego1/test.json"),
        }
        self.assertNotIn("output", resource_input)
        configure_inventory = {
            "entries": [inventory_entry], "inputs": [resource_input],
        }
        command_state = {
            "compiler_path": str(self.compiler.resolve()),
            "source_dir": str(source.resolve()),
            "build_dir": str(build.resolve()),
            "python_executable": str(Path(sys.executable).resolve()),
            "manifest_path": str(tools / "byte_identity_manifest.json"),
            "sealed_include_trees": [],
        }
        session = {
            "python": str(Path(sys.executable).resolve()),
            "framework": str(controller.resolve()),
            "controller_root": str(controller_root.resolve()),
            "source_root": str(source.resolve()),
            "build_root": str(build.resolve()),
        }
        flags_data = (build / "CMakeFiles/lego1.dir/flags.make").read_bytes()
        make_data = (build / "CMakeFiles/lego1.dir/build.make").read_bytes()
        with byte_identity.build_transaction(build, exclusive=True):
            normalized = byte_identity.normalized_command_inventory_entries(
                command_state, configure_inventory, build, lego1_database
            )
            self.assertEqual(len(normalized), 1)
            self.assertEqual(normalized[0]["launcher_prefix"], [])
            parsed_resources, dispatches = (
                byte_identity._resident_rc_target_recipes(
                    session=session, compiler=str(self.compiler.resolve()),
                    target="lego1", resource_inputs=[resource_input],
                    compile_entries=normalized, flags_data=flags_data,
                    make_data=make_data,
                )
            )
            self.assertEqual(len(parsed_resources), 1)
            self.assertEqual(len(dispatches), 1)
            derived_resource_output = Path(parsed_resources[0]["output"])
            self.assertTrue(derived_resource_output.is_relative_to(build))
            self.assertEqual(derived_resource_output.suffix, ".res")

            make_lines = make_data.decode().splitlines()
            cxx_index = next(
                index for index, line in enumerate(make_lines)
                if line.startswith("\t")
                and str((src / "lego1.cpp").resolve()) in line
            )
            rc_index = next(
                index for index, line in enumerate(make_lines)
                if line.startswith("\t")
                and str((resources / "lego1.rc").resolve()) in line
            )

            def rejected(lines):
                with self.assertRaisesRegex(
                    byte_identity.ByteIdentityError,
                    "resident (RC|C/C[+][+]) .*recipe",
                ):
                    byte_identity._resident_rc_target_recipes(
                        session=session,
                        compiler=str(self.compiler.resolve()),
                        target="lego1", resource_inputs=[resource_input],
                        compile_entries=normalized, flags_data=flags_data,
                        make_data=("\n".join(lines) + "\n").encode(),
                    )

            missing_dispatch = list(make_lines)
            missing_dispatch[cxx_index] = (
                "\t" + missing_dispatch[cxx_index].split(" -- ", 1)[1]
            )
            rejected(missing_dispatch)

            wrong_dispatch = list(make_lines)
            wrong_dispatch[cxx_index] = wrong_dispatch[cxx_index].replace(
                "--target 'lego1'", "--target 'wrong'", 1
            )
            self.assertNotEqual(
                wrong_dispatch[cxx_index], make_lines[cxx_index]
            )
            rejected(wrong_dispatch)

            raw_rc = list(make_lines)
            raw_rc[rc_index] = "\t" + raw_rc[rc_index].split(" -- ", 1)[1]
            rejected(raw_rc)

        with mock.patch.object(byte_identity, "run_child") as run_child:
            self.assertEqual(byte_identity.main([
                "compile-dispatch",
                "--manifest", str(tools / "byte_identity_manifest.json"),
                "--source-dir", str(source),
                "--build-dir", str(build),
                "--target", "lego1",
                "--configured-compiler", str(self.compiler.resolve()),
                "--", *raw_tokens,
            ]), 2)
            run_child.assert_not_called()

        archive_launch_count = 0
        for target in static_targets:
            link_text = (build / f"CMakeFiles/{target}.dir/link.txt").read_text()
            self.assertIn("archive-launch", link_text)
            self.assertIn(str(raw_tools["lib"]), link_text)
            self.assertLess(
                link_text.index("archive-launch"),
                link_text.index(str(raw_tools["lib"])),
            )
            archive_launch_count += link_text.count("archive-launch")
        self.assertEqual(archive_launch_count, 11)

        lego1_link = (build / "CMakeFiles/lego1.dir/link.txt").read_text()
        self.assertIn("link-launch", lego1_link)
        self.assertIn(str(raw_tools["link"]), lego1_link)
        self.assertLess(
            lego1_link.index("link-launch"),
            lego1_link.index(str(raw_tools["link"])),
        )
        self.assertIn("/MAP:", lego1_link)
        self.assertIn("/VERBOSE:LIB", lego1_link)
        self.assertNotIn("/debug", lego1_link.lower())
        self.assertTrue((build / "CMakeFiles/byte-identity-reccmp.dir").is_dir())
        self.assertTrue((build / "CMakeFiles/byte-identity-complete.dir").is_dir())

    def test_cmake_rejects_unregistered_cxx_target(self):
        extra = self.source.with_name("extra.cpp")
        extra.write_text("int extra() { return 23; }\n")
        self.assert_cmake_configure_rejected(
            build_name="cmake-unregistered-target",
            extra_targets=("add_library(extra STATIC src/extra.cpp)",),
            expected="target registry differs",
        )

    def test_cmake_rejects_global_rule_launch_compile(self):
        self.assert_cmake_configure_rejected(
            build_name="cmake-global-rule-hook",
            before_enable=(
                'set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "forbidden")',
            ),
            expected="Global/directory RULE_LAUNCH_COMPILE",
        )

    def test_cmake_rejects_target_rule_launch_compile(self):
        self.assert_cmake_configure_rejected(
            build_name="cmake-target-rule-hook",
            before_enable=(
                'set_property(TARGET fixture PROPERTY RULE_LAUNCH_COMPILE "forbidden")',
            ),
            expected="Target RULE_LAUNCH_COMPILE",
        )

    def test_cmake_rejects_source_rule_launch_compile(self):
        self.assert_cmake_configure_rejected(
            build_name="cmake-source-rule-hook",
            before_enable=(
                'set_property(SOURCE "${PROJECT_SOURCE_DIR}/src/unit.cpp" '
                'PROPERTY RULE_LAUNCH_COMPILE "forbidden")',
            ),
            expected="Source RULE_LAUNCH_COMPILE",
        )

    def test_cmake_finalizer_rejects_late_targets_and_launch_hooks(self):
        late = self.source.with_name("late.cpp")
        late.write_text("int late_target() { return 61; }\n")
        cases = {
            "same-directory-target": (
                'add_library(late STATIC src/late.cpp)',
                "target registry differs",
            ),
            "global-rule": (
                'set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "forbidden")',
                "Global/directory RULE_LAUNCH_COMPILE",
            ),
            "directory-rule": (
                'set_property(DIRECTORY PROPERTY RULE_LAUNCH_COMPILE "forbidden")',
                "Directory RULE_LAUNCH_COMPILE",
            ),
            "target-rule": (
                'set_property(TARGET fixture PROPERTY RULE_LAUNCH_COMPILE "forbidden")',
                "Target RULE_LAUNCH_COMPILE",
            ),
            "source-rule": (
                'set_property(SOURCE "${PROJECT_SOURCE_DIR}/src/unit.cpp" '
                'PROPERTY RULE_LAUNCH_COMPILE "forbidden")',
                "Source RULE_LAUNCH_COMPILE",
            ),
            "launcher-variable": (
                'set(CMAKE_CXX_COMPILER_LAUNCHER "forbidden")',
                "CMAKE_CXX_COMPILER_LAUNCHER changed",
            ),
        }
        for label, (mutation, expected) in cases.items():
            with self.subTest(label=label):
                self.assert_cmake_configure_rejected(
                    build_name=f"cmake-late-{label}",
                    after_enable=(mutation,),
                    expected=expected,
                )

    def test_cmake_tail_sentinel_observes_later_deferred_mutations(self):
        late = self.source.with_name("deferred-late.cpp")
        late.write_text("int deferred_late() { return 67; }\n")
        cases = {
            "target": (
                "function(_late_mutation)",
                "  add_library(deferred_late STATIC src/deferred-late.cpp)",
                "endfunction()",
                "cmake_language(DEFER CALL _late_mutation)",
            ),
            "hook": (
                "function(_late_mutation)",
                '  set_property(TARGET fixture PROPERTY RULE_LAUNCH_COMPILE "forbidden")',
                "endfunction()",
                "cmake_language(DEFER CALL _late_mutation)",
            ),
        }
        for label, mutation in cases.items():
            with self.subTest(label=label):
                _, result = self.configure_fixture(
                    ["src/unit.cpp"], f"cmake-deferred-{label}",
                    after_enable=mutation,
                )
                output = result.stdout + result.stderr
                self.assertNotEqual(result.returncode, 0, output)
                self.assertIn(
                    "target registry differs" if label == "target"
                    else "Target RULE_LAUNCH_COMPILE",
                    output,
                )

    def test_late_configure_failure_invalidates_stale_verdict_after_direct_refusal(self):
        cmake_build, configured = self.configure_fixture(
            ["src/unit.cpp"], "cmake-late-stale-verdict"
        )
        self.assertEqual(
            configured.returncode, 0, configured.stdout + configured.stderr
        )
        built = subprocess.run(
            ["cmake", "--build", str(cmake_build)],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(built.returncode, 0, built.stdout + built.stderr)
        self.assertIn(
            "supported live outer build session", built.stdout + built.stderr
        )
        verdict = cmake_build / "byte-identity/audit/framework-verdict.json"
        # Direct CMake cannot construct authoritative producer evidence.  Only
        # the resident outer driver may execute the closed plan and publish.
        self.assertFalse(verdict.exists())
        verdict.parent.mkdir(parents=True, exist_ok=True)
        verdict.write_text('{"stale":true}\n')

        late = self.source.with_name("stale-verdict-late.cpp")
        late.write_text("int stale_verdict_late() { return 71; }\n")
        second_build, rejected = self.configure_fixture(
            ["src/unit.cpp"], "cmake-late-stale-verdict",
            after_enable=(
                "add_library(stale_verdict_late STATIC src/stale-verdict-late.cpp)",
            ),
        )
        self.assertEqual(second_build, cmake_build)
        output = rejected.stdout + rejected.stderr
        self.assertNotEqual(rejected.returncode, 0, output)
        self.assertIn("target registry differs", output)
        self.assertFalse(verdict.exists())

    def test_cmake_disables_direct_preprocess_and_assembly_convenience_targets(self):
        cmake_build, result = self.configure_fixture(
            ["src/unit.cpp"], "cmake-no-convenience-rules"
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        started = self.directory / "cmake-convenience.started"
        with self.fake_control(STARTED=str(started)):
            for target in ("unit.i", "unit.s", "src/unit.i", "src/unit.s"):
                with self.subTest(target=target):
                    build = subprocess.run(
                        [
                            "cmake", "--build", str(cmake_build),
                            "--target", target,
                        ],
                        capture_output=True,
                        text=True,
                    )
                    self.assertNotEqual(
                        build.returncode, 0, build.stdout + build.stderr
                    )
        self.assertFalse(started.exists())

    def test_cmake_inventory_covers_every_tu_and_direct_build_refuses(self):
        extra = self.source.with_name("cmake-unlisted.cpp")
        extra.write_text("int cmake_unlisted() { return 41; }\n")
        count = self.directory / "cmake-policy-count.txt"
        call_log = self.directory / "cmake-policy-calls.jsonl"
        with self.fake_control(COUNT_FILE=str(count), CALL_LOG=str(call_log)):
            cmake_build, result = self.configure_fixture(
                ["src/unit.cpp", "src/cmake-unlisted.cpp"],
                "cmake-inventory-policy-rebuild",
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            first = subprocess.run(
                ["cmake", "--build", str(cmake_build), "--target", "fixture"],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(first.returncode, 0, first.stdout + first.stderr)
            self.assertIn(
                "supported live outer build session",
                first.stdout + first.stderr,
            )
            self.assertFalse(count.exists())
            self.assertFalse(call_log.exists())

            verified = subprocess.run(
                [
                    "cmake", "--build", str(cmake_build),
                    "--target", "byte-identity-verify",
                ],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(
                verified.returncode, 0, verified.stdout + verified.stderr
            )
            self.assertFalse(count.exists())
            self.assertFalse(call_log.exists())

        inventory_path = byte_identity.inventory_path(cmake_build)
        inventory = json.loads(inventory_path.read_text())
        self.assertEqual(
            [(entry["target"], entry["source"], entry["listed"])
             for entry in inventory["entries"]],
            [
                ("fixture", "src/unit.cpp", True),
                ("fixture", "src/cmake-unlisted.cpp", False),
            ],
        )
        self.assertTrue(all(
            entry["output_role"] == "cmake_compiler_object_from_Fo"
            for entry in inventory["entries"]
        ))
        expected_audits = {
            Path(entry["audit"]).resolve() for entry in inventory["entries"]
        }
        actual_audits = set()
        for root in (
            cmake_build / "byte-identity/audit/objects",
            cmake_build / "byte-identity/audit/unlisted-pass-through",
        ):
            actual_audits.update(
                path.resolve() for path in root.rglob("*.json")
            )
        self.assertTrue(expected_audits)
        self.assertEqual(actual_audits, set())
        # Generated inventory is plan input only.  A direct CMake build cannot
        # execute the resident producer DAG or publish terminal authority.
        self.assertFalse(
            (cmake_build / "byte-identity/audit/framework-verdict.json").exists()
        )

    def test_cmake_materializes_two_recipes_for_one_tu_without_compiling(self):
        self.enable_composer_fixture()
        second_id, _ = self.add_distinct_shape_recipe()
        cmake_build = self.configure_and_materialize(
            ["src/unit.cpp"], "cmake-build-two-recipes"
        )
        generated = list(
            (cmake_build / "byte-identity/generated").glob("declaration_*.h")
        )
        self.assertEqual(len(generated), 2)
        self.assertEqual(
            {
                path.name for path in (
                    cmake_build / "byte-identity/audit/materialization"
                ).glob("*.json")
            },
            {f"{self.recipe_id}.json", f"{second_id}.json"},
        )

    def test_cmake_materializes_shared_and_unique_recipes_once_without_compiling(self):
        self.enable_composer_fixture()
        shared_source = self.add_shared_recipe_unit()
        second_id, _ = self.add_distinct_shape_recipe(unit_index=1)
        cmake_build = self.configure_and_materialize(
            ["src/unit.cpp", "src/shared.cpp"],
            "cmake-build-shared-and-unique",
        )
        generated = list(
            (cmake_build / "byte-identity/generated").glob("declaration_*.h")
        )
        self.assertEqual(len(generated), 2)
        shared_audit = json.loads(
            (
                cmake_build
                / f"byte-identity/audit/materialization/{self.recipe_id}.json"
            ).read_text()
        )
        unique_audit = json.loads(
            (
                cmake_build
                / f"byte-identity/audit/materialization/{second_id}.json"
            ).read_text()
        )
        self.assertEqual(len(shared_audit["users"]), 2)
        self.assertEqual(shared_audit["users"][1]["source"],
                         shared_source.relative_to(self.source_dir).as_posix())
        self.assertEqual(len(unique_audit["users"]), 1)
        self.assertEqual(unique_audit["users"][0]["source"],
                         shared_source.relative_to(self.source_dir).as_posix())

    def test_listed_private_outputs_remain_held_through_publication(self):
        self.materialize()
        output = self.build_dir / "objects/post-hold-listed.obj"
        pdb = self.build_dir / "objects/post-hold-listed.pdb"
        output.parent.mkdir(parents=True)
        arguments = self.launch_args(output, pdb)
        source_id = hashlib.sha256(b"src/unit.cpp").hexdigest()[:16]
        private = self.build_dir / "byte-identity/work/fixture" / source_id / "seed"
        detached = private.with_name("seed-post-hold-detached")
        real_atomic_write = byte_identity.atomic_write
        swapped = False

        def swapping_atomic_write(path, data, **kwargs):
            nonlocal swapped
            result = real_atomic_write(path, data, **kwargs)
            if not swapped and Path(path) == private / "output.pdb":
                private.rename(detached)
                private.mkdir()
                for name in ("output.obj", "output.pdb"):
                    (private / name).write_bytes(
                        (detached / name).read_bytes() + b"POST-HOLD-SUBSTITUTION"
                    )
                swapped = True
            return result

        previous = Path.cwd()
        byte_identity.atomic_write = swapping_atomic_write
        try:
            with self.standalone_producer_diagnostic():
                os.chdir(self.build_dir)
                result = byte_identity.main(arguments)
        finally:
            os.chdir(previous)
            byte_identity.atomic_write = real_atomic_write
        self.assertEqual(result, 2)
        self.assertTrue(swapped)
        self.assertFalse(output.exists())
        self.assertFalse(pdb.exists())
        self.assertFalse(
            byte_identity.audit_object_path(
                self.build_dir, "fixture", "src/unit.cpp"
            ).exists()
        )
        self.assertFalse(
            (self.build_dir / "byte-identity/audit/framework-verdict.json").exists()
        )

    def test_unlisted_private_outputs_remain_held_through_publication(self):
        self.materialize()
        other = self.source.with_name("post-hold-unlisted.cpp")
        other.write_text("int post_hold_unlisted() { return 41; }\n")
        output = self.build_dir / "objects/post-hold-unlisted.obj"
        pdb = self.build_dir / "objects/post-hold-unlisted.pdb"
        output.parent.mkdir(parents=True)
        arguments = self.launch_args(output, pdb, source=other)
        source_relative = other.relative_to(self.source_dir).as_posix()
        source_id = hashlib.sha256(source_relative.encode()).hexdigest()[:16]
        private = (
            self.build_dir / "byte-identity/work/unlisted-pass-through/fixture"
            / source_id / "seed"
        )
        detached = private.with_name("seed-post-hold-detached")
        real_atomic_write = byte_identity.atomic_write
        swapped = False

        def swapping_atomic_write(path, data, **kwargs):
            nonlocal swapped
            result = real_atomic_write(path, data, **kwargs)
            if not swapped and Path(path) == private / "output.pdb":
                private.rename(detached)
                private.mkdir()
                for name in ("output.obj", "output.pdb"):
                    (private / name).write_bytes(
                        (detached / name).read_bytes() + b"POST-HOLD-SUBSTITUTION"
                    )
                swapped = True
            return result

        previous = Path.cwd()
        byte_identity.atomic_write = swapping_atomic_write
        try:
            with self.standalone_producer_diagnostic():
                os.chdir(self.build_dir)
                result = byte_identity.main(arguments)
        finally:
            os.chdir(previous)
            byte_identity.atomic_write = real_atomic_write
        self.assertEqual(result, 2)
        self.assertTrue(swapped)
        self.assertFalse(output.exists())
        self.assertFalse(pdb.exists())
        self.assertFalse(
            byte_identity.audit_unlisted_path(
                self.build_dir, "fixture", source_relative
            ).exists()
        )

    def test_verify_pins_exact_namespace_membership_before_and_after_verdict(self):
        self.materialize()
        output = self.build_dir / "objects/membership.obj"
        pdb = self.build_dir / "objects/membership.pdb"
        output.parent.mkdir(parents=True)
        previous = Path.cwd()
        try:
            os.chdir(self.build_dir)
            self.assertEqual(
                self.run_standalone_producer_diagnostic(
                    self.launch_args(output, pdb)
                ),
                0,
            )
        finally:
            os.chdir(previous)

        compiler_directory = byte_identity.audit_object_path(
            self.build_dir, "fixture", "src/unit.cpp"
        ).parent
        attacks = [
            (compiler_directory / "late.json", False),
            (compiler_directory / "late-empty-directory", True),
            (self.build_dir / "byte-identity/runtime-bin/late-runtime", False),
            (
                self.build_dir
                / "byte-identity/audit/materialization/late-materialization.json",
                False,
            ),
            (self.build_dir / "byte-identity/audit/late-top-level", False),
        ]
        real_revalidate = byte_identity.BuildRootAuthority.revalidate_epoch
        for injected, is_directory in attacks:
            with self.subTest(injected=injected.name):
                called = False

                def injecting_revalidate(authority):
                    nonlocal called
                    if not called:
                        if is_directory:
                            injected.mkdir()
                        else:
                            injected.write_bytes(b"{}\n")
                        called = True
                    return real_revalidate(authority)

                byte_identity.BuildRootAuthority.revalidate_epoch = injecting_revalidate
                try:
                    result = self.run_resident_verifier_diagnostic()
                finally:
                    byte_identity.BuildRootAuthority.revalidate_epoch = real_revalidate
                self.assertEqual(result, 2)
                self.assertTrue(called)
                self.assertFalse(
                    (self.build_dir / "byte-identity/audit/framework-verdict.json").exists()
                )
                if is_directory:
                    injected.rmdir()
                else:
                    injected.unlink()

        unknown = compiler_directory / "undeclared.bin"
        unknown.write_bytes(b"UNDECLARED")
        self.assertEqual(self.run_resident_verifier_diagnostic(), 2)
        self.assertFalse(
            (self.build_dir / "byte-identity/audit/framework-verdict.json").exists()
        )
        unknown.unlink()
        self.assertEqual(self.run_resident_verifier_diagnostic(), 0)

    def test_verify_revalidates_all_external_inputs_and_required_absence(self):
        absent = self.directory / "must-stay-absent.dll"
        self.document["toolchain"]["required_absent_toolchain_files"] = [
            absent.name
        ]
        self.write_manifest()
        self.materialize()
        output = self.build_dir / "objects/external-epoch.obj"
        pdb = self.build_dir / "objects/external-epoch.pdb"
        output.parent.mkdir(parents=True)
        previous = Path.cwd()
        try:
            os.chdir(self.build_dir)
            self.assertEqual(
                self.run_standalone_producer_diagnostic(
                    self.launch_args(output, pdb)
                ),
                0,
            )
        finally:
            os.chdir(previous)

        expected_external = {
            self.manifest.resolve(), self.source.resolve(), self.include.resolve(),
            self.compiler.resolve(), self.compiler_support.resolve(),
            Path(sys.executable).resolve(), self.cmake_module.resolve(),
            Path(byte_identity.__file__).resolve(), Path(entropy.__file__).resolve(),
            *(Path(shutil.which(name)).resolve() for name in (
                "python3", "bash", "dirname", "sed", "grep",
                "wine", "winepath", "wineserver",
            )),
        }
        original_source = self.source.read_bytes()
        real_revalidate = byte_identity.BuildRootAuthority.revalidate_epoch
        observed = False

        def mutating_revalidate(authority):
            nonlocal observed
            if not observed:
                pinned = {
                    Path(value["canonical"])
                    for value in authority.external_file_pins.values()
                }
                self.assertTrue(expected_external <= pinned)
                self.assertIn(
                    str(absent.resolve(strict=False)),
                    authority.external_absence_pins,
                )
                self.source.write_bytes(original_source + b"// late mutation\n")
                absent.write_bytes(b"LATE-APPEARANCE")
                observed = True
            return real_revalidate(authority)

        byte_identity.BuildRootAuthority.revalidate_epoch = mutating_revalidate
        try:
            result = self.run_resident_verifier_diagnostic()
        finally:
            byte_identity.BuildRootAuthority.revalidate_epoch = real_revalidate
            self.source.write_bytes(original_source)
            absent.unlink(missing_ok=True)
        self.assertEqual(result, 2)
        self.assertTrue(observed)
        self.assertFalse(
            (self.build_dir / "byte-identity/audit/framework-verdict.json").exists()
        )

    def test_component_pass_overrides_are_rejected_before_compiler_start(self):
        self.materialize()
        count = self.directory / "override-compiler-count.txt"
        cases = [
            ["/B1untrusted-c1"], ["-b2:untrusted-c2"], ["/BXuntrusted-pass"],
            ["/B1_5", "untrusted-c1xx"],
        ]
        with self.fake_control(COUNT_FILE=str(count)):
            for index, override in enumerate(cases):
                with self.subTest(override=override):
                    output = self.build_dir / f"objects/override-{index}.obj"
                    pdb = self.build_dir / f"objects/override-{index}.pdb"
                    output.parent.mkdir(parents=True, exist_ok=True)
                    arguments = self.launch_args(output, pdb)
                    arguments[-1:-1] = override
                    previous = Path.cwd()
                    try:
                        with self.standalone_producer_diagnostic():
                            os.chdir(self.build_dir)
                            result = byte_identity.main(arguments)
                    finally:
                        os.chdir(previous)
                    self.assertEqual(result, 2)
                    self.assertFalse(output.exists())
                    self.assertFalse(pdb.exists())
        self.assertFalse(count.exists())

    def test_source_and_build_roots_must_be_disjoint_before_state_mutation(self):
        nested_build = self.source_dir / "nested-build"
        nested_build.mkdir()
        nested_args = self.plan_args()
        nested_args[nested_args.index(str(self.build_dir))] = str(nested_build)
        nested_args[nested_args.index(str(self.plan))] = str(
            nested_build / "byte-identity/plan.cmake"
        )
        self.assertEqual(byte_identity.main(nested_args), 2)
        self.assertFalse((nested_build / "byte-identity").exists())

        enclosing_build = self.directory
        enclosing_args = self.plan_args()
        enclosing_args[enclosing_args.index(str(self.build_dir))] = str(enclosing_build)
        enclosing_args[enclosing_args.index(str(self.plan))] = str(
            enclosing_build / "byte-identity/plan.cmake"
        )
        self.assertEqual(byte_identity.main(enclosing_args), 2)
        self.assertFalse((enclosing_build / "byte-identity").exists())

        _, configured = self.configure_fixture(
            ["src/unit.cpp"], "cmake-disjoint-fixture"
        )
        self.assertEqual(
            configured.returncode, 0, configured.stdout + configured.stderr
        )
        cmake_nested = self.source_dir / "cmake-nested-build"
        nested_result = subprocess.run(
            [
                "cmake", "-S", str(self.source_dir), "-B", str(cmake_nested),
                "-G", "Ninja" if shutil.which("ninja") else "Unix Makefiles",
            ],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(nested_result.returncode, 0)
        self.assertIn(
            "must be disjoint",
            nested_result.stdout + nested_result.stderr,
        )

        enclosing_cmake = self.directory / "cmake-enclosing-build"
        enclosing_cmake.mkdir()
        enclosed_source = enclosing_cmake / "source"
        shutil.copytree(self.source_dir, enclosed_source)
        enclosing_result = subprocess.run(
            [
                "cmake", "-S", str(enclosed_source), "-B", str(enclosing_cmake),
                "-G", "Ninja" if shutil.which("ninja") else "Unix Makefiles",
            ],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(enclosing_result.returncode, 0)
        self.assertIn(
            "must be disjoint",
            enclosing_result.stdout + enclosing_result.stderr,
        )

    def test_verify_rejects_unknown_or_missing_fields_in_every_audit_schema(self):
        self.materialize()
        listed_object = self.build_dir / "objects/schema-listed.obj"
        listed_pdb = self.build_dir / "objects/schema-listed.pdb"
        listed_object.parent.mkdir(parents=True)
        other = self.source.with_name("schema-unlisted.cpp")
        other.write_text("int schema_unlisted() { return 43; }\n")
        unlisted_object = self.build_dir / "objects/schema-unlisted.obj"
        unlisted_pdb = self.build_dir / "objects/schema-unlisted.pdb"
        unlisted_arguments = self.launch_args(
            unlisted_object, unlisted_pdb, source=other
        )
        previous = Path.cwd()
        try:
            os.chdir(self.build_dir)
            self.assertEqual(
                self.run_standalone_producer_diagnostic(
                    self.launch_args(listed_object, listed_pdb)
                ),
                0,
            )
            self.assertEqual(
                self.run_standalone_producer_diagnostic(unlisted_arguments), 0
            )
        finally:
            os.chdir(previous)
        audit_cases = [
            (
                self.build_dir
                / f"byte-identity/audit/materialization/{self.recipe_id}.json",
                "emission_policy",
            ),
            (
                byte_identity.audit_object_path(
                    self.build_dir, "fixture", "src/unit.cpp"
                ),
                "input_command_sha256",
            ),
            (
                byte_identity.audit_unlisted_path(
                    self.build_dir, "fixture", "src/schema-unlisted.cpp"
                ),
                "input_command_sha256",
            ),
        ]
        for audit_path, missing_key in audit_cases:
            original = audit_path.read_bytes()
            for mutation in ("unknown", "missing"):
                with self.subTest(
                    audit=audit_path.parent.name, mutation=mutation
                ):
                    audit = json.loads(original)
                    if mutation == "unknown":
                        audit["unexpected_payload_claim"] = "forbidden"
                    else:
                        audit.pop(missing_key)
                    audit_path.write_text(json.dumps(audit) + "\n")
                    self.assertEqual(self.run_resident_verifier_diagnostic(), 2)
                    self.assertFalse(
                        (
                            self.build_dir
                            / "byte-identity/audit/framework-verdict.json"
                        ).exists()
                    )
                    audit_path.write_bytes(original)

    def test_verify_rejects_unknown_donor_and_nested_composition_fields(self):
        self.enable_composer_fixture()
        self.materialize()
        output = self.build_dir / "objects/schema-composed.obj"
        pdb = self.build_dir / "objects/schema-composed.pdb"
        output.parent.mkdir(parents=True)
        previous = Path.cwd()
        with self.fake_control(
            SEED_OBJ=str(self.seed_fixture), DONOR_OBJ=str(self.donor_fixture)
        ):
            try:
                os.chdir(self.build_dir)
                self.assertEqual(
                    self.run_standalone_producer_diagnostic(
                        self.launch_args(output, pdb)
                    ),
                    0,
                )
            finally:
                os.chdir(previous)
        audit_path = byte_identity.audit_object_path(
            self.build_dir, "fixture", "src/unit.cpp"
        )
        original = audit_path.read_bytes()
        mutations = [
            lambda audit: audit["donors"][0].__setitem__("unknown", True),
            lambda audit: audit["donors"][0].pop("executed_command_sha256"),
            lambda audit: audit["composition"][0]["retail_oracle"].__setitem__(
                "unknown", True
            ),
            lambda audit: audit["composition"][0]["retail_oracle"].pop(
                "verdict"
            ),
            lambda audit: audit["composition"][0]["provenance"].__setitem__(
                "unknown", True
            ),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                audit = json.loads(original)
                mutate(audit)
                audit_path.write_text(json.dumps(audit) + "\n")
                self.assertEqual(self.run_resident_verifier_diagnostic(), 2)
                self.assertFalse(
                    (self.build_dir / "byte-identity/audit/framework-verdict.json").exists()
                )
        audit_path.write_bytes(original)

    def test_cmake_requires_the_exact_attributable_compile_rule_templates(self):
        canonical_rules = {
            "CXX": (
                b"<CMAKE_CXX_COMPILER>  /nologo /TP <DEFINES> <INCLUDES> "
                b"<FLAGS> /Fo<OBJECT> /Fd<OBJECT>.pdb -c <SOURCE>"
            ),
            "C": (
                b"<CMAKE_C_COMPILER>  /nologo <DEFINES> <INCLUDES> <FLAGS> "
                b"/Fo<OBJECT> /Fd<OBJECT>.pdb -c <SOURCE>"
            ),
        }
        self.assertEqual(
            {
                language: (len(rule), hashlib.sha256(rule).hexdigest())
                for language, rule in canonical_rules.items()
            },
            {
                "CXX": (
                    102,
                    "cd7abe210ad8a1866e2d78d70f4c0a23309d824014106053fdf90406f77a173f",
                ),
                "C": (
                    96,
                    "2fdbd526f2d62e822033d663243522f0a7db4f25d4cbca650b4f5886f1418871",
                ),
            },
        )
        _, accepted = self.configure_fixture(
            ["src/unit.cpp"], "cmake-rule-exact-cmake-4-3-4"
        )
        self.assertEqual(
            accepted.returncode, 0, accepted.stdout + accepted.stderr
        )
        malformed_rules = (
            (
                "cxx-one-space",
                'set(CMAKE_CXX_COMPILE_OBJECT "<CMAKE_CXX_COMPILER> /nologo /TP '
                '<DEFINES> <INCLUDES> <FLAGS> /Fo<OBJECT> /Fd<OBJECT>.pdb '
                '-c <SOURCE>")',
            ),
            (
                "cxx-three-spaces",
                'set(CMAKE_CXX_COMPILE_OBJECT "<CMAKE_CXX_COMPILER>   /nologo /TP '
                '<DEFINES> <INCLUDES> <FLAGS> /Fo<OBJECT> /Fd<OBJECT>.pdb '
                '-c <SOURCE>")',
            ),
            (
                "cxx-tab",
                'set(CMAKE_CXX_COMPILE_OBJECT "<CMAKE_CXX_COMPILER>\t/nologo /TP '
                '<DEFINES> <INCLUDES> <FLAGS> /Fo<OBJECT> /Fd<OBJECT>.pdb '
                '-c <SOURCE>")',
            ),
            (
                "cxx-extra-command",
                'set(CMAKE_CXX_COMPILE_OBJECT "<CMAKE_CXX_COMPILER>  /nologo /TP '
                '<DEFINES> <INCLUDES> <FLAGS> /Fo<OBJECT> /Fd<OBJECT>.pdb '
                '-c <SOURCE>" "${CMAKE_COMMAND} -E true")',
            ),
            (
                "cxx-missing-tp",
                'set(CMAKE_CXX_COMPILE_OBJECT "<CMAKE_CXX_COMPILER>  /nologo '
                '<DEFINES> <INCLUDES> <FLAGS> /Fo<OBJECT> /Fd<OBJECT>.pdb '
                '-c <SOURCE>")',
            ),
            (
                "cxx-role-order",
                'set(CMAKE_CXX_COMPILE_OBJECT "<CMAKE_CXX_COMPILER>  /nologo /TP '
                '<INCLUDES> <DEFINES> <FLAGS> /Fo<OBJECT> /Fd<OBJECT>.pdb '
                '-c <SOURCE>")',
            ),
            (
                "cxx-separated-object",
                'set(CMAKE_CXX_COMPILE_OBJECT "<CMAKE_CXX_COMPILER>  /nologo /TP '
                '<DEFINES> <INCLUDES> <FLAGS> /Fo <OBJECT> /Fd<OBJECT>.pdb '
                '-c <SOURCE>")',
            ),
            (
                "cxx-source-not-final",
                'set(CMAKE_CXX_COMPILE_OBJECT "<CMAKE_CXX_COMPILER>  /nologo /TP '
                '<DEFINES> <INCLUDES> <FLAGS> <SOURCE> /Fo<OBJECT> '
                '/Fd<OBJECT>.pdb -c")',
            ),
            (
                "c-missing-compiler-role",
                'set(CMAKE_C_COMPILE_OBJECT "/nologo <DEFINES> <INCLUDES> '
                '<FLAGS> /Fo<OBJECT> /Fd<OBJECT>.pdb -c <SOURCE>")',
            ),
            (
                "c-one-space",
                'set(CMAKE_C_COMPILE_OBJECT "<CMAKE_C_COMPILER> /nologo '
                '<DEFINES> <INCLUDES> <FLAGS> /Fo<OBJECT> '
                '/Fd<OBJECT>.pdb -c <SOURCE>")',
            ),
            (
                "c-three-spaces",
                'set(CMAKE_C_COMPILE_OBJECT "<CMAKE_C_COMPILER>   /nologo '
                '<DEFINES> <INCLUDES> <FLAGS> /Fo<OBJECT> '
                '/Fd<OBJECT>.pdb -c <SOURCE>")',
            ),
            (
                "c-tab",
                'set(CMAKE_C_COMPILE_OBJECT "<CMAKE_C_COMPILER>\t/nologo '
                '<DEFINES> <INCLUDES> <FLAGS> /Fo<OBJECT> '
                '/Fd<OBJECT>.pdb -c <SOURCE>")',
            ),
        )
        for label, rule in malformed_rules:
            with self.subTest(label=label):
                self.assert_cmake_configure_rejected(
                    build_name=f"cmake-rule-{label}",
                    before_enable=(rule,),
                    expected="must be one canonical raw command element",
                )

    def test_cmake_reconfigure_and_direct_failure_cannot_publish_verdict(self):
        build_name = "cmake-default-failure-order"
        cmake_build, configured = self.configure_fixture(
            ["src/unit.cpp"], build_name
        )
        self.assertEqual(
            configured.returncode, 0, configured.stdout + configured.stderr
        )
        verdict = cmake_build / "byte-identity/audit/framework-verdict.json"
        self.assertFalse(verdict.exists())
        verdict.parent.mkdir(parents=True, exist_ok=True)
        verdict.write_text('{"stale":true}\n')

        cmake_build, reconfigured = self.configure_fixture(
            ["src/unit.cpp"],
            build_name,
            after_enable=(
                'add_custom_target(late_fail ALL '
                'COMMAND "${CMAKE_COMMAND}" -E sleep 0.8 '
                'COMMAND "${CMAKE_COMMAND}" -E false VERBATIM)',
            ),
        )
        self.assertEqual(
            reconfigured.returncode,
            0,
            reconfigured.stdout + reconfigured.stderr,
        )
        self.assertFalse(verdict.exists())
        failed = subprocess.run(
            ["cmake", "--build", str(cmake_build), "--parallel", "4"],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
        self.assertFalse(verdict.exists())

    def test_explicit_nondefault_target_invalidates_prior_verdict(self):
        cmake_build, configured = self.configure_fixture(
            ["src/unit.cpp"],
            "cmake-explicit-invalidation",
            after_enable=(
                'add_custom_target(explicit_fail '
                'COMMAND "${CMAKE_COMMAND}" -E false VERBATIM)',
            ),
        )
        self.assertEqual(
            configured.returncode, 0, configured.stdout + configured.stderr
        )
        verdict = cmake_build / "byte-identity/audit/framework-verdict.json"
        self.assertFalse(verdict.exists())
        verdict.parent.mkdir(parents=True, exist_ok=True)
        verdict.write_text('{"stale":true}\n')
        explicit = subprocess.run(
            [
                "cmake", "--build", str(cmake_build), "--target",
                "explicit_fail", "--parallel", "4",
            ],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(
            explicit.returncode, 0, explicit.stdout + explicit.stderr
        )
        self.assertFalse(verdict.exists())

    def test_cmake_recurses_subdirectories_but_direct_build_refuses(self):
        subdirectory = self.source_dir / "sub"
        subdirectory.mkdir()
        (subdirectory / "hidden.cpp").write_text(
            "int hidden_from_parent_directory() { return 47; }\n"
        )
        (subdirectory / "CMakeLists.txt").write_text(
            "add_library(hidden STATIC hidden.cpp)\n"
            "target_compile_options(hidden PRIVATE "
            "\"/FI${PROJECT_SOURCE_DIR}/include/pinned.h\")\n"
        )
        _, rejected = self.configure_fixture(
            ["src/unit.cpp"],
            "cmake-hidden-undeclared",
            before_enable=("add_subdirectory(sub)",),
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("target registry differs", rejected.stdout + rejected.stderr)

        self.document["target_policies"].append(
            {
                "target": "hidden",
                "allowed_force_includes": json.loads(
                    json.dumps(
                        self.document["target_policies"][0]["allowed_force_includes"]
                    )
                ),
            }
        )
        self.write_manifest()
        cmake_build, configured = self.configure_fixture(
            ["src/unit.cpp"],
            "cmake-hidden-declared",
            before_enable=("add_subdirectory(sub)",),
        )
        self.assertEqual(
            configured.returncode, 0, configured.stdout + configured.stderr
        )
        inventory = json.loads(
            (cmake_build / "byte-identity/inventory.json").read_text()
        )
        self.assertIn(
            ("hidden", "sub/hidden.cpp", "CXX"),
            {
                (entry["target"], entry["source"], entry["language"])
                for entry in inventory["entries"]
            },
        )
        built = subprocess.run(
            ["cmake", "--build", str(cmake_build)],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(built.returncode, 0, built.stdout + built.stderr)
        verdict = cmake_build / "byte-identity/audit/framework-verdict.json"
        self.assertFalse(verdict.exists())
        hidden_audit = byte_identity.audit_unlisted_path(
            cmake_build, "hidden", "sub/hidden.cpp"
        )
        self.assertFalse(hidden_audit.exists())

    def test_cmake_finalizer_inventories_late_nested_target(self):
        subdirectory = self.source_dir / "late-sub"
        subdirectory.mkdir()
        (subdirectory / "late.cpp").write_text(
            "int nested_late_target() { return 73; }\n"
        )
        (subdirectory / "CMakeLists.txt").write_text(
            "add_library(nested_late STATIC late.cpp)\n"
            "target_compile_options(nested_late PRIVATE "
            "\"/FI${PROJECT_SOURCE_DIR}/include/pinned.h\")\n"
        )
        self.document["target_policies"].append(
            {
                "target": "nested_late",
                "allowed_force_includes": json.loads(
                    json.dumps(
                        self.document["target_policies"][0][
                            "allowed_force_includes"
                        ]
                    )
                ),
            }
        )
        self.write_manifest()
        cmake_build, configured = self.configure_fixture(
            ["src/unit.cpp"], "cmake-late-nested",
            after_enable=("add_subdirectory(late-sub)",),
        )
        self.assertEqual(
            configured.returncode, 0, configured.stdout + configured.stderr
        )
        inventory = json.loads(
            (cmake_build / "byte-identity/inventory.json").read_text()
        )
        observed = {
            (entry["target"], entry["source"], entry["language"])
            for entry in inventory["entries"]
        }
        self.assertIn(("nested_late", "late-sub/late.cpp", "CXX"), observed)
        built = subprocess.run(
            ["cmake", "--build", str(cmake_build)],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(built.returncode, 0, built.stdout + built.stderr)
        self.assertFalse(
            (cmake_build / "byte-identity/audit/framework-verdict.json").exists()
        )
        self.assertFalse(
            byte_identity.audit_unlisted_path(
                cmake_build, "nested_late", "late-sub/late.cpp"
            ).exists()
        )

    def test_cmake_inventory_uses_all_advertised_c_cxx_extensions(self):
        source_names = ["src/unit.cpp"]
        expected = {"src/unit.cpp": "CXX"}
        for index, extension in enumerate(sorted(CMAKE_C_CXX_SOURCE_EXTENSIONS)):
            relative = f"src/advertised_{index}.{extension}"
            path = self.source_dir / relative
            path.write_text(f"int advertised_{index}() {{ return {index}; }}\n")
            source_names.append(relative)
            expected[relative] = "C" if extension in {"c", "m"} else "CXX"
        cmake_build, configured = self.configure_fixture(
            source_names,
            "cmake-advertised-extensions",
            extra_targets=(
                "set_property(TARGET fixture PROPERTY CXX_SCAN_FOR_MODULES OFF)",
            ),
        )
        self.assertEqual(
            configured.returncode, 0, configured.stdout + configured.stderr
        )
        inventory = json.loads(
            (cmake_build / "byte-identity/inventory.json").read_text()
        )
        observed = {
            entry["source"]: entry["language"] for entry in inventory["entries"]
        }
        self.assertEqual(observed, expected)

    def test_cmake_inventory_honors_arbitrary_extension_language_override(self):
        arbitrary = self.source.with_name("arbitrary.dat")
        arbitrary.write_text("int arbitrary_language() { return 79; }\n")
        cmake_build, configured = self.configure_fixture(
            ["src/unit.cpp", "src/arbitrary.dat"],
            "cmake-language-override",
            before_enable=(
                "set_source_files_properties(src/arbitrary.dat PROPERTIES LANGUAGE CXX)",
            ),
        )
        self.assertEqual(
            configured.returncode, 0, configured.stdout + configured.stderr
        )
        inventory = json.loads(
            (cmake_build / "byte-identity/inventory.json").read_text()
        )
        matches = [
            entry for entry in inventory["entries"]
            if entry["source"] == "src/arbitrary.dat"
        ]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["language"], "CXX")

    def test_cmake_rejects_unsupported_explicit_source_language(self):
        arbitrary = self.source.with_name("unsupported.dat")
        arbitrary.write_text("int unsupported_language() { return 83; }\n")
        _, configured = self.configure_fixture(
            ["src/unit.cpp", "src/unsupported.dat"],
            "cmake-unsupported-language",
            before_enable=(
                "set_source_files_properties(src/unsupported.dat PROPERTIES LANGUAGE CUDA)",
            ),
        )
        output = configured.stdout + configured.stderr
        self.assertNotEqual(configured.returncode, 0, output)
        self.assertIn("Unsupported effective source language CUDA", output)

    def test_cmake_rejects_every_opaque_object_archive_payload_route(self):
        opaque_object = self.source_dir / "src/opaque.obj"
        opaque_object.write_bytes(b"OPAQUE-OBJECT")
        _, source_result = self.configure_fixture(
            ["src/unit.cpp", "src/opaque.obj"], "cmake-opaque-source"
        )
        source_output = source_result.stdout + source_result.stderr
        self.assertNotEqual(source_result.returncode, 0, source_output)
        self.assertRegex(
            source_output, "EXTERNAL_OBJECT|Opaque object/archive/resource"
        )

        opaque_library = self.source_dir / "src/opaque.lib"
        opaque_library.write_bytes(b"!<arch>\nOPAQUE-LIBRARY")
        _, link_result = self.configure_fixture(
            ["src/unit.cpp"], "cmake-opaque-link",
            extra_targets=(
                f'target_link_libraries(fixture PRIVATE "{opaque_library}")',
            ),
        )
        link_output = link_result.stdout + link_result.stderr
        self.assertNotEqual(link_result.returncode, 0, link_output)
        self.assertIn("Opaque object/resource/archive link expression", link_output)

        generated = self.source_dir / "src/generated.cpp"
        generated.write_text("int forbidden_generated() { return 1; }\n")
        _, generated_result = self.configure_fixture(
            ["src/unit.cpp", "src/generated.cpp"], "cmake-generated-source",
            before_enable=(
                "set_source_files_properties(src/generated.cpp PROPERTIES GENERATED TRUE)",
            ),
        )
        generated_output = generated_result.stdout + generated_result.stderr
        self.assertNotEqual(generated_result.returncode, 0, generated_output)
        self.assertIn("Generated source/payload is forbidden", generated_output)

        injected = self.source_dir / "src/injected.cpp"
        injected.write_text("int injected_object() { return 2; }\n")
        _, expression_result = self.configure_fixture(
            ["src/unit.cpp"], "cmake-target-objects",
            extra_targets=(
                "add_library(injected OBJECT src/injected.cpp)",
                "target_sources(fixture PRIVATE $<TARGET_OBJECTS:injected>)",
            ),
        )
        expression_output = expression_result.stdout + expression_result.stderr
        self.assertNotEqual(expression_result.returncode, 0, expression_output)
        self.assertRegex(
            expression_output, "OBJECT_LIBRARY|Generator-expression source"
        )

    def test_cmake_evaluates_captured_plan_and_inventory_fragments(self):
        cmake_text = (ROOT / "cmake/byte_identity.cmake").read_text()
        self.assertNotIn('include("${_plan}")', cmake_text)
        self.assertNotIn('include("${_inventory_plan}")', cmake_text)
        self.assertIn("cmake_language(EVAL CODE \"${_plan_output}\")", cmake_text)
        self.assertIn(
            "cmake_language(EVAL CODE \"${_inventory_output}\")", cmake_text
        )

        commands = [
            (
                self.plan_args() + ["--emit-cmake"],
                self.plan,
                "ISLE_BYTE_IDENTITY_PLAN_COMPLETE",
            ),
            (
                self.inventory_args() + ["--emit-cmake"],
                byte_identity.inventory_plan_path(self.build_dir),
                "ISLE_BYTE_IDENTITY_INVENTORY_COMPLETE",
            ),
        ]
        for index, (arguments, state_path, sentinel) in enumerate(commands):
            result = subprocess.run(
                [sys.executable, str(TOOLS / "byte_identity.py"), *arguments],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn(f"set({sentinel} TRUE)", result.stdout)
            state_path.write_text('message(FATAL_ERROR "PATH-TOCTOU")\n')
            captured = self.directory / f"captured-fragment-{index}.cmake"
            captured.write_text(
                result.stdout
                + f'\nif(NOT {sentinel})\n  message(FATAL_ERROR "missing")\nendif()\n'
            )
            evaluated = subprocess.run(
                ["cmake", "-P", str(captured)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                evaluated.returncode, 0, evaluated.stdout + evaluated.stderr
            )


class WineRegistryNormalizationTests(unittest.TestCase):
    """Registry identity is content-exact modulo Wine's per-boot timestamps."""

    def test_key_timestamps_normalize_and_values_stay_authoritative(self):
        boot_one = (b"WINE REGISTRY Version 2\n"
                    b"[Software\\\\Fonts] 1786803048\n"
                    b"#time=1dd2cbfdee1d170\n"
                    b"\"Value\"=\"stable\"\n")
        boot_two = (b"WINE REGISTRY Version 2\n"
                    b"[Software\\\\Fonts] 1786803100\n"
                    b"#time=1dd2cbffe1084d8\n"
                    b"\"Value\"=\"stable\"\n")
        tampered = boot_two.replace(b"stable", b"edited")
        self.assertEqual(
            byte_identity.wine_registry_normalized_sha256(boot_one),
            byte_identity.wine_registry_normalized_sha256(boot_two),
        )
        self.assertNotEqual(
            byte_identity.wine_registry_normalized_sha256(boot_one),
            byte_identity.wine_registry_normalized_sha256(tampered),
        )
        renamed = boot_two.replace(b"Fonts]", b"Fonts\\\\X]")
        self.assertNotEqual(
            byte_identity.wine_registry_normalized_sha256(boot_one),
            byte_identity.wine_registry_normalized_sha256(renamed),
        )

    def test_loaded_bundle_font_directory_prefix_is_transport(self):
        bundle = (rb'"Marlett (TrueType)"="\\??\\unix\\Applications'
                  rb'\\Wine Stable.app\\Contents\\Resources\\wine'
                  rb'\\share\\wine\\fonts\\marlett.ttf"' b"\n")
        snapshot = (rb'"Marlett (TrueType)"="\\??\\unix\\Users\\any\\held'
                    rb'\\Wine Stable.app\\Contents\\Resources\\wine'
                    rb'\\share\\wine\\fonts\\marlett.ttf"' b"\n")
        host_font = (rb'"Menlo (TrueType)"="\\??\\unix\\System\\Library'
                     rb'\\Fonts\\Menlo.ttc"' b"\n")
        self.assertEqual(
            byte_identity.wine_registry_normalized_sha256(bundle),
            byte_identity.wine_registry_normalized_sha256(snapshot),
        )
        self.assertNotEqual(
            byte_identity.wine_registry_normalized_sha256(bundle),
            byte_identity.wine_registry_normalized_sha256(
                bundle.replace(b"marlett", b"symbol")),
        )
        self.assertNotEqual(
            byte_identity.wine_registry_normalized_sha256(host_font),
            byte_identity.wine_registry_normalized_sha256(
                host_font.replace(b"System", b"Elsewhere")),
        )


class ResidentInventoryRederiveTests(unittest.TestCase):
    """The resident replay must carry the overlay source-authority column."""

    def test_rederive_preserves_overlay_source_authority(self):
        raw = {
            "configured_compiler": "/abs/cl",
            "entries": [
                {"target": "lego1", "source_path": "/src/a.cpp",
                 "language": "CXX", "target_ordinal": 0,
                 "source_authority": "TYPED_SOURCE_OVERLAY"},
                {"target": "lego1", "source_path": "/src/b.cpp",
                 "language": "CXX", "target_ordinal": 1,
                 "source_authority": "CLEAN_SOURCE"},
            ],
            "targets": [], "inputs": [], "link_graph": [],
        }
        captured = {}

        def capture_inventory(namespace):
            captured["entry"] = namespace.entry

        with ExitStack() as stack:
            authority = stack.enter_context(mock.patch.object(
                byte_identity, "active_build_authority"))
            authority.return_value.read_bytes.return_value = json.dumps(
                raw).encode()
            stack.enter_context(mock.patch.object(
                byte_identity, "command_inventory_locked",
                side_effect=capture_inventory))
            stack.enter_context(mock.patch.object(
                byte_identity, "command_attest_commands_locked"))
            byte_identity.resident_rederive_inventory_locked(
                argparse.Namespace(
                    build_dir=Path("/build"), source_dir=Path("/src")),
                {"manifest_path": "/manifest.json",
                 "cmake_module_path": "/module.cmake"},
            )
        self.assertEqual(captured["entry"], [
            ["lego1", "/src/a.cpp", "CXX", "0", "TYPED_SOURCE_OVERLAY"],
            ["lego1", "/src/b.cpp", "CXX", "1", "CLEAN_SOURCE"],
        ])


class SourceOverlayRelocationPolicyTests(unittest.TestCase):
    """The relocated-range renderer must never lose reccmp annotations."""

    PAYLOAD = (
        b"\n"
        b"// FUNCTION: LEGO1 0x10003bd0\n"
        b"// FUNCTION: BETA10 0x10011530\n"
        b"float Vector3::LenSquared() const // trailing prose\n"
        b"{\n"
        b"\treturn m_data[0] * m_data[0]; /* block prose */\n"
        b"}\n"
        b"\n"
    )

    def test_prose_policy_preserves_annotations_lines_and_tokens(self):
        rendered = byte_identity.source_overlay_strip_prose_preserve_lines(
            self.PAYLOAD
        )
        self.assertIn(b"// FUNCTION: LEGO1 0x10003bd0", rendered)
        self.assertIn(b"// FUNCTION: BETA10 0x10011530", rendered)
        self.assertNotIn(b"trailing prose", rendered)
        self.assertNotIn(b"block prose", rendered)
        self.assertEqual(rendered.count(b"\n"), self.PAYLOAD.count(b"\n"))
        self.assertEqual(
            byte_identity.source_overlay_significant_sha256(rendered),
            byte_identity.source_overlay_significant_sha256(self.PAYLOAD),
        )

    def test_comment_policy_still_strips_annotations(self):
        rendered = byte_identity.source_overlay_strip_comments_preserve_lines(
            self.PAYLOAD
        )
        self.assertNotIn(b"FUNCTION", rendered)
        self.assertEqual(rendered.count(b"\n"), self.PAYLOAD.count(b"\n"))

    def test_range_render_dispatch_is_policy_exact(self):
        prose = byte_identity.source_overlay_render_relocated_range(
            self.PAYLOAD, "strip_prose_preserve_physical_lines_v1"
        )
        stripped = byte_identity.source_overlay_render_relocated_range(
            self.PAYLOAD, "strip_comments_preserve_physical_lines_v1"
        )
        self.assertIn(b"// FUNCTION: LEGO1 0x10003bd0", prose)
        self.assertNotIn(b"FUNCTION", stripped)
        with self.assertRaises(byte_identity.ByteIdentityError):
            byte_identity.source_overlay_render_relocated_range(
                self.PAYLOAD, "free_form_passthrough"
            )


if __name__ == "__main__":
    unittest.main()
