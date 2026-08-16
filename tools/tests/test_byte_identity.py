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
    def source_overlay_line_reservation(count=1):
        return {"k": "lines", "n": count}
    @staticmethod
    def source_overlay_literal_use():
        return {
            "k": "literal_alias",
            "literal": "config", "local_identifier": "configAppName",
            "owner_function": "CConfigApp::InitInstance",
            "use_ordinal": 1,
            "nl": False,
        }
    @staticmethod
    def source_overlay_anchor(data: bytes, offset: int, boundary_kind: str):
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
        before_count = min(32, token_boundary)
        after_count = min(32, len(tokens) - token_boundary)
        signature = (
            tokens[token_boundary - before_count:token_boundary]
            + ["<SEAT>"]
            + tokens[token_boundary:token_boundary + after_count]
        )
        anchor = {
            "ctx": byte_identity.source_overlay_token_sha256(signature),
        }
        if before_count != 32:
            anchor["b"] = before_count
        if after_count != 32:
            anchor["a"] = after_count
        boundary_short = {
            "after_newline": None, "file_start": "start", "file_end": "end",
            "before_next_token": "before_token",
            "after_previous_token": "after_token",
        }[boundary_kind]
        if boundary_short:
            anchor["at"] = boundary_short
        if boundary_kind == "after_newline":
            before_line, after_line = byte_identity.source_overlay_seat_lines(
                data, offset
            )
            anchor["line_before"] = byte_identity.sha256_bytes(before_line)
            anchor["line_after"] = byte_identity.sha256_bytes(after_line)
        return anchor
    @staticmethod
    def source_overlay_payload(outputs):
        return {
            "schema": byte_identity.SOURCE_OVERLAY_SCHEMA,
            "outputs": sorted(outputs, key=lambda item: item["path"]),
            "graph": {"generated_tus": [], "link_admissions": []},
        }
    def test_source_overlay_renderer_owns_bytes_with_residual_overrides(self):
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

        blank_override = dict(raw)
        blank_override["lines"] = 1
        blank_override["blank_indent"] = [
            [1, 1, [{"unit": "space", "count": 1}]]
        ]
        self.assertEqual(
            byte_identity.render_source_overlay_generator(
                byte_identity.validate_source_overlay_generator(
                    blank_override, "fixture.generator"
                )
            ),
            b" \n",
        )

        declaration = byte_identity.validate_source_overlay_generator(
            {"k": "fwd", "id": "FixtureRecordA"}, "fixture.forward"
        )
        self.assertEqual(
            byte_identity.render_source_overlay_generator(declaration),
            b"class FixtureRecordA;\n",
        )
        seated = byte_identity.validate_source_overlay_generator(
            {"k": "fwd", "id": "FixtureRecordA", "lines": 3, "at": [2]},
            "fixture.forward",
        )
        self.assertEqual(
            byte_identity.render_source_overlay_generator(seated),
            b"\nclass FixtureRecordA;\n\n",
        )
        unterminated = byte_identity.validate_source_overlay_generator(
            self.source_overlay_literal_use(), "fixture.literal"
        )
        self.assertEqual(
            byte_identity.render_source_overlay_generator(unterminated),
            b"configAppName",
        )

        unknown = dict(raw)
        unknown["literal_payload"] = "free-form text"
        with self.assertRaisesRegex(
            byte_identity.ByteIdentityError, "schema differs"
        ):
            byte_identity.validate_source_overlay_generator(
                unknown, "fixture.generator"
            )
        unknown_kind = {"k": "raw_text", "text": "free-form text"}
        with self.assertRaisesRegex(
            byte_identity.ByteIdentityError, "is unsupported"
        ):
            byte_identity.validate_source_overlay_generator(
                unknown_kind, "fixture.generator"
            )
    def test_source_overlay_after_newline_boundary_handles_drift_fail_closed(self):
        unique = b"int a;\n\nint b;\n"
        anchor = self.source_overlay_anchor(
            unique, unique.index(b"\n") + 1, "after_newline",
        )
        normalized = byte_identity.validate_source_overlay_anchor(
            anchor, "fixture.anchor"
        )
        self.assertEqual(
            byte_identity.resolve_source_overlay_anchor(
                unique, normalized, "fixture baseline"
            ),
            unique.index(b"\n") + 1,
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
            ambiguous_base, middle, "after_newline",
        )
        normalized_ambiguous = byte_identity.validate_source_overlay_anchor(
            ambiguous_anchor, "fixture.ambiguous_anchor"
        )
        with self.assertRaisesRegex(
            byte_identity.ByteIdentityError,
            "no unique after-newline structural seat",
        ):
            byte_identity.resolve_source_overlay_anchor(
                b"int a;\n\n\n\nint b;\n", normalized_ambiguous,
                "fixture ambiguous drift",
            )
        with self.assertRaisesRegex(
            byte_identity.ByteIdentityError, "missing from its clean input"
        ):
            byte_identity.resolve_source_overlay_anchor(
                b"int other;\n", normalized, "fixture absent context"
            )
    def test_source_overlay_clean_drift_and_generated_absence_fail_closed(self):
        relative = "overlay/example.h"
        path = self.source_dir / relative
        path.parent.mkdir()
        clean = b"int baseline;\n"
        path.write_bytes(clean)
        effective = clean + b"\n"
        output = {
            "path": relative,
            "clean": byte_identity.sha256_bytes(clean),
            "effective": byte_identity.sha256_bytes(effective),
            "size": len(effective),
            "ops": [{
                "op": "insert",
                "anchor": self.source_overlay_anchor(
                    clean, len(clean), "file_end"
                ),
                "gen": self.source_overlay_line_reservation(),
            }],
        }
        payload = self.source_overlay_payload([output])
        baseline = byte_identity.validate_source_overlay(
            payload, self.source_dir
        )
        self.assertEqual(baseline["actual_records"][0]["clean_state"], "present")
        self.assertEqual(
            baseline["effective_by_path"][relative]["sha256"],
            byte_identity.sha256_bytes(effective),
        )
        self.assertEqual(
            baseline["outputs"][0]["effective"]["baseline_line_count"],
            effective.count(b"\n"),
        )

        # The tolerated-drift path is retired: a clean input that differs
        # from its pin refuses instead of rebasing the overlay.
        drift = b"// harmless unrelated comment\n" + clean
        path.write_bytes(drift)
        with self.assertRaisesRegex(
            byte_identity.ByteIdentityError,
            "clean source overlay input differs from its pin",
        ):
            byte_identity.validate_source_overlay(payload, self.source_dir)
        path.write_bytes(clean)

        generated_relative = "overlay/generated.h"
        generated_output = {
            "path": generated_relative,
            "effective": byte_identity.sha256_bytes(b"\n"),
            "size": 1,
            "ops": [{
                "op": "append",
                "gen": self.source_overlay_line_reservation(),
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
        redirected_output["path"] = "redirected-overlay/generated.h"
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
        start = clean.index(b"\n") + 1
        end = clean.index(b"int after")
        removed = clean[start:end]
        fragment = b"configAppName"
        effective = clean[:start] + fragment + clean[end:]
        generator = self.source_overlay_literal_use()
        output = {
            "path": relative,
            "clean": byte_identity.sha256_bytes(clean),
            "effective": byte_identity.sha256_bytes(effective),
            "size": len(effective),
            "ops": [{
                "op": "replace",
                "id": "op_fixture_replace",
                "from": self.source_overlay_anchor(
                    clean, start, "after_newline"
                ),
                "to": self.source_overlay_anchor(
                    clean, end, "before_next_token"
                ),
                "removed": {
                    "sha256": byte_identity.sha256_bytes(removed),
                    "size": len(removed),
                },
                "gen": generator,
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
        # The literal-alias census is derived from the typed params, never
        # stored: the reseated identifier is a reference, not a declaration.
        normalized_generator = accepted["outputs"][0]["operations"][0][
            "generator"
        ]
        self.assertEqual(
            byte_identity.source_overlay_expected_identifier_roles(
                normalized_generator["kind"], normalized_generator["params"]
            ),
            {
                "declared_identifiers": [],
                "referenced_identifiers": ["configAppName"],
                "emitted_identifiers": [],
            },
        )

        tampered_range = json.loads(json.dumps(payload))
        tampered_range["outputs"][0]["ops"][0]["removed"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(
            byte_identity.ByteIdentityError,
            "authenticated input-range pins",
        ):
            byte_identity.validate_source_overlay(
                tampered_range, self.source_dir
            )

        path.write_bytes(clean.replace(
            b"authenticated seat", b"tampered range bytes"
        ))
        with self.assertRaisesRegex(
            byte_identity.ByteIdentityError,
            "clean source overlay input differs from its pin",
        ):
            byte_identity.validate_source_overlay(payload, self.source_dir)
    def test_source_overlay_composite_child_and_output_pins_are_exact(self):
        rendered = (
            b"\n"
            b"class FixtureRecordA;\n"
            b"class FixtureRun0;\n"
            b"class FixtureRun1;\n"
            b"class FixtureRun2;\n"
            b"\n"
        )
        composite = {
            "k": "seq", "lines": 6,
            "items": [
                {"k": "fwd", "id": "FixtureRecordA", "line": 2},
                {"k": "fwd_run", "stem": "FixtureRun", "first": 0,
                 "count": 3, "line": 3},
            ],
        }
        normalized = byte_identity.validate_source_overlay_generator(
            composite, "fixture.composite"
        )
        self.assertEqual(
            byte_identity.render_source_overlay_generator(normalized), rendered
        )
        self.assertEqual(
            [
                leaf["params"]["identifier"]
                for leaf in byte_identity.iter_source_overlay_leaf_generators(
                    normalized
                )
            ],
            ["FixtureRecordA", "FixtureRun0", "FixtureRun1", "FixtureRun2"],
        )

        conflict = json.loads(json.dumps(composite))
        conflict["items"][1]["line"] = 2
        with self.assertRaisesRegex(
            byte_identity.ByteIdentityError, "nonblank conflict"
        ):
            byte_identity.render_source_overlay_generator(
                byte_identity.validate_source_overlay_generator(
                    conflict, "fixture.composite"
                )
            )
        overflow = json.loads(json.dumps(composite))
        overflow["items"].append({"k": "lines", "n": 3, "line": 5})
        with self.assertRaisesRegex(
            byte_identity.ByteIdentityError, "child span differs"
        ):
            byte_identity.render_source_overlay_generator(
                byte_identity.validate_source_overlay_generator(
                    overflow, "fixture.composite"
                )
            )

        relative = "overlay/composite.h"
        (self.source_dir / "overlay").mkdir(exist_ok=True)
        output = {
            "path": relative,
            "effective": byte_identity.sha256_bytes(rendered),
            "size": len(rendered),
            "ops": [{
                "op": "append", "gen": composite,
            }],
        }
        byte_identity.validate_source_overlay(
            self.source_overlay_payload([output]), self.source_dir
        )
        output["effective"] = "0" * 64
        with self.assertRaisesRegex(
            byte_identity.ByteIdentityError,
            "differs from its effective pin",
        ):
            byte_identity.validate_source_overlay(
                self.source_overlay_payload([output]), self.source_dir
            )
    def test_source_overlay_type_strings_round_trip_the_closed_grammar(self):
        for spelling in (
            "MxBitmap", "const char*", "unsigned int",
            "LegoPathEdgeContainer*", "MxAtomId&", "float* const",
            "const LegoChar*&",
            "_Tree<LegoCacheSoundEntry, LegoCacheSoundEntry, "
            "Set100d6b4c::_Kfn, Set100d6b4cComparator, "
            "allocator<LegoCacheSoundEntry>>",
        ):
            normalized = byte_identity.validate_source_overlay_cpp_type(
                spelling, "fixture.type"
            )
            self.assertEqual(
                byte_identity.render_source_overlay_cpp_type(normalized),
                spelling,
            )
        for wrong in (
            "char *", "char  const", "vector<int >", "int[4]", "T<>",
            "int**", "void()",
        ):
            with self.assertRaises(byte_identity.ByteIdentityError):
                byte_identity.validate_source_overlay_cpp_type(
                    wrong, "fixture.type"
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
    def enable_comdat_selection_override_fixture(self):
        donor_source = self.source.with_name("donor.cpp")
        donor_source.write_text("int donor() { return 11; }\n")
        header = entropy.generate_pad_shape(1, 1).encode("utf-8")
        header_sha = digest(header)
        self.recipe_id = f"d_{header_sha[:12]}"
        unit = self.document["translation_units"][0]
        unit["mode"] = "compose_equal_body_comdat"
        unit["donors"] = [
            {
                "id": self.recipe_id,
                "status": "compiler_generated_current_source",
                "authenticity": "synthetic_baseline_only",
                "recipe": {
                    "kind": "pad_shape",
                    "classes": 1,
                    "functions_per_class": 1,
                    "generated_header_sha256": header_sha,
                    "compile_lane": {"required_define": "DIRECTX5_SDK"},
                    "emission_policy": "non_emitting_declarations_only",
                    "authenticity_rationale": (
                        "A source-generated declaration-only carrier selects "
                        "another translation unit's matching COMDAT copy."
                    ),
                    "donor_source": donor_source.relative_to(
                        self.source_dir
                    ).as_posix(),
                },
            }
        ]
        unit["functions"] = [
            {
                "mangled": TARGET_SYMBOL,
                "donor": self.recipe_id,
                "splice_class": "comdat_selection_override",
                "expected_seed_length": 30,
                "expected_donor_length": 30,
                "expected_body_sha256": "01" * 32,
                "retail_oracle": {
                    "image": "LEGO1.DLL",
                    "address": "0x10001000",
                    "verdict": "MATCH",
                    "length": 30,
                },
            }
        ]
        unit["completion"] = {
            "state": "object_composition_enabled_final_gates_incomplete",
            "reason": (
                "The fixture selects one source-generated COMDAT while final "
                "archive, image, and comparison gates remain incomplete."
            ),
            "may_replace_compiler_output": True,
        }
        self.write_manifest()
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
    def test_declaration_shape_matches_exhaustive_search_bytes(self):
        self.assertEqual(
            digest(entropy.generate_shape(2, 3).encode("utf-8")),
            "fcac8dfe7db78fdfbe3d9f1942feb51de8fc0f14885b8e4c23b695da2b4dff27",
        )
    def test_comdat_selection_override_manifest_schema_is_closed(self):
        self.enable_comdat_selection_override_fixture()
        normalized = byte_identity.validate_manifest(
            self.manifest, self.source_dir, self.build_dir,
            configured_compiler=str(self.compiler),
        )
        function = normalized["translation_units"][0]["functions"][0]
        self.assertEqual(function["splice_class"],
                         "comdat_selection_override")

        self.document["translation_units"][0]["functions"][0][
            "unexpected_key"
        ] = True
        self.write_manifest()
        with self.assertRaisesRegex(
            byte_identity.ByteIdentityError, "unknown keys.*unexpected_key"
        ):
            byte_identity.validate_manifest(
                self.manifest, self.source_dir, self.build_dir,
                configured_compiler=str(self.compiler),
            )
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
