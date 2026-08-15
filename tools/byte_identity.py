"""Fail-closed compiler-output composition for byte-identical builds.

The launcher compiles a pinned current source twice with the configured VC4.2
compiler: once without a declaration shape and once with a deterministic,
non-emitting shape force-included.  It may compose only equal-linked-span i386
FPO COMDATs whose complete compiler metadata closure passes the gates below.
Retail is represented only by manifest oracle facts for all first-party code
and data.  The sole payload exception is an exact, typed manifest declaration
for the third-party SmartHeap or Smacker archive.  Those two archives are
copied byte-for-byte into fixed build-authority seats and may be consumed only
through their attested direct-link sequences.  Xdata and unknown splice
classes remain fatal; a separate explicit completion command gates the final
LEGO1 image on all 4933 raw-exact reccmp rows and byte-for-byte SHA-256/MD5
identity.  All child compiler launches share a
crash-safe, build-wide four-process semaphore.  The implemented Darwin-hosted
POSIX/Wine reference backend uses root-fd/openat namespace authority.  The native-Windows module
provides held no-reparse handle chains, a logical-Z mapper, and kill-on-close
Job Objects as an architectural seam only.  Native-Windows production and CI
execution are deferred and untested; the production CMake path still refuses
Windows until that authority is wired through every framework mutation and
verification epoch.
VC4.2 itself necessarily opens pathname `/Fo` and `/Fd` arguments: the Darwin/Wine
launcher holds and revalidates authority-created private directories
immediately around that child boundary, then consumes and installs output only
through no-follow descriptors held continuously through final audit
publication and visibility revalidation.  It does not claim that VC's own
pathname open is immune to an adversarial same-user rename after spawn.
"""


from __future__ import annotations


import argparse


from collections import Counter, defaultdict


from collections.abc import Callable


from contextlib import contextmanager, ExitStack, nullcontext


import ctypes


import hashlib


import json


import math


import os


import platform


import plistlib


from pathlib import Path, PurePosixPath


import re


import shlex


import shutil


import signal


import stat


import struct


import subprocess


import sys


import sysconfig


import tempfile


import time


import uuid


import entropy as entropy_generator  # noqa: E402


import byte_identity_backend as execution_backend_module  # noqa: E402


from byte_identity_backend import (  # noqa: E402
    BackendError,
    BackendLockBusy,
    PlatformFileLock,
    POSIX_WINE_BACKEND,
    WINDOWS_NATIVE_BACKEND,
    WindowsHeldDirectoryChain,
    WindowsJob,
    WindowsNamespaceAuthority,
    capabilities as backend_capabilities,
    host_backend,
    process_is_alive,
    selected_backend,
    windows_creationflags,
)


SCHEMA_VERSION = 2


PHASE = "compiler_output_comdat_v1"


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


MD5_RE = re.compile(r"^[0-9a-f]{32}$")


RECIPE_ID_RE = re.compile(r"^[de]_[0-9a-f]{12}$")


ADDRESS_RE = re.compile(r"^0x[0-9a-f]{6,8}$")


TARGET_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.+-]*$")


IMPORTED_TARGET_RE = re.compile(
    r"^[A-Za-z0-9_][A-Za-z0-9_.+-]*::[A-Za-z0-9_][A-Za-z0-9_.+-]*$"
)


SUPPORTED_GENERATORS = {"Ninja", "Unix Makefiles"}


SOURCE_OVERLAY_SCHEMA = 1


SOURCE_OVERLAY_STATUS = "TYPED_SOURCE_OVERLAY"


SOURCE_OVERLAY_RENDERER = "closed_typed_source_overlay_v1"


SOURCE_OVERLAY_EFFECTIVE_MODE = "mirror_clean_then_typed_overlay"


NATIVE_DIAGNOSTIC_MANIFEST_POLICY = "native_tests_no_identity_authority_v1"


SOURCE_OVERLAY_GENERATOR_REGISTRY_SHA256 = (
    "9759a8612ef7a9c4b28aa2896a39ef53091849b586a5a07155d7e10a9293d53d"
)


SOURCE_OVERLAY_ANCHOR_POLICY = (
    "use strongest unique tier; fall back 32->16->8 only on zero matches; "
    "ambiguity at any attempted tier fails"
)


SOURCE_OVERLAY_DRIFT_CONTRACT = {
    "ambiguity": "fail_closed",
    "destructive_range_policy": (
        "delete/replace is authorized only when the uniquely anchored actual "
        "input range matches the operation baseline_input_range "
        "byte/size/line/token pins"
    ),
    "generated_only_path": (
        "clean state must remain absent and full effective baseline pins "
        "remain exact"
    ),
    "present_input_drift_path": (
        "otherwise every operation anchor resolves strongest-to-narrowest "
        "uniquely and every generated fragment matches its fixed baseline "
        "fragment pins"
    ),
    "present_input_fast_path": (
        "baseline effective pin may be compared directly only when actual "
        "clean hash and size equal baseline clean pins"
    ),
    "receipt_required_fields": [
        "logical_path", "actual_clean_sha256", "actual_clean_size",
        "operation_id", "chosen_anchor_tier", "resolved_token_offset",
        "actual_generated_fragment_sha256", "actual_removed_range_sha256",
        "actual_removed_range_size", "actual_removed_range_line_count",
        "actual_removed_range_significant_token_sha256",
        "actual_effective_sha256", "actual_effective_size",
    ],
    "receipt_field_applicability": (
        "actual_removed_range_* fields are mandatory for delete/replace "
        "operations and absent for non-destructive operations"
    ),
    "relocation_policy": (
        "capture each exact-one producer range from authenticated clean input "
        "before mutation; source and destination recipes share dependency ID, "
        "source operation ID, and identical range pins"
    ),
    "relocation_receipt_required_fields": [
        "range_dependency_id", "source_operation_id",
        "actual_held_source_range_sha256",
        "actual_held_source_range_size",
        "actual_held_source_range_line_count",
        "actual_held_source_range_significant_token_sha256",
        "consumer_operation_id",
    ],
}


SOURCE_OVERLAY_RUNTIME_TRUST = {
    "effective_hashes": "verification assertions only; never source payloads",
    "reconstruction": "authenticated clean inputs plus closed typed recipes only",
    "scratch_artifacts": "excluded",
}


SOURCE_OVERLAY_TOKEN_RE = re.compile(
    r"//[^\n]*|/\*.*?\*/|"
    r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|'
    r"[A-Za-z_]\w*|0[xX][0-9A-Fa-f]+|"
    r"\d+(?:\.\d*)?(?:[eE][+-]?\d+)?[A-Za-z]*|"
    r"::|->\*|->|\.\*|<<=|>>=|==|!=|<=|>=|\+\+|--|&&|\|\||"
    r"<<|>>|\+=|-=|\*=|/=|%=|&=|\|=|\^=|##|\.\.\.|[^\s]",
    re.S,
)


SOURCE_OVERLAY_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


SOURCE_OVERLAY_QUALIFIED_IDENTIFIER_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*$"
)


SOURCE_OVERLAY_STRUCTURAL_SEATS = frozenset({
    "before_first_significant_token", "after_final_significant_token",
    "before_include", "before_annotated_definition", "unique_token_boundary",
})


SOURCE_OVERLAY_ACTIONS = frozenset({
    "insert", "replace", "delete", "whole_file_append",
})


SOURCE_OVERLAY_KIND_POLICIES = {
    "archive_pull_seed_function_v1": (
        "discarded_archive_pull_seed", "archive_member_pull_seed"
    ),
    "archive_pull_seed_sequence_v1": (
        "discarded_archive_pull_seed", "ordered_undefined_binding_seed"
    ),
    "compile_time_layout_assert_seat_v1": (
        "compiler_state_only", "compile_time_assert_seat"
    ),
    "composed_typed_sequence_v1": (
        "composed", "line_indexed_nonblank_overlay"
    ),
    "conditional_declarations_v1": (
        "non_emitting_declaration", "conditional_directive_wrapper"
    ),
    "debug_assert_reseat_v1": (
        "compiler_state_only", "debug_assert_removal_and_carrier_reseat"
    ),
    "declaration_sequence_v1": (
        "non_emitting_declaration", "declaration_only"
    ),
    "discarded_console_crt_pull_v1": (
        "discarded_import_or_crt_pull", "console_crt_archive_pull"
    ),
    "discarded_import_library_probe_v1": (
        "discarded_import_or_crt_pull", "import_library_admission_probe"
    ),
    "empty_compound_statements_v1": (
        "compiler_state_only", "function_body_empty_scope_sequence"
    ),
    "include_dependency_v1": ("include_dependency", "preprocessor_include"),
    "include_seat_v1": ("include_dependency", "preprocessor_include"),
    "inline_budget_noop_statements_v1": (
        "compiler_state_only", "function_body_noop_sequence"
    ),
    "line_reservation_v1": ("source_layout_only", "physical_line_reservation"),
    "list_cursor_delete_emission_probe_v1": (
        "discarded_emission_probe", "list_cursor_delete_emission"
    ),
    "literal_first_use_alias_v1": (
        "compiler_state_only", "literal_first_use_reseat"
    ),
    "local_symbol_id_carrier_v1": (
        "compiler_state_only", "function_local_symbol_carrier"
    ),
    "qualified_member_comdat_emission_probe_v1": (
        "discarded_emission_probe", "qualified_member_comdat_emission"
    ),
    "record_header_v1": (
        "non_emitting_declaration", "whole_generated_header"
    ),
    "recursive_frame_texture_refresh_probe_v1": (
        "discarded_import_or_crt_pull", "recursive_guid_pull_probe"
    ),
    "synthetic_constant_pool_tu_v1": (
        "generated_padding_translation_unit",
        "include_driven_constant_pool_padding",
    ),
    "synthetic_crt_pull_v1": (
        "discarded_import_or_crt_pull", "array_delete_crt_pull"
    ),
    "synthetic_discarded_relocation_ring_v1": (
        "generated_padding_translation_unit", "discarded_relocation_ring"
    ),
    "synthetic_member_call_supplier_v1": (
        "generated_supplier_translation_unit", "member_call_supplier"
    ),
    "synthetic_template_member_supplier_v1": (
        "generated_supplier_translation_unit", "template_member_comdat_supplier"
    ),
}


CHILD_ENVIRONMENT_POLICY = {
    "policy": "strict_allowlist_v1",
    "fixed": {"LANG": "C", "LC_ALL": "C", "WINEDEBUG": "-all"},
    "isolated_directories": ["HOME", "TEMP", "TMP", "TMPDIR", "WINEPREFIX"],
    "path": "validated_build_tree_runtime_snapshot_only",
    "transport_marker": "run_private_virtual_z_root_v1",
}


MSVC_ENVIRONMENT_ROOT_TRANSFORM_SCHEMA = (
    "source_derived_logical_msvc_root_v1"
)


MSVC_WRAPPER_INVOCATION_TRANSFORM_SCHEMA = (
    "source_derived_held_bash_invocation_v1"
)


MSVC_WRAPPER_TRANSFORM_SCRIPTS = (
    "wine/x86/cl", "wine/x86/rc", "wine/x86/lib", "wine/x86/link",
)


MSVC_WINE_ARGUMENT_TRANSFORM_SCHEMA = (
    "source_derived_projected_argument_directory_v1"
)


FORBIDDEN_CONVENIENCE_OPTIONS = {
    "/e", "-e", "/ep", "-ep", "/p", "-p",
}


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


THIRD_PARTY_RETAIL_ARCHIVES = {
    "SmartHeap": "3rdparty/smartheap/SHLW32MT.LIB",
    "Smacker": "3rdparty/smacker/smackw32.lib",
}


THIRD_PARTY_RETAIL_ARCHIVE_POLICY = (
    "retail_bytes_explicitly_allowed_for_named_third_party_archive_only"
)


REQUIRED_THIRD_PARTY_ARCHIVES = frozenset(THIRD_PARTY_RETAIL_ARCHIVES)


REQUIRED_PROJECT_SDK_LIBRARIES = frozenset({
    "3rdparty/dx5/lib/d3drm.lib",
    "3rdparty/dx5/lib/ddraw.lib",
    "3rdparty/dx5/lib/dinput.lib",
    "3rdparty/dx5/lib/dsound.lib",
    "3rdparty/dx5/lib/dxguid.lib",
})


IMPORTED_TARGET_INTERFACE_PROPERTIES = (
    "INTERFACE_LINK_LIBRARIES",
    "INTERFACE_LINK_LIBRARIES_DIRECT",
    "INTERFACE_LINK_LIBRARIES_DIRECT_EXCLUDE",
    "INTERFACE_LINK_OPTIONS",
    "INTERFACE_LINK_DIRECTORIES",
    "INTERFACE_INCLUDE_DIRECTORIES",
    "INTERFACE_SYSTEM_INCLUDE_DIRECTORIES",
    "INTERFACE_COMPILE_OPTIONS",
    "INTERFACE_COMPILE_DEFINITIONS",
    "INTERFACE_COMPILE_FEATURES",
    "INTERFACE_SOURCES",
)


REQUIRED_IMPORTED_TARGETS = frozenset({
    "DirectX5::DirectX5", "Smacker::Smacker",
    "SmartHeap::SmartHeap", "Vec::Vec",
})


PRODUCER_SUPPORT_ROLES = frozenset({"resource", "archive", "link"})


FIRST_PARTY_DIRECTIVE_PATTERNS = frozenset({
    b"-defaultlib:libcpmt -defaultlib:LIBCMT -defaultlib:OLDNAMES ",
    b"-defaultlib:LIBCMT -defaultlib:OLDNAMES ",
    b"-defaultlib:libcpmt -defaultlib:LIBCMT -defaultlib:OLDNAMES "
      b"-export:??1MxDSFile@@UAE@XZ ",
    b"-defaultlib:LIBC -defaultlib:OLDNAMES ",
    b"-defaultlib:mfc42.lib -defaultlib:mfcs42.lib "
      b"-defaultlib:msvcrt.lib -defaultlib:kernel32.lib "
      b"-defaultlib:user32.lib -defaultlib:gdi32.lib "
      b"-defaultlib:comdlg32.lib -defaultlib:winspool.lib "
      b"-defaultlib:advapi32.lib -defaultlib:shell32.lib "
      b"-defaultlib:comctl32.lib /include:__afxForceEXCLUDE "
      b"/include:__afxForceSTDAFX -defaultlib:uuid.lib "
      b"-defaultlib:MSVCRT -defaultlib:OLDNAMES ",
    b"-defaultlib:msvcprt -defaultlib:MSVCRT -defaultlib:OLDNAMES ",
    b"-defaultlib:mfc42.lib -defaultlib:mfcs42.lib "
      b"-defaultlib:msvcrt.lib -defaultlib:kernel32.lib "
      b"-defaultlib:user32.lib -defaultlib:gdi32.lib "
      b"-defaultlib:comdlg32.lib -defaultlib:winspool.lib "
      b"-defaultlib:advapi32.lib -defaultlib:shell32.lib "
      b"-defaultlib:comctl32.lib /include:__afxForceEXCLUDE "
      b"/include:__afxForceSTDAFX -defaultlib:uuid.lib "
      b"-defaultlib:msvcprt -defaultlib:MSVCRT -defaultlib:OLDNAMES ",
    b"-defaultlib:MSVCRT -defaultlib:OLDNAMES ",
    b"-defaultlib:LIBCMT -defaultlib:OLDNAMES "
      b"-export:??1MxDSFile@@UAE@XZ ",
    b"-defaultlib:LIBCMT -defaultlib:OLDNAMES "
      b"-export:??0MxVideoParam@@QAE@AAVMxRect32@@PAVMxPalette@@KAAVMxVideoParamFlags@@@Z ",
})


WINDOWS_NATIVE_TOOLCHAIN_PINS = {
    "CL.EXE": "c5bf7ad84482e8a54d5753fcbd3e648d8a1192f5ca8b8cf1f5d23b651750585f",
    "C1.EXE": "c5a62937d806fbd8663b05f15bd02670a43bdf983a50ee4080bcfd90a7643b90",
    "C1XX.EXE": "9e0782ec157b30a387ca855374bc4c1b8a605dfb12364425497ba431541a5bf9",
    "C2.EXE": "2aa1fcace0779531b3ec80b730663acd98f181aed3cdff51366440c602b724b5",
    "MSPDB41.DLL": "6cab17cfcbc5a6317ab030a0db99164cafdfd1f360baa36186849237ffb25858",
    "MSVCRT40.DLL": "ab55a2de2b6faf3daacd3e69473d385ceaead8033f7c79beb6bbf802f230f030",
    "MSVCRT20.DLL": "72a46bd99188b67d48270a1bf40ffd6cd9bc5814818066a743eaffb8d64d88e8",
}


ACTIVE_BUILD_AUTHORITIES = []


class ByteIdentityError(RuntimeError):
    """A manifest, provenance, launch, or verification gate failed."""


MSVC_ENVIRONMENT_ROOT_DERIVATION_LINE = (
    b'MSVC_ROOT="$(cd -- "$(dirname -- "$0")/../.." && '
    b'printf \'%s\\n\' "$(pwd)")"\n'
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ByteIdentityError(message)


def unique_json_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, f"JSON object contains duplicate key: {key}")
        result[key] = value
    return result


class PreservedJsonObject(list):
    """A JSON object whose ordered pairs remain available after a strict failure."""


def preserved_json_object(pairs: list[tuple[str, object]]) -> PreservedJsonObject:
    return PreservedJsonObject(pairs)


def reject_json_constant(value: str) -> object:
    raise ByteIdentityError(f"JSON non-finite constant is forbidden: {value}")


def strict_json_loads(data: str | bytes, *, preserve_pairs: bool = False) -> object:
    return json.loads(
        data,
        object_pairs_hook=(preserved_json_object if preserve_pairs else unique_json_object),
        parse_constant=reject_json_constant,
    )


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def md5_bytes(data: bytes) -> str:
    """Return the legacy image identity digest, never a security decision."""
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


def sha256_file(path: Path) -> str:
    authority = active_authority_for_path(path)
    if authority is not None:
        return sha256_bytes(authority.read_bytes(path))
    if ACTIVE_BUILD_AUTHORITIES:
        return sha256_bytes(ACTIVE_BUILD_AUTHORITIES[-1].read_external_bytes(path))
    try:
        return sha256_bytes(path.read_bytes())
    except OSError as error:
        raise ByteIdentityError(f"cannot hash {path}: {error}") from error


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"
    ).encode("utf-8")


def exact_keys(value: dict, allowed: set[str], context: str) -> None:
    unknown = set(value) - allowed
    require(not unknown, f"{context} has unknown keys: {sorted(unknown)}")


def exact_audit_keys(
    value: dict, expected: set[str], context: str,
    optional: set[str] | None = None,
) -> None:
    unknown = set(value) - expected
    missing = expected - set(value) - (optional or set())
    require(
        not unknown and not missing,
        f"{context} schema differs; unknown={sorted(unknown)} "
        f"missing={sorted(missing)}",
    )


def exact_json_equal(left: object, right: object) -> bool:
    """JSON equality that never treats bool/int/float as interchangeable."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return (left.keys() == right.keys()
                and all(exact_json_equal(left[key], right[key]) for key in left))
    if isinstance(left, list):
        return (len(left) == len(right)
                and all(exact_json_equal(a, b) for a, b in zip(left, right)))
    return left == right


def require_sha(value: object, context: str) -> str:
    require(isinstance(value, str) and SHA256_RE.fullmatch(value) is not None,
            f"{context} must be a lowercase SHA-256")
    return value


def require_md5(value: object, context: str) -> str:
    require(isinstance(value, str) and MD5_RE.fullmatch(value) is not None,
            f"{context} must be a lowercase MD5")
    return value


def require_nonnegative_finite_number(value: object, context: str) -> float:
    require(
        type(value) is float
        and math.isfinite(value)
        and value >= 0,
        f"{context} must be a finite nonnegative JSON float",
    )
    return value


def require_exact_int(
    value: object, context: str, *, minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    require(type(value) is int, f"{context} must be an exact JSON integer")
    if minimum is not None:
        require(value >= minimum, f"{context} is below its minimum")
    if maximum is not None:
        require(value <= maximum, f"{context} exceeds its maximum")
    return value


def require_exact_bool(value: object, context: str) -> bool:
    require(type(value) is bool, f"{context} must be an exact JSON boolean")
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


def canonical_source_relative_path(value: object, context: str) -> str:
    """Normalize one lexical source-tree path without requiring it to exist."""
    require(isinstance(value, str) and value,
            f"{context} must be a non-empty path")
    require("\\" not in value and ";" not in value and "\0" not in value,
            f"{context} must use a safe POSIX path")
    pure = PurePosixPath(value)
    require(
        not pure.is_absolute() and pure.as_posix() == value
        and all(part not in ("", ".", "..") for part in pure.parts),
        f"{context} must be one canonical source-relative path",
    )
    return pure.as_posix()


def source_overlay_relative_path(value: object, context: str) -> str:
    """Normalize one manifest-owned logical source/header overlay path.

    Generated-only overlay outputs are intentionally absent from the clean
    checkout, so the ordinary ``resolve_relative`` existence check is not an
    authority for this namespace.  Overlay recipes additionally admit only
    the closed C/C++ source/header suffix family.  Ordinary CMake inventory
    paths use :func:`canonical_source_relative_path` because an explicit
    LANGUAGE property may legitimately assign C or C++ to another suffix.
    """
    relative = canonical_source_relative_path(value, context)
    pure = PurePosixPath(relative)
    require(pure.suffix.casefold() in {
        ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx",
        ".inc", ".inl",
    }, f"{context} has an unsupported source/header suffix")
    return relative


def source_overlay_logical_path(source_root: Path, relative: str) -> Path:
    """Return an exact lexical source seat and reject redirected ancestors."""
    root = source_root.resolve(strict=True)
    require(root.is_dir() and not root.is_symlink(),
            "source overlay root is absent or redirected")
    current = root
    parts = PurePosixPath(relative).parts
    for part in parts[:-1]:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as error:
            raise ByteIdentityError(
                f"source overlay parent is absent: {current}: {error}"
            ) from error
        require(stat.S_ISDIR(metadata.st_mode) and not current.is_symlink(),
                f"source overlay parent is redirected: {current}")
    return root.joinpath(*parts)


def source_overlay_tokens(data: bytes) -> list[tuple[str, int, int]]:
    """Lex C/C++ significant tokens with stable byte spans.

    Latin-1 provides a one-to-one byte/character mapping.  Comments never
    participate in anchor authority; string and character literals remain
    single exact tokens.
    """
    text = data.decode("latin1")
    result = []
    for match in SOURCE_OVERLAY_TOKEN_RE.finditer(text):
        token = match.group(0)
        if token.startswith(("//", "/*")):
            continue
        result.append((token, match.start(), match.end()))
    return result


def source_overlay_token_sha256(tokens: list[str]) -> str:
    return sha256_bytes("\0".join(tokens).encode("latin1"))


def source_overlay_significant_sha256(data: bytes) -> str:
    return source_overlay_token_sha256(
        [token for token, _, _ in source_overlay_tokens(data)]
    )


def source_overlay_strip_comments_preserve_lines(data: bytes) -> bytes:
    """Remove only comment bytes while retaining exact physical line seats."""
    text = data.decode("latin1")
    result = bytearray(data)
    for match in SOURCE_OVERLAY_TOKEN_RE.finditer(text):
        token = match.group(0)
        if not token.startswith(("//", "/*")):
            continue
        for index in range(match.start(), match.end()):
            if result[index] not in (10, 13):
                result[index] = 32
    return bytes(result)


SOURCE_OVERLAY_ANNOTATION_COMMENT_RE = re.compile(
    r"//\s*(?:FUNCTION|GLOBAL|VTABLE|STRING|LIBRARY|SYNTHETIC|TODO|OFFSET"
    r"|SIZE)\b"
)


SOURCE_OVERLAY_RANGE_RENDER_POLICIES = {
    "strip_comments_preserve_physical_lines_v1",
    "strip_prose_preserve_physical_lines_v1",
}


def source_overlay_strip_prose_preserve_lines(data: bytes) -> bytes:
    """Strip prose comments but keep annotation comments and line seats."""
    text = data.decode("latin1")
    result = bytearray(data)
    for match in SOURCE_OVERLAY_TOKEN_RE.finditer(text):
        token = match.group(0)
        if not token.startswith(("//", "/*")):
            continue
        if token.startswith("//") and SOURCE_OVERLAY_ANNOTATION_COMMENT_RE.match(
                token) is not None:
            continue
        for index in range(match.start(), match.end()):
            if result[index] not in (10, 13):
                result[index] = 32
    return bytes(result)


def source_overlay_render_relocated_range(data: bytes, policy: object) -> bytes:
    require(policy in SOURCE_OVERLAY_RANGE_RENDER_POLICIES,
            "source relocation render policy differs")
    if policy == "strip_prose_preserve_physical_lines_v1":
        return source_overlay_strip_prose_preserve_lines(data)
    return source_overlay_strip_comments_preserve_lines(data)


def source_overlay_structural_seat(
    data: bytes, offset: int, byte_boundary: dict,
) -> dict:
    require(0 <= offset <= len(data), "source overlay seat offset is invalid")
    prefix = data[:offset]
    suffix = data[offset:]
    prefix_lines = prefix.splitlines()
    suffix_lines = suffix.splitlines()
    before = prefix_lines[-1] if prefix_lines else b""
    after = suffix_lines[0] if suffix_lines else b""
    if not prefix.strip():
        kind = "before_first_significant_token"
    elif not suffix.strip():
        kind = "after_final_significant_token"
    elif after.lstrip().startswith(b"#include"):
        kind = "before_include"
    elif re.match(br"\s*//\s*(?:FUNCTION|GLOBAL|VTABLE)", after):
        kind = "before_annotated_definition"
    else:
        kind = "unique_token_boundary"
    return {
        "kind": kind,
        "before_line_sha256": sha256_bytes(before),
        "after_line_sha256": sha256_bytes(after),
        "byte_boundary": byte_boundary,
    }


def validate_source_overlay_anchor(
    value: object, context: str, *, logical_path: str, operation_id: str,
) -> dict:
    require(isinstance(value, dict), f"{context} must be an object")
    exact_audit_keys(
        value, {
            "anchor_kind", "logical_path", "operation_ids", "policy",
            "structural_seat", "tiers",
        }, context
    )
    require(value.get("anchor_kind") == "significant_token_context_v1",
            f"{context} has an unsupported anchor kind")
    normalized_path = source_overlay_relative_path(
        value.get("logical_path"), context + ".logical_path"
    )
    operation_ids = value.get("operation_ids")
    require(
        normalized_path == logical_path
        and isinstance(operation_ids, list) and operation_ids
        and len(operation_ids) == len(set(operation_ids))
        and all(
            isinstance(item, str)
            and re.fullmatch(r"op_[a-z0-9_]{1,120}", item) is not None
            for item in operation_ids
        )
        and operation_id in operation_ids
        and value.get("policy") == SOURCE_OVERLAY_ANCHOR_POLICY,
        f"{context} ownership/policy differs",
    )
    seat = value.get("structural_seat")
    require(isinstance(seat, dict), f"{context}.structural_seat must be an object")
    exact_audit_keys(
        seat, {
            "kind", "before_line_sha256", "after_line_sha256",
            "byte_boundary",
        },
        f"{context}.structural_seat",
    )
    require(seat.get("kind") in SOURCE_OVERLAY_STRUCTURAL_SEATS,
            f"{context}.structural_seat kind is unsupported")
    raw_boundary = seat.get("byte_boundary")
    require(isinstance(raw_boundary, dict),
            f"{context}.structural_seat.byte_boundary must be an object")
    boundary_kind = raw_boundary.get("kind")
    if boundary_kind == "after_newline":
        exact_audit_keys(raw_boundary, {"kind"},
                         f"{context}.structural_seat.byte_boundary")
        normalized_boundary = {"kind": boundary_kind}
    else:
        require(boundary_kind in {
            "file_start", "file_end", "after_previous_token",
            "before_next_token",
        }, f"{context}.structural_seat.byte_boundary kind is unsupported")
        exact_audit_keys(raw_boundary, {"kind"},
                         f"{context}.structural_seat.byte_boundary")
        normalized_boundary = {"kind": boundary_kind}
    normalized_seat = {
        "kind": seat["kind"],
        "before_line_sha256": require_sha(
            seat.get("before_line_sha256"),
            f"{context}.structural_seat.before_line_sha256",
        ),
        "after_line_sha256": require_sha(
            seat.get("after_line_sha256"),
            f"{context}.structural_seat.after_line_sha256",
        ),
        "byte_boundary": normalized_boundary,
    }
    tiers = value.get("tiers")
    require(isinstance(tiers, list) and len(tiers) == 3,
            f"{context}.tiers must contain the exact 32/16/8 fallback chain")
    normalized_tiers = []
    for index, (tier, width) in enumerate(zip(tiers, (32, 16, 8))):
        tier_context = f"{context}.tiers[{index}]"
        require(isinstance(tier, dict), f"{tier_context} must be an object")
        exact_audit_keys(tier, {
            "context_tokens_each_side", "before_token_count",
            "after_token_count", "context_sha256", "occurrences",
        }, tier_context)
        require(require_exact_int(
            tier.get("context_tokens_each_side"), tier_context + ".width",
            minimum=width, maximum=width,
        ) == width, f"{tier_context} width differs")
        before_count = require_exact_int(
            tier.get("before_token_count"), tier_context + ".before_token_count",
            minimum=0, maximum=width,
        )
        after_count = require_exact_int(
            tier.get("after_token_count"), tier_context + ".after_token_count",
            minimum=0, maximum=width,
        )
        require(before_count or after_count,
                f"{tier_context} cannot match an empty context")
        occurrences = require_exact_int(
            tier.get("occurrences"), tier_context + ".occurrences",
            minimum=1, maximum=2_000_000,
        )
        require(index != 0 or occurrences == 1,
                f"{tier_context} strongest tier is not uniquely authored")
        normalized_tiers.append({
            "context_tokens_each_side": width,
            "before_token_count": before_count,
            "after_token_count": after_count,
            "context_sha256": require_sha(
                tier.get("context_sha256"), tier_context + ".context_sha256"
            ),
            "occurrences": occurrences,
        })
    return {
        "anchor_kind": "significant_token_context_v1",
        "logical_path": normalized_path,
        "operation_ids": list(operation_ids),
        "policy": SOURCE_OVERLAY_ANCHOR_POLICY,
        "structural_seat": normalized_seat,
        "tiers": normalized_tiers,
    }


def resolve_source_overlay_anchor(
    data: bytes, anchor: dict, context: str, *,
    evidence: list[dict] | None = None, logical_path: str | None = None,
    operation_id: str | None = None, role: str | None = None,
) -> int:
    """Resolve the strongest unique token context to one exact byte seat."""
    matches = source_overlay_tokens(data)
    tokens = [item[0] for item in matches]
    for tier in anchor["tiers"]:
        before_count = tier["before_token_count"]
        after_count = tier["after_token_count"]
        candidates = []
        for index in range(len(tokens) + 1):
            if index < before_count or len(tokens) - index < after_count:
                continue
            signature = (
                tokens[index - before_count:index]
                + ["<SEAT>"]
                + tokens[index:index + after_count]
            )
            if source_overlay_token_sha256(signature) == tier["context_sha256"]:
                candidates.append(index)
        require(len(candidates) <= 1,
                f"{context} is ambiguous at the {tier['context_tokens_each_side']}-token tier")
        if not candidates:
            continue
        index = candidates[0]
        lower = matches[index - 1][2] if index else 0
        upper = matches[index][1] if index < len(matches) else len(data)
        require(lower <= upper, f"{context} token boundary is invalid")
        boundary = anchor["structural_seat"]["byte_boundary"]
        boundary_kind = boundary["kind"]
        if boundary_kind == "file_start":
            require(lower == 0, f"{context} is not at file start")
            selected_offset = 0
        elif boundary_kind == "file_end":
            require(upper == len(data), f"{context} is not at file end")
            selected_offset = len(data)
        elif boundary_kind == "after_previous_token":
            selected_offset = lower
        elif boundary_kind == "before_next_token":
            selected_offset = upper
        elif boundary_kind == "after_newline":
            newline_offsets = [
                position + 1
                for position in range(lower, upper)
                if data[position:position + 1] == b"\n"
            ]
            selected = [
                offset for offset in newline_offsets
                if source_overlay_structural_seat(data, offset, boundary)
                == anchor["structural_seat"]
            ]
            require(len(selected) == 1,
                    f"{context} has no unique after-newline structural seat")
            selected_offset = selected[0]
        else:
            raise ByteIdentityError(f"{context} byte boundary is unsupported")
        if boundary_kind != "after_newline":
            require(
                source_overlay_structural_seat(
                    data, selected_offset, boundary
                ) == anchor["structural_seat"],
                f"{context} structural byte seat differs",
            )
        if evidence is not None:
            require(all(isinstance(item, str) and item
                        for item in (logical_path, operation_id, role)),
                    f"{context} evidence identity is incomplete")
            evidence.append({
                "logical_path": logical_path,
                "operation_id": operation_id,
                "role": role,
                "selected_context_tokens_each_side":
                    tier["context_tokens_each_side"],
                "selected_token_boundary": index,
                "selected_byte_offset": selected_offset,
                "context_sha256": tier["context_sha256"],
                "structural_seat": anchor["structural_seat"],
            })
        return selected_offset
    raise ByteIdentityError(f"{context} is missing at every anchor tier")


def _source_overlay_identifier(value: object, context: str) -> str:
    require(isinstance(value, str)
            and SOURCE_OVERLAY_IDENTIFIER_RE.fullmatch(value) is not None,
            f"{context} must be a C/C++ identifier")
    return value


def _source_overlay_qualified_identifier(value: object, context: str) -> str:
    require(isinstance(value, str)
            and SOURCE_OVERLAY_QUALIFIED_IDENTIFIER_RE.fullmatch(value) is not None,
            f"{context} must be a qualified C/C++ identifier")
    return value


def _source_overlay_census_identifier(value: object, context: str) -> str:
    require(isinstance(value, str) and 1 <= len(value) <= 256
            and value.isascii() and not any(
                character in value for character in "\0\n\r\t;{}#<>\\\"'"
            ), f"{context} is not one safe census identity")
    if SOURCE_OVERLAY_QUALIFIED_IDENTIFIER_RE.fullmatch(value) is not None:
        return value
    if re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_~][A-Za-z0-9_]*)+",
        value,
    ) is not None:
        return value
    if re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)+"
        r"\(\) const",
        value,
    ) is not None:
        return value
    try:
        return source_overlay_relative_path(value, context)
    except ByteIdentityError as error:
        raise ByteIdentityError(f"{context} is not one closed census identity") from error


def validate_source_overlay_fragment(
    value: object, context: str, *, emission_class: str,
    structural_effect: str,
) -> dict:
    require(isinstance(value, dict), f"{context} must be an object")
    exact_audit_keys(value, {
        "baseline_sha256", "baseline_size", "baseline_line_count",
        "baseline_significant_token_sha256", "declared_identifiers",
        "referenced_identifiers", "emitted_identifiers",
        "structural_effect",
    }, context)
    census = {}
    for key in (
        "declared_identifiers", "referenced_identifiers",
        "emitted_identifiers",
    ):
        raw = value.get(key)
        require(isinstance(raw, list), f"{context}.{key} must be an array")
        normalized = [
            _source_overlay_census_identifier(
                item, f"{context}.{key}[{index}]"
            )
            for index, item in enumerate(raw)
        ]
        require(normalized == sorted(set(normalized)),
                f"{context}.{key} must be sorted/unique")
        census[key] = normalized
    require(value.get("structural_effect") == structural_effect,
            f"{context}.structural_effect differs")
    if emission_class in {
        "source_layout_only", "include_dependency", "compiler_state_only",
        "non_emitting_declaration",
    }:
        require(not census["emitted_identifiers"],
                f"{context} non-emitting generator claims an emitted identity")
    return {
        "baseline_sha256": require_sha(
            value.get("baseline_sha256"), context + ".baseline_sha256"
        ),
        "baseline_size": require_exact_int(
            value.get("baseline_size"), context + ".baseline_size",
            minimum=0, maximum=64 * 1024 * 1024,
        ),
        "baseline_line_count": require_exact_int(
            value.get("baseline_line_count"), context + ".baseline_line_count",
            minimum=0, maximum=2_000_000,
        ),
        "baseline_significant_token_sha256": require_sha(
            value.get("baseline_significant_token_sha256"),
            context + ".baseline_significant_token_sha256",
        ),
        **census,
        "structural_effect": structural_effect,
    }


def validate_source_overlay_range_pin(value: object, context: str) -> dict:
    """Validate an exact byte-and-token identity for a destructive range."""
    require(isinstance(value, dict), f"{context} must be an object")
    exact_audit_keys(value, {
        "baseline_sha256", "baseline_size", "baseline_line_count",
        "baseline_significant_token_sha256",
    }, context)
    return {
        "baseline_sha256": require_sha(
            value.get("baseline_sha256"), context + ".baseline_sha256"
        ),
        "baseline_size": require_exact_int(
            value.get("baseline_size"), context + ".baseline_size",
            minimum=0, maximum=64 * 1024 * 1024,
        ),
        "baseline_line_count": require_exact_int(
            value.get("baseline_line_count"), context + ".baseline_line_count",
            minimum=0, maximum=2_000_000,
        ),
        "baseline_significant_token_sha256": require_sha(
            value.get("baseline_significant_token_sha256"),
            context + ".baseline_significant_token_sha256",
        ),
    }


def require_source_overlay_range_pin(
    data: bytes, expected: dict, context: str,
) -> dict:
    """Authenticate one already-resolved clean-input byte range."""
    actual = {
        "actual_removed_range_sha256": sha256_bytes(data),
        "actual_removed_range_size": len(data),
        "actual_removed_range_line_count": data.count(b"\n"),
        "actual_removed_range_significant_token_sha256":
            source_overlay_significant_sha256(data),
    }
    require(
        actual["actual_removed_range_sha256"] == expected["baseline_sha256"]
        and actual["actual_removed_range_size"] == expected["baseline_size"]
        and actual["actual_removed_range_line_count"]
        == expected["baseline_line_count"]
        and actual["actual_removed_range_significant_token_sha256"]
        == expected["baseline_significant_token_sha256"],
        f"{context} differs from its authenticated input-range pins",
    )
    return actual


def _source_overlay_identifier_list(
    value: object, context: str, *, minimum: int = 0, maximum: int = 4096,
) -> list[str]:
    require(isinstance(value, list) and minimum <= len(value) <= maximum,
            f"{context} has an invalid length")
    return [
        _source_overlay_identifier(item, f"{context}[{index}]")
        for index, item in enumerate(value)
    ]


def _source_overlay_qualified_parts(value: object, context: str) -> list[str]:
    parts = _source_overlay_identifier_list(
        value, context, minimum=1, maximum=16
    )
    return parts


def _source_overlay_member_identifier(value: object, context: str) -> str:
    require(isinstance(value, str) and value,
            f"{context} must be a member identifier")
    if value.startswith("~"):
        _source_overlay_identifier(value[1:], context + ".destructor")
        return value
    return _source_overlay_identifier(value, context)


def validate_source_overlay_expression(value: object, context: str) -> dict:
    require(isinstance(value, dict), f"{context} must be an object")
    kind = value.get("kind")
    if kind == "integer_literal":
        exact_audit_keys(value, {"kind", "value"}, context)
        return {
            "kind": kind,
            "value": require_exact_int(
                value.get("value"), context + ".value",
                minimum=0, maximum=(1 << 31) - 1,
            ),
        }
    if kind in {"null_cast", "null_cast_dereference"}:
        exact_audit_keys(value, {"kind", "type"}, context)
        return {
            "kind": kind,
            "type": validate_source_overlay_cpp_type(
                value.get("type"), context + ".type"
            ),
        }
    if kind == "identifier":
        exact_audit_keys(value, {"kind", "identifier"}, context)
        return {
            "kind": kind,
            "identifier": _source_overlay_identifier(
                value.get("identifier"), context + ".identifier"
            ),
        }
    raise ByteIdentityError(f"{context}.kind is unsupported")


def render_source_overlay_expression(value: dict) -> str:
    kind = value["kind"]
    if kind == "integer_literal":
        return str(value["value"])
    if kind in {"null_cast", "null_cast_dereference"}:
        rendered = f'({render_source_overlay_cpp_type(value["type"])}) 0'
        return "*" + rendered if kind == "null_cast_dereference" else rendered
    if kind == "identifier":
        return value["identifier"]
    raise ByteIdentityError(f"typed source expression is unsupported: {kind}")


def validate_source_overlay_cpp_type(
    value: object, context: str, *, depth: int = 0,
) -> dict:
    """Validate the closed C++ type AST shared by generator kinds."""
    require(depth <= 8, f"{context} exceeds the type recursion bound")
    require(isinstance(value, dict), f"{context} must be an object")
    exact_audit_keys(value, {
        "kind", "base", "base_const", "indirection", "trailing_const",
    }, context)
    require(value.get("kind") == "cpp_type"
            and type(value.get("base_const")) is bool
            and type(value.get("trailing_const")) is bool,
            f"{context} type policy differs")
    indirection = value.get("indirection")
    require(isinstance(indirection, list) and len(indirection) <= 2
            and all(item in {"pointer", "lvalue_reference"}
                    for item in indirection)
            and indirection.count("pointer") <= 1
            and indirection.count("lvalue_reference") <= 1,
            f"{context}.indirection differs")
    base = value.get("base")
    require(isinstance(base, dict), f"{context}.base must be an object")
    base_kind = base.get("kind")
    if base_kind == "builtin":
        exact_audit_keys(base, {"kind", "specifier_sequence"}, context + ".base")
        specifiers = base.get("specifier_sequence")
        require(isinstance(specifiers, list) and 1 <= len(specifiers) <= 3
                and all(item in {
                    "void", "bool", "char", "short", "int", "long",
                    "signed", "unsigned", "float", "double",
                } for item in specifiers),
                f"{context}.base.specifier_sequence differs")
        normalized_base = {
            "kind": "builtin", "specifier_sequence": list(specifiers)
        }
    elif base_kind == "named":
        exact_audit_keys(base, {"kind", "qualified_identifier"}, context + ".base")
        normalized_base = {
            "kind": "named",
            "qualified_identifier": _source_overlay_qualified_parts(
                base.get("qualified_identifier"),
                context + ".base.qualified_identifier",
            ),
        }
    elif base_kind == "template_id":
        exact_audit_keys(base, {
            "kind", "qualified_identifier", "arguments",
        }, context + ".base")
        arguments = base.get("arguments")
        require(isinstance(arguments, list) and 1 <= len(arguments) <= 16,
                f"{context}.base.arguments has an invalid length")
        normalized_base = {
            "kind": "template_id",
            "qualified_identifier": _source_overlay_qualified_parts(
                base.get("qualified_identifier"),
                context + ".base.qualified_identifier",
            ),
            "arguments": [
                validate_source_overlay_cpp_type(
                    item, f"{context}.base.arguments[{index}]", depth=depth + 1
                )
                for index, item in enumerate(arguments)
            ],
        }
    else:
        raise ByteIdentityError(f"{context}.base.kind is unsupported")
    return {
        "kind": "cpp_type", "base": normalized_base,
        "base_const": value["base_const"],
        "indirection": list(indirection),
        "trailing_const": value["trailing_const"],
    }


def render_source_overlay_cpp_type(value: dict) -> str:
    base = value["base"]
    if base["kind"] == "builtin":
        rendered = " ".join(base["specifier_sequence"])
    else:
        rendered = "::".join(base["qualified_identifier"])
        if base["kind"] == "template_id":
            rendered += "<" + ", ".join(
                render_source_overlay_cpp_type(item)
                for item in base["arguments"]
            ) + ">"
    if value["base_const"]:
        rendered = "const " + rendered
    trailing_const_rendered = False
    for item in value["indirection"]:
        if item == "pointer":
            rendered += "*"
            if value["trailing_const"]:
                rendered += " const"
                trailing_const_rendered = True
        else:
            rendered += "&"
    if value["trailing_const"] and not trailing_const_rendered:
        rendered += " const"
    return rendered


def validate_source_overlay_parameter(value: object, context: str) -> dict:
    require(isinstance(value, dict), f"{context} must be an object")
    require(set(value) in ({"type"}, {"identifier", "type"}),
            f"{context} has unexpected fields")
    result = {
        "type": validate_source_overlay_cpp_type(
            value.get("type"), context + ".type"
        )
    }
    if "identifier" in value:
        result["identifier"] = _source_overlay_identifier(
            value.get("identifier"), context + ".identifier"
        )
    return result


def render_source_overlay_parameter(value: dict) -> str:
    rendered = render_source_overlay_cpp_type(value["type"])
    if "identifier" in value:
        rendered += " " + value["identifier"]
    return rendered


def validate_source_overlay_identifier_run(value: object, context: str) -> dict:
    require(isinstance(value, dict), f"{context} must be an object")
    exact_audit_keys(value, {"kind", "stem", "first", "count", "width"}, context)
    require(value.get("kind") == "identifier_run",
            f"{context}.kind differs")
    return {
        "kind": "identifier_run",
        "stem": _source_overlay_identifier(value.get("stem"), context + ".stem"),
        "first": require_exact_int(
            value.get("first"), context + ".first", minimum=0, maximum=1_000_000
        ),
        "count": require_exact_int(
            value.get("count"), context + ".count", minimum=1, maximum=4096
        ),
        "width": require_exact_int(
            value.get("width"), context + ".width", minimum=1, maximum=8
        ),
    }


def source_overlay_expand_identifier_run(value: dict) -> list[str]:
    return [
        value["stem"] + str(index).zfill(value["width"])
        for index in range(value["first"], value["first"] + value["count"])
    ]


def validate_source_overlay_identifier_collection(
    value: object, context: str, *, maximum: int = 4096,
) -> list[str] | dict:
    if isinstance(value, list):
        identifiers = _source_overlay_identifier_list(
            value, context, minimum=0, maximum=maximum,
        )
        require(identifiers == list(dict.fromkeys(identifiers)),
                f"{context} contains duplicate identifiers")
        return identifiers
    run = validate_source_overlay_identifier_run(value, context)
    require(run["count"] <= maximum, f"{context} exceeds its maximum")
    return run


def source_overlay_expand_identifier_collection(value: list[str] | dict) -> list[str]:
    return (
        list(value) if isinstance(value, list)
        else source_overlay_expand_identifier_run(value)
    )


def source_overlay_named_type_identities(value: object) -> list[str]:
    """Collect source-spelled named/template type identities from typed ASTs."""
    result = set()
    pending = [value]
    while pending:
        node = pending.pop()
        if isinstance(node, list):
            pending.extend(node)
        elif isinstance(node, dict):
            qualified = node.get("qualified_identifier")
            if (node.get("kind") in {"named", "template_id"}
                    and isinstance(qualified, list)):
                result.add("::".join(qualified))
            pending.extend(node.values())
    return sorted(result)


def source_overlay_expected_identifier_roles(
    kind: str, params: dict,
) -> dict[str, list[str]]:
    """Derive the exact output-affecting declaration/reference/emission sets.

    These roles are recomputed solely from normalized typed parameters.  The
    manifest census is an assertion and cannot mint or reclassify a symbol.
    """
    declared: set[str] = set()
    referenced: set[str] = set()
    emitted: set[str] = set()

    def definition(identifier: str) -> None:
        declared.add(identifier)
        emitted.add(identifier)

    def identifiers(value: object) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return source_overlay_expand_identifier_collection(value)

    if kind == "declaration_sequence_v1":
        referenced.update(source_overlay_named_type_identities(params))
        owners = identifiers(params.get("identifier"))
        declared.update(owners)
        declared.update(identifiers(params.get("identifiers")))
        declared.update(
            item["identifier"] for item in params.get("enumerators", [])
        )
        for owner in owners:
            declared.update(
                f'{owner}::{member["identifier"]}'
                for member in params.get("members", [])
            )
    elif kind == "record_header_v1":
        recipe = params["typed_recipe"]
        for item in recipe["items"]:
            if isinstance(item, str):
                declared.add(item)
                if recipe["kind"] == "unused_class_with_inline_void_methods":
                    policy = recipe["method_identifier_policy"]
                    if policy == "single_unindexed_record":
                        declared.add(f"{item}::Record")
                    else:
                        declared.update(
                            f"{item}::Record{index}"
                            for index in range(recipe["methods_per_class"])
                        )
            else:
                declared.update((item["name"], item["enumerator"]))
    elif kind == "conditional_declarations_v1":
        referenced.add(params["condition"]["macro_identifier"])
    elif kind in {
        "line_reservation_v1", "include_dependency_v1", "include_seat_v1",
        "empty_compound_statements_v1", "synthetic_constant_pool_tu_v1",
    }:
        pass
    elif kind == "inline_budget_noop_statements_v1":
        referenced.add(params["assignment_target"])
    elif kind == "local_symbol_id_carrier_v1":
        declared.update(params["identifiers"])
        referenced.add(params["type"])
    elif kind == "debug_assert_reseat_v1":
        dead_local = params.get("dead_local")
        if dead_local:
            declared.update(dead_local["identifiers"])
            referenced.add(dead_local["type"])
        if "condition" in params:
            referenced.update({
                "grec": {"grec"}, "donut": {"donut"},
                "proi": {"proi"}, "r2": {"r2"},
                "v1_and_v2": {"v1", "v2"},
            }[params["condition"]])
        else:
            referenced.update({
                "p_ammo", "m_world", "m_boundary", "m_pathController",
                "m_grec",
            })
    elif kind == "compile_time_layout_assert_seat_v1":
        referenced.update(item["type"] for item in params["assertions"])
    elif kind == "literal_first_use_alias_v1":
        if "type" in params:
            declared.add(params["local_identifier"])
            referenced.update(source_overlay_named_type_identities(params["type"]))
        else:
            referenced.add(params["local_identifier"])
    elif kind == "list_cursor_delete_emission_probe_v1":
        definition(params["function_identifier"])
        referenced.update((
            params["container_type"], params["cursor_type"],
            params["element_type"],
        ))
    elif kind == "qualified_member_comdat_emission_probe_v1":
        definition(params["function_identifier"])
        referenced.update(
            source_overlay_named_type_identities(params["receiver_type"])
        )
        target = "::".join(params["qualified_member"])
        referenced.add(target)
        emitted.add(target)
    elif kind == "discarded_console_crt_pull_v1":
        definition(params["function_identifier"])
        referenced.add(params["timer_type"])
        referenced.update(params["import_calls"])
        referenced.update(
            f'{params["timer_type"]}::{group["timer_member_call"]}'
            for group in params["control_flow"]["case_groups"]
        )
    elif kind == "discarded_import_library_probe_v1":
        definition(params["function_identifier"])
        referenced.update((
            params["api"], params["capabilities_type"],
            params["tested_flag"],
        ))
    elif kind == "recursive_frame_texture_refresh_probe_v1":
        definition(params["function_identifier"])
        referenced.update(
            source_overlay_named_type_identities(params["parameter_type"])
        )
        referenced.add(params["pull_identity"])
    elif kind == "synthetic_crt_pull_v1":
        definition(params["function_identifier"])
        referenced.update(
            source_overlay_named_type_identities(params["parameter"]["type"])
        )
    elif kind == "archive_pull_seed_function_v1":
        definition(params["function_identifier"])
        referenced.update(source_overlay_named_type_identities(params["calls"]))
        referenced.update(
            "::".join(call["qualified_member"])
            for call in params["calls"]
        )
    elif kind == "archive_pull_seed_sequence_v1":
        definition(params["function_identifier"])
        referenced.update(
            source_overlay_named_type_identities(params["declarations"])
        )
        referenced.update(
            source_overlay_named_type_identities(params["statements"])
        )
        for declaration in params["declarations"]:
            owner = declaration.get("identifier")
            if owner:
                declared.add(owner)
            declared.update(
                f'{owner}::{member["identifier"]}'
                for member in declaration.get("members", [])
            )
        for statement in params["statements"]:
            statement_kind = statement["kind"]
            if statement_kind == "discarded_new":
                for type_name in source_overlay_named_type_identities(
                    statement["type"]
                ):
                    referenced.add(
                        f'{type_name}::{type_name.rsplit("::", 1)[-1]}'
                    )
            elif statement_kind == "free_call":
                referenced.add(statement["function_identifier"])
            elif statement_kind in {
                "qualified_call", "null_receiver_qualified_call",
            }:
                referenced.add("::".join(
                    statement["qualifier"] + [statement["member_identifier"]]
                ))
            else:
                require(statement_kind == "volatile_local_binding",
                        "typed archive seed statement kind is unsupported")
                referenced.add(statement["initializer"]["identifier"])
    elif kind == "source_range_relocation_v1":
        if params.get("role") != "destination_include_seat":
            identity = params.get("range_identity") or params.get(
                "logical_header"
            )
            require(identity, "source relocation definition lacks an identity")
            definition(identity)
    elif kind in {
        "synthetic_template_member_supplier_v1",
        "synthetic_member_call_supplier_v1",
    }:
        referenced.update(source_overlay_named_type_identities(params))
        prefix = params["prefix_declarations"]
        for name in (
            "forward_class_identifiers", "empty_class_identifiers",
            "value_counter_class_identifiers", "range_class_identifiers",
        ):
            declared.update(identifiers(prefix[name]))
        for enum in prefix["enum_declarations"]:
            declared.update((enum["identifier"], enum["enumerator"]))
        for counter in identifiers(prefix["value_counter_class_identifiers"]):
            declared.update((
                f"{counter}::GetValue", f"{counter}::m_value",
            ))
        for range_class in identifiers(prefix["range_class_identifiers"]):
            declared.update((
                f"{range_class}::GetFirst", f"{range_class}::GetLast",
                f"{range_class}::m_first", f"{range_class}::m_last",
            ))
        if kind == "synthetic_template_member_supplier_v1":
            declared.add(params["container_alias"]["identifier"])
            for probe in params["probes"]:
                probe_id = probe["probe_identifier"]
                get_id = f"{probe_id}::Get"
                declared.update((probe_id, f"{probe_id}::Fn", get_id))
                emitted.add(get_id)
                target = "::".join(probe["target_qualified_identifier"])
                referenced.add(target)
                emitted.add(target)
        else:
            wrapper = params["wrapper"]
            definition(wrapper["function_identifier"])
            owner_types = source_overlay_named_type_identities(
                wrapper["parameter"]["type"]
            )
            require(len(owner_types) == 1,
                    "member-call supplier wrapper owner is not singular")
            target = f"{owner_types[0]}::erase"
            referenced.add(target)
            emitted.add(target)
            for relocated in params["relocated_ranges"]:
                definition(relocated["range_identity"])
    elif kind == "synthetic_discarded_relocation_ring_v1":
        functions = {
            f'{params["function_identifier_stem"]}'
            f'{index:0{params["function_identifier_width"]}d}'
            for index in range(params["function_count"])
        }
        declared.update(functions)
        referenced.update(functions)
        emitted.update(functions)
    elif kind == "composed_typed_sequence_v1":
        for item in params["items"]:
            child = item["generator"]["baseline_fragment"]
            declared.update(child["declared_identifiers"])
            referenced.update(child["referenced_identifiers"])
            emitted.update(child["emitted_identifiers"])
    else:
        raise ByteIdentityError(
            f"source overlay role derivation is absent: {kind}"
        )
    return {
        "declared_identifiers": sorted(declared),
        "referenced_identifiers": sorted(referenced),
        "emitted_identifiers": sorted(emitted),
    }


def iter_source_overlay_leaf_generators(generator: dict):
    """Yield the physical rendering owners beneath a composite summary."""
    if generator["kind"] == "composed_typed_sequence_v1":
        for item in generator["params"]["items"]:
            yield from iter_source_overlay_leaf_generators(item["generator"])
        return
    yield generator


def source_overlay_generator_identity_scope(generator: dict) -> str:
    """Derive the closed C++ scope used for declaration collisions."""
    kind = generator["kind"]
    params = generator["params"]
    if kind == "local_symbol_id_carrier_v1":
        return f'function:{params["function"]}'
    if kind == "debug_assert_reseat_v1" and params.get("dead_local"):
        return f'function:{params["carrier_function"]}'
    if kind == "literal_first_use_alias_v1":
        return f'function:{params["owner_function"]}'
    return "output_scope"


def validate_source_overlay_renderer_layout(
    value: object, context: str,
) -> dict:
    """Validate one complete, renderer-owned physical line canvas.

    Semantic generators produce only ordered nonblank lines.  This envelope
    is the sole authority for physical placement, indentation, transparent
    whitespace lines and the terminal LF.  Expected fragment hashes are
    therefore checks on rendering, never inputs which can choose formatting.
    """
    require(isinstance(value, dict), f"{context} must be an object")
    exact_audit_keys(value, {
        "kind", "physical_line_count", "content_lines",
        "transparent_line_runs", "line_ending", "terminal_newline",
    }, context)
    require(value.get("kind") == "typed_line_canvas_v1",
            f"{context}.kind differs")
    physical_count = require_exact_int(
        value.get("physical_line_count"), context + ".physical_line_count",
        minimum=0, maximum=2_000_000,
    )
    line_ending = value.get("line_ending")
    terminal_newline = value.get("terminal_newline")
    require(line_ending in {"lf", "none"}
            and type(terminal_newline) is bool,
            f"{context} newline policy differs")
    require(
        (physical_count == 0 and line_ending == "none"
         and terminal_newline is False)
        or (physical_count == 1 and line_ending == "none"
            and terminal_newline is False)
        or (physical_count >= 1 and line_ending == "lf"),
        f"{context} physical/newline policy is inconsistent",
    )

    def indentation_units(raw: object, item_context: str) -> list[dict]:
        require(isinstance(raw, list) and len(raw) <= 32,
                f"{item_context} must be a bounded array")
        result = []
        previous = None
        for index, item in enumerate(raw):
            unit_context = f"{item_context}[{index}]"
            require(isinstance(item, dict),
                    f"{unit_context} must be an object")
            exact_audit_keys(item, {"unit", "count"}, unit_context)
            unit = item.get("unit")
            require(unit in {"tab", "space"} and unit != previous,
                    f"{unit_context}.unit differs or is noncanonical")
            previous = unit
            result.append({
                "unit": unit,
                "count": require_exact_int(
                    item.get("count"), unit_context + ".count",
                    minimum=1, maximum=4096,
                ),
            })
        return result

    raw_content = value.get("content_lines")
    require(isinstance(raw_content, list),
            f"{context}.content_lines must be an array")
    content = []
    content_physical = set()
    for index, item in enumerate(raw_content):
        item_context = f"{context}.content_lines[{index}]"
        require(isinstance(item, dict), f"{item_context} must be an object")
        exact_audit_keys(
            item, {"semantic_line", "relative_line", "indentation_units"},
            item_context,
        )
        semantic = require_exact_int(
            item.get("semantic_line"), item_context + ".semantic_line",
            minimum=index + 1, maximum=index + 1,
        )
        relative = require_exact_int(
            item.get("relative_line"), item_context + ".relative_line",
            minimum=1, maximum=max(1, physical_count),
        )
        require(physical_count > 0 and relative not in content_physical,
                f"{item_context}.relative_line is duplicated or out of range")
        content_physical.add(relative)
        content.append({
            "semantic_line": semantic,
            "relative_line": relative,
            "indentation_units": indentation_units(
                item.get("indentation_units"),
                item_context + ".indentation_units",
            ),
        })

    raw_runs = value.get("transparent_line_runs")
    require(isinstance(raw_runs, list),
            f"{context}.transparent_line_runs must be an array")
    runs = []
    transparent_physical = set()
    previous_end = 0
    for index, item in enumerate(raw_runs):
        item_context = f"{context}.transparent_line_runs[{index}]"
        require(isinstance(item, dict), f"{item_context} must be an object")
        exact_audit_keys(
            item, {"first", "count", "indentation_units"}, item_context
        )
        first = require_exact_int(
            item.get("first"), item_context + ".first",
            minimum=1, maximum=max(1, physical_count),
        )
        count = require_exact_int(
            item.get("count"), item_context + ".count",
            minimum=1, maximum=max(1, physical_count),
        )
        last = first + count - 1
        require(physical_count > 0 and first > previous_end
                and last <= physical_count,
                f"{item_context} is unsorted, overlapping, or out of range")
        previous_end = last
        lines = set(range(first, last + 1))
        require(not lines.intersection(content_physical),
                f"{item_context} overlaps a semantic content line")
        transparent_physical.update(lines)
        runs.append({
            "first": first, "count": count,
            "indentation_units": indentation_units(
                item.get("indentation_units"),
                item_context + ".indentation_units",
            ),
        })
    require(
        content_physical.union(transparent_physical)
        == set(range(1, physical_count + 1)),
        f"{context} does not classify every physical line exactly once",
    )
    return {
        "kind": "typed_line_canvas_v1",
        "physical_line_count": physical_count,
        "content_lines": content,
        "transparent_line_runs": runs,
        "line_ending": line_ending,
        "terminal_newline": terminal_newline,
    }


def source_overlay_layout_line_count(layout: dict) -> int:
    count = layout["physical_line_count"]
    if layout["line_ending"] == "none":
        return 0
    return count if layout["terminal_newline"] else max(0, count - 1)


def source_overlay_generator_policy(kind: str, params: dict) -> tuple[str, str]:
    if kind != "source_range_relocation_v1":
        policy = SOURCE_OVERLAY_KIND_POLICIES.get(kind)
        require(policy is not None,
                f"source overlay generator kind is unsupported: {kind}")
        return policy
    if params.get("role") == "destination_include_seat":
        return "include_dependency", "source_relocation_include_seat"
    return "source_relocation", "authenticated_source_range_owner_transfer"


def validate_source_overlay_generator(value: object, context: str) -> dict:
    """Validate the closed initial typed-generator registry.

    Production kinds are added here with exact recursive schemas.  There is no
    generic text/template/command escape hatch, and descriptive metadata never
    reaches a renderer.
    """
    require(isinstance(value, dict), f"{context} must be an object")
    kind = value.get("kind")
    raw_params = value.get("params")
    require(isinstance(kind, str) and isinstance(raw_params, dict),
            f"{context} kind/params are invalid")
    exact_audit_keys(
        value,
        {"kind", "emission_class", "params", "baseline_fragment"},
        context,
    )
    param_context = context + ".params"
    layout = validate_source_overlay_renderer_layout(
        raw_params.get("renderer_layout"),
        param_context + ".renderer_layout",
    )
    params = {
        key: item for key, item in raw_params.items()
        if key != "renderer_layout"
    }
    if kind == "line_reservation_v1":
        exact_audit_keys(params, {"content_role", "physical_line_count"}, param_context)
        require(params.get("content_role") == "renderer_owned_layout_comment",
                f"{param_context}.content_role differs")
        normalized = {
            "content_role": params["content_role"],
            "physical_line_count": require_exact_int(
                params.get("physical_line_count"),
                param_context + ".physical_line_count", minimum=1, maximum=4096,
            ),
        }
    elif kind == "include_dependency_v1":
        exact_audit_keys(params, {"header", "style"}, param_context)
        header = params.get("header")
        require(isinstance(header, str) and header and len(header) <= 256
                and "\\" not in header and "\0" not in header
                and not PurePosixPath(header).is_absolute()
                and ".." not in PurePosixPath(header).parts
                and all(character not in header for character in '<>"\'\n\r'),
                f"{param_context}.header is unsafe")
        require(params.get("style") in {"angle", "quote"},
                f"{param_context}.style differs")
        normalized = {"header": header, "style": params["style"]}
    elif kind == "include_seat_v1":
        exact_audit_keys(params, {"basename", "logical_header", "style"}, param_context)
        logical = source_overlay_relative_path(
            params.get("logical_header"), param_context + ".logical_header"
        )
        basename = params.get("basename")
        require(isinstance(basename, str) and basename == PurePosixPath(logical).name,
                f"{param_context}.basename differs from logical_header")
        require(params.get("style") in {"angle", "quote"},
                f"{param_context}.style differs")
        normalized = {
            "basename": basename, "logical_header": logical,
            "style": params["style"],
        }
    elif kind == "empty_compound_statements_v1":
        exact_audit_keys(params, {"scope_count"}, param_context)
        normalized = {"scope_count": require_exact_int(
            params.get("scope_count"), param_context + ".scope_count",
            minimum=1, maximum=256,
        )}
    elif kind == "inline_budget_noop_statements_v1":
        exact_audit_keys(params, {"assignment_target", "operator", "repeat"}, param_context)
        require(params.get("operator") == "self_plus_zero",
                f"{param_context}.operator differs")
        normalized = {
            "assignment_target": _source_overlay_identifier(
                params.get("assignment_target"), param_context + ".assignment_target"
            ),
            "operator": "self_plus_zero",
            "repeat": require_exact_int(
                params.get("repeat"), param_context + ".repeat",
                minimum=1, maximum=64,
            ),
        }
    elif kind == "compile_time_layout_assert_seat_v1":
        exact_audit_keys(
            params, {"assertions", "integer_literal_format"}, param_context
        )
        integer_format = params.get("integer_literal_format")
        require(isinstance(integer_format, dict),
                f"{param_context}.integer_literal_format must be an object")
        exact_audit_keys(integer_format, {
            "base", "prefix", "digit_case", "minimum_digits",
        }, param_context + ".integer_literal_format")
        require(
            integer_format == {
                "base": "hexadecimal", "prefix": "0x",
                "digit_case": "lower", "minimum_digits": 1,
            },
            f"{param_context}.integer_literal_format differs",
        )
        assertions = params.get("assertions")
        require(isinstance(assertions, list) and assertions,
                f"{param_context}.assertions must be non-empty")
        normalized_assertions = []
        for index, assertion in enumerate(assertions):
            item_context = f"{param_context}.assertions[{index}]"
            require(isinstance(assertion, dict), f"{item_context} must be an object")
            exact_audit_keys(assertion, {"type", "size"}, item_context)
            normalized_assertions.append({
                "type": _source_overlay_qualified_identifier(
                    assertion.get("type"), item_context + ".type"
                ),
                "size": require_exact_int(
                    assertion.get("size"), item_context + ".size",
                    minimum=1, maximum=1 << 24,
                ),
            })
        normalized = {
            "assertions": normalized_assertions,
            "integer_literal_format": dict(integer_format),
        }
    elif kind == "declaration_sequence_v1":
        shape = params.get("shape")
        if shape in {"forward", "empty_class"}:
            exact_audit_keys(params, {"shape", "tag", "identifier"}, param_context)
            require(params.get("tag") in {"class", "struct"},
                    f"{param_context}.tag differs")
            normalized = {
                "shape": shape, "tag": params["tag"],
                "identifier": _source_overlay_identifier(
                    params.get("identifier"), param_context + ".identifier"
                ),
            }
        elif shape == "forward_sequence":
            exact_audit_keys(params, {"shape", "tag", "identifiers"}, param_context)
            require(params.get("tag") in {"class", "struct"},
                    f"{param_context}.tag differs")
            normalized = {
                "shape": shape, "tag": params["tag"],
                "identifiers": validate_source_overlay_identifier_run(
                    params.get("identifiers"), param_context + ".identifiers"
                ),
            }
        elif shape == "enum":
            exact_audit_keys(params, {
                "shape", "identifier", "enumerators", "trailing_comma",
            }, param_context)
            raw_enumerators = params.get("enumerators")
            require(isinstance(raw_enumerators, list)
                    and 1 <= len(raw_enumerators) <= 4096,
                    f"{param_context}.enumerators has an invalid length")
            enumerators = []
            for index, item in enumerate(raw_enumerators):
                item_context = f"{param_context}.enumerators[{index}]"
                require(isinstance(item, dict), f"{item_context} must be an object")
                exact_audit_keys(item, {"identifier"}, item_context)
                enumerators.append({
                    "identifier": _source_overlay_identifier(
                        item.get("identifier"), item_context + ".identifier"
                    )
                })
            normalized = {
                "shape": shape,
                "identifier": _source_overlay_identifier(
                    params.get("identifier"), param_context + ".identifier"
                ),
                "enumerators": enumerators,
                "trailing_comma": require_exact_bool(
                    params.get("trailing_comma"),
                    param_context + ".trailing_comma",
                ),
            }
        elif shape == "typedef_builtin":
            exact_audit_keys(params, {"shape", "aliased_type", "identifier"}, param_context)
            require(params.get("aliased_type") in {
                "char", "short", "int", "long", "unsigned int",
            }, f"{param_context}.aliased_type differs")
            normalized = {
                "shape": shape, "aliased_type": params["aliased_type"],
                "identifier": _source_overlay_identifier(
                    params.get("identifier"), param_context + ".identifier"
                ),
            }
        elif shape == "function_prototype":
            exact_audit_keys(params, {
                "shape", "identifier", "return_type", "parameters",
            }, param_context)
            raw_parameters = params.get("parameters")
            require(isinstance(raw_parameters, list) and len(raw_parameters) <= 32,
                    f"{param_context}.parameters has an invalid length")
            normalized = {
                "shape": shape,
                "identifier": _source_overlay_identifier(
                    params.get("identifier"), param_context + ".identifier"
                ),
                "return_type": validate_source_overlay_cpp_type(
                    params.get("return_type"), param_context + ".return_type"
                ),
                "parameters": [
                    validate_source_overlay_parameter(
                        item, f"{param_context}.parameters[{index}]"
                    ) for index, item in enumerate(raw_parameters)
                ],
            }
        elif shape == "unused_class_void_member_sequence":
            exact_audit_keys(params, {
                "shape", "tag", "identifier", "members",
                "access_transitions",
            }, param_context)
            require(params.get("tag") in {"class", "struct"},
                    f"{param_context}.tag differs")
            raw_members = params.get("members")
            require(isinstance(raw_members, list)
                    and 1 <= len(raw_members) <= 256,
                    f"{param_context}.members has an invalid length")
            members = []
            member_identifiers = set()
            for index, item in enumerate(raw_members):
                item_context = f"{param_context}.members[{index}]"
                require(isinstance(item, dict),
                        f"{item_context} must be an object")
                exact_audit_keys(item, {
                    "kind", "identifier", "inline_specifier", "access",
                }, item_context)
                member_kind = item.get("kind")
                require(member_kind in {
                    "empty_void_method_definition", "void_method_declaration",
                }, f"{item_context}.kind differs")
                inline = require_exact_bool(
                    item.get("inline_specifier"),
                    item_context + ".inline_specifier",
                )
                require(
                    (member_kind == "empty_void_method_definition" or not inline),
                    f"{item_context} declaration cannot be inline",
                )
                access = item.get("access")
                require(access in {"implicit_default", "public"},
                        f"{item_context}.access differs")
                identifier = _source_overlay_identifier(
                    item.get("identifier"), item_context + ".identifier"
                )
                require(identifier not in member_identifiers,
                        f"{item_context}.identifier is duplicated")
                member_identifiers.add(identifier)
                members.append({
                    "kind": member_kind, "identifier": identifier,
                    "inline_specifier": inline, "access": access,
                })
            raw_transitions = params.get("access_transitions")
            require(isinstance(raw_transitions, list)
                    and len(raw_transitions) <= len(members),
                    f"{param_context}.access_transitions has an invalid length")
            transitions = []
            previous_index = -1
            for index, item in enumerate(raw_transitions):
                item_context = f"{param_context}.access_transitions[{index}]"
                require(isinstance(item, dict),
                        f"{item_context} must be an object")
                exact_audit_keys(item, {"access", "before_member_index"}, item_context)
                require(item.get("access") == "public",
                        f"{item_context}.access differs")
                before = require_exact_int(
                    item.get("before_member_index"),
                    item_context + ".before_member_index",
                    minimum=0, maximum=len(members) - 1,
                )
                require(before > previous_index,
                        f"{item_context}.before_member_index is not increasing")
                previous_index = before
                transitions.append({"access": "public", "before_member_index": before})
            transition_by_index = {
                item["before_member_index"]: item["access"]
                for item in transitions
            }
            active_access = "implicit_default"
            for index, member in enumerate(members):
                if index in transition_by_index:
                    active_access = transition_by_index[index]
                require(member["access"] == active_access,
                        f"{param_context}.members[{index}].access differs from transitions")
            normalized = {
                "shape": shape, "tag": params["tag"],
                "identifier": _source_overlay_identifier(
                    params.get("identifier"), param_context + ".identifier"
                ),
                "members": members, "access_transitions": transitions,
            }
        else:
            raise ByteIdentityError(f"{param_context}.shape is unsupported")
    elif kind == "conditional_declarations_v1":
        exact_audit_keys(params, {
            "branch_policy", "condition", "physical_line_count",
            "branch_topology", "directive_sequence",
        }, param_context)
        require(params.get("branch_policy") == "typed_declarations_only",
                f"{param_context}.branch_policy differs")
        condition = params.get("condition")
        require(isinstance(condition, dict),
                f"{param_context}.condition must be an object")
        exact_audit_keys(condition, {"macro_identifier", "polarity"},
                         param_context + ".condition")
        require(condition.get("polarity") == "ifdef",
                f"{param_context}.condition.polarity differs")
        normalized = {
            "branch_policy": "typed_declarations_only",
            "condition": {
                "macro_identifier": _source_overlay_identifier(
                    condition.get("macro_identifier"),
                    param_context + ".condition.macro_identifier",
                ),
                "polarity": condition["polarity"],
            },
            "physical_line_count": require_exact_int(
                params.get("physical_line_count"),
                param_context + ".physical_line_count",
                minimum=2, maximum=4096,
            ),
        }
        topology = params.get("branch_topology")
        require(topology in {"ifdef_endif", "ifdef_else_endif"},
                f"{param_context}.branch_topology differs")
        raw_directives = params.get("directive_sequence")
        expected_directives = (
            ["ifdef", "endif"] if topology == "ifdef_endif"
            else ["ifdef", "else", "endif"]
        )
        require(isinstance(raw_directives, list)
                and len(raw_directives) == len(expected_directives),
                f"{param_context}.directive_sequence differs")
        directives = []
        previous_line = 0
        for index, (item, expected_directive) in enumerate(zip(
            raw_directives, expected_directives
        )):
            item_context = f"{param_context}.directive_sequence[{index}]"
            require(isinstance(item, dict), f"{item_context} must be an object")
            expected_keys = {"directive", "relative_line"}
            if expected_directive == "ifdef":
                expected_keys.add("macro_identifier")
            exact_audit_keys(item, expected_keys, item_context)
            require(item.get("directive") == expected_directive,
                    f"{item_context}.directive differs")
            relative_line = require_exact_int(
                item.get("relative_line"), item_context + ".relative_line",
                minimum=1, maximum=normalized["physical_line_count"],
            )
            require(relative_line > previous_line,
                    f"{item_context}.relative_line is not increasing")
            previous_line = relative_line
            normalized_item = {
                "directive": expected_directive,
                "relative_line": relative_line,
            }
            if expected_directive == "ifdef":
                require(item.get("macro_identifier")
                        == normalized["condition"]["macro_identifier"],
                        f"{item_context}.macro_identifier differs")
                normalized_item["macro_identifier"] = item["macro_identifier"]
            directives.append(normalized_item)
        require(directives[0]["relative_line"] == 1
                and directives[-1]["relative_line"]
                == normalized["physical_line_count"],
                f"{param_context}.directive_sequence boundary differs")
        normalized["branch_topology"] = topology
        normalized["directive_sequence"] = directives
    elif kind == "composed_typed_sequence_v1":
        exact_audit_keys(params, {
            "physical_line_count", "comment_policy", "composition_policy",
            "items",
        }, param_context)
        require(params.get("comment_policy")
                == "strip_prose_preserve_physical_lines_v1"
                and params.get("composition_policy")
                == "line_overlay_disjoint_nonblank_conflict_reject_v2",
                f"{param_context} composition policy differs")
        physical_line_count = require_exact_int(
            params.get("physical_line_count"),
            param_context + ".physical_line_count",
            minimum=1, maximum=2_000_000,
        )
        raw_items = params.get("items")
        require(isinstance(raw_items, list) and 1 <= len(raw_items) <= 8192,
                f"{param_context}.items has an invalid length")
        normalized_items = []
        for index, item in enumerate(raw_items):
            item_context = f"{param_context}.items[{index}]"
            require(isinstance(item, dict), f"{item_context} must be an object")
            exact_audit_keys(item, {
                "index", "relative_lines", "transparent_relative_lines",
                "generator",
            }, item_context)
            require(require_exact_int(
                item.get("index"), item_context + ".index",
                minimum=index, maximum=index,
            ) == index, f"{item_context}.index differs")
            relative_lines = item.get("relative_lines")
            require(isinstance(relative_lines, list) and len(relative_lines) == 2,
                    f"{item_context}.relative_lines differs")
            first = require_exact_int(
                relative_lines[0], item_context + ".relative_lines[0]",
                minimum=1, maximum=physical_line_count,
            )
            last = require_exact_int(
                relative_lines[1], item_context + ".relative_lines[1]",
                minimum=first, maximum=physical_line_count,
            )
            transparent = item.get("transparent_relative_lines")
            require(isinstance(transparent, list)
                    and transparent == sorted(set(transparent)),
                    f"{item_context}.transparent_relative_lines must be sorted/unique")
            normalized_transparent = [
                require_exact_int(
                    line, f"{item_context}.transparent_relative_lines[{line_index}]",
                    minimum=first, maximum=last,
                ) for line_index, line in enumerate(transparent)
            ]
            normalized_items.append({
                "index": index, "relative_lines": [first, last],
                "transparent_relative_lines": normalized_transparent,
                "generator": validate_source_overlay_generator(
                    item.get("generator"), item_context + ".generator"
                ),
            })
        normalized = {
            "physical_line_count": physical_line_count,
            "comment_policy": "strip_prose_preserve_physical_lines_v1",
            "composition_policy":
                "line_overlay_disjoint_nonblank_conflict_reject_v2",
            "items": normalized_items,
        }
    elif kind == "local_symbol_id_carrier_v1":
        exact_audit_keys(params, {
            "function", "type", "identifiers",
        }, param_context)
        require(params.get("function") == "Act3Shark::EatPizza",
                f"{param_context}.function differs")
        require(params.get("type") == "MxS32",
                f"{param_context}.type differs")
        identifiers = _source_overlay_identifier_list(
            params.get("identifiers"), param_context + ".identifiers",
            minimum=2, maximum=2,
        )
        require(identifiers == ["unkRecord0", "unkRecord1"],
                f"{param_context}.identifiers differ")
        normalized = {
            "function": "Act3Shark::EatPizza", "type": "MxS32",
            "identifiers": identifiers,
        }
    elif kind == "qualified_member_comdat_emission_probe_v1":
        exact_audit_keys(params, {
            "arguments", "function_identifier", "inline_depth",
            "qualified_member", "receiver_type",
        }, param_context)
        require(params.get("function_identifier") == "TowTrackBitmapEmitter",
                f"{param_context}.function_identifier differs")
        require(require_exact_int(
            params.get("inline_depth"), param_context + ".inline_depth",
            minimum=0, maximum=0,
        ) == 0, f"{param_context}.inline_depth differs")
        qualified_member = _source_overlay_qualified_parts(
            params.get("qualified_member"),
            param_context + ".qualified_member",
        )
        require(qualified_member == ["MxBitmap", "VTable0x28"],
                f"{param_context}.qualified_member differs")
        receiver_type = validate_source_overlay_cpp_type(
            params.get("receiver_type"), param_context + ".receiver_type"
        )
        require(render_source_overlay_cpp_type(receiver_type) == "MxBitmap",
                f"{param_context}.receiver_type differs")
        arguments = params.get("arguments")
        require(isinstance(arguments, list) and len(arguments) == 1,
                f"{param_context}.arguments differ")
        argument = arguments[0]
        require(isinstance(argument, dict),
                f"{param_context}.arguments[0] must be an object")
        exact_audit_keys(argument, {"kind", "value"},
                         param_context + ".arguments[0]")
        require(argument == {"kind": "integer", "value": 0},
                f"{param_context}.arguments[0] differs")
        normalized = {
            "arguments": [{"kind": "integer", "value": 0}],
            "function_identifier": "TowTrackBitmapEmitter",
            "inline_depth": 0,
            "qualified_member": qualified_member,
            "receiver_type": receiver_type,
        }
    elif kind == "synthetic_template_member_supplier_v1":
        exact_audit_keys(params, {
            "container_alias", "include_identity", "logical_path",
            "prefix_declarations", "probes",
        }, param_context)
        logical_path = source_overlay_relative_path(
            params.get("logical_path"), param_context + ".logical_path"
        )
        include_identity = params.get("include_identity")
        require(isinstance(include_identity, str) and include_identity
                and include_identity == PurePosixPath(include_identity).name
                and all(character not in include_identity
                        for character in '\\\0<>"\'\n\r'),
                f"{param_context}.include_identity is unsafe")
        raw_prefix = params.get("prefix_declarations")
        require(isinstance(raw_prefix, dict),
                f"{param_context}.prefix_declarations must be an object")
        exact_audit_keys(raw_prefix, {
            "empty_class_identifiers", "enum_declarations",
            "forward_class_identifiers", "range_class_identifiers",
            "value_counter_class_identifiers",
        }, param_context + ".prefix_declarations")
        prefix = {
            name: validate_source_overlay_identifier_collection(
                raw_prefix.get(name),
                f"{param_context}.prefix_declarations.{name}",
                maximum=256,
            )
            for name in (
                "empty_class_identifiers", "forward_class_identifiers",
                "range_class_identifiers", "value_counter_class_identifiers",
            )
        }
        raw_enums = raw_prefix.get("enum_declarations")
        require(isinstance(raw_enums, list) and len(raw_enums) <= 256,
                f"{param_context}.prefix_declarations.enum_declarations differs")
        enum_declarations = []
        for index, item in enumerate(raw_enums):
            item_context = (
                f"{param_context}.prefix_declarations.enum_declarations[{index}]"
            )
            require(isinstance(item, dict), f"{item_context} must be an object")
            exact_audit_keys(item, {"identifier", "enumerator", "value"}, item_context)
            shift_value = item.get("value")
            require(isinstance(shift_value, dict),
                    f"{item_context}.value must be an object")
            exact_audit_keys(shift_value, {"kind", "lhs", "rhs"},
                             item_context + ".value")
            require(shift_value.get("kind") == "left_shift"
                    and require_exact_int(
                        shift_value.get("lhs"), item_context + ".value.lhs",
                        minimum=1, maximum=1,
                    ) == 1,
                    f"{item_context}.value differs")
            enum_declarations.append({
                "identifier": _source_overlay_identifier(
                    item.get("identifier"), item_context + ".identifier"
                ),
                "enumerator": _source_overlay_identifier(
                    item.get("enumerator"), item_context + ".enumerator"
                ),
                "value": {
                    "kind": "left_shift", "lhs": 1,
                    "rhs": require_exact_int(
                        shift_value.get("rhs"), item_context + ".value.rhs",
                        minimum=0, maximum=31,
                    ),
                },
            })
        prefix["enum_declarations"] = enum_declarations
        alias = params.get("container_alias")
        require(isinstance(alias, dict),
                f"{param_context}.container_alias must be an object")
        exact_audit_keys(alias, {"identifier", "type"},
                         param_context + ".container_alias")
        normalized_alias = {
            "identifier": _source_overlay_identifier(
                alias.get("identifier"), param_context + ".container_alias.identifier"
            ),
            "type": validate_source_overlay_cpp_type(
                alias.get("type"), param_context + ".container_alias.type"
            ),
        }
        raw_probes = params.get("probes")
        require(isinstance(raw_probes, list) and 1 <= len(raw_probes) <= 16,
                f"{param_context}.probes has an invalid length")
        probes = []
        probe_identifiers = set()
        for index, item in enumerate(raw_probes):
            item_context = f"{param_context}.probes[{index}]"
            require(isinstance(item, dict), f"{item_context} must be an object")
            exact_audit_keys(item, {
                "base_type", "member_pointer", "probe_identifier",
                "target_qualified_identifier",
            }, item_context)
            probe_identifier = _source_overlay_identifier(
                item.get("probe_identifier"), item_context + ".probe_identifier"
            )
            require(probe_identifier not in probe_identifiers,
                    f"{item_context}.probe_identifier is duplicated")
            probe_identifiers.add(probe_identifier)
            pointer = item.get("member_pointer")
            require(isinstance(pointer, dict),
                    f"{item_context}.member_pointer must be an object")
            exact_audit_keys(pointer, {
                "alias_identifier", "kind", "method_const", "owner_type",
                "parameters", "return_type",
            }, item_context + ".member_pointer")
            require(pointer.get("kind") == "member_function_pointer",
                    f"{item_context}.member_pointer.kind differs")
            raw_parameters = pointer.get("parameters")
            require(isinstance(raw_parameters, list)
                    and len(raw_parameters) <= 16,
                    f"{item_context}.member_pointer.parameters differs")
            probes.append({
                "base_type": validate_source_overlay_cpp_type(
                    item.get("base_type"), item_context + ".base_type"
                ),
                "member_pointer": {
                    "alias_identifier": _source_overlay_identifier(
                        pointer.get("alias_identifier"),
                        item_context + ".member_pointer.alias_identifier",
                    ),
                    "kind": "member_function_pointer",
                    "method_const": require_exact_bool(
                        pointer.get("method_const"),
                        item_context + ".member_pointer.method_const",
                    ),
                    "owner_type": validate_source_overlay_cpp_type(
                        pointer.get("owner_type"),
                        item_context + ".member_pointer.owner_type",
                    ),
                    "parameters": [
                        validate_source_overlay_parameter(
                            parameter,
                            f"{item_context}.member_pointer.parameters[{parameter_index}]",
                        )
                        for parameter_index, parameter in enumerate(raw_parameters)
                    ],
                    "return_type": validate_source_overlay_cpp_type(
                        pointer.get("return_type"),
                        item_context + ".member_pointer.return_type",
                    ),
                },
                "probe_identifier": probe_identifier,
                "target_qualified_identifier": _source_overlay_qualified_parts(
                    item.get("target_qualified_identifier"),
                    item_context + ".target_qualified_identifier",
                ),
            })
        normalized = {
            "container_alias": normalized_alias,
            "include_identity": include_identity,
            "logical_path": logical_path,
            "prefix_declarations": prefix,
            "probes": probes,
        }
    elif kind == "archive_pull_seed_function_v1":
        exact_audit_keys(params, {"calls", "function_identifier"}, param_context)
        require(params.get("function_identifier") == "SeedActionNotification",
                f"{param_context}.function_identifier differs")
        calls = params.get("calls")
        require(isinstance(calls, list) and len(calls) == 1,
                f"{param_context}.calls differs")
        call = calls[0]
        require(isinstance(call, dict),
                f"{param_context}.calls[0] must be an object")
        exact_audit_keys(call, {
            "qualified_member", "receiver", "receiver_type",
        }, param_context + ".calls[0]")
        receiver = call.get("receiver")
        require(isinstance(receiver, dict),
                f"{param_context}.calls[0].receiver must be an object")
        exact_audit_keys(receiver, {"kind"}, param_context + ".calls[0].receiver")
        require(receiver.get("kind") == "null_cast",
                f"{param_context}.calls[0].receiver.kind differs")
        receiver_type = validate_source_overlay_cpp_type(
            call.get("receiver_type"), param_context + ".calls[0].receiver_type"
        )
        require(render_source_overlay_cpp_type(receiver_type)
                == "MxStartActionNotificationParam",
                f"{param_context}.calls[0].receiver_type differs")
        qualified_member = _source_overlay_qualified_parts(
            call.get("qualified_member"),
            param_context + ".calls[0].qualified_member",
        )
        require(qualified_member
                == ["MxStartActionNotificationParam", "Clone"],
                f"{param_context}.calls[0].qualified_member differs")
        normalized = {
            "calls": [{
                "qualified_member": qualified_member,
                "receiver": {"kind": "null_cast"},
                "receiver_type": receiver_type,
            }],
            "function_identifier": "SeedActionNotification",
        }
    elif kind == "archive_pull_seed_sequence_v1":
        exact_audit_keys(params, {
            "declarations", "function_identifier", "statements",
            "undefined_binding_order",
        }, param_context)
        require(params.get("function_identifier") == "SeedOrder"
                and params.get("undefined_binding_order")
                == "reverse_statement_order_msvc_4_20",
                f"{param_context} seed policy differs")
        raw_declarations = params.get("declarations")
        require(isinstance(raw_declarations, list)
                and 1 <= len(raw_declarations) <= 256,
                f"{param_context}.declarations has an invalid length")
        declarations = []
        declaration_identifiers = set()
        for index, item in enumerate(raw_declarations):
            item_context = f"{param_context}.declarations[{index}]"
            require(isinstance(item, dict), f"{item_context} must be an object")
            declaration_kind = item.get("kind")
            if declaration_kind == "forward_record":
                exact_audit_keys(item, {"kind", "tag", "identifier"}, item_context)
                require(item.get("tag") in {"class", "struct"},
                        f"{item_context}.tag differs")
                normalized_item = {
                    "kind": declaration_kind, "tag": item["tag"],
                    "identifier": _source_overlay_identifier(
                        item.get("identifier"), item_context + ".identifier"
                    ),
                }
            elif declaration_kind == "extern_variable":
                exact_audit_keys(item, {"kind", "type", "identifier"}, item_context)
                normalized_item = {
                    "kind": declaration_kind,
                    "type": validate_source_overlay_cpp_type(
                        item.get("type"), item_context + ".type"
                    ),
                    "identifier": _source_overlay_identifier(
                        item.get("identifier"), item_context + ".identifier"
                    ),
                }
            elif declaration_kind == "function_declaration":
                exact_audit_keys(item, {
                    "kind", "identifier", "parameters", "return_type",
                }, item_context)
                raw_parameters = item.get("parameters")
                require(isinstance(raw_parameters, list)
                        and len(raw_parameters) <= 16,
                        f"{item_context}.parameters has an invalid length")
                normalized_item = {
                    "kind": declaration_kind,
                    "identifier": _source_overlay_identifier(
                        item.get("identifier"), item_context + ".identifier"
                    ),
                    "parameters": [
                        validate_source_overlay_parameter(
                            parameter, f"{item_context}.parameters[{parameter_index}]"
                        )
                        for parameter_index, parameter in enumerate(raw_parameters)
                    ],
                    "return_type": validate_source_overlay_cpp_type(
                        item.get("return_type"), item_context + ".return_type"
                    ),
                }
            elif declaration_kind == "record_definition":
                exact_audit_keys(item, {
                    "kind", "tag", "identifier", "members",
                }, item_context)
                require(item.get("tag") in {"class", "struct"},
                        f"{item_context}.tag differs")
                raw_members = item.get("members")
                require(isinstance(raw_members, list)
                        and 1 <= len(raw_members) <= 16,
                        f"{item_context}.members has an invalid length")
                members = []
                for member_index, member in enumerate(raw_members):
                    member_context = f"{item_context}.members[{member_index}]"
                    require(isinstance(member, dict),
                            f"{member_context} must be an object")
                    exact_audit_keys(member, {
                        "identifier", "kind", "method_const", "parameters",
                        "return_type", "storage",
                    }, member_context)
                    member_kind = member.get("kind")
                    require(member_kind in {"constructor", "destructor", "method"},
                            f"{member_context}.kind differs")
                    storage = member.get("storage")
                    require(storage in {"ordinary", "static", "virtual"},
                            f"{member_context}.storage differs")
                    method_const = require_exact_bool(
                        member.get("method_const"),
                        member_context + ".method_const",
                    )
                    raw_parameters = member.get("parameters")
                    require(isinstance(raw_parameters, list)
                            and len(raw_parameters) <= 16,
                            f"{member_context}.parameters has an invalid length")
                    return_type = member.get("return_type")
                    if member_kind == "method":
                        normalized_return_type = validate_source_overlay_cpp_type(
                            return_type, member_context + ".return_type"
                        )
                    else:
                        require(return_type is None,
                                f"{member_context}.return_type must be null")
                        normalized_return_type = None
                    member_identifier = _source_overlay_member_identifier(
                        member.get("identifier"), member_context + ".identifier"
                    )
                    if member_kind == "constructor":
                        require(member_identifier == item.get("identifier"),
                                f"{member_context} constructor differs")
                    elif member_kind == "destructor":
                        require(member_identifier == "~" + str(item.get("identifier")),
                                f"{member_context} destructor differs")
                    require(not method_const or member_kind == "method",
                            f"{member_context} const policy differs")
                    require(not (storage == "static" and method_const),
                            f"{member_context} static const policy differs")
                    members.append({
                        "identifier": member_identifier, "kind": member_kind,
                        "method_const": method_const,
                        "parameters": [
                            validate_source_overlay_parameter(
                                parameter,
                                f"{member_context}.parameters[{parameter_index}]",
                            )
                            for parameter_index, parameter in enumerate(raw_parameters)
                        ],
                        "return_type": normalized_return_type,
                        "storage": storage,
                    })
                normalized_item = {
                    "kind": declaration_kind, "tag": item["tag"],
                    "identifier": _source_overlay_identifier(
                        item.get("identifier"), item_context + ".identifier"
                    ),
                    "members": members,
                }
            else:
                raise ByteIdentityError(f"{item_context}.kind is unsupported")
            require(normalized_item["identifier"] not in declaration_identifiers,
                    f"{item_context}.identifier is duplicated")
            declaration_identifiers.add(normalized_item["identifier"])
            declarations.append(normalized_item)
        raw_statements = params.get("statements")
        require(isinstance(raw_statements, list)
                and 1 <= len(raw_statements) <= 256,
                f"{param_context}.statements has an invalid length")
        statements = []
        for index, item in enumerate(raw_statements):
            item_context = f"{param_context}.statements[{index}]"
            require(isinstance(item, dict), f"{item_context} must be an object")
            statement_kind = item.get("kind")
            if statement_kind == "discarded_new":
                exact_audit_keys(item, {"kind", "type"}, item_context)
                normalized_item = {
                    "kind": statement_kind,
                    "type": validate_source_overlay_cpp_type(
                        item.get("type"), item_context + ".type"
                    ),
                }
            elif statement_kind == "free_call":
                exact_audit_keys(item, {
                    "kind", "function_identifier", "arguments",
                }, item_context)
                raw_arguments = item.get("arguments")
                require(isinstance(raw_arguments, list)
                        and len(raw_arguments) <= 16,
                        f"{item_context}.arguments has an invalid length")
                normalized_item = {
                    "kind": statement_kind,
                    "function_identifier": _source_overlay_identifier(
                        item.get("function_identifier"),
                        item_context + ".function_identifier",
                    ),
                    "arguments": [
                        validate_source_overlay_expression(
                            argument, f"{item_context}.arguments[{argument_index}]"
                        )
                        for argument_index, argument in enumerate(raw_arguments)
                    ],
                }
            elif statement_kind in {
                "null_receiver_qualified_call", "qualified_call",
            }:
                expected_keys = {
                    "kind", "qualifier", "member_identifier", "arguments",
                }
                if statement_kind == "null_receiver_qualified_call":
                    expected_keys.add("receiver_type")
                exact_audit_keys(item, expected_keys, item_context)
                raw_arguments = item.get("arguments")
                require(isinstance(raw_arguments, list)
                        and len(raw_arguments) <= 16,
                        f"{item_context}.arguments has an invalid length")
                normalized_item = {
                    "kind": statement_kind,
                    "qualifier": _source_overlay_qualified_parts(
                        item.get("qualifier"), item_context + ".qualifier"
                    ),
                    "member_identifier": _source_overlay_member_identifier(
                        item.get("member_identifier"),
                        item_context + ".member_identifier",
                    ),
                    "arguments": [
                        validate_source_overlay_expression(
                            argument, f"{item_context}.arguments[{argument_index}]"
                        )
                        for argument_index, argument in enumerate(raw_arguments)
                    ],
                }
                if statement_kind == "null_receiver_qualified_call":
                    normalized_item["receiver_type"] = (
                        validate_source_overlay_cpp_type(
                            item.get("receiver_type"),
                            item_context + ".receiver_type",
                        )
                    )
            elif statement_kind == "volatile_local_binding":
                exact_audit_keys(item, {
                    "kind", "type", "identifier", "initializer",
                }, item_context)
                normalized_item = {
                    "kind": statement_kind,
                    "type": validate_source_overlay_cpp_type(
                        item.get("type"), item_context + ".type"
                    ),
                    "identifier": _source_overlay_identifier(
                        item.get("identifier"), item_context + ".identifier"
                    ),
                    "initializer": validate_source_overlay_expression(
                        item.get("initializer"), item_context + ".initializer"
                    ),
                }
            else:
                raise ByteIdentityError(f"{item_context}.kind is unsupported")
            statements.append(normalized_item)
        normalized = {
            "declarations": declarations,
            "function_identifier": "SeedOrder",
            "statements": statements,
            "undefined_binding_order": "reverse_statement_order_msvc_4_20",
        }
    elif kind == "discarded_console_crt_pull_v1":
        exact_audit_keys(params, {
            "control_flow", "function_identifier", "import_calls",
            "timer_type",
        }, param_context)
        require(params.get("function_identifier")
                == "LegoTestTimerConsoleControl"
                and params.get("timer_type") == "LegoTestTimer"
                and params.get("import_calls") == ["_kbhit", "_getch"],
                f"{param_context} console profile differs")
        flow = params.get("control_flow")
        require(isinstance(flow, dict),
                f"{param_context}.control_flow must be an object")
        exact_audit_keys(flow, {
            "case_groups", "dispatch_call", "wait_loop",
        }, param_context + ".control_flow")
        wait_loop = flow.get("wait_loop")
        require(isinstance(wait_loop, dict),
                f"{param_context}.control_flow.wait_loop must be an object")
        exact_audit_keys(wait_loop, {"continue_while", "predicate_call"},
                         param_context + ".control_flow.wait_loop")
        require(wait_loop == {
            "continue_while": "logical_not", "predicate_call": "_kbhit",
        } and flow.get("dispatch_call") == "_getch",
                f"{param_context}.control_flow differs")
        raw_groups = flow.get("case_groups")
        require(isinstance(raw_groups, list) and len(raw_groups) == 2,
                f"{param_context}.control_flow.case_groups differs")
        groups = []
        expected_groups = [([115, 83], "ResetAtNextTick"), ([112, 80], "Print")]
        for index, (item, expected) in enumerate(zip(raw_groups, expected_groups)):
            item_context = f"{param_context}.control_flow.case_groups[{index}]"
            require(isinstance(item, dict), f"{item_context} must be an object")
            exact_audit_keys(item, {"character_codes", "timer_member_call"},
                             item_context)
            require(item.get("character_codes") == expected[0]
                    and item.get("timer_member_call") == expected[1],
                    f"{item_context} differs")
            groups.append({
                "character_codes": list(expected[0]),
                "timer_member_call": expected[1],
            })
        normalized = {
            "control_flow": {
                "case_groups": groups, "dispatch_call": "_getch",
                "wait_loop": dict(wait_loop),
            },
            "function_identifier": "LegoTestTimerConsoleControl",
            "import_calls": ["_kbhit", "_getch"],
            "timer_type": "LegoTestTimer",
        }
    elif kind == "synthetic_member_call_supplier_v1":
        exact_audit_keys(params, {
            "global_definitions", "include_identity", "logical_path",
            "prefix_declarations", "relocated_ranges", "wrapper",
        }, param_context)
        require(params.get("global_definitions") == [],
                f"{param_context}.global_definitions differs")
        include_identity = params.get("include_identity")
        require(include_identity in {
            "legopathcontroller.h", "legopathedgecontainer.h",
        }, f"{param_context}.include_identity differs")
        logical_path = source_overlay_relative_path(
            params.get("logical_path"), param_context + ".logical_path"
        )
        prefix = params.get("prefix_declarations")
        require(isinstance(prefix, dict),
                f"{param_context}.prefix_declarations must be an object")
        exact_audit_keys(prefix, {
            "empty_class_identifiers", "enum_declarations",
            "forward_class_identifiers", "range_class_identifiers",
            "value_counter_class_identifiers",
        }, param_context + ".prefix_declarations")
        for name in (
            "empty_class_identifiers", "enum_declarations",
            "range_class_identifiers", "value_counter_class_identifiers",
        ):
            require(prefix.get(name) == [],
                    f"{param_context}.prefix_declarations.{name} differs")
        forward_identifiers = validate_source_overlay_identifier_run(
            prefix.get("forward_class_identifiers"),
            param_context + ".prefix_declarations.forward_class_identifiers",
        )
        require(forward_identifiers["stem"] == "MxUnkRecordTP"
                and forward_identifiers["first"] == 0
                and forward_identifiers["width"] == 3
                and forward_identifiers["count"] in {490, 896},
                f"{param_context}.prefix_declarations.forward_class_identifiers differs")
        raw_ranges = params.get("relocated_ranges")
        require(isinstance(raw_ranges, list) and len(raw_ranges) <= 1,
                f"{param_context}.relocated_ranges differs")
        relocated_ranges = []
        for index, item in enumerate(raw_ranges):
            item_context = f"{param_context}.relocated_ranges[{index}]"
            require(isinstance(item, dict), f"{item_context} must be an object")
            exact_audit_keys(item, {
                "range_dependency_id", "range_identity", "range_render_policy",
                "source_operation_id", "source_output", "source_range_token_pin",
                "transfer",
            }, item_context)
            require(item.get("transfer") == "copy_authenticated_clean_source_range"
                    and item.get("range_render_policy")
                    in SOURCE_OVERLAY_RANGE_RENDER_POLICIES,
                    f"{item_context} transfer policy differs")
            source_operation_id = item.get("source_operation_id")
            range_dependency_id = item.get("range_dependency_id")
            require(isinstance(source_operation_id, str)
                    and re.fullmatch(r"op_[a-z0-9_]{1,120}", source_operation_id)
                    and isinstance(range_dependency_id, str)
                    and re.fullmatch(r"[a-z][a-z0-9_]{1,160}", range_dependency_id),
                    f"{item_context} dependency identity differs")
            relocated_ranges.append({
                "range_dependency_id": range_dependency_id,
                "range_identity": _source_overlay_census_identifier(
                    item.get("range_identity"), item_context + ".range_identity"
                ),
                "range_render_policy": item["range_render_policy"],
                "source_operation_id": source_operation_id,
                "source_output": source_overlay_relative_path(
                    item.get("source_output"), item_context + ".source_output"
                ),
                "source_range_token_pin": validate_source_overlay_range_pin(
                    item.get("source_range_token_pin"),
                    item_context + ".source_range_token_pin",
                ),
                "transfer": "copy_authenticated_clean_source_range",
            })
        wrapper = params.get("wrapper")
        require(isinstance(wrapper, dict),
                f"{param_context}.wrapper must be an object")
        exact_audit_keys(wrapper, {
            "function_identifier", "operation", "parameter",
        }, param_context + ".wrapper")
        require(wrapper.get("function_identifier") in {
            "EraseFirstCtrlEdge", "EraseBEWithMidpoint",
        } and wrapper.get("operation") == "erase_begin_iterator",
                f"{param_context}.wrapper policy differs")
        parameter = validate_source_overlay_parameter(
            wrapper.get("parameter"), param_context + ".wrapper.parameter"
        )
        require(parameter.get("identifier") == "p_set"
                and parameter["type"]["indirection"] == ["lvalue_reference"],
                f"{param_context}.wrapper.parameter differs")
        normalized = {
            "global_definitions": [], "include_identity": include_identity,
            "logical_path": logical_path,
            "prefix_declarations": {
                "empty_class_identifiers": [], "enum_declarations": [],
                "forward_class_identifiers": forward_identifiers,
                "range_class_identifiers": [],
                "value_counter_class_identifiers": [],
            },
            "relocated_ranges": relocated_ranges,
            "wrapper": {
                "function_identifier": wrapper["function_identifier"],
                "operation": "erase_begin_iterator", "parameter": parameter,
            },
        }
    elif kind == "synthetic_constant_pool_tu_v1":
        exact_audit_keys(params, {"include_identity", "logical_path"}, param_context)
        require(params.get("include_identity") == "legopathboundary.h",
                f"{param_context}.include_identity differs")
        logical_path = source_overlay_relative_path(
            params.get("logical_path"), param_context + ".logical_path"
        )
        require(re.fullmatch(
            r"LEGO1/lego/legoomni/src/paths/legordatapad[1-4]\.cpp",
            logical_path,
        ) is not None, f"{param_context}.logical_path differs")
        normalized = {
            "include_identity": "legopathboundary.h",
            "logical_path": logical_path,
        }
    elif kind == "synthetic_discarded_relocation_ring_v1":
        exact_audit_keys(params, {
            "cyclic_successor_reference_count", "function_count",
            "function_identifier_stem", "function_identifier_width",
            "logical_path",
        }, param_context)
        require(params.get("function_identifier_stem") == "LegoRelocPad"
                and params.get("logical_path")
                == "LEGO1/lego/legoomni/src/paths/legorelocpad.cpp",
                f"{param_context} relocation ring identity differs")
        references = params.get("cyclic_successor_reference_count")
        require(isinstance(references, dict),
                f"{param_context}.cyclic_successor_reference_count must be an object")
        exact_audit_keys(references, {"first_15", "remaining_9"},
                         param_context + ".cyclic_successor_reference_count")
        require(references == {"first_15": 20, "remaining_9": 19},
                f"{param_context}.cyclic_successor_reference_count differs")
        require(require_exact_int(
            params.get("function_count"), param_context + ".function_count",
            minimum=24, maximum=24,
        ) == 24, f"{param_context}.function_count differs")
        require(require_exact_int(
            params.get("function_identifier_width"),
            param_context + ".function_identifier_width",
            minimum=2, maximum=2,
        ) == 2, f"{param_context}.function_identifier_width differs")
        normalized = {
            "cyclic_successor_reference_count": dict(references),
            "function_count": 24,
            "function_identifier_stem": "LegoRelocPad",
            "function_identifier_width": 2,
            "logical_path": "LEGO1/lego/legoomni/src/paths/legorelocpad.cpp",
        }
    elif kind == "list_cursor_delete_emission_probe_v1":
        exact_audit_keys(params, {
            "container_type", "cursor_type", "element_type",
            "function_identifier", "operation",
        }, param_context)
        expected = {
            "container_type": "ModelDbPartList",
            "cursor_type": "ModelDbPartListCursor",
            "element_type": "ModelDbPart",
            "function_identifier": "ModelDbPartListRecord",
            "operation": "delete_each_cursor_element",
        }
        require(params == expected, f"{param_context} list cursor profile differs")
        normalized = dict(expected)
    elif kind == "recursive_frame_texture_refresh_probe_v1":
        exact_audit_keys(params, {
            "function_identifier", "parameter_type", "pull_identity",
            "traversal_steps",
        }, param_context)
        require(params.get("function_identifier") == "FlushFrameBuffers"
                and params.get("pull_identity") == "IID_IDirect3DRMFrame2"
                and params.get("traversal_steps") == [
                    "enumerate_visuals", "refresh_mesh_group_textures",
                    "enumerate_child_frames", "recurse_child_frames",
                ], f"{param_context} frame traversal profile differs")
        parameter_type = validate_source_overlay_cpp_type(
            params.get("parameter_type"), param_context + ".parameter_type"
        )
        require(render_source_overlay_cpp_type(parameter_type)
                == "IDirect3DRMFrame2*",
                f"{param_context}.parameter_type differs")
        normalized = {
            "function_identifier": "FlushFrameBuffers",
            "parameter_type": parameter_type,
            "pull_identity": "IID_IDirect3DRMFrame2",
            "traversal_steps": list(params["traversal_steps"]),
        }
    elif kind == "literal_first_use_alias_v1":
        require(set(params) in (
            {"literal", "local_identifier", "owner_function", "type"},
            {"literal", "local_identifier", "owner_function", "use_ordinal"},
        ), f"{param_context} fields differ")
        require(params.get("literal") == "config"
                and params.get("owner_function")
                == "CConfigApp::InitInstance",
                f"{param_context}.literal differs")
        normalized = {
            "literal": "config",
            "local_identifier": _source_overlay_identifier(
                params.get("local_identifier"),
                param_context + ".local_identifier",
            ),
            "owner_function": "CConfigApp::InitInstance",
        }
        if "type" in params:
            normalized["type"] = validate_source_overlay_cpp_type(
                params.get("type"), param_context + ".type"
            )
        else:
            normalized["use_ordinal"] = require_exact_int(
                params.get("use_ordinal"), param_context + ".use_ordinal",
                minimum=1, maximum=1,
            )
    elif kind == "debug_assert_reseat_v1":
        if "condition" in params:
            exact_audit_keys(params, {"condition", "restore_seat"}, param_context)
            condition = params.get("condition")
            require(condition in {"donut", "grec", "proi", "r2", "v1_and_v2"},
                    f"{param_context}.condition differs")
            seat = params.get("restore_seat")
            require(isinstance(seat, dict),
                    f"{param_context}.restore_seat must be an object")
            seat_kind = seat.get("kind")
            if seat_kind == "after_local_declaration":
                exact_audit_keys(seat, {"kind", "identifier", "type"},
                                 param_context + ".restore_seat")
                normalized_seat = {
                    "kind": seat_kind,
                    "identifier": _source_overlay_identifier(
                        seat.get("identifier"),
                        param_context + ".restore_seat.identifier",
                    ),
                    "type": validate_source_overlay_cpp_type(
                        seat.get("type"), param_context + ".restore_seat.type"
                    ),
                }
            elif seat_kind == "after_local_declaration_sequence":
                exact_audit_keys(seat, {"kind", "declarations"},
                                 param_context + ".restore_seat")
                declarations = seat.get("declarations")
                require(isinstance(declarations, list)
                        and 1 <= len(declarations) <= 8,
                        f"{param_context}.restore_seat.declarations differs")
                normalized_seat = {
                    "kind": seat_kind,
                    "declarations": [
                        validate_source_overlay_parameter(
                            item,
                            f"{param_context}.restore_seat.declarations[{index}]",
                        ) for index, item in enumerate(declarations)
                    ],
                }
            elif seat_kind == "after_new_assignment":
                exact_audit_keys(seat, {
                    "kind", "target_identifier", "constructed_type",
                }, param_context + ".restore_seat")
                normalized_seat = {
                    "kind": seat_kind,
                    "target_identifier": _source_overlay_identifier(
                        seat.get("target_identifier"),
                        param_context + ".restore_seat.target_identifier",
                    ),
                    "constructed_type": validate_source_overlay_cpp_type(
                        seat.get("constructed_type"),
                        param_context + ".restore_seat.constructed_type",
                    ),
                }
            else:
                raise ByteIdentityError(
                    f"{param_context}.restore_seat.kind is unsupported"
                )
            normalized = {"condition": condition, "restore_seat": normalized_seat}
        else:
            exact_audit_keys(params, {
                "authentic_function", "carrier_function", "dead_local",
                "carrier_conditions", "restored_conditions",
            }, param_context)
            dead_local = params.get("dead_local")
            require(isinstance(dead_local, dict),
                    f"{param_context}.dead_local must be an object")
            exact_audit_keys(dead_local, {"type", "identifiers"},
                             param_context + ".dead_local")
            carrier_conditions = params.get("carrier_conditions")
            restored_conditions = params.get("restored_conditions")
            require(carrier_conditions == [
                "address_of_p_ammo", "m_world", "m_boundary",
                "m_pathController", "m_grec_null_tautology",
            ] and restored_conditions == [
                "grec", "donut", "proi", "r2", "v1_and_v2",
            ], f"{param_context} assertion condition profile differs")
            normalized = {
                "authentic_function": _source_overlay_qualified_identifier(
                    params.get("authentic_function"),
                    param_context + ".authentic_function",
                ),
                "carrier_function": _source_overlay_qualified_identifier(
                    params.get("carrier_function"),
                    param_context + ".carrier_function",
                ),
                "dead_local": {
                    "type": _source_overlay_identifier(
                        dead_local.get("type"), param_context + ".dead_local.type"
                    ),
                    "identifiers": _source_overlay_identifier_list(
                        dead_local.get("identifiers"),
                        param_context + ".dead_local.identifiers",
                        minimum=1, maximum=16,
                    ),
                },
                "carrier_conditions": list(carrier_conditions),
                "restored_conditions": list(restored_conditions),
            }
    elif kind == "discarded_import_library_probe_v1":
        exact_audit_keys(params, {
            "api", "capabilities_type", "function_identifier",
            "import_library", "tested_flag",
        }, param_context)
        require(
            params == {
                "api": "DirectSoundCreate",
                "capabilities_type": "DSCAPS",
                "function_identifier": "Detect3DSound",
                "import_library": "dsound",
                "tested_flag": "DSCAPS_PRIMARY16BIT",
            },
            f"{param_context} DirectSound probe profile differs",
        )
        normalized = dict(params)
    elif kind == "synthetic_crt_pull_v1":
        exact_audit_keys(params, {
            "deallocation_operator", "function_identifier", "parameter",
        }, param_context)
        require(params.get("deallocation_operator") == "array_delete"
                and params.get("function_identifier")
                == "IsleUnusedArrayHelper",
                f"{param_context} CRT pull profile differs")
        parameter = validate_source_overlay_parameter(
            params.get("parameter"), param_context + ".parameter"
        )
        require(parameter.get("identifier") == "p_array",
                f"{param_context}.parameter identifier differs")
        normalized = {
            "deallocation_operator": "array_delete",
            "function_identifier": "IsleUnusedArrayHelper",
            "parameter": parameter,
        }
    elif kind == "record_header_v1":
        exact_audit_keys(
            params, {"logical_path", "typed_recipe"}, param_context
        )
        logical_path = source_overlay_relative_path(
            params.get("logical_path"), param_context + ".logical_path"
        )
        recipe = params.get("typed_recipe")
        require(isinstance(recipe, dict),
                f"{param_context}.typed_recipe must be an object")
        recipe_context = param_context + ".typed_recipe"
        recipe_kind = recipe.get("kind")
        guard = _source_overlay_identifier(
            recipe.get("guard"), recipe_context + ".guard"
        )
        if recipe_kind == "enum_one_enumerator":
            exact_audit_keys(
                recipe, {"kind", "guard", "items"}, recipe_context
            )
            raw_items = recipe.get("items")
            require(isinstance(raw_items, list)
                    and 1 <= len(raw_items) <= 256,
                    f"{recipe_context}.items differs")
            items = []
            for index, item in enumerate(raw_items):
                item_context = f"{recipe_context}.items[{index}]"
                require(isinstance(item, dict),
                        f"{item_context} must be an object")
                exact_audit_keys(item, {"name", "enumerator"}, item_context)
                items.append({
                    "name": _source_overlay_identifier(
                        item.get("name"), item_context + ".name"
                    ),
                    "enumerator": _source_overlay_identifier(
                        item.get("enumerator"), item_context + ".enumerator"
                    ),
                })
            normalized_recipe = {
                "kind": recipe_kind, "guard": guard, "items": items,
            }
        elif recipe_kind == "unused_class_with_inline_void_methods":
            exact_audit_keys(recipe, {
                "kind", "guard", "items", "methods_per_class",
                "method_identifier_policy",
            }, recipe_context)
            items = _source_overlay_identifier_list(
                recipe.get("items"), recipe_context + ".items",
                minimum=1, maximum=256,
            )
            methods_per_class = require_exact_int(
                recipe.get("methods_per_class"),
                recipe_context + ".methods_per_class",
                minimum=1, maximum=256,
            )
            method_policy = recipe.get("method_identifier_policy")
            require(
                method_policy in {
                    "single_unindexed_record", "zero_based_indexed_record",
                }
                and (
                    (methods_per_class == 1)
                    is (method_policy == "single_unindexed_record")
                ),
                f"{recipe_context}.method_identifier_policy differs",
            )
            normalized_recipe = {
                "kind": recipe_kind, "guard": guard, "items": items,
                "methods_per_class": methods_per_class,
                "method_identifier_policy": method_policy,
            }
        else:
            raise ByteIdentityError(
                f"{recipe_context}.kind is unsupported"
            )
        normalized = {
            "logical_path": logical_path,
            "typed_recipe": normalized_recipe,
        }
    elif kind == "source_range_relocation_v1":
        keyset = set(params)
        if keyset == {"logical_header", "role", "style"}:
            require(params.get("role") == "destination_include_seat",
                    f"{param_context}.role differs")
            require(params.get("style") in {"angle", "quote"},
                    f"{param_context}.style differs")
            normalized = {
                "logical_header": source_overlay_relative_path(
                    params.get("logical_header"),
                    param_context + ".logical_header",
                ),
                "role": "destination_include_seat",
                "style": params["style"],
            }
        elif keyset == {
            "range_identity", "ordinary_owner", "byte_destination",
            "source_range_token_pin", "transfer", "source_operation_id",
            "range_dependency_id", "range_render_policy",
        }:
            require(params.get("transfer")
                    == "copy_authenticated_clean_source_range"
                    and params.get("range_render_policy")
                    in SOURCE_OVERLAY_RANGE_RENDER_POLICIES,
                    f"{param_context}.transfer differs")
            normalized = {
                "range_identity": _source_overlay_census_identifier(
                    params.get("range_identity"),
                    param_context + ".range_identity",
                ),
                "ordinary_owner": source_overlay_relative_path(
                    params.get("ordinary_owner"),
                    param_context + ".ordinary_owner",
                ),
                "byte_destination": source_overlay_relative_path(
                    params.get("byte_destination"),
                    param_context + ".byte_destination",
                ),
                "source_range_token_pin": validate_source_overlay_range_pin(
                    params.get("source_range_token_pin"),
                    param_context + ".source_range_token_pin",
                ),
                "source_operation_id": params.get("source_operation_id"),
                "range_dependency_id": params.get("range_dependency_id"),
                "range_render_policy": params["range_render_policy"],
                "transfer": "copy_authenticated_clean_source_range",
            }
            require(
                isinstance(normalized["source_operation_id"], str)
                and re.fullmatch(
                    r"op_[a-z0-9_]{1,120}", normalized["source_operation_id"]
                ) is not None
                and isinstance(normalized["range_dependency_id"], str)
                and re.fullmatch(
                    r"[a-z][a-z0-9_]{1,160}",
                    normalized["range_dependency_id"],
                ) is not None,
                f"{param_context} source dependency identity differs",
            )
            require(normalized["ordinary_owner"]
                    != normalized["byte_destination"],
                    f"{param_context} owner mapping differs")
        elif keyset == {
            "range_identity", "source_logical_path", "destination_logical_path",
            "ordinary_owner", "byte_owner", "destination_guard",
            "destination_include_identity", "destination_include_seat",
            "transfer", "source_operation_id", "range_dependency_id",
            "source_range_token_pin", "range_render_policy",
        }:
            require(params.get("transfer")
                    == "copy_authenticated_clean_source_range"
                    and params.get("range_render_policy")
                    in SOURCE_OVERLAY_RANGE_RENDER_POLICIES,
                    f"{param_context}.transfer differs")
            include_seat = params.get("destination_include_seat")
            require(isinstance(include_seat, dict),
                    f"{param_context}.destination_include_seat must be an object")
            exact_audit_keys(include_seat, {"before_function", "owner"},
                             param_context + ".destination_include_seat")
            normalized = {
                "range_identity": _source_overlay_census_identifier(
                    params.get("range_identity"),
                    param_context + ".range_identity",
                ),
                "source_logical_path": source_overlay_relative_path(
                    params.get("source_logical_path"),
                    param_context + ".source_logical_path",
                ),
                "destination_logical_path": source_overlay_relative_path(
                    params.get("destination_logical_path"),
                    param_context + ".destination_logical_path",
                ),
                "ordinary_owner": source_overlay_relative_path(
                    params.get("ordinary_owner"),
                    param_context + ".ordinary_owner",
                ),
                "byte_owner": source_overlay_relative_path(
                    params.get("byte_owner"), param_context + ".byte_owner",
                ),
                "destination_guard": _source_overlay_identifier(
                    params.get("destination_guard"),
                    param_context + ".destination_guard",
                ),
                "destination_include_identity": source_overlay_relative_path(
                    params.get("destination_include_identity"),
                    param_context + ".destination_include_identity",
                ),
                "destination_include_seat": {
                    "before_function": _source_overlay_qualified_identifier(
                        include_seat.get("before_function"),
                        param_context + ".destination_include_seat.before_function",
                    ),
                    "owner": source_overlay_relative_path(
                        include_seat.get("owner"),
                        param_context + ".destination_include_seat.owner",
                    ),
                },
                "source_operation_id": params.get("source_operation_id"),
                "range_dependency_id": params.get("range_dependency_id"),
                "range_render_policy": params["range_render_policy"],
                "source_range_token_pin": validate_source_overlay_range_pin(
                    params.get("source_range_token_pin"),
                    param_context + ".source_range_token_pin",
                ),
                "transfer": "copy_authenticated_clean_source_range",
            }
            require(normalized["source_logical_path"]
                    == normalized["ordinary_owner"]
                    and normalized["destination_logical_path"]
                    == normalized["byte_owner"]
                    and normalized["ordinary_owner"] != normalized["byte_owner"],
                    f"{param_context} owner mapping differs")
            require(
                isinstance(normalized["source_operation_id"], str)
                and re.fullmatch(
                    r"op_[a-z0-9_]{1,120}", normalized["source_operation_id"]
                ) is not None
                and isinstance(normalized["range_dependency_id"], str)
                and re.fullmatch(
                    r"[a-z][a-z0-9_]{1,160}",
                    normalized["range_dependency_id"],
                ) is not None,
                f"{param_context} source dependency identity differs",
            )
        else:
            raise ByteIdentityError(
                f"{param_context} source relocation variant is unsupported"
            )
    else:
        raise ByteIdentityError(f"{context} has unsupported generator kind: {kind}")
    normalized["renderer_layout"] = layout
    emission_class, structural_effect = source_overlay_generator_policy(
        kind, normalized
    )
    require(value.get("emission_class") == emission_class,
            f"{context}.emission_class differs")
    fragment = validate_source_overlay_fragment(
        value.get("baseline_fragment"), context + ".baseline_fragment",
        emission_class=emission_class,
        structural_effect=structural_effect,
    )
    require(
        fragment["baseline_line_count"]
        == source_overlay_layout_line_count(layout),
        f"{context} fragment line count differs from renderer_layout",
    )
    if kind == "literal_first_use_alias_v1":
        local_identifier = normalized["local_identifier"]
        if "type" in normalized:
            expected_census = {
                "declared_identifiers": [local_identifier],
                "referenced_identifiers": [], "emitted_identifiers": [],
            }
        else:
            expected_census = {
                "declared_identifiers": [],
                "referenced_identifiers": [local_identifier],
                "emitted_identifiers": [],
            }
        require(all(fragment[key] == expected
                    for key, expected in expected_census.items()),
                f"{context} literal alias census differs")
    if kind == "discarded_import_library_probe_v1":
        require(
            fragment["declared_identifiers"] == ["Detect3DSound"]
            and fragment["emitted_identifiers"] == ["Detect3DSound"]
            and fragment["referenced_identifiers"] == [
                "DSCAPS", "DSCAPS_PRIMARY16BIT", "DirectSoundCreate",
            ],
            f"{context} import probe census differs",
        )
    expected_roles = source_overlay_expected_identifier_roles(kind, normalized)
    require(
        all(fragment[role] == identities
            for role, identities in expected_roles.items()),
        f"{context} identifier role census differs",
    )
    return {
        "kind": kind,
        "emission_class": emission_class,
        "params": normalized,
        "baseline_fragment": fragment,
    }


def _source_overlay_indentation_bytes(units: list[dict]) -> bytes:
    return b"".join(
        (b"\t" if item["unit"] == "tab" else b" ") * item["count"]
        for item in units
    )


def _seat_source_overlay_fragment(generator: dict, semantic: bytes) -> bytes:
    """Seat semantic lines using only typed renderer inputs.

    This deliberately does not inspect ``baseline_fragment``.  Canonical
    hashes are assertions on the resulting bytes, never formatting inputs.
    """
    require(b"\r" not in semantic and semantic.isascii(),
            f"typed source overlay fragment is not ASCII/LF: {generator['kind']}")
    semantic_lines = []
    for line in semantic.splitlines():
        if not line.strip(b" \t"):
            continue
        normalized = line.lstrip(b" \t")
        require(normalized == normalized.rstrip(b" \t"),
                f"typed source overlay semantic line has trailing whitespace: {generator['kind']}")
        semantic_lines.append(normalized)
    layout = generator["params"]["renderer_layout"]
    content = layout["content_lines"]
    require(len(semantic_lines) == len(content),
            f"typed source overlay semantic line count differs: {generator['kind']}")
    physical = [None] * layout["physical_line_count"]
    for item, line in zip(content, semantic_lines):
        index = item["relative_line"] - 1
        require(physical[index] is None and line.strip(),
                f"typed source overlay content seat is duplicated: {generator['kind']}")
        physical[index] = (
            _source_overlay_indentation_bytes(item["indentation_units"]) + line
        )
    for run in layout["transparent_line_runs"]:
        indentation = _source_overlay_indentation_bytes(
            run["indentation_units"]
        )
        for relative in range(run["first"], run["first"] + run["count"]):
            index = relative - 1
            require(physical[index] is None,
                    f"typed source overlay transparent seat overlaps: {generator['kind']}")
            physical[index] = indentation
    require(all(line is not None for line in physical),
            f"typed source overlay physical canvas is incomplete: {generator['kind']}")
    if layout["line_ending"] == "none":
        body = b"" if not physical else physical[0]
    else:
        body = b"\n".join(physical)
        if layout["terminal_newline"]:
            body += b"\n"
    return body


def _finish_source_overlay_fragment(generator: dict, semantic: bytes) -> bytes:
    """Seat semantic lines through the canvas and verify all fragment pins."""
    body = _seat_source_overlay_fragment(generator, semantic)
    expected = generator["baseline_fragment"]
    require(
        len(body) == expected["baseline_size"]
        and body.count(b"\n") == expected["baseline_line_count"]
        and sha256_bytes(body) == expected["baseline_sha256"]
        and source_overlay_significant_sha256(body)
        == expected["baseline_significant_token_sha256"],
        f"typed source overlay fragment differs from its canonical pins: {generator['kind']}",
    )
    return body


def render_source_overlay_template_supplier(params: dict) -> bytes:
    lines: list[str] = []
    prefix = params["prefix_declarations"]
    for identifier in source_overlay_expand_identifier_collection(
        prefix["forward_class_identifiers"]
    ):
        lines.append(f"class {identifier};")
    for identifier in source_overlay_expand_identifier_collection(
        prefix["empty_class_identifiers"]
    ):
        lines.append(f"class {identifier} {{}};")
    for item in prefix["enum_declarations"]:
        lines.extend([
            f'enum {item["identifier"]} {{',
            f'{item["enumerator"]} = {item["value"]["lhs"]} << '
            f'{item["value"]["rhs"]}',
            "};",
        ])
    for identifier in source_overlay_expand_identifier_collection(
        prefix["value_counter_class_identifiers"]
    ):
        lines.extend([
            f"class {identifier} {{", "public:",
            "int GetValue() { return m_value; }", "private:",
            "int m_value;", "};",
        ])
    for identifier in source_overlay_expand_identifier_collection(
        prefix["range_class_identifiers"]
    ):
        lines.extend([
            f"class {identifier} {{", "public:",
            "int GetFirst() { return m_first; }",
            "int GetLast() { return m_last; }", "private:",
            "int m_first;", "int m_last;", "};",
        ])
    lines.append(f'#include "{params["include_identity"]}"')
    alias = params["container_alias"]
    alias_type = alias["type"]
    base = alias_type["base"]
    if (base["kind"] == "template_id"
            and len(base["arguments"]) > 1
            and not alias_type["base_const"]
            and not alias_type["indirection"]
            and not alias_type["trailing_const"]):
        lines.append(f'typedef {"::".join(base["qualified_identifier"])}<')
        for argument in base["arguments"]:
            lines.append(render_source_overlay_cpp_type(argument) + ",")
        lines[-1] = lines[-1][:-1]
        lines.append(f'> {alias["identifier"]};')
    else:
        lines.append(
            f'typedef {render_source_overlay_cpp_type(alias_type)} '
            f'{alias["identifier"]};'
        )
    for probe in params["probes"]:
        probe_identifier = probe["probe_identifier"]
        base_type = render_source_overlay_cpp_type(probe["base_type"])
        pointer = probe["member_pointer"]
        return_type = render_source_overlay_cpp_type(pointer["return_type"])
        owner_type = render_source_overlay_cpp_type(pointer["owner_type"])
        parameters = ", ".join(
            render_source_overlay_parameter(item)
            for item in pointer["parameters"]
        )
        method_const = " const" if pointer["method_const"] else ""
        alias_identifier = pointer["alias_identifier"]
        lines.extend([
            f"struct {probe_identifier} : public {base_type} {{",
            f"typedef {return_type} ({owner_type}::*{alias_identifier})"
            f"({parameters}){method_const};",
            f"static {alias_identifier} Get();",
            "};",
            f"{probe_identifier}::{alias_identifier} "
            f"{probe_identifier}::Get()",
            "{",
            f'return &{"::".join(probe["target_qualified_identifier"])};',
            "}",
        ])
    return ("\n".join(lines) + "\n").encode("ascii")


def render_source_overlay_seed_sequence(params: dict) -> bytes:
    lines: list[str] = []
    for item in params["declarations"]:
        kind = item["kind"]
        if kind == "forward_record":
            lines.append(f'{item["tag"]} {item["identifier"]};')
        elif kind == "extern_variable":
            lines.append(
                f'extern {render_source_overlay_cpp_type(item["type"])} '
                f'{item["identifier"]};'
            )
        elif kind == "function_declaration":
            lines.append(
                f'{render_source_overlay_cpp_type(item["return_type"])} '
                f'{item["identifier"]}('
                + ", ".join(
                    render_source_overlay_parameter(parameter)
                    for parameter in item["parameters"]
                ) + ");"
            )
        elif kind == "record_definition":
            lines.append(f'{item["tag"]} {item["identifier"]} {{')
            if item["tag"] == "class":
                lines.append("public:")
            for member in item["members"]:
                storage = (
                    member["storage"] + " "
                    if member["storage"] in {"static", "virtual"} else ""
                )
                return_type = (
                    render_source_overlay_cpp_type(member["return_type"]) + " "
                    if member["return_type"] is not None else ""
                )
                parameters = ", ".join(
                    render_source_overlay_parameter(parameter)
                    for parameter in member["parameters"]
                )
                method_const = " const" if member["method_const"] else ""
                lines.append(
                    f'{storage}{return_type}{member["identifier"]}'
                    f'({parameters}){method_const};'
                )
            lines.append("};")
        else:
            raise ByteIdentityError(
                f"typed seed declaration is unsupported: {kind}"
            )
    lines.extend([f'void {params["function_identifier"]}()', "{"])
    for item in params["statements"]:
        kind = item["kind"]
        if kind == "discarded_new":
            statement = f'new {render_source_overlay_cpp_type(item["type"])}'
        elif kind == "free_call":
            statement = (
                f'{item["function_identifier"]}('
                + ", ".join(
                    render_source_overlay_expression(argument)
                    for argument in item["arguments"]
                ) + ")"
            )
        elif kind in {"null_receiver_qualified_call", "qualified_call"}:
            arguments = ", ".join(
                render_source_overlay_expression(argument)
                for argument in item["arguments"]
            )
            call = (
                f'{"::".join(item["qualifier"])}::'
                f'{item["member_identifier"]}({arguments})'
            )
            if kind == "null_receiver_qualified_call":
                receiver_type = render_source_overlay_cpp_type(
                    item["receiver_type"]
                )
                statement = f'(({receiver_type}) 0)->{call}'
            else:
                statement = call
        elif kind == "volatile_local_binding":
            statement = (
                f'{render_source_overlay_cpp_type(item["type"])} volatile '
                f'{item["identifier"]} = '
                f'{render_source_overlay_expression(item["initializer"])}'
            )
        else:
            raise ByteIdentityError(
                f"typed seed statement is unsupported: {kind}"
            )
        lines.append(statement + ";")
    lines.append("}")
    return ("\n".join(lines) + "\n").encode("ascii")


def render_source_overlay_generator(
    generator: dict, *, relocation_ranges: dict[tuple[str, str], bytes] | None = None,
) -> bytes:
    kind = generator["kind"]
    params = generator["params"]
    if kind == "line_reservation_v1":
        result = b""
    elif kind == "include_dependency_v1":
        if params["style"] == "angle":
            result = f'#include <{params["header"]}>\n'.encode("ascii")
        else:
            result = f'#include "{params["header"]}"\n'.encode("ascii")
    elif kind == "include_seat_v1":
        quote_open, quote_close = (
            ('"', '"') if params["style"] == "quote" else ("<", ">")
        )
        result = (
            f'#include {quote_open}{params["basename"]}{quote_close}\n'
        ).encode("ascii")
    elif kind == "empty_compound_statements_v1":
        result = b"\t{\n\t}\n" * params["scope_count"]
    elif kind == "inline_budget_noop_statements_v1":
        target = params["assignment_target"]
        result = (f"\t{target} = {target} + 0;\n" * params["repeat"]).encode("ascii")
    elif kind == "compile_time_layout_assert_seat_v1":
        result = b"".join(
            f'DECOMP_SIZE_ASSERT({item["type"]}, 0x{item["size"]:x})\n'.encode("ascii")
            for item in params["assertions"]
        )
    elif kind == "declaration_sequence_v1":
        shape = params["shape"]
        if shape == "forward":
            result = f'{params["tag"]} {params["identifier"]};\n'.encode("ascii")
        elif shape == "forward_sequence":
            result = (
                " ".join(
                    f'{params["tag"]} {identifier};'
                    for identifier in source_overlay_expand_identifier_run(
                        params["identifiers"]
                    )
                ) + "\n"
            ).encode("ascii")
        elif shape == "empty_class":
            result = f'{params["tag"]} {params["identifier"]} {{}};\n'.encode("ascii")
        elif shape == "enum":
            lines = [f'enum {params["identifier"]} {{\n']
            for index, item in enumerate(params["enumerators"]):
                comma = (
                    "," if index + 1 < len(params["enumerators"])
                    or params["trailing_comma"] else ""
                )
                lines.append(f'\t{item["identifier"]}{comma}\n')
            lines.append("};\n")
            result = "".join(lines).encode("ascii")
        elif shape == "typedef_builtin":
            result = (
                f'typedef {params["aliased_type"]} {params["identifier"]};\n'
            ).encode("ascii")
        elif shape == "function_prototype":
            result = (
                render_source_overlay_cpp_type(params["return_type"]) + " "
                + params["identifier"] + "("
                + ", ".join(
                    render_source_overlay_parameter(item)
                    for item in params["parameters"]
                ) + ");\n"
            ).encode("ascii")
        elif shape == "unused_class_void_member_sequence":
            lines = [f'{params["tag"]} {params["identifier"]} {{\n']
            transitions = {
                item["before_member_index"]: item["access"]
                for item in params["access_transitions"]
            }
            for index, member in enumerate(params["members"]):
                if index in transitions:
                    lines.append(f'{transitions[index]}:\n')
                if member["kind"] == "empty_void_method_definition":
                    lines.append(
                        f'{"inline " if member["inline_specifier"] else ""}'
                        f'void {member["identifier"]}() {{}}\n'
                    )
                else:
                    lines.append(f'void {member["identifier"]}();\n')
            lines.append("};\n")
            result = "".join(lines).encode("ascii")
        else:
            raise ByteIdentityError(
                f'typed declaration shape is unsupported: {shape}'
            )
    elif kind == "conditional_declarations_v1":
        directives = []
        for item in params["directive_sequence"]:
            if item["directive"] == "ifdef":
                directives.append(f'#ifdef {item["macro_identifier"]}')
            elif item["directive"] == "else":
                directives.append("#else")
            else:
                directives.append("#endif")
        result = ("\n".join(directives) + "\n").encode("ascii")
    elif kind == "composed_typed_sequence_v1":
        grid = [b"\n"] * params["physical_line_count"]
        for item in params["items"]:
            child = render_source_overlay_generator(
                item["generator"], relocation_ranges=relocation_ranges
            )
            child_lines = child.splitlines(keepends=True)
            first, last = item["relative_lines"]
            require(len(child_lines) == last - first + 1
                    and all(line.endswith(b"\n") for line in child_lines),
                    "typed source overlay composite child span differs")
            transparent = set(item["transparent_relative_lines"])
            require(all(
                not child_lines[line - first].strip() for line in transparent
            ), "typed source overlay delegated line is not transparent")
            for offset, line in enumerate(child_lines, start=first - 1):
                if not line.strip():
                    continue
                require(not grid[offset].strip() or grid[offset] == line,
                        "typed source overlay composite has a nonblank conflict")
                grid[offset] = line
        result = b"".join(grid)
        return _finish_source_overlay_fragment(generator, result)
    elif kind == "local_symbol_id_carrier_v1":
        result = (
            f'{params["type"]} {", ".join(params["identifiers"])};\n'
        ).encode("ascii")
    elif kind == "qualified_member_comdat_emission_probe_v1":
        receiver = render_source_overlay_cpp_type(params["receiver_type"])
        member = "::".join(params["qualified_member"])
        argument = str(params["arguments"][0]["value"])
        result = (
            f'#pragma inline_depth({params["inline_depth"]})\n'
            f'MxS32 {params["function_identifier"]}({receiver}* p_bitmap)\n'
            '{\n'
            f'return p_bitmap->{member}({argument});\n'
            '}\n'
            '#pragma inline_depth()\n'
        ).encode("ascii")
    elif kind == "synthetic_template_member_supplier_v1":
        result = render_source_overlay_template_supplier(params)
    elif kind == "archive_pull_seed_function_v1":
        call = params["calls"][0]
        receiver_type = render_source_overlay_cpp_type(call["receiver_type"])
        member = "::".join(call["qualified_member"])
        result = (
            f'void {params["function_identifier"]}()\n'
            '{\n'
            f'(({receiver_type}*) 0)->{member}();\n'
            '}\n'
        ).encode("ascii")
    elif kind == "archive_pull_seed_sequence_v1":
        result = render_source_overlay_seed_sequence(params)
    elif kind == "discarded_console_crt_pull_v1":
        flow = params["control_flow"]
        lines = [
            f'void {params["function_identifier"]}('
            f'{params["timer_type"]}* p_timer)',
            "{",
            f'while (!{flow["wait_loop"]["predicate_call"]}()) {{',
            "}",
            f'switch ({flow["dispatch_call"]}()) {{',
        ]
        for group in flow["case_groups"]:
            for code in group["character_codes"]:
                lines.append(f"case '{chr(code)}':")
            lines.extend([
                f'p_timer->{group["timer_member_call"]}();', "break;",
            ])
        lines.extend(["}", "}"])
        result = ("\n".join(lines) + "\n").encode("ascii")
    elif kind == "synthetic_member_call_supplier_v1":
        lines = [
            f"class {identifier};"
            for identifier in source_overlay_expand_identifier_run(
                params["prefix_declarations"]["forward_class_identifiers"]
            )
        ]
        lines.append(f'#include "{params["include_identity"]}"')
        result = ("\n".join(lines) + "\n").encode("ascii")
        for relocated in params["relocated_ranges"]:
            require(relocation_ranges is not None,
                    "member supplier lacks authenticated relocation ranges")
            key = (
                relocated["source_operation_id"],
                relocated["range_dependency_id"],
            )
            payload = relocation_ranges.get(key)
            require(payload is not None,
                    "member supplier relocation range is absent")
            require_source_overlay_range_pin(
                payload, relocated["source_range_token_pin"],
                "member supplier relocation range",
            )
            result += source_overlay_render_relocated_range(
                payload, relocated["range_render_policy"]
            )
        wrapper = params["wrapper"]
        parameter = render_source_overlay_parameter(wrapper["parameter"])
        result += (
            f'void {wrapper["function_identifier"]}({parameter})\n'
            '{\n'
            f'{wrapper["parameter"]["identifier"]}.erase('
            f'{wrapper["parameter"]["identifier"]}.begin());\n'
            '}\n'
        ).encode("ascii")
    elif kind == "synthetic_constant_pool_tu_v1":
        result = f'#include "{params["include_identity"]}"\n'.encode("ascii")
    elif kind == "synthetic_discarded_relocation_ring_v1":
        stem = params["function_identifier_stem"]
        count = params["function_count"]
        width = params["function_identifier_width"]
        identifiers = [f"{stem}{index:0{width}d}" for index in range(count)]
        lines = [
            f"typedef void (*{stem}Fn)();",
            f"void {stem}Sink({stem}Fn);",
        ]
        lines.extend(f"void {identifier}();" for identifier in identifiers)
        lines.extend([
            f"void {stem}Sink({stem}Fn p_fn)", "{", "(void) p_fn;", "}",
        ])
        for index, identifier in enumerate(identifiers):
            reference_count = (
                params["cyclic_successor_reference_count"]["first_15"]
                if index < 15 else
                params["cyclic_successor_reference_count"]["remaining_9"]
            )
            lines.extend([f"void {identifier}()", "{"])
            for distance in range(1, reference_count + 1):
                successor = identifiers[(index + distance) % count]
                lines.append(f"{stem}Sink({successor});")
            lines.append("}")
        result = ("\n".join(lines) + "\n").encode("ascii")
    elif kind == "list_cursor_delete_emission_probe_v1":
        result = (
            f'void {params["function_identifier"]}('
            f'{params["container_type"]}* p_partlist)\n'
            '{\n'
            f'{params["cursor_type"]} cursor(p_partlist);\n'
            f'{params["element_type"]}* part;\n'
            'while (cursor.Next(part)) {\n'
            'delete part;\n'
            '}\n'
            '}\n'
        ).encode("ascii")
    elif kind == "recursive_frame_texture_refresh_probe_v1":
        result = (
            f'int {params["function_identifier"]}('
            f'{render_source_overlay_cpp_type(params["parameter_type"])} p_frame)\n'
            '{\n'
            'LPDIRECT3DRMVISUALARRAY visuals = NULL;\n'
            'if (p_frame->GetVisuals(&visuals) == D3DRM_OK && visuals != NULL) {\n'
            'int numVisuals = visuals->GetSize();\n'
            'for (int i = 0; i < numVisuals; i++) {\n'
            'LPDIRECT3DRMVISUAL visual = NULL;\n'
            'if (visuals->GetElement(i, &visual) == D3DRM_OK && visual != NULL) {\n'
            'LPDIRECT3DRMMESH mesh = NULL;\n'
            'if (visual->QueryInterface(IID_IDirect3DRMMesh, (LPVOID*) &mesh) '
            '== D3DRM_OK && mesh != NULL) {\n'
            'unsigned int numGroups = mesh->GetGroupCount();\n'
            'for (unsigned int j = 0; j < numGroups; j++) {\n'
            'LPDIRECT3DRMTEXTURE texture = NULL;\n'
            'if (mesh->GetGroupTexture(j, &texture) == D3DRM_OK && texture != NULL) {\n'
            'LPDIRECT3DRMTEXTURE2 texture2 = NULL;\n'
            'if (texture->QueryInterface(IID_IDirect3DRMTexture2, (LPVOID*) &texture2) '
            '== D3DRM_OK &&\n'
            'texture2 != NULL) {\n'
            'mesh->SetGroupTexture(j, NULL);\n'
            'texture2->Changed(TRUE, TRUE);\n'
            'mesh->SetGroupTexture(j, texture);\n'
            'texture2->Release();\n'
            '}\n'
            'texture->Release();\n'
            '}\n'
            '}\n'
            'mesh->Release();\n'
            '}\n'
            'else {\n'
            'LPDIRECT3DRMFRAME2 childFrame = NULL;\n'
            f'if (visual->QueryInterface({params["pull_identity"]}, '
            '(LPVOID*) &childFrame) == D3DRM_OK &&\n'
            'childFrame != NULL) {\n'
            f'{params["function_identifier"]}(childFrame);\n'
            'childFrame->Release();\n'
            '}\n'
            '}\n'
            'visual->Release();\n'
            '}\n'
            '}\n'
            'visuals->Release();\n'
            '}\n'
            'return 0;\n'
            '}\n'
        ).encode("ascii")
    elif kind == "literal_first_use_alias_v1":
        if "type" in params:
            result = (
                f'\t{render_source_overlay_cpp_type(params["type"])} '
                f'{params["local_identifier"]} = "{params["literal"]}";\n'
            ).encode("ascii")
        else:
            result = params["local_identifier"].encode("ascii")
    elif kind == "debug_assert_reseat_v1":
        if "condition" in params:
            result = b""
        else:
            conditions = {
                "address_of_p_ammo": "&p_ammo",
                "m_boundary": "m_boundary",
                "m_grec_null_tautology": "m_grec == NULL || m_grec != NULL",
                "m_pathController": "m_pathController",
                "m_world": "m_world",
            }
            result = (
                f'\t{params["dead_local"]["type"]} '
                + ", ".join(params["dead_local"]["identifiers"])
                + ";\n\n"
                + "".join(
                    f'\tassert({conditions[item]});\n'
                    for item in params["carrier_conditions"]
                )
            ).encode("ascii")
    elif kind == "discarded_import_library_probe_v1":
        result = (
            "BOOL Detect3DSound()\n"
            "{\n"
            "LPDIRECTSOUND lpDirectSound;\n"
            "DSCAPS caps;\n"
            "if (FAILED(DirectSoundCreate(NULL, &lpDirectSound, NULL))) {\n"
            "return FALSE;\n"
            "}\n"
            "caps.dwSize = sizeof(caps);\n"
            "if (FAILED(lpDirectSound->GetCaps(&caps))) {\n"
            "lpDirectSound->Release();\n"
            "return FALSE;\n"
            "}\n"
            "lpDirectSound->Release();\n"
            "return caps.dwFlags & DSCAPS_PRIMARY16BIT;\n"
            "}\n"
        ).encode("ascii")
    elif kind == "synthetic_crt_pull_v1":
        result = (
            f'void {params["function_identifier"]}('
            f'{render_source_overlay_parameter(params["parameter"])})\n'
            "{\n"
            f'delete[] {params["parameter"]["identifier"]};\n'
            "}\n"
        ).encode("ascii")
    elif kind == "record_header_v1":
        recipe = params["typed_recipe"]
        lines = [f'#ifndef {recipe["guard"]}', f'#define {recipe["guard"]}']
        if recipe["kind"] == "enum_one_enumerator":
            for item in recipe["items"]:
                lines.extend([
                    f'enum {item["name"]} {{', item["enumerator"], "};",
                ])
        else:
            for identifier in recipe["items"]:
                lines.append(f'class {identifier} {{')
                for index in range(recipe["methods_per_class"]):
                    method = (
                        "Record"
                        if recipe["method_identifier_policy"]
                        == "single_unindexed_record"
                        else f"Record{index}"
                    )
                    lines.append(f'inline void {method}() {{}}')
                lines.append("};")
        lines.append("#endif")
        result = ("\n".join(lines) + "\n").encode("ascii")
    elif kind == "source_range_relocation_v1":
        if params.get("role") == "destination_include_seat":
            opening, closing = (
                ('"', '"') if params["style"] == "quote" else ("<", ">")
            )
            result = (
                f'#include {opening}'
                f'{PurePosixPath(params["logical_header"]).name}{closing}\n'
            ).encode("ascii")
        else:
            require(relocation_ranges is not None,
                    "source relocation lacks an authenticated held range")
            key = (
                params["source_operation_id"], params["range_dependency_id"]
            )
            if "byte_destination" in params:
                payload = relocation_ranges.get(key)
                require(payload is not None,
                        "source relocation source range is absent")
                require_source_overlay_range_pin(
                    payload, params["source_range_token_pin"],
                    "source relocation range",
                )
                result = source_overlay_render_relocated_range(
                    payload, params["range_render_policy"]
                )
            else:
                payload = relocation_ranges.get(key)
                require(payload is not None,
                        "source relocation source range is absent")
                result = (
                    f'#ifndef {params["destination_guard"]}\n'
                    f'#define {params["destination_guard"]}\n'
                    f'#include "{params["destination_include_identity"]}"\n'
                ).encode("ascii") + source_overlay_render_relocated_range(
                    payload, params["range_render_policy"]
                ) + (
                    '#endif\n'
                ).encode("ascii")
    else:
        raise ByteIdentityError(f"source overlay renderer is absent: {kind}")
    return _finish_source_overlay_fragment(generator, result)


def validate_source_overlay_operation(
    value: object, context: str, *, logical_path: str,
) -> dict:
    require(isinstance(value, dict), f"{context} must be an object")
    action = value.get("action")
    require(action in SOURCE_OVERLAY_ACTIONS,
            f"{context}.action is unsupported")
    operation_id = value.get("id")
    require(isinstance(operation_id, str)
            and re.fullmatch(r"op_[a-z0-9_]{1,120}", operation_id) is not None,
            f"{context}.id is invalid")
    if action == "insert":
        allowed = {"id", "action", "start_anchor", "generator"}
        if "required_graph_admission_ids" in value:
            allowed.add("required_graph_admission_ids")
        exact_audit_keys(value, allowed, context)
        result = {
            "id": operation_id, "action": action,
            "start_anchor": validate_source_overlay_anchor(
                value.get("start_anchor"), context + ".start_anchor",
                logical_path=logical_path, operation_id=operation_id,
            ),
            "generator": validate_source_overlay_generator(
                value.get("generator"), context + ".generator"
            ),
        }
        if "required_graph_admission_ids" in value:
            require(
                value["required_graph_admission_ids"]
                == ["config_private_dsound_probe_v1"],
                f"{context}.required_graph_admission_ids differs",
            )
            result["required_graph_admission_ids"] = list(
                value["required_graph_admission_ids"]
            )
        return result
    if action == "replace":
        exact_audit_keys(value, {
            "id", "action", "start_anchor", "end_anchor", "generator",
            "baseline_input_range",
        }, context)
        return {
            "id": operation_id, "action": action,
            "start_anchor": validate_source_overlay_anchor(
                value.get("start_anchor"), context + ".start_anchor",
                logical_path=logical_path, operation_id=operation_id,
            ),
            "end_anchor": validate_source_overlay_anchor(
                value.get("end_anchor"), context + ".end_anchor",
                logical_path=logical_path, operation_id=operation_id,
            ),
            "generator": validate_source_overlay_generator(
                value.get("generator"), context + ".generator"
            ),
            "baseline_input_range": validate_source_overlay_range_pin(
                value.get("baseline_input_range"),
                context + ".baseline_input_range",
            ),
        }
    if action == "delete":
        exact_audit_keys(value, {
            "id", "action", "start_anchor", "end_anchor", "generator",
            "baseline_input_range",
        }, context)
        return {
            "id": operation_id, "action": action,
            "start_anchor": validate_source_overlay_anchor(
                value.get("start_anchor"), context + ".start_anchor",
                logical_path=logical_path, operation_id=operation_id,
            ),
            "end_anchor": validate_source_overlay_anchor(
                value.get("end_anchor"), context + ".end_anchor",
                logical_path=logical_path, operation_id=operation_id,
            ),
            "generator": validate_source_overlay_generator(
                value.get("generator"), context + ".generator"
            ),
            "baseline_input_range": validate_source_overlay_range_pin(
                value.get("baseline_input_range"),
                context + ".baseline_input_range",
            ),
        }
    if action == "whole_file_append":
        exact_audit_keys(value, {"id", "action", "generator"}, context)
        generator = validate_source_overlay_generator(
            value.get("generator"), context + ".generator"
        )
        return {
            "id": operation_id, "action": action,
            "generator": generator,
        }
    raise ByteIdentityError(f"{context}.action is unsupported")


def validate_source_overlay_graph(value: object, outputs: list[dict]) -> dict:
    context = "manifest.source_overlay.graph"
    require(isinstance(value, dict), f"{context} must be an object")
    exact_audit_keys(value, {
        "generated_translation_units", "link_admissions",
        "forbidden_legacy_interfaces", "prebuilt_source_artifacts",
    }, context)
    output_by_path = {item["logical_path"]: item for item in outputs}
    operation_owner = {}
    for output in outputs:
        for operation in output["operations"]:
            require(operation["id"] not in operation_owner,
                    f"source overlay operation is duplicated: {operation['id']}")
            operation_owner[operation["id"]] = (output, operation)
    raw_units = value.get("generated_translation_units")
    require(isinstance(raw_units, list),
            f"{context}.generated_translation_units must be an array")
    units = []
    owners = set()
    for index, item in enumerate(raw_units):
        item_context = f"{context}.generated_translation_units[{index}]"
        require(isinstance(item, dict), f"{item_context} must be an object")
        exact_audit_keys(item, {
            "logical_path", "language", "target_family", "source_ordinal",
            "insert_after", "insert_before", "targets",
            "generation_operation_ids", "generated_output",
        }, item_context)
        logical = source_overlay_relative_path(
            item.get("logical_path"), item_context + ".logical_path"
        )
        after = source_overlay_relative_path(
            item.get("insert_after"), item_context + ".insert_after"
        )
        before_value = item.get("insert_before")
        before = (
            None if before_value is None else source_overlay_relative_path(
                before_value, item_context + ".insert_before"
            )
        )
        require(item.get("language") == "CXX"
                and item.get("target_family")
                == "list_targets_from_add_lego_libraries"
                and item.get("targets") == ["lego1", "beta10"],
                f"{item_context} language/target family differs")
        require(logical != after and logical != before and after != before,
                f"{item_context} neighbor anchors are invalid")
        output = output_by_path.get(logical)
        require(output is not None and output["clean"]["state"] == "absent"
                and PurePosixPath(logical).suffix.casefold() in {".cc", ".cpp", ".cxx"},
                f"{item_context} is not one generated-only C++ output")
        require(logical not in owners,
                f"{item_context} duplicates a generated source")
        generation_operation_ids = item.get("generation_operation_ids")
        expected_operation_ids = [
            operation["id"] for operation in output["operations"]
        ]
        require(generation_operation_ids == expected_operation_ids
                and all(
                    operation_owner[operation_id][0] is output
                    for operation_id in generation_operation_ids
                ), f"{item_context} operation dependency closure differs")
        generated_output = item.get("generated_output")
        require(isinstance(generated_output, dict),
                f"{item_context}.generated_output must be an object")
        exact_audit_keys(generated_output, {
            "baseline_sha256", "baseline_size", "baseline_line_count",
            "baseline_significant_token_sha256", "materialization",
        }, item_context + ".generated_output")
        require(generated_output.get("materialization")
                == "build_tree_overlay_at_logical_path",
                f"{item_context}.generated_output.materialization differs")
        normalized_generated_output = {
            "baseline_sha256": require_sha(
                generated_output.get("baseline_sha256"),
                item_context + ".generated_output.baseline_sha256",
            ),
            "baseline_size": require_exact_int(
                generated_output.get("baseline_size"),
                item_context + ".generated_output.baseline_size",
                minimum=0, maximum=64 * 1024 * 1024,
            ),
            "baseline_line_count": require_exact_int(
                generated_output.get("baseline_line_count"),
                item_context + ".generated_output.baseline_line_count",
                minimum=0, maximum=2_000_000,
            ),
            "baseline_significant_token_sha256": require_sha(
                generated_output.get("baseline_significant_token_sha256"),
                item_context
                + ".generated_output.baseline_significant_token_sha256",
            ),
            "materialization": "build_tree_overlay_at_logical_path",
        }
        require(all(
            normalized_generated_output[key] == output["effective"][key]
            for key in (
                "baseline_sha256", "baseline_size", "baseline_line_count",
                "baseline_significant_token_sha256",
            )
        ), f"{item_context} output pins differ from the owned recipe")
        owners.add(logical)
        units.append({
            "logical_path": logical, "language": "CXX",
            "target_family": "list_targets_from_add_lego_libraries",
            "targets": ["lego1", "beta10"],
            "source_ordinal": require_exact_int(
                item.get("source_ordinal"), item_context + ".source_ordinal",
                minimum=1, maximum=100000,
            ),
            "insert_after": after, "insert_before": before,
            "generation_operation_ids": list(generation_operation_ids),
            "generated_output": normalized_generated_output,
        })
    units.sort(key=lambda item: item["source_ordinal"])
    require(
        len({item["source_ordinal"] for item in units}) == len(units),
        "source overlay generated TU ordinals are duplicated",
    )
    tail_units = [item for item in units if item["insert_before"] is None]
    require(
        (not units and not tail_units)
        or (len(tail_units) == 1 and tail_units[0] is units[-1]),
        "source overlay graph lacks its unique final generated-TU seat",
    )
    absent_compile_outputs = {
        item["logical_path"] for item in outputs
        if item["clean"]["state"] == "absent"
        and PurePosixPath(item["logical_path"]).suffix.casefold()
        in {".c", ".cc", ".cpp", ".cxx"}
    }
    require(owners == absent_compile_outputs,
            "source overlay graph does not own the exact generated TU universe")

    raw_links = value.get("link_admissions")
    require(isinstance(raw_links, list) and len(raw_links) <= 1,
            f"{context}.link_admissions must contain at most one record")
    links = []
    for index, item in enumerate(raw_links):
        item_context = f"{context}.link_admissions[{index}]"
        require(isinstance(item, dict), f"{item_context} must be an object")
        exact_audit_keys(item, {
            "admission_id", "target", "visibility", "library",
            "insert_after", "insert_before", "source_output",
            "required_operation_ids",
        }, item_context)
        require(
            item.get("admission_id") == "config_private_dsound_probe_v1"
            and item.get("target") == "config"
            and item.get("visibility") == "PRIVATE"
            and item.get("library") == "dsound"
            and item.get("insert_after") == "ddraw"
            and item.get("insert_before") == "dxguid",
            f"{item_context} differs from the one admitted byte graph link seat",
        )
        source_output = source_overlay_relative_path(
            item.get("source_output"), item_context + ".source_output"
        )
        required_operation_ids = item.get("required_operation_ids")
        require(required_operation_ids == ["op_3624_config_dsound_probe"],
                f"{item_context}.required_operation_ids differs")
        owner = output_by_path.get(source_output)
        operation_record = operation_owner.get(required_operation_ids[0])
        require(
            source_output == "CONFIG/detectdx5.cpp"
            and owner is not None and operation_record is not None
            and operation_record[0] is owner
            and operation_record[1]["generator"]["kind"]
            == "discarded_import_library_probe_v1",
            f"{item_context} is not reciprocally bound to its typed probe",
        )
        require(
            operation_record[1].get("required_graph_admission_ids")
            == [item["admission_id"]],
            f"{item_context} lacks reciprocal source-operation admission",
        )
        links.append({
            "admission_id": "config_private_dsound_probe_v1",
            "target": "config", "visibility": "PRIVATE",
            "library": "dsound", "insert_after": "ddraw",
            "insert_before": "dxguid", "source_output": source_output,
            "required_operation_ids": list(required_operation_ids),
        })
    forbidden = value.get("forbidden_legacy_interfaces")
    require(forbidden == [
        "ISLE_INCLUDE_ENTROPY", "ISLE_ENTROPY_FILENAME",
        "ISLE_TU_ENTROPY_MANIFEST",
    ], f"{context}.forbidden_legacy_interfaces differs")
    require(value.get("prebuilt_source_artifacts") == "forbidden",
            f"{context}.prebuilt_source_artifacts differs")
    return {
        "generated_translation_units": units,
        "link_admissions": links,
        "forbidden_legacy_interfaces": list(forbidden),
        "prebuilt_source_artifacts": "forbidden",
    }


def _read_source_overlay_clean_inputs(
    source_root: Path, outputs: list[dict],
) -> dict[str, bytes]:
    result = {}
    authority = ACTIVE_BUILD_AUTHORITIES[-1] if ACTIVE_BUILD_AUTHORITIES else None
    for output in outputs:
        relative = output["logical_path"]
        path = source_overlay_logical_path(source_root, relative)
        clean = output["clean"]
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            metadata = None
        except OSError as error:
            raise ByteIdentityError(
                f"cannot inspect clean source overlay input {path}: {error}"
            ) from error
        if clean["state"] == "absent":
            require(metadata is None,
                    f"generated-only clean source path unexpectedly exists: {path}")
            result[relative] = b""
            continue
        require(metadata is not None and stat.S_ISREG(metadata.st_mode)
                and not path.is_symlink() and path.resolve(strict=True) == path,
                f"clean source overlay input is absent or redirected: {path}")
        data = (
            authority.read_external_bytes(path, max_bytes=64 * 1024 * 1024)
            if authority is not None else path.read_bytes()
        )
        require(len(data) <= 64 * 1024 * 1024,
                f"clean source overlay input is too large: {relative}")
        result[relative] = data
    return result


def _apply_source_overlay_edits(
    data: bytes, edits: list[tuple[int, int, bytes, int, str]], context: str,
) -> bytes:
    grouped: dict[tuple[int, int], list[tuple[int, bytes, str]]] = defaultdict(list)
    for start, end, payload, ordinal, operation_id in edits:
        require(0 <= start <= end <= len(data),
                f"{context} edit range is invalid: {operation_id}")
        grouped[(start, end)].append((ordinal, payload, operation_id))
    ranges = sorted(grouped)
    previous_end = -1
    for start, end in ranges:
        require(start >= previous_end,
                f"{context} edits overlap at byte {start}")
        if end > start:
            require(len(grouped[(start, end)]) == 1,
                    f"{context} replacement range is duplicated")
            previous_end = end
        else:
            previous_end = max(previous_end, start)
    result = data
    for start, end in sorted(ranges, reverse=True):
        payloads = b"".join(
            payload for _, payload, _ in sorted(grouped[(start, end)])
        )
        result = result[:start] + payloads + result[end:]
    return result


def render_source_overlay_outputs(
    overlay: dict, clean_inputs: dict[str, bytes], *,
    evidence_out: list[dict] | None = None,
) -> dict[str, bytes]:
    """Render effective outputs from one immutable view of the clean inputs.

    Every anchor is resolved before any edit is applied.  Destructive ranges
    are authenticated as bytes *and* significant tokens before they can be
    removed.  Source relocation captures that same held range once and passes
    it to the destination renderer by an explicit operation/dependency key.
    """
    outputs = overlay["outputs"]
    output_by_path = {item["logical_path"]: item for item in outputs}
    require(set(clean_inputs) == set(output_by_path),
            "source overlay clean input universe differs")
    resolved = []
    operations_by_id = {}
    ordinal = 0
    relocation_ranges: dict[tuple[str, str], bytes] = {}
    relocation_authority: dict[tuple[str, str], dict] = {}

    # Resolve against the immutable clean view.  Rendering is deliberately a
    # separate pass so an earlier insertion can never change a later anchor.
    for output in outputs:
        relative = output["logical_path"]
        base = clean_inputs[relative]
        for operation in output["operations"]:
            ordinal += 1
            operation_id = operation["id"]
            require(operation_id not in operations_by_id,
                    f"source overlay operation is duplicated: {operation_id}")
            operations_by_id[operation_id] = (relative, operation)
            action = operation["action"]
            anchor_evidence = []
            start = end = None
            removed = None
            removed_evidence = None
            if action == "insert":
                require(output["clean"]["state"] == "present",
                        f"insert operation lacks a clean owner: {operation_id}")
                start = end = resolve_source_overlay_anchor(
                    base, operation["start_anchor"],
                    f"source overlay operation {operation_id}",
                    evidence=anchor_evidence, logical_path=relative,
                    operation_id=operation_id, role="insert",
                )
            elif action in {"delete", "replace"}:
                require(output["clean"]["state"] == "present",
                        f"destructive operation lacks a clean owner: {operation_id}")
                start = resolve_source_overlay_anchor(
                    base, operation["start_anchor"],
                    f"source overlay operation {operation_id} start",
                    evidence=anchor_evidence, logical_path=relative,
                    operation_id=operation_id, role="range_start",
                )
                end = resolve_source_overlay_anchor(
                    base, operation["end_anchor"],
                    f"source overlay operation {operation_id} end",
                    evidence=anchor_evidence, logical_path=relative,
                    operation_id=operation_id, role="range_end",
                )
                require(start < end,
                        f"source overlay operation has an empty/reversed range: {operation_id}")
                removed = base[start:end]
                removed_evidence = require_source_overlay_range_pin(
                    removed, operation["baseline_input_range"],
                    f"source overlay operation {operation_id}",
                )
                generator = operation["generator"]
                params = generator["params"]
                if (action == "delete"
                        and generator["kind"] == "source_range_relocation_v1"):
                    require(
                        params.get("source_operation_id") == operation_id
                        and params.get("ordinary_owner") == relative
                        and params.get("source_range_token_pin")
                        == operation["baseline_input_range"]
                        and all(
                            generator["baseline_fragment"][fragment_key]
                            == operation["baseline_input_range"][range_key]
                            for fragment_key, range_key in (
                                ("baseline_sha256", "baseline_sha256"),
                                ("baseline_size", "baseline_size"),
                                ("baseline_line_count", "baseline_line_count"),
                                ("baseline_significant_token_sha256",
                                 "baseline_significant_token_sha256"),
                            )
                        ),
                        f"source relocation producer differs: {operation_id}",
                    )
                    dependency_key = (
                        operation_id, params["range_dependency_id"]
                    )
                    require(dependency_key not in relocation_ranges,
                            f"source relocation dependency is duplicated: {dependency_key}")
                    relocation_ranges[dependency_key] = removed
                    relocation_authority[dependency_key] = {
                        "source_output": relative,
                        "byte_destination": params["byte_destination"],
                        "range_identity": params["range_identity"],
                        "source_range_token_pin": params["source_range_token_pin"],
                    }
            else:
                require(action == "whole_file_append"
                        and output["clean"]["state"] == "absent",
                        f"whole-file generator has a clean input: {operation_id}")
            resolved.append({
                "ordinal": ordinal, "logical_path": relative,
                "output": output, "operation": operation,
                "start": start, "end": end, "removed": removed,
                "removed_evidence": removed_evidence,
                "anchor_evidence": anchor_evidence,
            })

    def relocation_consumers(generator: dict):
        kind = generator["kind"]
        params = generator["params"]
        if kind == "composed_typed_sequence_v1":
            for item in params["items"]:
                yield from relocation_consumers(item["generator"])
        elif kind == "source_range_relocation_v1" and (
            "source_operation_id" in params and "byte_destination" not in params
        ):
            yield {
                "source_operation_id": params["source_operation_id"],
                "range_dependency_id": params["range_dependency_id"],
                "source_output": params["ordinary_owner"],
                "byte_destination": params.get(
                    "destination_logical_path", params.get("byte_owner")
                ),
                "range_identity": params["range_identity"],
                "source_range_token_pin": params["source_range_token_pin"],
            }
        elif kind == "synthetic_member_call_supplier_v1":
            for item in params["relocated_ranges"]:
                yield {
                    "source_operation_id": item["source_operation_id"],
                    "range_dependency_id": item["range_dependency_id"],
                    "source_output": item["source_output"],
                    "byte_destination": params["logical_path"],
                    "range_identity": item["range_identity"],
                    "source_range_token_pin": item["source_range_token_pin"],
                }

    consumer_counts = Counter()
    relocation_consumer_operations = {}
    for record in resolved:
        generator = record["operation"]["generator"]
        for consumer in relocation_consumers(generator):
            dependency_key = (
                consumer["source_operation_id"],
                consumer["range_dependency_id"],
            )
            authority = relocation_authority.get(dependency_key)
            require(
                authority is not None
                and authority["source_output"] == consumer["source_output"]
                and authority["byte_destination"] == consumer["byte_destination"]
                and authority["range_identity"] == consumer["range_identity"]
                and authority["source_range_token_pin"]
                == consumer["source_range_token_pin"],
                f"source relocation consumer differs: {dependency_key}",
            )
            consumer_counts[dependency_key] += 1
            relocation_consumer_operations[dependency_key] = record[
                "operation"
            ]["id"]
    require(set(consumer_counts) == set(relocation_authority)
            and all(count == 1 for count in consumer_counts.values()),
            "source relocation producer/consumer closure differs")

    edits: dict[str, list[tuple[int, int, bytes, int, str]]] = defaultdict(list)
    whole_outputs: dict[str, list[tuple[int, bytes, str]]] = defaultdict(list)
    operation_evidence = []
    for record in resolved:
        relative = record["logical_path"]
        operation = record["operation"]
        operation_id = operation["id"]
        action = operation["action"]
        generator = operation["generator"]
        if action == "delete":
            if generator["kind"] == "source_range_relocation_v1":
                fragment = record["removed"]
                _finish_source_overlay_fragment(generator, fragment)
            else:
                fragment = render_source_overlay_generator(
                    generator, relocation_ranges=relocation_ranges
                )
            payload = b""
        else:
            fragment = render_source_overlay_generator(
                generator, relocation_ranges=relocation_ranges
            )
            payload = fragment
        if action == "whole_file_append":
            whole_outputs[relative].append((
                record["ordinal"], payload, operation_id
            ))
        else:
            edits[relative].append((
                record["start"], record["end"], payload,
                record["ordinal"], operation_id,
            ))
        anchor = record["anchor_evidence"][0] if record["anchor_evidence"] else None
        receipt = {
            "logical_path": relative,
            "operation_id": operation_id,
            "action": action,
            "actual_clean_sha256": (
                None if record["output"]["clean"]["state"] == "absent"
                else sha256_bytes(clean_inputs[relative])
            ),
            "actual_clean_size": (
                None if record["output"]["clean"]["state"] == "absent"
                else len(clean_inputs[relative])
            ),
            "chosen_anchor_tier": (
                None if anchor is None else
                anchor["selected_context_tokens_each_side"]
            ),
            "resolved_token_offset": (
                None if anchor is None else anchor["selected_token_boundary"]
            ),
            "anchor_evidence": record["anchor_evidence"],
            "actual_generated_fragment_sha256": sha256_bytes(fragment),
        }
        if record["removed_evidence"] is not None:
            receipt.update(record["removed_evidence"])
        relocation_keys = []
        if (action == "delete"
                and generator["kind"] == "source_range_relocation_v1"):
            relocation_keys.append((
                operation_id,
                generator["params"]["range_dependency_id"],
            ))
        relocation_keys.extend(
            (
                consumer["source_operation_id"],
                consumer["range_dependency_id"],
            )
            for consumer in relocation_consumers(generator)
        )
        require(len(relocation_keys) <= 1,
                f"source overlay operation owns multiple relocation receipts: {operation_id}")
        if relocation_keys:
            dependency_key = relocation_keys[0]
            held_range = relocation_ranges[dependency_key]
            receipt.update({
                "range_dependency_id": dependency_key[1],
                "source_operation_id": dependency_key[0],
                "actual_held_source_range_sha256": sha256_bytes(held_range),
                "actual_held_source_range_size": len(held_range),
                "actual_held_source_range_line_count": held_range.count(b"\n"),
                "actual_held_source_range_significant_token_sha256":
                    source_overlay_significant_sha256(held_range),
                "consumer_operation_id":
                    relocation_consumer_operations[dependency_key],
            })
        operation_evidence.append(receipt)

    rendered = {}
    for output in outputs:
        relative = output["logical_path"]
        if output["clean"]["state"] == "absent":
            parts = sorted(whole_outputs.get(relative, []))
            require(parts, f"generated-only source has no typed assembly: {relative}")
            rendered[relative] = b"".join(item[1] for item in parts)
        else:
            require(relative not in whole_outputs,
                    f"clean source has a whole-file overlay: {relative}")
            rendered[relative] = _apply_source_overlay_edits(
                clean_inputs[relative], edits.get(relative, []),
                f"source overlay output {relative}",
            )

    for output in outputs:
        relative = output["logical_path"]
        data = rendered[relative]
        expected = output["effective"]
        clean = output["clean"]
        clean_data = clean_inputs[relative]
        baseline_clean = (
            clean["state"] == "absent"
            or (
                len(clean_data) == clean["baseline_size"]
                and sha256_bytes(clean_data) == clean["baseline_sha256"]
            )
        )
        if baseline_clean:
            require(
                len(data) == expected["baseline_size"]
                and data.count(b"\n") == expected["baseline_line_count"]
                and sha256_bytes(data) == expected["baseline_sha256"]
                and source_overlay_significant_sha256(data)
                == expected["baseline_significant_token_sha256"],
                f"baseline source overlay output differs: {relative}",
            )
        for receipt in operation_evidence:
            if receipt["logical_path"] == relative:
                receipt.update({
                    "actual_effective_sha256": sha256_bytes(data),
                    "actual_effective_size": len(data),
                })
    if evidence_out is not None:
        evidence_out.extend(operation_evidence)
    return rendered


def validate_source_overlay(value: object, source_root: Path) -> dict:
    """Validate and execute the manifest's closed clean-to-byte overlay."""
    if value is None:
        disabled = {
            "enabled": False, "schema": SOURCE_OVERLAY_SCHEMA,
            "status": "DISABLED", "renderer": SOURCE_OVERLAY_RENDERER,
            "closed_universe": {
                "physical_output_count": 0,
                "sorted_logical_paths_sha256": sha256_bytes(b""),
            },
            "outputs": [],
            "graph": {
                "generated_translation_units": [], "link_admissions": [],
                "forbidden_legacy_interfaces": [],
                "prebuilt_source_artifacts": "forbidden",
            },
        }
        disabled["policy_sha256"] = sha256_bytes(canonical_json_bytes(disabled))
        disabled["actual_records"] = []
        disabled["actual_records_sha256"] = sha256_bytes(canonical_json_bytes([]))
        disabled["anchor_evidence"] = []
        disabled["anchor_evidence_sha256"] = sha256_bytes(canonical_json_bytes([]))
        disabled["effective_by_path"] = {}
        return disabled
    context = "manifest.source_overlay"
    require(isinstance(value, dict), f"{context} must be an object")
    exact_audit_keys(value, {
        "schema", "status", "renderer", "generator_registry_sha256",
        "closed_universe", "drift_contract", "runtime_trust", "outputs",
        "graph",
    }, context)
    require(require_exact_int(
        value.get("schema"), context + ".schema",
        minimum=SOURCE_OVERLAY_SCHEMA, maximum=SOURCE_OVERLAY_SCHEMA,
    ) == SOURCE_OVERLAY_SCHEMA, f"{context}.schema differs")
    require(value.get("status") == SOURCE_OVERLAY_STATUS
            and value.get("renderer") == SOURCE_OVERLAY_RENDERER
            and require_sha(
                value.get("generator_registry_sha256"),
                context + ".generator_registry_sha256",
            ) == SOURCE_OVERLAY_GENERATOR_REGISTRY_SHA256
            and exact_json_equal(
                value.get("drift_contract"), SOURCE_OVERLAY_DRIFT_CONTRACT
            )
            and exact_json_equal(
                value.get("runtime_trust"), SOURCE_OVERLAY_RUNTIME_TRUST
            ),
            f"{context} status/renderer differs")
    raw_outputs = value.get("outputs")
    require(isinstance(raw_outputs, list) and raw_outputs,
            f"{context}.outputs must be non-empty")
    outputs = []
    paths = set()
    folded = {}
    for index, item in enumerate(raw_outputs):
        item_context = f"{context}.outputs[{index}]"
        require(isinstance(item, dict), f"{item_context} must be an object")
        exact_audit_keys(item, {
            "logical_path", "clean", "effective", "operations",
        }, item_context)
        logical = source_overlay_relative_path(
            item.get("logical_path"), item_context + ".logical_path"
        )
        require(logical not in paths, f"source overlay path is duplicated: {logical}")
        prior = folded.get(logical.casefold())
        require(prior is None,
                f"source overlay has a casefold collision: {prior} / {logical}")
        paths.add(logical)
        folded[logical.casefold()] = logical
        clean = item.get("clean")
        require(isinstance(clean, dict), f"{item_context}.clean must be an object")
        state = clean.get("state")
        require(state in {"present", "absent"},
                f"{item_context}.clean.state differs")
        if state == "present":
            exact_audit_keys(clean, {
                "state", "baseline_sha256", "baseline_size",
            }, item_context + ".clean")
            normalized_clean = {
                "state": state,
                "baseline_sha256": require_sha(
                    clean.get("baseline_sha256"),
                    item_context + ".clean.baseline_sha256",
                ),
                "baseline_size": require_exact_int(
                    clean.get("baseline_size"),
                    item_context + ".clean.baseline_size",
                    minimum=0, maximum=64 * 1024 * 1024,
                ),
            }
        else:
            exact_audit_keys(clean, {"state"}, item_context + ".clean")
            normalized_clean = {"state": state}
        effective = item.get("effective")
        require(isinstance(effective, dict),
                f"{item_context}.effective must be an object")
        exact_audit_keys(effective, {
            "mode", "baseline_sha256", "baseline_size",
            "baseline_line_count", "baseline_significant_token_sha256",
        }, item_context + ".effective")
        require(effective.get("mode") == SOURCE_OVERLAY_EFFECTIVE_MODE,
                f"{item_context}.effective.mode differs")
        operations = item.get("operations")
        require(isinstance(operations, list) and operations,
                f"{item_context}.operations must be non-empty")
        outputs.append({
            "logical_path": logical,
            "clean": normalized_clean,
            "effective": {
                "mode": SOURCE_OVERLAY_EFFECTIVE_MODE,
                "baseline_sha256": require_sha(
                    effective.get("baseline_sha256"),
                    item_context + ".effective.baseline_sha256"
                ),
                "baseline_size": require_exact_int(
                    effective.get("baseline_size"),
                    item_context + ".effective.baseline_size",
                    minimum=0, maximum=64 * 1024 * 1024,
                ),
                "baseline_line_count": require_exact_int(
                    effective.get("baseline_line_count"),
                    item_context + ".effective.baseline_line_count",
                    minimum=0, maximum=2000000,
                ),
                "baseline_significant_token_sha256": require_sha(
                    effective.get("baseline_significant_token_sha256"),
                    item_context + ".effective.baseline_significant_token_sha256",
                ),
            },
            "operations": [
                validate_source_overlay_operation(
                    operation,
                    f"{item_context}.operations[{operation_index}]",
                    logical_path=logical,
                )
                for operation_index, operation in enumerate(operations)
            ],
        })
    require([item["logical_path"] for item in outputs] == sorted(paths),
            f"{context}.outputs must be sorted by logical_path")
    universe = value.get("closed_universe")
    require(isinstance(universe, dict),
            f"{context}.closed_universe must be an object")
    exact_audit_keys(universe, {
        "physical_output_count", "sorted_logical_paths_sha256",
    }, context + ".closed_universe")
    sorted_path_sha = sha256_bytes(
        "".join(path + "\n" for path in sorted(paths)).encode("utf-8")
    )
    require(require_exact_int(
        universe.get("physical_output_count"),
        context + ".closed_universe.physical_output_count",
        minimum=1, maximum=2000,
    ) == len(outputs), f"{context} output count differs")
    require(require_sha(
        universe.get("sorted_logical_paths_sha256"),
        context + ".closed_universe.sorted_logical_paths_sha256",
    ) == sorted_path_sha, f"{context} logical path universe differs")
    graph = validate_source_overlay_graph(value.get("graph"), outputs)
    normalized = {
        "enabled": True, "schema": SOURCE_OVERLAY_SCHEMA,
        "status": SOURCE_OVERLAY_STATUS, "renderer": SOURCE_OVERLAY_RENDERER,
        "generator_registry_sha256": SOURCE_OVERLAY_GENERATOR_REGISTRY_SHA256,
        "drift_contract": SOURCE_OVERLAY_DRIFT_CONTRACT,
        "runtime_trust": SOURCE_OVERLAY_RUNTIME_TRUST,
        "closed_universe": {
            "physical_output_count": len(outputs),
            "sorted_logical_paths_sha256": sorted_path_sha,
        },
        "outputs": outputs, "graph": graph,
    }
    clean_inputs = _read_source_overlay_clean_inputs(source_root, outputs)
    normalized["policy_sha256"] = sha256_bytes(canonical_json_bytes(normalized))
    for output in outputs:
        relative = output["logical_path"]
        clean_tokens = {
            token for token, _, _ in source_overlay_tokens(clean_inputs[relative])
        }
        introductions: dict[tuple[str, str], list[tuple[int, str]]] = {}
        references: list[tuple[str, str, int, str]] = []
        for operation_index, operation in enumerate(output["operations"]):
            if operation["action"] == "delete":
                continue
            generator = operation.get("generator")
            if not isinstance(generator, dict):
                continue
            # Composite census records are summaries rather than additional
            # physical declarations. Recurse to leaf rendering owners and key
            # function locals by their typed owner scope; the same spelling in
            # two distinct functions is valid C++.
            for leaf in iter_source_overlay_leaf_generators(generator):
                scope = source_overlay_generator_identity_scope(leaf)
                fragment = leaf["baseline_fragment"]
                for identifier in fragment["declared_identifiers"]:
                    terminal_identifier = identifier.rsplit("::", 1)[-1]
                    if ("::" not in identifier
                            and SOURCE_OVERLAY_IDENTIFIER_RE.fullmatch(
                                terminal_identifier
                            )):
                        require(
                            terminal_identifier not in clean_tokens,
                            "source overlay identifier already exists in its "
                            f"clean input: {identifier}",
                        )
                    key = (scope, identifier)
                    introductions.setdefault(key, []).append(
                        (operation_index, operation["id"])
                    )
                references.extend(
                    (scope, identifier, operation_index, operation["id"])
                    for identifier in fragment["referenced_identifiers"]
                )
        duplicates = {
            key: occurrences for key, occurrences in introductions.items()
            if len(occurrences) != 1
        }
        require(
            not duplicates,
            "source overlay identifier is introduced twice in "
            f"{relative}: {sorted(duplicates.items())[0] if duplicates else ''}",
        )
        for scope, identifier, reference_index, operation_id in references:
            candidate_keys = [(scope, identifier)]
            if scope != "output_scope":
                candidate_keys.append(("output_scope", identifier))
            candidates = [
                occurrence
                for key in candidate_keys
                for occurrence in introductions.get(key, [])
            ]
            require(
                not candidates
                or min(index for index, _ in candidates) <= reference_index,
                "source overlay reference precedes its declaration: "
                f"{relative}:{operation_id}:{scope}:{identifier}",
            )
    anchor_evidence = []
    rendered = render_source_overlay_outputs(
        normalized, clean_inputs, evidence_out=anchor_evidence
    )
    actual_records = []
    for output in outputs:
        relative = output["logical_path"]
        clean_data = clean_inputs[relative]
        effective_data = rendered[relative]
        clean = output["clean"]
        actual_records.append({
            "logical_path": relative,
            "clean_state": clean["state"],
            "clean_sha256": (
                None if clean["state"] == "absent"
                else sha256_bytes(clean_data)
            ),
            "clean_size": (
                None if clean["state"] == "absent" else len(clean_data)
            ),
            "clean_baseline_match": (
                clean["state"] == "absent"
                or (
                    len(clean_data) == clean["baseline_size"]
                    and sha256_bytes(clean_data) == clean["baseline_sha256"]
                )
            ),
            "effective_sha256": sha256_bytes(effective_data),
            "effective_size": len(effective_data),
            "effective_line_count": effective_data.count(b"\n"),
            "effective_significant_token_sha256":
                source_overlay_significant_sha256(effective_data),
        })
    normalized["actual_records"] = actual_records
    normalized["actual_records_sha256"] = sha256_bytes(
        canonical_json_bytes(actual_records)
    )
    normalized["anchor_evidence"] = anchor_evidence
    normalized["anchor_evidence_sha256"] = sha256_bytes(
        canonical_json_bytes(anchor_evidence)
    )
    normalized["effective_by_path"] = {
        item["logical_path"]: {
            "sha256": sha256_bytes(rendered[item["logical_path"]]),
            "size": len(rendered[item["logical_path"]]),
            "line_count": rendered[item["logical_path"]].count(b"\n"),
            "significant_token_sha256": source_overlay_significant_sha256(
                rendered[item["logical_path"]]
            ),
        }
        for item in outputs
    }
    return normalized


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


def canonical_tree_snapshot(
    root: Path, *, hash_files: bool, max_entries: int = 20000,
    max_depth: int = 32, excluded_names: frozenset[str] = frozenset(),
    skip_symlinks: bool = False, include_metadata_records: bool = False,
) -> dict:
    """Snapshot one external input tree without following any tree symlink.

    The content Merkle covers canonical path/type/mode/exec/size/SHA records.
    The local metadata Merkle additionally covers inode and ctime/mtime so a
    later launcher can cheaply prove that previously hashed bytes were not
    replaced before or after VC runs.
    """
    requested = lexical_absolute_path(root)
    canonical = requested.resolve(strict=True)
    require(requested == canonical,
            f"sealed input tree root is symlinked or noncanonical: {requested}")
    descriptor = os.open(canonical, DIRECTORY_FD_FLAGS)
    records: list[dict] = []
    metadata_records: list[dict] = []
    observed_max_depth = 0

    def walk(directory_fd: int, relative: PurePosixPath, depth: int) -> None:
        nonlocal observed_max_depth
        require(depth <= max_depth,
                f"sealed input tree exceeds maximum depth: {canonical}")
        observed_max_depth = max(observed_max_depth, depth)
        try:
            names = sorted(os.listdir(directory_fd), key=lambda item: (item.casefold(), item))
        except OSError as error:
            raise ByteIdentityError(f"cannot enumerate sealed input tree {canonical}: {error}") from error
        folded = [name.casefold() for name in names]
        require(len(folded) == len(set(folded)),
                f"sealed input tree contains a casefold collision: {canonical / Path(*relative.parts)}")
        for name in names:
            require(name not in ("", ".", "..") and "/" not in name and "\0" not in name,
                    "sealed input tree contains an unsafe entry")
            if name in excluded_names:
                continue
            child_relative = relative / name
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if skip_symlinks and stat.S_ISLNK(metadata.st_mode):
                continue
            mode = stat.S_IMODE(metadata.st_mode)
            base = {
                "path": child_relative.as_posix(),
                "mode": mode,
                "executable": bool(mode & 0o111),
                "size": metadata.st_size,
            }
            local = {
                **base,
                "dev": metadata.st_dev, "nlink": metadata.st_nlink,
                "ino": metadata.st_ino,
                "mtime_ns": metadata.st_mtime_ns,
                "ctime_ns": metadata.st_ctime_ns,
            }
            if stat.S_ISDIR(metadata.st_mode):
                base["type"] = local["type"] = "directory"
                base["sha256"] = sha256_bytes(b"")
                child_fd = os.open(name, DIRECTORY_FD_FLAGS, dir_fd=directory_fd)
                try:
                    opened = os.fstat(child_fd)
                    require((opened.st_dev, opened.st_ino)
                            == (metadata.st_dev, metadata.st_ino),
                            f"sealed input directory changed while opened: {child_relative}")
                    records.append(base)
                    metadata_records.append(local)
                    require(len(records) <= max_entries,
                            f"sealed input tree exceeds maximum entries: {canonical}")
                    walk(child_fd, child_relative, depth + 1)
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(metadata.st_mode):
                base["type"] = local["type"] = "file"
                if hash_files:
                    file_fd = os.open(name, AUDIT_FILE_FD_FLAGS, dir_fd=directory_fd)
                    try:
                        opened = os.fstat(file_fd)
                        require(stat.S_ISREG(opened.st_mode)
                                and (opened.st_dev, opened.st_ino)
                                == (metadata.st_dev, metadata.st_ino),
                                f"sealed input file changed while opened: {child_relative}")
                        digest = hashlib.sha256()
                        while True:
                            chunk = os.read(file_fd, 1024 * 1024)
                            if not chunk:
                                break
                            digest.update(chunk)
                        after = os.fstat(file_fd)
                        require((after.st_dev, after.st_ino, after.st_size,
                                 after.st_mtime_ns, after.st_ctime_ns)
                                == (opened.st_dev, opened.st_ino, opened.st_size,
                                    opened.st_mtime_ns, opened.st_ctime_ns),
                                f"sealed input file changed while read: {child_relative}")
                        base["sha256"] = digest.hexdigest()
                    finally:
                        os.close(file_fd)
                records.append(base)
                metadata_records.append(local)
            elif stat.S_ISLNK(metadata.st_mode):
                base["type"] = local["type"] = "symlink"
                target = os.readlink(name, dir_fd=directory_fd)
                require(target and "\0" not in target,
                        f"sealed input symlink target is invalid: {child_relative}")
                target_path = PurePosixPath(target)
                require(not target_path.is_absolute(),
                        f"sealed input symlink escapes its root: {child_relative}")
                lexical_target = os.path.normpath(
                    os.path.join(os.fspath(child_relative.parent), target)
                )
                require(lexical_target != ".." and not lexical_target.startswith("../"),
                        f"sealed input symlink escapes its root: {child_relative}")
                base["target"] = local["target"] = target
                base["sha256"] = sha256_bytes(target.encode("utf-8"))
                records.append(base)
                metadata_records.append(local)
            else:
                raise ByteIdentityError(
                    f"sealed input tree contains unsupported entry type: {child_relative}"
                )
            require(len(records) <= max_entries,
                    f"sealed input tree exceeds maximum entries: {canonical}")

    try:
        root_metadata = os.fstat(descriptor)
        root_mode = stat.S_IMODE(root_metadata.st_mode)
        records.append({
            "path": ".", "type": "directory", "mode": root_mode,
            "executable": bool(root_mode & 0o111), "size": root_metadata.st_size,
            "sha256": sha256_bytes(b""),
        })
        metadata_records.append({
            "path": ".", "type": "directory", "mode": root_mode,
            "executable": bool(root_mode & 0o111), "size": root_metadata.st_size,
            "dev": root_metadata.st_dev, "ino": root_metadata.st_ino,
            "nlink": root_metadata.st_nlink,
            "mtime_ns": root_metadata.st_mtime_ns,
            "ctime_ns": root_metadata.st_ctime_ns,
        })
        walk(descriptor, PurePosixPath(), 0)
    finally:
        os.close(descriptor)
    membership_records = [
        {key: value for key, value in record.items() if key != "sha256"}
        for record in records
    ]
    result = {
        "root": str(canonical),
        "entry_count": len(records),
        "max_depth": observed_max_depth,
        "membership_sha256": sha256_bytes(json.dumps(
            membership_records, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")),
        "metadata_sha256": sha256_bytes(json.dumps(
            metadata_records, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")),
        # Callers that materialize an immutable input snapshot need the exact
        # already-hashed leaf universe.  This is intentionally not copied into
        # the manifest or command inventory; those documents retain only the
        # bounded Merkle/count/depth pins.
        "records": records,
    }
    if hash_files:
        result["content_sha256"] = sha256_bytes(json.dumps(
            records, sort_keys=True, separators=(",", ":")
        ).encode("utf-8"))
    if include_metadata_records:
        # These host-local identities never enter a descriptor or Merkle.
        # A transaction-scoped execution projection uses them to prove that
        # the exact files hashed above remain the same readonly inodes at each
        # child cut point, then performs one terminal content rescan.
        result["metadata_records"] = metadata_records
    return result


def current_host_runtime_identity() -> dict:
    """Return the bounded host identity for dyld-cache-resolved Wine imports."""
    system_version_path = Path(
        "/System/Library/CoreServices/SystemVersion.plist"
    )
    dyld_path = Path("/usr/lib/dyld")
    require(platform.system() == "Darwin",
            "the pinned Wine runtime requires Darwin")
    plist_bytes = (
        ACTIVE_BUILD_AUTHORITIES[-1].read_external_bytes(system_version_path)
        if ACTIVE_BUILD_AUTHORITIES else system_version_path.read_bytes()
    )
    try:
        system_version = plistlib.loads(plist_bytes)
    except (plistlib.InvalidFileException, ValueError) as error:
        raise ByteIdentityError(f"cannot parse host SystemVersion.plist: {error}") from error
    require(isinstance(system_version, dict),
            "host SystemVersion.plist is not an object")
    dyld_bytes = (
        ACTIVE_BUILD_AUTHORITIES[-1].read_external_bytes(dyld_path)
        if ACTIVE_BUILD_AUTHORITIES else dyld_path.read_bytes()
    )
    return {
        "schema": "darwin_dyld_cache_identity_v1",
        "system": platform.system(),
        "machine": platform.machine(),
        "darwin_release": platform.release(),
        "kernel_version": platform.version(),
        "product_version": system_version.get("ProductVersion"),
        "product_build": system_version.get("ProductBuildVersion"),
        "system_version_plist": str(system_version_path),
        "system_version_plist_sha256": sha256_bytes(plist_bytes),
        "dyld_path": str(dyld_path),
        "dyld_size": len(dyld_bytes),
        "dyld_sha256": sha256_bytes(dyld_bytes),
    }


def require_disjoint_source_build(source_dir: Path, build_dir: Path) -> tuple[Path, Path]:
    """Reject either containment direction before any build namespace mutation."""
    source_root = source_dir.resolve(strict=True)
    build_root = build_dir.resolve(strict=True)
    contains = False
    for child, parent in ((build_root, source_root), (source_root, build_root)):
        try:
            child.relative_to(parent)
        except ValueError:
            continue
        contains = True
    require(
        not contains,
        "byte-identity source and build roots must be disjoint",
    )
    return source_root, build_root


def recipe_output(build_dir: Path, recipe_id: str, header_sha256: str) -> Path:
    require(recipe_id.startswith("d_"),
            "generated recipe is not a declaration-shape identity")
    return (
        lexical_absolute_path(build_dir)
        / "byte-identity/generated"
        / f"declaration_{header_sha256}.h"
    )


def archive_output(build_dir: Path, identity: str, source: str) -> Path:
    """Fixed build-authority seat for one explicitly authorized archive."""
    require(identity in THIRD_PARTY_RETAIL_ARCHIVES,
            f"unsupported third-party archive identity: {identity}")
    return (
        lexical_absolute_path(build_dir)
        / "byte-identity/third-party-archives"
        / identity
        / PurePosixPath(source).name
    )


def archive_audit_path(build_dir: Path, identity: str) -> Path:
    require(identity in THIRD_PARTY_RETAIL_ARCHIVES,
            f"unsupported third-party archive identity: {identity}")
    return (
        lexical_absolute_path(build_dir)
        / "byte-identity/audit/archives"
        / f"{identity}.json"
    )


def final_report_path(build_dir: Path, identity: str) -> Path:
    require(identity == "LEGO1", f"unsupported final image identity: {identity}")
    return lexical_absolute_path(build_dir) / "byte-identity/final/LEGO1.json"


def final_image_path(build_dir: Path, identity: str) -> Path:
    require(identity == "LEGO1", f"unsupported final image identity: {identity}")
    return lexical_absolute_path(build_dir) / "LEGO1.DLL"


def lexical_absolute_path(path: Path, cwd: Path | None = None) -> Path:
    """Normalize dots without dereferencing any filesystem entry."""
    candidate = path if path.is_absolute() else (cwd or Path.cwd()) / path
    return Path(os.path.abspath(os.fspath(candidate)))


DIRECTORY_FD_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


AUDIT_FILE_FD_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NONBLOCK", 0)
)


EXPECTED_DYLD_IMPORT_IDENTITIES = [
    "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"
    "|compatibility=150.0.0|current=4201.0.0",
    "/System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices"
    "|compatibility=1.0.0|current=1226.0.0",
    "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit"
    "|compatibility=1.0.0|current=275.0.0",
    "/usr/lib/libSystem.B.dylib|compatibility=1.0.0|current=1356.0.0",
    "@rpath/libinotify.0.dylib|compatibility=1.0.0|current=1.0.0",
]


MANIFEST_HOST_ROOT_ENV = {
    "WINE_BUNDLE": "ISLE_BYTE_IDENTITY_WINE_BUNDLE",
    "WINE_PREFIX_TEMPLATE": "ISLE_BYTE_IDENTITY_WINE_PREFIX_TEMPLATE",
    "RECCMP_EXECUTABLE": "ISLE_BYTE_IDENTITY_RECCMP_EXECUTABLE",
    "PYTHON_RUNTIME_ROOT": "ISLE_BYTE_IDENTITY_PYTHON_RUNTIME_ROOT",
    "HOMEBREW_PREFIX": "ISLE_BYTE_IDENTITY_HOMEBREW_PREFIX",
    "HOMEBREW_CELLAR": "ISLE_BYTE_IDENTITY_HOMEBREW_CELLAR",
    "RECCMP_PACKAGE_ROOT": "ISLE_BYTE_IDENTITY_RECCMP_PACKAGE_ROOT",
    "RECCMP_SITE_PACKAGES": "ISLE_BYTE_IDENTITY_RECCMP_SITE_PACKAGES",
}


MANIFEST_HOST_PATH_RE = re.compile(r"^<([A-Z0-9_]+)>(?:/(.*))?$")


def manifest_host_roots() -> dict[str, str]:
    """Capture configured physical seats; content identities remain manifest pins."""
    result = {}
    for token, environment_name in MANIFEST_HOST_ROOT_ENV.items():
        value = os.environ.get(environment_name)
        if value is None:
            continue
        require(value and Path(value).is_absolute(),
                f"{environment_name} must be an absolute host path")
        lexical = lexical_absolute_path(Path(value))
        canonical = lexical.resolve(strict=True)
        require(lexical == canonical and not canonical.is_symlink(),
                f"{environment_name} is redirected or noncanonical")
        result[token] = str(canonical)
    return result


def manifest_host_path(
    value: object, context: str, roots: dict[str, str],
) -> Path:
    require(isinstance(value, str) and value,
            f"{context} must be a non-empty host path")
    match = MANIFEST_HOST_PATH_RE.fullmatch(value)
    if match is None:
        require(Path(value).is_absolute(), f"{context} must be absolute")
        return lexical_absolute_path(Path(value))
    token, suffix = match.groups()
    require(token in MANIFEST_HOST_ROOT_ENV and token in roots,
            f"{context} requires ${MANIFEST_HOST_ROOT_ENV.get(token, token)}")
    relative = PurePosixPath(suffix or "")
    require(not relative.is_absolute() and ".." not in relative.parts,
            f"{context} host-root suffix escapes")
    return lexical_absolute_path(
        Path(roots[token]).joinpath(*relative.parts)
    )


def manifest_host_string(
    value: object, context: str, roots: dict[str, str],
) -> str:
    return str(manifest_host_path(value, context, roots))


def validate_wine_prefix_template(files: list[dict]) -> dict:
    """Validate the dedicated immutable four-file Wine prefix seed."""
    require(len(files) == 4, "Wine prefix template must contain four pins")
    roots = {Path(item["path"]).parent for item in files}
    require(len(roots) == 1,
            "Wine prefix template files do not share one physical root")
    root = roots.pop()
    canonical = root.resolve(strict=True)
    metadata = root.stat(follow_symlinks=False)
    require(root == canonical and stat.S_ISDIR(metadata.st_mode)
            and not root.is_symlink()
            and stat.S_IMODE(metadata.st_mode) == 0o555,
            "Wine prefix template root is redirected or not mode 0555")
    snapshot = canonical_tree_snapshot(
        root, hash_files=True, max_entries=5, max_depth=0
    )
    by_name = {
        record["path"]: record for record in snapshot["records"]
        if record["path"] != "."
    }
    expected_names = {
        ".update-timestamp", "system.reg", "user.reg", "userdef.reg"
    }
    require(snapshot["entry_count"] == 5
            and snapshot["max_depth"] == 0
            and set(by_name) == expected_names,
            "Wine prefix template root contains an extra or missing entry")
    pins = {item["name"]: item for item in files}
    for name in sorted(expected_names):
        record = by_name[name]
        pin = pins[name]
        require(record["type"] == "file"
                and record["mode"] == 0o444
                and pin["mode"] == 0o444
                and Path(pin["path"]) == root / name
                and record["sha256"] == pin["sha256"],
                f"Wine prefix template leaf differs: {name}")
    return {"root": str(root), "tree": _tree_pin(snapshot)}


class BuildRootAuthority:
    """Held, no-follow authority for every byte-identity build-tree access.

    All names are interpreted relative to one already-open build root.  Each
    directory component is opened with ``O_DIRECTORY|O_NOFOLLOW`` and all
    leaf operations are ``*at`` operations against held parent descriptors.
    Thus an ancestor rename can detach work from the visible namespace, but it
    can never redirect this process into the source tree or another directory.
    Verification additionally pins every directory/file read and reopens the
    names before publishing its verdict, rejecting any detached epoch.
    """

    def __init__(self, build_dir: Path, root_fd: int, build_root: Path):
        self.build_dir = lexical_absolute_path(build_dir)
        self.build_root = build_root
        self.root_fd = root_fd
        root_metadata = os.fstat(root_fd)
        self.root_identity = (root_metadata.st_dev, root_metadata.st_ino)
        self.track_reads = False
        self.directory_pins: dict[tuple[str, ...], tuple[int, int]] = {}
        self.file_pins: dict[
            tuple[str, ...], tuple[int, int, int, int, str]
        ] = {}
        self.symlink_pins: dict[
            tuple[str, ...], tuple[int, int, int, str]
        ] = {}
        self.enumerated_file_pins: dict[
            tuple[str, ...], tuple[int, int]
        ] = {}
        self.directory_membership_pins: dict[
            tuple[str, ...], tuple[tuple[str, str, int, int], ...]
        ] = {}
        self.external_file_pins: dict[str, dict] = {}
        self.external_absence_pins: dict[str, dict] = {}
        self.build_absence_pins: dict[
            tuple[str, ...], tuple[tuple[str, ...], tuple[int, int]]
        ] = {}
        self.lock_pins: dict[tuple[str, ...], tuple[int, int]] = {}
        self.compiler_holders: list[HeldBuildDirectories] = []
        self.compiler_stack = ExitStack()
        # Shared immutable snapshots are fully scanned once per authoritative
        # transaction. Producer runs verify their copied/loaded leaves, and a
        # terminal rescan closes the cache before publication.
        self.snapshot_validation_cache: dict[str, dict] = {}
        # The POSIX-Wine backend projects the already-authenticated command
        # and toolchain inputs into one transaction-scoped logical Z: view.
        # Producer invocations lease its single empty writable build branch;
        # they never clone the immutable tree per process.
        self.execution_projection: dict | None = None
        self.execution_projection_receipt: dict | None = None
        self.resident_producer_state_cache: dict | None = None
        self.terminal_verification_state_cache: dict | None = None
        self.resident_input_retirement_receipt: dict | None = None

    def close(self) -> None:
        """Release descriptors retained for one authoritative transaction."""
        self.compiler_stack.close()
        self.compiler_holders.clear()
        try:
            self._close_external_pins()
        except OSError:
            pass

    def retain_directories(self, paths: list[Path]):
        """Hold private compiler paths until the build transaction closes."""
        holder = HeldBuildDirectories(self, paths)
        holder.revalidate()
        self.compiler_stack.callback(holder.close)
        self.compiler_holders.append(holder)
        return holder

    def assert_root_stable(self) -> None:
        try:
            named = os.stat(self.build_dir, follow_symlinks=False)
        except OSError as error:
            raise ByteIdentityError(
                f"configured build root changed during operation: {error}"
            ) from error
        require(stat.S_ISDIR(named.st_mode)
                and (named.st_dev, named.st_ino) == self.root_identity,
                "configured build root was swapped or redirected")

    def parts(
        self, path: Path, *, cwd: Path | None = None, allow_root: bool = False
    ) -> tuple[str, ...]:
        parts = relative_build_parts(
            path, self.build_dir, cwd, canonical_root=self.build_root
        )
        require(parts is not None and (allow_root or parts),
                f"path is outside the held build-root authority: {path}")
        return parts or ()

    def path(self, parts: tuple[str, ...]) -> Path:
        return self.build_root.joinpath(*parts)

    def _record_directory(self, parts: tuple[str, ...], descriptor: int) -> None:
        if self.track_reads:
            metadata = os.fstat(descriptor)
            identity = (metadata.st_dev, metadata.st_ino)
            previous = self.directory_pins.get(parts)
            require(previous is None or previous == identity,
                    f"build directory changed during authority epoch: {self.path(parts)}")
            self.directory_pins[parts] = identity

    def open_directory_parts(
        self, parts: tuple[str, ...], *, create: bool = False
    ) -> int:
        descriptor = os.dup(self.root_fd)
        prefix: list[str] = []
        try:
            self._record_directory((), descriptor)
            for part in parts:
                require(part not in ("", ".", "..") and "/" not in part
                        and "\0" not in part,
                        "unsafe build-tree path component")
                if create:
                    try:
                        os.mkdir(part, 0o700, dir_fd=descriptor)
                    except FileExistsError:
                        pass
                try:
                    child = os.open(part, DIRECTORY_FD_FLAGS, dir_fd=descriptor)
                except FileNotFoundError:
                    raise
                except OSError as error:
                    raise ByteIdentityError(
                        f"build directory is redirected or invalid: "
                        f"{self.path(tuple(prefix + [part]))}: {error}"
                    ) from error
                os.close(descriptor)
                descriptor = child
                prefix.append(part)
                self._record_directory(tuple(prefix), descriptor)
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    @contextmanager
    def parent(
        self, path: Path, *, create: bool = False, cwd: Path | None = None
    ):
        parts = self.parts(path, cwd=cwd)
        descriptor = self.open_directory_parts(parts[:-1], create=create)
        try:
            yield descriptor, parts[-1], parts
        finally:
            os.close(descriptor)

    def mkdirs(self, path: Path) -> None:
        self.assert_root_stable()
        parts = self.parts(path, allow_root=True)
        descriptor = self.open_directory_parts(parts, create=True)
        try:
            metadata = os.fstat(descriptor)
            identity = (metadata.st_dev, metadata.st_ino)
        finally:
            os.close(descriptor)
        visible = self.open_directory_parts(parts)
        try:
            metadata = os.fstat(visible)
            require((metadata.st_dev, metadata.st_ino) == identity,
                    f"created build directory is not visible: {self.path(parts)}")
        finally:
            os.close(visible)
        self.assert_root_stable()

    def chmod_directory(self, path: Path, mode: int) -> None:
        """Change one build directory through its held no-follow descriptor."""
        require(type(mode) is int and 0 <= mode <= 0o777,
                f"build directory mode is invalid: {path}")
        self.assert_root_stable()
        parts = self.parts(path, allow_root=True)
        descriptor = self.open_directory_parts(parts)
        try:
            before = os.fstat(descriptor)
            require(stat.S_ISDIR(before.st_mode),
                    f"build path is not a directory: {path}")
            os.fchmod(descriptor, mode)
            after = os.fstat(descriptor)
            require(
                (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino)
                and stat.S_IMODE(after.st_mode) == mode,
                f"build directory mode change was not stable: {path}",
            )
        finally:
            os.close(descriptor)
        self.assert_root_stable()

    def mkdir_exclusive(self, path: Path) -> None:
        self.assert_root_stable()
        created = False
        try:
            with self.parent(path, create=True) as (parent_fd, name, parts):
                parent_metadata = os.fstat(parent_fd)
                parent_identity = (parent_metadata.st_dev, parent_metadata.st_ino)
                try:
                    os.mkdir(name, 0o700, dir_fd=parent_fd)
                    created = True
                except FileExistsError as error:
                    raise ByteIdentityError(
                        f"private build directory already exists: {self.path(parts)}"
                    ) from error
                descriptor = os.open(name, DIRECTORY_FD_FLAGS, dir_fd=parent_fd)
                try:
                    metadata = os.fstat(descriptor)
                    identity = (metadata.st_dev, metadata.st_ino)
                    self._record_directory(parts, descriptor)
                finally:
                    os.close(descriptor)
                current_parent = self.open_directory_parts(parts[:-1])
                try:
                    current_parent_metadata = os.fstat(current_parent)
                    require(
                        (current_parent_metadata.st_dev, current_parent_metadata.st_ino)
                        == parent_identity,
                        f"private build parent changed: {self.path(parts[:-1])}",
                    )
                    current = os.open(name, DIRECTORY_FD_FLAGS, dir_fd=current_parent)
                    try:
                        current_metadata = os.fstat(current)
                        require(
                            (current_metadata.st_dev, current_metadata.st_ino)
                            == identity,
                            f"private build directory changed: {self.path(parts)}",
                        )
                    finally:
                        os.close(current)
                finally:
                    os.close(current_parent)
            self.assert_root_stable()
        except BaseException:
            if created:
                # ``os.mkdir`` transferred ownership to this call. Any later
                # check failure must roll back that exact seat; a collision
                # never sets ``created`` and is therefore never deleted.
                self.remove_tree(path)
                self.assert_absent(path)
            raise

    @contextmanager
    def hold_directories(self, paths: list[Path]):
        """Hold and revalidate private compiler directories across VC argv I/O.

        VC4.2 receives pathname `/Fo` and `/Fd` arguments, not inherited file
        descriptors.  These held descriptors cannot make an adversarial
        same-user rename impossible for VC itself; they do prove that every
        admitted path is a no-follow authority-created directory immediately
        before spawn and that the same named directories remain after child
        postflight, before any output is consumed or installed.
        """
        holder = HeldBuildDirectories(self, paths)
        try:
            holder.revalidate()
            yield holder
        finally:
            try:
                holder.revalidate()
            finally:
                holder.close()

    @staticmethod
    def _entry_kind(mode: int) -> str:
        if stat.S_ISREG(mode):
            return "file"
        if stat.S_ISDIR(mode):
            return "directory"
        if stat.S_ISLNK(mode):
            return "symlink"
        return "other"

    def _snapshot_directory_fd(
        self, descriptor: int, parts: tuple[str, ...]
    ) -> tuple[tuple[str, str, int, int], ...]:
        try:
            names_before = sorted(os.listdir(descriptor))
            entries = []
            for name in names_before:
                require(
                    name not in ("", ".", "..") and "/" not in name
                    and "\0" not in name,
                    f"unsafe build directory entry: {self.path(parts)}",
                )
                metadata = os.stat(
                    name, dir_fd=descriptor, follow_symlinks=False
                )
                entries.append(
                    (
                        name,
                        self._entry_kind(metadata.st_mode),
                        metadata.st_dev,
                        metadata.st_ino,
                    )
                )
            require(
                sorted(os.listdir(descriptor)) == names_before,
                f"build directory changed while enumerated: {self.path(parts)}",
            )
        except OSError as error:
            raise ByteIdentityError(
                f"cannot enumerate build directory {self.path(parts)}: {error}"
            ) from error
        snapshot = tuple(entries)
        if self.track_reads:
            previous = self.directory_membership_pins.get(parts)
            require(
                previous is None or previous == snapshot,
                f"build directory membership changed during authority epoch: "
                f"{self.path(parts)}",
            )
            self.directory_membership_pins[parts] = snapshot
        return snapshot

    def lstat(self, path: Path, *, cwd: Path | None = None):
        try:
            with self.parent(path, cwd=cwd) as (parent_fd, name, _):
                try:
                    return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    return None
        except FileNotFoundError:
            return None

    def is_regular_file(self, path: Path) -> bool:
        metadata = self.lstat(path)
        return metadata is not None and stat.S_ISREG(metadata.st_mode)

    def stable_regular_file_identity(self, path: Path) -> tuple:
        """Return the backend's opaque O(1) identity for one regular file."""
        if active_authority_for_path(path) is self:
            metadata = self.lstat(path)
        else:
            metadata = path.stat(follow_symlinks=False)
        require(metadata is not None and stat.S_ISREG(metadata.st_mode),
                f"stable file identity is absent or non-regular: {path}")
        if hasattr(metadata, "attributes"):
            return (
                "windows_file_id_v1", metadata.st_dev, metadata.st_ino,
                metadata.st_size, metadata.st_mtime_ns,
                metadata.attributes, metadata.st_nlink,
            )
        return (
            "posix_inode_times_v1", metadata.st_dev, metadata.st_ino,
            metadata.st_size, metadata.st_mtime_ns,
            metadata.st_ctime_ns, metadata.st_nlink,
        )

    def read_bytes(
        self, path: Path, *, max_bytes: int = 1024 * 1024 * 1024
    ) -> bytes:
        self.assert_root_stable()
        with self.parent(path) as (parent_fd, name, parts):
            parent_metadata = os.fstat(parent_fd)
            parent_identity = (parent_metadata.st_dev, parent_metadata.st_ino)
            try:
                descriptor = os.open(name, AUDIT_FILE_FD_FLAGS, dir_fd=parent_fd)
            except OSError as error:
                raise ByteIdentityError(f"cannot open build file {self.path(parts)}: {error}") from error
            try:
                before = os.fstat(descriptor)
                require(stat.S_ISREG(before.st_mode)
                        and 0 <= before.st_size <= max_bytes,
                        f"build file is not a bounded regular file: {self.path(parts)}")
                enumerated = self.enumerated_file_pins.get(parts)
                require(
                    enumerated is None
                    or enumerated == (before.st_dev, before.st_ino),
                    f"enumerated build file changed before read: {self.path(parts)}",
                )
                remaining = before.st_size
                chunks = []
                while remaining:
                    chunk = os.read(descriptor, min(remaining, 1024 * 1024))
                    require(chunk, f"build file changed while read: {self.path(parts)}")
                    chunks.append(chunk)
                    remaining -= len(chunk)
                require(not os.read(descriptor, 1),
                        f"build file grew while read: {self.path(parts)}")
                after = os.fstat(descriptor)
                data = b"".join(chunks)
                identity = (
                    after.st_dev, after.st_ino, after.st_size,
                    after.st_mtime_ns, sha256_bytes(data),
                )
                require((before.st_dev, before.st_ino, before.st_size,
                         before.st_mtime_ns)
                        == identity[:4],
                        f"build file changed while read: {self.path(parts)}")
                if self.track_reads:
                    previous = self.file_pins.get(parts)
                    require(previous is None or previous == identity,
                            f"build file changed during authority epoch: {self.path(parts)}")
                    self.file_pins[parts] = identity
                current_parent = self.open_directory_parts(parts[:-1])
                try:
                    parent_now = os.fstat(current_parent)
                    require((parent_now.st_dev, parent_now.st_ino)
                            == parent_identity,
                            f"build file parent changed while read: {self.path(parts)}")
                    visible = os.stat(name, dir_fd=current_parent, follow_symlinks=False)
                    require((visible.st_dev, visible.st_ino)
                            == (after.st_dev, after.st_ino),
                            f"build file changed while read: {self.path(parts)}")
                finally:
                    os.close(current_parent)
                self.assert_root_stable()
                return data
            finally:
                os.close(descriptor)

    def read_text(self, path: Path, *, encoding: str = "utf-8") -> str:
        try:
            return self.read_bytes(path).decode(encoding)
        except UnicodeError as error:
            raise ByteIdentityError(f"cannot decode build file {path}: {error}") from error

    def atomic_write(
        self, path: Path, data: bytes, *, if_changed: bool = False,
        mode: int = 0o600,
    ) -> None:
        require(type(mode) is int and 0 <= mode <= 0o777,
                f"atomic build output mode is invalid: {path}")
        self.assert_root_stable()
        with self.parent(path, create=True) as (parent_fd, name, parts):
            parent_metadata = os.fstat(parent_fd)
            parent_identity = (parent_metadata.st_dev, parent_metadata.st_ino)
            if if_changed:
                current_identity = None
                try:
                    current_fd = os.open(
                        name, AUDIT_FILE_FD_FLAGS, dir_fd=parent_fd
                    )
                    try:
                        current_metadata = os.fstat(current_fd)
                        if (stat.S_ISREG(current_metadata.st_mode)
                                and current_metadata.st_size == len(data)):
                            chunks = []
                            remaining = current_metadata.st_size
                            while remaining:
                                chunk = os.read(
                                    current_fd, min(remaining, 1024 * 1024)
                                )
                                require(chunk, f"build file changed while read: {path}")
                                chunks.append(chunk)
                                remaining -= len(chunk)
                            require(not os.read(current_fd, 1),
                                    f"build file grew while read: {path}")
                            current = b"".join(chunks)
                            after = os.fstat(current_fd)
                            require(
                                (
                                    current_metadata.st_dev,
                                    current_metadata.st_ino,
                                    current_metadata.st_size,
                                    current_metadata.st_mtime_ns,
                                )
                                == (
                                    after.st_dev,
                                    after.st_ino,
                                    after.st_size,
                                    after.st_mtime_ns,
                                ),
                                f"build file changed while read: {path}",
                            )
                            current_identity = (after.st_dev, after.st_ino)
                        else:
                            current = None
                    finally:
                        os.close(current_fd)
                except (FileNotFoundError, OSError):
                    current = None
                if current == data:
                    current_parent = self.open_directory_parts(parts[:-1])
                    try:
                        metadata = os.fstat(current_parent)
                        visible = os.stat(
                            name, dir_fd=current_parent, follow_symlinks=False
                        )
                        require((metadata.st_dev, metadata.st_ino) == parent_identity,
                                f"build output parent changed: {self.path(parts[:-1])}")
                        require(
                            stat.S_ISREG(visible.st_mode)
                            and (visible.st_dev, visible.st_ino) == current_identity,
                            f"build output changed while compared: {self.path(parts)}",
                        )
                    finally:
                        os.close(current_parent)
                    self.assert_root_stable()
                    return
            temporary = f".{name}.{uuid.uuid4().hex}.tmp"
            flags = (
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0)
            )
            descriptor = None
            try:
                descriptor = os.open(temporary, flags, mode, dir_fd=parent_fd)
                os.fchmod(descriptor, mode)
                view = memoryview(data)
                while view:
                    count = os.write(descriptor, view)
                    require(count > 0, f"short atomic write: {self.path(parts)}")
                    view = view[count:]
                os.fsync(descriptor)
                os.close(descriptor)
                descriptor = None
                os.rename(
                    temporary, name,
                    src_dir_fd=parent_fd, dst_dir_fd=parent_fd,
                )
                installed = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                require(stat.S_ISREG(installed.st_mode)
                        and installed.st_size == len(data),
                        f"atomic build output is not the installed file: {self.path(parts)}")
                current_parent = self.open_directory_parts(parts[:-1])
                try:
                    metadata = os.fstat(current_parent)
                    require((metadata.st_dev, metadata.st_ino) == parent_identity,
                            f"build output parent changed: {self.path(parts[:-1])}")
                    visible = os.stat(name, dir_fd=current_parent, follow_symlinks=False)
                    require((visible.st_dev, visible.st_ino)
                            == (installed.st_dev, installed.st_ino),
                            f"atomic build output is not visible: {self.path(parts)}")
                finally:
                    os.close(current_parent)
                self.assert_root_stable()
                self.file_pins.pop(parts, None)
                self.symlink_pins.pop(parts, None)
            except BaseException:
                if descriptor is not None:
                    os.close(descriptor)
                try:
                    os.unlink(temporary, dir_fd=parent_fd)
                except OSError:
                    pass
                raise

    def atomic_symlink(self, path: Path, target: Path) -> None:
        self.assert_root_stable()
        with self.parent(path, create=True) as (parent_fd, name, parts):
            parent_metadata = os.fstat(parent_fd)
            parent_identity = (parent_metadata.st_dev, parent_metadata.st_ino)
            temporary = f".{name}.{uuid.uuid4().hex}.tmp"
            try:
                os.symlink(str(target), temporary, dir_fd=parent_fd)
                os.rename(
                    temporary, name,
                    src_dir_fd=parent_fd, dst_dir_fd=parent_fd,
                )
                current_parent = self.open_directory_parts(parts[:-1])
                try:
                    metadata = os.fstat(current_parent)
                    require((metadata.st_dev, metadata.st_ino) == parent_identity,
                            f"runtime-bin parent changed: {self.path(parts[:-1])}")
                    require(os.readlink(name, dir_fd=current_parent) == str(target),
                            f"runtime-bin symlink is not visible: {self.path(parts)}")
                finally:
                    os.close(current_parent)
                self.assert_root_stable()
                self.file_pins.pop(parts, None)
                self.symlink_pins.pop(parts, None)
            except BaseException:
                try:
                    os.unlink(temporary, dir_fd=parent_fd)
                except OSError:
                    pass
                raise

    def readlink(self, path: Path) -> str:
        self.assert_root_stable()
        with self.parent(path) as (parent_fd, name, parts):
            try:
                parent_metadata = os.fstat(parent_fd)
                metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                require(stat.S_ISLNK(metadata.st_mode),
                        f"build entry is not a symlink: {self.path(parts)}")
                target = os.readlink(name, dir_fd=parent_fd)
                identity = (
                    metadata.st_dev, metadata.st_ino,
                    metadata.st_mtime_ns, target,
                )
                if self.track_reads:
                    previous = self.symlink_pins.get(parts)
                    require(previous is None or previous == identity,
                            f"build symlink changed during authority epoch: {self.path(parts)}")
                    self.symlink_pins[parts] = identity
                current_parent = self.open_directory_parts(parts[:-1])
                try:
                    parent_now = os.fstat(current_parent)
                    visible = os.stat(name, dir_fd=current_parent, follow_symlinks=False)
                    require((parent_now.st_dev, parent_now.st_ino)
                            == (parent_metadata.st_dev, parent_metadata.st_ino)
                            and (visible.st_dev, visible.st_ino)
                            == (metadata.st_dev, metadata.st_ino)
                            and os.readlink(name, dir_fd=current_parent) == target,
                            f"build symlink changed while read: {self.path(parts)}")
                finally:
                    os.close(current_parent)
                self.assert_root_stable()
                return target
            except OSError as error:
                raise ByteIdentityError(f"cannot read build symlink {self.path(parts)}: {error}") from error

    def list_names(self, path: Path) -> list[str]:
        self.assert_root_stable()
        parts = self.parts(path, allow_root=True)
        descriptor = self.open_directory_parts(parts)
        try:
            metadata = os.fstat(descriptor)
            snapshot = self._snapshot_directory_fd(descriptor, parts)
            names = [entry[0] for entry in snapshot]
        finally:
            os.close(descriptor)
        visible = self.open_directory_parts(parts)
        try:
            current = os.fstat(visible)
            require((current.st_dev, current.st_ino)
                    == (metadata.st_dev, metadata.st_ino),
                    f"build directory changed while enumerated: {self.path(parts)}")
        finally:
            os.close(visible)
        self.assert_root_stable()
        return names

    @staticmethod
    def _open_external_directory(path: Path) -> int:
        """Open one canonical absolute directory without following components."""
        require(path.is_absolute(), f"external directory is not absolute: {path}")
        descriptor = os.open(Path(path.anchor), DIRECTORY_FD_FLAGS)
        try:
            for part in path.parts[1:]:
                metadata = os.stat(
                    part, dir_fd=descriptor, follow_symlinks=False
                )
                require(
                    stat.S_ISDIR(metadata.st_mode),
                    f"external directory component is redirected: {path}",
                )
                child = os.open(part, DIRECTORY_FD_FLAGS, dir_fd=descriptor)
                opened = os.fstat(child)
                require(
                    (opened.st_dev, opened.st_ino)
                    == (metadata.st_dev, metadata.st_ino),
                    f"external directory changed while opened: {path}",
                )
                os.close(descriptor)
                descriptor = child
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    @staticmethod
    def _read_regular_fd(
        descriptor: int, context: str, *, max_bytes: int = 1024 * 1024 * 1024
    ) -> tuple[bytes, tuple[int, int, int, int, int, str]]:
        before = os.fstat(descriptor)
        require(
            stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= max_bytes,
            f"{context} is not a bounded regular file",
        )
        os.lseek(descriptor, 0, os.SEEK_SET)
        remaining = before.st_size
        chunks = []
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            require(chunk, f"{context} changed while read")
            chunks.append(chunk)
            remaining -= len(chunk)
        require(not os.read(descriptor, 1), f"{context} grew while read")
        after = os.fstat(descriptor)
        data = b"".join(chunks)
        identity = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            sha256_bytes(data),
        )
        require(
            (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_size,
                before.st_mtime_ns,
            )
            == identity[:5],
            f"{context} changed while read",
        )
        return data, identity

    def read_external_bytes(
        self, path: Path, *, max_bytes: int = 1024 * 1024 * 1024
    ) -> bytes:
        """Read and, during verify, retain an exact external input snapshot."""
        requested = lexical_absolute_path(path)
        try:
            canonical = requested.resolve(strict=True)
        except OSError as error:
            raise ByteIdentityError(
                f"cannot resolve authoritative external input {requested}: {error}"
            ) from error
        require(
            active_authority_for_path(canonical) is None,
            f"external input unexpectedly resolves into the build tree: {requested}",
        )
        parent_fd = self._open_external_directory(canonical.parent)
        descriptor = None
        try:
            parent_metadata = os.fstat(parent_fd)
            descriptor = os.open(
                canonical.name, AUDIT_FILE_FD_FLAGS, dir_fd=parent_fd
            )
            data, identity = self._read_regular_fd(
                descriptor, f"authoritative external input {requested}",
                max_bytes=max_bytes,
            )
            visible = os.stat(
                canonical.name, dir_fd=parent_fd, follow_symlinks=False
            )
            require(
                stat.S_ISREG(visible.st_mode)
                and (visible.st_dev, visible.st_ino) == identity[:2]
                and requested.resolve(strict=True) == canonical,
                f"authoritative external input changed while read: {requested}",
            )
            if not self.track_reads:
                return data
            key = str(requested)
            pin = {
                "requested": requested,
                "canonical": canonical,
                "parent_identity": (
                    parent_metadata.st_dev, parent_metadata.st_ino
                ),
                "identity": identity,
            }
            previous = self.external_file_pins.get(key)
            if previous is not None:
                require(
                    previous["canonical"] == canonical
                    and previous["identity"] == identity
                    and previous["parent_identity"] == pin["parent_identity"],
                    f"authoritative external input changed during verification: "
                    f"{requested}",
                )
            else:
                self.external_file_pins[key] = pin
            return data
        except (OSError, ValueError) as error:
            raise ByteIdentityError(
                f"cannot read authoritative external input {requested}: {error}"
            ) from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if parent_fd is not None:
                os.close(parent_fd)

    def require_external_absent(self, path: Path) -> None:
        """Require and, during verify, retain one exact absent external name."""
        requested = lexical_absolute_path(path)
        try:
            canonical_parent = requested.parent.resolve(strict=True)
        except OSError as error:
            raise ByteIdentityError(
                f"cannot resolve required-absence parent {requested.parent}: {error}"
            ) from error
        parent_fd = self._open_external_directory(canonical_parent)
        try:
            parent_metadata = os.fstat(parent_fd)
            require(
                requested.parent.resolve(strict=True) == canonical_parent,
                f"required-absence parent changed: {requested.parent}",
            )
            try:
                os.stat(requested.name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ByteIdentityError(
                    f"authoritative external file must remain absent: {requested}"
                )
            if not self.track_reads:
                return
            key = str(requested)
            pin = {
                "requested": requested,
                "canonical_parent": canonical_parent,
                "parent_identity": (
                    parent_metadata.st_dev, parent_metadata.st_ino
                ),
            }
            previous = self.external_absence_pins.get(key)
            if previous is not None:
                require(
                    previous["canonical_parent"] == canonical_parent
                    and previous["parent_identity"] == pin["parent_identity"],
                    f"required-absence parent changed during verification: {requested}",
                )
            else:
                self.external_absence_pins[key] = pin
        finally:
            if parent_fd is not None:
                os.close(parent_fd)

    def _close_external_pins(self) -> None:
        self.external_file_pins.clear()
        self.external_absence_pins.clear()

    def revalidate_external_inputs(self) -> None:
        for pin in self.external_file_pins.values():
            current_parent = self._open_external_directory(pin["canonical"].parent)
            try:
                current = os.fstat(current_parent)
                require(
                    (current.st_dev, current.st_ino) == pin["parent_identity"],
                    f"authoritative external parent changed before verdict: "
                    f"{pin['canonical'].parent}",
                )
                descriptor = os.open(
                    pin["canonical"].name,
                    AUDIT_FILE_FD_FLAGS,
                    dir_fd=current_parent,
                )
                try:
                    data, identity = self._read_regular_fd(
                        descriptor,
                        f"authoritative external input {pin['requested']}",
                    )
                    visible = os.stat(
                        pin["canonical"].name,
                        dir_fd=current_parent,
                        follow_symlinks=False,
                    )
                    require(
                        identity == pin["identity"]
                        and sha256_bytes(data) == pin["identity"][-1]
                        and (visible.st_dev, visible.st_ino) == identity[:2],
                        f"authoritative external input changed before verdict: "
                        f"{pin['requested']}",
                    )
                finally:
                    os.close(descriptor)
            finally:
                os.close(current_parent)
            require(
                pin["requested"].resolve(strict=True) == pin["canonical"],
                f"authoritative external input was replaced before verdict: "
                f"{pin['requested']}",
            )
        for pin in self.external_absence_pins.values():
            require(
                pin["requested"].parent.resolve(strict=True)
                == pin["canonical_parent"],
                f"required-absence parent changed before verdict: "
                f"{pin['requested'].parent}",
            )
            parent_now = self._open_external_directory(pin["canonical_parent"])
            try:
                metadata = os.fstat(parent_now)
                require(
                    (metadata.st_dev, metadata.st_ino)
                    == pin["parent_identity"],
                    f"required-absence parent was replaced before verdict: "
                    f"{pin['canonical_parent']}",
                )
                try:
                    os.stat(
                        pin["requested"].name,
                        dir_fd=parent_now,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    pass
                else:
                    raise ByteIdentityError(
                        f"authoritative external file appeared before verdict: "
                        f"{pin['requested']}"
                    )
            finally:
                os.close(parent_now)

    def unlink(
        self, path: Path, *, cwd: Path | None = None, missing_ok: bool = True
    ) -> bool:
        self.assert_root_stable()
        parts = self.parts(path, cwd=cwd)
        try:
            parent_fd = self.open_directory_parts(parts[:-1])
        except FileNotFoundError:
            return False
        try:
            parent_metadata = os.fstat(parent_fd)
            parent_identity = (parent_metadata.st_dev, parent_metadata.st_ino)
            try:
                metadata = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return False
            require(not stat.S_ISDIR(metadata.st_mode),
                    f"refusing to unlink a build directory as a file: {self.path(parts)}")
            try:
                os.unlink(parts[-1], dir_fd=parent_fd)
            except FileNotFoundError:
                if missing_ok:
                    return False
                raise
            self.file_pins.pop(parts, None)
            self.symlink_pins.pop(parts, None)
            current_parent = self.open_directory_parts(parts[:-1])
            try:
                current = os.fstat(current_parent)
                require((current.st_dev, current.st_ino) == parent_identity,
                        f"build output parent changed during cleanup: {self.path(parts[:-1])}")
            finally:
                os.close(current_parent)
            self.assert_root_stable()
            return True
        finally:
            os.close(parent_fd)

    def prune_leaf_or_redirect(self, path: Path) -> bool:
        """Remove a leaf, or the first non-directory ancestor, without following it."""
        self.assert_root_stable()
        parts = self.parts(path)
        descriptor = os.dup(self.root_fd)
        try:
            for index, part in enumerate(parts):
                try:
                    metadata = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                except FileNotFoundError:
                    return False
                last = index == len(parts) - 1
                if last or not stat.S_ISDIR(metadata.st_mode):
                    require(not stat.S_ISDIR(metadata.st_mode),
                            f"verdict leaf is unexpectedly a directory: {self.path(parts)}")
                    os.unlink(part, dir_fd=descriptor)
                    self.file_pins.pop(tuple(parts[:index + 1]), None)
                    return not last
                try:
                    child = os.open(part, DIRECTORY_FD_FLAGS, dir_fd=descriptor)
                except OSError:
                    # The entry was swapped after lstat. Remove only the current
                    # lexical non-directory redirect, never anything beneath it.
                    current = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                    require(not stat.S_ISDIR(current.st_mode),
                            f"build namespace changed during invalidation: {self.path(tuple(parts[:index + 1]))}")
                    os.unlink(part, dir_fd=descriptor)
                    return True
                os.close(descriptor)
                descriptor = child
        finally:
            os.close(descriptor)
            self.assert_root_stable()
        return False

    def assert_absent(self, path: Path) -> None:
        self.assert_root_stable()
        parts = self.parts(path)
        descriptor = os.dup(self.root_fd)
        try:
            for index, part in enumerate(parts):
                try:
                    metadata = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                except FileNotFoundError:
                    return
                if index == len(parts) - 1:
                    raise ByteIdentityError(
                        f"build state could not be invalidated: {self.path(parts)}"
                    )
                require(stat.S_ISDIR(metadata.st_mode),
                        f"build namespace is redirected: {self.path(tuple(parts[:index + 1]))}")
                child = os.open(part, DIRECTORY_FD_FLAGS, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
        finally:
            os.close(descriptor)
            self.assert_root_stable()

    def pin_build_absence(self, path: Path) -> None:
        """Pin the first absent component of one build-tree namespace."""
        parts = self.parts(path)
        descriptor = os.dup(self.root_fd)
        parent_parts: tuple[str, ...] = ()
        try:
            for index, part in enumerate(parts):
                try:
                    metadata = os.stat(
                        part, dir_fd=descriptor, follow_symlinks=False
                    )
                except FileNotFoundError:
                    if self.track_reads:
                        parent = os.fstat(descriptor)
                        missing_parts = parts[:index + 1]
                        value = (
                            parent_parts,
                            (parent.st_dev, parent.st_ino),
                        )
                        previous = self.build_absence_pins.get(missing_parts)
                        require(
                            previous is None or previous == value,
                            f"absent build namespace changed during epoch: "
                            f"{self.path(missing_parts)}",
                        )
                        self.build_absence_pins[missing_parts] = value
                    return
                require(
                    stat.S_ISDIR(metadata.st_mode),
                    f"absent build namespace is redirected: "
                    f"{self.path(parts[:index + 1])}",
                )
                child = os.open(part, DIRECTORY_FD_FLAGS, dir_fd=descriptor)
                opened = os.fstat(child)
                require(
                    (opened.st_dev, opened.st_ino)
                    == (metadata.st_dev, metadata.st_ino),
                    f"build namespace changed while absence was pinned: "
                    f"{self.path(parts[:index + 1])}",
                )
                os.close(descriptor)
                descriptor = child
                parent_parts = parts[:index + 1]
            raise ByteIdentityError(
                f"build namespace expected absent but exists: {self.path(parts)}"
            )
        finally:
            os.close(descriptor)

    def _remove_directory_contents(self, directory_fd: int) -> None:
        # Private fake-Z inputs are deliberately sealed readonly for the child.
        # Reopen-time descriptor authority, rather than pathname chmod, restores
        # owner write permission solely for bounded recursive cleanup.
        os.fchmod(directory_fd, 0o700)
        for name in sorted(os.listdir(directory_fd)):
            require(name not in ("", ".", "..") and "/" not in name
                    and "\0" not in name,
                    "unsafe entry in private compiler directory")
            try:
                metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if stat.S_ISDIR(metadata.st_mode):
                child_fd = os.open(name, DIRECTORY_FD_FLAGS, dir_fd=directory_fd)
                try:
                    opened = os.fstat(child_fd)
                    require(
                        (opened.st_dev, opened.st_ino)
                        == (metadata.st_dev, metadata.st_ino),
                        f"private compiler directory changed during cleanup: {name}",
                    )
                    self._remove_directory_contents(child_fd)
                finally:
                    os.close(child_fd)
                try:
                    os.rmdir(name, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass
            else:
                try:
                    os.unlink(name, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass

    def remove_tree(self, path: Path) -> None:
        self.assert_root_stable()
        parts = self.parts(path)
        try:
            parent_fd = self.open_directory_parts(parts[:-1])
        except FileNotFoundError:
            return
        try:
            parent_metadata = os.fstat(parent_fd)
            parent_identity = (parent_metadata.st_dev, parent_metadata.st_ino)
            try:
                metadata = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return
            if not stat.S_ISDIR(metadata.st_mode):
                os.unlink(parts[-1], dir_fd=parent_fd)
            else:
                directory_fd = os.open(parts[-1], DIRECTORY_FD_FLAGS, dir_fd=parent_fd)
                try:
                    opened = os.fstat(directory_fd)
                    require(
                        (opened.st_dev, opened.st_ino)
                        == (metadata.st_dev, metadata.st_ino),
                        f"private compiler directory changed during cleanup: {self.path(parts)}",
                    )
                    self._remove_directory_contents(directory_fd)
                finally:
                    os.close(directory_fd)
                try:
                    os.rmdir(parts[-1], dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
            current_parent = self.open_directory_parts(parts[:-1])
            try:
                current = os.fstat(current_parent)
                require((current.st_dev, current.st_ino) == parent_identity,
                        f"private compiler parent changed during cleanup: {self.path(parts[:-1])}")
            finally:
                os.close(current_parent)
            self.assert_root_stable()
        finally:
            os.close(parent_fd)

    def open_lock(self, path: Path):
        self.assert_root_stable()
        with self.parent(path, create=True) as (parent_fd, name, parts):
            parent_metadata = os.fstat(parent_fd)
            parent_identity = (parent_metadata.st_dev, parent_metadata.st_ino)
            flags = (
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0)
            )
            try:
                descriptor = os.open(name, flags, 0o600, dir_fd=parent_fd)
            except OSError as error:
                raise ByteIdentityError(f"cannot open build lock {path}: {error}") from error
            try:
                metadata = os.fstat(descriptor)
                require(stat.S_ISREG(metadata.st_mode), f"build lock is not regular: {path}")
                current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                require((current.st_dev, current.st_ino)
                        == (metadata.st_dev, metadata.st_ino),
                        f"build lock changed during acquisition: {path}")
                identity = (metadata.st_dev, metadata.st_ino)
                previous = self.lock_pins.get(parts)
                require(previous is None or previous == identity,
                        f"build lock identity changed: {path}")
                self.lock_pins[parts] = identity
                current_parent = self.open_directory_parts(parts[:-1])
                try:
                    current_parent_metadata = os.fstat(current_parent)
                    visible = os.stat(name, dir_fd=current_parent, follow_symlinks=False)
                    require(
                        (current_parent_metadata.st_dev, current_parent_metadata.st_ino)
                        == parent_identity
                        and stat.S_ISREG(visible.st_mode)
                        and (visible.st_dev, visible.st_ino) == identity,
                        f"build lock changed during acquisition: {path}",
                    )
                finally:
                    os.close(current_parent)
                self.assert_root_stable()
                return os.fdopen(descriptor, "a+b")
            except BaseException:
                os.close(descriptor)
                raise

    def revalidate_locks(self) -> None:
        self.assert_root_stable()
        for parts, expected in self.lock_pins.items():
            with self.parent(self.path(parts)) as (parent_fd, name, _):
                metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                require(stat.S_ISREG(metadata.st_mode)
                        and (metadata.st_dev, metadata.st_ino) == expected,
                        f"build lock changed during transaction: {self.path(parts)}")
        self.assert_root_stable()

    def enumerate_json_files(self, roots: tuple[Path, ...]) -> list[Path]:
        result: list[Path] = []

        def walk(descriptor: int, parts: tuple[str, ...]) -> None:
            snapshot = self._snapshot_directory_fd(descriptor, parts)
            for name, kind, device, inode in snapshot:
                metadata = os.stat(
                    name, dir_fd=descriptor, follow_symlinks=False
                )
                require(
                    (metadata.st_dev, metadata.st_ino) == (device, inode)
                    and self._entry_kind(metadata.st_mode) == kind,
                    f"compiler audit entry changed while enumerated: "
                    f"{self.path((*parts, name))}",
                )
                child_parts = (*parts, name)
                require(kind != "symlink",
                        f"compiler audit path is a symlink: {self.path(child_parts)}")
                if kind == "directory":
                    child_fd = os.open(name, DIRECTORY_FD_FLAGS, dir_fd=descriptor)
                    try:
                        opened = os.fstat(child_fd)
                        require(
                            (opened.st_dev, opened.st_ino)
                            == (metadata.st_dev, metadata.st_ino),
                            f"compiler audit directory changed while enumerated: {self.path(child_parts)}",
                        )
                        self._record_directory(child_parts, child_fd)
                        walk(child_fd, child_parts)
                    finally:
                        os.close(child_fd)
                else:
                    require(
                        kind == "file" and name.endswith(".json"),
                        f"undeclared compiler audit entry: {self.path(child_parts)}",
                    )
                    if self.track_reads:
                        identity = (metadata.st_dev, metadata.st_ino)
                        previous = self.enumerated_file_pins.get(child_parts)
                        require(
                            previous is None or previous == identity,
                            f"compiler audit changed while enumerated: {self.path(child_parts)}",
                        )
                        self.enumerated_file_pins[child_parts] = identity
                    result.append(self.path(child_parts))

        for root in roots:
            parts = tuple(root.parts)
            try:
                descriptor = self.open_directory_parts(parts)
            except FileNotFoundError:
                self.pin_build_absence(self.path(parts))
                continue
            try:
                walk(descriptor, parts)
            finally:
                os.close(descriptor)
        return sorted(result)

    def begin_verification_epoch(self) -> None:
        self.directory_pins.clear()
        self.file_pins.clear()
        self.symlink_pins.clear()
        self.enumerated_file_pins.clear()
        self.directory_membership_pins.clear()
        self.build_absence_pins.clear()
        self._close_external_pins()
        self.track_reads = True

    def revalidate_epoch(self) -> None:
        directory_pins = dict(self.directory_pins)
        file_pins = dict(self.file_pins)
        symlink_pins = dict(self.symlink_pins)
        enumerated_file_pins = dict(self.enumerated_file_pins)
        directory_membership_pins = dict(self.directory_membership_pins)
        build_absence_pins = dict(self.build_absence_pins)
        self.track_reads = False
        try:
            self.revalidate_locks()
            self.assert_root_stable()
            for parts, expected in directory_pins.items():
                descriptor = self.open_directory_parts(parts)
                try:
                    metadata = os.fstat(descriptor)
                    require((metadata.st_dev, metadata.st_ino) == expected,
                            f"build directory changed before verdict: {self.path(parts)}")
                finally:
                    os.close(descriptor)
            for parts, expected in directory_membership_pins.items():
                descriptor = self.open_directory_parts(parts)
                try:
                    require(
                        self._snapshot_directory_fd(descriptor, parts) == expected,
                        f"build directory membership changed before verdict: "
                        f"{self.path(parts)}",
                    )
                finally:
                    os.close(descriptor)
            for parts, expected in file_pins.items():
                data = self.read_bytes(self.path(parts))
                metadata = self.lstat(self.path(parts))
                require(metadata is not None and stat.S_ISREG(metadata.st_mode)
                        and (metadata.st_dev, metadata.st_ino, metadata.st_size,
                             metadata.st_mtime_ns, sha256_bytes(data)) == expected,
                        f"build file changed before verdict: {self.path(parts)}")
            for parts, expected in symlink_pins.items():
                with self.parent(self.path(parts)) as (parent_fd, name, _):
                    metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    target = os.readlink(name, dir_fd=parent_fd)
                    require(stat.S_ISLNK(metadata.st_mode)
                            and (metadata.st_dev, metadata.st_ino,
                                 metadata.st_mtime_ns, target) == expected,
                            f"build symlink changed before verdict: {self.path(parts)}")
            for parts, expected in enumerated_file_pins.items():
                metadata = self.lstat(self.path(parts))
                require(
                    metadata is not None
                    and stat.S_ISREG(metadata.st_mode)
                    and (metadata.st_dev, metadata.st_ino) == expected,
                    f"enumerated compiler audit changed before verdict: {self.path(parts)}",
                )
            for missing_parts, (parent_parts, parent_identity) in (
                build_absence_pins.items()
            ):
                parent_fd = self.open_directory_parts(parent_parts)
                try:
                    parent = os.fstat(parent_fd)
                    require(
                        (parent.st_dev, parent.st_ino) == parent_identity,
                        f"absent build namespace parent changed before verdict: "
                        f"{self.path(missing_parts)}",
                    )
                    try:
                        os.stat(
                            missing_parts[-1],
                            dir_fd=parent_fd,
                            follow_symlinks=False,
                        )
                    except FileNotFoundError:
                        pass
                    else:
                        raise ByteIdentityError(
                            f"absent build namespace appeared before verdict: "
                            f"{self.path(missing_parts)}"
                        )
                finally:
                    os.close(parent_fd)
            self.revalidate_external_inputs()
            self.assert_root_stable()
            self.revalidate_locks()
        finally:
            self.track_reads = True


class HeldBuildDirectories:
    """Private compiler directories and output leaves held through publication."""

    def __init__(self, authority: BuildRootAuthority, paths: list[Path]):
        self.authority = authority
        self.directories: dict[tuple[str, ...], tuple[int, tuple[int, int]]] = {}
        self.files: dict[
            tuple[str, ...], dict[str, object]
        ] = {}
        try:
            for path in paths:
                parts = authority.parts(path, allow_root=True)
                if parts in self.directories:
                    continue
                descriptor = authority.open_directory_parts(parts)
                metadata = os.fstat(descriptor)
                self.directories[parts] = (
                    descriptor,
                    (metadata.st_dev, metadata.st_ino),
                )
        except BaseException:
            self.close()
            raise

    def _held_parent(
        self, path: Path
    ) -> tuple[tuple[str, ...], int, tuple[str, ...]]:
        parts = self.authority.parts(path)
        parent_parts = parts[:-1]
        require(
            parent_parts in self.directories,
            f"compiler output parent is not held: {self.authority.path(parts)}",
        )
        return parts, self.directories[parent_parts][0], parent_parts

    def read_bytes(
        self, path: Path, *, max_bytes: int = 1024 * 1024 * 1024
    ) -> bytes:
        """Read a compiler output relative to its continuously held parent fd."""
        parts, parent_fd, parent_parts = self._held_parent(path)
        try:
            descriptor = os.open(
                parts[-1], AUDIT_FILE_FD_FLAGS, dir_fd=parent_fd
            )
        except OSError as error:
            raise ByteIdentityError(
                f"cannot open held compiler output {self.authority.path(parts)}: {error}"
            ) from error
        try:
            data, identity = self.authority._read_regular_fd(
                descriptor,
                f"held compiler output {self.authority.path(parts)}",
                max_bytes=max_bytes,
            )
            visible = os.stat(
                parts[-1], dir_fd=parent_fd, follow_symlinks=False
            )
            require(
                (visible.st_dev, visible.st_ino) == identity[:2],
                f"held compiler output changed while read: "
                f"{self.authority.path(parts)}",
            )
            current_parent = self.authority.open_directory_parts(parent_parts)
            try:
                parent_metadata = os.fstat(current_parent)
                current = os.stat(
                    parts[-1], dir_fd=current_parent, follow_symlinks=False
                )
                require(
                    (parent_metadata.st_dev, parent_metadata.st_ino)
                    == self.directories[parent_parts][1]
                    and (current.st_dev, current.st_ino) == identity[:2],
                    f"held compiler output is not visible at its admitted path: "
                    f"{self.authority.path(parts)}",
                )
            finally:
                os.close(current_parent)
            previous = self.files.get(parts)
            if previous is not None:
                require(
                    previous["identity"] == identity
                    and previous["data"] == data,
                    f"held compiler output changed during publication: "
                    f"{self.authority.path(parts)}",
                )
            else:
                self.files[parts] = {
                    "fd": descriptor,
                    "identity": identity,
                    "data": data,
                    "parent_parts": parent_parts,
                }
                descriptor = None
            return data
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def membership(self, path: Path) -> dict[str, str]:
        """Snapshot one continuously held directory and its visible name."""
        parts = self.authority.parts(path, allow_root=True)
        require(parts in self.directories,
                f"private compiler directory is not held: {path}")
        descriptor, expected_identity = self.directories[parts]
        held_snapshot = self.authority._snapshot_directory_fd(descriptor, parts)
        current = self.authority.open_directory_parts(parts)
        try:
            metadata = os.fstat(current)
            current_snapshot = self.authority._snapshot_directory_fd(current, parts)
            require(
                (metadata.st_dev, metadata.st_ino) == expected_identity
                and current_snapshot == held_snapshot,
                f"private compiler directory membership changed: "
                f"{self.authority.path(parts)}",
            )
        finally:
            os.close(current)
        return {name: kind for name, kind, _, _ in held_snapshot}

    def revalidate(self) -> None:
        self.authority.assert_root_stable()
        for parts, (_, expected) in self.directories.items():
            current_fd = self.authority.open_directory_parts(parts)
            try:
                metadata = os.fstat(current_fd)
                require(
                    (metadata.st_dev, metadata.st_ino) == expected,
                    f"private compiler directory changed: "
                    f"{self.authority.path(parts)}",
                )
            finally:
                os.close(current_fd)
        for parts, pin in self.files.items():
            data, identity = self.authority._read_regular_fd(
                pin["fd"],
                f"held compiler output {self.authority.path(parts)}",
            )
            require(
                identity == pin["identity"] and data == pin["data"],
                f"held compiler output changed before publication completed: "
                f"{self.authority.path(parts)}",
            )
            parent_parts = pin["parent_parts"]
            parent_fd = self.directories[parent_parts][0]
            held_visible = os.stat(
                parts[-1], dir_fd=parent_fd, follow_symlinks=False
            )
            current_parent = self.authority.open_directory_parts(parent_parts)
            try:
                current_parent_metadata = os.fstat(current_parent)
                current_visible = os.stat(
                    parts[-1], dir_fd=current_parent, follow_symlinks=False
                )
                require(
                    (held_visible.st_dev, held_visible.st_ino) == identity[:2]
                    and (
                        current_parent_metadata.st_dev,
                        current_parent_metadata.st_ino,
                    ) == self.directories[parent_parts][1]
                    and (current_visible.st_dev, current_visible.st_ino)
                    == identity[:2],
                    f"held compiler output was replaced before publication "
                    f"completed: {self.authority.path(parts)}",
                )
            finally:
                os.close(current_parent)
        self.authority.assert_root_stable()

    def close(self) -> None:
        for pin in self.files.values():
            descriptor = pin.get("fd")
            if isinstance(descriptor, int):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        self.files.clear()
        for descriptor, _ in self.directories.values():
            try:
                os.close(descriptor)
            except OSError:
                pass
        self.directories.clear()


def active_build_authority() -> BuildRootAuthority:
    require(len(ACTIVE_BUILD_AUTHORITIES) == 1,
            "byte-identity build operation lacks one held root authority")
    return ACTIVE_BUILD_AUTHORITIES[-1]


def active_authority_for_path(path: Path) -> BuildRootAuthority | None:
    if not ACTIVE_BUILD_AUTHORITIES:
        return None
    authority = ACTIVE_BUILD_AUTHORITIES[-1]
    return (
        authority
        if relative_build_parts(
            path,
            authority.build_dir,
            canonical_root=authority.build_root,
        ) is not None
        else None
    )


def relative_build_parts(
    path: Path,
    build_dir: Path,
    cwd: Path | None = None,
    *,
    canonical_root: Path | None = None,
) -> tuple[str, ...] | None:
    """Map a lexical compiler path below either spelling of the build root."""
    original = Path(path)
    if ".." in original.parts:
        return None
    candidate = lexical_absolute_path(original, cwd)
    if canonical_root is None:
        canonical_root = build_dir.resolve()
    roots = (
        lexical_absolute_path(build_dir),
        lexical_absolute_path(canonical_root),
    )
    for root in roots:
        try:
            relative = candidate.relative_to(root)
        except ValueError:
            continue
        parts = relative.parts
        if not parts:
            return ()
        if all(
                part not in ("", ".", "..")
                and "/" not in part and "\0" not in part
                for part in parts
        ):
            return parts
    return None


def validate_execution_backends(value: object | None) -> dict:
    """Validate the platform-neutral backend registry and select this host."""
    if value is None:
        # Schema-2 native fixtures predate the explicit registry. Preserve
        # their POSIX policy surface without silently admitting Windows.
        require(
            host_backend() == POSIX_WINE_BACKEND,
            "manifest has no native-Windows execution backend registry",
        )
        return {
            "id": POSIX_WINE_BACKEND,
            "host": "posix",
            "status": "framework_implemented",
            "transport": "wine_virtual_z_v1",
            "filesystem_authority": "root_fd_openat_nofollow",
            "process_tree": "posix_process_group",
        }
    require(isinstance(value, dict), "execution_backends must be an object")
    exact_audit_keys(
        value, {"selection", "profiles"}, "execution_backends"
    )
    require(
        value.get("selection") == "host_os_exact_no_cross_backend_v1",
        "execution backend selection policy differs",
    )
    profiles = value.get("profiles")
    require(isinstance(profiles, list) and len(profiles) == 2,
            "execution_backends.profiles must contain exactly two profiles")
    normalized = {}
    for index, profile in enumerate(profiles):
        context = f"execution_backends.profiles[{index}]"
        require(isinstance(profile, dict), f"{context} must be an object")
        identifier = profile.get("id")
        if identifier == POSIX_WINE_BACKEND:
            exact_audit_keys(
                profile,
                {
                    "id", "host", "status", "transport",
                    "filesystem_authority", "process_tree",
                },
                context,
            )
            require(
                exact_json_equal(profile, {
                    "id": POSIX_WINE_BACKEND,
                    "host": "posix",
                    "status": "framework_implemented",
                    "transport": "wine_virtual_z_v1",
                    "filesystem_authority": "root_fd_openat_nofollow",
                    "process_tree": "posix_process_group",
                }),
                f"{context} policy differs",
            )
        elif identifier == WINDOWS_NATIVE_BACKEND:
            exact_audit_keys(
                profile,
                {
                    "id", "host", "status", "transport", "logical_drive",
                    "filesystem_authority", "process_tree",
                    "toolchain_repository", "toolchain_commit",
                    "toolchain_files", "ci_contract",
                },
                context,
            )
            require(
                profile.get("host") == "nt"
                and profile.get("status")
                == "architectural_seam_deferred_untested"
                and profile.get("transport") == "native_windows_logical_z_v1"
                and profile.get("logical_drive") == "Z:"
                and profile.get("filesystem_authority")
                == "held_nofollow_handle_chain"
                and profile.get("process_tree")
                == "windows_kill_on_close_job_object"
                and profile.get("toolchain_repository") == "itsmattkc/msvc420"
                and profile.get("toolchain_commit")
                == "df2c13aad74c094988c6c7e784234c2e778a0e91"
                and exact_json_equal(
                    profile.get("toolchain_files"), WINDOWS_NATIVE_TOOLCHAIN_PINS
                )
                and profile.get("ci_contract") == "deferred_nonblocking_v1",
                f"{context} native Windows authority contract differs",
            )
        else:
            raise ByteIdentityError(f"{context}.id is unsupported")
        require(identifier not in normalized,
                f"duplicate execution backend profile: {identifier}")
        normalized[identifier] = profile
    require(set(normalized) == {POSIX_WINE_BACKEND, WINDOWS_NATIVE_BACKEND},
            "execution backend registry is incomplete")
    return dict(normalized[selected_backend()])


TOOLCHAIN_COMMON_KEYS = {
    "compiler_sha256", "compiler_id", "compiler_version",
    "python_sha256", "python_version", "keep_compile_debug",
    "max_child_seconds", "provenance",
}


TOOLCHAIN_POSIX_PROFILE_KEYS = {
    "status", "transport_schema", "compiler_root_parent_levels",
    "compiler_support_files", "producer_support_files",
    "required_absent_toolchain_files",
    "runtime_executables", "sealed_include_trees", "runtime_closure",
    "transport", "child_environment",
}


TOOLCHAIN_LEGACY_POSIX_KEYS = (
    TOOLCHAIN_POSIX_PROFILE_KEYS - {"status", "transport_schema"}
)


def select_toolchain_backend_profile(
    toolchain: object, *, explicit_registry: bool, execution_backend: dict,
) -> tuple[dict, bool]:
    """Select transport policy before resolving any backend host pathname."""
    require(isinstance(toolchain, dict), "toolchain must be an object")
    if not explicit_registry:
        exact_keys(
            toolchain, TOOLCHAIN_COMMON_KEYS | TOOLCHAIN_LEGACY_POSIX_KEYS,
            "toolchain",
        )
        require(execution_backend["id"] == POSIX_WINE_BACKEND,
                "legacy toolchain policy is POSIX/Wine only")
        return ({
            "status": "framework_implemented",
            "transport_schema": "wine_virtual_z_v1",
            **{key: toolchain[key] for key in TOOLCHAIN_LEGACY_POSIX_KEYS},
        }, True)

    exact_keys(toolchain, TOOLCHAIN_COMMON_KEYS | {"backend_profiles"},
               "toolchain")
    profiles = toolchain.get("backend_profiles")
    require(isinstance(profiles, dict)
            and set(profiles) == {
                POSIX_WINE_BACKEND, WINDOWS_NATIVE_BACKEND,
            }, "toolchain backend profile universe differs")
    posix = profiles[POSIX_WINE_BACKEND]
    require(isinstance(posix, dict),
            "POSIX/Wine toolchain backend profile is not an object")
    exact_audit_keys(posix, TOOLCHAIN_POSIX_PROFILE_KEYS,
                     "POSIX/Wine toolchain backend profile")
    require(
        posix.get("status") == "framework_implemented"
        and posix.get("transport_schema") == "wine_virtual_z_v1",
        "POSIX/Wine toolchain backend profile differs",
    )
    windows = profiles[WINDOWS_NATIVE_BACKEND]
    require(isinstance(windows, dict),
            "native-Windows toolchain backend profile is not an object")
    exact_audit_keys(
        windows, {"status", "transport_schema"},
        "native-Windows toolchain backend profile",
    )
    require(
        windows == {
            "status": "architectural_seam_deferred_untested",
            "transport_schema": "native_windows_logical_z_v1",
        },
        "native-Windows toolchain backend profile differs",
    )
    selected = profiles[execution_backend["id"]]
    require(
        selected.get("status") == "framework_implemented",
        "toolchain backend is explicitly deferred: "
        f"{execution_backend['id']}",
    )
    return dict(selected), False


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
    build_root = (
        ACTIVE_BUILD_AUTHORITIES[-1].build_root
        if ACTIVE_BUILD_AUTHORITIES else build_dir.resolve()
    )
    source_root, _ = require_disjoint_source_build(source_dir, build_root)
    try:
        authority = (
            ACTIVE_BUILD_AUTHORITIES[-1] if ACTIVE_BUILD_AUTHORITIES else None
        )
        raw = (
            authority.read_bytes(manifest_path)
            if authority is not None
            and active_authority_for_path(manifest_path) is authority
            else authority.read_external_bytes(manifest_path)
            if authority is not None
            else manifest_path.read_bytes()
        )
        manifest = strict_json_loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ByteIdentityError(f"cannot read manifest {manifest_path}: {error}") from error
    require(isinstance(manifest, dict), "manifest root must be an object")
    exact_keys(
        manifest,
        {
            "schema", "phase", "toolchain", "target_policies",
            "translation_units", "archives", "images", "execution_backends",
            "terminal_producers", "source_overlay", "diagnostic_policy",
        },
        "manifest",
    )
    require(type(manifest.get("schema")) is int
            and manifest.get("schema") == SCHEMA_VERSION,
            "unsupported byte-identity schema")
    require(manifest.get("phase") == PHASE, f"manifest phase must be {PHASE}")
    diagnostic_policy = manifest.get("diagnostic_policy")
    require(
        diagnostic_policy is None
        or diagnostic_policy == NATIVE_DIAGNOSTIC_MANIFEST_POLICY,
        "manifest diagnostic policy is unsupported",
    )
    execution_backend = validate_execution_backends(
        manifest.get("execution_backends")
    )
    source_overlay = validate_source_overlay(
        manifest.get("source_overlay"), source_dir
    )
    source_overlay_by_path = {
        item["logical_path"]: item for item in source_overlay["outputs"]
    }

    toolchain = manifest.get("toolchain")
    toolchain_profile, _legacy_toolchain_profile = (
        select_toolchain_backend_profile(
            toolchain,
            explicit_registry=manifest.get("execution_backends") is not None,
            execution_backend=execution_backend,
        )
    )
    # Backend-specific physical roots are intentionally captured only after
    # the selected transport has been admitted.  A deferred native-Windows
    # profile therefore never resolves Darwin/Homebrew/Wine path tokens.
    host_roots = manifest_host_roots()
    expected_compiler_sha = require_sha(toolchain.get("compiler_sha256"), "compiler_sha256")
    require(toolchain.get("compiler_id") == "MSVC", "only the pinned MSVC toolchain is supported")
    require(toolchain.get("compiler_version") == "10.20", "only MSVC 4.20 is supported")
    expected_python_sha = require_sha(toolchain.get("python_sha256"), "python_sha256")
    expected_python_version = toolchain.get("python_version")
    require(
        isinstance(expected_python_version, str)
        and re.fullmatch(r"[0-9]+[.][0-9]+[.][0-9]+", expected_python_version),
        "python_version must pin an exact three-component version",
    )
    current_python = Path(sys.executable).resolve()
    require(current_python.is_file() and os.access(current_python, os.X_OK),
            "active Python interpreter is not executable")
    require(sha256_file(current_python) == expected_python_sha,
            f"active Python interpreter hash differs: {current_python}")
    current_python_version = ".".join(str(value) for value in sys.version_info[:3])
    require(current_python_version == expected_python_version,
            "active Python interpreter version differs")
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
        exact_json_equal(provenance, {
            "retail_use": "oracle_only_no_payload_copy",
            "payload_source": "configured_compiler_output",
            "forbid_emitted_padding": True,
            "forbid_opaque_objects": True,
            "forbid_source_tree_writes": True,
        }),
        "hard provenance policy changed",
    )

    root_parent_levels = toolchain_profile.get("compiler_root_parent_levels")
    require(isinstance(root_parent_levels, int) and not isinstance(root_parent_levels, bool)
            and 0 <= root_parent_levels <= 6,
            "compiler_root_parent_levels is out of range")
    support_files = toolchain_profile.get("compiler_support_files")
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
                and not pure.is_absolute() and ".." not in pure.parts
                and pure.as_posix() == relative,
                f"{support_context}.path must stay below the compiler root")
        relative = pure.as_posix()
        require(relative not in support_names, f"duplicate compiler support file: {relative}")
        support_names.add(relative)
        normalized_support.append(
            {"path": relative, "sha256": require_sha(support.get("sha256"), f"{support_context}.sha256")}
        )
    producer_support_files = toolchain_profile.get("producer_support_files")
    require(isinstance(producer_support_files, list),
            "producer_support_files must be an array")
    normalized_producer_support = []
    producer_support_names = set()
    for support_index, support in enumerate(producer_support_files):
        context = f"producer_support_files[{support_index}]"
        require(isinstance(support, dict), f"{context} must be an object")
        exact_keys(support, {"path", "sha256", "roles"}, context)
        relative = support.get("path")
        require(isinstance(relative, str) and relative,
                f"{context}.path is invalid")
        pure = PurePosixPath(relative)
        require("\\" not in relative and ";" not in relative
                and not pure.is_absolute() and ".." not in pure.parts
                and pure.as_posix() == relative,
                f"{context}.path must stay below the compiler root")
        require(relative not in producer_support_names,
                f"duplicate producer support file: {relative}")
        producer_support_names.add(relative)
        roles = support.get("roles")
        require(isinstance(roles, list) and roles
                and all(isinstance(role, str) for role in roles)
                and len(roles) == len(set(roles))
                and set(roles) <= PRODUCER_SUPPORT_ROLES
                and roles == sorted(roles),
                f"{context}.roles is not a canonical producer-role set")
        normalized_producer_support.append({
            "path": relative,
            "sha256": require_sha(
                support.get("sha256"), f"{context}.sha256"
            ),
            "roles": roles,
        })
    normalized_producer_support.sort(key=lambda item: item["path"])
    require(not producer_support_names.intersection(support_names),
            "compiler and producer support files overlap")
    required_absent = toolchain_profile.get("required_absent_toolchain_files")
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
    require(not set(normalized_absent).intersection(
                support_names | producer_support_names),
            "toolchain files cannot be both required and absent")

    runtime_executables = toolchain_profile.get("runtime_executables")
    require(isinstance(runtime_executables, list) and runtime_executables,
            "runtime_executables must be a non-empty array")
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
    require(
        {
            "bash", "dirname", "sed", "grep",
            "wine", "winepath", "wineserver",
        } <= runtime_names,
        "POSIX/Wine runtime executable closure is incomplete",
    )

    sealed_include_trees = toolchain_profile.get("sealed_include_trees")
    require(isinstance(sealed_include_trees, list)
            and len(sealed_include_trees) == 2,
            "sealed_include_trees must pin the MSVC and MFC include roots")
    normalized_include_trees = []
    include_tree_roles = set()
    for tree_index, tree in enumerate(sealed_include_trees):
        tree_context = f"sealed_include_trees[{tree_index}]"
        require(isinstance(tree, dict), f"{tree_context} must be an object")
        exact_audit_keys(
            tree,
            {"role", "path", "entry_count", "max_depth",
             "membership_sha256", "content_sha256"},
            tree_context,
        )
        role = tree.get("role")
        require(role in ("msvc_include", "mfc_include")
                and role not in include_tree_roles,
                f"{tree_context}.role is invalid or duplicated")
        include_tree_roles.add(role)
        relative = tree.get("path")
        require(isinstance(relative, str) and relative,
                f"{tree_context}.path is invalid")
        pure = PurePosixPath(relative)
        require(not pure.is_absolute() and ".." not in pure.parts
                and "\\" not in relative and ";" not in relative,
                f"{tree_context}.path must stay below the compiler root")
        entry_count = tree.get("entry_count")
        maximum_depth = tree.get("max_depth")
        require(type(entry_count) is int and 1 <= entry_count <= 20000,
                f"{tree_context}.entry_count is invalid")
        require(type(maximum_depth) is int and 0 <= maximum_depth <= 32,
                f"{tree_context}.max_depth is invalid")
        normalized_include_trees.append({
            "role": role,
            "path": pure.as_posix(),
            "entry_count": entry_count,
            "max_depth": maximum_depth,
            "membership_sha256": require_sha(
                tree.get("membership_sha256"), f"{tree_context}.membership_sha256"
            ),
            "content_sha256": require_sha(
                tree.get("content_sha256"), f"{tree_context}.content_sha256"
            ),
        })
    require(include_tree_roles == {"msvc_include", "mfc_include"},
            "sealed include tree roles are incomplete")

    runtime_closure = toolchain_profile.get("runtime_closure")
    require(isinstance(runtime_closure, dict), "runtime_closure must be an object")
    exact_audit_keys(
        runtime_closure,
        {
            "schema", "membership_roots", "loaded_files",
            "host_identity", "system_imports", "resolution_policy",
        },
        "runtime_closure",
    )
    require(runtime_closure.get("schema") == "wine_runtime_closure_v1"
            and runtime_closure.get("resolution_policy")
            == "casefold_unique_first_match_v1",
            "runtime_closure schema/resolution policy differs")
    runtime_roots = runtime_closure.get("membership_roots")
    require(isinstance(runtime_roots, list) and runtime_roots,
            "runtime_closure.membership_roots must be non-empty")
    normalized_runtime_roots = []
    runtime_root_roles = set()
    for root_index, root_pin in enumerate(runtime_roots):
        root_context = f"runtime_closure.membership_roots[{root_index}]"
        require(isinstance(root_pin, dict), f"{root_context} must be an object")
        exact_audit_keys(
            root_pin,
            {
                "role", "path", "entry_count", "max_depth",
                "membership_sha256", "content_sha256",
            },
            root_context,
        )
        role = root_pin.get("role")
        path_value = root_pin.get("path")
        require(isinstance(role, str) and TARGET_RE.fullmatch(role) is not None
                and role not in runtime_root_roles,
                f"{root_context}.role is invalid or duplicated")
        runtime_root_roles.add(role)
        root_path = manifest_host_path(path_value, f"{root_context}.path", host_roots)
        entry_count = root_pin.get("entry_count")
        maximum_depth = root_pin.get("max_depth")
        require(type(entry_count) is int and 1 <= entry_count <= 20000,
                f"{root_context}.entry_count is invalid")
        require(type(maximum_depth) is int and 0 <= maximum_depth <= 32,
                f"{root_context}.max_depth is invalid")
        normalized_runtime_roots.append({
            "role": role, "path": str(root_path),
            "entry_count": entry_count, "max_depth": maximum_depth,
            "membership_sha256": require_sha(
                root_pin.get("membership_sha256"),
                f"{root_context}.membership_sha256",
            ),
            "content_sha256": require_sha(
                root_pin.get("content_sha256"),
                f"{root_context}.content_sha256",
            ),
        })
    runtime_loaded = runtime_closure.get("loaded_files")
    require(isinstance(runtime_loaded, list) and runtime_loaded,
            "runtime_closure.loaded_files must be non-empty")
    normalized_runtime_loaded = []
    loaded_roles = set()
    loaded_paths = set()
    for loaded_index, loaded in enumerate(runtime_loaded):
        loaded_context = f"runtime_closure.loaded_files[{loaded_index}]"
        require(isinstance(loaded, dict), f"{loaded_context} must be an object")
        exact_audit_keys(loaded, {"role", "path", "sha256"}, loaded_context)
        role = loaded.get("role")
        path_value = loaded.get("path")
        require(isinstance(role, str) and TARGET_RE.fullmatch(role) is not None
                and role not in loaded_roles,
                f"{loaded_context}.role is invalid or duplicated")
        loaded_roles.add(role)
        loaded_path = manifest_host_path(
            path_value, f"{loaded_context}.path", host_roots
        )
        canonical_loaded = str(loaded_path.resolve(strict=True))
        require(canonical_loaded not in loaded_paths,
                f"{loaded_context}.path is duplicated")
        loaded_paths.add(canonical_loaded)
        normalized_runtime_loaded.append({
            "role": role, "path": canonical_loaded,
            "sha256": require_sha(loaded.get("sha256"), f"{loaded_context}.sha256"),
        })
    host_identity = runtime_closure.get("host_identity")
    require(isinstance(host_identity, dict),
            "runtime_closure.host_identity must be an object")
    expected_host_identity = current_host_runtime_identity()
    exact_audit_keys(
        host_identity, set(expected_host_identity),
        "runtime_closure.host_identity",
    )
    require(exact_json_equal(host_identity, expected_host_identity),
            "runtime_closure host/dyld identity differs")
    system_imports = runtime_closure.get("system_imports")
    require(exact_json_equal(system_imports, EXPECTED_DYLD_IMPORT_IDENTITIES),
            "runtime_closure dyld-cache import identities differ")
    normalized_runtime_closure = {
        "schema": "wine_runtime_closure_v1",
        "membership_roots": normalized_runtime_roots,
        "loaded_files": normalized_runtime_loaded,
        "host_identity": expected_host_identity,
        "system_imports": list(EXPECTED_DYLD_IMPORT_IDENTITIES),
        "resolution_policy": "casefold_unique_first_match_v1",
    }

    transport = toolchain_profile.get("transport")
    require(isinstance(transport, dict), "toolchain.transport must be an object")
    exact_audit_keys(
        transport,
        {
            "schema", "copy_policy", "runtime_snapshot_policy",
            "prefix_template_files", "prefix_directories", "dosdevices",
            "server_shutdown", "msvc_environment",
        },
        "toolchain.transport",
    )
    require(
        transport.get("schema") == "wine_virtual_z_v1"
        and transport.get("copy_policy")
        == "independent_regular_files_no_hardlinks_v1"
        and transport.get("runtime_snapshot_policy")
        == "selected_loaded_closure_with_full_root_content_merkle_v1"
        and transport.get("server_shutdown")
        == "prefix_scoped_kill_wait_bounded_v1"
        and exact_json_equal(transport.get("dosdevices"), ["c:", "z:"]),
        "toolchain.transport policy differs",
    )
    prefix_files = transport.get("prefix_template_files")
    require(isinstance(prefix_files, list) and prefix_files,
            "toolchain.transport.prefix_template_files must be non-empty")
    normalized_prefix_files = []
    prefix_names = set()
    for index, item in enumerate(prefix_files):
        context = f"toolchain.transport.prefix_template_files[{index}]"
        require(isinstance(item, dict), f"{context} must be an object")
        exact_audit_keys(item, {"name", "path", "sha256", "mode"}, context)
        name = item.get("name")
        path_value = item.get("path")
        require(isinstance(name, str) and name
                and PurePosixPath(name).name == name
                and name not in prefix_names,
                f"{context}.name is invalid or duplicated")
        prefix_names.add(name)
        prefix_path = manifest_host_path(
            path_value, f"{context}.path", host_roots
        )
        mode = require_exact_int(item.get("mode"), f"{context}.mode",
                                 minimum=0, maximum=0o777)
        require(mode == 0o444,
                f"{context}.mode must be the immutable 0444 template mode")
        normalized_prefix_files.append({
            "name": name,
            "path": str(prefix_path),
            "sha256": require_sha(item.get("sha256"), f"{context}.sha256"),
            "mode": mode,
        })
    require(prefix_names == {
                ".update-timestamp", "system.reg", "user.reg", "userdef.reg"
            }, "Wine prefix template file set differs")
    prefix_template_root = validate_wine_prefix_template(
        normalized_prefix_files
    )
    prefix_directories = transport.get("prefix_directories")
    require(isinstance(prefix_directories, list) and prefix_directories,
            "toolchain.transport.prefix_directories must be non-empty")
    normalized_prefix_directories = []
    for index, value in enumerate(prefix_directories):
        context = f"toolchain.transport.prefix_directories[{index}]"
        require(isinstance(value, str) and value and "\\" not in value,
                f"{context} is invalid")
        pure = PurePosixPath(value)
        require(not pure.is_absolute() and ".." not in pure.parts
                and pure.as_posix() == value,
                f"{context} escapes the prefix")
        normalized_prefix_directories.append(value)
    require(len(normalized_prefix_directories)
            == len(set(normalized_prefix_directories))
            and "drive_c" in normalized_prefix_directories,
            "Wine prefix directory set is duplicated or incomplete")
    msvc_environment = transport.get("msvc_environment")
    require(isinstance(msvc_environment, dict),
            "toolchain.transport.msvc_environment must be an object")
    exact_audit_keys(
        msvc_environment,
        {
            "include_order", "winepath_order", "winedlloverrides",
            "root_transform", "wrapper_invocation_transform",
            "argument_path_transform",
        },
        "toolchain.transport.msvc_environment",
    )
    root_transform = msvc_environment.get("root_transform")
    require(isinstance(root_transform, dict),
            "toolchain.transport.msvc_environment.root_transform must be an object")
    exact_audit_keys(
        root_transform, {"schema", "script"},
        "toolchain.transport.msvc_environment.root_transform",
    )
    root_transform_script = root_transform.get("script")
    require(
        root_transform.get("schema")
        == MSVC_ENVIRONMENT_ROOT_TRANSFORM_SCHEMA
        and root_transform_script == "wine/x86/msvcenv.sh"
        and root_transform_script in support_names,
        "toolchain.transport MSVC root transform differs",
    )
    wrapper_transform = msvc_environment.get("wrapper_invocation_transform")
    require(isinstance(wrapper_transform, dict),
            "toolchain.transport MSVC wrapper transform must be an object")
    exact_audit_keys(
        wrapper_transform, {"schema", "scripts"},
        "toolchain.transport.msvc_environment.wrapper_invocation_transform",
    )
    wrapper_transform_scripts = wrapper_transform.get("scripts")
    require(
        wrapper_transform.get("schema")
        == MSVC_WRAPPER_INVOCATION_TRANSFORM_SCHEMA
        and exact_json_equal(
            wrapper_transform_scripts, list(MSVC_WRAPPER_TRANSFORM_SCRIPTS)
        ),
        "toolchain.transport MSVC wrapper invocation transform differs",
    )
    argument_transform = msvc_environment.get("argument_path_transform")
    require(isinstance(argument_transform, dict),
            "toolchain.transport MSVC argument transform must be an object")
    exact_audit_keys(
        argument_transform, {"schema", "script"},
        "toolchain.transport.msvc_environment.argument_path_transform",
    )
    require(
        argument_transform.get("schema")
        == MSVC_WINE_ARGUMENT_TRANSFORM_SCHEMA
        and argument_transform.get("script") == "wine/x86/wine-msvc.sh"
        and argument_transform.get("script") in support_names,
        "toolchain.transport MSVC argument transform differs",
    )
    include_order = msvc_environment.get("include_order")
    require(isinstance(include_order, list) and len(include_order) == 2
            and len(set(include_order)) == 2
            and all(
                isinstance(value, str) and value
                and not PurePosixPath(value).is_absolute()
                and ".." not in PurePosixPath(value).parts
                and PurePosixPath(value).as_posix() == value
                for value in include_order
            ) and exact_json_equal(
                msvc_environment.get("winepath_order"),
                ["bin", "bin/winnt"],
            )
            and msvc_environment.get("winedlloverrides")
            == "msvcrt40=n;msvcrt20=n",
            "toolchain.transport MSVC wrapper environment differs")
    normalized_transport = {
        "schema": "wine_virtual_z_v1",
        "copy_policy": "independent_regular_files_no_hardlinks_v1",
        "runtime_snapshot_policy":
            "selected_loaded_closure_with_full_root_content_merkle_v1",
        "prefix_template_files": normalized_prefix_files,
        "prefix_template_root": prefix_template_root,
        "prefix_directories": normalized_prefix_directories,
        "dosdevices": ["c:", "z:"],
        "server_shutdown": "prefix_scoped_kill_wait_bounded_v1",
        "msvc_environment": msvc_environment,
    }

    child_environment = toolchain_profile.get("child_environment")
    require(exact_json_equal(child_environment, CHILD_ENVIRONMENT_POLICY),
            "child_environment must match the strict compiler allowlist policy")
    toolchain_fingerprint = sha256_bytes(
        json.dumps(
            {
                "compiler_sha256": expected_compiler_sha,
                "python_sha256": expected_python_sha,
                "python_version": expected_python_version,
                "root_parent_levels": root_parent_levels,
                "support_files": normalized_support,
                "producer_support_files": normalized_producer_support,
                "required_absent": normalized_absent,
                "runtime_executables": normalized_runtimes,
                "sealed_include_trees": normalized_include_trees,
                "runtime_closure": normalized_runtime_closure,
                "transport": normalized_transport,
                "child_environment": CHILD_ENVIRONMENT_POLICY,
                "transport_backend": {
                    "backend": execution_backend["id"],
                    "schema": toolchain_profile["transport_schema"],
                },
                "execution_backend": execution_backend,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    compiler_root = None
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
            support["absolute_path"] = str(support_path)
        for support in normalized_producer_support:
            _, support_path = declared_toolchain_path(
                compiler_root, support["path"],
                f"producer support file {support['path']}",
            )
            require(support_path.is_file(),
                    f"producer support file is absent: {support['path']}")
            require(sha256_file(support_path) == support["sha256"],
                    f"producer support file hash differs: {support['path']}")
            support["absolute_path"] = str(support_path)
        for relative in normalized_absent:
            _, absent_path = declared_toolchain_path(
                compiler_root, relative, f"required absent toolchain file {relative}"
            )
            if ACTIVE_BUILD_AUTHORITIES:
                ACTIVE_BUILD_AUTHORITIES[-1].require_external_absent(absent_path)
            else:
                require(not absent_path.exists() and not absent_path.is_symlink(),
                        f"toolchain file must remain absent: {relative}")
        for runtime in normalized_runtimes:
            located = shutil.which(runtime["name"])
            require(located is not None,
                    f"runtime executable is absent from PATH: {runtime['name']}")
            located_path = Path(located).resolve()
            require(sha256_file(located_path) == runtime["sha256"],
                    f"runtime executable hash differs: {runtime['name']}")
            runtime["absolute_path"] = str(located_path)
            metadata = located_path.stat(follow_symlinks=False)
            runtime["materialization"] = (
                "system_direct_immutable_v1"
                if (
                    str(located_path).startswith(("/bin/", "/usr/bin/"))
                    and located_path.resolve(strict=True) == located_path
                    and not located_path.is_symlink()
                    and metadata.st_uid == 0
                    and stat.S_ISREG(metadata.st_mode)
                    and not (stat.S_IMODE(metadata.st_mode) & 0o022)
                )
                else "private_snapshot_copy_v1"
            )
        for tree in normalized_include_trees:
            _, tree_path = declared_toolchain_path(
                compiler_root, tree["path"], f"sealed include tree {tree['role']}"
            )
            snapshot = canonical_tree_snapshot(
                tree_path, hash_files=True,
                max_entries=tree["entry_count"], max_depth=tree["max_depth"],
            )
            require(snapshot["entry_count"] == tree["entry_count"]
                    and snapshot["max_depth"] == tree["max_depth"]
                    and snapshot["membership_sha256"] == tree["membership_sha256"]
                    and snapshot["content_sha256"] == tree["content_sha256"],
                    f"sealed include tree differs: {tree['role']}")
            tree["absolute_path"] = str(tree_path)
            tree["metadata_sha256"] = snapshot["metadata_sha256"]
        # The resident materializes and validates the complete Wine membership
        # once. Common compiler/RC/LIB/LINK manifest revalidation must not
        # reread this ~843 MiB host closure for every producer role.
        for prefix_file in normalized_prefix_files:
            prefix_path = Path(prefix_file["path"])
            require(prefix_path.is_file()
                    and not prefix_path.is_symlink()
                    and stat.S_IMODE(prefix_path.stat().st_mode)
                    == prefix_file["mode"]
                    and sha256_file(prefix_path) == prefix_file["sha256"],
                    f"Wine prefix template file differs: {prefix_file['name']}")
        expected_include_order = [
            str(Path(tree["absolute_path"]))
            for tree in normalized_include_trees
        ]
        expected_winepath = [
            str(compiler_root / "bin"), str(compiler_root / "bin/winnt")
        ]
        require(
            exact_json_equal(
                [str(compiler_root / value)
                 for value in msvc_environment["include_order"]],
                expected_include_order,
            ) and exact_json_equal(
                [str(compiler_root / value)
                 for value in msvc_environment["winepath_order"]],
                expected_winepath,
            ),
            "pinned MSVC wrapper search environment differs from compiler root",
        )
        normalized_transport["msvc_environment"] = {
            **msvc_environment,
            "include_order": expected_include_order,
            "winepath_order": expected_winepath,
        }
    if compiler_id is not None:
        require(compiler_id == toolchain["compiler_id"], "configured compiler ID differs")
    if compiler_version is not None:
        require(compiler_version == toolchain["compiler_version"], "configured compiler version differs")
    if generator is not None:
        require(generator in SUPPORTED_GENERATORS, f"unsupported CMake generator: {generator}")

    target_policies = manifest.get("target_policies")
    require(isinstance(target_policies, list) and target_policies,
            "target_policies must be a non-empty array")
    normalized_target_policies = []
    target_policy_by_name = {}
    for policy_index, policy in enumerate(target_policies):
        policy_context = f"target_policies[{policy_index}]"
        require(isinstance(policy, dict), f"{policy_context} must be an object")
        exact_keys(policy, {"target", "allowed_force_includes"}, policy_context)
        target = policy.get("target")
        require(isinstance(target, str) and TARGET_RE.fullmatch(target) is not None,
                f"{policy_context}.target is invalid")
        require(target not in target_policy_by_name,
                f"duplicate target policy: {target}")
        allowed_force_includes = policy.get("allowed_force_includes")
        require(isinstance(allowed_force_includes, list),
                f"{policy_context}.allowed_force_includes must be an array")
        normalized_force_includes = []
        seen_force_includes = set()
        for include_index, include in enumerate(allowed_force_includes):
            include_context = (
                f"{policy_context}.allowed_force_includes[{include_index}]"
            )
            require(isinstance(include, dict), f"{include_context} must be an object")
            exact_keys(include, {"path", "sha256"}, include_context)
            include_relative = source_overlay_relative_path(
                include.get("path"), f"{include_context}.path"
            )
            include_path = source_overlay_logical_path(
                source_dir, include_relative
            )
            include_sha = require_sha(
                include.get("sha256"), f"{include_context}.sha256"
            )
            require(include_relative not in seen_force_includes,
                    f"duplicate force-include in {policy_context}: {include_relative}")
            seen_force_includes.add(include_relative)
            overlay_output = source_overlay_by_path.get(include_relative)
            effective_include_sha = include_sha
            if overlay_output is None:
                require(include_path.is_file()
                        and sha256_file(include_path) == include_sha,
                        f"force-include hash differs: {include_relative}")
            else:
                require(
                    overlay_output["effective"]["baseline_sha256"] == include_sha,
                    f"overlay force-include baseline hash differs: {include_relative}",
                )
                effective_include_sha = source_overlay[
                    "effective_by_path"
                ][include_relative]["sha256"]
            normalized_force_includes.append(
                {
                    "path": include_relative,
                    "absolute_path": str(include_path),
                    "sha256": effective_include_sha,
                }
            )
        normalized_policy = {
            "target": target,
            "allowed_force_includes": normalized_force_includes,
        }
        normalized_target_policies.append(normalized_policy)
        target_policy_by_name[target] = normalized_policy

    translation_units = manifest.get("translation_units")
    require(isinstance(translation_units, list) and translation_units,
            "translation_units must be a non-empty array")
    normalized_units = []
    owners = set()
    recipe_registry = {}
    recipe_order = []
    retail_identities = set()
    for unit_index, unit in enumerate(translation_units):
        context = f"translation_units[{unit_index}]"
        require(isinstance(unit, dict), f"{context} must be an object")
        if unit.get("mode") == "swap_comdat_group_order":
            exact_audit_keys(
                unit,
                {
                    "target", "source", "source_sha256", "mode",
                    "command_policy", "group_order", "completion",
                },
                context,
            )
        else:
            exact_audit_keys(
                unit,
                {
                    "target", "source", "source_sha256", "mode",
                    "command_policy", "donors", "functions", "completion",
                },
                context,
            )
        target = unit.get("target")
        require(isinstance(target, str) and TARGET_RE.fullmatch(target) is not None,
                f"{context}.target is invalid")
        require(target in target_policy_by_name,
                f"{context}.target has no build-wide target policy")
        source_relative = source_overlay_relative_path(
            unit.get("source"), f"{context}.source"
        )
        source_path = source_overlay_logical_path(source_dir, source_relative)
        source_sha = require_sha(unit.get("source_sha256"), f"{context}.source_sha256")
        overlay_output = source_overlay_by_path.get(source_relative)
        effective_source_sha = source_sha
        if overlay_output is None:
            require(source_path.is_file() and sha256_file(source_path) == source_sha,
                    f"source hash differs: {source_relative}")
        else:
            require(overlay_output["effective"]["baseline_sha256"] == source_sha,
                    f"overlay source baseline hash differs: {source_relative}")
            effective_source_sha = source_overlay[
                "effective_by_path"
            ][source_relative]["sha256"]
        owner = (target, source_relative)
        require(owner not in owners, f"duplicate translation-unit owner: {owner}")
        owners.add(owner)
        mode = unit.get("mode")
        require(
            mode in ("compose_equal_linked_span_fpo",
                     "compose_equal_body_comdat",
                     "swap_comdat_group_order")
            or (
                mode == "pass_through"
                and diagnostic_policy == NATIVE_DIAGNOSTIC_MANIFEST_POLICY
            ),
            f"{context}.mode is unsupported outside a non-authoritative "
            "native diagnostic manifest",
        )

        command_policy = unit.get("command_policy")
        require(isinstance(command_policy, dict), f"{context}.command_policy must be an object")
        exact_audit_keys(
            command_policy,
            {"required_flags", "forbidden_prefixes"},
            f"{context}.command_policy",
        )
        required_flags = command_policy.get("required_flags")
        forbidden_prefixes = command_policy.get("forbidden_prefixes")
        require(isinstance(required_flags, list)
                and all(isinstance(item, str) for item in required_flags),
                f"{context}.required_flags must be strings")
        require(isinstance(forbidden_prefixes, list)
                and all(isinstance(item, str) for item in forbidden_prefixes),
                f"{context}.forbidden_prefixes must be strings")
        require(any(item in required_flags for item in ("/Zi", "-Zi"))
                and any(item in required_flags for item in ("/c", "-c")),
                f"{context} must require /Zi and a compile-only flag")
        folded_forbidden = {item.casefold() for item in forbidden_prefixes}
        require({"/gl", "-gl", "/z7", "-z7"}.issubset(folded_forbidden),
                f"{context} must forbid alternate code/debug modes")
        if mode == "swap_comdat_group_order":
            group_order = unit.get("group_order")
            require(isinstance(group_order, dict)
                    and set(group_order) == {"first", "second"},
                    f"{context}.group_order must name first/second")
            for role in ("first", "second"):
                value = group_order.get(role)
                require(isinstance(value, str) and value.startswith("?")
                        and len(value) >= 8,
                        f"{context}.group_order.{role} is invalid")
            require(group_order["first"] != group_order["second"],
                    f"{context}.group_order names must differ")
            completion = unit.get("completion")
            require(isinstance(completion, dict),
                    f"{context}.completion must be an object")
            exact_keys(completion,
                       {"state", "reason", "may_replace_compiler_output"},
                       f"{context}.completion")
            require(
                completion.get("state")
                == "object_composition_enabled_final_gates_incomplete"
                and completion.get("may_replace_compiler_output") is True
                and isinstance(completion.get("reason"), str)
                and len(completion["reason"]) >= 24,
                f"{context}.completion policy is invalid",
            )
            normalized_units.append({
                **unit,
                "source": source_relative,
                "source_path": str(source_path),
                "source_sha256": effective_source_sha,
            })
            continue

        donors = unit.get("donors")
        require(isinstance(donors, list) and donors,
                f"{context}.donors must be a non-empty array")
        normalized_donors = []
        local_recipe_ids = set()
        for donor_index, donor in enumerate(donors):
            donor_context = f"{context}.donors[{donor_index}]"
            require(isinstance(donor, dict), f"{donor_context} must be an object")
            exact_keys(
                donor, {"id", "status", "authenticity", "recipe"},
                donor_context,
            )
            recipe_id = donor.get("id")
            require(isinstance(recipe_id, str) and RECIPE_ID_RE.fullmatch(recipe_id) is not None,
                    f"{donor_context}.id is invalid")
            require(recipe_id not in local_recipe_ids,
                    f"{donor_context}.id is duplicated within this TU")
            local_recipe_ids.add(recipe_id)
            expected_status = (
                "planned_not_composed"
                if mode == "pass_through"
                else "compiler_generated_current_source"
            )
            require(donor.get("status") == expected_status,
                    f"{donor_context}.status must be {expected_status}")
            require(
                donor.get("authenticity") == "synthetic_baseline_only",
                f"{donor_context}.authenticity must be synthetic_baseline_only",
            )
            recipe = donor.get("recipe")
            require(isinstance(recipe, dict), f"{donor_context}.recipe must be an object")
            kind = recipe.get("kind")
            if mode == "compose_equal_body_comdat":
                require(
                    kind in ("forward_declaration_run", "declaration_shape"),
                    f"{donor_context}: equal-body donors require a "
                    "generated declaration recipe",
                )
                lane = recipe.get("compile_lane")
                require(
                    isinstance(lane, dict)
                    and set(lane) == {"required_define"}
                    and isinstance(lane.get("required_define"), str)
                    and lane["required_define"],
                    f"{donor_context}.compile_lane must select by a define",
                )
                if kind == "forward_declaration_run":
                    exact_keys(
                        recipe,
                        {
                            "kind", "placement", "prefix", "count", "width",
                            "generated_header_sha256", "compile_lane",
                            "emission_policy", "authenticity_rationale",
                        },
                        f"{donor_context}.recipe",
                    )
                    require(
                        recipe.get("placement") in ("prefix",
                                                    "force_include"),
                        f"{donor_context}.placement is invalid")
                    run_prefix = recipe.get("prefix")
                    run_count = recipe.get("count")
                    run_width = recipe.get("width")
                    require(isinstance(run_prefix, str)
                            and isinstance(run_count, int)
                            and not isinstance(run_count, bool)
                            and isinstance(run_width, int)
                            and not isinstance(run_width, bool),
                            f"{donor_context} forward-run parameters "
                            "are invalid")
                    try:
                        generated = entropy_generator.generate_forward_run(
                            run_prefix, run_count, run_width
                        ).encode("utf-8")
                    except ValueError as error:
                        raise ByteIdentityError(
                            f"{donor_context} forward-run parameters: {error}"
                        ) from error
                else:
                    exact_keys(
                        recipe,
                        {
                            "kind", "classes", "functions",
                            "generated_header_sha256", "compile_lane",
                            "emission_policy", "authenticity_rationale",
                        },
                        f"{donor_context}.recipe",
                    )
                    classes = recipe.get("classes")
                    functions_count = recipe.get("functions")
                    require(isinstance(classes, int)
                            and not isinstance(classes, bool)
                            and 1 <= classes <= 10,
                            f"{donor_context}.classes is invalid")
                    require(isinstance(functions_count, int)
                            and not isinstance(functions_count, bool)
                            and classes <= functions_count <= 10 * classes,
                            f"{donor_context}.functions is invalid")
                    generated = entropy_generator.generate_shape(
                        classes, functions_count
                    ).encode("utf-8")
            else:
                require(
                    kind == "declaration_shape",
                    f"{donor_context}: donors require declaration_shape",
                )
                exact_keys(
                    recipe,
                    {
                        "kind", "classes", "functions", "generated_header_sha256",
                        "emission_policy", "authenticity_rationale",
                    },
                    f"{donor_context}.recipe",
                )
                classes = recipe.get("classes")
                functions = recipe.get("functions")
                require(isinstance(classes, int) and not isinstance(classes, bool)
                        and 1 <= classes <= 10,
                        f"{donor_context}.classes is invalid")
                require(isinstance(functions, int) and not isinstance(functions, bool)
                        and classes <= functions <= 10 * classes,
                        f"{donor_context}.functions is invalid")
                generated = entropy_generator.generate_shape(
                    classes, functions
                ).encode("utf-8")
            required_prefix = "d_"
            serialized_recipe = json.dumps(recipe, sort_keys=True).casefold()
            require(not any(word in serialized_recipe for word in FORBIDDEN_RECIPE_WORDS),
                    f"{donor_context} contains forbidden provenance")
            header_sha = require_sha(
                recipe.get("generated_header_sha256"),
                f"{donor_context}.generated_header_sha256",
            )
            require(recipe_id == f"{required_prefix}{header_sha[:12]}",
                    f"{donor_context}.id is not the header content ID")
            require(sha256_bytes(generated) == header_sha,
                    f"{donor_context}: declaration generator/hash drift")
            require(recipe.get("emission_policy") == "non_emitting_declarations_only",
                    f"{donor_context}: recipe must be non-emitting declarations")
            rationale = recipe.get("authenticity_rationale")
            require(isinstance(rationale, str) and len(rationale) >= 32,
                    f"{donor_context}: authenticity rationale is too weak")
            header_output = str(recipe_output(build_dir, recipe_id, header_sha))
            existing_recipe = recipe_registry.get(recipe_id)
            if existing_recipe is None:
                recipe_registry[recipe_id] = {
                    "id": recipe_id,
                    "recipe": recipe,
                    "header_output": header_output,
                    "users": [],
                }
                recipe_order.append(recipe_id)
            else:
                require(existing_recipe["recipe"] == recipe
                        and existing_recipe["header_output"] == header_output,
                        f"duplicate recipe definition differs: {recipe_id}")
            normalized_donors.append(
                {
                    **donor,
                    "header_output": header_output,
                }
            )

        functions = unit.get("functions")
        require(isinstance(functions, list), f"{context}.functions must be an array")
        normalized_functions = []
        seen_functions = set()
        seen_section_numbers = set()
        function_recipe_ids = set()
        allowed_function_keys = {
            "mangled", "donor", "splice_class", "expected_section_number",
            "expected_seed_length", "expected_donor_length", "expected_linked_span",
            "expected_characteristics", "expected_selection", "expected_relocation_count",
            "expected_seed_line_count", "expected_donor_line_count",
            "expected_local_symbol_updates", "compiler_output_body_sha256",
            "expected_donor_fpo", "retail_oracle",
        }
        equal_body_function_keys = {
            "mangled", "donor", "splice_class", "expected_body_length",
            "expected_body_sha256", "expected_changed_offsets",
            "expected_code_renames", "expected_xdata_rename_offsets",
            "expected_relocation_moves",
        }
        for function_index, function in enumerate(functions):
            function_context = f"{context}.functions[{function_index}]"
            require(isinstance(function, dict), f"{function_context} must be an object")
            if mode == "compose_equal_body_comdat":
                mangled = function.get("mangled")
                require(isinstance(mangled, str) and mangled.startswith("?")
                        and len(mangled) >= 8,
                        f"{function_context}.mangled is invalid")
                require(mangled not in seen_functions,
                        f"{function_context}.mangled is duplicated")
                seen_functions.add(mangled)
                donor_id = function.get("donor")
                require(donor_id in local_recipe_ids,
                        f"{function_context}.donor is not declared by this TU")
                function_recipe_ids.add(donor_id)
                splice_class = function.get("splice_class")
                require(splice_class in ("equal_body_strict",
                                         "equal_body_eh_structural_local",
                                         "equal_body_eh_reloc_layout",
                                         "same_slot_resize"),
                        f"{function_context}: unsupported splice class")
                if splice_class == "same_slot_resize":
                    exact_keys(
                        function,
                        {"mangled", "donor", "splice_class",
                         "expected_seed_length", "expected_donor_length",
                         "expected_linked_span", "expected_body_sha256"},
                        function_context,
                    )
                    for name in ("expected_seed_length",
                                 "expected_donor_length",
                                 "expected_linked_span"):
                        value = function.get(name)
                        require(isinstance(value, int)
                                and not isinstance(value, bool) and value > 0,
                                f"{function_context}.{name} is invalid")
                    require(
                        function["expected_linked_span"] % 16 == 0
                        and ((function["expected_seed_length"] + 15) // 16)
                        * 16 == function["expected_linked_span"]
                        == ((function["expected_donor_length"] + 15) // 16)
                        * 16
                        and function["expected_seed_length"]
                        != function["expected_donor_length"],
                        f"{function_context}: resize spans are inconsistent",
                    )
                    require_sha(function.get("expected_body_sha256"),
                                f"{function_context}.expected_body_sha256")
                    normalized_functions.append(dict(function))
                    continue
                required_keys = set(equal_body_function_keys)
                if splice_class == "equal_body_strict":
                    required_keys -= {"expected_code_renames",
                                      "expected_xdata_rename_offsets",
                                      "expected_relocation_moves"}
                elif splice_class == "equal_body_eh_structural_local":
                    required_keys -= {"expected_relocation_moves"}
                else:
                    required_keys -= {"expected_code_renames"}
                exact_keys(function, required_keys, function_context)
                length = function.get("expected_body_length")
                require(isinstance(length, int) and not isinstance(length, bool)
                        and length > 0,
                        f"{function_context}.expected_body_length is invalid")
                require_sha(function.get("expected_body_sha256"),
                            f"{function_context}.expected_body_sha256")
                offsets = function.get("expected_changed_offsets")
                require(isinstance(offsets, list) and offsets
                        and all(isinstance(item, int)
                                and not isinstance(item, bool)
                                and 0 <= item < length
                                for item in offsets)
                        and offsets == sorted(set(offsets)),
                        f"{function_context}.expected_changed_offsets is invalid")
                if splice_class == "equal_body_eh_structural_local":
                    renames = function.get("expected_code_renames")
                    require(
                        isinstance(renames, list)
                        and all(isinstance(item, list) and len(item) == 2
                                and isinstance(item[0], int)
                                and item[1] in ("L", "T")
                                for item in renames),
                        f"{function_context}.expected_code_renames is invalid",
                    )
                if splice_class == "equal_body_eh_reloc_layout":
                    moves = function.get("expected_relocation_moves")
                    require(
                        isinstance(moves, list) and moves
                        and all(isinstance(item, list) and len(item) == 2
                                and all(isinstance(v, int)
                                        and not isinstance(v, bool)
                                        and 0 <= v < length
                                        for v in item)
                                for item in moves),
                        f"{function_context}.expected_relocation_moves "
                        "is invalid",
                    )
                if splice_class in ("equal_body_eh_structural_local",
                                    "equal_body_eh_reloc_layout"):
                    xdata_offsets = function.get("expected_xdata_rename_offsets")
                    require(
                        isinstance(xdata_offsets, list)
                        and all(isinstance(item, int)
                                and not isinstance(item, bool)
                                for item in xdata_offsets),
                        f"{function_context}.expected_xdata_rename_offsets "
                        "is invalid",
                    )
                normalized_functions.append(dict(function))
                continue
            exact_keys(function, allowed_function_keys, function_context)
            mangled = function.get("mangled")
            require(isinstance(mangled, str) and mangled.startswith("?") and len(mangled) >= 8,
                    f"{function_context}.mangled is invalid")
            require(mangled not in seen_functions,
                    f"{function_context}.mangled is duplicated")
            seen_functions.add(mangled)
            donor_id = function.get("donor")
            require(donor_id in local_recipe_ids,
                    f"{function_context}.donor is not declared by this TU")
            function_recipe_ids.add(donor_id)
            require(function.get("splice_class") == "equal_linked_span_fpo",
                    f"{function_context}: unsupported splice class")
            for name in (
                "expected_section_number", "expected_seed_length", "expected_donor_length",
                "expected_linked_span", "expected_characteristics", "expected_selection",
                "expected_relocation_count", "expected_seed_line_count",
                "expected_donor_line_count", "expected_local_symbol_updates",
            ):
                value = function.get(name)
                require(isinstance(value, int) and not isinstance(value, bool) and value >= 0,
                        f"{function_context}.{name} is invalid")
            require(function["expected_section_number"] > 0,
                    f"{function_context}.expected_section_number is invalid")
            require(function["expected_section_number"] not in seen_section_numbers,
                    f"{function_context}.expected_section_number is duplicated within this TU")
            seen_section_numbers.add(function["expected_section_number"])
            require(function["expected_seed_length"] > 0
                    and function["expected_donor_length"] > 0,
                    f"{function_context}: zero-length functions are unsupported")
            require(function["expected_linked_span"] > 0
                    and function["expected_linked_span"] % 16 == 0,
                    f"{function_context}.expected_linked_span is invalid")
            require(((function["expected_seed_length"] + 15) // 16) * 16
                    == function["expected_linked_span"]
                    == ((function["expected_donor_length"] + 15) // 16) * 16,
                    f"{function_context}: declared linked spans are not equal")
            require(function["expected_selection"] == 2,
                    f"{function_context}: only select-any FPO COMDATs are supported")
            require_sha(function.get("compiler_output_body_sha256"),
                        f"{function_context}.compiler_output_body_sha256")
            expected_donor_fpo = validate_manifest_fpo_record(
                function.get("expected_donor_fpo"),
                f"{function_context}.expected_donor_fpo",
            )
            require(expected_donor_fpo["cbProcSize"]
                    == function["expected_donor_length"],
                    f"{function_context}.expected_donor_fpo size differs")
            retail = function.get("retail_oracle")
            require(isinstance(retail, dict), f"{function_context}.retail_oracle must be an object")
            exact_keys(retail, {"image", "address", "verdict", "length"},
                       f"{function_context}.retail_oracle")
            require(retail.get("image") in ("LEGO1.DLL", "ISLE.EXE"),
                    f"{function_context}.retail_oracle.image is invalid")
            require(isinstance(retail.get("address"), str)
                    and ADDRESS_RE.fullmatch(retail["address"]) is not None,
                    f"{function_context}.retail_oracle.address is invalid")
            retail_identity = (retail.get("image"), retail.get("address"))
            require(retail_identity not in retail_identities,
                    f"{function_context}.retail_oracle identity/address is duplicated")
            retail_identities.add(retail_identity)
            require(retail.get("verdict") == "MATCH"
                    and type(retail.get("length")) is int
                    and retail.get("length") == function["expected_donor_length"],
                    f"{function_context}: retail oracle is not a pinned exact-length match")
            normalized_functions.append({
                **function, "expected_donor_fpo": expected_donor_fpo,
            })

        if mode == "pass_through":
            require(not functions, f"{context}: pass_through cannot request functions")
        else:
            require(functions, f"{context}: composer mode requires functions")
            require(function_recipe_ids == local_recipe_ids,
                    f"{context}: every compiler donor must own at least one function")

        completion = unit.get("completion")
        require(isinstance(completion, dict), f"{context}.completion must be an object")
        exact_keys(completion, {"state", "reason", "may_replace_compiler_output"},
                   f"{context}.completion")
        expected_completion = (
            "planned_not_composed"
            if mode == "pass_through"
            else "object_composition_enabled_final_gates_incomplete"
        )
        require(completion.get("state") == expected_completion,
                f"{context}.completion.state must be {expected_completion}")
        require(completion.get("may_replace_compiler_output")
                is (mode != "pass_through"),
                f"{context}.completion replacement policy is invalid")
        require(isinstance(completion.get("reason"), str) and len(completion["reason"]) >= 24,
                f"{context}.completion.reason is too weak")

        normalized_units.append(
            {
                **unit,
                "source": source_relative,
                "source_path": str(source_path),
                "source_sha256": effective_source_sha,
                "command_policy": {
                    **command_policy,
                    "allowed_force_includes": target_policy_by_name[target][
                        "allowed_force_includes"
                    ],
                },
                "donors": normalized_donors,
                "functions": normalized_functions,
            }
        )
        for donor in normalized_donors:
            recipe_registry[donor["id"]]["users"].append(
                {
                    "target": target,
                    "source": source_relative,
                    "mode": mode,
                    "completion": completion["state"],
                }
            )

    archives = manifest.get("archives")
    require(isinstance(archives, list), "archives must be an array")
    normalized_archives = []
    archive_identities = set()
    for archive_index, archive in enumerate(archives):
        context = f"archives[{archive_index}]"
        require(isinstance(archive, dict), f"{context} must be an object")
        exact_audit_keys(
            archive,
            {
                "kind", "identity", "source", "source_sha256",
                "payload_policy", "imported_target", "link_contract",
                "completion",
            },
            context,
        )
        require(
            archive.get("kind") == "third_party_reconstructed_archive",
            f"{context}.kind is not the narrow third-party archive exception",
        )
        identity = archive.get("identity")
        require(
            identity in THIRD_PARTY_RETAIL_ARCHIVES
            and identity not in archive_identities,
            f"{context}.identity is unsupported or duplicated",
        )
        archive_identities.add(identity)
        expected_relative = THIRD_PARTY_RETAIL_ARCHIVES[identity]
        require(
            archive.get("source") == expected_relative,
            f"{context}.source is not the exact {identity} archive seat",
        )
        source_path = source_root.joinpath(*PurePosixPath(expected_relative).parts)
        try:
            source_canonical = source_path.resolve(strict=True)
        except OSError as error:
            raise ByteIdentityError(
                f"{context}.source cannot be resolved: {error}"
            ) from error
        require(
            lexical_absolute_path(source_path) == source_canonical
            and source_canonical.is_file(),
            f"{context}.source is absent or redirected",
        )
        source_sha = require_sha(
            archive.get("source_sha256"), f"{context}.source_sha256"
        )
        source_bytes = (
            active_build_authority().read_external_bytes(source_path)
            if ACTIVE_BUILD_AUTHORITIES else source_path.read_bytes()
        )
        require(
            source_bytes.startswith(b"!<arch>\n")
            and sha256_bytes(source_bytes) == source_sha,
            f"{context}.source archive bytes differ from their pin",
        )
        require(
            archive.get("payload_policy") == THIRD_PARTY_RETAIL_ARCHIVE_POLICY,
            f"{context}.payload_policy is not the exact named exception",
        )
        imported_target = archive.get("imported_target")
        expected_imported_target = f"{identity}::{identity}"
        require(
            imported_target == expected_imported_target,
            f"{context}.imported_target must be {expected_imported_target}",
        )
        link_contract = archive.get("link_contract")
        require(
            isinstance(link_contract, list) and link_contract,
            f"{context}.link_contract must be a non-empty array",
        )
        normalized_link_contract = []
        contract_targets = set()
        for contract_index, contract in enumerate(link_contract):
            contract_context = f"{context}.link_contract[{contract_index}]"
            require(isinstance(contract, dict),
                    f"{contract_context} must be an object")
            exact_audit_keys(
                contract,
                {"target", "direct_link_sequence", "occurrences"},
                contract_context,
            )
            target = contract.get("target")
            sequence = contract.get("direct_link_sequence")
            occurrences = contract.get("occurrences")
            require(
                isinstance(target, str)
                and TARGET_RE.fullmatch(target) is not None
                and target not in contract_targets,
                f"{contract_context}.target is invalid or duplicated",
            )
            contract_targets.add(target)
            require(
                isinstance(sequence, list)
                and len(sequence) >= 2
                and all(isinstance(token, str) and token for token in sequence)
                and imported_target in sequence,
                f"{contract_context}.direct_link_sequence is invalid",
            )
            require_exact_int(
                occurrences,
                f"{contract_context}.occurrences",
                minimum=1,
            )
            normalized_link_contract.append({
                "target": target,
                "direct_link_sequence": sequence,
                "occurrences": occurrences,
            })
        completion = archive.get("completion")
        require(isinstance(completion, dict), f"{context}.completion must be an object")
        exact_audit_keys(
            completion,
            {"state", "reason", "may_supply_linker_payload"},
            f"{context}.completion",
        )
        require(
            completion.get("state")
            == "authorized_exact_archive_materialization_enabled"
            and completion.get("may_supply_linker_payload") is True
            and isinstance(completion.get("reason"), str)
            and len(completion["reason"]) >= 24,
            f"{context}.completion must authorize only exact materialization",
        )
        output = archive_output(build_root, identity, expected_relative)
        normalized_archives.append({
            **archive,
            "source_path": str(source_path),
            "source_size": len(source_bytes),
            "output": str(output),
            "audit": str(archive_audit_path(build_root, identity)),
            "link_contract": normalized_link_contract,
        })
    images = manifest.get("images")
    require(isinstance(images, dict), "images must be an object")
    image_contracts = {
        "LEGO1": {
            "target": "lego1", "original": "legobin/LEGO1.DLL",
            "recompiled": "LEGO1.DLL", "required_row_count": 4933,
        },
        "ISLE": {
            "target": "isle", "original": "legobin/ISLE.EXE",
            "recompiled": "ISLE.EXE", "required_row_count": 172,
        },
        "CONFIG": {
            "target": "config", "original": "legobin/CONFIG.EXE",
            "recompiled": "CONFIG.EXE", "required_row_count": 111,
        },
    }
    require(set(images) <= set(image_contracts),
            "images contains an unsupported identity")
    normalized_images = []
    for identity, image in images.items():
        context = f"images.{identity}"
        contract = image_contracts[identity]
        require(isinstance(image, dict),
                f"{context} must be an image gate object")
        exact_audit_keys(
            image,
            {
                "kind", "target", "original", "original_sha256",
                "original_md5", "original_size", "recompiled",
                "reccmp_report", "reccmp_schema", "required_row_count",
                "row_identity_sha256", "iteration_baseline", "completion",
                "link_time", "resource_time",
            },
            context,
        )
        require(
            image.get("kind") == "final_image_identity_gate"
            and image.get("target") == contract["target"],
            f"{context} target/kind differs",
        )
        original_relative, original_path = resolve_relative(
            source_root, image.get("original"), f"{context}.original"
        )
        require(original_relative == contract["original"],
                f"{context}.original must use the fixed retail oracle seat")
        original_data = (
            active_build_authority().read_external_bytes(original_path)
            if ACTIVE_BUILD_AUTHORITIES else original_path.read_bytes()
        )
        original_sha256 = require_sha(
            image.get("original_sha256"), f"{context}.original_sha256"
        )
        original_md5 = require_md5(
            image.get("original_md5"), f"{context}.original_md5"
        )
        original_size = require_exact_int(
            image.get("original_size"), f"{context}.original_size", minimum=1
        )
        require(
            original_data.startswith(b"MZ")
            and len(original_data) == original_size
            and sha256_bytes(original_data) == original_sha256
            and md5_bytes(original_data) == original_md5,
            f"{context} retail oracle image differs from its pins",
        )
        # The declared link and resource times must be exactly the retail
        # image's own fields: they are recorded 1997 build facts, never
        # chosen values.
        pe_offset = int.from_bytes(original_data[0x3C:0x40], "little")
        header_time = int.from_bytes(
            original_data[pe_offset + 8:pe_offset + 12], "little"
        )
        require(
            image.get("link_time") == header_time,
            f"{context}.link_time differs from the retail PE header",
        )
        resource_times = pe_resource_directory_times(original_data)
        require(
            resource_times == {image.get("resource_time")},
            f"{context}.resource_time differs from the retail resource tree",
        )
        require(
            image.get("recompiled") == contract["recompiled"]
            and image.get("reccmp_report")
            == f"byte-identity/final/{identity}.json"
            and image.get("reccmp_schema")
            == "reccmp_json_diet_exact_rows_v1",
            f"{context} build output/report contract differs",
        )
        required_rows = require_exact_int(
            image.get("required_row_count"),
            f"{context}.required_row_count",
            minimum=contract["required_row_count"],
            maximum=contract["required_row_count"],
        )
        row_identity_sha256 = require_sha(
            image.get("row_identity_sha256"),
            f"{context}.row_identity_sha256",
        )
        iteration = image.get("iteration_baseline")
        require(isinstance(iteration, dict),
                f"{context}.iteration_baseline must be an object")
        exact_audit_keys(
            iteration,
            {
                "state", "exact_raw_1_0_count",
                "accepted_row_identity_sha256", "require_zero_losses",
                "reference_target",
            },
            f"{context}.iteration_baseline",
            optional={"reference_target"},
        )
        iteration_count = require_exact_int(
            iteration.get("exact_raw_1_0_count"),
            f"{context}.iteration_baseline.exact_raw_1_0_count",
            minimum=1, maximum=required_rows,
        )
        iteration_sha = require_sha(
            iteration.get("accepted_row_identity_sha256"),
            f"{context}.iteration_baseline.accepted_row_identity_sha256",
        )
        require(
            iteration.get("state") in {
                "accepted_raw_score_set_pinned_v1",
                "accepted_raw_score_set_pinned_v2_source_true",
            }
            and iteration.get("require_zero_losses") is True,
            f"{context}.iteration_baseline policy differs",
        )
        completion = image.get("completion")
        require(isinstance(completion, dict), f"{context}.completion must be an object")
        exact_audit_keys(
            completion,
            {
                "state", "require_all_rows_raw_1_0",
                "require_recompiled_md5_equal_original",
                "require_recompiled_sha256_equal_original",
                "require_recompiled_address_equal_retail",
            },
            f"{context}.completion",
        )
        require(
            exact_json_equal(completion, {
                "state": "required_for_byte_identity_complete",
                "require_all_rows_raw_1_0": True,
                "require_recompiled_md5_equal_original": True,
                "require_recompiled_sha256_equal_original": True,
                "require_recompiled_address_equal_retail": True,
            }),
            f"{context}.completion policy differs",
        )
        normalized_images.append({
            **image,
            "identity": identity,
            "original": original_relative,
            "original_path": str(original_path),
            "original_sha256": original_sha256,
            "original_md5": original_md5,
            "original_size": original_size,
            "recompiled_path": str(final_image_path(build_root, identity)),
            "reccmp_report_path": str(final_report_path(build_root, identity)),
            "required_row_count": required_rows,
            "row_identity_sha256": row_identity_sha256,
            "iteration_baseline": {
                **iteration,
                "exact_raw_1_0_count": iteration_count,
                "accepted_row_identity_sha256": iteration_sha,
            },
        })
    # A manifest that can ever publish a final image verdict must declare both
    # narrowly authorized third-party archives.  An empty/subset declaration
    # would otherwise let a stale host-tree archive satisfy LINK while the
    # manifest still appeared to govern the final image.
    if normalized_images:
        require(
            archive_identities == REQUIRED_THIRD_PARTY_ARCHIVES,
            "final byte identity requires exactly SmartHeap and Smacker archives",
        )

    terminal = manifest.get("terminal_producers")
    require(isinstance(terminal, dict), "terminal_producers must be an object")
    if not normalized_images:
        require(not terminal,
                "terminal_producers require a declared final image gate")
        normalized_terminal = {}
    else:
        exact_audit_keys(terminal, {"link", "reccmp"}, "terminal_producers")
        link = terminal.get("link")
        require(isinstance(link, dict), "terminal_producers.link must be an object")
        exact_audit_keys(
            link,
            {
                "schema", "tools", "library_trees", "project_sdk_libraries",
                "imported_targets",
                "release_required_options", "analysis_added_options",
                "generator_standard_libraries",
                "verified_nonterminal_leaf_audits",
                "ordered_library_occurrence_count",
                "ordered_library_identity_sha256",
                "map_evidence", "member_evidence", "max_child_seconds",
            },
            "terminal_producers.link",
        )
        require(link.get("schema") == "msvc42_dual_link_map_pdb_v1",
                "terminal link producer schema differs")
        link_timeout = require_exact_int(
            link.get("max_child_seconds"),
            "terminal_producers.link.max_child_seconds", minimum=1, maximum=900,
        )
        tools = link.get("tools")
        require(isinstance(tools, list) and len(tools) == 6,
                "terminal link producer must pin six exact tools")
        required_tool_roles = {
            "link_wrapper", "link_binary", "lib_wrapper", "lib_binary",
            "rc_wrapper", "rc_binary",
        }
        normalized_link_tools = []
        tool_roles = set()
        tool_paths = set()
        for index, item in enumerate(tools):
            context = f"terminal_producers.link.tools[{index}]"
            require(isinstance(item, dict), f"{context} must be an object")
            exact_audit_keys(item, {"role", "path", "sha256"}, context)
            role = item.get("role")
            require(role in required_tool_roles and role not in tool_roles,
                    f"{context}.role is unsupported or duplicated")
            tool_roles.add(role)
            relative = item.get("path")
            require(isinstance(relative, str) and relative,
                    f"{context}.path is invalid")
            pure = PurePosixPath(relative)
            require(not pure.is_absolute() and ".." not in pure.parts
                    and "\\" not in relative and ";" not in relative,
                    f"{context}.path escapes the compiler root")
            relative = pure.as_posix()
            require(relative not in tool_paths,
                    f"{context}.path is duplicated")
            tool_paths.add(relative)
            normalized = {
                "role": role, "path": relative,
                "sha256": require_sha(item.get("sha256"), f"{context}.sha256"),
            }
            if compiler_root is not None:
                logical = compiler_root.joinpath(*pure.parts)
                try:
                    path = logical.resolve(strict=True)
                    metadata = logical.stat(follow_symlinks=False)
                except OSError as error:
                    raise ByteIdentityError(
                        f"terminal link tool is absent: {logical}"
                    ) from error
                require(
                    path == logical
                    and stat.S_ISREG(metadata.st_mode)
                    and not logical.is_symlink(),
                    f"terminal link tool is redirected or non-regular: {logical}",
                )
                if role.endswith("_wrapper"):
                    require(os.access(path, os.X_OK),
                            f"terminal link wrapper is not executable: {path}")
                require(sha256_file(path) == normalized["sha256"],
                        f"terminal link tool hash differs: {role}")
                normalized["absolute_path"] = str(path)
            normalized_link_tools.append(normalized)
        require(tool_roles == required_tool_roles,
                "terminal link producer tool role set is incomplete")

        library_trees = link.get("library_trees")
        require(isinstance(library_trees, list) and len(library_trees) == 2,
                "terminal link producer must pin MSVC and MFC library trees")
        normalized_library_trees = []
        library_roles = set()
        for index, item in enumerate(library_trees):
            context = f"terminal_producers.link.library_trees[{index}]"
            require(isinstance(item, dict), f"{context} must be an object")
            exact_audit_keys(
                item,
                {"role", "path", "entry_count", "max_depth",
                 "membership_sha256", "content_sha256"},
                context,
            )
            role = item.get("role")
            require(role in {"msvc_lib", "mfc_lib"} and role not in library_roles,
                    f"{context}.role is unsupported or duplicated")
            library_roles.add(role)
            relative = item.get("path")
            require(isinstance(relative, str) and relative,
                    f"{context}.path is invalid")
            pure = PurePosixPath(relative)
            require(not pure.is_absolute() and ".." not in pure.parts
                    and "\\" not in relative and ";" not in relative,
                    f"{context}.path escapes the compiler root")
            pin = {
                "role": role,
                "path": pure.as_posix(),
                "entry_count": require_exact_int(
                    item.get("entry_count"), f"{context}.entry_count",
                    minimum=1, maximum=20000,
                ),
                "max_depth": require_exact_int(
                    item.get("max_depth"), f"{context}.max_depth",
                    minimum=0, maximum=32,
                ),
                "membership_sha256": require_sha(
                    item.get("membership_sha256"), f"{context}.membership_sha256"
                ),
                "content_sha256": require_sha(
                    item.get("content_sha256"), f"{context}.content_sha256"
                ),
            }
            if compiler_root is not None:
                _, path = declared_toolchain_path(
                    compiler_root, pin["path"], f"terminal library tree {role}"
                )
                snapshot = canonical_tree_snapshot(
                    path, hash_files=True, max_entries=pin["entry_count"],
                    max_depth=pin["max_depth"],
                )
                require(
                    snapshot["entry_count"] == pin["entry_count"]
                    and snapshot["max_depth"] == pin["max_depth"]
                    and snapshot["membership_sha256"] == pin["membership_sha256"]
                    and snapshot["content_sha256"] == pin["content_sha256"],
                    f"terminal library tree differs: {role}",
                )
                pin["absolute_path"] = str(path)
                pin["metadata_sha256"] = snapshot["metadata_sha256"]
            normalized_library_trees.append(pin)
        require(library_roles == {"msvc_lib", "mfc_lib"},
                "terminal library tree role set is incomplete")

        project_sdk_libraries = link.get("project_sdk_libraries")
        require(isinstance(project_sdk_libraries, list),
                "terminal project SDK library pins must be an array")
        normalized_project_sdk_libraries = []
        sdk_paths = set()
        for index, item in enumerate(project_sdk_libraries):
            context = f"terminal_producers.link.project_sdk_libraries[{index}]"
            require(isinstance(item, dict), f"{context} must be an object")
            exact_audit_keys(item, {"path", "sha256"}, context)
            relative = item.get("path")
            require(isinstance(relative, str) and relative,
                    f"{context}.path is invalid")
            pure = PurePosixPath(relative)
            require(not pure.is_absolute() and ".." not in pure.parts
                    and "\\" not in relative and ";" not in relative,
                    f"{context}.path escapes the source root")
            relative = pure.as_posix()
            require(relative not in sdk_paths,
                    f"{context}.path is duplicated")
            sdk_paths.add(relative)
            path = source_dir / PurePosixPath(relative)
            try:
                resolved_sdk = path.resolve(strict=True)
            except OSError as error:
                raise ByteIdentityError(
                    f"{context}.path is absent or redirected: {error}"
                ) from error
            require(resolved_sdk == path and path.is_file()
                    and not path.is_symlink(),
                    f"{context}.path is absent or redirected")
            expected_sha = require_sha(
                item.get("sha256"), f"{context}.sha256"
            )
            require(sha256_file(path) == expected_sha,
                    f"{context}.sha256 differs")
            normalized_project_sdk_libraries.append({
                "path": relative, "absolute_path": str(path),
                "sha256": expected_sha,
            })
        require(sdk_paths == REQUIRED_PROJECT_SDK_LIBRARIES,
                "terminal project SDK library set differs from exact DirectX 5 closure")

        imported_targets = link.get("imported_targets")
        require(isinstance(imported_targets, list),
                "terminal imported-target contracts must be an array")
        normalized_imported_targets = []
        imported_names = set()
        source_root_text = str(source_dir)
        for index, item in enumerate(imported_targets):
            context = f"terminal_producers.link.imported_targets[{index}]"
            require(isinstance(item, dict), f"{context} must be an object")
            exact_audit_keys(
                item, {"name", "type", "global", "location", "properties"},
                context,
            )
            name = item.get("name")
            target_type = item.get("type")
            require(isinstance(name, str) and IMPORTED_TARGET_RE.fullmatch(name)
                    and name not in imported_names,
                    f"{context}.name is invalid or duplicated")
            imported_names.add(name)
            require(target_type in {"STATIC_LIBRARY", "INTERFACE_LIBRARY"},
                    f"{context}.type is unsupported")
            require(type(item.get("global")) is bool,
                    f"{context}.global must be boolean")
            location = item.get("location")
            require(location is None or (isinstance(location, str) and location),
                    f"{context}.location is invalid")
            require((target_type == "STATIC_LIBRARY") is (location is not None),
                    f"{context}.location/type contract differs")
            properties = item.get("properties")
            require(isinstance(properties, dict),
                    f"{context}.properties must be an object")
            exact_audit_keys(
                properties, set(IMPORTED_TARGET_INTERFACE_PROPERTIES),
                f"{context}.properties",
            )

            def expand_imported_value(value: object, value_context: str) -> str:
                require(isinstance(value, str) and value and "\0" not in value
                        and ";" not in value,
                        f"{value_context} must be one non-empty CMake list item")
                expanded = value.replace("<SOURCE_ROOT>", source_root_text)
                require("<" not in expanded and ">" not in expanded,
                        f"{value_context} contains an unknown placeholder")
                return expanded

            normalized_properties = {}
            for property_name in IMPORTED_TARGET_INTERFACE_PROPERTIES:
                values = properties.get(property_name)
                require(isinstance(values, list)
                        and all(isinstance(value, str) for value in values),
                        f"{context}.properties.{property_name} must be an array")
                normalized_properties[property_name] = [
                    expand_imported_value(
                        value,
                        f"{context}.properties.{property_name}[{value_index}]",
                    )
                    for value_index, value in enumerate(values)
                ]
            normalized_location = (
                expand_imported_value(location, f"{context}.location")
                if location is not None else None
            )
            normalized_imported_targets.append({
                "name": name,
                "type": target_type,
                "global": item["global"],
                "location": normalized_location,
                "properties": normalized_properties,
            })
        require(imported_names == REQUIRED_IMPORTED_TARGETS,
                "terminal imported-target name universe differs")
        normalized_imported_targets.sort(key=lambda item: item["name"])

        release_options = link.get("release_required_options")
        analysis_options = link.get("analysis_added_options")
        require(exact_json_equal(release_options, ["/MAP", "/VERBOSE:LIB"]),
                "terminal release link option contract differs")
        require(exact_json_equal(analysis_options, ["/DEBUG"]),
                "terminal analysis link option contract differs")
        standard_libraries = link.get("generator_standard_libraries")
        require(isinstance(standard_libraries, dict),
                "terminal generator standard-library contract must be an object")
        exact_audit_keys(
            standard_libraries,
            {"configuration", "base", "configuration_specific"},
            "terminal_producers.link.generator_standard_libraries",
        )
        require(standard_libraries.get("configuration") == "RelWithDebInfo",
                "terminal generator standard-library configuration differs")
        normalized_standard_libraries = {}
        for key in ("base", "configuration_specific"):
            values = standard_libraries.get(key)
            require(isinstance(values, list)
                    and all(isinstance(value, str) for value in values),
                    "terminal generator standard-library sequence is invalid")
            require(all(re.fullmatch(r"[a-z0-9_+.\-]+\.lib", value)
                        for value in values),
                    "terminal generator standard-library name is noncanonical")
            require(len(values) == len(set(values)),
                    "terminal generator standard-library sequence is duplicated")
            normalized_standard_libraries[key] = list(values)
        require(not normalized_standard_libraries["configuration_specific"],
                "terminal config-specific standard libraries are unsupported")
        require(normalized_standard_libraries["base"],
                "terminal base standard-library sequence is empty")
        normalized_standard_libraries["configuration"] = "RelWithDebInfo"
        leaf_audits = link.get("verified_nonterminal_leaf_audits")
        require(isinstance(leaf_audits, list),
                "verified nonterminal leaf-audit policy must be an array")
        normalized_leaf_audits = []
        leaf_targets = set()
        for index, item in enumerate(leaf_audits):
            context = (
                f"terminal_producers.link.verified_nonterminal_leaf_audits[{index}]"
            )
            require(isinstance(item, dict), f"{context} must be an object")
            exact_audit_keys(
                item,
                {"target", "compiler_audit_count", "resource_audit_count"},
                context,
            )
            target = item.get("target")
            require(isinstance(target, str) and TARGET_RE.fullmatch(target)
                    and target != "lego1" and target not in leaf_targets,
                    f"{context}.target is invalid or duplicated")
            leaf_targets.add(target)
            normalized_leaf_audits.append({
                "target": target,
                "compiler_audit_count": require_exact_int(
                    item.get("compiler_audit_count"),
                    f"{context}.compiler_audit_count", minimum=0, maximum=1000,
                ),
                "resource_audit_count": require_exact_int(
                    item.get("resource_audit_count"),
                    f"{context}.resource_audit_count", minimum=0, maximum=1000,
                ),
            })
        require(normalized_leaf_audits
                == sorted(normalized_leaf_audits,
                          key=lambda item: item["target"]),
                "verified nonterminal leaf-audit policy is not target-sorted")
        ordered_library_occurrence_count = require_exact_int(
            link.get("ordered_library_occurrence_count"),
            "terminal_producers.link.ordered_library_occurrence_count",
            minimum=1, maximum=1000,
        )
        ordered_library_identity_sha256 = require_sha(
            link.get("ordered_library_identity_sha256"),
            "terminal_producers.link.ordered_library_identity_sha256",
        )

        def normalize_evidence(values: object, context: str, keys: set[str]) -> list[dict]:
            require(isinstance(values, list) and values,
                    f"{context} must be a non-empty array")
            result = []
            seen = set()
            for index, item in enumerate(values):
                item_context = f"{context}[{index}]"
                require(isinstance(item, dict), f"{item_context} must be an object")
                exact_audit_keys(item, keys, item_context)
                require(all(isinstance(item.get(key), str) and item.get(key)
                            for key in keys),
                        f"{item_context} values must be non-empty strings")
                identity = tuple(item[key] for key in sorted(keys))
                require(identity not in seen, f"{item_context} is duplicated")
                seen.add(identity)
                result.append(dict(item))
            return result

        normalized_map_evidence = normalize_evidence(
            link.get("map_evidence"), "terminal_producers.link.map_evidence",
            {"symbol", "address", "library", "member"},
        )
        normalized_member_evidence = normalize_evidence(
            link.get("member_evidence"),
            "terminal_producers.link.member_evidence",
            {"symbol", "referenced_in", "library", "member"},
        )
        required_member_triples = {
            ("SHLW32MT.LIB", "shnew.obj"),
            ("smackw32.lib", "smackw32.obj"),
            ("libcmt.lib", "strstr.obj"),
        }
        require(
            {(item["library"], item["member"])
             for item in normalized_member_evidence} >= required_member_triples,
            "terminal member evidence omits SmartHeap, Smacker, or libcmt strstr",
        )

        reccmp = terminal.get("reccmp")
        require(isinstance(reccmp, dict),
                "terminal_producers.reccmp must be an object")
        require(reccmp.get("schema") == "reccmp_paths_json_diet_producer_v1",
                "terminal reccmp producer schema differs")
        if "backend_profiles" in reccmp:
            exact_audit_keys(
                reccmp,
                {"schema", "backend_profiles", "argv_template",
                 "max_child_seconds"},
                "terminal_producers.reccmp",
            )
            profiles = reccmp.get("backend_profiles")
            require(isinstance(profiles, dict)
                    and set(profiles) == {
                        POSIX_WINE_BACKEND, WINDOWS_NATIVE_BACKEND,
                    }, "terminal reccmp backend profile universe differs")
            posix_profile = profiles[POSIX_WINE_BACKEND]
            require(isinstance(posix_profile, dict),
                    "terminal POSIX reccmp profile is not an object")
            exact_audit_keys(posix_profile, {
                "status", "transport_schema", "executable",
                "executable_sha256", "interpreter", "interpreter_sha256",
                "private_runtime", "closure_roots",
            }, "terminal POSIX reccmp profile")
            require(
                posix_profile.get("status") == "framework_implemented"
                and posix_profile.get("transport_schema")
                == "darwin_native_python_private_cvdump_wine_v1",
                "terminal POSIX reccmp backend profile differs",
            )
            windows_profile = profiles[WINDOWS_NATIVE_BACKEND]
            require(isinstance(windows_profile, dict),
                    "terminal Windows reccmp profile is not an object")
            exact_audit_keys(windows_profile, {"status", "transport_schema"},
                             "terminal Windows reccmp profile")
            require(
                windows_profile == {
                    "status": "architectural_seam_deferred_untested",
                    "transport_schema": "windows_native_python_cvdump_v1",
                }, "terminal Windows reccmp backend profile differs",
            )
            profile = profiles[execution_backend["id"]]
            require(profile.get("status") == "framework_implemented",
                    f"terminal reccmp backend is explicitly deferred: "
                    f"{execution_backend['id']}")
        else:
            # Native test fixtures without the explicit backend registry retain
            # the POSIX profile only. Production manifests must be keyed before
            # any host-specific pathname is resolved.
            require(manifest.get("execution_backends") is None
                    and execution_backend["id"] == POSIX_WINE_BACKEND,
                    "terminal reccmp host paths are not backend-keyed")
            exact_audit_keys(
                reccmp,
                {
                    "schema", "executable", "executable_sha256",
                    "interpreter", "interpreter_sha256", "private_runtime",
                    "closure_roots", "argv_template", "max_child_seconds",
                },
                "terminal_producers.reccmp",
            )
            profile = {
                **reccmp,
                "status": "framework_implemented",
                "transport_schema":
                    "darwin_native_python_private_cvdump_wine_v1",
            }
        normalized_reccmp_paths = {}
        for name in ("executable", "interpreter"):
            value = profile.get(name)
            path = manifest_host_path(
                value, f"terminal reccmp {name}", host_roots
            )
            expected = require_sha(
                profile.get(f"{name}_sha256"),
                f"terminal_producers.reccmp.{name}_sha256",
            )
            normalized_reccmp_paths[f"{name}_path"] = str(path)
            normalized_reccmp_paths[f"{name}_sha256"] = expected
        private_runtime = profile.get("private_runtime")
        require(isinstance(private_runtime, dict),
                "terminal reccmp private_runtime must be an object")
        exact_audit_keys(
            private_runtime,
            {
                "schema", "app_binary", "app_binary_sha256",
                "framework_dylib", "framework_dylib_sha256", "stdlib",
                "external_dylibs",
            },
            "terminal_producers.reccmp.private_runtime",
        )
        require(private_runtime.get("schema")
                == "darwin_relocated_cpython312_v1",
                "terminal reccmp private runtime schema differs")
        normalized_private_runtime = {"schema": private_runtime["schema"]}
        for name in ("app_binary", "framework_dylib"):
            value = private_runtime.get(name)
            path = manifest_host_path(
                value, f"terminal private runtime {name}", host_roots
            )
            expected = require_sha(
                private_runtime.get(f"{name}_sha256"),
                f"terminal private runtime {name}_sha256",
            )
            normalized_private_runtime[name] = str(path)
            normalized_private_runtime[f"{name}_sha256"] = expected
        stdlib = private_runtime.get("stdlib")
        require(isinstance(stdlib, dict),
                "terminal private runtime stdlib must be an object")
        exact_audit_keys(
            stdlib,
            {"path", "entry_count", "max_depth", "membership_sha256",
             "content_sha256"},
            "terminal private runtime stdlib",
        )
        stdlib_path = manifest_host_path(
            stdlib.get("path"), "terminal private runtime stdlib.path",
            host_roots,
        )
        stdlib_pin = {
            "path": str(stdlib_path),
            "entry_count": require_exact_int(
                stdlib.get("entry_count"), "private runtime stdlib entry_count",
                minimum=1, maximum=10000,
            ),
            "max_depth": require_exact_int(
                stdlib.get("max_depth"), "private runtime stdlib max_depth",
                minimum=0, maximum=32,
            ),
            "membership_sha256": require_sha(
                stdlib.get("membership_sha256"),
                "private runtime stdlib membership_sha256",
            ),
            "content_sha256": require_sha(
                stdlib.get("content_sha256"),
                "private runtime stdlib content_sha256",
            ),
        }
        normalized_private_runtime["stdlib"] = stdlib_pin
        external_dylibs = private_runtime.get("external_dylibs")
        require(isinstance(external_dylibs, list) and external_dylibs,
                "terminal private runtime dylib closure must be non-empty")
        normalized_dylibs = []
        private_names = set()
        install_names = set()
        for dylib_index, dylib in enumerate(external_dylibs):
            context = f"terminal private runtime dylib[{dylib_index}]"
            require(isinstance(dylib, dict), f"{context} must be an object")
            exact_audit_keys(
                dylib, {"path", "private_name", "sha256", "install_names"},
                context,
            )
            path = manifest_host_path(
                dylib.get("path"), f"{context}.path", host_roots
            )
            private_name = dylib.get("private_name")
            require(isinstance(private_name, str)
                    and PurePosixPath(private_name).name == private_name
                    and private_name.endswith(".dylib")
                    and private_name not in private_names,
                    f"{context} path/private name differs")
            private_names.add(private_name)
            expected = require_sha(dylib.get("sha256"), f"{context}.sha256")
            aliases = dylib.get("install_names")
            require(isinstance(aliases, list) and aliases,
                    f"{context} install_names are invalid")
            expanded_aliases = [
                manifest_host_string(
                    alias, f"{context}.install_names[{alias_index}]",
                    host_roots,
                )
                for alias_index, alias in enumerate(aliases)
            ]
            require(not (set(expanded_aliases) & install_names),
                    f"{context} install_names are invalid or duplicated")
            install_names.update(expanded_aliases)
            normalized_dylibs.append({
                "path": str(path), "private_name": private_name,
                "sha256": expected, "install_names": expanded_aliases,
            })
        normalized_private_runtime["external_dylibs"] = normalized_dylibs
        closure_roots = profile.get("closure_roots")
        require(isinstance(closure_roots, list) and closure_roots,
                "terminal reccmp closure_roots must be non-empty")
        normalized_closure_roots = []
        closure_roles = set()
        for index, item in enumerate(closure_roots):
            context = f"terminal_producers.reccmp.closure_roots[{index}]"
            require(isinstance(item, dict), f"{context} must be an object")
            exact_audit_keys(
                item,
                {"role", "path", "entry_count", "max_depth",
                 "membership_sha256", "content_sha256"},
                context,
            )
            role = item.get("role")
            path_value = item.get("path")
            require(isinstance(role, str) and TARGET_RE.fullmatch(role) is not None
                    and role not in closure_roles,
                    f"{context}.role is invalid or duplicated")
            closure_roles.add(role)
            path = manifest_host_path(
                path_value, f"{context}.path", host_roots
            )
            count = require_exact_int(
                item.get("entry_count"), f"{context}.entry_count",
                minimum=1, maximum=20000,
            )
            depth = require_exact_int(
                item.get("max_depth"), f"{context}.max_depth",
                minimum=0, maximum=32,
            )
            membership = require_sha(
                item.get("membership_sha256"), f"{context}.membership_sha256"
            )
            content = require_sha(
                item.get("content_sha256"), f"{context}.content_sha256"
            )
            normalized_closure_roots.append({
                **item, "path": str(path),
            })
        require([item["role"] for item in normalized_closure_roots]
                == ["reccmp_source", "reccmp_environment"],
                "terminal reccmp closure roles/order differs")
        argv_template = reccmp.get("argv_template")
        require(exact_json_equal(argv_template, [
                    "--paths", "<ORIGINAL>", "<IMAGE>", "<PDB>",
                    "<SOURCE_ROOT>", "--json", "<REPORT>", "--json-diet",
                    "--print-rec-addr", "--silent",
                ]), "terminal reccmp argv template differs")
        reccmp_timeout = require_exact_int(
            reccmp.get("max_child_seconds"),
            "terminal_producers.reccmp.max_child_seconds",
            minimum=1, maximum=1800,
        )
        normalized_terminal = {
            "link": {
                **link,
                "tools": normalized_link_tools,
                "library_trees": normalized_library_trees,
                "project_sdk_libraries": normalized_project_sdk_libraries,
                "imported_targets": normalized_imported_targets,
                "map_evidence": normalized_map_evidence,
                "member_evidence": normalized_member_evidence,
                "ordered_library_occurrence_count":
                    ordered_library_occurrence_count,
                "ordered_library_identity_sha256":
                    ordered_library_identity_sha256,
                "generator_standard_libraries":
                    normalized_standard_libraries,
                "verified_nonterminal_leaf_audits": normalized_leaf_audits,
                "max_child_seconds": link_timeout,
            },
            "reccmp": {
                "schema": reccmp["schema"],
                "backend": execution_backend["id"],
                "transport_schema": profile["transport_schema"],
                **normalized_reccmp_paths,
                "private_runtime": normalized_private_runtime,
                "closure_roots": normalized_closure_roots,
                "argv_template": argv_template,
                "max_child_seconds": reccmp_timeout,
            },
        }
    return {
        "manifest": manifest,
        "manifest_path": str(manifest_path.resolve()),
        "manifest_sha256": sha256_bytes(raw),
        "source_dir": str(source_dir.resolve()),
        "build_dir": str(build_root),
        "host_roots": host_roots,
        "source_overlay": source_overlay,
        "diagnostic_policy": diagnostic_policy,
        "translation_units": normalized_units,
        "target_policies": normalized_target_policies,
        "recipes": [recipe_registry[recipe_id] for recipe_id in recipe_order],
        "archives": normalized_archives,
        "images": normalized_images,
        "terminal_producers": normalized_terminal,
        "compiler_sha256": expected_compiler_sha,
        "compiler_path": (
            str(compiler_path(configured_compiler))
            if configured_compiler is not None else None
        ),
        "compiler_root": str(compiler_root) if compiler_root is not None else None,
        "python_executable": str(current_python),
        "python_sha256": expected_python_sha,
        "python_version": expected_python_version,
        "compiler_support_files": normalized_support,
        "producer_support_files": normalized_producer_support,
        "required_absent_toolchain_files": normalized_absent,
        "runtime_executables": normalized_runtimes,
        "sealed_include_trees": normalized_include_trees,
        "runtime_closure": normalized_runtime_closure,
        "transport": normalized_transport,
        "toolchain_transport": {
            "backend": execution_backend["id"],
            "schema": toolchain_profile["transport_schema"],
        },
        "execution_backend": execution_backend,
        "toolchain_fingerprint": toolchain_fingerprint,
        "framework_tool_sha256": sha256_file(Path(__file__).resolve()),
        "backend_tool_path": str(Path(execution_backend_module.__file__).resolve()),
        "backend_tool_sha256": sha256_file(
            Path(execution_backend_module.__file__).resolve()
        ),
        "entropy_tool_sha256": sha256_file(Path(entropy_generator.__file__).resolve()),
        "child_environment": CHILD_ENVIRONMENT_POLICY,
        "max_child_seconds": timeout,
    }


def _tree_pin(snapshot: dict) -> dict:
    return {
        key: snapshot[key]
        for key in (
            "root", "entry_count", "max_depth",
            "membership_sha256", "content_sha256",
        )
    }


def _argument_text(value: str) -> str:
    # The OS has already removed shell quoting.  Literal quote bytes here are
    # compiler input, not syntax, and must never be normalized into an
    # apparently policy-compatible token.
    return value


def raw_argument_token_errors(arguments: list[str]) -> list[str]:
    errors = []
    for index, value in enumerate(arguments):
        if not isinstance(value, str) or not value or "\0" in value:
            errors.append(f"compiler argv token {index} is empty or invalid")
            continue
        if '"' in value or "'" in value:
            errors.append(
                f"compiler argv token {index} contains literal wrapping/escape quotes"
            )
    return errors


ADMITTED_NO_OPERAND_OPTIONS = {
    "/nologo", "-nologo", "/W3", "-W3", "/WX", "-WX",
    "/GX", "-GX", "/Zi", "-Zi", "/O1", "-O1", "/O2", "-O2",
    "/Od", "-Od", "/Ox", "-Ox", "/Ob0", "-Ob0", "/Ob1", "-Ob1",
    "/Ob2", "-Ob2", "/Oy", "-Oy", "/Oy-", "-Oy-",
    "/Gm", "-Gm", "/Gm-", "-Gm-", "/GR", "-GR", "/GR-", "-GR-",
    "/c", "-c", "/TC", "-TC", "/TP", "-TP",
    "/MD", "-MD", "/MDd", "-MDd", "/MT", "-MT", "/MTd", "-MTd",
}


def _admitted_warning_option(token: str) -> bool:
    return re.fullmatch(r"[/-](?:W[0-4]|WX|w[devo]?[0-9]+)", token) is not None


def lex_compile_arguments(arguments: list[str]) -> dict:
    """Classify every token before the attested final source by role.

    Only `/D`, `/U`, and `/I` intentionally admit a separate operand.  The
    output and force-include options are collected even in their forbidden
    separated form so pre-gate cleanup can use the same lexer as semantic
    validation.  An unknown option or any earlier positional token is fatal.
    """
    valued: dict[str, list[tuple[int, str, bool]]] = {
        "Fo": [], "Fd": [], "FI": [], "D": [], "U": [], "I": [],
    }
    role_operands = []
    compile_only = []
    compile_only_indices = []
    debug_format = []
    language_modes = []
    roles = [{"index": 0, "role": "compiler", "token": arguments[0]}] if arguments else []
    errors = []
    errors.extend(raw_argument_token_errors(arguments))
    if len(arguments) < 2 or not _argument_text(arguments[-1]):
        errors.append("compiler command has no final positional source")
        final_source = ""
        limit = len(arguments)
    else:
        final_source = _argument_text(arguments[-1])
        limit = len(arguments) - 1

    index = 1
    while index < limit:
        token = _argument_text(arguments[index])
        matched = False
        for option in ("FI", "Fd", "Fo"):
            for sigil in ("/", "-"):
                prefix = sigil + option
                if token == prefix:
                    if index + 1 < limit and _argument_text(arguments[index + 1]):
                        value = _argument_text(arguments[index + 1])
                        valued[option].append((index, value, True))
                        role_operands.append((option, value))
                        roles.append({
                            "index": index, "role": option, "token": token,
                            "value": value, "separate": True,
                        })
                        errors.append(
                            f"/{option} value must be attached to its exact option token"
                        )
                        index += 2
                    else:
                        errors.append(f"missing value after {token}")
                        index += 1
                    matched = True
                    break
                if token.startswith(prefix):
                    value = token[len(prefix):]
                    if value:
                        valued[option].append((index, value, False))
                        role_operands.append((option, value))
                        roles.append({
                            "index": index, "role": option, "token": token,
                            "value": value, "separate": False,
                        })
                    else:
                        errors.append(f"missing value after {prefix}")
                    index += 1
                    matched = True
                    break
            if matched:
                break
        if matched:
            continue

        for option in ("D", "U", "I"):
            for sigil in ("/", "-"):
                prefix = sigil + option
                if token == prefix:
                    if index + 1 < limit and _argument_text(arguments[index + 1]):
                        value = _argument_text(arguments[index + 1])
                        valued[option].append((index, value, True))
                        role_operands.append((option, value))
                        roles.append({
                            "index": index, "role": option, "token": token,
                            "value": value, "separate": True,
                        })
                        index += 2
                    else:
                        errors.append(f"missing value after {token}")
                        index += 1
                    matched = True
                    break
                if token.startswith(prefix):
                    value = token[len(prefix):]
                    if value:
                        valued[option].append((index, value, False))
                        role_operands.append((option, value))
                        roles.append({
                            "index": index, "role": option, "token": token,
                            "value": value, "separate": False,
                        })
                    else:
                        errors.append(f"missing value after {prefix}")
                    index += 1
                    matched = True
                    break
            if matched:
                break
        if matched:
            continue

        if token in ADMITTED_NO_OPERAND_OPTIONS or _admitted_warning_option(token):
            roles.append({"index": index, "role": "flag", "token": token})
            if token in ("/c", "-c"):
                compile_only.append(token)
                compile_only_indices.append(index)
            elif token in ("/Zi", "-Zi"):
                debug_format.append(token)
            elif token in ("/TC", "-TC"):
                language_modes.append("C")
            elif token in ("/TP", "-TP"):
                language_modes.append("CXX")
            index += 1
            continue

        folded = token.casefold()
        if folded in ("/c", "-c"):
            errors.append("compile-only mode must use exact lowercase /c or -c")
        elif folded in ("/zi", "-zi"):
            errors.append("debug format must use exact /Zi or -Zi")
        elif any(
            folded.startswith((sigil + option).casefold())
            for option in ("FI", "Fd", "Fo") for sigil in ("/", "-")
        ):
            errors.append(f"compiler option collides with exact output grammar: {token}")
        elif folded.startswith(("/y", "-y")):
            errors.append(f"the complete /Y compiler state family is forbidden: {token}")
        elif re.match(r"^[/-]b(?:$|1|2|x)", token, re.IGNORECASE):
            errors.append("compiler component/pass override options are forbidden")
        elif folded in FORBIDDEN_CONVENIENCE_OPTIONS:
            errors.append(f"preprocess compiler convenience mode is forbidden: {token}")
        elif folded in ("/link", "-link") or folded.startswith(("/link:", "-link:")):
            errors.append("compiler link-tail mode is forbidden")
        elif folded.startswith((
            "/fi", "-fi", "/fr", "-fr", "/fp", "-fp",
            "/fc", "-fc", "/fs", "-fs", "/fu", "-fu", "/fx", "-fx",
            "/fe", "-fe", "/fm", "-fm", "/fa", "-fa",
            "/tc", "-tc", "/tp", "-tp", "/ld", "-ld",
            "/zs", "-zs", "/gl", "-gl", "/z7", "-z7",
            "/ai", "-ai", "/doc", "-doc", "/analyze", "-analyze",
            "/ifc", "-ifc", "/interface", "-interface",
            "/internalpartition", "-internalpartition",
            "/exportheader", "-exportheader", "/headerunit", "-headerunit",
            "/reference", "-reference", "/sourcedependencies", "-sourcedependencies",
            "/scandependencies", "-scandependencies", "/clr", "-clr",
            "/zw", "-zw",
        )):
            errors.append(f"unsupported compiler input/output/link mode: {token}")
        elif token.startswith(("/", "-")):
            errors.append(f"unsupported compiler option: {token}")
        else:
            errors.append(f"extra positional compiler input before final source: {token}")
        index += 1

    if len(valued["Fo"]) != 1:
        errors.append(f"expected one exact /Fo, found {len(valued['Fo'])}")
    if len(valued["Fd"]) != 1:
        errors.append(f"expected one exact /Fd, found {len(valued['Fd'])}")
    if len(compile_only) != 1:
        errors.append(f"expected one exact /c or -c, found {len(compile_only)}")
    if len(debug_format) != 1:
        errors.append(f"expected one exact /Zi or -Zi, found {len(debug_format)}")
    if len(language_modes) > 1:
        errors.append(
            f"expected at most one exact /TC or /TP, found {len(language_modes)}"
        )
    if (len(valued["Fo"]) == 1 and len(valued["Fd"]) == 1
            and len(compile_only_indices) == 1):
        if (
            valued["Fo"][0][0] != len(arguments) - 4
            or valued["Fo"][0][2]
            or valued["Fd"][0][0] != len(arguments) - 3
            or valued["Fd"][0][2]
            or compile_only_indices[0] != len(arguments) - 2
        ):
            errors.append(
                "compiler command must end with attached /Fo, attached /Fd, "
                "exact -c, and the configured source"
            )
    return {
        "valued": valued,
        "role_operands": role_operands,
        "compile_only": compile_only,
        "compile_only_indices": compile_only_indices,
        "debug_format": debug_format,
        "language_modes": language_modes,
        "roles": [
            *roles,
            ({"index": len(arguments) - 1, "role": "source", "token": final_source}
             if final_source else {}),
        ] if final_source else roles,
        "source_token": final_source,
        "errors": errors,
    }


def validate_compile_arguments(arguments: list[str]) -> dict:
    """Enforce the closed, case-aware VC4.2 compiler argv grammar."""
    parsed = lex_compile_arguments(arguments)
    require(not parsed["errors"], "; ".join(parsed["errors"]))
    valued = parsed["valued"]
    return {
        "Fo": valued["Fo"][0],
        "Fd": valued["Fd"][0],
        "force_includes": valued["FI"],
        "definitions": valued["D"],
        "undefinitions": valued["U"],
        "include_paths": valued["I"],
        "role_operands": parsed["role_operands"],
        "source_token": parsed["source_token"],
        "compile_only": parsed["compile_only"][0],
        "debug_format": parsed["debug_format"][0],
        "language_mode": (
            parsed["language_modes"][0] if parsed["language_modes"] else None
        ),
        "roles": parsed["roles"],
    }


def coff_unpack(format_string: str, data: bytes, offset: int, context: str) -> tuple:
    size = struct.calcsize(format_string)
    require(0 <= offset <= len(data) - size, f"{context} is outside the COFF file")
    return struct.unpack_from(format_string, data, offset)


class CoffObject:
    """Strict reader for the classic i386 COFF emitted by VC4.2."""

    def __init__(self, data: bytes):
        self.data = data
        require(len(data) >= 20, "COFF header is truncated")
        (
            self.machine,
            self.section_count,
            self.timestamp,
            self.symbol_offset,
            self.symbol_count,
            optional_size,
            self.characteristics,
        ) = coff_unpack("<HHIIIHH", data, 0, "COFF header")
        require(self.machine == 0x14C, "only i386 COFF objects are supported")
        require(optional_size == 0, "COFF optional headers are unsupported")
        require(0 < self.section_count < 0x10000, "COFF section count is invalid")
        require(self.symbol_count > 0, "COFF object has no symbol table")
        self.string_offset = self.symbol_offset + self.symbol_count * 18
        string_size, = coff_unpack("<I", data, self.string_offset, "COFF string table")
        require(string_size >= 4 and self.string_offset <= len(data) - string_size,
                "COFF string table is invalid")
        self.string_end = self.string_offset + string_size
        require(self.string_end == len(data), "bytes after the COFF string table are unsupported")

        table_end = 20 + self.section_count * 40
        require(table_end <= len(data), "COFF section table is truncated")
        self.sections = []
        for index in range(self.section_count):
            header_offset = 20 + index * 40
            raw_name = data[header_offset : header_offset + 8]
            name = self._section_name(raw_name)
            (
                _, _, raw_size, raw_offset, relocation_offset, line_offset,
                relocation_count, line_count, characteristics,
            ) = coff_unpack("<IIIIIIHHI", data, header_offset + 8,
                            f"section {index + 1} header")
            if raw_size and not (characteristics & 0x00000080):
                require(raw_offset >= table_end and raw_offset <= len(data) - raw_size,
                        f"section {index + 1} raw data is invalid")
            elif raw_size:
                # IMAGE_SCN_CNT_UNINITIALIZED_DATA (.bss): sized but with no
                # raw bytes on disk.
                require(raw_offset == 0,
                        f"section {index + 1} uninitialized raw pointer is invalid")
            else:
                require(raw_offset == 0 or raw_offset >= table_end,
                        f"section {index + 1} empty raw pointer is invalid")
            if relocation_count:
                require(relocation_offset >= table_end
                        and relocation_offset <= len(data) - relocation_count * 10,
                        f"section {index + 1} relocation table is invalid")
            if line_count:
                require(line_offset >= table_end
                        and line_offset <= len(data) - line_count * 6,
                        f"section {index + 1} line table is invalid")
            self.sections.append(
                {
                    "number": index + 1,
                    "header_offset": header_offset,
                    "name": name,
                    "raw_size": raw_size,
                    "raw_offset": raw_offset,
                    "relocation_offset": relocation_offset,
                    "relocation_count": relocation_count,
                    "line_offset": line_offset,
                    "line_count": line_count,
                    "characteristics": characteristics,
                }
            )

        require(self.symbol_offset >= table_end
                and self.symbol_offset <= len(data) - self.symbol_count * 18,
                "COFF symbol table is invalid")
        self.symbols = {}
        symbol_index = 0
        while symbol_index < self.symbol_count:
            offset = self.symbol_offset + symbol_index * 18
            name = self._symbol_name(data[offset : offset + 8])
            value, section, symbol_type, storage, auxiliary_count = coff_unpack(
                "<IhHBB", data, offset + 8, f"symbol {symbol_index}"
            )
            require(symbol_index + auxiliary_count < self.symbol_count,
                    f"symbol {symbol_index} auxiliary records are truncated")
            self.symbols[symbol_index] = {
                "index": symbol_index,
                "name": name,
                "value": value,
                "section": section,
                "type": symbol_type,
                "storage": storage,
                "aux_count": auxiliary_count,
            }
            symbol_index += 1 + auxiliary_count

    def _string(self, relative: int, context: str) -> str:
        require(4 <= relative < self.string_end - self.string_offset,
                f"{context} string offset is invalid")
        absolute = self.string_offset + relative
        end = self.data.find(b"\0", absolute, self.string_end)
        require(end >= 0, f"{context} is not NUL-terminated")
        return self.data[absolute:end].decode("ascii", "strict")

    def _section_name(self, raw: bytes) -> str:
        if raw.startswith(b"/"):
            digits = raw[1:].rstrip(b"\0")
            require(digits.isdigit(), "long COFF section name is invalid")
            return self._string(int(digits), "section name")
        return raw.rstrip(b"\0").decode("ascii", "strict")

    def _symbol_name(self, raw: bytes) -> str:
        if raw[:4] == b"\0\0\0\0":
            relative, = coff_unpack("<I", raw, 4, "long symbol name")
            return self._string(relative, "symbol name")
        return raw.rstrip(b"\0").decode("ascii", "strict")

    def function_section(self, mangled: str) -> dict:
        matches = [
            symbol
            for symbol in self.symbols.values()
            if symbol["name"] == mangled
            and symbol["section"] > 0
            and symbol["value"] == 0
            and symbol["type"] == 0x20
            and symbol["storage"] in (2, 3)
        ]
        require(len(matches) == 1,
                f"expected one definition of {mangled!r}, found {len(matches)}")
        section = self.sections[matches[0]["section"] - 1]
        require(section["name"].startswith(".text"),
                f"{mangled!r} is not in a text section")
        require(section["characteristics"] & 0x1000,
                f"{mangled!r} is not in a COMDAT section")
        return section


def coff_body(coff: CoffObject, section: dict) -> bytes:
    if not section["raw_size"]:
        return b""
    if section["characteristics"] & 0x00000080:
        # IMAGE_SCN_CNT_UNINITIALIZED_DATA (.bss): sized, no raw payload.
        return b""
    start = section["raw_offset"]
    return coff.data[start : start + section["raw_size"]]


def raw_coff_directive(data: bytes, context: str) -> bytes | None:
    """Return the exact classic-COFF `.drectve` bytes, if present."""
    if len(data) < 20:
        return None
    machine, section_count = struct.unpack_from("<HH", data, 0)
    if machine != 0x14C:
        return None
    require(0 < section_count < 0x10000
            and 20 + section_count * 40 <= len(data),
            f"{context} COFF section table is invalid")
    directives = []
    for index in range(section_count):
        offset = 20 + index * 40
        raw_name = data[offset:offset + 8]
        name = raw_name.rstrip(b"\0")
        if name != b".drectve":
            continue
        raw_size, raw_offset = struct.unpack_from("<II", data, offset + 16)
        require(raw_size > 0 and raw_offset <= len(data) - raw_size,
                f"{context} .drectve body is invalid")
        directives.append(data[raw_offset:raw_offset + raw_size])
    require(len(directives) <= 1,
            f"{context} contains duplicate .drectve sections")
    return directives[0] if directives else None


def validate_first_party_object_directive(data: bytes, context: str) -> bytes:
    raw = raw_coff_directive(data, context)
    require(raw is not None and raw in FIRST_PARTY_DIRECTIVE_PATTERNS,
            f"{context} raw .drectve bytes/order are not allowlisted")
    # The raw-pattern gate is authoritative.  Token validation makes the
    # finite implicit LINK surface explicit and rejects malformed whitespace.
    tokens = raw.decode("ascii", "strict").split()
    require(tokens and raw == (" ".join(tokens) + " ").encode("ascii"),
            f"{context} .drectve spacing differs")
    allowed_prefixes = ("-defaultlib:", "-export:", "/include:")
    require(all(token.startswith(allowed_prefixes) for token in tokens),
            f"{context} .drectve contains an unsupported option")
    return raw


def coff_table(coff: CoffObject, section: dict, kind: str) -> bytes:
    if kind == "relocations":
        start = section["relocation_offset"]
        size = section["relocation_count"] * 10
    elif kind == "lines":
        start = section["line_offset"]
        size = section["line_count"] * 6
    else:
        raise ByteIdentityError(f"unknown COFF table kind: {kind}")
    return coff.data[start : start + size] if size else b""


def coff_auxiliary(coff: CoffObject, symbol_index: int, symbol: dict) -> bytes:
    require(symbol["aux_count"] >= 1,
            f"symbol {symbol['name']!r} has no auxiliary record")
    offset = coff.symbol_offset + (symbol_index + 1) * 18
    return coff.data[offset : offset + 18]


def unique_symbol(coff: CoffObject, predicate, description: str) -> tuple[int, dict]:
    matches = [
        (index, symbol)
        for index, symbol in coff.symbols.items()
        if predicate(symbol)
    ]
    require(len(matches) == 1, f"expected one {description}, found {len(matches)}")
    return matches[0]


def function_symbol(coff: CoffObject, mangled: str, section_number: int) -> tuple[int, dict]:
    return unique_symbol(
        coff,
        lambda symbol: (
            symbol["name"] == mangled
            and symbol["section"] == section_number
            and symbol["value"] == 0
            and symbol["type"] == 0x20
            and symbol["storage"] in (2, 3)
        ),
        f"function symbol {mangled!r}",
    )


def section_symbol(coff: CoffObject, section: dict) -> tuple[int, dict]:
    return unique_symbol(
        coff,
        lambda symbol: (
            symbol["name"] == section["name"]
            and symbol["section"] == section["number"]
            and symbol["storage"] == 3
            and symbol["aux_count"] >= 1
        ),
        f"section-definition symbol for section {section['number']}",
    )


def marker_symbol(coff: CoffObject, name: str, section_number: int) -> tuple[int, dict]:
    return unique_symbol(
        coff,
        lambda symbol: (
            symbol["name"] == name
            and symbol["section"] == section_number
            and symbol["storage"] == 101
            and symbol["aux_count"] >= 1
        ),
        f"{name} symbol for section {section_number}",
    )


def section_definitions(coff: CoffObject) -> dict[int, dict]:
    result = {}
    for index, symbol in coff.symbols.items():
        if not (
            0 < symbol["section"] <= len(coff.sections)
            and symbol["storage"] == 3
            and symbol["aux_count"] >= 1
        ):
            continue
        section = coff.sections[symbol["section"] - 1]
        if symbol["name"] != section["name"]:
            continue
        auxiliary = coff_auxiliary(coff, index, symbol)
        associated = (
            int.from_bytes(auxiliary[12:14], "little")
            | (int.from_bytes(auxiliary[16:18], "little") << 16)
        )
        result[section["number"]] = {
            "symbol_index": index,
            "raw": auxiliary,
            "length": int.from_bytes(auxiliary[0:4], "little"),
            "relocations": int.from_bytes(auxiliary[4:6], "little"),
            "lines": int.from_bytes(auxiliary[6:8], "little"),
            "checksum": int.from_bytes(auxiliary[8:12], "little"),
            "associated": associated,
            "selection": auxiliary[14],
        }
    return result


def associated_sections(
    coff: CoffObject, definitions: dict[int, dict], parent: int
) -> tuple[tuple[int, str], ...]:
    return tuple(
        (section["number"], section["name"])
        for section in coff.sections
        if definitions.get(section["number"], {}).get("selection") == 5
        and definitions[section["number"]]["associated"] == parent
    )


def function_multiset(coff: CoffObject) -> Counter:
    return Counter(
        symbol["name"]
        for symbol in coff.symbols.values()
        if symbol["type"] == 0x20
        and symbol["section"] > 0
        and symbol["value"] == 0
        and symbol["storage"] in (2, 3)
        and coff.sections[symbol["section"] - 1]["name"].startswith(".text")
        and coff.sections[symbol["section"] - 1]["raw_size"] > 0
    )


RELOCATION_WIDTHS = {
    0x0006: 4,  # IMAGE_REL_I386_DIR32
    0x0007: 4,  # IMAGE_REL_I386_DIR32NB
    0x000A: 2,  # IMAGE_REL_I386_SECTION
    0x000B: 4,  # IMAGE_REL_I386_SECREL
    0x0014: 4,  # IMAGE_REL_I386_REL32
}


def detailed_relocations(coff: CoffObject, section: dict) -> list[dict]:
    result = []
    for ordinal in range(section["relocation_count"]):
        offset = section["relocation_offset"] + ordinal * 10
        virtual_address, symbol_index, relocation_type = coff_unpack(
            "<IIH", coff.data, offset, f"section {section['number']} relocation {ordinal}"
        )
        require(symbol_index in coff.symbols,
                f"section {section['number']} relocation {ordinal} references an auxiliary symbol")
        width = RELOCATION_WIDTHS.get(relocation_type)
        require(width is not None,
                f"unsupported i386 relocation type 0x{relocation_type:04x}")
        require(virtual_address <= section["raw_size"] - width,
                f"section {section['number']} relocation {ordinal} operand is outside raw data")
        addend = int.from_bytes(
            coff.data[
                section["raw_offset"] + virtual_address:
                section["raw_offset"] + virtual_address + width
            ],
            "little",
        )
        target = coff.symbols[symbol_index]
        result.append(
            {
                "ordinal": ordinal,
                "offset": virtual_address,
                "symbol_index": symbol_index,
                "type": relocation_type,
                "width": width,
                "addend": addend,
                "target": target["name"],
                "target_section": target["section"],
                "target_value": target["value"],
                "target_type": target["type"],
                "target_storage": target["storage"],
            }
        )
    return result


def local_symbol_kind(name: str) -> str | None:
    if len(name) > 2 and name[0] == "$" and name[1] in "LT" and name[2:].isdigit():
        return name[1]
    if name.startswith("$done$") and name[6:].isdigit():
        return "done"
    return None


def relocation_compatibility(
    seed_rows: list[dict], donor_rows: list[dict], seed_primary: int, donor_primary: int
) -> dict | None:
    """Pair primary relocations by semantic target/type/addend, not file offset."""
    if len(seed_rows) != len(donor_rows):
        return None
    local_updates = {}
    pairs = []
    for seed, donor in zip(seed_rows, donor_rows):
        if not (
            seed["type"] == donor["type"]
            and seed["width"] == donor["width"]
            and seed["addend"] == donor["addend"]
            and seed["target_type"] == donor["target_type"]
            and seed["target_storage"] == donor["target_storage"]
        ):
            return None
        seed_internal = seed["target_section"] == seed_primary
        donor_internal = donor["target_section"] == donor_primary
        if seed_internal != donor_internal:
            return None
        seed_kind = local_symbol_kind(seed["target"])
        donor_kind = local_symbol_kind(donor["target"])
        if seed_kind or donor_kind:
            if not (seed_internal and donor_internal and seed_kind == donor_kind):
                return None
            previous = local_updates.setdefault(seed["symbol_index"], donor["target_value"])
            if previous != donor["target_value"]:
                return None
        elif not (
            seed["target"] == donor["target"]
            and (
                (seed_internal and seed["target_value"] == donor["target_value"])
                or (
                    not seed_internal
                    and seed["target_section"] == donor["target_section"]
                    and seed["target_value"] == donor["target_value"]
                )
            )
        ):
            return None
        pairs.append(
            {
                "ordinal": seed["ordinal"],
                "seed_offset": seed["offset"],
                "donor_offset": donor["offset"],
                "type": donor["type"],
                "addend": donor["addend"],
                "seed_target": seed["target"],
                "donor_target": donor["target"],
            }
        )
    return {"pairs": pairs, "local_updates": local_updates}


def linker_payload_multiset(coff: CoffObject) -> Counter:
    """Fingerprint every non-code, non-CodeView linker contribution.

    This intentionally includes `.drectve`, `.xdata`, import/CRT/tls families,
    and unknown section names.  A declaration shape is not allowed to create
    or perturb any such payload even though the final composition retains the
    seed copy. Raw relocation-table bytes are deliberately excluded because
    their symbol-index field is object bookkeeping; the ordered resolved tuple
    below retains offset, type, addend, target identity, section, value, type,
    and storage while the section-body digest retains the relocated operands.
    """
    result = Counter()
    for section in coff.sections:
        if section["name"].startswith(".text") or section["name"].startswith(".debug"):
            continue
        relocations = tuple(
            (
                item["offset"], item["type"], item["addend"],
                local_symbol_kind(item["target"]) or item["target"],
                item["target_section"], item["target_value"],
                item["target_type"], item["target_storage"],
            )
            for item in detailed_relocations(coff, section)
        )
        result[
            (
                section["name"], section["raw_size"], section["characteristics"],
                sha256_bytes(coff_body(coff, section)), relocations,
            )
        ] += 1
    return result


def declaration_identifiers(header: bytes) -> set[str]:
    text = header.decode("ascii", "strict")
    require("Generated declaration-only entropy shape. Emits no code or data." in text,
            "generated declaration shape marker is absent")
    identifiers = set(re.findall(r"\b(?:Class|Function)[A-Za-z]+\b", text))
    require(identifiers, "generated declaration shape has no identifiers")
    return identifiers


def verify_non_emitting_donor(
    seed: CoffObject, donor: CoffObject, identifiers: set[str]
) -> dict:
    require(function_multiset(seed) == function_multiset(donor),
            "declaration shape changed the complete function multiset")
    require(len(seed.sections) == len(donor.sections),
            "declaration shape changed the section count")
    require(
        all(
            left["name"] == right["name"]
            and left["characteristics"] == right["characteristics"]
            for left, right in zip(seed.sections, donor.sections)
        ),
        "declaration shape changed section order or characteristics",
    )
    leaked_symbols = sorted(
        symbol["name"]
        for symbol in donor.symbols.values()
        if any(identifier in symbol["name"] for identifier in identifiers)
    )
    require(not leaked_symbols,
            f"declaration shape emitted COFF symbols: {leaked_symbols[:5]}")
    require(linker_payload_multiset(seed) == linker_payload_multiset(donor),
            "declaration shape added or altered non-code/directive/import/CRT linker payload")

    # VC4.2 can place CodeView type records in an ordinary `.debug$S` stream
    # (not only `.debug$T`).  Such records are compiler metadata, not linker
    # payload, and none of them is copied into the seed-based composition.
    debug_type_ranges = [
        (section["raw_offset"], section["raw_offset"] + section["raw_size"])
        for section in donor.sections
        if section["name"] in (".debug$S", ".debug$T") and section["raw_size"]
    ]
    for identifier in identifiers:
        needle = identifier.encode("ascii")
        start = 0
        while True:
            occurrence = donor.data.find(needle, start)
            if occurrence < 0:
                break
            require(any(left <= occurrence < right for left, right in debug_type_ranges),
                    f"declaration identifier escaped CodeView types: {identifier}")
            start = occurrence + 1
    return {
        "function_count": sum(function_multiset(seed).values()),
        "section_count": len(seed.sections),
        "defined_or_undefined_shape_symbols": [],
        "noncode_directive_import_crt_payload_identical": True,
    }


def normalized_donor_lines(
    seed: CoffObject,
    donor: CoffObject,
    seed_section: dict,
    donor_section: dict,
    seed_function_index: int,
    donor_function_index: int,
) -> bytes:
    require(seed_section["line_count"] > 0 and donor_section["line_count"] > 0,
            "FPO composer requires COFF line tables")
    seed_lines = coff_table(seed, seed_section, "lines")
    donor_lines = bytearray(coff_table(donor, donor_section, "lines"))
    require(struct.unpack_from("<IH", seed_lines, 0) == (seed_function_index, 0),
            "seed COFF line sentinel is invalid")
    require(struct.unpack_from("<IH", donor_lines, 0) == (donor_function_index, 0),
            "donor COFF line sentinel is invalid")
    struct.pack_into("<I", donor_lines, 0, seed_function_index)
    previous = -1
    for index in range(1, donor_section["line_count"]):
        offset, line = struct.unpack_from("<IH", donor_lines, index * 6)
        require(line != 0 and previous <= offset < donor_section["raw_size"],
                f"donor COFF line row {index} is outside or nonmonotonic")
        previous = offset
    return bytes(donor_lines)


def apply_replacements(data: bytes, replacements: list[tuple[int, int, bytes]]) -> bytes:
    ordered = sorted(replacements, key=lambda item: item[0])
    cursor = 0
    chunks = []
    for start, end, replacement in ordered:
        require(cursor <= start <= end <= len(data), "COFF replacement ranges overlap")
        chunks.extend((data[cursor:start], replacement))
        cursor = end
    chunks.append(data[cursor:])
    return b"".join(chunks)


def shifted_pointer(pointer: int, replacements: list[tuple[int, int, bytes]]) -> int:
    if pointer == 0:
        return 0
    delta = 0
    for start, end, replacement in sorted(replacements, key=lambda item: item[0]):
        if pointer < start:
            break
        if pointer == start:
            return start + delta
        require(pointer >= end, "COFF pointer falls inside a replaced range")
        delta += len(replacement) - (end - start)
    return pointer + delta


FPO_RECORD_KEYS = {
    "ulOffStart", "cbProcSize", "cdwLocals", "cdwParams", "cbProlog",
    "cbRegs", "fHasSEH", "fUseBP", "reserved", "cbFrame", "raw_sha256",
}


def parse_fpo_data(raw: bytes, *, expected_proc_size: int | None = None) -> dict:
    """Decode and structurally validate one classic 16-byte FPO_DATA row."""
    require(isinstance(raw, bytes) and len(raw) == 16,
            "associated FPO record is not exactly 16 bytes")
    ul_off_start, cb_proc_size, cdw_locals, cdw_params = struct.unpack_from(
        "<IIIH", raw, 0
    )
    cb_prolog = raw[14]
    packed = raw[15]
    result = {
        "ulOffStart": ul_off_start,
        "cbProcSize": cb_proc_size,
        "cdwLocals": cdw_locals,
        "cdwParams": cdw_params,
        "cbProlog": cb_prolog,
        "cbRegs": packed & 0x7,
        "fHasSEH": (packed >> 3) & 0x1,
        "fUseBP": (packed >> 4) & 0x1,
        "reserved": (packed >> 5) & 0x1,
        "cbFrame": (packed >> 6) & 0x3,
        "raw_sha256": sha256_bytes(raw),
    }
    require(result["ulOffStart"] == 0,
            "associative function FPO ulOffStart must be zero")
    require(result["cbProcSize"] > 0,
            "FPO cbProcSize must be positive")
    if expected_proc_size is not None:
        require(type(expected_proc_size) is int and expected_proc_size > 0
                and result["cbProcSize"] == expected_proc_size,
                "FPO cbProcSize differs from its function section")
    require(result["cbProlog"] <= result["cbProcSize"],
            "FPO cbProlog exceeds cbProcSize")
    require(result["reserved"] == 0,
            "FPO reserved bit must remain zero")
    require(result["cdwLocals"] <= 0x3FFFFFFF,
            "FPO local DWORD count overflows its byte range")
    require(result["cdwParams"] <= 0x7FFF,
            "FPO parameter WORD count overflows its byte range")
    return result


def validate_manifest_fpo_record(value: object, context: str) -> dict:
    require(isinstance(value, dict), f"{context} must be an object")
    exact_audit_keys(value, FPO_RECORD_KEYS, context)
    integer_ranges = {
        "ulOffStart": (0, 0xFFFFFFFF),
        "cbProcSize": (1, 0xFFFFFFFF),
        "cdwLocals": (0, 0x3FFFFFFF),
        "cdwParams": (0, 0x7FFF),
        "cbProlog": (0, 0xFF),
        "cbRegs": (0, 7),
        "fHasSEH": (0, 1),
        "fUseBP": (0, 1),
        "reserved": (0, 0),
        "cbFrame": (0, 3),
    }
    normalized = {}
    for name, (minimum, maximum) in integer_ranges.items():
        item = value.get(name)
        require(type(item) is int and minimum <= item <= maximum,
                f"{context}.{name} is invalid")
        normalized[name] = item
    normalized["raw_sha256"] = require_sha(
        value.get("raw_sha256"), f"{context}.raw_sha256"
    )
    require(normalized["ulOffStart"] == 0
            and normalized["cbProlog"] <= normalized["cbProcSize"],
            f"{context} is structurally invalid")
    return normalized


def _comdat_child_closure(coff: CoffObject, primary: dict) -> tuple:
    """Return (count, sorted child section names) of a COMDAT's selection-5
    associates."""
    definitions = section_definitions(coff)
    children = tuple(sorted(
        section["name"]
        for section in coff.sections
        if definitions.get(section["number"], {}).get("selection") == 5
        and definitions[section["number"]]["associated"] == primary["number"]
    ))
    return (len(children), children)


def _comdat_child(coff: CoffObject, primary: dict, name: str) -> dict:
    definitions = section_definitions(coff)
    matches = [
        section
        for section in coff.sections
        if section["name"] == name
        and definitions.get(section["number"], {}).get("selection") == 5
        and definitions[section["number"]]["associated"] == primary["number"]
    ]
    require(len(matches) == 1, f"expected one {name} child, found {len(matches)}")
    return matches[0]


def _normalized_relocation_renames(
    seed: CoffObject, seed_section: dict,
    donor: CoffObject, donor_section: dict,
    context: str,
) -> list[tuple[int, str]]:
    """Require literal relocation equality except paired object-local $L/$T
    serial renames whose targets are structurally identical."""
    left = detailed_relocations(seed, seed_section)
    right = detailed_relocations(donor, donor_section)
    require(len(left) == len(right), f"{context}: relocation counts differ")
    renames = []
    for a, b in zip(left, right):
        require(
            (a["offset"], a["type"], a["addend"])
            == (b["offset"], b["type"], b["addend"]),
            f"{context}: relocation offset/type/addend differs",
        )
        if a["target"] == b["target"]:
            continue
        kind = local_symbol_kind(a["target"])
        require(
            kind is not None and kind == local_symbol_kind(b["target"]),
            f"{context}: non-local relocation rename "
            f"{a['target']!r} -> {b['target']!r}",
        )
        require(
            all(a["target_" + field] == b["target_" + field]
                for field in ("section", "value", "type", "storage")),
            f"{context}: renamed local relocation target structure differs",
        )
        renames.append((a["offset"], kind))
    return renames


def _coff_table_bytes(coff: CoffObject, section: dict, kind: str) -> bytes:
    if kind == "relocations":
        start = section["relocation_offset"]
        size = section["relocation_count"] * 10
    else:
        start = section["line_offset"]
        size = section["line_count"] * 6
    return coff.data[start:start + size] if size else b""


def _coff_marker(coff: CoffObject, name: str, section_number: int):
    matches = [
        (index, symbol) for index, symbol in coff.symbols.items()
        if symbol["name"] == name and symbol["section"] == section_number
        and symbol["storage"] == 101 and symbol["aux_count"] >= 1
    ]
    require(len(matches) == 1,
            f"expected one {name} marker in section {section_number}")
    return matches[0]


def _coff_section_symbol(coff: CoffObject, section: dict):
    matches = [
        (index, symbol) for index, symbol in coff.symbols.items()
        if symbol["name"] == section["name"]
        and symbol["section"] == section["number"]
        and symbol["storage"] == 3 and symbol["aux_count"] >= 1
    ]
    require(len(matches) == 1, "expected one section definition symbol")
    return matches[0]


def _pair_same_slot_relocations(seed_rows, donor_rows, seed_primary,
                                donor_primary, seed_xdata, donor_xdata,
                                mapping, context):
    """Pair ordinal relocation semantics allowing offset movement and
    consistently mapped object-local symbols inside the target closure."""
    require(len(seed_rows) == len(donor_rows),
            f"{context}: relocation counts differ")
    reverse = {right: left for left, right in mapping.items()}

    def role(section_number, primary, xdata):
        if section_number == primary:
            return "primary"
        if section_number == xdata:
            return "xdata"
        return "external"

    pairs = []
    for left, right in zip(seed_rows, donor_rows):
        require(left["type"] == right["type"]
                and left["addend"] == right["addend"],
                f"{context}: relocation type/addend differs")
        require(
            role(left["target_section"], seed_primary, seed_xdata)
            == role(right["target_section"], donor_primary, donor_xdata),
            f"{context}: relocation target role differs",
        )
        left_local = local_symbol_kind(left["target"]) is not None
        right_local = local_symbol_kind(right["target"]) is not None
        if left_local or right_local:
            require(
                left_local and right_local
                and left["target"][1] == right["target"][1]
                and left["target_type"] == right["target_type"]
                and left["target_storage"] == right["target_storage"],
                f"{context}: local relocation target class differs",
            )
            if role(left["target_section"], seed_primary,
                    seed_xdata) in ("primary", "xdata"):
                require(
                    mapping.setdefault(left["symbol_index"],
                                       right["symbol_index"])
                    == right["symbol_index"]
                    and reverse.setdefault(right["symbol_index"],
                                           left["symbol_index"])
                    == left["symbol_index"],
                    f"{context}: local symbol mapping is inconsistent",
                )
            else:
                # An equal-valued local in a shared external section needs
                # no remapping: the seed's own symbol already denotes the
                # same location.
                require(
                    left["target_section"] == right["target_section"]
                    and left["target_value"] == right["target_value"],
                    f"{context}: external local relocation target differs",
                )
        else:
            require(
                left["target"] == right["target"]
                and left["target_type"] == right["target_type"]
                and left["target_storage"] == right["target_storage"],
                f"{context}: relocation target differs",
            )
        pairs.append((left, right))
    return pairs


def compose_same_slot_resize(
    seed_bytes: bytes,
    donor_bytes: bytes,
    function: dict,
) -> tuple[bytes, dict]:
    """Install a donor code body of a different size that occupies the same
    16-byte linked contribution slot, repairing every dependent COFF record.

    The seed supplies the object, symbol table, CodeView types/names, xdata
    raw bytes/relocations, and every non-target section.  The donor supplies
    the compiler-generated target code, COFF line offsets, and procedure
    debug range.  Mapped object-local symbol values move to the donor's.
    """
    seed = CoffObject(seed_bytes)
    donor = CoffObject(donor_bytes)
    mangled = function["mangled"]
    sp = seed.function_section(mangled)
    dp = donor.function_section(mangled)
    require(sp["raw_size"] == function["expected_seed_length"]
            and dp["raw_size"] == function["expected_donor_length"],
            "target body lengths changed")
    require(
        ((sp["raw_size"] + 15) // 16) * 16
        == ((dp["raw_size"] + 15) // 16) * 16
        == function["expected_linked_span"],
        "target 16-byte linked contribution span changed",
    )
    require(sp["number"] == dp["number"],
            "target section seat changed")
    # A carrier-state donor owns its own global tail layout; the target
    # closure seats, function multiset, and per-relocation role/target
    # checks carry the equivalence proof.
    require(len(seed.sections) == len(donor.sections),
            "global section count differs")
    require(function_multiset(seed) == function_multiset(donor),
            "donor function set differs")
    require(
        all(sp[key] == dp[key] for key in
            ("name", "relocation_count", "line_count", "characteristics")),
        "target header shape changed",
    )
    seed_defs = section_definitions(seed)
    donor_defs = section_definitions(donor)
    require(
        seed_defs[sp["number"]]["selection"]
        == donor_defs[dp["number"]]["selection"],
        "target COMDAT selection changed",
    )
    closure = _comdat_child_closure(seed, seed_primary := sp)
    require(closure == _comdat_child_closure(donor, dp)
            and closure == (2, (".debug$S", ".xdata$x")),
            "target closure is not the EH (.debug$S/.xdata$x) pair")
    sx = _comdat_child(seed, sp, ".xdata$x")
    dx = _comdat_child(donor, dp, ".xdata$x")
    sd = _comdat_child(seed, sp, ".debug$S")
    dd = _comdat_child(donor, dp, ".debug$S")
    require(sx["number"] == dx["number"] and sd["number"] == dd["number"],
            "closure section seats changed")
    for left, right, name in ((sx, dx, "xdata"), (sd, dd, "debug$S")):
        require(
            all(left[key] == right[key] for key in
                ("name", "raw_size", "relocation_count", "line_count",
                 "characteristics")),
            f"{name} section shape changed",
        )
    require(coff_body(seed, sx) == coff_body(donor, dx),
            "runtime xdata bytes differ")

    donor_code = coff_body(donor, dp)
    require(sha256_bytes(donor_code) == function["expected_body_sha256"],
            "donor body differs from its pinned compiler output")

    spr = detailed_relocations(seed, sp)
    dpr = detailed_relocations(donor, dp)
    sxr = detailed_relocations(seed, sx)
    dxr = detailed_relocations(donor, dx)
    sdr = detailed_relocations(seed, sd)
    ddr = detailed_relocations(donor, dd)
    mapping: dict[int, int] = {}
    _pair_same_slot_relocations(spr, dpr, sp["number"], dp["number"],
                                sx["number"], dx["number"], mapping,
                                "primary")
    xdata_pairs = _pair_same_slot_relocations(
        sxr, dxr, sp["number"], dp["number"], sx["number"], dx["number"],
        mapping, "xdata")
    debug_pairs = _pair_same_slot_relocations(
        sdr, ddr, sp["number"], dp["number"], sx["number"], dx["number"],
        mapping, "debug$S")
    require(all(a["offset"] == b["offset"] for a, b in xdata_pairs),
            "xdata relocation offsets moved")
    require(all(a["offset"] == b["offset"] for a, b in debug_pairs),
            "debug$S relocation offsets moved")
    allowed_sections = {sp["number"], sx["number"], sd["number"]}
    for section in seed.sections:
        for record in (detailed_relocations(seed, section)
                       if section["relocation_count"]
                       and section["number"] not in allowed_sections else []):
            require(record["symbol_index"] not in mapping,
                    "mapped local is consumed outside the target closure")
    for seed_index, donor_index in mapping.items():
        left = seed.symbols[seed_index]
        right = donor.symbols[donor_index]
        require(
            (left["section"], left["type"], left["storage"])
            == (right["section"], right["type"], right["storage"]),
            "mapped local symbol class changed",
        )

    seed_function_index, seed_function = function_symbol(
        seed, mangled, sp["number"])
    donor_function_index, donor_function = function_symbol(
        donor, mangled, dp["number"])
    require(sp["line_count"] > 0
            and sp["line_count"] == dp["line_count"],
            "target COFF line count changed")
    seed_lines = _coff_table_bytes(seed, sp, "lines")
    donor_lines = bytearray(_coff_table_bytes(donor, dp, "lines"))
    require(
        coff_unpack("<IH", seed_lines, 0, "seed line sentinel")
        == (seed_function_index, 0)
        and coff_unpack("<IH", donor_lines, 0, "donor line sentinel")
        == (donor_function_index, 0),
        "COFF line sentinel is invalid",
    )
    donor_lines[0:4] = seed_function_index.to_bytes(4, "little")
    previous = -1
    for index in range(1, dp["line_count"]):
        offset, line = coff_unpack("<IH", bytes(donor_lines), index * 6,
                                   "donor line row")
        require(line != 0 and previous <= offset < dp["raw_size"],
                "donor COFF line row is outside/nonmonotonic")
        previous = offset
    donor_lines = bytes(donor_lines)

    seed_debug_raw = coff_body(seed, sd)
    donor_debug_raw = coff_body(donor, dd)
    require(len(seed_debug_raw) >= 28 and seed_debug_raw[2:4] == b"\x05\x02"
            and donor_debug_raw[2:4] == b"\x05\x02",
            "debug$S is not an S_*PROC32 record")
    donor_cbproc, donor_dbgstart, donor_dbgend = coff_unpack(
        "<III", donor_debug_raw, 16, "donor debug range")
    require(donor_cbproc == dp["raw_size"]
            and 0 <= donor_dbgstart <= donor_dbgend < donor_cbproc,
            "donor debug procedure range is stale")
    expected_debug_raw = bytearray(seed_debug_raw)
    expected_debug_raw[16:28] = donor_debug_raw[16:28]

    old_end = sp["raw_offset"] + sp["raw_size"]
    delta = dp["raw_size"] - sp["raw_size"]

    def shifted(pointer: int) -> int:
        return pointer + delta if pointer and pointer >= old_end else pointer

    output = bytearray(
        seed_bytes[:sp["raw_offset"]] + donor_code + seed_bytes[old_end:]
    )
    new_symbol_offset = seed.symbol_offset + delta
    output[8:12] = new_symbol_offset.to_bytes(4, "little")

    for section in seed.sections:
        header = 20 + (section["number"] - 1) * 40
        if section["number"] == sp["number"]:
            output[header + 16:header + 20] = dp["raw_size"].to_bytes(
                4, "little")
        for field, relative in (("raw_offset", 20),
                                ("relocation_offset", 24),
                                ("line_offset", 28)):
            pointer = shifted(section[field])
            if pointer != section[field]:
                output[header + relative:header + relative + 4] = (
                    pointer.to_bytes(4, "little"))

    primary_relocation_output = shifted(sp["relocation_offset"])
    for index, (left, right) in enumerate(zip(spr, dpr)):
        at = primary_relocation_output + index * 10
        output[at:at + 4] = right["offset"].to_bytes(4, "little")
        output[at + 4:at + 8] = left["symbol_index"].to_bytes(4, "little")
        output[at + 8:at + 10] = right["type"].to_bytes(2, "little")

    line_output = shifted(sp["line_offset"])
    output[line_output:line_output + len(donor_lines)] = donor_lines

    for symbol_index, item in seed.symbols.items():
        if item["type"] != 0x20 or item["aux_count"] < 1:
            continue
        auxiliary = coff_auxiliary(seed, symbol_index, item)
        line_pointer = int.from_bytes(auxiliary[8:12], "little")
        if line_pointer and line_pointer >= old_end:
            at = new_symbol_offset + (symbol_index + 1) * 18
            output[at + 8:at + 12] = (line_pointer + delta).to_bytes(
                4, "little")

    local_value_updates = 0
    for seed_index, donor_index in sorted(mapping.items()):
        value = donor.symbols[donor_index]["value"]
        if value != seed.symbols[seed_index]["value"]:
            local_value_updates += 1
        at = new_symbol_offset + seed_index * 18
        output[at + 8:at + 12] = value.to_bytes(4, "little")

    donor_function_aux = coff_auxiliary(donor, donor_function_index,
                                        donor_function)
    require(int.from_bytes(donor_function_aux[4:8], "little")
            == dp["raw_size"],
            "donor Function Definition TotalSize is stale")
    at = new_symbol_offset + (seed_function_index + 1) * 18
    output[at + 4:at + 8] = dp["raw_size"].to_bytes(4, "little")

    seed_begin_index, seed_begin = _coff_marker(seed, ".bf", sp["number"])
    donor_begin_index, donor_begin = _coff_marker(donor, ".bf", dp["number"])
    seed_begin_aux = coff_auxiliary(seed, seed_begin_index, seed_begin)
    donor_begin_aux = coff_auxiliary(donor, donor_begin_index, donor_begin)
    # Adopt only the donor's line field; the tail of the aux record holds
    # the seed's own next-.bf chain, which a cross-layout donor cannot
    # supply.
    require(seed_begin_aux[:4] == donor_begin_aux[:4]
            and seed_begin_aux[6:12] == donor_begin_aux[6:12]
            and seed_begin_aux[16:] == donor_begin_aux[16:],
            ".bf non-line metadata changed")
    at = new_symbol_offset + (seed_begin_index + 1) * 18
    output[at + 4:at + 6] = donor_begin_aux[4:6]

    seed_end_index, seed_end = _coff_marker(seed, ".ef", sp["number"])
    donor_end_index, donor_end = _coff_marker(donor, ".ef", dp["number"])
    require(donor_end["value"] == dp["raw_size"], "donor .ef value is stale")
    seed_end_aux = coff_auxiliary(seed, seed_end_index, seed_end)
    donor_end_aux = coff_auxiliary(donor, donor_end_index, donor_end)
    require(seed_end_aux[:4] == donor_end_aux[:4]
            and seed_end_aux[6:] == donor_end_aux[6:],
            ".ef non-line metadata changed")
    at = new_symbol_offset + seed_end_index * 18
    output[at + 8:at + 12] = donor_end["value"].to_bytes(4, "little")
    output[at + 18 + 4:at + 18 + 6] = donor_end_aux[4:6]

    seed_section_index, seed_section_sym = _coff_section_symbol(seed, sp)
    donor_section_index, donor_section_sym = _coff_section_symbol(donor, dp)
    at = new_symbol_offset + (seed_section_index + 1) * 18
    output[at:at + 18] = coff_auxiliary(donor, donor_section_index,
                                        donor_section_sym)

    debug_output = shifted(sd["raw_offset"])
    output[debug_output:debug_output + len(expected_debug_raw)] = (
        expected_debug_raw)
    composed = bytes(output)

    checked = CoffObject(composed)
    cp = checked.function_section(mangled)
    require(len(composed) == len(seed_bytes) + delta,
            "output file-size delta is wrong")
    require(coff_body(checked, cp) == donor_code,
            "output target body differs from donor")
    cx = _comdat_child(checked, cp, ".xdata$x")
    cd = _comdat_child(checked, cp, ".debug$S")
    require(coff_body(checked, cx) == coff_body(seed, sx),
            "output xdata differs from the seed")
    require(coff_body(checked, cd) == bytes(expected_debug_raw),
            "output debug$S policy differs")
    require(function_multiset(checked) == function_multiset(seed),
            "output function set changed")
    require(_coff_table_bytes(checked, cp, "lines") == donor_lines,
            "output line table differs from the normalized donor")
    require(_coff_table_bytes(checked, cx, "relocations")
            == _coff_table_bytes(seed, sx, "relocations"),
            "output xdata relocation records changed")
    require(_coff_table_bytes(checked, cd, "relocations")
            == _coff_table_bytes(seed, sd, "relocations"),
            "output debug$S relocation records changed")
    for before, after in zip(seed.sections, checked.sections):
        if before["number"] in allowed_sections:
            continue
        require(coff_body(seed, before) == coff_body(checked, after),
                f"non-target raw section changed: {before['number']}")
        require(_coff_table_bytes(seed, before, "relocations")
                == _coff_table_bytes(checked, after, "relocations"),
                f"non-target relocation table changed: {before['number']}")
        require(_coff_table_bytes(seed, before, "lines")
                == _coff_table_bytes(checked, after, "lines"),
                f"non-target line table changed: {before['number']}")
    return composed, {
        "mangled": mangled,
        "splice_class": "same_slot_resize",
        "section_number": cp["number"],
        "seed_length": sp["raw_size"],
        "donor_length": dp["raw_size"],
        "file_size_delta": delta,
        "linked_span": function["expected_linked_span"],
        "mapped_locals": len(mapping),
        "changed_local_values": local_value_updates,
    }


def compose_swap_comdat_group_order(
    seed_bytes: bytes,
    specification: dict,
) -> tuple[bytes, dict]:
    """Swap the link-visible order of two complete compiler-produced COMDAT
    groups (primary + associated children) inside one object, renumbering
    section ordinals and associations only.

    No raw code, relocation, xdata, data, line, or debug payload byte moves;
    every symbol keeps its exact raw contribution.  The permutation makes
    the `first` function's group precede the `second` function's group; the
    intervening contributions keep their relative order.
    """
    seed = CoffObject(seed_bytes)
    first = seed.function_section(specification["first"])
    second = seed.function_section(specification["second"])
    definitions = section_definitions(seed)

    def group(primary: dict) -> list[int]:
        children = [
            section["number"]
            for section in seed.sections
            if definitions.get(section["number"], {}).get("selection") == 5
            and definitions[section["number"]]["associated"]
            == primary["number"]
        ]
        return [primary["number"], *children]

    first_group = group(first)
    second_group = group(second)
    require(not set(first_group) & set(second_group),
            "COMDAT groups overlap")
    require(second["number"] < first["number"],
            "the requested group order already holds")
    window = sorted(set(first_group) | set(second_group))
    low, high = min(window), max(
        max(first_group), max(second_group))
    window_numbers = list(range(low, high + 1))
    rest = [number for number in window_numbers
            if number not in first_group and number not in second_group]
    new_order = first_group + second_group + rest
    require(sorted(new_order) == window_numbers,
            "group window is not a permutation")
    old_to_new = {
        old: window_numbers[index] for index, old in enumerate(new_order)
    }

    def mapped(number: int) -> int:
        return old_to_new.get(number, number)

    work = bytearray(seed_bytes)
    original_headers = {
        number: seed_bytes[20 + (number - 1) * 40:20 + number * 40]
        for number in window_numbers
    }
    for old, new in old_to_new.items():
        start = 20 + (new - 1) * 40
        work[start:start + 40] = original_headers[old]

    symbol_writes = 0
    association_writes = 0
    for index, symbol in seed.symbols.items():
        if symbol["section"] > 0 and mapped(symbol["section"]) != symbol["section"]:
            offset = seed.symbol_offset + index * 18 + 12
            work[offset:offset + 2] = mapped(symbol["section"]).to_bytes(
                2, "little", signed=True)
            symbol_writes += 1
        definition = definitions.get(symbol["section"])
        if (definition is not None
                and symbol["storage"] == 3
                and symbol["aux_count"]
                and symbol["name"]
                == seed.sections[symbol["section"] - 1]["name"]
                and definition["selection"] == 5
                and mapped(definition["associated"])
                != definition["associated"]):
            aux = seed.symbol_offset + (index + 1) * 18
            parent = mapped(definition["associated"])
            work[aux + 12:aux + 14] = (parent & 0xFFFF).to_bytes(2, "little")
            work[aux + 16:aux + 18] = (parent >> 16).to_bytes(2, "little")
            association_writes += 1

    composed = bytes(work)
    require(len(composed) == len(seed_bytes), "object size changed")
    checked = CoffObject(composed)
    checked_definitions = section_definitions(checked)
    section_fields = (
        "name", "raw_size", "raw_offset", "relocation_offset",
        "relocation_count", "line_offset", "line_count", "characteristics",
    )
    for section in seed.sections:
        peer = checked.sections[mapped(section["number"]) - 1]
        require(all(section[field] == peer[field]
                    for field in section_fields),
                f"semantic section changed: old {section['number']}")
    require(seed.symbols.keys() == checked.symbols.keys(),
            "symbol index set changed")
    for index, symbol in seed.symbols.items():
        peer = checked.symbols[index]
        require(
            all(symbol[field] == peer[field]
                for field in ("name", "value", "type", "storage",
                              "aux_count"))
            and peer["section"] == mapped(symbol["section"]),
            f"symbol identity changed at {index}",
        )
    for old_number, definition in definitions.items():
        peer = checked_definitions.get(mapped(old_number))
        require(peer is not None
                and peer["selection"] == definition["selection"]
                and peer["associated"] == mapped(definition["associated"]),
                f"section definition mapping changed: {old_number}")
    checked_first = checked.function_section(specification["first"])
    checked_second = checked.function_section(specification["second"])
    require(checked_first["number"] < checked_second["number"],
            "target group order was not swapped")
    for name in sorted({
        section["name"] for section in seed.sections
        if not section["name"].startswith(".debug$")
    }):
        before = [section["raw_offset"] for section in seed.sections
                  if section["name"] == name]
        after = [section["raw_offset"] for section in checked.sections
                 if section["name"] == name]
        if name == first["name"]:
            expected = list(before)
            left = expected.index(first["raw_offset"])
            right = expected.index(second["raw_offset"])
            require(left > right,
                    "target contributions were already ordered")
            expected[left], expected[right] = expected[right], expected[left]
            require(after == expected,
                    "more than the target contribution pair moved")
        else:
            require(after == before,
                    f"link-visible {name} contribution order changed")
    return composed, {
        "first": specification["first"],
        "second": specification["second"],
        "window": [low, high],
        "symbol_section_writes": symbol_writes,
        "association_writes": association_writes,
    }


def compose_equal_body_comdat(
    seed_bytes: bytes,
    donor_bytes: bytes,
    function: dict,
) -> tuple[bytes, dict]:
    """Copy one equal-size compiler-produced COMDAT code body from a donor
    object into the seed object, retaining every seed relocation, xdata,
    debug, and symbol byte.

    Two proved splice classes:
    - equal_body_strict: (.debug$F, .debug$S) closure, literal-equal
      relocation tuples.
    - equal_body_eh_structural_local: (.debug$S, .xdata$x) closure with
      byte-identical xdata and paired object-local $L/$T relocation renames
      resolving to structurally identical targets.
    """
    seed = CoffObject(seed_bytes)
    donor = CoffObject(donor_bytes)
    mangled = function["mangled"]
    splice_class = function["splice_class"]
    seed_primary = seed.function_section(mangled)
    donor_primary = donor.function_section(mangled)

    require(
        seed_primary["raw_size"] == donor_primary["raw_size"]
        == function["expected_body_length"],
        "target COMDAT body length changed",
    )
    for field in ("name", "characteristics"):
        require(seed_primary[field] == donor_primary[field],
                f"target section {field} differs")
    seed_definitions = section_definitions(seed)
    donor_definitions = section_definitions(donor)
    seed_definition = seed_definitions.get(seed_primary["number"])
    donor_definition = donor_definitions.get(donor_primary["number"])
    require(seed_definition is not None and donor_definition is not None,
            "target COMDAT definition record is missing")
    require(
        all(
            seed_definition[field] == donor_definition[field]
            for field in ("selection", "associated", "length", "relocations")
        ),
        "target COMDAT definition record differs",
    )

    donor_body = coff_body(donor, donor_primary)
    require(sha256_bytes(donor_body) == function["expected_body_sha256"],
            "donor body differs from its pinned compiler output")
    seed_body = coff_body(seed, seed_primary)
    changed = [
        index for index, pair in enumerate(zip(seed_body, donor_body))
        if pair[0] != pair[1]
    ]
    require(changed == function["expected_changed_offsets"],
            "seed/donor body delta changed")

    closure = _comdat_child_closure(seed, seed_primary)
    require(closure == _comdat_child_closure(donor, donor_primary),
            "target COMDAT child closure differs")

    relocation_moves = []
    if splice_class == "equal_body_eh_reloc_layout":
        # The donor reschedules instructions, moving relocated operands.
        # Pair the tables by ordinal, require identical types and
        # structurally identical targets, and record the offset moves; the
        # seed's relocation records then take the donor's operand offsets.
        left = detailed_relocations(seed, seed_primary)
        right = detailed_relocations(donor, donor_primary)
        require(len(left) == len(right),
                "reloc-layout splice: relocation counts differ")
        for a, b in zip(left, right):
            require(a["type"] == b["type"] and a["addend"] == b["addend"],
                    "reloc-layout splice: relocation type/addend differs")
            if a["target"] != b["target"]:
                kind = local_symbol_kind(a["target"])
                require(kind is not None
                        and kind == local_symbol_kind(b["target"])
                        and all(a["target_" + field] == b["target_" + field]
                                for field in ("section", "value", "type",
                                              "storage")),
                        "reloc-layout splice: non-local relocation rename")
            if a["offset"] != b["offset"]:
                relocation_moves.append([a["offset"], b["offset"]])
        require(relocation_moves == function["expected_relocation_moves"],
                "reloc-layout splice: relocation move set changed")

    if splice_class == "equal_body_strict":
        require(closure == (2, (".debug$F", ".debug$S")),
                "strict splice requires the FPO debug closure")
        renames = _normalized_relocation_renames(
            seed, seed_primary, donor, donor_primary, "code"
        )
        require(renames == [], "strict splice forbids relocation renames")
        detail = {"code_renames": []}
    else:
        require(splice_class in ("equal_body_eh_structural_local",
                                 "equal_body_eh_reloc_layout"),
                "unsupported equal-body splice class")
        fpo_closure = closure == (2, (".debug$F", ".debug$S"))
        require(
            closure == (2, (".debug$S", ".xdata$x"))
            or (fpo_closure
                and splice_class == "equal_body_eh_reloc_layout"),
            "splice closure kind is unsupported for this class",
        )
        # The xdata association model depends on a shared global section
        # layout; an FPO-closure donor from a different carrier state has
        # its own layout, and the per-relocation target checks carry the
        # equivalence proof instead.
        if not fpo_closure:
            require(
                len(seed.sections) == len(donor.sections)
                and all(
                    (a["number"], a["name"], a["characteristics"])
                    == (b["number"], b["name"], b["characteristics"])
                    for a, b in zip(seed.sections, donor.sections)
                ),
                "global section order/name/characteristics differ",
            )
        if fpo_closure:
            require(function["expected_xdata_rename_offsets"] == [],
                    "FPO-closure splice cannot declare xdata renames")
            xdata_renames = []
        else:
            seed_xdata = _comdat_child(seed, seed_primary, ".xdata$x")
            donor_xdata = _comdat_child(donor, donor_primary, ".xdata$x")
            require(
                coff_body(seed, seed_xdata) == coff_body(donor, donor_xdata),
                "EH xdata raw bytes differ")
            xdata_renames = _normalized_relocation_renames(
                seed, seed_xdata, donor, donor_xdata, "xdata"
            )
            require(
                [offset for offset, _ in xdata_renames]
                == function["expected_xdata_rename_offsets"],
                "xdata local-relocation rename set changed",
            )
        if splice_class == "equal_body_eh_structural_local":
            code_renames = _normalized_relocation_renames(
                seed, seed_primary, donor, donor_primary, "code"
            )
            require(
                [[offset, kind] for offset, kind in code_renames]
                == function["expected_code_renames"],
                "code local-relocation rename set changed",
            )
            relocation_mask = {
                record["offset"] + byte
                for record in detailed_relocations(donor, donor_primary)
                for byte in range(record["width"])
            }
            require(all(offset not in relocation_mask for offset in changed),
                    "donor changes a relocated operand")
            detail = {
                "code_renames": code_renames,
                "xdata_rename_offsets": [o for o, _ in xdata_renames],
            }
        else:
            detail = {
                "relocation_moves": relocation_moves,
                "xdata_rename_offsets": [o for o, _ in xdata_renames],
            }

    composed = bytearray(seed_bytes)
    start = seed_primary["raw_offset"]
    composed[start:start + seed_primary["raw_size"]] = donor_body
    if relocation_moves:
        donor_offsets = [
            record["offset"]
            for record in detailed_relocations(donor, donor_primary)
        ]
        for ordinal, offset in enumerate(donor_offsets):
            record_at = seed_primary["relocation_offset"] + ordinal * 10
            composed[record_at:record_at + 4] = offset.to_bytes(4, "little")
    composed = bytes(composed)

    checked = CoffObject(composed)
    checked_primary = checked.function_section(mangled)
    require(coff_body(checked, checked_primary) == donor_body,
            "composed body differs from the donor")
    checked_relocations = detailed_relocations(checked, checked_primary)
    seed_relocations = detailed_relocations(seed, seed_primary)
    if relocation_moves:
        donor_relocations = detailed_relocations(donor, donor_primary)
        require(
            [(r["offset"], r["type"], r["addend"], r["symbol_index"])
             for r in checked_relocations]
            == [(d["offset"], d["type"], d["addend"], s["symbol_index"])
                for d, s in zip(donor_relocations, seed_relocations)],
            "composed relocations differ from the donor layout",
        )
    else:
        require(checked_relocations == seed_relocations,
                "composed relocations differ from the seed")
    changed_offsets = [
        index for index, pair in enumerate(zip(seed_bytes, composed))
        if pair[0] != pair[1]
    ]
    allowed = set(range(start, start + seed_primary["raw_size"]))
    if relocation_moves:
        allowed |= {
            seed_primary["relocation_offset"] + ordinal * 10 + byte
            for ordinal in range(seed_primary["relocation_count"])
            for byte in range(4)
        }
    require(set(changed_offsets) <= allowed,
            "composition changed bytes outside the selected body")
    return composed, {
        "mangled": mangled,
        "splice_class": splice_class,
        "section_number": seed_primary["number"],
        "body_length": seed_primary["raw_size"],
        "body_changed_offsets": changed,
        **detail,
    }


def compose_equal_linked_span_fpo(
    seed_bytes: bytes,
    donor_bytes: bytes,
    function: dict,
    shape_identifiers: set[str],
) -> tuple[bytes, dict]:
    """Compose one compiler-produced FPO COMDAT and prove its full closure."""
    seed = CoffObject(seed_bytes)
    donor = CoffObject(donor_bytes)
    mangled = function["mangled"]
    seed_primary = seed.function_section(mangled)
    donor_primary = donor.function_section(mangled)
    require(
        seed_primary["number"] == donor_primary["number"]
        == function["expected_section_number"],
        "target COMDAT section seat changed",
    )
    require(seed_primary["raw_size"] == function["expected_seed_length"],
            "seed target length changed")
    require(donor_primary["raw_size"] == function["expected_donor_length"],
            "donor target length changed")
    require(
        ((seed_primary["raw_size"] + 15) // 16) * 16
        == function["expected_linked_span"]
        == ((donor_primary["raw_size"] + 15) // 16) * 16,
        "target 16-byte linked contribution span changed",
    )
    require(
        seed_primary["name"] == donor_primary["name"]
        and seed_primary["characteristics"] == donor_primary["characteristics"]
        == function["expected_characteristics"],
        "target section kind or characteristics changed",
    )
    require((seed_primary["characteristics"] & 0x00F00000) == 0x00500000,
            "target COMDAT does not declare 16-byte section alignment")
    require(
        seed_primary["relocation_count"] == donor_primary["relocation_count"]
        == function["expected_relocation_count"],
        "target relocation count changed",
    )
    require(seed_primary["line_count"] == function["expected_seed_line_count"]
            and donor_primary["line_count"] == function["expected_donor_line_count"],
            "target COFF line count changed")

    seed_definitions = section_definitions(seed)
    donor_definitions = section_definitions(donor)
    require(seed_primary["number"] in seed_definitions
            and donor_primary["number"] in donor_definitions,
            "target Section Definition auxiliary record is absent")
    require(
        seed_definitions[seed_primary["number"]]["selection"]
        == donor_definitions[donor_primary["number"]]["selection"]
        == function["expected_selection"],
        "target COMDAT selection changed",
    )
    seed_associated = associated_sections(seed, seed_definitions, seed_primary["number"])
    donor_associated = associated_sections(donor, donor_definitions, donor_primary["number"])
    require(seed_associated == donor_associated,
            "target associative-section seats changed")
    require(tuple(sorted(name for _, name in seed_associated)) == (".debug$F", ".debug$S"),
            "target closure is not exactly .debug$S + .debug$F; xdata is unsupported")
    provenance = verify_non_emitting_donor(seed, donor, shape_identifiers)
    seed_closure = {
        name: seed.sections[number - 1] for number, name in seed_associated
    }
    donor_closure = {
        name: donor.sections[number - 1] for number, name in donor_associated
    }
    for name in (".debug$S", ".debug$F"):
        left = seed_closure[name]
        right = donor_closure[name]
        require(
            left["number"] == right["number"]
            and left["raw_size"] == right["raw_size"]
            and left["relocation_count"] == right["relocation_count"]
            and left["line_count"] == right["line_count"] == 0
            and left["characteristics"] == right["characteristics"],
            f"{name} closure geometry changed",
        )
        left_rows = detailed_relocations(seed, left)
        right_rows = detailed_relocations(donor, right)
        require(
            [
                (
                    row["offset"], row["type"], row["addend"], row["target"],
                    row["target_section"], row["target_value"],
                    row["target_type"], row["target_storage"],
                )
                for row in left_rows
            ]
            == [
                (
                    row["offset"], row["type"], row["addend"], row["target"],
                    row["target_section"], row["target_value"],
                    row["target_type"], row["target_storage"],
                )
                for row in right_rows
            ],
            f"{name} relocation target/type/addend closure changed",
        )

    seed_relocations = detailed_relocations(seed, seed_primary)
    donor_relocations = detailed_relocations(donor, donor_primary)
    compatibility = relocation_compatibility(
        seed_relocations,
        donor_relocations,
        seed_primary["number"],
        donor_primary["number"],
    )
    require(compatibility is not None,
            "primary relocation target/type/addend semantics changed")
    require(len(compatibility["local_updates"])
            == function["expected_local_symbol_updates"],
            "primary local-symbol update count changed")
    donor_body = coff_body(donor, donor_primary)
    require(sha256_bytes(donor_body) == function["compiler_output_body_sha256"],
            "compiler donor body hash differs from the retail-approved oracle pin")

    seed_function_index, seed_function = function_symbol(
        seed, mangled, seed_primary["number"]
    )
    donor_function_index, donor_function = function_symbol(
        donor, mangled, donor_primary["number"]
    )
    donor_lines = normalized_donor_lines(
        seed, donor, seed_primary, donor_primary,
        seed_function_index, donor_function_index,
    )
    replacements = [
        (
            seed_primary["raw_offset"],
            seed_primary["raw_offset"] + seed_primary["raw_size"],
            donor_body,
        ),
        (
            seed_primary["line_offset"],
            seed_primary["line_offset"] + seed_primary["line_count"] * 6,
            donor_lines,
        ),
    ]
    output = bytearray(apply_replacements(seed_bytes, replacements))
    total_delta = sum(len(replacement) - (end - start)
                      for start, end, replacement in replacements)
    new_symbol_offset = shifted_pointer(seed.symbol_offset, replacements)
    struct.pack_into("<I", output, 8, new_symbol_offset)

    expected_headers = bytearray(seed.data[20 : 20 + seed.section_count * 40])
    for section in seed.sections:
        relative_header = (section["number"] - 1) * 40
        if section["number"] == seed_primary["number"]:
            struct.pack_into("<I", expected_headers, relative_header + 16,
                             donor_primary["raw_size"])
            struct.pack_into("<H", expected_headers, relative_header + 34,
                             donor_primary["line_count"])
        for field, relative in (
            ("raw_offset", 20), ("relocation_offset", 24), ("line_offset", 28)
        ):
            struct.pack_into(
                "<I", expected_headers, relative_header + relative,
                shifted_pointer(section[field], replacements),
            )
    output[20 : 20 + len(expected_headers)] = expected_headers

    new_primary_relocation_offset = shifted_pointer(
        seed_primary["relocation_offset"], replacements
    )
    for ordinal, (seed_row, donor_row) in enumerate(
        zip(seed_relocations, donor_relocations)
    ):
        struct.pack_into(
            "<IIH", output, new_primary_relocation_offset + ordinal * 10,
            donor_row["offset"], seed_row["symbol_index"], donor_row["type"],
        )

    expected_symbols = bytearray(
        seed.data[seed.symbol_offset : seed.symbol_offset + seed.symbol_count * 18]
    )
    shifted_function_line_pointers = 0
    for symbol_index, symbol in seed.symbols.items():
        if symbol["type"] != 0x20 or symbol["aux_count"] < 1:
            continue
        auxiliary_offset = (symbol_index + 1) * 18
        line_pointer, = struct.unpack_from("<I", expected_symbols, auxiliary_offset + 8)
        mapped = shifted_pointer(line_pointer, replacements)
        if mapped != line_pointer:
            struct.pack_into("<I", expected_symbols, auxiliary_offset + 8, mapped)
            shifted_function_line_pointers += 1
    for symbol_index, donor_value in compatibility["local_updates"].items():
        struct.pack_into("<I", expected_symbols, symbol_index * 18 + 8, donor_value)

    donor_function_auxiliary = coff_auxiliary(
        donor, donor_function_index, donor_function
    )
    seed_function_auxiliary = coff_auxiliary(
        seed, seed_function_index, seed_function
    )
    require(
        seed_function["type"] == donor_function["type"]
        and seed_function["storage"] == donor_function["storage"]
        and seed_function["aux_count"] == donor_function["aux_count"] == 1
        and seed_function_auxiliary[:4] == donor_function_auxiliary[:4]
        and seed_function_auxiliary[12:] == donor_function_auxiliary[12:],
        "Function Definition tag/next-function auxiliary metadata changed",
    )
    seed_total_size, seed_line_pointer = struct.unpack_from(
        "<II", seed_function_auxiliary, 4
    )
    donor_total_size, donor_line_pointer = struct.unpack_from(
        "<II", donor_function_auxiliary, 4
    )
    require(seed_total_size == seed_primary["raw_size"]
            and seed_line_pointer == seed_primary["line_offset"],
            "seed Function Definition size/line pointer is stale")
    require(donor_total_size == donor_primary["raw_size"]
            and donor_line_pointer == donor_primary["line_offset"],
            "donor Function Definition size/line pointer is stale")
    struct.pack_into("<I", expected_symbols, (seed_function_index + 1) * 18 + 4,
                     donor_total_size)

    seed_begin_index, seed_begin = marker_symbol(seed, ".bf", seed_primary["number"])
    donor_begin_index, donor_begin = marker_symbol(donor, ".bf", donor_primary["number"])
    seed_begin_auxiliary = coff_auxiliary(seed, seed_begin_index, seed_begin)
    donor_begin_auxiliary = coff_auxiliary(donor, donor_begin_index, donor_begin)
    require(
        seed_begin["aux_count"] == donor_begin["aux_count"] == 1
        and seed_begin["value"] == donor_begin["value"]
        and seed_begin["type"] == donor_begin["type"]
        and seed_begin["storage"] == donor_begin["storage"]
        and seed_begin_auxiliary[:4] == donor_begin_auxiliary[:4]
        and seed_begin_auxiliary[6:] == donor_begin_auxiliary[6:],
        ".bf tag/next-function auxiliary metadata changed",
    )
    expected_symbols[(seed_begin_index + 1) * 18 + 4:
                     (seed_begin_index + 1) * 18 + 6] = donor_begin_auxiliary[4:6]

    seed_end_index, seed_end = marker_symbol(seed, ".ef", seed_primary["number"])
    donor_end_index, donor_end = marker_symbol(donor, ".ef", donor_primary["number"])
    require(seed_end["value"] == seed_primary["raw_size"],
            "seed .ef value is stale")
    require(donor_end["value"] == donor_primary["raw_size"],
            "donor .ef value is stale")
    seed_end_auxiliary = coff_auxiliary(seed, seed_end_index, seed_end)
    donor_end_auxiliary = coff_auxiliary(donor, donor_end_index, donor_end)
    require(
        seed_end["aux_count"] == donor_end["aux_count"] == 1
        and seed_end["type"] == donor_end["type"]
        and seed_end["storage"] == donor_end["storage"]
        and seed_end_auxiliary[:4] == donor_end_auxiliary[:4]
        and seed_end_auxiliary[6:] == donor_end_auxiliary[6:],
        ".ef tag/next-function auxiliary metadata changed",
    )
    struct.pack_into("<I", expected_symbols, seed_end_index * 18 + 8,
                     donor_end["value"])
    expected_symbols[(seed_end_index + 1) * 18 + 4:
                     (seed_end_index + 1) * 18 + 6] = donor_end_auxiliary[4:6]

    seed_section_index, seed_section_symbol = section_symbol(seed, seed_primary)
    donor_section_index, donor_section_symbol = section_symbol(donor, donor_primary)
    donor_section_auxiliary = coff_auxiliary(
        donor, donor_section_index, donor_section_symbol
    )
    seed_section_auxiliary = coff_auxiliary(
        seed, seed_section_index, seed_section_symbol
    )
    require(
        seed_section_symbol["aux_count"]
        == donor_section_symbol["aux_count"] == 1
        and seed_section_symbol["type"] == donor_section_symbol["type"]
        and seed_section_symbol["storage"] == donor_section_symbol["storage"]
        and seed_section_auxiliary[12:] == donor_section_auxiliary[12:]
        and int.from_bytes(seed_section_auxiliary[0:4], "little")
        == seed_primary["raw_size"]
        and int.from_bytes(seed_section_auxiliary[4:6], "little")
        == seed_primary["relocation_count"]
        and int.from_bytes(seed_section_auxiliary[6:8], "little")
        == seed_primary["line_count"]
        and int.from_bytes(donor_section_auxiliary[0:4], "little")
        == donor_primary["raw_size"]
        and int.from_bytes(donor_section_auxiliary[4:6], "little")
        == donor_primary["relocation_count"]
        and int.from_bytes(donor_section_auxiliary[6:8], "little")
        == donor_primary["line_count"]
        and donor_section_auxiliary[14] == function["expected_selection"],
        "donor Section Definition auxiliary record is stale",
    )
    expected_symbols[(seed_section_index + 1) * 18:
                     (seed_section_index + 2) * 18] = donor_section_auxiliary
    output[new_symbol_offset:new_symbol_offset + len(expected_symbols)] = expected_symbols

    seed_debug_s_raw = coff_body(seed, seed_closure[".debug$S"])
    donor_debug_s_raw = coff_body(donor, donor_closure[".debug$S"])
    require(len(seed_debug_s_raw) == len(donor_debug_s_raw) >= 28,
            "CodeView procedure record size changed or is truncated")
    require(seed_debug_s_raw[2:4] == donor_debug_s_raw[2:4] == b"\x05\x02",
            "associated CodeView record is not S_*PROC32")
    donor_cbproc, donor_dbgstart, donor_dbgend = struct.unpack_from(
        "<III", donor_debug_s_raw, 16
    )
    require(donor_cbproc == donor_primary["raw_size"]
            and 0 <= donor_dbgstart <= donor_dbgend < donor_cbproc,
            "donor CodeView procedure range is invalid")
    expected_debug_s = bytearray(seed_debug_s_raw)
    expected_debug_s[16:28] = donor_debug_s_raw[16:28]
    debug_s_offset = shifted_pointer(seed_closure[".debug$S"]["raw_offset"], replacements)
    output[debug_s_offset:debug_s_offset + len(expected_debug_s)] = expected_debug_s

    seed_debug_f_raw = coff_body(seed, seed_closure[".debug$F"])
    donor_debug_f_raw = coff_body(donor, donor_closure[".debug$F"])
    seed_fpo = parse_fpo_data(
        seed_debug_f_raw, expected_proc_size=seed_primary["raw_size"]
    )
    donor_fpo = parse_fpo_data(
        donor_debug_f_raw, expected_proc_size=donor_primary["raw_size"]
    )
    require(exact_json_equal(donor_fpo, function["expected_donor_fpo"]),
            "compiler donor FPO record differs from the manifest pin")
    require(donor_fpo["cbProcSize"] == donor_cbproc,
            "donor FPO and CodeView procedure sizes differ")
    debug_f_offset = shifted_pointer(seed_closure[".debug$F"]["raw_offset"], replacements)
    output[debug_f_offset:debug_f_offset + 16] = donor_debug_f_raw
    output_bytes = bytes(output)

    checked = CoffObject(output_bytes)
    checked_primary = checked.function_section(mangled)
    require(len(output_bytes) == len(seed_bytes) + total_delta,
            "composed COFF file length delta is wrong")
    require(function_multiset(checked) == function_multiset(seed),
            "composed COFF function multiset changed")
    require(coff_body(checked, checked_primary) == donor_body,
            "composed target body differs from compiler donor")
    require(coff_table(checked, checked_primary, "lines") == donor_lines,
            "composed COFF line table differs from normalized donor")
    checked_relocations = detailed_relocations(checked, checked_primary)
    require(
        [
            (row["offset"], row["symbol_index"], row["type"], row["addend"])
            for row in checked_relocations
        ]
        == [
            (donor_row["offset"], seed_row["symbol_index"], donor_row["type"], donor_row["addend"])
            for seed_row, donor_row in zip(seed_relocations, donor_relocations)
        ],
        "composed primary relocation table is incoherent",
    )
    checked_definitions = section_definitions(checked)
    checked_associated = associated_sections(
        checked, checked_definitions, checked_primary["number"]
    )
    require(checked_associated == seed_associated,
            "composed associative closure changed")
    expected_closure_raw = {
        seed_closure[".debug$S"]["number"]: bytes(expected_debug_s),
        seed_closure[".debug$F"]["number"]: donor_debug_f_raw,
    }
    for before, after in zip(seed.sections, checked.sections):
        require(before["number"] == after["number"]
                and before["name"] == after["name"]
                and before["characteristics"] == after["characteristics"],
                "composed section order/characteristics changed")
        number = before["number"]
        if number in expected_closure_raw:
            require(coff_body(checked, after) == expected_closure_raw[number],
                    f"composed debug closure raw bytes differ: section {number}")
            require(coff_table(seed, before, "relocations")
                    == coff_table(checked, after, "relocations"),
                    f"composed debug closure relocations changed: section {number}")
        elif number != seed_primary["number"]:
            require(coff_body(seed, before) == coff_body(checked, after),
                    f"non-target raw section changed: section {number}")
            require(coff_table(seed, before, "relocations")
                    == coff_table(checked, after, "relocations"),
                    f"non-target relocation table changed: section {number}")
        if number != seed_primary["number"]:
            require(coff_table(seed, before, "lines")
                    == coff_table(checked, after, "lines"),
                    f"non-target COFF line table changed: section {number}")

    require(
        checked.data[checked.symbol_offset:
                     checked.symbol_offset + checked.symbol_count * 18]
        == bytes(expected_symbols),
        "composed symbol/auxiliary table differs from the proven reconstruction",
    )
    checked_function_index, checked_function = function_symbol(
        checked, mangled, checked_primary["number"]
    )
    checked_function_auxiliary = coff_auxiliary(
        checked, checked_function_index, checked_function
    )
    require(struct.unpack_from("<I", checked_function_auxiliary, 4)[0]
            == donor_primary["raw_size"]
            and struct.unpack_from("<I", checked_function_auxiliary, 8)[0]
            == checked_primary["line_offset"],
            "composed Function Definition auxiliary record is stale")
    checked_begin_index, checked_begin = marker_symbol(
        checked, ".bf", checked_primary["number"]
    )
    require(coff_auxiliary(checked, checked_begin_index, checked_begin)[4:6]
            == donor_begin_auxiliary[4:6],
            "composed .bf line is stale")
    checked_end_index, checked_end = marker_symbol(
        checked, ".ef", checked_primary["number"]
    )
    require(checked_end["value"] == donor_primary["raw_size"]
            and coff_auxiliary(checked, checked_end_index, checked_end)
            == coff_auxiliary(donor, donor_end_index, donor_end),
            "composed .ef metadata differs from donor")
    checked_section_index, checked_section_symbol = section_symbol(checked, checked_primary)
    require(coff_auxiliary(checked, checked_section_index, checked_section_symbol)
            == donor_section_auxiliary,
            "composed Section Definition auxiliary record differs from donor")
    require(not any(identifier.encode("ascii") in output_bytes
                    for identifier in shape_identifiers),
            "declaration-shape identifiers leaked into the composed object")

    return output_bytes, {
        "mangled": mangled,
        "address": function["retail_oracle"]["address"],
        "retail_oracle": dict(function["retail_oracle"]),
        "retail_payload_bytes_read": 0,
        "section_number": checked_primary["number"],
        "seed_length": seed_primary["raw_size"],
        "donor_length": donor_primary["raw_size"],
        "linked_span": function["expected_linked_span"],
        "file_size_delta": total_delta,
        "relocation_count": len(checked_relocations),
        "relocation_offsets_moved": sum(
            left["offset"] != right["offset"]
            for left, right in zip(seed_relocations, donor_relocations)
        ),
        "local_symbols_updated": len(compatibility["local_updates"]),
        "function_line_pointers_shifted": shifted_function_line_pointers,
        "coff_line_policy": "whole_donor_normalized_function_index",
        "coff_line_rows": donor_primary["line_count"],
        "codeview_policy": "seed_types_names_locals_with_donor_cbProc_DbgStart_DbgEnd",
        "codeview_range": {
            "cbProc": donor_cbproc,
            "DbgStart": donor_dbgstart,
            "DbgEnd": donor_dbgend,
        },
        "fpo_policy": "whole_donor_debug_F_record",
        "seed_fpo": seed_fpo,
        "donor_fpo": donor_fpo,
        "target_body_sha256": sha256_bytes(donor_body),
        "input_sha256": sha256_bytes(seed_bytes),
        "donor_sha256": sha256_bytes(donor_bytes),
        "output_sha256": sha256_bytes(output_bytes),
        "provenance": provenance,
    }


def pe_resource_sections(data: bytes) -> tuple[int, int, int] | None:
    """Return (virtual_address, raw_offset, raw_size) of .rsrc, or None."""
    pe = int.from_bytes(data[0x3C:0x40], "little")
    section_count = int.from_bytes(data[pe + 6:pe + 8], "little")
    optional_size = int.from_bytes(data[pe + 20:pe + 22], "little")
    table = pe + 24 + optional_size
    for index in range(section_count):
        header = table + index * 40
        if data[header:header + 8].rstrip(b"\0") == b".rsrc":
            virtual = int.from_bytes(data[header + 12:header + 16], "little")
            raw_size = int.from_bytes(data[header + 16:header + 20], "little")
            raw_offset = int.from_bytes(data[header + 20:header + 24],
                                        "little")
            return (virtual, raw_offset, raw_size)
    return None


def pe_resource_directory_offsets(data: bytes) -> list[int]:
    """File offsets of every resource DIRECTORY record in the .rsrc tree."""
    section = pe_resource_sections(data)
    if section is None:
        return []
    _, raw_offset, _ = section
    offsets = []

    def walk(directory: int) -> None:
        offsets.append(raw_offset + directory)
        named = int.from_bytes(
            data[raw_offset + directory + 12:raw_offset + directory + 14],
            "little")
        idents = int.from_bytes(
            data[raw_offset + directory + 14:raw_offset + directory + 16],
            "little")
        for index in range(named + idents):
            entry = raw_offset + directory + 16 + index * 8
            value = int.from_bytes(data[entry + 4:entry + 8], "little")
            if value & 0x80000000:
                walk(value & 0x7FFFFFFF)

    walk(0)
    return offsets


def pe_resource_directory_times(data: bytes) -> set[int]:
    return {
        int.from_bytes(data[offset + 4:offset + 8], "little")
        for offset in pe_resource_directory_offsets(data)
    }


def validate_reccmp_report_snapshot(data: bytes, image_gate: dict) -> dict:
    """Validate the image's fixed row universe and report exact score-set facts."""
    try:
        document = strict_json_loads(data)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ByteIdentityError(f"cannot parse final reccmp report: {error}") from error
    require(isinstance(document, dict), "final reccmp report must be an object")
    exact_audit_keys(document, {"file", "format", "timestamp", "data"},
                     "final reccmp report")
    require(
        document.get("file") == image_gate["recompiled"]
        and type(document.get("format")) is int
        and document.get("format") == 1,
        "final reccmp report identity/schema differs",
    )
    require_nonnegative_finite_number(
        document.get("timestamp"), "final reccmp report timestamp"
    )
    rows = document.get("data")
    required_count = image_gate["required_row_count"]
    require(isinstance(rows, list) and len(rows) == required_count,
            f"final reccmp row count must be exactly {required_count}")
    identity_rows = []
    accepted_rows = []
    accepted_address_aligned = 0
    address_aligned = 0
    previous_address = -1
    seen_addresses = set()
    for index, row in enumerate(rows):
        context = f"final reccmp row[{index}]"
        require(isinstance(row, dict), f"{context} must be an object")
        required_keys = {"address", "name", "matching", "recomp", "type"}
        require(
            required_keys <= set(row)
            and set(row) <= required_keys | {"effective"},
            f"{context} schema differs",
        )
        address = row.get("address")
        name = row.get("name")
        row_type = row.get("type")
        require(
            isinstance(address, str)
            and ADDRESS_RE.fullmatch(address) is not None
            and isinstance(name, str) and bool(name)
            and type(row_type) is int and row_type in (1, 5),
            f"{context} identity is invalid",
        )
        numeric_address = int(address, 16)
        require(
            numeric_address > previous_address and address not in seen_addresses,
            f"{context} address order/uniqueness differs",
        )
        previous_address = numeric_address
        seen_addresses.add(address)
        matching = row.get("matching")
        recomp = row.get("recomp")
        require(type(matching) is float and math.isfinite(matching)
                and 0.0 <= matching <= 1.0,
                f"{context} raw matching score is invalid")
        require(isinstance(recomp, str)
                and ADDRESS_RE.fullmatch(recomp) is not None,
                f"{context} recompiled address is invalid")
        if "effective" in row:
            require(row["effective"] is True,
                    f"{context}.effective must be exact JSON true")
        identity_rows.append([address, name, row_type])
        if recomp == address:
            address_aligned += 1
        if matching == 1.0:
            accepted_rows.append([address, name, row_type])
            if recomp == address:
                accepted_address_aligned += 1
    identity_bytes = (
        "\n".join(
            json.dumps(row, separators=(",", ":"), ensure_ascii=True)
            for row in identity_rows
        ) + "\n"
    ).encode("utf-8")
    identity_sha = sha256_bytes(identity_bytes)
    require(
        identity_sha == image_gate["row_identity_sha256"],
        "final reccmp row identity/order universe differs from the retail pin",
    )
    accepted_bytes = (
        "\n".join(
            json.dumps(row, separators=(",", ":"), ensure_ascii=True)
            for row in accepted_rows
        ) + "\n"
    ).encode("utf-8")
    return {
        "row_count": len(rows),
        "raw_1_0_count": len(accepted_rows),
        "raw_1_0_address_aligned_count": accepted_address_aligned,
        "address_aligned_row_count": address_aligned,
        "accepted_row_identity_sha256": sha256_bytes(accepted_bytes),
        "row_identity_sha256": identity_sha,
    }


def validate_iteration_reccmp_report(data: bytes, image_gate: dict) -> dict:
    """Require the manifest-pinned accepted score set with zero losses/gains."""
    result = validate_reccmp_report_snapshot(data, image_gate)
    baseline = image_gate["iteration_baseline"]
    require(
        result["raw_1_0_count"] == baseline["exact_raw_1_0_count"]
        and result["accepted_row_identity_sha256"]
        == baseline["accepted_row_identity_sha256"],
        "iteration reccmp accepted raw-1.0 row set differs from its exact pin",
    )
    return result


def validate_complete_reccmp_report(data: bytes, image_gate: dict) -> dict:
    """Require every fixed row to be raw-exact and address-aligned."""
    result = validate_reccmp_report_snapshot(data, image_gate)
    required = image_gate["required_row_count"]
    require(result["raw_1_0_count"] == required
            and result["raw_1_0_address_aligned_count"] == required
            and result["address_aligned_row_count"] == required,
            "final reccmp report is not exactly 4933/4933 and address-aligned")
    return {
        "row_count": result["row_count"],
        "exact_row_count": result["raw_1_0_count"],
        "address_aligned_row_count": result["address_aligned_row_count"],
        "row_identity_sha256": result["row_identity_sha256"],
    }
