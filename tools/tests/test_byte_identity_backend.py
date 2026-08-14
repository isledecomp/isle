#!/usr/bin/env python3
"""Platform-adapter tests for the byte-identity execution boundary.

These tests never exercise retail inputs.  On Windows CI the explicit
``BYTE_IDENTITY_REQUIRE_NATIVE_CL=1`` contract upgrades the native adapter
smoke from optional discovery to a required VC4.2 compile through logical Z:.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))

from byte_identity_backend import (  # noqa: E402
    BackendError,
    BackendLockBusy,
    PlatformFileLock,
    POSIX_WINE_BACKEND,
    WINDOWS_NATIVE_BACKEND,
    WindowsDriveMapping,
    WindowsJob,
    WindowsNamespaceAuthority,
    capabilities,
    host_backend,
    quote_windows_command,
    selected_backend,
    windows_creationflags,
)
MSVC420_FILES = {
    "CL.EXE": "c5bf7ad84482e8a54d5753fcbd3e648d8a1192f5ca8b8cf1f5d23b651750585f",
    "C1.EXE": "c5a62937d806fbd8663b05f15bd02670a43bdf983a50ee4080bcfd90a7643b90",
    "C1XX.EXE": "9e0782ec157b30a387ca855374bc4c1b8a605dfb12364425497ba431541a5bf9",
    "C2.EXE": "2aa1fcace0779531b3ec80b730663acd98f181aed3cdff51366440c602b724b5",
    "MSPDB41.DLL": "6cab17cfcbc5a6317ab030a0db99164cafdfd1f360baa36186849237ffb25858",
    "MSVCRT40.DLL": "ab55a2de2b6faf3daacd3e69473d385ceaead8033f7c79beb6bbf802f230f030",
    "MSVCRT20.DLL": "72a46bd99188b67d48270a1bf40ffd6cd9bc5814818066a743eaffb8d64d88e8",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class BackendNeutralTests(unittest.TestCase):
    def test_capability_records_are_explicit_and_distinct(self):
        wine = capabilities(POSIX_WINE_BACKEND)
        native = capabilities(WINDOWS_NATIVE_BACKEND)
        self.assertEqual(wine.identifier, POSIX_WINE_BACKEND)
        self.assertEqual(native.identifier, WINDOWS_NATIVE_BACKEND)
        self.assertTrue(wine.wine_prefix)
        self.assertFalse(native.wine_prefix)
        self.assertNotEqual(wine.process_tree_primitive, native.process_tree_primitive)
        self.assertNotEqual(wine.filesystem_authority, native.filesystem_authority)

    def test_selected_backend_cannot_impersonate_another_host(self):
        self.assertEqual(selected_backend(), host_backend())
        other = (
            WINDOWS_NATIVE_BACKEND
            if host_backend() == POSIX_WINE_BACKEND
            else POSIX_WINE_BACKEND
        )
        with self.assertRaises(BackendError):
            selected_backend(other)

    def test_windows_command_quoting_rejects_unsafe_argv(self):
        self.assertEqual(
            quote_windows_command(["cl.exe", "/DVALUE=a b", "unit.cpp"]),
            'cl.exe "/DVALUE=a b" unit.cpp',
        )
        for command in ([], ["cl.exe", "bad\0token"]):
            with self.subTest(command=command), self.assertRaises(BackendError):
                quote_windows_command(command)

    def test_platform_lock_has_fail_closed_nonblocking_contention(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "slot.lock"
            with path.open("a+b") as first_stream, path.open("a+b") as second_stream:
                first = PlatformFileLock(first_stream)
                second = PlatformFileLock(second_stream)
                first.acquire(exclusive=True, nonblocking=True)
                try:
                    with self.assertRaises(BackendLockBusy):
                        second.acquire(exclusive=True, nonblocking=True)
                finally:
                    first.release()
                second.acquire(exclusive=True, nonblocking=True)
                second.release()


@unittest.skipUnless(os.name == "nt", "native Windows adapter")
class NativeWindowsBackendTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()

    def tearDown(self):
        self.temporary.cleanup()

    def test_held_namespace_atomic_write_and_reparse_rejection(self):
        build = self.root / "build"
        output_dir = build / "audit"
        outside = self.root / "outside"
        output_dir.mkdir(parents=True)
        outside.mkdir()
        sentinel = outside / "sentinel.json"
        sentinel.write_bytes(b"outside\n")

        authority = WindowsNamespaceAuthority(build)
        try:
            output = output_dir / "state.json"
            expected = b'{"status":"native"}\n'
            self.assertEqual(authority.atomic_write(output, expected), sha256(output))
            self.assertEqual(authority.read_bytes(output), expected)
            self.assertTrue(authority.unlink(output))
            self.assertFalse(output.exists())

            junction = build / "redirect"
            linked = subprocess.run(
                ["cmd", "/d", "/c", "mklink", "/J", str(junction), str(outside)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(linked.returncode, 0, linked.stdout + linked.stderr)
            with self.assertRaises(BackendError):
                authority.atomic_write(junction / "sentinel.json", b"attacker\n")
            self.assertEqual(sentinel.read_bytes(), b"outside\n")
        finally:
            authority.close()

    def _required_toolchain(self) -> Path:
        root_value = os.environ.get("BYTE_IDENTITY_MSVC420_ROOT")
        required = os.environ.get("BYTE_IDENTITY_REQUIRE_NATIVE_CL") == "1"
        if not root_value:
            if required:
                self.fail(
                    "BYTE_IDENTITY_MSVC420_ROOT is required by the explicitly "
                    "requested native-Windows diagnostic"
                )
            self.skipTest("deferred native-Windows diagnostic was not requested")
        root = Path(root_value).resolve()
        for name, expected in MSVC420_FILES.items():
            path = root / "bin" / name
            if not path.is_file():
                self.fail(f"required native VC4.2 file is absent: {path}")
            self.assertEqual(sha256(path), expected, str(path))
        return root

    def test_native_vc42_compiles_only_from_a_pinned_logical_z_snapshot(self):
        toolchain = self._required_toolchain()
        drive = self.root / "drive"
        source_dir = drive / "source"
        output_dir = drive / "output"
        temporary = drive / "tmp"
        bin_dir = drive / "toolchain" / "bin"
        for directory in (source_dir, output_dir, temporary, bin_dir):
            directory.mkdir(parents=True, exist_ok=True)
        for name in MSVC420_FILES:
            shutil.copy2(toolchain / "bin" / name, bin_dir / name)
        source = source_dir / "smoke.cpp"
        source.write_text("extern \"C\" int native_byte_identity_smoke() { return 42; }\n")

        mapping = WindowsDriveMapping("Z", drive)
        mapping.map()
        job = WindowsJob()
        try:
            command = [
                r"Z:\toolchain\bin\CL.EXE",
                "/nologo", "/TP", "/Zi", "/O2", "/c",
                r"/FoZ:\output\smoke.obj",
                r"/FdZ:\output\smoke.pdb",
                r"Z:\source\smoke.cpp",
            ]
            environment = {
                "COMSPEC": os.environ["COMSPEC"],
                "PATH": rf"Z:\toolchain\bin;{os.environ['SystemRoot']}\System32",
                "SystemRoot": os.environ["SystemRoot"],
                "TEMP": r"Z:\tmp",
                "TMP": r"Z:\tmp",
                "INCLUDE": "",
            }
            process = subprocess.Popen(
                command,
                cwd=r"Z:\source",
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                creationflags=windows_creationflags(),
            )
            job.assign_and_resume(process)
            output, _ = process.communicate(timeout=60)
            self.assertEqual(
                process.returncode,
                0,
                output.decode("mbcs", errors="replace"),
            )
            self.assertEqual(job.active_processes(), 0)
            self.assertTrue((output_dir / "smoke.obj").is_file())
            self.assertTrue((output_dir / "smoke.pdb").is_file())
            payload = (output_dir / "smoke.obj").read_bytes()
            self.assertNotIn(str(drive).encode("utf-8"), payload)
            self.assertNotIn(str(drive).encode("utf-16le"), payload)
        finally:
            job.close()
            mapping.unmap()

    def test_cmake_configure_observes_the_same_session_z_mapping(self):
        self._required_toolchain()
        cmake = shutil.which("cmake")
        self.assertIsNotNone(
            cmake, "CMake is required by the requested native-Windows diagnostic"
        )
        drive = self.root / "configure-drive"
        source = drive / "source"
        build = drive / "build"
        source.mkdir(parents=True)
        build.mkdir()
        (source / "CMakeLists.txt").write_text(
            "cmake_minimum_required(VERSION 3.19 FATAL_ERROR)\n"
            "project(native_z_fixture NONE)\n"
            "if(NOT CMAKE_SOURCE_DIR STREQUAL \"Z:/source\")\n"
            "  message(FATAL_ERROR \"source is not the logical Z snapshot\")\n"
            "endif()\n"
            "file(WRITE \"${CMAKE_BINARY_DIR}/native-z-configured.txt\" \"ok\\n\")\n"
        )
        mapping = WindowsDriveMapping("Z", drive)
        mapping.map()
        try:
            configured = subprocess.run(
                [cmake, "-S", r"Z:\source", "-B", r"Z:\build", "-G", "NMake Makefiles"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                configured.returncode, 0, configured.stdout + configured.stderr
            )
            self.assertEqual(
                (build / "native-z-configured.txt").read_text(), "ok\n"
            )
        finally:
            mapping.unmap()


if __name__ == "__main__":
    unittest.main()
