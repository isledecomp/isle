#!/usr/bin/env python3
"""Configure-only tests for the typed source-overlay graph contract."""

from __future__ import annotations

from pathlib import Path
import json
import os
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "cmake/byte_identity.cmake"


class SourceOverlayCMakeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def configure(self, generator: str, scenario: str = "positive", *,
                  targets: tuple[str, ...] = ("lego1",)):
        identity = "-".join(targets) if targets else "no-target"
        suffix = f"{generator.replace(' ', '-')}-{scenario}-{identity}"
        source = self.directory / f"source-{suffix}"
        build = self.directory / f"build-{suffix}"
        source.mkdir()
        for relative in ("a.cpp", "b.cpp", "config.cpp"):
            (source / relative).write_text("// fixture\n", encoding="ascii")
        sentinel = source / "compiler-sentinel"
        sentinel_log = source / "compiler-sentinel.log"
        sentinel.write_text(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> "
            + repr(str(sentinel_log)) + "\nexit 97\n",
            encoding="ascii",
        )
        sentinel.chmod(0o755)
        toolchain = source / "toolchain.cmake"
        toolchain.write_text(
            "\n".join([
                'set(CMAKE_SYSTEM_NAME "Generic")',
                f'set(CMAKE_CXX_COMPILER "{sentinel.as_posix()}")',
                'set(CMAKE_CXX_COMPILER_ID "GNU")',
                'set(CMAKE_CXX_COMPILER_ID_RUN TRUE)',
                'set(CMAKE_CXX_COMPILER_FORCED TRUE)',
                'set(CMAKE_CXX_COMPILER_WORKS TRUE)',
            ]) + "\n",
            encoding="utf-8",
        )

        enabled = scenario != "disabled-emitted"
        unit_indices = "0;1"
        generated_path = "gen.cpp"
        generated_ordinal = "2"
        generated_after = "a.cpp"
        generated_before = "b.cpp"
        tail_path = "tail.cpp"
        tail_ordinal = "4"
        tail_after = "b.cpp"
        tail_before = ""
        include_tail = True
        config_links = "ddraw;dxguid"
        forbidden = ""
        extra_lines: list[str] = []

        if scenario == "generated-exists":
            (source / generated_path).write_text("// forbidden\n", encoding="ascii")
        elif scenario == "redirected-parent":
            real_parent = source / "real-generated"
            real_parent.mkdir()
            (source / "generated").symlink_to(real_parent, target_is_directory=True)
            generated_path = "generated/gen.cpp"
        elif scenario == "bad-predecessor":
            generated_after = "wrong.cpp"
        elif scenario == "bad-successor":
            generated_before = "wrong.cpp"
        elif scenario == "tail-not-final":
            unit_indices = "0"
            generated_ordinal = "2"
            generated_before = ""
            include_tail = False
        elif scenario == "tail-then-def":
            (source / "fixture.def").write_text("EXPORTS\n", encoding="ascii")
            extra_lines.append("target_sources(lego1 PRIVATE fixture.def)")
        elif scenario == "ordinal-out-of-bounds":
            generated_ordinal = "99"
        elif scenario == "duplicate-policy":
            unit_indices = "0;0"
            include_tail = False
        elif scenario == "duplicate-link-seat":
            config_links = "ddraw;dxguid;ddraw;dxguid"
        elif scenario == "legacy-defined":
            forbidden = "LEGACY_ENTROPY_KNOB"
            extra_lines.append("set(LEGACY_ENTROPY_KNOB OFF)")
        elif scenario == "disabled-emitted":
            unit_indices = ""
            include_tail = False
        elif scenario != "positive" and scenario != "no-lego-target":
            raise AssertionError(f"unknown scenario {scenario}")

        lines = [
            "cmake_minimum_required(VERSION 3.21)",
            "project(source_overlay_graph LANGUAGES CXX)",
            "set(CMAKE_EXPORT_COMPILE_COMMANDS ON)",
            f'include("{MODULE.as_posix()}")',
        ]
        for target in targets if scenario != "no-lego-target" else ():
            lines.append(f"add_library({target} STATIC a.cpp b.cpp)")
        lines.extend([
            "add_library(config STATIC config.cpp)",
            f"target_link_libraries(config PRIVATE {config_links.replace(';', ' ')})",
            f"set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_ENABLED "
            f"{'TRUE' if enabled else 'FALSE'})",
            'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_PREBUILT_SOURCE_ARTIFACTS "forbidden")',
            f'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_OUTPUTS '
            f'"{generated_path};{tail_path};CONFIG/detectdx5.cpp")',
            f'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_INDICES "{unit_indices}")',
            'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_LINK_INDICES "0")',
            f'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_FORBIDDEN_INTERFACES "{forbidden}")',
            f'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_0_PATH "{generated_path}")',
            'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_0_LANGUAGE "CXX")',
            'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_0_TARGET_FAMILY '
            '"list_targets_from_add_lego_libraries")',
            'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_0_TARGETS "lego1;beta10")',
            f'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_0_SOURCE_ORDINAL '
            f'"{generated_ordinal}")',
            f'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_0_INSERT_AFTER '
            f'"{generated_after}")',
            f'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_0_INSERT_BEFORE '
            f'"{generated_before}")',
            'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_0_GENERATION_OPERATION_IDS "op_fixture")',
            'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_0_OUTPUT_SHA256 '
            '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")',
            'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_0_OUTPUT_TOKEN_SHA256 '
            '"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")',
            'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_0_OUTPUT_SIZE "1")',
            'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_0_OUTPUT_LINE_COUNT "1")',
        ])
        if include_tail:
            lines.extend([
                f'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_1_PATH "{tail_path}")',
                'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_1_LANGUAGE "CXX")',
                'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_1_TARGET_FAMILY '
                '"list_targets_from_add_lego_libraries")',
                'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_1_TARGETS "lego1;beta10")',
                f'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_1_SOURCE_ORDINAL "{tail_ordinal}")',
                f'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_1_INSERT_AFTER "{tail_after}")',
                f'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_1_INSERT_BEFORE "{tail_before}")',
                'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_1_GENERATION_OPERATION_IDS "op_tail")',
                'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_1_OUTPUT_SHA256 '
                '"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")',
                'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_1_OUTPUT_TOKEN_SHA256 '
                '"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")',
                'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_1_OUTPUT_SIZE "1")',
                'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_1_OUTPUT_LINE_COUNT "1")',
            ])
        lines.extend([
            'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_LINK_0_ADMISSION_ID '
            '"config_private_dsound_probe_v1")',
            'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_LINK_0_TARGET "config")',
            'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_LINK_0_VISIBILITY "PRIVATE")',
            'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_LINK_0_LIBRARY "dsound")',
            'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_LINK_0_INSERT_AFTER "ddraw")',
            'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_LINK_0_INSERT_BEFORE "dxguid")',
            'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_LINK_0_SOURCE_OUTPUT '
            '"CONFIG/detectdx5.cpp")',
            'set(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_LINK_0_REQUIRED_OPERATION_IDS '
            '"op_3624_config_dsound_probe")',
            *extra_lines,
            "_isle_apply_byte_identity_source_overlay_graph()",
        ])
        for target in targets if scenario != "no-lego-target" else ():
            lines.extend([
                f"get_target_property({target}_sources {target} SOURCES)",
                f'file(APPEND "${{CMAKE_BINARY_DIR}}/result.txt" '
                f'"{target}=${{{target}_sources}}\\n")',
            ])
        lines.extend([
            "get_target_property(config_links config LINK_LIBRARIES)",
            'file(APPEND "${CMAKE_BINARY_DIR}/result.txt" '
            '"config=${config_links}\\n")',
        ])
        (source / "CMakeLists.txt").write_text(
            "\n".join(lines) + "\n", encoding="utf-8"
        )

        command = [
            "cmake", "-S", str(source), "-B", str(build), "-G", generator,
            f"-DCMAKE_TOOLCHAIN_FILE={toolchain}",
        ]
        if generator == "Ninja" and shutil.which("ninja") is None:
            ninja = source / "ninja"
            ninja.write_text(
                "#!/bin/sh\nif [ \"$1\" = --version ]; then "
                "echo 1.11.1; exit 0; fi\nexit 0\n",
                encoding="ascii",
            )
            ninja.chmod(0o755)
            command.append(f"-DCMAKE_MAKE_PROGRAM={ninja}")
        result = subprocess.run(
            command, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, check=False,
            env={**os.environ, "LC_ALL": "C"},
        )
        self.assertFalse(sentinel_log.exists(), result.stdout)
        return result, source, build

    def test_overlay_graph_configures_exact_sources_and_link_seat(self):
        for generator in ("Ninja", "Unix Makefiles"):
            for targets in (("lego1",), ("beta10",), ("lego1", "beta10")):
                with self.subTest(generator=generator, targets=targets):
                    result, source, build = self.configure(
                        generator, targets=targets
                    )
                    self.assertEqual(result.returncode, 0, result.stdout)
                    records = dict(
                        line.split("=", 1)
                        for line in (build / "result.txt").read_text().splitlines()
                    )
                    expected = [
                        str(source / "a.cpp"), str(source / "gen.cpp"),
                        str(source / "b.cpp"), str(source / "tail.cpp"),
                    ]
                    for target in targets:
                        actual = [
                            str(
                                (source / item).resolve()
                                if not Path(item).is_absolute()
                                else Path(item).resolve()
                            )
                            for item in records[target].split(";")
                        ]
                        self.assertEqual(
                            actual, [str(Path(item).resolve()) for item in expected]
                        )
                    self.assertEqual(records["config"], "ddraw;dsound;dxguid")
                    commands = json.loads(
                        (build / "compile_commands.json").read_text()
                    )
                    generated_files = [
                        str(Path(item["file"]).resolve())
                        for item in commands
                        if Path(item["file"]).name in {"gen.cpp", "tail.cpp"}
                    ]
                    self.assertEqual(
                        generated_files,
                        [
                            str((source / relative).resolve())
                            for _target in targets
                            for relative in ("gen.cpp", "tail.cpp")
                        ],
                    )
                    self.assertTrue(all(
                        str(source / relative) in item["command"]
                        for item in commands
                        for relative in (
                            [Path(item["file"]).name]
                            if Path(item["file"]).name in {"gen.cpp", "tail.cpp"}
                            else []
                        )
                    ))

    def test_overlay_graph_tolerates_trailing_noncompiled_sources(self):
        # A module-definition file a target appends after its source list may
        # trail the final generated TU; only a trailing C/C++ TU is fatal.
        result, _source, _build = self.configure(
            "Unix Makefiles", "tail-then-def"
        )
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_overlay_graph_rejects_every_ambiguous_or_legacy_seat(self):
        cases = {
            "generated-exists": "unexpectedly exists",
            "redirected-parent": "parent is redirected",
            "bad-predecessor": "graph seat differs",
            "bad-successor": "successor differs",
            "tail-not-final": "final TU is not the C++ compile tail",
            "ordinal-out-of-bounds": "ordinal is outside",
            "duplicate-policy": "indices are not canonical",
            "duplicate-link-seat": "link neighbor seat is not unique",
            "legacy-defined": "Legacy entropy interface remains defined",
            "no-lego-target": "no configured LEGO target instance",
            "disabled-emitted": "Disabled source overlay emitted graph policy",
        }
        for scenario, message in cases.items():
            with self.subTest(scenario=scenario):
                result, _source, _build = self.configure(
                    "Unix Makefiles", scenario,
                    targets=() if scenario == "no-lego-target" else ("lego1",),
                )
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(message, result.stdout)


if __name__ == "__main__":
    unittest.main()
