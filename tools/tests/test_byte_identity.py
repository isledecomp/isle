#!/usr/bin/env python3
"""Native-only tests for the fail-closed byte-identity framework phase."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest


TOOLS = Path(__file__).resolve().parents[1]
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))
import byte_identity as byte_identity  # noqa: E402
import entropy  # noqa: E402


FAKE_COMPILER = r'''#!/usr/bin/env python3
import os
from pathlib import Path
import sys
import time

if os.environ.get("FAKE_SLEEP"):
    time.sleep(float(os.environ["FAKE_SLEEP"]))
if os.environ.get("FAKE_FAIL"):
    print("intentional fake compiler failure")
    raise SystemExit(7)

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
    return Path(matches[0])

source = next(Path(value) for value in sys.argv[1:] if value.endswith(".cpp"))
obj = option("Fo")
pdb = option("Fd")
obj.parent.mkdir(parents=True, exist_ok=True)
pdb.parent.mkdir(parents=True, exist_ok=True)
obj.write_bytes(
    b"FAKE-OBJ\0"
    + source.read_bytes()
    + os.environ.get("CL", "").encode()
    + os.environ.get("WINEDEBUG", "").encode()
)
pdb.write_bytes(b"FAKE-PDB\0" + os.environ["TMP"].encode())
print("fake compiler success")
'''


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class ByteIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.source_dir = self.directory / "source"
        self.build_dir = self.directory / "build"
        self.source = self.source_dir / "src/unit.cpp"
        self.include = self.source_dir / "include/pinned.h"
        self.compiler = self.directory / "fake-cl"
        self.compiler_support = self.directory / "fake-support"
        self.manifest = self.source_dir / "tools/byte_identity_manifest.json"
        self.plan = self.build_dir / "byte-identity/plan.cmake"
        self.source.parent.mkdir(parents=True)
        self.include.parent.mkdir(parents=True)
        self.manifest.parent.mkdir(parents=True)
        self.build_dir.mkdir()
        self.source.write_text("int unit() { return 7; }\n")
        self.include.write_text("#define PINNED_HEADER 1\n")
        self.compiler.write_text(FAKE_COMPILER)
        self.compiler.chmod(0o755)
        self.compiler_support.write_text("pinned fake compiler support\n")
        seed = 638847751
        header_sha = digest(entropy.generate(seed).encode("utf-8"))
        self.recipe_id = f"e_{header_sha[:12]}"
        self.document = {
            "schema": 1,
            "phase": "pass_through_launcher_v1",
            "toolchain": {
                "compiler_sha256": byte_identity.sha256_file(self.compiler),
                "compiler_id": "MSVC",
                "compiler_version": "10.20",
                "keep_compile_debug": "/Zi",
                "max_child_seconds": 3,
                "compiler_root_parent_levels": 0,
                "compiler_support_files": [
                    {
                        "path": "fake-support",
                        "sha256": byte_identity.sha256_file(self.compiler_support),
                    }
                ],
                "required_absent_toolchain_files": [],
                "runtime_executables": [],
                "sanitized_environment": list(byte_identity.SANITIZED_ENVIRONMENT),
                "provenance": {
                    "retail_use": "oracle_only_no_payload_copy",
                    "payload_source": "configured_compiler_output",
                    "forbid_emitted_padding": True,
                    "forbid_opaque_objects": True,
                    "forbid_source_tree_writes": True,
                },
            },
            "translation_units": [
                {
                    "target": "fixture",
                    "source": "src/unit.cpp",
                    "source_sha256": byte_identity.sha256_file(self.source),
                    "mode": "pass_through",
                    "command_policy": {
                        "required_flags": ["/Zi", "-c"],
                        "forbidden_prefixes": ["/GL", "-GL", "/Z7", "-Z7"],
                        "allowed_force_includes": [
                            {
                                "path": "include/pinned.h",
                                "sha256": byte_identity.sha256_file(self.include),
                            }
                        ],
                    },
                    "donors": [
                        {
                            "id": self.recipe_id,
                            "status": "planned_not_composed",
                            "recipe": {
                                "kind": "entropy",
                                "seed": seed,
                                "generated_header_sha256": header_sha,
                                "emission_policy": "non_emitting_declarations_only",
                                "authenticity_rationale": (
                                    "Unused period-plausible declarations perturb compiler state "
                                    "without emitting any linker input."
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
        }
        self.write_manifest()

    def tearDown(self):
        self.temporary.cleanup()

    def write_manifest(self):
        self.manifest.write_text(json.dumps(self.document, indent=2) + "\n")

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
        return self.build_dir / "byte-identity/generated" / f"entropy_{header_sha}.h"

    def materialize(self):
        output = self.materialized_header()
        result = byte_identity.main(
            [
                "materialize",
                "--manifest", str(self.manifest),
                "--source-dir", str(self.source_dir),
                "--build-dir", str(self.build_dir),
                "--recipe-id", self.recipe_id,
                "--output", str(output),
            ]
        )
        self.assertEqual(result, 0)
        return output

    def launch_args(self, output, pdb):
        return [
            "compile-launch",
            "--manifest", str(self.manifest),
            "--source-dir", str(self.source_dir),
            "--build-dir", str(self.build_dir),
            "--target", "fixture",
            "--configured-compiler", str(self.compiler),
            "--",
            str(self.compiler),
            "/Zi",
            "-c",
            f"/FI{self.include}",
            f"/Fo{output}",
            f"/Fd{pdb}",
            str(self.source),
        ]

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

    def test_entropy_cli_preserves_historical_seed_bytes(self):
        result = subprocess.run(
            [sys.executable, str(TOOLS / "entropy.py"), "638847751"],
            check=True,
            capture_output=True,
        )
        self.assertEqual(
            digest(result.stdout),
            "ab52dfd59e21a2e67253e650f9ce656511b93fe06a8e2c6c92f47892c21e6cc7",
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
        self.assertFalse((self.source_dir / "plan.cmake").exists())

    def test_opaque_recipe_is_forbidden(self):
        recipe = self.document["translation_units"][0]["donors"][0]["recipe"]
        recipe["kind"] = "opaque_obj"
        self.write_manifest()
        self.assertEqual(byte_identity.main(self.plan_args()), 2)

    def test_duplicate_manifest_key_is_forbidden(self):
        raw = self.manifest.read_text()
        self.manifest.write_text(raw.replace('"schema": 1,', '"schema": 1,\n  "schema": 1,', 1))
        self.assertEqual(byte_identity.main(self.plan_args()), 2)

    def test_unsupported_splice_class_is_fatal(self):
        self.document["translation_units"][0]["functions"] = [
            {"mangled": "?Function@@YAXXZ", "splice_class": "same_slot_xdata"}
        ]
        self.write_manifest()
        self.assertEqual(byte_identity.main(self.plan_args()), 2)

    def test_atomic_launcher_success_and_incomplete_audit(self):
        self.materialize()
        output = self.build_dir / "objects/unit.obj"
        pdb = self.build_dir / "objects/unit.pdb"
        output.parent.mkdir(parents=True)
        output.write_bytes(b"STALE")
        pdb.write_bytes(b"STALE-PDB")
        previous = Path.cwd()
        old_cl = os.environ.get("CL")
        os.environ["CL"] = "/DPOISONED_BY_PARENT_ENVIRONMENT"
        try:
            os.chdir(self.build_dir)
            result = byte_identity.main(self.launch_args(output, pdb))
        finally:
            os.chdir(previous)
            if old_cl is None:
                os.environ.pop("CL", None)
            else:
                os.environ["CL"] = old_cl
        self.assertEqual(result, 0)
        self.assertTrue(output.read_bytes().startswith(b"FAKE-OBJ\0"))
        self.assertNotIn(b"POISONED_BY_PARENT_ENVIRONMENT", output.read_bytes())
        self.assertTrue(pdb.read_bytes().startswith(b"FAKE-PDB\0"))
        audit_path = byte_identity.audit_object_path(
            self.build_dir, "fixture", "src/unit.cpp"
        )
        audit = json.loads(audit_path.read_text())
        self.assertEqual(audit["status"], "pass_through_not_composed")
        self.assertFalse(audit["may_claim_byte_identity"])
        self.assertTrue(audit["recipes_materialized_but_not_injected"])
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
            0,
        )
        verdict = json.loads(
            (self.build_dir / "byte-identity/audit/framework-verdict.json").read_text()
        )
        self.assertFalse(verdict["byte_identity_complete"])
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

    def test_failed_compiler_removes_stale_expected_object(self):
        self.materialize()
        output = self.build_dir / "objects/unit.obj"
        pdb = self.build_dir / "objects/unit.pdb"
        output.parent.mkdir(parents=True)
        output.write_bytes(b"STALE")
        pdb.write_bytes(b"STALE-PDB")
        previous = Path.cwd()
        old = os.environ.get("FAKE_FAIL")
        os.environ["FAKE_FAIL"] = "1"
        try:
            os.chdir(self.build_dir)
            result = byte_identity.main(self.launch_args(output, pdb))
        finally:
            os.chdir(previous)
            if old is None:
                os.environ.pop("FAKE_FAIL", None)
            else:
                os.environ["FAKE_FAIL"] = old
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
        old = os.environ.get("FAKE_SLEEP")
        os.environ["FAKE_SLEEP"] = "2"
        try:
            os.chdir(self.build_dir)
            result = byte_identity.main(self.launch_args(output, pdb))
        finally:
            os.chdir(previous)
            if old is None:
                os.environ.pop("FAKE_SLEEP", None)
            else:
                os.environ["FAKE_SLEEP"] = old
        self.assertEqual(result, 2)
        self.assertFalse(output.exists())
        self.assertFalse(pdb.exists())

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
            os.chdir(self.build_dir)
            result = byte_identity.main(arguments)
        finally:
            os.chdir(previous)
        self.assertEqual(result, 2)
        self.assertFalse(output.exists())
        self.assertFalse(pdb.exists())

    def test_unlisted_target_source_is_atomic_and_sanitized(self):
        # A different target may legitimately have a different baseline force
        # include.  The target-wide launcher must not union policies across the
        # whole manifest when it handles an unlisted source.
        other_include = self.include.with_name("other-target.h")
        other_include.write_text("#define OTHER_TARGET_HEADER 1\n")
        other_unit = json.loads(json.dumps(self.document["translation_units"][0]))
        other_unit["target"] = "other_target"
        other_unit["command_policy"]["allowed_force_includes"] = [
            {
                "path": "include/other-target.h",
                "sha256": byte_identity.sha256_file(other_include),
            }
        ]
        other_seed = 3
        other_header_sha = digest(entropy.generate(other_seed).encode("utf-8"))
        other_unit["donors"][0]["id"] = f"e_{other_header_sha[:12]}"
        other_unit["donors"][0]["recipe"]["seed"] = other_seed
        other_unit["donors"][0]["recipe"]["generated_header_sha256"] = other_header_sha
        self.document["translation_units"].append(other_unit)
        self.write_manifest()
        self.materialize()
        other = self.source.with_name("other.cpp")
        other.write_text("int other() { return 11; }\n")
        output = self.build_dir / "objects/other.obj"
        pdb = self.build_dir / "objects/other.pdb"
        output.parent.mkdir(parents=True)
        output.write_bytes(b"STALE")
        pdb.write_bytes(b"STALE-PDB")
        arguments = self.launch_args(output, pdb)
        arguments[arguments.index(str(self.source))] = str(other)
        previous = Path.cwd()
        old_cl = os.environ.get("CL")
        old_wine = os.environ.get("WINEDEBUG")
        os.environ["CL"] = "/DPOISONED_UNLISTED_CL"
        os.environ["WINEDEBUG"] = "POISONED_UNLISTED_WINE"
        try:
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
        self.assertTrue(output.read_bytes().startswith(b"FAKE-OBJ\0"))
        self.assertNotIn(b"POISONED_UNLISTED", output.read_bytes())
        self.assertTrue(pdb.read_bytes().startswith(b"FAKE-PDB\0"))
        audit = json.loads(
            byte_identity.audit_unlisted_path(
                self.build_dir, "fixture", "src/other.cpp"
            ).read_text()
        )
        self.assertEqual(audit["status"], "unlisted_atomic_pass_through")
        self.assertFalse(audit["may_claim_byte_identity"])

    def test_failed_unlisted_compile_removes_stale_outputs(self):
        self.materialize()
        other = self.source.with_name("other.cpp")
        other.write_text("int other() { return 11; }\n")
        output = self.build_dir / "objects/other.obj"
        pdb = self.build_dir / "objects/other.pdb"
        output.parent.mkdir(parents=True)
        output.write_bytes(b"STALE")
        pdb.write_bytes(b"STALE-PDB")
        arguments = self.launch_args(output, pdb)
        arguments[arguments.index(str(self.source))] = str(other)
        previous = Path.cwd()
        old = os.environ.get("FAKE_FAIL")
        os.environ["FAKE_FAIL"] = "1"
        try:
            os.chdir(self.build_dir)
            result = byte_identity.main(arguments)
        finally:
            os.chdir(previous)
            if old is None:
                os.environ.pop("FAKE_FAIL", None)
            else:
                os.environ["FAKE_FAIL"] = old
        self.assertEqual(result, 2)
        self.assertFalse(output.exists())
        self.assertFalse(pdb.exists())
        self.assertFalse(
            byte_identity.audit_unlisted_path(
                self.build_dir, "fixture", "src/other.cpp"
            ).exists()
        )

    def test_repository_manifest_and_cmake_module_are_native_valid(self):
        repository_manifest = ROOT / "tools/byte_identity_manifest.json"
        module_text = (ROOT / "cmake/byte_identity.cmake").read_text()
        self.assertIn("if(NOT CMAKE_HOST_UNIX)", module_text)
        self.assertNotIn("if(NOT UNIX)", module_text)
        with tempfile.TemporaryDirectory() as build:
            state = byte_identity.validate_manifest(
                repository_manifest, ROOT, Path(build)
            )
        self.assertEqual(state["translation_units"][0]["source"],
                         "LEGO1/lego/legoomni/src/entity/legoworld.cpp")
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "check.cmake"
            script.write_text(
                f'include("{ROOT / "cmake/byte_identity.cmake"}")\n'
            )
            subprocess.run(["cmake", "-P", str(script)], check=True,
                           capture_output=True, text=True)

    def test_cmake_module_plans_and_materializes_without_compiling(self):
        fixture_tools = self.source_dir / "tools"
        fixture_cmake = self.source_dir / "cmake"
        fixture_cmake.mkdir()
        shutil.copy2(TOOLS / "byte_identity.py", fixture_tools / "byte_identity.py")
        shutil.copy2(TOOLS / "entropy.py", fixture_tools / "entropy.py")
        shutil.copy2(ROOT / "cmake/byte_identity.cmake",
                     fixture_cmake / "byte_identity.cmake")
        (self.source_dir / "CMakeLists.txt").write_text(
            "\n".join(
                [
                    "cmake_minimum_required(VERSION 3.15 FATAL_ERROR)",
                    "project(byte_identity_native_fixture CXX)",
                    "add_library(fixture STATIC src/unit.cpp)",
                    "set(ISLE_BYTE_IDENTICAL ON)",
                    "set(ISLE_PER_OBJECT_PDB ON)",
                    "set(CMAKE_BUILD_TYPE Debug)",
                    'set(CMAKE_CXX_FLAGS_DEBUG "/Zi")',
                    'string(APPEND CMAKE_CXX_COMPILE_OBJECT " /Fd<OBJECT>.pdb")',
                    "set(ISLE_INCLUDE_ENTROPY OFF)",
                    'set(ISLE_TU_ENTROPY_MANIFEST "")',
                    "set(MSVC_FOR_DECOMP TRUE)",
                    f'set(CMAKE_CXX_COMPILER "{self.compiler}")',
                    'set(CMAKE_CXX_COMPILER_ID "MSVC")',
                    'set(CMAKE_CXX_COMPILER_VERSION "10.20")',
                    'include("${PROJECT_SOURCE_DIR}/cmake/byte_identity.cmake")',
                    "isle_enable_byte_identity(",
                    '  "${PROJECT_SOURCE_DIR}/tools/byte_identity_manifest.json")',
                    "",
                ]
            )
        )
        cmake_build = self.directory / "cmake-build"
        generator = "Ninja" if shutil.which("ninja") else "Unix Makefiles"
        subprocess.run(
            ["cmake", "-S", str(self.source_dir), "-B", str(cmake_build),
             "-G", generator],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            ["cmake", "--build", str(cmake_build), "--target",
             "byte-identity-materialize"],
            check=True,
            capture_output=True,
            text=True,
        )
        generated = list((cmake_build / "byte-identity/generated").glob("entropy_*.h"))
        self.assertEqual(len(generated), 1)
        self.assertEqual(
            byte_identity.sha256_file(generated[0]),
            self.document["translation_units"][0]["donors"][0]["recipe"][
                "generated_header_sha256"
            ],
        )


if __name__ == "__main__":
    unittest.main()
