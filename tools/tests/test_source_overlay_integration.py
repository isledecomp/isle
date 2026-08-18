import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import byte_identity  # noqa: E402


class SourceOverlayIntegrationTests(unittest.TestCase):
    def test_checked_manifest_reconstructs_the_complete_effective_source_view(self):
        source_root = Path(__file__).resolve().parents[2]
        manifest = byte_identity.strict_json_loads(
            (source_root / "tools/byte_identity_manifest.json").read_bytes()
        )
        overlay = manifest["source_overlay"]

        normalized = byte_identity.validate_source_overlay(overlay, source_root)

        self.assertEqual(len(normalized["outputs"]), 173)
        self.assertEqual(
            sum(len(output["operations"]) for output in normalized["outputs"]),
            417,
        )
        self.assertEqual(
            len(normalized["graph"]["generated_translation_units"]), 20
        )
        outputs_by_path = {
            output["logical_path"]: output for output in normalized["outputs"]
        }
        for generated in normalized["graph"]["generated_translation_units"]:
            logical_path = generated["logical_path"]
            self.assertEqual(outputs_by_path[logical_path]["clean"]["state"], "absent")
            self.assertFalse((source_root / logical_path).exists())
            self.assertFalse((source_root / logical_path).is_symlink())
        # dsound is original CONFIG build configuration (retail carries a
        # zero-function DSOUND.dll import descriptor), so it lives on the
        # ordinary CMake link line rather than as an overlay admission.
        self.assertEqual(normalized["graph"]["link_admissions"], [])
        self.assertEqual(
            sum(output["clean"]["state"] == "present"
                for output in normalized["outputs"]),
            147,
        )
        self.assertEqual(
            sum(output["clean"]["state"] == "absent"
                for output in normalized["outputs"]),
            26,
        )

        for output in normalized["outputs"]:
            expected = output["effective"]
            actual = normalized["effective_by_path"][output["logical_path"]]
            self.assertEqual(actual["sha256"], expected["baseline_sha256"])
            self.assertEqual(actual["size"], expected["baseline_size"])
            self.assertEqual(
                actual["line_count"], expected["baseline_line_count"]
            )
            self.assertEqual(
                actual["significant_token_sha256"],
                expected["baseline_significant_token_sha256"],
            )

        forbidden_payload_keys = {
            "raw", "text", "template", "command", "source_bytes",
            "source_text", "free_form", "freeform", "payload",
        }

        def assert_no_opaque_payload(value, path="source_overlay"):
            if isinstance(value, dict):
                self.assertFalse(
                    forbidden_payload_keys.intersection(value),
                    f"opaque payload field at {path}",
                )
                for key, child in value.items():
                    assert_no_opaque_payload(child, f"{path}.{key}")
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    assert_no_opaque_payload(child, f"{path}[{index}]")

        assert_no_opaque_payload(overlay)

    def test_relocated_ranges_keep_their_reccmp_annotations(self):
        source_root = Path(__file__).resolve().parents[2]
        manifest = byte_identity.strict_json_loads(
            (source_root / "tools/byte_identity_manifest.json").read_bytes()
        )
        normalized = byte_identity.validate_source_overlay(
            manifest["source_overlay"], source_root
        )
        clean_inputs = {}
        for output in normalized["outputs"]:
            path = output["logical_path"]
            clean_inputs[path] = (
                (source_root / path).read_bytes()
                if output["clean"]["state"] == "present" else b""
            )
        rendered = byte_identity.render_source_overlay_outputs(
            normalized, clean_inputs
        )
        self.assertIn(
            b"// FUNCTION: LEGO1 0x10003bd0",
            rendered["LEGO1/realtime/vector3dtail.inl.h"],
        )
        self.assertIn(
            b"// GLOBAL: LEGO1 0x100f435c",
            rendered["LEGO1/lego/legoomni/src/paths/legopathctrledge.cpp"],
        )


if __name__ == "__main__":
    unittest.main()
