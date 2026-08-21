"""Tests for the OVERLAID sibling instruction-source role.

`cross_tu_instruction_source_only_v1` is the provenance object the framework
already admits for a whole-body cross-TU donor
(`cross_tu_complete_target_only_v1`), confined to a strictly smaller
transfer: the manifest-pinned instruction bytes of one cross-TU instruction
hybrid.  Its whole reason to exist is a distinction the clean cross-TU recipe
cannot express, and these tests fix that distinction:

  * the clean recipe pins the CHECKED-IN text and therefore refuses an
    overlaid donor, because for an overlaid TU the checked-in text is not
    what the build compiles -- that refusal is regression-guarded here;
  * this role pins the EFFECTIVE text, and requires the overlay to be
    DECLARED, matched against the manifest's own `source_overlay` record and
    against the rendering that overlay actually produced.

The adversarial cases: an overlaid donor whose overlay is not declared, a
declared overlay that does not match the rendering, a rendering that is not
the unmodified effective TU, a donor path with no overlay at all, a range that
fails line certification, and an image that differs from the pinned retail
oracle.  Each refuses with its own message.
"""
from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import byte_identity  # noqa: E402
# Imported as a MODULE, never by name: binding the fixture class into this
# module's namespace would make pytest collect and re-run its whole suite here.
import test_comdat_splice_extensions as splice  # noqa: E402

TARGET_SYMBOL = splice.TARGET_SYMBOL
_patched_target_line_boundary = splice._patched_target_line_boundary

DONOR_RELATIVE = "sibling/donor.cpp"
OWNER_RELATIVE = "owner/owner.cpp"
CLEAN_PAYLOAD = b"int sibling_fixture;\n"
EFFECTIVE_PAYLOAD = b"class MxUnkRecordFixture00;\nint sibling_fixture;\n"
RATIONALE = (
    "Fixture sibling translation unit compiled from the declared and pinned "
    "effective rendering of its checked-in source."
)


def overlay_record(payload=EFFECTIVE_PAYLOAD, clean=CLEAN_PAYLOAD):
    return {
        "logical_path": DONOR_RELATIVE,
        "clean": {
            "state": "present",
            "baseline_sha256": hashlib.sha256(clean).hexdigest(),
        },
        "effective": {
            "baseline_sha256": hashlib.sha256(payload).hexdigest(),
            "baseline_size": len(payload),
            "baseline_line_count": payload.count(b"\n"),
        },
    }


def recipe_for(payload=EFFECTIVE_PAYLOAD, clean=CLEAN_PAYLOAD):
    return {
        "kind": byte_identity.CROSS_TU_INSTRUCTION_SOURCE_RECIPE,
        "donor_source": DONOR_RELATIVE,
        "donor_source_overlay": {
            "declared": True,
            "clean_source_sha256": hashlib.sha256(clean).hexdigest(),
            "effective_source_sha256": hashlib.sha256(payload).hexdigest(),
            "effective_source_size": len(payload),
            "effective_source_line_count": payload.count(b"\n"),
        },
        "donor_effective_source_sha256": hashlib.sha256(payload).hexdigest(),
        "rendered_source_sha256": hashlib.sha256(payload).hexdigest(),
        "rendered_source_size": len(payload),
        "rendered_source_line_count": payload.count(b"\n"),
        "compile_lane": {"required_define": "FIXTURE_DEFINE"},
        "emission_policy": "unmodified_effective_translation_unit_only",
        "role_policy": byte_identity.CROSS_TU_INSTRUCTION_SOURCE_RECIPE_POLICY,
        "authenticity_rationale": RATIONALE,
    }


class OverlaidCrossTuInstructionSourceRecipeTests(unittest.TestCase):
    """The recipe's own obligations, one refusal at a time."""

    def validate(self, recipe, *, overlay=None, rendered=None, root=None,
                 owner=OWNER_RELATIVE):
        overlay_map = (
            {} if overlay is False
            else {DONOR_RELATIVE: overlay or overlay_record()}
        )
        rendered_map = (
            {} if rendered is None else {DONOR_RELATIVE: rendered}
        )
        return byte_identity.validate_overlaid_cross_tu_instruction_source_recipe(
            recipe, root, owner, overlay_map, rendered_map, "fixture")

    def temporary_root(self, clean=CLEAN_PAYLOAD):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        donor = root / DONOR_RELATIVE
        donor.parent.mkdir(parents=True, exist_ok=True)
        donor.write_bytes(clean)
        return root

    # -- positive control ------------------------------------------------
    def test_positive_control_accepts_a_declared_and_pinned_overlay(self):
        root = self.temporary_root()
        normalized = self.validate(
            recipe_for(), root=root, rendered=EFFECTIVE_PAYLOAD)
        self.assertEqual(normalized["donor_source"], DONOR_RELATIVE)
        self.assertTrue(normalized["donor_source_overlay"]["declared"])
        self.assertEqual(
            normalized["donor_effective_source_sha256"],
            hashlib.sha256(EFFECTIVE_PAYLOAD).hexdigest())
        # The role pins BOTH texts: the checked-in one and the effective one,
        # and they are genuinely different.
        self.assertNotEqual(
            normalized["donor_source_overlay"]["clean_source_sha256"],
            normalized["donor_source_overlay"]["effective_source_sha256"])

    # -- adversarial case 1: the overlay is not declared -------------------
    def test_refuses_an_overlaid_donor_whose_overlay_is_not_declared(self):
        root = self.temporary_root()
        recipe = recipe_for()
        recipe["donor_source_overlay"]["declared"] = False
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "overlay is not declared"):
            self.validate(recipe, root=root, rendered=EFFECTIVE_PAYLOAD)

    def test_refuses_an_overlay_declaration_with_missing_fields(self):
        root = self.temporary_root()
        recipe = recipe_for()
        del recipe["donor_source_overlay"]["effective_source_line_count"]
        with self.assertRaises(byte_identity.ByteIdentityError):
            self.validate(recipe, root=root, rendered=EFFECTIVE_PAYLOAD)

    # -- adversarial case 2: the declaration does not match ----------------
    def test_refuses_a_declared_overlay_that_differs_from_the_manifest(self):
        root = self.temporary_root()
        for field, value in (
            ("effective_source_sha256", "0" * 64),
            ("effective_source_size", len(EFFECTIVE_PAYLOAD) + 1),
            ("effective_source_line_count",
             EFFECTIVE_PAYLOAD.count(b"\n") + 1),
            ("clean_source_sha256", "1" * 64),
        ):
            recipe = recipe_for()
            recipe["donor_source_overlay"][field] = value
            recipe["donor_effective_source_sha256"] = (
                recipe["donor_source_overlay"]["effective_source_sha256"])
            recipe["rendered_source_sha256"] = (
                recipe["donor_source_overlay"]["effective_source_sha256"])
            recipe["rendered_source_size"] = (
                recipe["donor_source_overlay"]["effective_source_size"])
            recipe["rendered_source_line_count"] = (
                recipe["donor_source_overlay"]["effective_source_line_count"])
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                        byte_identity.ByteIdentityError,
                        "differs from the manifest's effective rendering"):
                    self.validate(recipe, root=root,
                                  rendered=EFFECTIVE_PAYLOAD)

    def test_refuses_a_donor_effective_sha_that_is_not_the_declaration(self):
        root = self.temporary_root()
        recipe = recipe_for()
        recipe["donor_effective_source_sha256"] = hashlib.sha256(
            CLEAN_PAYLOAD).hexdigest()
        with self.assertRaisesRegex(
                byte_identity.ByteIdentityError,
                "not the unmodified effective translation unit"):
            self.validate(recipe, root=root, rendered=EFFECTIVE_PAYLOAD)

    def test_refuses_a_rendering_that_carries_a_generated_payload(self):
        """A carrier stapled onto the sibling is not this role's business."""
        root = self.temporary_root()
        carried = EFFECTIVE_PAYLOAD + b"class MxUnkRecVC000;\n"
        recipe = recipe_for()
        recipe["rendered_source_sha256"] = hashlib.sha256(carried).hexdigest()
        recipe["rendered_source_size"] = len(carried)
        recipe["rendered_source_line_count"] = carried.count(b"\n")
        with self.assertRaisesRegex(
                byte_identity.ByteIdentityError,
                "not the unmodified effective translation unit"):
            self.validate(recipe, root=root, rendered=EFFECTIVE_PAYLOAD)

    def test_refuses_a_rendering_that_differs_from_the_overlay_output(self):
        root = self.temporary_root()
        with self.assertRaisesRegex(
                byte_identity.ByteIdentityError,
                "differs from the overlay's own output"):
            self.validate(recipe_for(), root=root,
                          rendered=EFFECTIVE_PAYLOAD + b"drift\n")

    # -- adversarial case 3: there is no overlay at all --------------------
    def test_refuses_a_donor_path_with_no_effective_overlay(self):
        root = self.temporary_root()
        with self.assertRaisesRegex(
                byte_identity.ByteIdentityError,
                "no effective source overlay to declare"):
            self.validate(recipe_for(), overlay=False, root=root,
                          rendered=EFFECTIVE_PAYLOAD)

    # -- the checked-in text is pinned too ---------------------------------
    def test_refuses_a_checked_in_source_that_drifted_from_its_pin(self):
        root = self.temporary_root(clean=CLEAN_PAYLOAD + b"drift\n")
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "differs from its checked-in pin"):
            self.validate(recipe_for(), root=root, rendered=EFFECTIVE_PAYLOAD)

    def test_refuses_a_redirected_donor_source(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        (root / "sibling").mkdir(parents=True)
        real = root / "sibling" / "real.cpp"
        real.write_bytes(CLEAN_PAYLOAD)
        (root / DONOR_RELATIVE).symlink_to(real.name)
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "redirected or non-regular"):
            self.validate(recipe_for(), root=root, rendered=EFFECTIVE_PAYLOAD)

    def test_refuses_the_owner_translation_unit_as_its_own_donor(self):
        root = self.temporary_root()
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "not cross-translation-unit"):
            self.validate(recipe_for(), root=root,
                          rendered=EFFECTIVE_PAYLOAD, owner=DONOR_RELATIVE)

    def test_refuses_a_wrong_role_policy_or_emission_policy(self):
        root = self.temporary_root()
        for field, value, message in (
            ("role_policy",
             byte_identity.CROSS_TU_COMPLETE_TARGET_RECIPE_POLICY,
             "role_policy differs"),
            ("emission_policy",
             "unmodified_checked_in_translation_unit_only",
             "emission_policy differs"),
        ):
            recipe = recipe_for()
            recipe[field] = value
            with self.subTest(field=field):
                with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                            message):
                    self.validate(recipe, root=root,
                                  rendered=EFFECTIVE_PAYLOAD)

    # -- the bar this role does NOT move -----------------------------------
    def test_clean_cross_tu_recipe_still_refuses_an_overlaid_donor(self):
        root = self.temporary_root()
        clean_recipe = {
            "kind": byte_identity.CLEAN_CURRENT_SOURCE_CROSS_TU_RECIPE,
            "donor_source": DONOR_RELATIVE,
            "source_sha256": hashlib.sha256(CLEAN_PAYLOAD).hexdigest(),
            "compile_lane": {"required_define": "FIXTURE_DEFINE"},
            "emission_policy":
                "unmodified_checked_in_translation_unit_only",
            "authenticity_rationale": RATIONALE,
        }
        byte_identity.validate_clean_current_source_cross_tu_recipe(
            clean_recipe, root, OWNER_RELATIVE, set(), "fixture")
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "has an effective source overlay"):
            byte_identity.validate_clean_current_source_cross_tu_recipe(
                clean_recipe, root, OWNER_RELATIVE, {DONOR_RELATIVE},
                "fixture")


class OverlaidCrossTuInstructionSourceBindingTests(unittest.TestCase):
    """The role is confined to exactly one instruction-donor consumer."""

    def bind(self, primary, non_primary, bound):
        byte_identity.require_cross_tu_instruction_source_bindings(
            {"d_sib"}, primary, non_primary, bound, "fixture")

    def test_accepts_exactly_one_instruction_use(self):
        self.bind([], ["d_sib"], ["d_sib"])

    def test_rejects_an_unbound_recipe(self):
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "consumed exactly once"):
            self.bind([], [], [])

    def test_rejects_a_second_instruction_use(self):
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "consumed exactly once"):
            self.bind([], ["d_sib", "d_sib"], ["d_sib", "d_sib"])

    def test_rejects_a_primary_use(self):
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "may not be primary donors"):
            self.bind(["d_sib"], ["d_sib"], ["d_sib"])

    def test_rejects_a_second_non_primary_role(self):
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "another non-primary role"):
            self.bind([], ["d_sib", "d_sib"], ["d_sib"])

    def test_preflight_refuses_a_whole_body_or_mosaic_consumer(self):
        """It may supply instruction bytes and nothing else."""
        manifest = {
            "source_overlay": {"outputs": []},
            "translation_units": [{
                "source": OWNER_RELATIVE,
                "donors": [{
                    "id": "d_sib",
                    "recipe": {
                        "kind":
                            byte_identity.CROSS_TU_INSTRUCTION_SOURCE_RECIPE,
                        "role_policy": byte_identity
                        .CROSS_TU_INSTRUCTION_SOURCE_RECIPE_POLICY,
                    },
                }],
                "functions": [{
                    "mangled": "?Target@@YAXXZ",
                    "donor": "d_target",
                    "instruction_donor": "d_sib",
                    "splice_class": "retail_exact_instruction_mosaic",
                }],
            }],
        }
        with self.assertRaisesRegex(
                byte_identity.ByteIdentityError,
                "only cross-TU hybrid instruction bytes"):
            byte_identity.require_manifest_source_refactor_role_preflight(
                manifest, "manifest")

    def test_preflight_accepts_the_cross_tu_hybrid_consumer(self):
        manifest = {
            "source_overlay": {"outputs": []},
            "translation_units": [{
                "source": OWNER_RELATIVE,
                "donors": [{
                    "id": "d_sib",
                    "recipe": {
                        "kind":
                            byte_identity.CROSS_TU_INSTRUCTION_SOURCE_RECIPE,
                        "role_policy": byte_identity
                        .CROSS_TU_INSTRUCTION_SOURCE_RECIPE_POLICY,
                    },
                }],
                "functions": [{
                    "mangled": "?Target@@YAXXZ",
                    "donor": "d_target",
                    "instruction_donor": "d_sib",
                    "splice_class":
                        byte_identity.CROSS_TU_INSTRUCTION_HYBRID_RESIZE_CLASS,
                }],
            }],
        }
        byte_identity.require_manifest_source_refactor_role_preflight(
            manifest, "manifest")


class OverlaidCrossTuInstructionSourceComposerTests(unittest.TestCase):
    """The obligations the role does NOT touch, exercised through it.

    The donor's provenance changes; the transfer's proof does not.  Line
    certification on both sides, relocation disjointness and retail equality
    are the existing class's, and they still refuse.
    """

    def fixture(self):
        return splice.CrossTuInstructionHybridResizeTests.fixture(self)

    def compose(self, seed, target_donor, instruction_donor, function,
                retail):
        return (
            byte_identity
            .compose_retail_exact_cross_tu_instruction_hybrid_resize(
                seed, target_donor, instruction_donor, function, retail))

    def test_positive_control_is_retail_exact(self):
        (seed, target, instruction, function, retail, _) = self.fixture()
        _, detail = self.compose(seed, target, instruction, function, retail)
        self.assertTrue(detail["retail_exact"])

    # -- adversarial case 4: the range is not line-certified ---------------
    def test_refuses_a_range_without_a_preceding_line_boundary(self):
        (seed, target, instruction, function, retail, _) = self.fixture()
        start = function["instruction_ranges"][0]["target_start"]
        # Move the donor's only line-table data row PAST the range start, so
        # nothing certifies the stream that contains it.
        moved = _patched_target_line_boundary(target, start + 1)
        with self.assertRaisesRegex(
                byte_identity.ByteIdentityError,
                "no preceding compiler line boundary"):
            self.compose(seed, moved, instruction, function, retail)

    def test_refuses_an_instruction_donor_without_a_line_boundary(self):
        (seed, target, instruction, function, retail, _) = self.fixture()
        start = function["instruction_ranges"][0]["instruction_donor_start"]
        moved = _patched_target_line_boundary(instruction, start + 1)
        with self.assertRaisesRegex(
                byte_identity.ByteIdentityError,
                "no preceding compiler line boundary"):
            self.compose(seed, target, moved, function, retail)

    # -- adversarial case 5: the image is not the oracle -------------------
    def test_refuses_an_image_that_differs_from_the_pinned_oracle(self):
        (seed, target, instruction, function, retail, _) = self.fixture()
        wrong = bytearray(retail)
        wrong[9] ^= 0xFF          # a byte no relocation masks
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "retail"):
            self.compose(seed, target, instruction, function, bytes(wrong))

    def test_refuses_a_range_that_overlaps_a_relocation_operand(self):
        (seed, target, instruction, function, retail, _) = self.fixture()
        coff = byte_identity.CoffObject(target)
        primary = coff.function_section(TARGET_SYMBOL)
        body = byte_identity.coff_body(coff, primary)
        row = byte_identity.detailed_relocations(coff, primary)[0]
        bad = copy.deepcopy(function)
        item = bad["instruction_ranges"][0]
        start = row["offset"]
        item["target_start"] = item["instruction_donor_start"] = start
        item["target_end"] = item["instruction_donor_end"] = start + 4
        item["target_bytes"] = body[start:start + 4].hex()
        item["target_sha256"] = hashlib.sha256(
            bytes(body[start:start + 4])).hexdigest()
        instruction_coff = byte_identity.CoffObject(instruction)
        instruction_body = byte_identity.coff_body(
            instruction_coff,
            instruction_coff.function_section(TARGET_SYMBOL))
        item["instruction_donor_bytes"] = instruction_body[
            start:start + 4].hex()
        item["instruction_donor_sha256"] = hashlib.sha256(
            bytes(instruction_body[start:start + 4])).hexdigest()
        with self.assertRaises(byte_identity.ByteIdentityError):
            self.compose(seed, target, instruction, bad, retail)


class LiveManifestRoleTests(unittest.TestCase):
    """Whatever is live in the repo manifest must satisfy its own role."""

    def test_every_live_cross_tu_instruction_donor_is_role_pinned(self):
        manifest = json.loads(
            (TOOLS / "byte_identity_manifest.json").read_text())
        overlay_outputs = manifest["source_overlay"]["outputs"]
        overlaid = {item["path"] for item in overlay_outputs}
        matches = [
            (unit, function)
            for unit in manifest["translation_units"]
            for function in unit.get("functions", [])
            if function.get("splice_class")
            == byte_identity.CROSS_TU_INSTRUCTION_HYBRID_RESIZE_CLASS
        ]
        overlay_map = {
            item["logical_path"]: item
            for item in byte_identity.validate_source_overlay(
                manifest["source_overlay"], ROOT)["outputs"]
        }
        for unit, function in matches:
            donor = next(
                item for item in unit["donors"]
                if item["id"] == function["instruction_donor"])
            kind = donor["recipe"]["kind"]
            with self.subTest(source=unit["source"], kind=kind):
                if kind == byte_identity.CROSS_TU_INSTRUCTION_SOURCE_RECIPE:
                    normalized = (
                        byte_identity
                        .validate_overlaid_cross_tu_instruction_source_recipe(
                            donor["recipe"], ROOT, unit["source"],
                            overlay_map, {}, "fixture"))
                    # The role is only ever for an OVERLAID sibling, and the
                    # clean recipe must still refuse that same donor.
                    self.assertIn(normalized["donor_source"], overlaid)
                    self.assertEqual(
                        donor["authenticity"],
                        "effective_checked_in_source_only")
                else:
                    self.assertEqual(
                        kind,
                        byte_identity.CLEAN_CURRENT_SOURCE_CROSS_TU_RECIPE)
                    normalized = (
                        byte_identity
                        .validate_clean_current_source_cross_tu_recipe(
                            donor["recipe"], ROOT, unit["source"], overlaid,
                            "fixture"))
                    self.assertNotIn(normalized["donor_source"], overlaid)


if __name__ == "__main__":
    unittest.main()
