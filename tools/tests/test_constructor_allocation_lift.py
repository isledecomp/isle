"""Tests for the donor-private constructor allocation lift.

Three amendments meet here and each one has to stay closed:

* ``member_signature_v1`` grew a ``constructor`` kind with a typed parameter
  list, a one-element specifier enum, and an INVERTED A7a (the class must
  exist and the overload must not);
* ``constructor_allocation_lift_v1`` renders the caller's removed statements
  and the lifted constructor body from ONE parameter set, bound to a semantic
  witness out of the checked-in header;
* ``compose_same_slot_resize`` accepts a shorter ``.debug$S`` closure child
  only behind a pinned, source-bound local-set delta that also makes the
  composed output drop the stale record.

Every test below is a refusal test unless it says otherwise.
"""
from __future__ import annotations

import copy
import hashlib
import json
import struct
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import byte_identity  # noqa: E402
from test_comdat_splice_extensions import (  # noqa: E402
    DONOR_SIZE, RETAIL_ADDRESS, SEED_SIZE, TARGET_SYMBOL,
    function_record, make_divergent_coff, retail_body_for,
)

HEADER = "LEGO1/lego/legoomni/include/legocachesoundmanager.h"
UNIT = "LEGO1/lego/legoomni/src/audio/legocachesoundmanager.cpp"
MANGLED = "?FindSoundByKey@LegoCacheSoundManager@@QAEPAVLegoCacheSound@@PBD@Z"

LIFT_PARAMS = {
    "k": "ctor_alloc_lift",
    "role": "call_site",
    "class_identifier": "LegoCacheSoundEntry",
    "parameter_identifier": "p_key",
    "buffer_member": "m_name",
    "buffer_cast_type": "char*",
    "element_type": "char",
    "extent_function": "strlen",
    "copy_function": "strcpy",
    "null_members": ["m_sound"],
    "caller_result_identifier": "key",
    "caller_result_type": "char*",
    "null_argument_position": 0,
    "iterator_type": "Set100d6b4c::iterator",
    "iterator_identifier": "it",
    "container_identifier": "m_set",
    "find_member": "find",
    "declaration_indent": "\t",
}

CHECKED_IN_INPUT = (
    b"\tchar* key = new char[strlen(p_key) + 1];\n"
    b"\tstrcpy(key, p_key);\n\n"
    b"\tSet100d6b4c::iterator it = m_set.find("
    b"LegoCacheSoundEntry(NULL, key));\n"
)


def lift(**overrides):
    return {**LIFT_PARAMS, **overrides}


def validated_lift(**overrides):
    return byte_identity.validate_source_overlay_generator(
        lift(**overrides), "gen")["params"]


class ConstructorMemberSignatureTests(unittest.TestCase):
    """A7 for the amended kind: closed schema, closed name, closed forms."""

    def _gen(self, **overrides):
        params = {
            "class_identifier": "LegoCacheSoundEntry",
            "member_identifier": "LegoCacheSoundEntry",
            "kind": "constructor",
            "form": "in_class_declaration",
            "parameters": [{"type": "const char*", "identifier": "p_key"}],
        }
        params.update(overrides)
        return {"k": "member_sig", **params}

    def _render(self, **overrides):
        return byte_identity.render_source_overlay_generator(
            byte_identity.validate_source_overlay_generator(
                self._gen(**overrides), "gen"))

    def test_renders_exactly_the_two_authorised_constructor_forms(self):
        self.assertEqual(self._render(nl=False),
                         b"LegoCacheSoundEntry(const char* p_key);")
        self.assertEqual(
            self._render(form="qualified_definition_header",
                         specifiers=["inline"], nl=False),
            b"inline LegoCacheSoundEntry::LegoCacheSoundEntry"
            b"(const char* p_key)")
        # no body, no return type, no terminator on the definition header
        rendered = self._render(form="qualified_definition_header",
                                specifiers=["inline"], nl=False)
        self.assertNotIn(b"{", rendered)
        self.assertFalse(rendered.endswith(b";"))

    def test_rejects_a_missing_parameter_list(self):
        generator = self._gen()
        del generator["parameters"]
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "missing=\\['parameters'\\]"):
            byte_identity.validate_source_overlay_generator(generator, "gen")

    def test_rejects_a_member_name_that_is_not_the_class(self):
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "must equal the class identifier"):
            byte_identity.validate_source_overlay_generator(
                self._gen(member_identifier="NotTheClass"), "gen")

    def test_rejects_specifiers_outside_the_one_element_enum(self):
        for specifiers in (["static"], ["inline", "static"], [], "inline",
                           ["INLINE"]):
            with self.subTest(specifiers=specifiers):
                with self.assertRaisesRegex(
                        byte_identity.ByteIdentityError,
                        'specifiers must be exactly \\["inline"\\]'):
                    byte_identity.validate_source_overlay_generator(
                        self._gen(form="qualified_definition_header",
                                  specifiers=specifiers), "gen")

    def test_rejects_inline_on_an_in_class_declaration(self):
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "admitted only on the qualified "
                                    "definition header form"):
            byte_identity.validate_source_overlay_generator(
                self._gen(specifiers=["inline"]), "gen")

    def test_rejects_an_unbounded_or_unnamed_parameter_list(self):
        cases = {
            "empty": [],
            "too_many": [{"type": "int", "identifier": f"p{index}"}
                         for index in range(5)],
            "unnamed": [{"type": "const char*"}],
            "duplicate": [{"type": "int", "identifier": "p"},
                          {"type": "int", "identifier": "p"}],
        }
        for name, parameters in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(byte_identity.ByteIdentityError):
                    byte_identity.validate_source_overlay_generator(
                        self._gen(parameters=parameters), "gen")

    def test_rejects_a_free_text_parameter_type(self):
        for spelling in ("void (*)()", "char* /* comment */",
                         "struct { int x; }", "T<"):
            with self.subTest(spelling=spelling):
                with self.assertRaises(byte_identity.ByteIdentityError):
                    byte_identity.validate_source_overlay_generator(
                        self._gen(parameters=[{"type": spelling,
                                               "identifier": "p"}]), "gen")

    def test_destructor_kind_still_admits_no_parameters(self):
        with self.assertRaises(byte_identity.ByteIdentityError):
            byte_identity.validate_source_overlay_generator(
                {"k": "member_sig",
                 "class_identifier": "LegoCacheSoundEntry",
                 "member_identifier": "LegoCacheSoundEntry",
                 "kind": "destructor", "form": "in_class_declaration",
                 "parameters": [{"type": "int", "identifier": "p"}]}, "gen")


class ConstructorA7aInversionTests(unittest.TestCase):
    """A7a is a gate for constructors, not a tautology."""

    def setUp(self):
        self.header = (ROOT / HEADER).read_bytes()

    def test_existential_half_asks_only_whether_the_class_exists(self):
        self.assertTrue(byte_identity.source_overlay_member_is_declared(
            self.header, "LegoCacheSoundEntry", "LegoCacheSoundEntry",
            "constructor"))
        self.assertFalse(byte_identity.source_overlay_member_is_declared(
            self.header, "NoSuchClass", "NoSuchClass", "constructor"))

    def test_freshness_half_sees_the_existing_overloads(self):
        count = byte_identity.source_overlay_constructor_overload_count
        existing = [{"type": "LegoCacheSound*", "identifier": "p_sound"}]
        self.assertEqual(
            count(self.header, "LegoCacheSoundEntry",
                  [byte_identity.validate_source_overlay_parameter(
                      item, "p") for item in existing]),
            1)
        fresh = [byte_identity.validate_source_overlay_parameter(
            {"type": "const char*", "identifier": "p_key"}, "p")]
        self.assertEqual(
            count(self.header, "LegoCacheSoundEntry", fresh), 0)

    def test_parameter_names_do_not_make_an_overload_fresh(self):
        count = byte_identity.source_overlay_constructor_overload_count
        renamed = [byte_identity.validate_source_overlay_parameter(
            {"type": "LegoCacheSound*", "identifier": "p_other"}, "p")]
        self.assertEqual(
            count(self.header, "LegoCacheSoundEntry", renamed), 1)

    def _recipe(self, parameters):
        header = (ROOT / HEADER).read_bytes()
        anchor_line = (
            b"\tLegoCacheSoundEntry(LegoCacheSound* p_sound) : "
            b"m_sound(p_sound), m_name(p_sound->GetUnknown0x48().GetData())"
            b" {}\n")
        seat = header.index(anchor_line) + len(anchor_line)
        tokens = byte_identity.source_overlay_tokens(header)
        index = next(i for i in range(len(tokens) + 1)
                     if (tokens[i - 1][2] if i else 0) <= seat
                     <= (tokens[i][1] if i < len(tokens) else len(header)))
        signature = ([t[0] for t in tokens[index - 32:index]] + ["<SEAT>"]
                     + [t[0] for t in tokens[index:index + 32]])
        before, after = byte_identity.source_overlay_seat_lines(header, seat)
        return {
            "kind": "donor_source_overlay",
            "compile_lane": {"required_define": "DIRECTX5_SDK"},
            "renderings": [{
                "path": HEADER,
                "clean_sha256": hashlib.sha256(header).hexdigest(),
                "rendered_sha256": "0" * 64,
                "operations": [{
                    "op": "insert", "id": "op_probe",
                    "anchor": {
                        "ctx": byte_identity.source_overlay_token_sha256(
                            signature),
                        "line_before": hashlib.sha256(before).hexdigest(),
                        "line_after": hashlib.sha256(after).hexdigest(),
                    },
                    "gen": {"k": "member_sig",
                            "class_identifier": "LegoCacheSoundEntry",
                            "member_identifier": "LegoCacheSoundEntry",
                            "kind": "constructor",
                            "form": "in_class_declaration",
                            "parameters": parameters},
                }],
            }],
        }

    def test_recipe_refuses_an_overload_that_already_exists(self):
        recipe = self._recipe([{"type": "LegoCacheSound*",
                                "identifier": "p_sound"}])
        with self.assertRaisesRegex(
                byte_identity.ByteIdentityError,
                "already declares this parameter type sequence"):
            byte_identity.validate_donor_source_overlay_recipe(recipe, ROOT)

    def test_recipe_refuses_a_class_absent_from_checked_in_source(self):
        recipe = self._recipe([{"type": "const char*",
                                "identifier": "p_key"}])
        recipe["renderings"][0]["operations"][0]["gen"].update({
            "class_identifier": "NoSuchClass",
            "member_identifier": "NoSuchClass",
        })
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "is not declared in any"):
            byte_identity.validate_donor_source_overlay_recipe(recipe, ROOT)

    def test_recipe_accepts_the_fresh_overload(self):
        recipe = self._recipe([{"type": "const char*",
                                "identifier": "p_key"}])
        validated = byte_identity.validate_donor_source_overlay_recipe(
            recipe, ROOT)
        self.assertEqual(len(validated["renderings"]), 1)


class ConstructorAllocationLiftGeneratorTests(unittest.TestCase):
    """One closed parameter set; two renderings that cannot disagree."""

    def test_input_render_reconstructs_the_checked_in_statements(self):
        rendered = byte_identity.render_constructor_allocation_lift_input(
            validated_lift())
        self.assertEqual(rendered, CHECKED_IN_INPUT)
        window = byte_identity.select_source_permutation_window(
            (ROOT / UNIT).read_bytes(),
            {"kind": "constructor_allocation_lift_v1",
             "selector": "brace_balanced_function_after_marker_v1",
             "start_marker": "// FUNCTION: LEGO1 0x1003d170"},
            "window")
        self.assertEqual(window.count(rendered), 1)

    def test_call_site_and_body_come_from_the_same_parameters(self):
        params = validated_lift()
        self.assertEqual(
            byte_identity.render_constructor_allocation_lift_call_site(params),
            b"\tSet100d6b4c::iterator it = m_set.find("
            b"LegoCacheSoundEntry(p_key));\n")
        self.assertEqual(
            byte_identity
            .render_constructor_allocation_lift_constructor_body(params),
            b"\n{\n"
            b"\tm_name = new char[strlen(p_key) + 1];\n"
            b"\tstrcpy((char*) m_name, p_key);\n"
            b"\tm_sound = NULL;\n"
            b"}\n\n")

    def test_role_dispatch_is_closed(self):
        for role in ("body", "declaration", "", "Call_Site"):
            with self.subTest(role=role):
                with self.assertRaisesRegex(
                        byte_identity.ByteIdentityError,
                        "role is outside the closed enum"):
                    byte_identity.validate_source_overlay_generator(
                        lift(role=role), "gen")

    def test_buffer_cast_type_must_be_the_element_type_plus_one_pointer(self):
        for spelling in ("char", "const char*", "int*"):
            with self.subTest(spelling=spelling):
                with self.assertRaisesRegex(
                        byte_identity.ByteIdentityError,
                        "buffer_cast_type is not the element type"):
                    byte_identity.validate_source_overlay_generator(
                        lift(buffer_cast_type=spelling), "gen")
        with self.assertRaises(byte_identity.ByteIdentityError):
            byte_identity.validate_source_overlay_generator(
                lift(buffer_cast_type="char**"), "gen")

    def test_caller_result_type_must_equal_the_buffer_cast_type(self):
        with self.assertRaisesRegex(
                byte_identity.ByteIdentityError,
                "caller_result_type differs from the buffer cast type"):
            byte_identity.validate_source_overlay_generator(
                lift(caller_result_type="const char*"), "gen")

    def test_element_type_is_a_closed_integral_value_type(self):
        for spelling in ("LegoCacheSound", "const char", "char*", "void"):
            with self.subTest(spelling=spelling):
                with self.assertRaises(byte_identity.ByteIdentityError):
                    byte_identity.validate_source_overlay_generator(
                        lift(element_type=spelling,
                             buffer_cast_type=spelling + "*",
                             caller_result_type=spelling + "*"), "gen")

    def test_identifier_roles_must_be_distinct(self):
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "roles must be distinct"):
            byte_identity.validate_source_overlay_generator(
                lift(caller_result_identifier="it"), "gen")
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "roles must be distinct"):
            byte_identity.validate_source_overlay_generator(
                lift(null_members=["m_name"]), "gen")

    def test_the_lift_declares_nothing_and_emits_nothing(self):
        for role in ("call_site", "constructor_body"):
            with self.subTest(role=role):
                roles = byte_identity.source_overlay_expected_identifier_roles(
                    "constructor_allocation_lift_v1", validated_lift(role=role)
                )
                self.assertEqual(roles["declared_identifiers"], [])
                self.assertEqual(roles["emitted_identifiers"], [])
                self.assertIn("p_key", roles["referenced_identifiers"])
        body_roles = byte_identity.source_overlay_expected_identifier_roles(
            "constructor_allocation_lift_v1",
            validated_lift(role="constructor_body"))
        self.assertIn("strcpy", body_roles["referenced_identifiers"])
        call_roles = byte_identity.source_overlay_expected_identifier_roles(
            "constructor_allocation_lift_v1",
            validated_lift(role="call_site"))
        self.assertIn("LegoCacheSoundEntry",
                      call_roles["referenced_identifiers"])

    def test_it_is_classified_as_a_source_refactor_generator(self):
        self.assertIn("constructor_allocation_lift_v1",
                      byte_identity.SOURCE_REFACTOR_GENERATOR_KINDS)
        self.assertTrue(
            byte_identity.source_overlay_generator_is_source_refactor({
                "kind": "member_signature_v1",
                "params": {"kind": "constructor"}}))
        self.assertFalse(
            byte_identity.source_overlay_generator_is_source_refactor({
                "kind": "member_signature_v1",
                "params": {"kind": "destructor"}}))


class ConstructorAllocationLiftProofTests(unittest.TestCase):
    """The proof, not either generator, owns the new member's identity."""

    def setUp(self):
        manifest = byte_identity.strict_json_loads(
            (TOOLS / "byte_identity_manifest.json").read_bytes())
        unit = next(item for item in manifest["translation_units"]
                    if item["source"] == UNIT)
        self.function = copy.deepcopy(
            next(item for item in unit["functions"]
                 if item["mangled"] == MANGLED))
        self.proof = copy.deepcopy(self.function["target_source_refactor"])

    def test_the_shipped_proof_validates(self):
        byte_identity.validate_target_source_refactor_proof(
            self.proof, "proof")

    def test_operation_ids_must_name_all_four_roles(self):
        proof = copy.deepcopy(self.proof)
        proof["operation_ids"] = proof["operation_ids"][:3]
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "four bound allocation-lift roles"):
            byte_identity.validate_target_source_refactor_proof(
                proof, "proof")

    def test_constructor_signature_must_name_the_witness_class(self):
        proof = copy.deepcopy(self.proof)
        proof["constructor_signature"]["class_identifier"] = "Set100d6b4c"
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "names a different class"):
            byte_identity.validate_target_source_refactor_proof(
                proof, "proof")

    def test_witness_requires_exactly_one_nulled_member(self):
        proof = copy.deepcopy(self.proof)
        proof["semantic_witness"]["null_members"] = []
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "exactly one nulled member"):
            byte_identity.validate_target_source_refactor_proof(
                proof, "proof")

    def test_witness_member_and_parameter_identities_may_not_collide(self):
        proof = copy.deepcopy(self.proof)
        proof["semantic_witness"][
            "baseline_constructor_parameter_identifiers"] = [
                "m_sound", "p_name"]
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "identities collide"):
            byte_identity.validate_target_source_refactor_proof(
                proof, "proof")


class ConstructorAllocationLiftRecipePolicyTests(unittest.TestCase):
    """The four bound roles, the two renderings, and their seats."""

    @classmethod
    def setUpClass(cls):
        manifest = byte_identity.strict_json_loads(
            (TOOLS / "byte_identity_manifest.json").read_bytes())
        unit = next(item for item in manifest["translation_units"]
                    if item["source"] == UNIT)
        cls.function_raw = next(item for item in unit["functions"]
                                if item["mangled"] == MANGLED)
        cls.recipe_raw = next(
            item["recipe"] for item in unit["donors"]
            if item["id"] == cls.function_raw["donor"])
        overlay = byte_identity.validate_source_overlay(
            manifest["source_overlay"], ROOT)
        cls.canonical = next(
            item["operations"] for item in overlay["outputs"]
            if item["logical_path"] == UNIT)
        cls.overlaid = {item["logical_path"] for item in overlay["outputs"]}

    def run_policy(self, recipe=None, function=None):
        function = copy.deepcopy(function or self.function_raw)
        function["target_source_refactor"] = (
            byte_identity.validate_target_source_refactor_proof(
                function["target_source_refactor"], "proof"))
        if "local_set_delta" in function:
            function["local_set_delta"] = (
                byte_identity.validate_local_set_delta(
                    function["local_set_delta"], "delta"))
        return byte_identity.require_target_source_refactor_recipe_policy(
            copy.deepcopy(recipe or self.recipe_raw), function, ROOT, UNIT,
            "policy", self.canonical, set(self.overlaid))

    def test_the_shipped_recipe_passes(self):
        detail = self.run_policy()
        self.assertEqual(detail["allocation_lift_entry_class"],
                         "LegoCacheSoundEntry")
        self.assertEqual(detail["allocation_lift_nulled_members"],
                         ["m_sound"])

    def test_refuses_anything_other_than_its_two_renderings(self):
        recipe = copy.deepcopy(self.recipe_raw)
        recipe["renderings"] = [item for item in recipe["renderings"]
                                if item["path"] == UNIT]
        # dropping the header takes A7a's authority with it
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "is not declared in any"):
            self.run_policy(recipe)
        recipe = copy.deepcopy(self.recipe_raw)
        third = "LEGO1/lego/legoomni/include/legoworld.h"
        recipe["renderings"].append({
            "path": third,
            "clean_sha256": hashlib.sha256(
                (ROOT / third).read_bytes()).hexdigest(),
            "rendered_sha256": "0" * 64,
            "operations": [{"op": "append", "id": "op_probe_third",
                            "gen": {"k": "lines", "n": 1}}],
        })
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "renders its own TU and the class's "
                                    "owning header"):
            self.run_policy(recipe)

    def test_refuses_a_header_rendering_with_a_second_operation(self):
        recipe = copy.deepcopy(self.recipe_raw)
        header = next(item for item in recipe["renderings"]
                      if item["path"] == HEADER)
        header["operations"].append(
            {"op": "append", "id": "op_probe_extra",
             "gen": {"k": "lines", "n": 1}})
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "exactly one bound operation"):
            self.run_policy(recipe)

    def test_refuses_a_header_rendering_that_is_not_the_witness_header(self):
        recipe = copy.deepcopy(self.recipe_raw)
        function = copy.deepcopy(self.function_raw)
        function["target_source_refactor"]["semantic_witness"][
            "owner_header"]["path"] = "LEGO1/lego/legoomni/include/misc.h"
        with self.assertRaises(byte_identity.ByteIdentityError):
            self.run_policy(recipe, function)

    def test_refuses_a_definition_header_that_is_not_inline(self):
        recipe = copy.deepcopy(self.recipe_raw)
        unit = next(item for item in recipe["renderings"]
                    if item["path"] == UNIT)
        operation = next(item for item in unit["operations"]
                         if item.get("id") == "op_lcs_ctor_define")
        del operation["gen"]["specifiers"]
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "must be inline"):
            self.run_policy(recipe)

    def test_refuses_a_declaration_and_definition_that_disagree(self):
        recipe = copy.deepcopy(self.recipe_raw)
        header = next(item for item in recipe["renderings"]
                      if item["path"] == HEADER)
        header["operations"][0]["gen"]["parameters"] = [
            {"type": "char*", "identifier": "p_key"}]
        with self.assertRaisesRegex(
                byte_identity.ByteIdentityError,
                "signature differs from the proof's constructor signature"):
            self.run_policy(recipe)

    def test_refuses_a_call_site_and_body_that_are_not_one_parameter_set(self):
        recipe = copy.deepcopy(self.recipe_raw)
        unit = next(item for item in recipe["renderings"]
                    if item["path"] == UNIT)
        operation = next(item for item in unit["operations"]
                         if item.get("id") == "op_lcs_ctor_body")
        operation["gen"]["copy_function"] = "memcpy"
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "not two renderings of one parameter "
                                    "set"):
            self.run_policy(recipe)

    def test_refuses_a_body_rendered_before_its_definition_header(self):
        recipe = copy.deepcopy(self.recipe_raw)
        unit = next(item for item in recipe["renderings"]
                    if item["path"] == UNIT)
        operations = unit["operations"]
        first = next(index for index, item in enumerate(operations)
                     if item.get("id") == "op_lcs_ctor_define")
        second = next(index for index, item in enumerate(operations)
                      if item.get("id") == "op_lcs_ctor_body")
        operations[first], operations[second] = (
            operations[second], operations[first])
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "rendered before its definition header"):
            self.run_policy(recipe)

    def test_refuses_a_local_set_delta_that_is_not_what_the_lift_removes(self):
        function = copy.deepcopy(self.function_raw)
        function["local_set_delta"]["removed_records"][0]["identifier"] = "it"
        with self.assertRaisesRegex(
                byte_identity.ByteIdentityError,
                "not the set of locals this refactor removes"):
            self.run_policy(function=function)

    def test_refuses_a_witness_pin_that_drifts_from_the_header(self):
        function = copy.deepcopy(self.function_raw)
        function["target_source_refactor"]["semantic_witness"][
            "owner_header"]["destructor_body_range_pin"][
                "baseline_size"] += 1
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "authenticated input-range pins"):
            self.run_policy(function=function)

    def test_refuses_a_witness_that_misnames_the_argument_roles(self):
        function = copy.deepcopy(self.function_raw)
        function["target_source_refactor"]["semantic_witness"][
            "null_argument_position"] = 1
        with self.assertRaises(byte_identity.ByteIdentityError):
            self.run_policy(function=function)


class LocalSetDeltaSchemaTests(unittest.TestCase):
    """D1's manifest half: removal-only, pinned, and accounted for."""

    BASE = {
        "kind": "removed_caller_locals_v1",
        "expected_seed_debug_size": 173,
        "expected_donor_debug_size": 161,
        "removed_records": [
            {"seed_offset": 157, "size": 12, "record_type": 2,
             "identifier": "key"},
        ],
    }

    def test_the_shipped_delta_validates(self):
        byte_identity.validate_local_set_delta(
            copy.deepcopy(self.BASE), "delta")

    def test_refuses_an_addition(self):
        delta = copy.deepcopy(self.BASE)
        delta["expected_seed_debug_size"] = 161
        delta["expected_donor_debug_size"] = 173
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "must remove locals, never add them"):
            byte_identity.validate_local_set_delta(delta, "delta")

    def test_refuses_sizes_that_do_not_account_for_the_change(self):
        delta = copy.deepcopy(self.BASE)
        delta["removed_records"][0]["size"] = 8
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "do not account for the whole debug"):
            byte_identity.validate_local_set_delta(delta, "delta")

    def test_refuses_a_record_type_outside_the_closed_set(self):
        delta = copy.deepcopy(self.BASE)
        delta["removed_records"][0]["record_type"] = 0x0205
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "outside the closed local record types"):
            byte_identity.validate_local_set_delta(delta, "delta")

    def test_refuses_unsorted_or_repeated_offsets(self):
        delta = copy.deepcopy(self.BASE)
        delta["expected_donor_debug_size"] = 149
        delta["removed_records"] = [
            {"seed_offset": 157, "size": 12, "record_type": 2,
             "identifier": "key"},
            {"seed_offset": 157, "size": 12, "record_type": 2,
             "identifier": "other"},
        ]
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "unsorted or repeated"):
            byte_identity.validate_local_set_delta(delta, "delta")

    def test_refuses_duplicate_identifiers(self):
        delta = copy.deepcopy(self.BASE)
        delta["expected_donor_debug_size"] = 149
        delta["removed_records"] = [
            {"seed_offset": 145, "size": 12, "record_type": 2,
             "identifier": "key"},
            {"seed_offset": 157, "size": 12, "record_type": 2,
             "identifier": "key"},
        ]
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "identifiers must be distinct"):
            byte_identity.validate_local_set_delta(delta, "delta")

    def test_the_kind_set_is_closed(self):
        self.assertEqual(byte_identity.LOCAL_SET_DELTA_REFACTOR_KINDS,
                         frozenset({"constructor_allocation_lift_v1"}))


def _codeview_record(record_type, payload):
    return struct.pack("<HH", len(payload) + 2, record_type) + payload


def _named(record_type, fixed, name):
    return _codeview_record(
        record_type,
        fixed + bytes([len(name)]) + name.encode("ascii"))


def _procedure_record(name):
    return _named(0x0205, bytes(33), name)


def _register_record(name):
    return _named(0x0002, struct.pack("<HH", 0x0470, 0x0013), name)


END_RECORD = _codeview_record(0x0006, b"")


class CodeViewSymbolStreamTests(unittest.TestCase):
    """The stream parser refuses rather than approximates."""

    def test_parses_a_well_formed_stream(self):
        stream = (_procedure_record("Target") + _register_record("key")
                  + END_RECORD)
        records = byte_identity.parse_codeview_symbol_stream(stream, "ctx")
        self.assertEqual([item["name"] for item in records],
                         ["Target", "key", ""])
        self.assertEqual(records[1]["type"], 0x0002)

    def test_refuses_a_truncated_stream(self):
        stream = _procedure_record("Target")[:-3]
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "record length is out of range"):
            byte_identity.parse_codeview_symbol_stream(stream, "ctx")

    def test_refuses_a_record_type_outside_the_table(self):
        stream = _codeview_record(0x1234, b"\0\0\0\0") + END_RECORD
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "outside the closed table"):
            byte_identity.parse_codeview_symbol_stream(stream, "ctx")

    def test_collapses_only_compiler_local_serials(self):
        identity = byte_identity.codeview_symbol_identity
        self.assertEqual(identity({"type": 0x0209, "name": "$L66664"}),
                         (0x0209, "$L"))
        self.assertEqual(identity({"type": 0x0200, "name": "it"}),
                         (0x0200, "it"))


def _lift_function(record, delta=None):
    record = copy.deepcopy(record)
    record["target_source_refactor"] = {
        "kind": "constructor_allocation_lift_v1"}
    if delta is not None:
        record["local_set_delta"] = delta
    return record


class LocalSetDeltaComposerTests(unittest.TestCase):
    """D1's object half, on a synthetic pair shaped like the real one."""

    SEED_STREAM = (_procedure_record("T") + _register_record("key")
                   + END_RECORD)
    DONOR_STREAM = _procedure_record("T") + END_RECORD
    DELTA = {
        "kind": "removed_caller_locals_v1",
        "expected_seed_debug_size": len(SEED_STREAM),
        "expected_donor_debug_size": len(DONOR_STREAM),
        "removed_records": [{
            "seed_offset": len(_procedure_record("T")),
            "size": len(_register_record("key")),
            "record_type": 2, "identifier": "key",
        }],
    }

    def pair(self):
        seed = make_divergent_coff(debug_stream=self.SEED_STREAM)
        donor = make_divergent_coff(donor=True,
                                    debug_stream=self.DONOR_STREAM)
        return seed, donor

    def compose(self, function):
        seed, donor = self.pair()
        return byte_identity.compose_same_slot_resize(
            seed, donor, function, retail_body=retail_body_for(donor))

    def test_without_a_local_set_delta_the_shape_gate_refuses(self):
        seed, donor = self.pair()
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.compose_same_slot_resize(
                seed, donor, function_record(donor),
                retail_body=retail_body_for(donor))
        self.assertEqual(str(caught.exception),
                         "debug$S section shape changed")

    def test_with_a_pinned_delta_the_composition_succeeds(self):
        composed, detail = self.compose(
            _lift_function(function_record(self.pair()[1]),
                           byte_identity.validate_local_set_delta(
                               copy.deepcopy(self.DELTA), "delta")))
        self.assertEqual(detail["local_set_removed_identifiers"], ["key"])
        self.assertEqual(detail["local_set_debug_size_delta"],
                         len(self.DONOR_STREAM) - len(self.SEED_STREAM))
        parsed = byte_identity.CoffObject(composed)
        primary = parsed.function_section(TARGET_SYMBOL)
        child = byte_identity._comdat_child(parsed, primary, ".debug$S")
        # obligation (8): the output DROPS the stale record and says so in
        # the section header, instead of claiming a local it does not have.
        self.assertEqual(child["raw_size"], len(self.DONOR_STREAM))
        index, symbol = byte_identity._coff_section_symbol(parsed, child)
        self.assertEqual(
            int.from_bytes(byte_identity.coff_auxiliary(
                parsed, index, symbol)[:4], "little"),
            len(self.DONOR_STREAM))
        names = [item["name"] for item in
                 byte_identity.parse_codeview_symbol_stream(
                     byte_identity.coff_body(parsed, child), "out")]
        self.assertNotIn("key", names)

    def test_a_delta_outside_its_closed_refactor_kinds_refuses(self):
        function = _lift_function(
            function_record(self.pair()[1]),
            byte_identity.validate_local_set_delta(
                copy.deepcopy(self.DELTA), "delta"))
        function["target_source_refactor"] = {
            "kind": "fixed_array_fill_loop_v1"}
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "outside its closed source-refactor "
                                    "kinds"):
            self.compose(function)

    def test_a_misnamed_record_refuses(self):
        delta = copy.deepcopy(self.DELTA)
        delta["removed_records"][0]["identifier"] = "other"
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "is not the seed's"):
            self.compose(_lift_function(
                function_record(self.pair()[1]),
                byte_identity.validate_local_set_delta(delta, "delta")))

    def test_a_removal_overlapping_a_relocated_span_refuses(self):
        # If a removed span sat at or before the last debug$S relocation
        # plus its width, every later relocation offset would move and
        # debug_pairs' offset equality would silently break.
        delta = byte_identity.validate_local_set_delta(
            copy.deepcopy(self.DELTA), "delta")
        guard = self.DELTA["removed_records"][0]["seed_offset"]
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "overlaps a relocated span"):
            byte_identity.require_removed_caller_locals_delta(
                self.SEED_STREAM, self.DONOR_STREAM, [guard - 3], delta,
                "ctx")
        detail, _ = byte_identity.require_removed_caller_locals_delta(
            self.SEED_STREAM, self.DONOR_STREAM, [guard - 4], delta, "ctx")
        self.assertEqual(detail["local_set_removed_records"], 1)

    def test_a_surviving_sequence_that_is_not_the_donors_refuses(self):
        seed_stream = (_procedure_record("T") + _register_record("key")
                       + _register_record("abc") + END_RECORD)
        donor_stream = (_procedure_record("T") + _register_record("xyz")
                        + END_RECORD)
        delta = byte_identity.validate_local_set_delta({
            "kind": "removed_caller_locals_v1",
            "expected_seed_debug_size": len(seed_stream),
            "expected_donor_debug_size": len(donor_stream),
            "removed_records": [{
                "seed_offset": len(_procedure_record("T")),
                "size": len(_register_record("key")),
                "record_type": 2, "identifier": "key"}],
        }, "delta")
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "is not the donor's symbol sequence"):
            byte_identity.require_removed_caller_locals_delta(
                seed_stream, donor_stream, [0], delta, "ctx")

    def test_a_removed_local_that_survives_in_the_donor_refuses(self):
        seed_stream = (_procedure_record("T") + _register_record("key")
                       + _register_record("key") + END_RECORD)
        donor_stream = (_procedure_record("T") + _register_record("key")
                        + END_RECORD)
        delta = byte_identity.validate_local_set_delta({
            "kind": "removed_caller_locals_v1",
            "expected_seed_debug_size": len(seed_stream),
            "expected_donor_debug_size": len(donor_stream),
            "removed_records": [{
                "seed_offset": len(_procedure_record("T")),
                "size": len(_register_record("key")),
                "record_type": 2, "identifier": "key"}],
        }, "delta")
        with self.assertRaisesRegex(
                byte_identity.ByteIdentityError,
                "still exists in the donor's symbol stream"):
            byte_identity.require_removed_caller_locals_delta(
                seed_stream, donor_stream, [0], delta, "ctx")

    def test_a_stream_that_is_not_one_bounded_procedure_refuses(self):
        stream = _register_record("key") + END_RECORD
        delta = byte_identity.validate_local_set_delta({
            "kind": "removed_caller_locals_v1",
            "expected_seed_debug_size": len(stream),
            "expected_donor_debug_size": len(END_RECORD),
            "removed_records": [{
                "seed_offset": 0, "size": len(_register_record("key")),
                "record_type": 2, "identifier": "key"}],
        }, "delta")
        with self.assertRaisesRegex(byte_identity.ByteIdentityError,
                                    "not one bounded procedure record"):
            byte_identity.require_removed_caller_locals_delta(
                stream, END_RECORD, [], delta, "ctx")


LANE_OBJECTS = Path(
    "/private/tmp/claude-501/-Users-foxtacles-Projects-isle/"
    "686cf7a8-49da-4dfd-9625-b99378ddc574/scratchpad")
SEED_OBJECT = LANE_OBJECTS / "N-cu-before/lego1_legocachesoundmanager.cpp.obj"
DONOR_OBJECT = LANE_OBJECTS / "N-cu-after/lego1_legocachesoundmanager.cpp.obj"


@unittest.skipUnless(SEED_OBJECT.is_file() and DONOR_OBJECT.is_file(),
                     "the measured clean/fsk_d object pair is not present")
class LocalSetDeltaRealObjectTests(unittest.TestCase):
    """The same two obligations against the objects the numbers came from."""

    DELTA = {
        "kind": "removed_caller_locals_v1",
        "expected_seed_debug_size": 173,
        "expected_donor_debug_size": 161,
        "removed_records": [{"seed_offset": 157, "size": 12,
                             "record_type": 2, "identifier": "key"}],
    }

    def function(self, delta=None):
        manifest = byte_identity.strict_json_loads(
            (TOOLS / "byte_identity_manifest.json").read_bytes())
        unit = next(item for item in manifest["translation_units"]
                    if item["source"] == UNIT)
        record = copy.deepcopy(next(item for item in unit["functions"]
                                    if item["mangled"] == MANGLED))
        donor = byte_identity.CoffObject(DONOR_OBJECT.read_bytes())
        section = donor.function_section(MANGLED)
        record["expected_body_sha256"] = hashlib.sha256(
            byte_identity.coff_body(donor, section)).hexdigest()
        retail = byte_identity.retail_image_body(
            manifest, "LEGO1.DLL", 0x1003D170, 281)
        rows = byte_identity.detailed_relocations(donor, section)
        oracle = []
        for row in rows:
            raw = retail[row["offset"]:row["offset"] + 4]
            if row["type"] == 0x0006:
                resolved = int.from_bytes(raw, "little")
            else:
                resolved = (0x1003D170 + row["offset"] + 4
                            + int.from_bytes(raw, "little", signed=True))
            oracle.append({
                **{key: row[key] for key in (
                    "offset", "type", "addend", "target", "target_section",
                    "target_value", "target_type", "target_storage")},
                "retail_target": f"0x{resolved & 0xFFFFFFFF:08x}",
            })
        record["retail_relocations"] = oracle
        record.pop("local_set_delta", None)
        if delta is not None:
            record["local_set_delta"] = byte_identity.validate_local_set_delta(
                copy.deepcopy(delta), "delta")
        return record, retail

    def test_the_measured_pair_refuses_without_a_local_set_delta(self):
        record, retail = self.function()
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.compose_same_slot_resize(
                SEED_OBJECT.read_bytes(), DONOR_OBJECT.read_bytes(),
                record, retail_body=retail)
        self.assertEqual(str(caught.exception),
                         "debug$S section shape changed")

    def test_the_pinned_delta_clears_the_shape_gate_on_the_measured_pair(self):
        # This exact pair is the lane's clean/fsk_d measurement, taken at a
        # carrier state that is one byte away from retail; B1 therefore still
        # refuses it, which is the point.  What must be true is that the
        # refusal is no longer the debug$S SHAPE gate.
        record, retail = self.function(self.DELTA)
        with self.assertRaises(byte_identity.ByteIdentityError) as caught:
            byte_identity.compose_same_slot_resize(
                SEED_OBJECT.read_bytes(), DONOR_OBJECT.read_bytes(),
                record, retail_body=retail)
        self.assertNotIn("shape changed", str(caught.exception))
        self.assertIn("retail-exact", str(caught.exception))

    def test_the_measured_streams_reduce_to_the_donors_symbol_sequence(self):
        seed = byte_identity.CoffObject(SEED_OBJECT.read_bytes())
        donor = byte_identity.CoffObject(DONOR_OBJECT.read_bytes())
        seed_child = byte_identity._comdat_child(
            seed, seed.function_section(MANGLED), ".debug$S")
        donor_child = byte_identity._comdat_child(
            donor, donor.function_section(MANGLED), ".debug$S")
        seed_stream = byte_identity.coff_body(seed, seed_child)
        detail, reduced = byte_identity.require_removed_caller_locals_delta(
            seed_stream, byte_identity.coff_body(donor, donor_child),
            [row["offset"] for row in
             byte_identity.detailed_relocations(seed, seed_child)],
            byte_identity.validate_local_set_delta(
                copy.deepcopy(self.DELTA), "delta"),
            "measured pair")
        self.assertEqual(detail["local_set_removed_identifiers"], ["key"])
        self.assertEqual(len(reduced), 161)
        self.assertEqual(reduced, seed_stream[:157] + seed_stream[169:])
        names = [item["name"] for item in
                 byte_identity.parse_codeview_symbol_stream(
                     reduced, "reduced")]
        self.assertNotIn("key", names)


if __name__ == "__main__":
    unittest.main()
