#!/usr/bin/env python

# MIT License
#
# Copyright (c) 2018 Nithin Nellikunnu (nithin.nn@gmail.com)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import logging
import argparse
import yaml
import re
import sys
import difflib
import os
import fnmatch
from clang.cindex import Index
from clang.cindex import CursorKind
from clang.cindex import StorageClass
from clang.cindex import TypeKind
from clang.cindex import Config


# Clang cursor kind to ncc Defined cursor map
default_rules_db = {}
clang_to_user_map = {}
special_kind = {CursorKind.STRUCT_DECL: 1, CursorKind.CLASS_DECL: 1}
file_extensions = [".c", ".cpp", ".h", ".hpp"]


class Rule(object):
    def __init__(self, name, clang_kind, parent_kind=None, pattern_str='^.*$'):
        self.name = name
        self.clang_kind = clang_kind
        self.parent_kind = parent_kind
        self.pattern_str = pattern_str
        self.pattern = re.compile(pattern_str)
        self.includes = []
        self.excludes = []

    def evaluate(self, node, scope=None):
        if not self.pattern.match(node.spelling):
            fmt = '{}:{}:{}: "{}" does not match "{}" associated with {}\n'
            msg = fmt.format(node.location.file.name, node.location.line, node.location.column,
                             node.displayname, self.pattern_str, self.name)
            sys.stderr.write(msg)
            return False
        return True


class ScopePrefixRule(object):
    def __init__(self, pattern_obj):
        self.name = "ScopePrefixRule"
        self.rule_names = ["Global", "Static", "ClassMember", "StructMember"]
        self.global_prefix = ""
        self.static_prefix = ""
        self.class_member_prefix = ""
        self.struct_member_prefix = ""

        try:
            for key, value in pattern_obj.items():
                if key == "Global":
                    self.global_prefix = value
                elif key == "Static":
                    self.static_prefix = value
                elif key == "ClassMember":
                    self.class_member_prefix = value
                elif key == "StructMember":
                    self.struct_member_prefix = value
                else:
                    raise ValueError(key)
        except ValueError as e:
            sys.stderr.write('{} is not a valid rule name\n'.format(e.message))
            fixit = difflib.get_close_matches(e.message, self.rule_names, n=1, cutoff=0.8)
            if fixit:
                sys.stderr.write('Did you mean rule name: {} ?\n'.format(fixit[0]))
            sys.exit(1)


class DataTypePrefixRule(object):
    def __init__(self, pattern_obj):
        self.name = "DataTypePrefix"
        self.rule_names = ["String", "Integer", "Bool", "Pointer"]
        self.string_prefix = ""

        try:
            for key, value in pattern_obj.items():
                if key == "String":
                    self.string_prefix = value
                elif key == "Integer":
                    self.integer_prefix = value
                elif key == "Bool":
                    self.bool_prefix = value
                elif key == "Pointer":
                    self.pointer_prefix = value
                else:
                    raise ValueError(key)
        except ValueError as e:
            sys.stderr.write('{} is not a valid rule name\n'.format(e.message))
            fixit = difflib.get_close_matches(e.message, self.rule_names, n=1, cutoff=0.8)
            if fixit:
                sys.stderr.write('Did you mean rule name: {} ?\n'.format(fixit[0]))
            sys.exit(1)


class VariableNameRule(object):
    def __init__(self, pattern_obj=None):
        self.name = "VariableName"
        self.pattern_str = "^.*$"
        self.rule_names = ["ScopePrefix", "DataTypePrefix", "Pattern"]
        self.scope_prefix_rule = None
        self.datatype_prefix_rule = None

        try:
            for key, value in pattern_obj.items():
                if key == "ScopePrefix":
                    self.scope_prefix_rule = ScopePrefixRule(value)
                elif key == "DataTypePrefix":
                    self.datatype_prefix_rule = DataTypePrefixRule(value)
                elif key == "Pattern":
                    self.pattern_str = value
                else:
                    raise ValueError(key)
        except ValueError as e:
            sys.stderr.write('{} is not a valid rule name\n'.format(e.message))
            fixit = difflib.get_close_matches(e.message, self.rule_names, n=1, cutoff=0.8)
            if fixit:
                sys.stderr.write('Did you mean rule name: {} ?\n'.format(fixit[0]))
            sys.exit(1)
        except re.error as e:
            sys.stderr.write('{} is not a valid pattern \n'.format(e.message))
            sys.exit(1)

    def get_scope_prefix(self, node, scope=None):
        if node.storage_class == StorageClass.STATIC:
            return self.scope_prefix_rule.static_prefix
        elif (scope is None) and (node.storage_class == StorageClass.EXTERN or
                                  node.storage_class == StorageClass.NONE):
            return self.scope_prefix_rule.global_prefix
        elif (scope is CursorKind.CLASS_DECL) or (scope is CursorKind.CLASS_TEMPLATE):
            return self.scope_prefix_rule.class_member_prefix
        elif (scope is CursorKind.STRUCT_DECL):
            return self.scope_prefix_rule.struct_member_prefix
        return ""

    def get_datatype_prefix(self, node):
        if node.type.kind is TypeKind.ELABORATED:
            if node.type.spelling.startswith('std::string'):
                return self.datatype_prefix_rule.string_prefix
            elif (node.type.spelling.startswith('std::unique_ptr') or
                  node.type.spelling.startswith("std::shared_ptr")):
                return self.datatype_prefix_rule.pointer_prefix
        elif node.type.kind is TypeKind.POINTER:
            return self.datatype_prefix_rule.pointer_prefix
        else:
            if node.type.spelling == "int":
                return self.datatype_prefix_rule.integer_prefix
            elif node.type.spelling.startswith('bool'):
                return self.datatype_prefix_rule.bool_prefix
        return ""

    def evaluate(self, node, scope=None):
        pattern_str = self.pattern_str
        scope_prefix = self.get_scope_prefix(node, scope)
        datatype_prefix = self.get_datatype_prefix(node)

        pattern_str = pattern_str[0] + scope_prefix + datatype_prefix + pattern_str[1:]

        pattern = re.compile(pattern_str)
        if not pattern.match(node.spelling):
            fmt = '{}:{}:{}: "{}" does not have the pattern {} associated with Variable name\n'
            msg = fmt.format(node.location.file.name, node.location.line, node.location.column,
                             node.displayname, pattern_str)
            sys.stderr.write(msg)
            return False

        return True


# All supported rules
default_rules_db["StructName"] = Rule("StructName", CursorKind.STRUCT_DECL)
default_rules_db["UnionName"] = Rule("UnionName", CursorKind.UNION_DECL)
default_rules_db["ClassName"] = Rule("ClassName", CursorKind.CLASS_DECL)
default_rules_db["EnumName"] = Rule("EnumName", CursorKind.ENUM_DECL)
default_rules_db["EnumConstantName"] = Rule("EnumConstantName", CursorKind.ENUM_CONSTANT_DECL)
default_rules_db["FunctionName"] = Rule("FunctionName", CursorKind.FUNCTION_DECL)
default_rules_db["ParameterName"] = Rule("ParameterName", CursorKind.PARM_DECL)
default_rules_db["TypedefName"] = Rule("TypedefName", CursorKind.TYPEDEF_DECL)
default_rules_db["CppMethod"] = Rule("CppMethod", CursorKind.CXX_METHOD)
default_rules_db["Namespace"] = Rule("Namespace", CursorKind.NAMESPACE)
default_rules_db["ConversionFunction"] = Rule("ConversionFunction", CursorKind.CONVERSION_FUNCTION)
default_rules_db["TemplateTypeParameter"] = Rule(
    "TemplateTypeParameter", CursorKind.TEMPLATE_TYPE_PARAMETER)
default_rules_db["TemplateNonTypeParameter"] = Rule(
    "TemplateNonTypeParameter", CursorKind.TEMPLATE_NON_TYPE_PARAMETER)
default_rules_db["TemplateTemplateParameter"] = Rule(
    "TemplateTemplateParameter", CursorKind.TEMPLATE_TEMPLATE_PARAMETER)
default_rules_db["FunctionTemplate"] = Rule("FunctionTemplate", CursorKind.FUNCTION_TEMPLATE)
default_rules_db["ClassTemplate"] = Rule("ClassTemplate", CursorKind.CLASS_TEMPLATE)
default_rules_db["ClassTemplatePartialSpecialization"] = Rule(
    "ClassTemplatePartialSpecialization", CursorKind.CLASS_TEMPLATE_PARTIAL_SPECIALIZATION)
default_rules_db["NamespaceAlias"] = Rule("NamespaceAlias", CursorKind.NAMESPACE_ALIAS)
default_rules_db["UsingDirective"] = Rule("UsingDirective", CursorKind.USING_DIRECTIVE)
default_rules_db["UsingDeclaration"] = Rule("UsingDeclaration", CursorKind.USING_DECLARATION)
default_rules_db["TypeAliasName"] = Rule("TypeAliasName", CursorKind.TYPE_ALIAS_DECL)
default_rules_db["ClassAccessSpecifier"] = Rule(
    "ClassAccessSpecifier", CursorKind.CXX_ACCESS_SPEC_DECL)
default_rules_db["TypeReference"] = Rule("TypeReference", CursorKind.TYPE_REF)
default_rules_db["CxxBaseSpecifier"] = Rule("CxxBaseSpecifier", CursorKind.CXX_BASE_SPECIFIER)
default_rules_db["TemplateReference"] = Rule("TemplateReference", CursorKind.TEMPLATE_REF)
default_rules_db["NamespaceReference"] = Rule("NamespaceReference", CursorKind.NAMESPACE_REF)
default_rules_db["MemberReference"] = Rule("MemberReference", CursorKind.MEMBER_REF)
default_rules_db["LabelReference"] = Rule("LabelReference", CursorKind.LABEL_REF)
default_rules_db["OverloadedDeclarationReference"] = Rule(
    "OverloadedDeclarationReference", CursorKind.OVERLOADED_DECL_REF)
default_rules_db["VariableReference"] = Rule("VariableReference", CursorKind.VARIABLE_REF)
default_rules_db["InvalidFile"] = Rule("InvalidFile", CursorKind.INVALID_FILE)
default_rules_db["NoDeclarationFound"] = Rule("NoDeclarationFound", CursorKind.NO_DECL_FOUND)
default_rules_db["NotImplemented"] = Rule("NotImplemented", CursorKind.NOT_IMPLEMENTED)
default_rules_db["InvalidCode"] = Rule("InvalidCode", CursorKind.INVALID_CODE)
default_rules_db["UnexposedExpression"] = Rule("UnexposedExpression", CursorKind.UNEXPOSED_EXPR)
default_rules_db["DeclarationReferenceExpression"] = Rule(
    "DeclarationReferenceExpression", CursorKind.DECL_REF_EXPR)
default_rules_db["MemberReferenceExpression"] = Rule(
    "MemberReferenceExpression", CursorKind.MEMBER_REF_EXPR)
default_rules_db["CallExpression"] = Rule("CallExpression", CursorKind.CALL_EXPR)
default_rules_db["BlockExpression"] = Rule("BlockExpression", CursorKind.BLOCK_EXPR)
default_rules_db["IntegerLiteral"] = Rule("IntegerLiteral", CursorKind.INTEGER_LITERAL)
default_rules_db["FloatingLiteral"] = Rule("FloatingLiteral", CursorKind.FLOATING_LITERAL)
default_rules_db["ImaginaryLiteral"] = Rule("ImaginaryLiteral", CursorKind.IMAGINARY_LITERAL)
default_rules_db["StringLiteral"] = Rule("StringLiteral", CursorKind.STRING_LITERAL)
default_rules_db["CharacterLiteral"] = Rule("CharacterLiteral", CursorKind.CHARACTER_LITERAL)
default_rules_db["ParenExpression"] = Rule("ParenExpression", CursorKind.PAREN_EXPR)
default_rules_db["UnaryOperator"] = Rule("UnaryOperator", CursorKind.UNARY_OPERATOR)
default_rules_db["ArraySubscriptExpression"] = Rule(
    "ArraySubscriptExpression", CursorKind.ARRAY_SUBSCRIPT_EXPR)
default_rules_db["BinaryOperator"] = Rule("BinaryOperator", CursorKind.BINARY_OPERATOR)
default_rules_db["CompoundAssignmentOperator"] = Rule(
    "CompoundAssignmentOperator", CursorKind.COMPOUND_ASSIGNMENT_OPERATOR)
default_rules_db["ConditionalOperator"] = Rule(
    "ConditionalOperator", CursorKind.CONDITIONAL_OPERATOR)
default_rules_db["CstyleCastExpression"] = Rule(
    "CstyleCastExpression", CursorKind.CSTYLE_CAST_EXPR)
default_rules_db["CompoundLiteralExpression"] = Rule(
    "CompoundLiteralExpression", CursorKind.COMPOUND_LITERAL_EXPR)
default_rules_db["InitListExpression"] = Rule("InitListExpression", CursorKind.INIT_LIST_EXPR)
default_rules_db["AddrLabelExpression"] = Rule("AddrLabelExpression", CursorKind.ADDR_LABEL_EXPR)
default_rules_db["StatementExpression"] = Rule("StatementExpression", CursorKind.StmtExpr)
default_rules_db["GenericSelectionExpression"] = Rule(
    "GenericSelectionExpression", CursorKind.GENERIC_SELECTION_EXPR)
default_rules_db["GnuNullExpression"] = Rule("GnuNullExpression", CursorKind.GNU_NULL_EXPR)
default_rules_db["CxxStaticCastExpression"] = Rule(
    "CxxStaticCastExpression", CursorKind.CXX_STATIC_CAST_EXPR)
default_rules_db["CxxDynamicCastExpression"] = Rule(
    "CxxDynamicCastExpression", CursorKind.CXX_DYNAMIC_CAST_EXPR)
default_rules_db["CxxReinterpretCastExpression"] = Rule(
    "CxxReinterpretCastExpression", CursorKind.CXX_REINTERPRET_CAST_EXPR)
default_rules_db["CxxConstCastExpression"] = Rule(
    "CxxConstCastExpression", CursorKind.CXX_CONST_CAST_EXPR)
default_rules_db["CxxFunctionalCastExpression"] = Rule(
    "CxxFunctionalCastExpression", CursorKind.CXX_FUNCTIONAL_CAST_EXPR)
default_rules_db["CxxTypeidExpression"] = Rule("CxxTypeidExpression", CursorKind.CXX_TYPEID_EXPR)
default_rules_db["CxxBoolLiteralExpression"] = Rule(
    "CxxBoolLiteralExpression", CursorKind.CXX_BOOL_LITERAL_EXPR)
default_rules_db["CxxNullPointerLiteralExpression"] = Rule(
    "CxxNullPointerLiteralExpression", CursorKind.CXX_NULL_PTR_LITERAL_EXPR)
default_rules_db["CxxThisExpression"] = Rule("CxxThisExpression", CursorKind.CXX_THIS_EXPR)
default_rules_db["CxxThrowExpression"] = Rule("CxxThrowExpression", CursorKind.CXX_THROW_EXPR)
default_rules_db["CxxNewExpression"] = Rule("CxxNewExpression", CursorKind.CXX_NEW_EXPR)
default_rules_db["CxxDeleteExpression"] = Rule("CxxDeleteExpression", CursorKind.CXX_DELETE_EXPR)
default_rules_db["CxxUnaryExpression"] = Rule("CxxUnaryExpression", CursorKind.CXX_UNARY_EXPR)
default_rules_db["PackExpansionExpression"] = Rule(
    "PackExpansionExpression", CursorKind.PACK_EXPANSION_EXPR)
default_rules_db["SizeOfPackExpression"] = Rule(
    "SizeOfPackExpression", CursorKind.SIZE_OF_PACK_EXPR)
default_rules_db["LambdaExpression"] = Rule("LambdaExpression", CursorKind.LAMBDA_EXPR)
default_rules_db["ObjectBoolLiteralExpression"] = Rule(
    "ObjectBoolLiteralExpression", CursorKind.OBJ_BOOL_LITERAL_EXPR)
default_rules_db["ObjectSelfExpression"] = Rule("ObjectSelfExpression", CursorKind.OBJ_SELF_EXPR)
default_rules_db["UnexposedStatement"] = Rule("UnexposedStatement", CursorKind.UNEXPOSED_STMT)
default_rules_db["LabelStatement"] = Rule("LabelStatement", CursorKind.LABEL_STMT)
default_rules_db["CompoundStatement"] = Rule("CompoundStatement", CursorKind.COMPOUND_STMT)
default_rules_db["CaseStatement"] = Rule("CaseStatement", CursorKind.CASE_STMT)
default_rules_db["DefaultStatement"] = Rule("DefaultStatement", CursorKind.DEFAULT_STMT)
default_rules_db["IfStatement"] = Rule("IfStatement", CursorKind.IF_STMT)
default_rules_db["SwitchStatement"] = Rule("SwitchStatement", CursorKind.SWITCH_STMT)
default_rules_db["WhileStatement"] = Rule("WhileStatement", CursorKind.WHILE_STMT)
default_rules_db["DoStatement"] = Rule("DoStatement", CursorKind.DO_STMT)
default_rules_db["ForStatement"] = Rule("ForStatement", CursorKind.FOR_STMT)
default_rules_db["GotoStatement"] = Rule("GotoStatement", CursorKind.GOTO_STMT)
default_rules_db["IndirectGotoStatement"] = Rule(
    "IndirectGotoStatement", CursorKind.INDIRECT_GOTO_STMT)
default_rules_db["ContinueStatement"] = Rule("ContinueStatement", CursorKind.CONTINUE_STMT)
default_rules_db["BreakStatement"] = Rule("BreakStatement", CursorKind.BREAK_STMT)
default_rules_db["ReturnStatement"] = Rule("ReturnStatement", CursorKind.RETURN_STMT)
default_rules_db["AsmStatement"] = Rule("AsmStatement", CursorKind.ASM_STMT)
default_rules_db["CxxCatchStatement"] = Rule("CxxCatchStatement", CursorKind.CXX_CATCH_STMT)
default_rules_db["CxxTryStatement"] = Rule("CxxTryStatement", CursorKind.CXX_TRY_STMT)
default_rules_db["CxxForRangeStatement"] = Rule(
    "CxxForRangeStatement", CursorKind.CXX_FOR_RANGE_STMT)
default_rules_db["MsAsmStatement"] = Rule("MsAsmStatement", CursorKind.MS_ASM_STMT)
default_rules_db["NullStatement"] = Rule("NullStatement", CursorKind.NULL_STMT)
default_rules_db["DeclarationStatement"] = Rule("DeclarationStatement", CursorKind.DECL_STMT)
default_rules_db["TranslationUnit"] = Rule("TranslationUnit", CursorKind.TRANSLATION_UNIT)
default_rules_db["UnexposedAttribute"] = Rule("UnexposedAttribute", CursorKind.UNEXPOSED_ATTR)
default_rules_db["CxxFinalAttribute"] = Rule("CxxFinalAttribute", CursorKind.CXX_FINAL_ATTR)
default_rules_db["CxxOverrideAttribute"] = Rule(
    "CxxOverrideAttribute", CursorKind.CXX_OVERRIDE_ATTR)
default_rules_db["AnnotateAttribute"] = Rule("AnnotateAttribute", CursorKind.ANNOTATE_ATTR)
default_rules_db["AsmLabelAttribute"] = Rule("AsmLabelAttribute", CursorKind.ASM_LABEL_ATTR)
default_rules_db["PackedAttribute"] = Rule("PackedAttribute", CursorKind.PACKED_ATTR)
default_rules_db["PureAttribute"] = Rule("PureAttribute", CursorKind.PURE_ATTR)
default_rules_db["ConstAttribute"] = Rule("ConstAttribute", CursorKind.CONST_ATTR)
default_rules_db["NoduplicateAttribute"] = Rule(
    "NoduplicateAttribute", CursorKind.NODUPLICATE_ATTR)
default_rules_db["PreprocessingDirective"] = Rule(
    "PreprocessingDirective", CursorKind.PREPROCESSING_DIRECTIVE)
default_rules_db["MacroDefinition"] = Rule("MacroDefinition", CursorKind.MACRO_DEFINITION)
default_rules_db["MacroInstantiation"] = Rule("MacroInstantiation", CursorKind.MACRO_INSTANTIATION)
default_rules_db["InclusionDirective"] = Rule("InclusionDirective", CursorKind.INCLUSION_DIRECTIVE)
default_rules_db["TypeAliasTeplateDeclaration"] = Rule(
    "TypeAliasTeplateDeclaration", CursorKind.TYPE_ALIAS_TEMPLATE_DECL)

# Reverse lookup map. The parse identifies Clang cursor kinds, which must be mapped
# to user defined types
for key, value in default_rules_db.items():
    clang_to_user_map[value.clang_kind] = key
default_rules_db["VariableName"] = Rule("VariableName", CursorKind.VAR_DECL)
clang_to_user_map[CursorKind.FIELD_DECL] = "VariableName"
clang_to_user_map[CursorKind.VAR_DECL] = "VariableName"


class AstNodeStack(object):
    def __init__(self):
        self.stack = []

    def pop(self):
        return self.stack.pop()

    def push(self, kind):
        self.stack.append(kind)

    def peek(self):
        if len(self.stack) > 0:
            return self.stack[-1]
        return None


class Options:
    def __init__(self):
        self.args = None
        self._style_file = None
        self.file_exclusions = None
        self._skip_file = None

        self.parser = argparse.ArgumentParser(
            prog="ncc.py",
            description="ncc is a development tool to help programmers "
            "write C/C++ code that adheres to adhere some naming conventions. It automates the "
            "process of checking C code to spare humans of this boring "
            "(but important) task. This makes it ideal for projects that want "
            "to enforce a coding standard.")

        self.parser.add_argument('--recurse', action='store_true', dest="recurse",
                                 help="Read all files under each directory, recursively")

        self.parser.add_argument('--style', dest="style_file",
                                 help="Read rules from the specified file. If the user does not"
                                 "provide a style file ncc will use all style rules. To print"
                                 "all style rules use --dump option")

        self.parser.add_argument('--include', dest='include', nargs="+", help="User defined "
                                 "header file path, this is same as -I argument to the compiler")

        self.parser.add_argument('--definition', dest='definition', nargs="+", help="User specified "
                                 "definitions, this is same as -D argument to the compiler")

        self.parser.add_argument('--dump', dest='dump', action='store_true',
                                 help="Dump all available options")

        self.parser.add_argument('--output', dest='output', help="output file name where"
                                 "naming convenction vialoations will be stored")

        self.parser.add_argument('--filetype', dest='filetype', help="File extentions type"
                                 "that are applicable for naming convection validation")

        self.parser.add_argument('--clang-lib', dest='clang_lib',
                                 help="Custom location of clang library")

        self.parser.add_argument('--exclude', dest='exclude', nargs="+", help="Skip files "
                                 "matching the pattern specified from recursive searches. It "
                                 "matches a specified pattern according to the rules used by "
                                 "the Unix shell")

        self.parser.add_argument('--skip', '-s', dest="skip_file",
                                 help="Read list of items to ignore during the check. "
                                 "User can use the skip file to specify character sequences that should "
                                 "be ignored by ncc")

        # self.parser.add_argument('--exclude-dir', dest='exclude_dir', help="Skip the directories"
        #                          "matching the pattern specified")

        self.parser.add_argument('--path', dest='path', nargs="+",
                                 help="Path of file or directory")

    def parse_cmd_line(self):
        self.args = self.parser.parse_args()

        if self.args.dump:
            self.dump_all_rules()

        if self.args.style_file:
            self._style_file = self.args.style_file
            if not os.path.exists(self._style_file):
                sys.stderr.write("Style file '{}' not found!\n".format(self._style_file))
                sys.exit(1)

        if self.args.skip_file:
            self._skip_file = self.args.skip_file
            if not os.path.exists(self._skip_file):
                sys.stderr.write("Skip file '{}' not found!\n".format(self._skip_file))

    def dump_all_rules(self):
        print("----------------------------------------------------------")
        print("{:<35} | {}".format("Rule Name", "Pattern"))
        print("----------------------------------------------------------")
        for (key, value) in default_rules_db.items():
            print("{:<35} : {}".format(key, value.pattern_str))

class SkipDb(object):
    def __init__(self, skip_file=None):
        self.__skip_db = {}

        if skip_file:
            self.build_skip_db(skip_file)

    def build_skip_db(self, skip_file):
        with open(skip_file) as stylefile:
            style_rules = yaml.safe_load(stylefile)
            for (skip_string, skip_comment) in style_rules.items():
                self.__skip_db[skip_string] = skip_comment

    def check_skip_db(self, input_query):
        if input_query in self.__skip_db.keys():
            return 1
        else:
            return 0

class RulesDb(object):
    def __init__(self, style_file=None):
        self.__rule_db = {}
        self.__clang_db = {}

        if style_file:
            self.build_rules_db(style_file)
        else:
            self.__rule_db = default_rules_db
            self.__clang_db = clang_to_user_map

    def build_rules_db(self, style_file):
        with open(style_file) as stylefile:
            style_rules = yaml.safe_load(stylefile)

        for (rule_name, pattern_str) in style_rules.items():
            try:
                clang_kind = default_rules_db[rule_name].clang_kind
                if clang_kind:
                    if rule_name == "VariableName":
                        self.__rule_db[rule_name] = VariableNameRule(pattern_str)
                        self.__clang_db[CursorKind.FIELD_DECL] = rule_name
                        self.__clang_db[CursorKind.VAR_DECL] = rule_name
                    else:
                        self.__rule_db[rule_name] = default_rules_db[rule_name]
                        self.__rule_db[rule_name].pattern_str = pattern_str
                        self.__rule_db[rule_name].pattern = re.compile(pattern_str)
                        self.__clang_db[clang_kind] = rule_name

            except KeyError as e:
                sys.stderr.write('{} is not a valid C/C++ construct name\n'.format(e.message))
                fixit = difflib.get_close_matches(e.message, default_rules_db.keys(),
                                                  n=1, cutoff=0.8)
                if fixit:
                    sys.stderr.write('Did you mean rule name: {} ?\n'.format(fixit[0]))
                sys.exit(1)
            except re.error as e:
                sys.stderr.write('"{}" pattern {} has {} \n'.
                                 format(rule_name, pattern_str, e.message))
                sys.exit(1)

    def is_rule_enabled(self, kind):
        if self.__clang_db.get(kind):
            return True
        return False

    def get_rule_names(self, kind):
        """
        Multiple user defined rules can be configured against one type of ClangKind
        For e.g. ClassMemberVariable, StructMemberVariable are types of FIELD_DECL
        """
        return self.__clang_db.get(kind)

    def get_rule(self, rule_name):
        return self.__rule_db.get(rule_name)


class Validator(object):
    def __init__(self, rule_db, filename, options, skip_db=None):
        self.filename = filename
        self.rule_db = rule_db
        self.skip_db = skip_db
        self.options = options
        self.node_stack = AstNodeStack()

        index = Index.create()
        args = []
        args.append('-x')
        args.append('c++')
        args.append('-D_GLIBCXX_USE_CXX11_ABI=0')
        if self.options.args.definition:
            for item in self.options.args.definition:
                defintion = r'-D' + item
                args.append(defintion)
        if self.options.args.include:
            for item in self.options.args.include:
                inc = r'-I' + item
                args.append(inc)
        self.cursor = index.parse(filename, args).cursor

    def validate(self):
        return self.check(self.cursor)

    def check(self, node):
        """
        Recursively visit all nodes of the AST and match against the patter provided by
        the user. Return the total number of errors caught in the file
        """
        errors = 0
        for child in node.get_children():
            if self.is_local(child, self.filename):

                # This is the case when typedef of struct is causing double reporting of error
                # TODO: Find a better way to handle it
                parent = self.node_stack.peek()
                if (parent and parent == CursorKind.TYPEDEF_DECL and
                        child.kind == CursorKind.STRUCT_DECL):
                    return 0

                errors += self.evaluate(child)

                # Members struct, class, and unions must be treated differently.
                # So parent ast node information is pushed in to the stack.
                # Once all its children are validated pop it out of the stack
                self.node_stack.push(child.kind)
                errors += self.check(child)
                self.node_stack.pop()

        return errors

    def evaluate(self, node):
        """
        get the node's rule and match the pattern. Report and error if pattern
        matching fails
        """
        if not self.rule_db.is_rule_enabled(node.kind):
            return 0

        # If the pattern is in the skip list, ignore it
        if self.skip_db.check_skip_db(node.displayname):
            return 0

        rule_name = self.rule_db.get_rule_names(node.kind)
        rule = self.rule_db.get_rule(rule_name)
        if rule.evaluate(node, self.node_stack.peek()) is False:
            return 1
        return 0

    def is_local(self, node, filename):
        """ Returns True is node belongs to the file being validated and not an include file """
        if node.location.file and node.location.file.name in filename:
            return True
        return False


def do_validate(options, filename):
    """
    Returns true if the file should be validated
    - Check if its a c/c++ file
    - Check if the file is not excluded
    """
    path, extension = os.path.splitext(filename)
    if extension not in file_extensions:
        return False

    if options.args.exclude:
        for item in options.args.exclude:
            if fnmatch.fnmatch(filename, item):
                return False

    return True


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s',
                        filename='log.txt', filemode='w')

    """ Parse all command line arguments and validate """
    op = Options()
    op.parse_cmd_line()

    if op.args.path is None:
        sys.exit(1)

    if op.args.clang_lib:
        Config.set_library_file(op.args.clang_lib)

    """ Creating the rules database """
    rules_db = RulesDb(op._style_file)

    """ Creating the skip database """
    skip_db = SkipDb(op._skip_file)

    """ Check the source code against the configured rules """
    errors = 0
    for path in op.args.path:
        if os.path.isfile(path):
            if do_validate(op, path):
                v = Validator(rules_db, path, op, skip_db)
                errors += v.validate()
        elif os.path.isdir(path):
            for (root, subdirs, files) in os.walk(path):
                for filename in files:
                    path = root + '/' + filename
                    if do_validate(op, path):
                        v = Validator(rules_db, path, op, skip_db)
                        errors += v.validate()

                if not op.args.recurse:
                    break
        else:
            sys.stderr.write("File '{}' not found!\n".format(path))
            sys.exit(1)

    if errors:
        print("Total number of errors = {}".format(errors))
        sys.exit(1)
