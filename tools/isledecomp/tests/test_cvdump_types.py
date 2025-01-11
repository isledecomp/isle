"""Specifically testing the Cvdump TYPES parser
and type dependency tree walker."""

import pytest
from isledecomp.cvdump.types import (
    CvdumpTypesParser,
    CvdumpKeyError,
    CvdumpIntegrityError,
    FieldListItem,
    VirtualBaseClass,
    VirtualBasePointer,
)

TEST_LINES = """
0x1018 : Length = 18, Leaf = 0x1201 LF_ARGLIST argument count = 3
	list[0] = 0x100D
	list[1] = 0x1016
	list[2] = 0x1017

0x1019 : Length = 14, Leaf = 0x1008 LF_PROCEDURE
	Return type = T_LONG(0012), Call type = C Near
	Func attr = none
	# Parms = 3, Arg list type = 0x1018

0x101e : Length = 26, Leaf = 0x1009 LF_MFUNCTION
	Return type = T_CHAR(0010), Class type = 0x101A, This type = 0x101B,
	Call type = ThisCall, Func attr = none
	Parms = 2, Arg list type = 0x101d, This adjust = 0

0x1028 : Length = 10, Leaf = 0x1001 LF_MODIFIER
    const, modifies type T_REAL32(0040)

0x103b : Length = 14, Leaf = 0x1503 LF_ARRAY
    Element type = T_REAL32(0040)
    Index type = T_SHORT(0011)
    length = 16
    Name =

0x103c : Length = 14, Leaf = 0x1503 LF_ARRAY
    Element type = 0x103B
    Index type = T_SHORT(0011)
    length = 64
    Name =

0x10e0 : Length = 86, Leaf = 0x1203 LF_FIELDLIST
    list[0] = LF_MEMBER, public, type = T_REAL32(0040), offset = 0
        member name = 'x'
    list[1] = LF_MEMBER, public, type = T_REAL32(0040), offset = 0
        member name = 'dvX'
    list[2] = LF_MEMBER, public, type = T_REAL32(0040), offset = 4
        member name = 'y'
    list[3] = LF_MEMBER, public, type = T_REAL32(0040), offset = 4
        member name = 'dvY'
    list[4] = LF_MEMBER, public, type = T_REAL32(0040), offset = 8
        member name = 'z'
    list[5] = LF_MEMBER, public, type = T_REAL32(0040), offset = 8
        member name = 'dvZ'

0x10e1 : Length = 34, Leaf = 0x1505 LF_STRUCTURE
    # members = 6,  field list type 0x10e0,
    Derivation list type 0x0000, VT shape type 0x0000
    Size = 12, class name = _D3DVECTOR, UDT(0x000010e1)

0x10e4 : Length = 14, Leaf = 0x1503 LF_ARRAY
    Element type = T_UCHAR(0020)
    Index type = T_SHORT(0011)
    length = 8
    Name =

0x10ea : Length = 14, Leaf = 0x1503 LF_ARRAY
    Element type = 0x1028
    Index type = T_SHORT(0011)
    length = 12
    Name =

0x11f0 : Length = 30, Leaf = 0x1504 LF_CLASS
    # members = 0,  field list type 0x0000, FORWARD REF,
    Derivation list type 0x0000, VT shape type 0x0000
    Size = 0, class name = MxRect32, UDT(0x00001214)

0x11f2 : Length = 10, Leaf = 0x1001 LF_MODIFIER
    const, modifies type 0x11F0

0x1213 : Length = 530, Leaf = 0x1203 LF_FIELDLIST
    list[0] = LF_METHOD, count = 5, list = 0x1203, name = 'MxRect32'
    list[1] = LF_ONEMETHOD, public, VANILLA, index = 0x1205, name = 'operator='
    list[2] = LF_ONEMETHOD, public, VANILLA, index = 0x11F5, name = 'Intersect'
    list[3] = LF_ONEMETHOD, public, VANILLA, index = 0x1207, name = 'SetPoint'
    list[4] = LF_ONEMETHOD, public, VANILLA, index = 0x1207, name = 'AddPoint'
    list[5] = LF_ONEMETHOD, public, VANILLA, index = 0x1207, name = 'SubtractPoint'
    list[6] = LF_ONEMETHOD, public, VANILLA, index = 0x11F5, name = 'UpdateBounds'
    list[7] = LF_ONEMETHOD, public, VANILLA, index = 0x1209, name = 'IsValid'
    list[8] = LF_ONEMETHOD, public, VANILLA, index = 0x120A, name = 'IntersectsWith'
    list[9] = LF_ONEMETHOD, public, VANILLA, index = 0x120B, name = 'GetWidth'
    list[10] = LF_ONEMETHOD, public, VANILLA, index = 0x120B, name = 'GetHeight'
    list[11] = LF_ONEMETHOD, public, VANILLA, index = 0x120C, name = 'GetPoint'
    list[12] = LF_ONEMETHOD, public, VANILLA, index = 0x120D, name = 'GetSize'
    list[13] = LF_ONEMETHOD, public, VANILLA, index = 0x120B, name = 'GetLeft'
    list[14] = LF_ONEMETHOD, public, VANILLA, index = 0x120B, name = 'GetTop'
    list[15] = LF_ONEMETHOD, public, VANILLA, index = 0x120B, name = 'GetRight'
    list[16] = LF_ONEMETHOD, public, VANILLA, index = 0x120B, name = 'GetBottom'
    list[17] = LF_ONEMETHOD, public, VANILLA, index = 0x120E, name = 'SetLeft'
    list[18] = LF_ONEMETHOD, public, VANILLA, index = 0x120E, name = 'SetTop'
    list[19] = LF_ONEMETHOD, public, VANILLA, index = 0x120E, name = 'SetRight'
    list[20] = LF_ONEMETHOD, public, VANILLA, index = 0x120E, name = 'SetBottom'
    list[21] = LF_METHOD, count = 3, list = 0x1211, name = 'CopyFrom'
    list[22] = LF_ONEMETHOD, private, STATIC, index = 0x1212, name = 'Min'
    list[23] = LF_ONEMETHOD, private, STATIC, index = 0x1212, name = 'Max'
    list[24] = LF_MEMBER, private, type = T_INT4(0074), offset = 0
        member name = 'm_left'
    list[25] = LF_MEMBER, private, type = T_INT4(0074), offset = 4
        member name = 'm_top'
    list[26] = LF_MEMBER, private, type = T_INT4(0074), offset = 8
        member name = 'm_right'
    list[27] = LF_MEMBER, private, type = T_INT4(0074), offset = 12
        member name = 'm_bottom'

0x1214 : Length = 30, Leaf = 0x1504 LF_CLASS
    # members = 34,  field list type 0x1213, CONSTRUCTOR, OVERLOAD,
    Derivation list type 0x0000, VT shape type 0x0000
    Size = 16, class name = MxRect32, UDT(0x00001214)

0x1220 : Length = 30, Leaf = 0x1504 LF_CLASS
    # members = 0,  field list type 0x0000, FORWARD REF,
    Derivation list type 0x0000, VT shape type 0x0000
    Size = 0, class name = MxCore, UDT(0x00004060)

0x14db : Length = 30, Leaf = 0x1504 LF_CLASS
    # members = 0,  field list type 0x0000, FORWARD REF,
    Derivation list type 0x0000, VT shape type 0x0000
    Size = 0, class name = MxString, UDT(0x00004db6)

0x19b0 : Length = 34, Leaf = 0x1505 LF_STRUCTURE
    # members = 0,  field list type 0x0000, FORWARD REF,
    Derivation list type 0x0000, VT shape type 0x0000
    Size = 0, class name = ROIColorAlias, UDT(0x00002a76)

0x19b1 : Length = 14, Leaf = 0x1503 LF_ARRAY
    Element type = 0x19B0
    Index type = T_SHORT(0011)
    length = 440
    Name =

0x2339 : Length = 26, Leaf = 0x1506 LF_UNION
	# members = 0,  field list type 0x0000, FORWARD REF, Size = 0	,class name = FlagBitfield, UDT(0x00002e85)

0x2e85 : Length = 26, Leaf = 0x1506 LF_UNION
	# members = 8,  field list type 0x2e84, Size = 1	,class name = FlagBitfield, UDT(0x00002e85)

0x2a75 : Length = 98, Leaf = 0x1203 LF_FIELDLIST
    list[0] = LF_MEMBER, public, type = T_32PRCHAR(0470), offset = 0
        member name = 'm_name'
    list[1] = LF_MEMBER, public, type = T_INT4(0074), offset = 4
        member name = 'm_red'
    list[2] = LF_MEMBER, public, type = T_INT4(0074), offset = 8
        member name = 'm_green'
    list[3] = LF_MEMBER, public, type = T_INT4(0074), offset = 12
        member name = 'm_blue'
    list[4] = LF_MEMBER, public, type = T_INT4(0074), offset = 16
        member name = 'm_unk0x10'

0x2a76 : Length = 34, Leaf = 0x1505 LF_STRUCTURE
    # members = 5,  field list type 0x2a75,
    Derivation list type 0x0000, VT shape type 0x0000
    Size = 20, class name = ROIColorAlias, UDT(0x00002a76)

0x22d4 : Length = 154, Leaf = 0x1203 LF_FIELDLIST
    list[0] = LF_VFUNCTAB, type = 0x20FC
    list[1] = LF_METHOD, count = 3, list = 0x22D0, name = 'MxVariable'
    list[2] = LF_ONEMETHOD, public, INTRODUCING VIRTUAL, index = 0x1F0F,
        vfptr offset = 0, name = 'GetValue'
    list[3] = LF_ONEMETHOD, public, INTRODUCING VIRTUAL, index = 0x1F10,
        vfptr offset = 4, name = 'SetValue'
    list[4] = LF_ONEMETHOD, public, INTRODUCING VIRTUAL, index = 0x1F11,
        vfptr offset = 8, name = '~MxVariable'
    list[5] = LF_ONEMETHOD, public, VANILLA, index = 0x22D3, name = 'GetKey'
    list[6] = LF_MEMBER, protected, type = 0x14DB, offset = 4
        member name = 'm_key'
    list[7] = LF_MEMBER, protected, type = 0x14DB, offset = 20
        member name = 'm_value'

0x22d5 : Length = 34, Leaf = 0x1504 LF_CLASS
    # members = 10,  field list type 0x22d4, CONSTRUCTOR,
    Derivation list type 0x0000, VT shape type 0x20fb
    Size = 36, class name = MxVariable, UDT(0x00004041)

0x3c45 : Length = 50, Leaf = 0x1203 LF_FIELDLIST
	list[0] = LF_ENUMERATE, public, value = 1, name = 'c_read'
	list[1] = LF_ENUMERATE, public, value = 2, name = 'c_write'
	list[2] = LF_ENUMERATE, public, value = 4, name = 'c_text'

0x3cc2 : Length = 38, Leaf = 0x1507 LF_ENUM
    # members = 64,  type = T_INT4(0074) field list type 0x3cc1
NESTED,     enum name = JukeBox::JukeBoxScript, UDT(0x00003cc2)

0x3fab : Length = 10, Leaf = 0x1002 LF_POINTER
    Pointer (NEAR32), Size: 0
    Element type : 0x3FAA

0x405f : Length = 158, Leaf = 0x1203 LF_FIELDLIST
    list[0] = LF_VFUNCTAB, type = 0x2090
    list[1] = LF_ONEMETHOD, public, VANILLA, index = 0x176A, name = 'MxCore'
    list[2] = LF_ONEMETHOD, public, INTRODUCING VIRTUAL, index = 0x176A,
        vfptr offset = 0, name = '~MxCore'
    list[3] = LF_ONEMETHOD, public, INTRODUCING VIRTUAL, index = 0x176B,
        vfptr offset = 4, name = 'Notify'
    list[4] = LF_ONEMETHOD, public, INTRODUCING VIRTUAL, index = 0x2087,
        vfptr offset = 8, name = 'Tickle'
    list[5] = LF_ONEMETHOD, public, INTRODUCING VIRTUAL, index = 0x202F,
        vfptr offset = 12, name = 'ClassName'
    list[6] = LF_ONEMETHOD, public, INTRODUCING VIRTUAL, index = 0x2030,
        vfptr offset = 16, name = 'IsA'
    list[7] = LF_ONEMETHOD, public, VANILLA, index = 0x2091, name = 'GetId'
    list[8] = LF_MEMBER, private, type = T_UINT4(0075), offset = 4
        member name = 'm_id'

0x4060 : Length = 30, Leaf = 0x1504 LF_CLASS
    # members = 9,  field list type 0x405f, CONSTRUCTOR,
    Derivation list type 0x0000, VT shape type 0x1266
    Size = 8, class name = MxCore, UDT(0x00004060)

0x4262 : Length = 14, Leaf = 0x1503 LF_ARRAY
    Element type = 0x3CC2
    Index type = T_SHORT(0011)
    length = 24
    Name =

0x432f : Length = 14, Leaf = 0x1503 LF_ARRAY
    Element type = T_INT4(0074)
    Index type = T_SHORT(0011)
    length = 12
    Name =

0x4db5 : Length = 246, Leaf = 0x1203 LF_FIELDLIST
    list[0] = LF_BCLASS, public, type = 0x1220, offset = 0
    list[1] = LF_METHOD, count = 3, list = 0x14E3, name = 'MxString'
    list[2] = LF_ONEMETHOD, public, VIRTUAL, index = 0x14DE, name = '~MxString'
    list[3] = LF_METHOD, count = 2, list = 0x14E7, name = 'operator='
    list[4] = LF_ONEMETHOD, public, VANILLA, index = 0x14DE, name = 'ToUpperCase'
    list[5] = LF_ONEMETHOD, public, VANILLA, index = 0x14DE, name = 'ToLowerCase'
    list[6] = LF_ONEMETHOD, public, VANILLA, index = 0x14E8, name = 'operator+'
    list[7] = LF_ONEMETHOD, public, VANILLA, index = 0x14E9, name = 'operator+='
    list[8] = LF_ONEMETHOD, public, VANILLA, index = 0x14EB, name = 'Compare'
    list[9] = LF_ONEMETHOD, public, VANILLA, index = 0x14EC, name = 'GetData'
    list[10] = LF_ONEMETHOD, public, VANILLA, index = 0x4DB4, name = 'GetLength'
    list[11] = LF_MEMBER, private, type = T_32PRCHAR(0470), offset = 8
        member name = 'm_data'
    list[12] = LF_MEMBER, private, type = T_USHORT(0021), offset = 12
        member name = 'm_length'


0x4dee : Length = 406, Leaf = 0x1203 LF_FIELDLIST
	list[0] = LF_VBCLASS, public, direct base type = 0x15EA
		virtual base ptr = 0x43E9, vbpoff = 4, vbind = 3
	list[1] = LF_IVBCLASS, public, indirect base type = 0x1183
		virtual base ptr = 0x43E9, vbpoff = 4, vbind = 1
	list[2] = LF_IVBCLASS, public, indirect base type = 0x1468
		virtual base ptr = 0x43E9, vbpoff = 4, vbind = 2
	list[3] = LF_VFUNCTAB, type = 0x2B95
	list[4] = LF_ONEMETHOD, public, VANILLA, index = 0x15C2, name = 'LegoRaceMap'
	list[5] = LF_ONEMETHOD, public, VIRTUAL, index = 0x15C3, name = '~LegoRaceMap'
	list[6] = LF_ONEMETHOD, public, VIRTUAL, index = 0x15C5, name = 'Notify'
	list[7] = LF_ONEMETHOD, public, VIRTUAL, index = 0x15C4, name = 'ParseAction'
	list[8] = LF_ONEMETHOD, public, VIRTUAL, index = 0x4DED, name = 'VTable0x70'
	list[9] = LF_ONEMETHOD, public, INTRODUCING VIRTUAL, index = 0x15C2,
		vfptr offset = 0, name = 'FUN_1005d4b0'
	list[10] = LF_MEMBER, private, type = T_UCHAR(0020), offset = 8
		member name = 'm_parentClass2Field1'
	list[11] = LF_MEMBER, private, type = T_32PVOID(0403), offset = 12
		member name = 'm_parentClass2Field2'

0x4def : Length = 34, Leaf = 0x1504 LF_CLASS
	# members = 21,  field list type 0x4dee, CONSTRUCTOR,
	Derivation list type 0x0000, VT shape type 0x12a0
	Size = 436, class name = LegoRaceMap, UDT(0x00004def)

0x4db6 : Length = 30, Leaf = 0x1504 LF_CLASS
    # members = 16,  field list type 0x4db5, CONSTRUCTOR, OVERLOAD,
    Derivation list type 0x0000, VT shape type 0x1266
    Size = 16, class name = MxString, UDT(0x00004db6)

0x5591 : Length = 570, Leaf = 0x1203 LF_FIELDLIST
	list[0] = LF_VBCLASS, public, direct base type = 0x15EA
		virtual base ptr = 0x43E9, vbpoff = 4, vbind = 3
	list[1] = LF_IVBCLASS, public, indirect base type = 0x1183
		virtual base ptr = 0x43E9, vbpoff = 4, vbind = 1
	list[2] = LF_IVBCLASS, public, indirect base type = 0x1468
		virtual base ptr = 0x43E9, vbpoff = 4, vbind = 2
	list[3] = LF_VFUNCTAB, type = 0x4E11
	list[4] = LF_ONEMETHOD, public, VANILLA, index = 0x1ABD, name = 'LegoCarRaceActor'
	list[5] = LF_ONEMETHOD, public, VIRTUAL, index = 0x1AE0, name = 'ClassName'
	list[6] = LF_ONEMETHOD, public, VIRTUAL, index = 0x1AE1, name = 'IsA'
	list[7] = LF_ONEMETHOD, public, VIRTUAL, index = 0x1ADD, name = 'VTable0x6c'
	list[8] = LF_ONEMETHOD, public, VIRTUAL, index = 0x1ADB, name = 'VTable0x70'
	list[9] = LF_ONEMETHOD, public, VIRTUAL, index = 0x1ADA, name = 'SwitchBoundary'
	list[10] = LF_ONEMETHOD, public, VIRTUAL, index = 0x1ADC, name = 'VTable0x9c'
	list[11] = LF_ONEMETHOD, public, INTRODUCING VIRTUAL, index = 0x558E,
		vfptr offset = 0, name = 'FUN_10080590'
	list[12] = LF_ONEMETHOD, public, INTRODUCING VIRTUAL, index = 0x1AD8,
		vfptr offset = 4, name = 'FUN_10012bb0'
	list[13] = LF_ONEMETHOD, public, INTRODUCING VIRTUAL, index = 0x1AD9,
		vfptr offset = 8, name = 'FUN_10012bc0'
	list[14] = LF_ONEMETHOD, public, INTRODUCING VIRTUAL, index = 0x1AD8,
		vfptr offset = 12, name = 'FUN_10012bd0'
	list[15] = LF_ONEMETHOD, public, INTRODUCING VIRTUAL, index = 0x1AD9,
		vfptr offset = 16, name = 'FUN_10012be0'
	list[16] = LF_ONEMETHOD, public, INTRODUCING VIRTUAL, index = 0x1AD8,
		vfptr offset = 20, name = 'FUN_10012bf0'
	list[17] = LF_ONEMETHOD, public, INTRODUCING VIRTUAL, index = 0x1AD9,
		vfptr offset = 24, name = 'FUN_10012c00'
	list[18] = LF_ONEMETHOD, public, INTRODUCING VIRTUAL, index = 0x1ABD,
		vfptr offset = 28, name = 'VTable0x1c'
	list[19] = LF_MEMBER, protected, type = T_REAL32(0040), offset = 8
		member name = 'm_parentClass1Field1'
	list[25] = LF_ONEMETHOD, public, VIRTUAL, (compgenx), index = 0x15D1, name = '~LegoCarRaceActor'

0x5592 : Length = 38, Leaf = 0x1504 LF_CLASS
	# members = 26,  field list type 0x5591, CONSTRUCTOR,
	Derivation list type 0x0000, VT shape type 0x34c7
	Size = 416, class name = LegoCarRaceActor, UDT(0x00005592)

0x5593 : Length = 638, Leaf = 0x1203 LF_FIELDLIST
	list[0] = LF_BCLASS, public, type = 0x5592, offset = 0
	list[1] = LF_BCLASS, public, type = 0x4DEF, offset = 32
	list[2] = LF_IVBCLASS, public, indirect base type = 0x1183
		virtual base ptr = 0x43E9, vbpoff = 4, vbind = 1
	list[3] = LF_IVBCLASS, public, indirect base type = 0x1468
		virtual base ptr = 0x43E9, vbpoff = 4, vbind = 2
	list[4] = LF_IVBCLASS, public, indirect base type = 0x15EA
		virtual base ptr = 0x43E9, vbpoff = 4, vbind = 3
	list[5] = LF_ONEMETHOD, public, VANILLA, index = 0x15CD, name = 'LegoRaceCar'
	list[6] = LF_ONEMETHOD, public, VIRTUAL, index = 0x15CE, name = '~LegoRaceCar'
	list[7] = LF_ONEMETHOD, public, VIRTUAL, index = 0x15D2, name = 'Notify'
	list[8] = LF_ONEMETHOD, public, VIRTUAL, index = 0x15E8, name = 'ClassName'
	list[9] = LF_ONEMETHOD, public, VIRTUAL, index = 0x15E9, name = 'IsA'
	list[10] = LF_ONEMETHOD, public, VIRTUAL, index = 0x15D5, name = 'ParseAction'
	list[11] = LF_ONEMETHOD, public, VIRTUAL, index = 0x15D3, name = 'SetWorldSpeed'
	list[12] = LF_ONEMETHOD, public, VIRTUAL, index = 0x15DF, name = 'VTable0x6c'
	list[13] = LF_ONEMETHOD, public, VIRTUAL, index = 0x15D3, name = 'VTable0x70'
	list[14] = LF_ONEMETHOD, public, VIRTUAL, index = 0x15DC, name = 'VTable0x94'
	list[15] = LF_ONEMETHOD, public, VIRTUAL, index = 0x15E5, name = 'SwitchBoundary'
	list[16] = LF_ONEMETHOD, public, VIRTUAL, index = 0x15DD, name = 'VTable0x9c'
	list[17] = LF_ONEMETHOD, public, INTRODUCING VIRTUAL, index = 0x15D4,
		vfptr offset = 32, name = 'SetMaxLinearVelocity'
	list[18] = LF_ONEMETHOD, public, INTRODUCING VIRTUAL, index = 0x15D4,
		vfptr offset = 36, name = 'FUN_10012ff0'
	list[19] = LF_ONEMETHOD, public, INTRODUCING VIRTUAL, index = 0x5588,
		vfptr offset = 40, name = 'HandleSkeletonKicks'
	list[20] = LF_MEMBER, private, type = T_UCHAR(0020), offset = 84
		member name = 'm_childClassField'

0x5594 : Length = 34, Leaf = 0x1504 LF_CLASS
	# members = 30,  field list type 0x5593, CONSTRUCTOR,
	Derivation list type 0x0000, VT shape type 0x2d1e
	Size = 512, class name = LegoRaceCar, UDT(0x000055bb)
"""


@pytest.fixture(name="parser")
def types_parser_fixture():
    parser = CvdumpTypesParser()
    for line in TEST_LINES.split("\n"):
        parser.read_line(line)

    return parser


def test_basic_parsing(parser: CvdumpTypesParser):
    obj = parser.keys["0x4db6"]
    assert obj["type"] == "LF_CLASS"
    assert obj["name"] == "MxString"
    assert obj["udt"] == "0x4db6"

    assert len(parser.keys["0x4db5"]["members"]) == 2


def test_scalar_types(parser: CvdumpTypesParser):
    """Full tests on the scalar_* methods are in another file.
    Here we are just testing the passthrough of the "T_" types."""
    assert parser.get("T_CHAR").name is None
    assert parser.get("T_CHAR").size == 1

    assert parser.get("T_32PVOID").name is None
    assert parser.get("T_32PVOID").size == 4


def test_resolve_forward_ref(parser: CvdumpTypesParser):
    # Non-forward ref
    assert parser.get("0x22d5").name == "MxVariable"
    # Forward ref
    assert parser.get("0x14db").name == "MxString"
    assert parser.get("0x14db").size == 16


def test_members(parser: CvdumpTypesParser):
    """Return the list of items to compare for a given complex type.
    If the class has a superclass, add those members too."""
    # MxCore field list
    mxcore_members = parser.get_scalars("0x405f")
    assert mxcore_members == [
        (0, "vftable", "T_32PVOID"),
        (4, "m_id", "T_UINT4"),
    ]

    # MxCore class id. Should be the same members
    assert mxcore_members == parser.get_scalars("0x4060")

    # MxString field list. Should add inherited members from MxCore
    assert parser.get_scalars("0x4db5") == [
        (0, "vftable", "T_32PVOID"),
        (4, "m_id", "T_UINT4"),
        (8, "m_data", "T_32PRCHAR"),
        (12, "m_length", "T_USHORT"),
    ]

    # LegoRaceCar with multiple superclasses
    assert parser.get("0x5594").members == [
        FieldListItem(offset=0, name="vftable", type="T_32PVOID"),
        FieldListItem(offset=0, name="vftable", type="T_32PVOID"),
        FieldListItem(offset=8, name="m_parentClass1Field1", type="T_REAL32"),
        FieldListItem(offset=8, name="m_parentClass2Field1", type="T_UCHAR"),
        FieldListItem(offset=12, name="m_parentClass2Field2", type="T_32PVOID"),
        FieldListItem(offset=84, name="m_childClassField", type="T_UCHAR"),
    ]


def test_virtual_base_classes(parser: CvdumpTypesParser):
    """Make sure that virtual base classes are parsed correctly."""

    lego_car_race_actor = parser.keys.get("0x5591")
    assert lego_car_race_actor is not None
    assert lego_car_race_actor["vbase"] == VirtualBasePointer(
        vboffset=4,
        bases=[
            VirtualBaseClass(type="0x1183", index=1, direct=False),
            VirtualBaseClass(type="0x1468", index=2, direct=False),
            VirtualBaseClass(type="0x15EA", index=3, direct=True),
        ],
    )


def test_members_recursive(parser: CvdumpTypesParser):
    """Make sure that we unwrap the dependency tree correctly."""
    # MxVariable field list
    assert parser.get_scalars("0x22d4") == [
        (0, "vftable", "T_32PVOID"),
        (4, "m_key.vftable", "T_32PVOID"),
        (8, "m_key.m_id", "T_UINT4"),
        (12, "m_key.m_data", "T_32PRCHAR"),
        (16, "m_key.m_length", "T_USHORT"),  # with padding
        (20, "m_value.vftable", "T_32PVOID"),
        (24, "m_value.m_id", "T_UINT4"),
        (28, "m_value.m_data", "T_32PRCHAR"),
        (32, "m_value.m_length", "T_USHORT"),  # with padding
    ]


def test_struct(parser: CvdumpTypesParser):
    """Basic test for converting type into struct.unpack format string."""
    # MxCore: vftable and uint32. The vftable pointer is read as uint32.
    assert parser.get_format_string("0x4060") == "<LL"

    # _D3DVECTOR, three floats. Union types should already be removed.
    assert parser.get_format_string("0x10e1") == "<fff"

    # MxRect32, four signed ints.
    assert parser.get_format_string("0x1214") == "<llll"


def test_struct_padding(parser: CvdumpTypesParser):
    """For data comparison purposes, make sure we have no gaps in the
    list of scalar types. Any gap is filled by an unsigned char."""

    # MxString, padded to 16 bytes. 4 actual members. 2 bytes of padding.
    assert len(parser.get_scalars("0x4db6")) == 4
    assert len(parser.get_scalars_gapless("0x4db6")) == 6

    # MxVariable, with two MxStrings (and a vtable)
    # Fill in the middle gap and the outer gap.
    assert len(parser.get_scalars("0x22d5")) == 9
    assert len(parser.get_scalars_gapless("0x22d5")) == 13


def test_struct_format_string(parser: CvdumpTypesParser):
    """Generate the struct.unpack format string using the
    list of scalars with padding filled in."""
    # MxString, padded to 16 bytes.
    assert parser.get_format_string("0x4db6") == "<LLLHBB"

    # MxVariable, with two MxString members.
    assert parser.get_format_string("0x22d5") == "<LLLLHBBLLLHBB"


def test_array(parser: CvdumpTypesParser):
    """LF_ARRAY members are created dynamically based on the
    total array size and the size of one element."""
    # unsigned char[8]
    assert parser.get_scalars("0x10e4") == [
        (0, "[0]", "T_UCHAR"),
        (1, "[1]", "T_UCHAR"),
        (2, "[2]", "T_UCHAR"),
        (3, "[3]", "T_UCHAR"),
        (4, "[4]", "T_UCHAR"),
        (5, "[5]", "T_UCHAR"),
        (6, "[6]", "T_UCHAR"),
        (7, "[7]", "T_UCHAR"),
    ]

    # float[4]
    assert parser.get_scalars("0x103b") == [
        (0, "[0]", "T_REAL32"),
        (4, "[1]", "T_REAL32"),
        (8, "[2]", "T_REAL32"),
        (12, "[3]", "T_REAL32"),
    ]


def test_2d_array(parser: CvdumpTypesParser):
    """Make sure 2d array elements are named as we expect."""
    # float[4][4]
    float_array = parser.get_scalars("0x103c")
    assert len(float_array) == 16
    assert float_array[0] == (0, "[0][0]", "T_REAL32")
    assert float_array[1] == (4, "[0][1]", "T_REAL32")
    assert float_array[4] == (16, "[1][0]", "T_REAL32")
    assert float_array[-1] == (60, "[3][3]", "T_REAL32")


def test_enum(parser: CvdumpTypesParser):
    """LF_ENUM should equal 4-byte int"""
    assert parser.get("0x3cc2").size == 4
    assert parser.get_scalars("0x3cc2") == [(0, None, "T_INT4")]

    # Now look at an array of enum, 24 bytes
    enum_array = parser.get_scalars("0x4262")
    assert len(enum_array) == 6  # 24 / 4
    assert enum_array[0].size == 4


def test_lf_pointer(parser: CvdumpTypesParser):
    """LF_POINTER is just a wrapper for scalar pointer type"""
    assert parser.get("0x3fab").size == 4
    # assert parser.get("0x3fab").is_pointer is True  # TODO: ?

    assert parser.get_scalars("0x3fab") == [(0, None, "T_32PVOID")]


def test_key_not_exist(parser: CvdumpTypesParser):
    """Accessing a non-existent type id should raise our exception"""
    with pytest.raises(CvdumpKeyError):
        parser.get("0xbeef")

    with pytest.raises(CvdumpKeyError):
        parser.get_scalars("0xbeef")


def test_broken_forward_ref(parser: CvdumpTypesParser):
    """Raise an exception if we cannot follow a forward reference"""
    # Verify forward reference on MxCore
    parser.get("0x1220")

    # Delete the MxCore LF_CLASS
    del parser.keys["0x4060"]

    # Forward ref via 0x1220 will fail
    with pytest.raises(CvdumpKeyError):
        parser.get("0x1220")


def test_null_forward_ref(parser: CvdumpTypesParser):
    """If the forward ref object is invalid and has no forward ref id,
    raise an exception."""
    # Test MxString forward reference
    parser.get("0x14db")

    # Delete the UDT for MxString
    del parser.keys["0x14db"]["udt"]

    # Cannot complete the forward reference lookup
    with pytest.raises(CvdumpIntegrityError):
        parser.get("0x14db")


def test_broken_array_element_ref(parser: CvdumpTypesParser):
    # Test LF_ARRAY of ROIColorAlias
    parser.get("0x19b1")

    # Delete ROIColorAlias
    del parser.keys["0x19b0"]

    # Type reference lookup will fail
    with pytest.raises(CvdumpKeyError):
        parser.get("0x19b1")


def test_lf_modifier(parser: CvdumpTypesParser):
    """Is this an alias for another type?"""
    # Modifies float
    assert parser.get("0x1028").size == 4
    assert parser.get_scalars("0x1028") == [(0, None, "T_REAL32")]

    mxrect = parser.get_scalars("0x1214")
    # Modifies MxRect32 via forward ref
    assert mxrect == parser.get_scalars("0x11f2")


def test_union_members(parser: CvdumpTypesParser):
    """If there is a union somewhere in our dependency list, we can
    expect to see duplicated member offsets and names. This is ok for
    the TypeInfo tuple, but the list of ScalarType items should have
    unique offset to simplify comparison."""

    # D3DVector type with duplicated offsets
    d3dvector = parser.get("0x10e1")
    assert d3dvector.members is not None
    assert len(d3dvector.members) == 6
    assert len([m for m in d3dvector.members if m.offset == 0]) == 2

    # Deduplicated comparison list
    vector_items = parser.get_scalars("0x10e1")
    assert len(vector_items) == 3


def test_arglist(parser: CvdumpTypesParser):
    arglist = parser.keys["0x1018"]
    assert arglist["argcount"] == 3
    assert arglist["args"] == ["0x100D", "0x1016", "0x1017"]


def test_procedure(parser: CvdumpTypesParser):
    procedure = parser.keys["0x1019"]
    assert procedure == {
        "type": "LF_PROCEDURE",
        "return_type": "T_LONG(0012)",
        "call_type": "C Near",
        "func_attr": "none",
        "num_params": "3",
        "arg_list_type": "0x1018",
    }


def test_mfunction(parser: CvdumpTypesParser):
    mfunction = parser.keys["0x101e"]
    assert mfunction == {
        "type": "LF_MFUNCTION",
        "return_type": "T_CHAR(0010)",
        "class_type": "0x101A",
        "this_type": "0x101B",
        "call_type": "ThisCall",
        "func_attr": "none",
        "num_params": "2",
        "arg_list_type": "0x101d",
        "this_adjust": "0",
    }


def test_union_forward_ref(parser: CvdumpTypesParser):
    union = parser.keys["0x2339"]
    assert union["is_forward_ref"] is True
    assert union["udt"] == "0x2e85"


def test_union(parser: CvdumpTypesParser):
    union = parser.keys["0x2e85"]
    assert union == {
        "type": "LF_UNION",
        "name": "FlagBitfield",
        "size": 1,
        "udt": "0x2e85",
    }


def test_fieldlist_enumerate(parser: CvdumpTypesParser):
    fieldlist_enum = parser.keys["0x3c45"]
    assert fieldlist_enum == {
        "type": "LF_FIELDLIST",
        "variants": [
            {"name": "c_read", "value": 1},
            {"name": "c_write", "value": 2},
            {"name": "c_text", "value": 4},
        ],
    }


UNNAMED_UNION_DATA = """
0x369d : Length = 34, Leaf = 0x1203 LF_FIELDLIST
    list[0] = LF_MEMBER, public, type = T_32PRCHAR(0470), offset = 0
        member name = 'sz'
    list[1] = LF_MEMBER, public, type = T_32PUSHORT(0421), offset = 0
        member name = 'wz'

0x369e : Length = 22, Leaf = 0x1506 LF_UNION
    # members = 2,  field list type 0x369d, NESTED, Size = 4    ,class name = __unnamed
"""


def test_unnamed_union():
    """Make sure we can parse anonymous union types without a UDT"""
    parser = CvdumpTypesParser()
    for line in UNNAMED_UNION_DATA.split("\n"):
        parser.read_line(line)

    # Make sure we can parse the members line
    union = parser.keys["0x369e"]
    assert union["size"] == 4
