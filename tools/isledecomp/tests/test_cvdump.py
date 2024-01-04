import pytest
from isledecomp.cvdump.analysis import data_type_info

# fmt: off
type_check_cases = [
    ("T_32PINT4",      4, True),
    ("T_32PLONG",      4, True),
    ("T_32PRCHAR",     4, True),
    ("T_32PREAL32",    4, True),
    ("T_32PUCHAR",     4, True),
    ("T_32PUINT4",     4, True),
    ("T_32PULONG",     4, True),
    ("T_32PUSHORT",    4, True),
    ("T_32PVOID",      4, True),
    ("T_CHAR",         1, False),
    ("T_INT4",         4, False),
    ("T_LONG",         4, False),
    ("T_NOTYPE",       0, False),  # ?
    ("T_QUAD",         8, False),
    ("T_RCHAR",        1, False),
    ("T_REAL32",       4, False),
    ("T_REAL64",       8, False),
    ("T_SHORT",        2, False),
    ("T_UCHAR",        1, False),
    ("T_UINT4",        4, False),
    ("T_ULONG",        4, False),
    ("T_UQUAD",        8, False),
    ("T_USHORT",       2, False),
    ("T_VOID",         0, False),  # ?
    ("T_WCHAR",        2, False),
]
# fmt: on


@pytest.mark.parametrize("type_name, size, is_pointer", type_check_cases)
def test_type_check(type_name: str, size: int, is_pointer: bool):
    assert (info := data_type_info(type_name)) is not None
    assert info[0] == size
    assert info[1] == is_pointer
