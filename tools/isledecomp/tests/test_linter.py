import pytest
from isledecomp.parser import DecompLinter
from isledecomp.parser.error import ParserError


@pytest.fixture(name="linter")
def fixture_linter():
    return DecompLinter()


def test_simple_in_order(linter):
    lines = [
        "// FUNCTION: TEST 0x1000",
        "void function1() {}",
        "// FUNCTION: TEST 0x2000",
        "void function2() {}",
        "// FUNCTION: TEST 0x3000",
        "void function3() {}",
    ]
    assert linter.check_lines(lines, "test.cpp", "TEST") is True


def test_simple_not_in_order(linter):
    lines = [
        "// FUNCTION: TEST 0x1000",
        "void function1() {}",
        "// FUNCTION: TEST 0x3000",
        "void function3() {}",
        "// FUNCTION: TEST 0x2000",
        "void function2() {}",
    ]
    assert linter.check_lines(lines, "test.cpp", "TEST") is False
    assert len(linter.alerts) == 1

    assert linter.alerts[0].code == ParserError.FUNCTION_OUT_OF_ORDER
    # N.B. Line number given is the start of the function, not the marker
    assert linter.alerts[0].line_number == 6


def test_byname_ignored(linter):
    """Should ignore lookup-by-name markers when checking order."""
    lines = [
        "// FUNCTION: TEST 0x1000",
        "void function1() {}",
        "// FUNCTION: TEST 0x3000",
        "// MyClass::MyMethod",
        "// FUNCTION: TEST 0x2000",
        "void function2() {}",
    ]
    # TODO: This will fail after enforcing that bynames belong in headers
    assert linter.check_lines(lines, "test.cpp", "TEST") is True
    assert len(linter.alerts) == 0


def test_module_isolation(linter):
    """Should check the order of markers from a single module only."""
    lines = [
        "// FUNCTION: ALPHA 0x0001",
        "// FUNCTION: TEST 0x1000",
        "void function1() {}",
        "// FUNCTION: ALPHA 0x0002",
        "// FUNCTION: TEST 0x2000",
        "void function2() {}",
        "// FUNCTION: ALPHA 0x0003",
        "// FUNCTION: TEST 0x3000",
        "void function3() {}",
    ]

    assert linter.check_lines(lines, "test.cpp", "TEST") is True
    assert linter.check_lines(lines, "test.cpp", "ALPHA") is True


def test_byname_headers_only(linter):
    """Markers that ar referenced by name with cvdump belong in header files only."""
    lines = [
        "// FUNCTION: TEST 0x1000",
        "// MyClass::~MyClass",
    ]

    assert linter.check_lines(lines, "test.h", "TEST") is True
    assert linter.check_lines(lines, "test.cpp", "TEST") is False
    assert linter.alerts[0].code == ParserError.BYNAME_FUNCTION_IN_CPP
