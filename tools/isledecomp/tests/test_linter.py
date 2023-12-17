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
    # This will fail because byname lookup does not belong in the cpp file
    assert linter.check_lines(lines, "test.cpp", "TEST") is False
    # but it should not fail for function order.
    assert all(
        alert.code != ParserError.FUNCTION_OUT_OF_ORDER for alert in linter.alerts
    )


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
    linter.reset(True)
    assert linter.check_lines(lines, "test.cpp", "ALPHA") is True


def test_byname_headers_only(linter):
    """Markers that ar referenced by name with cvdump belong in header files only."""
    lines = [
        "// FUNCTION: TEST 0x1000",
        "// MyClass::~MyClass",
    ]

    assert linter.check_lines(lines, "test.h", "TEST") is True
    linter.reset(True)
    assert linter.check_lines(lines, "test.cpp", "TEST") is False
    assert linter.alerts[0].code == ParserError.BYNAME_FUNCTION_IN_CPP


def test_duplicate_offsets(linter):
    """The linter will retain module/offset pairs found until we do a full reset."""
    lines = [
        "// FUNCTION: TEST 0x1000",
        "// FUNCTION: HELLO 0x1000",
        "// MyClass::~MyClass",
    ]

    # Should not fail for duplicate offset 0x1000 because the modules are unique.
    assert linter.check_lines(lines, "test.h", "TEST") is True

    # Simulate a failure by reading the same file twice.
    assert linter.check_lines(lines, "test.h", "TEST") is False

    # Two errors because offsets from both modules are duplicated
    assert len(linter.alerts) == 2
    assert all(a.code == ParserError.DUPLICATE_OFFSET for a in linter.alerts)

    # Partial reset will retain the list of seen offsets.
    linter.reset(False)
    assert linter.check_lines(lines, "test.h", "TEST") is False

    # Full reset will forget seen offsets.
    linter.reset(True)
    assert linter.check_lines(lines, "test.h", "TEST") is True
