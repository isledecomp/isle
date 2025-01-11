from os import name as os_name
import pytest
from isledecomp.dir import PathResolver


if os_name != "nt":
    pytest.skip(reason="Skip Windows-only tests", allow_module_level=True)


@pytest.fixture(name="resolver")
def fixture_resolver_win():
    yield PathResolver("C:\\isle")


def test_identity(resolver):
    assert resolver.resolve_cvdump("C:\\isle\\test.h") == "C:\\isle\\test.h"


def test_outside_basedir(resolver):
    assert resolver.resolve_cvdump("C:\\lego\\test.h") == "C:\\lego\\test.h"


def test_relative(resolver):
    assert resolver.resolve_cvdump(".\\test.h") == "C:\\isle\\test.h"
    assert resolver.resolve_cvdump("..\\test.h") == "C:\\test.h"


def test_intermediate_relative(resolver):
    """These paths may not register as `relative` paths, but we want to
    produce a single absolute path for each."""
    assert resolver.resolve_cvdump("C:\\isle\\test\\..\\test.h") == "C:\\isle\\test.h"
    assert resolver.resolve_cvdump(".\\subdir\\..\\test.h") == "C:\\isle\\test.h"
