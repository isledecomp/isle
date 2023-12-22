from os import name as os_name
from unittest.mock import patch
import pytest
from isledecomp.dir import PathResolver


if os_name == "nt":
    pytest.skip(reason="Skip Posix-only tests", allow_module_level=True)


@pytest.fixture(name="resolver")
def fixture_resolver_posix():
    # Skip the call to winepath by using a patch, although this is not strictly necessary.
    with patch("isledecomp.dir.winepath_unix_to_win", return_value="Z:\\usr\\isle"):
        yield PathResolver("/usr/isle")


@patch("isledecomp.dir.winepath_win_to_unix")
def test_identity(winepath_mock, resolver):
    """Test with an absolute Wine path where a path swap is possible."""
    # In this and upcoming tests, patch is_file so we always assume there is
    # a file at the given unix path. We want to test the conversion logic only.
    with patch("pathlib.Path.is_file", return_value=True):
        assert resolver.resolve_cvdump("Z:\\usr\\isle\\test.h") == "/usr/isle/test.h"
    winepath_mock.assert_not_called()

    # Without the patch, this should call the winepath_mock, but we have
    # memoized the value from the previous run.
    assert resolver.resolve_cvdump("Z:\\usr\\isle\\test.h") == "/usr/isle/test.h"
    winepath_mock.assert_not_called()


@patch("isledecomp.dir.winepath_win_to_unix")
def test_file_does_not_exist(winepath_mock, resolver):
    """These test files (probably) don't exist, so we always assume
    the path swap failed and defer to winepath."""
    resolver.resolve_cvdump("Z:\\usr\\isle\\test.h")
    winepath_mock.assert_called_once_with("Z:\\usr\\isle\\test.h")


@patch("isledecomp.dir.winepath_win_to_unix")
def test_outside_basedir(winepath_mock, resolver):
    """Test an absolute path where we cannot do a path swap."""
    with patch("pathlib.Path.is_file", return_value=True):
        resolver.resolve_cvdump("Z:\\lego\\test.h")
    winepath_mock.assert_called_once_with("Z:\\lego\\test.h")


@patch("isledecomp.dir.winepath_win_to_unix")
def test_relative(winepath_mock, resolver):
    """Test relative paths inside and outside of the base dir."""
    with patch("pathlib.Path.is_file", return_value=True):
        assert resolver.resolve_cvdump("./test.h") == "/usr/isle/test.h"

        # This works because we will resolve "/usr/isle/test/../test.h"
        assert resolver.resolve_cvdump("../test.h") == "/usr/test.h"
    winepath_mock.assert_not_called()


@patch("isledecomp.dir.winepath_win_to_unix")
def test_intermediate_relative(winepath_mock, resolver):
    """We can resolve intermediate backdirs if they are relative to the basedir."""
    with patch("pathlib.Path.is_file", return_value=True):
        assert (
            resolver.resolve_cvdump("Z:\\usr\\isle\\test\\..\\test.h")
            == "/usr/isle/test.h"
        )
        assert resolver.resolve_cvdump(".\\subdir\\..\\test.h") == "/usr/isle/test.h"
    winepath_mock.assert_not_called()
