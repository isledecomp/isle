def pytest_addoption(parser):
    """Allow the option to run tests against the original LEGO1.DLL."""
    parser.addoption("--lego1", action="store", help="Path to LEGO1.DLL")
