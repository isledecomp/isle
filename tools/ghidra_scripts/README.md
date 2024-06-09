# Ghidra Scripts

The scripts in this directory provide additional functionality in Ghidra, e.g. imports of symbols and types from the PDB debug symbol file.

## Setup

### Ghidrathon
Since these scripts and its dependencies are written in Python 3, [Ghidrathon](https://github.com/mandiant/Ghidrathon) must be installed first. Follow the instructions and install a recent build (these scripts were tested with Python 3.12 and Ghidrathon v4.0.0).

### Script Directory
- In Ghidra, _Open Window -> Script Manager_.
- Click the _Manage Script Directories_ button on the top right.
- Click the _Add_ (Plus icon) button and select this file's parent directory.
- Close the window and click the _Refresh_ button.
- This script should now be available under the folder _LEGO1_.

### Virtual environment
As of now, there must be a Python virtual environment set up under `$REPOSITORY_ROOT/.venv`, and the dependencies of `isledecomp` must be installed there, see [here](../README.md#tooling).

## Development
- Type hints for Ghidra (optional): Download a recent release from https://github.com/VDOO-Connected-Trust/ghidra-pyi-generator,
  unpack it somewhere, and `pip install` that directory in this virtual environment. This provides types and headers for Python.
  Be aware that some of these files contain errors - in particular, `from typing import overload` seems to be missing everywhere, leading to spurious type errors.
- Note that the imported modules persist across multiple runs of the script (see [here](https://github.com/mandiant/Ghidrathon/issues/103)).
  If you indend to modify an imported library, you have to use `import importlib; importlib.reload(${library})` or restart Ghidra for your changes to have any effect. Unfortunately, even that is not perfectly reliable, so you may still have to restart Ghidra for some changes in `isledecomp` to be applied.
