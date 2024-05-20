# Ghidra Scripts

The scripts in this directory provide additional functionality in Ghidra, e.g. imports of symbols from the PDB debug symbol file.

## Setup

### Ghidrathon
Since these scripts and its dependencies are written in Python 3, [Ghidrathon](https://github.com/mandiant/Ghidrathon) must be installed first. Follow the instructions and install a recent build (these scripts were tested with Python 3.12 and Ghidrathon v4.0.0).

### Script Directory
- In Ghidra, _Open Window -> Script Manager_.
- Click the _Manage Script Directories_ button on the top right.
- Click the _Add_ (Plus icon) button and select this file's parent directory.
- Close the window and click the _Refresh_ button.
- This script should now be available under the folder _LEGO1_.

## Development
- Type hints for Ghira (optional): Download a recent release from https://github.com/VDOO-Connected-Trust/ghidra-pyi-generator,
  unpack it somewhere, and `pip install` that directory in this virtual environment. This provides types and headers for Python.
- Note that as of 2024-05-20 there is a [bug](https://github.com/mandiant/Ghidrathon/issues/103) in Ghidrathon v4.0.0: Changes in dependent scripts are not detected. If you modify a file that is imported by the script, you must restart Ghidra for the change to have any effect.
