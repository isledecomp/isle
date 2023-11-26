# LEGO Island Decompilation Tools

These are a set of Python tools for helping with the decomp project.

## Installing
Use pip to install the required packages:

```
pip install -r tools/requirements.txt
```

## Overview

* `reccmp`: Compares the original EXE or DLL with a recompiled EXE or DLL, provided a PDB file
* `verexp`: Verifies exports by comparing the exports of the original DLL and the recompiled DLL
* `checkorder`: Checks `OFFSET` declarations, ensuring they appear in ascending order within a unit
* `isledecomp`: A library that is used by the above scripts, it has a collection of useful classes and functions

## Testing
`isledecomp` has a small suite of tests. Install pylint and run it, passing in the directory:

```
pip install pytest
pytest tools/isledecomp/tests/
```

## Development
In order to keep the code clean and consistent, we use `pylint` and `black`:

```
pip install black pylint
```
### Run pylint (ignores build and virtualenv):
```
pylint tools/ --ignore=build,bin,lib
```
### Check code formatting without rewriting files:
```
black --check tools/
```
### Apply code formatting:
```
black tools/
```
