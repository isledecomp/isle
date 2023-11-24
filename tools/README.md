# LEGO Island Decompilation Tools

These are a set of Python tools for helping with the decomp project

## Installing
Use pip to install the required packages:

```
pip install -r tools/requirements.txt
```

## reccmp
This is a script to compare the original EXE or DLL with a recpmpiled EXE or DLL, provided a .PDB file

## verexp
This verifies exports by comparing the exports of an original DLL and the recompiled DLL

## checkorder
This checks the order of C++ source and header files to make sure the functions are in order

## Development
In order to keep the code clean and consistent, we use `pylint` and `black`:

```
pip install black pylint
```
### To run pylint:
```
pylint tools/ --ignore=build,tests,bin,lib
```

### To check code formatting without rewriting files:
```
black --check tools/
```
### To apply code formatting:
```
black tools/
```