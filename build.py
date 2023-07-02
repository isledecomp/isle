#! /usr/bin/env python3

import pathlib
import subprocess
import argparse
import re
import requests

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--inspect", metavar='<offset>',
  help="Get an assembly diff for the function at a given offset after building. "
  "When decomping you will typically run this command over and over again as "
  "you refine your code towards a 100% match.")
parser.add_argument("-s", "--status", action="store_true",
  help="Get a general status report on the progress decompiling all functions.")
parser.add_argument("--inspect-shim", nargs=2, metavar=('<file>', '<line>'),
  help="Inspect the assembly diff of the function spanning <line> in <file>. "
  "Intended to be invoked by IDE commands.")
args = parser.parse_args()

# Figure out what offset to pass to the reccmp tool if any
def get_inspect_offset():
  if inspect_offset := args.inspect:
    if inspect_offset.startswith("0x"):
      return inspect_offset
    else:
      return "0x" + inspect_offset
  elif args.inspect_shim:
    print("Inspect: ", args.inspect_shim[0], ":", args.inspect_shim[1])
    with open(args.inspect_shim[0], 'r') as f:
      # get the lines in an array
      lines = f.readlines()
      OFFSET_PATTERN = re.compile(r'OFFSET:\s*LEGO1\s*(0x[0-9a-f]+)')
      for i in range(int(args.inspect_shim[1]), 0, -1):
        if i > 0 and i < len(lines):
          if match := OFFSET_PATTERN.search(lines[i]):
            inspect_offset = match.group(1)
            break
      if inspect_offset:
        return inspect_offset
      else:
        print("Could not find any function to inspect near cursor.")
        exit(1)
  return None

# If the build directory doesn't exist yet, run configure.py
if not pathlib.Path("build").exists():
  print("Not configured yet, please run configure.py first.")
  exit(1)

# Run cmake, with no parallel build because that does not play nice the
# MSVC420 compiler the original game was built with thanks to the different
# threads contending over the pdb file.
result = subprocess.run(["cmake", "--build", ".", "-j", "1"], cwd="build")

def require_original():
  if not pathlib.Path("original/LEGO1.DLL").exists():
    print("Couldn't find original/LEGO1.DLL. Downloading a copy...")
    url1 = "https://legoisland.org/download/ISLE.EXE"
    r1 = requests.get(url1, stream=True)
    if r1.status_code == 200:
      with open("original/ISLE.EXE", 'wb') as f:
        for chunk in r1.iter_content(chunk_size=8192):
            f.write(chunk)
    url2 = "https://legoisland.org/download/LEGO1.DLL"
    r2 = requests.get(url2, stream=True)
    if r2.status_code == 200:
      with open("original/LEGO1.DLL", 'wb') as f:
        for chunk in r2.iter_content(chunk_size=8192):
            f.write(chunk)
    else:
        print("Failed to find or download LEGO1.DLL.")
        print("Please obtain a copy from the original game and place it in `original/`")
        exit(1)
    print("Downloaded LEGO1.DLL to `original/`.")

# If the build succeeded, run the decompiler
if result.returncode == 0:
  if inspect_offset := get_inspect_offset():
    require_original()
    subprocess.run(["python", "tools/reccmp/reccmp.py",
      "original/LEGO1.DLL", "build/LEGO1.DLL",
      "build/LEGO1.PDB", ".",
      "-v", inspect_offset])

  elif args.status:
    require_original()
    subprocess.run(["python", "tools/reccmp/reccmp.py",
      "original/LEGO1.DLL", "build/LEGO1.DLL",
      "build/LEGO1.PDB", "."])

else:
  print("Build failed.")
  exit(1)
