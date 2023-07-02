#!/usr/bin/env python3

import argparse
import io
import os
import pathlib
import platform
import requests
import shutil
import subprocess
import textwrap
import zipfile

ISLE_PATH = pathlib.Path(__file__).parents[0]

parser = argparse.ArgumentParser(allow_abbrev=False)
parser.add_argument("-m", "--modern-compiler", action="store_true",
  help="Use a contemporary compiler instead of Microsoft Visual C++ 4.2 even though this will result in non-matching code")
parser.add_argument("-B", dest="builddir", default=ISLE_PATH / "build", type=pathlib.Path, help="build directory")
args = parser.parse_args()

builddir = args.builddir.resolve()

compilerdir = ISLE_PATH / "tools/msvc42"

# Create a build folder in the current directory if it does not exist
builddir.mkdir(parents=True, exist_ok=True)

# Check if MSVC420 is in the INCLUDE environment variable
set_compiler_paths = not args.modern_compiler
if not args.modern_compiler and not compilerdir.exists():
  # Create a folder for the compiler
  compilerdir.mkdir(parents=True, exist_ok=True)

  print(f"MSVC420 not found in {compilerdir}/...")
  url = "https://github.com/itsmattkc/MSVC420/archive/refs/heads/master.zip"
  print("Downloading MSVC420...")
  r = requests.get(url, stream=True)
  z = zipfile.ZipFile(io.BytesIO(r.content))
  print(f"Unzipping MSVC420 to {compilerdir}/...")
  for name in z.namelist():
    info = z.getinfo(name)
    # Remove the MSVC420-master prefix
    extract_name = name.split("/", 1)[1]
    if not extract_name:
      continue
    fullpath = compilerdir / extract_name
    if info.is_dir():
      fullpath.mkdir(parents=True, exist_ok=True)
    else:
      with fullpath.open("wb") as f:
        f.write(z.read(name))

# Run cmake in the build folder
cmake_cmd = [
  "cmake",
  str(ISLE_PATH),
  "-G", "Ninja",
  "-DCMAKE_BUILD_TYPE=RelWithDebInfo"
]

# Do we have a builtin ninja?
if shutil.which("ninja") is None:
  sys = platform.system()
  ninjadir = ISLE_PATH / "tools/ninja" / sys
  ninja_urls = {
    "Windows": "https://github.com/ninja-build/ninja/releases/download/v1.11.1/ninja-win.zip",
    "Linux": "https://github.com/ninja-build/ninja/releases/download/v1.11.1/ninja-linux.zip",
    "Darwin": "https://github.com/ninja-build/ninja/releases/download/v1.11.1/ninja-mac.zip",
  }
  if sys not in ninja_urls:
    print("Ninja is not available for this platform, please install ninja and add it to your PATH.")
    exit(1)
  if not ninjadir.exists():
    print("Downloading Ninja...")
    r = requests.get(ninja_urls[sys], stream=True)
    z = zipfile.ZipFile(io.BytesIO(r.content))
    print(f"Unzipping Ninja to {ninjadir}/...")
    z.extractall(path=str(ninjadir))

  specific_ninja = ninjadir / ("ninja" + ".exe" if sys == "Windows" else "")

  print("Using specific ninja:", specific_ninja)
  cmake_cmd += [f"-DCMAKE_MAKE_PROGRAM={specific_ninja.as_posix()}"]

extra_include_dirs = []
extra_library_dirs = []

if set_compiler_paths:
  full_compiler_path = compilerdir
  cl_path = (full_compiler_path / "bin" / "CL.EXE").as_posix()
  link_path = (full_compiler_path / "bin" / "LINK.EXE").as_posix()
  rc_path = (full_compiler_path / "bin" / "RC.EXE").as_posix()

  extra_include_dirs += [
    (full_compiler_path / "include").as_posix(),
  ]
  extra_library_dirs += [
    (full_compiler_path / "lib").as_posix(),
  ]

  cmake_toolchain_file = builddir / "msvc42.cmake"
  cmake_cmd += [f"-DCMAKE_TOOLCHAIN_FILE={cmake_toolchain_file}"]
  with cmake_toolchain_file.open("w") as f:
    print(textwrap.dedent(f"""\
      set(CMAKE_C_COMPILER "{cl_path}")
      set(CMAKE_CXX_COMPILER "{cl_path}")
      set(CMAKE_RC_COMPILER "{rc_path}")
      set(CMAKE_LINKER "{link_path}")
    """), file=f)
    for incdir in extra_include_dirs:
      print(f"""include_directories("{incdir}")""", file=f)
    for libdir in extra_library_dirs:
      print(f"""link_directories("{libdir}")""", file=f)

print("cmake command:", " ".join(cmake_cmd))
subprocess.run(cmake_cmd, cwd=builddir)

# Create a folder for the original binaries
if not pathlib.Path("original/LEGO1.DLL").exists():
  pathlib.Path("original").mkdir(parents=True, exist_ok=True)
  print("\nIf you plan on contributing, place a copy of the original game's "
    "ISLE.EXE and LEGO1.DLL into the `original/` folder so that the assembly "
    "diff tools can compare against them. If you do not, build.py will download "
    "a copy of these files for you.")
