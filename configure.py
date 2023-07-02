
import pathlib
import subprocess
import argparse
import shutil
import platform
import requests
import zipfile
import io
import os

parser = argparse.ArgumentParser()
parser.add_argument("-m", "--modern-compiler", action="store_true",
  help="Use a contemporary compiler instead of Microsoft Visual C++ 4.2 even though this will result in non-matching code")
args = parser.parse_args()

# Do we have a builtin ninja?
specific_ninja = None
if shutil.which("ninja") is None:
  sys = platform.system()
  # Use the bundled ninja
  if sys == "Windows":
    specific_ninja = "./tools/ninja/ninja-win.exe"
  elif sys == "Linux":
    specific_ninja = "./tools/ninja/ninja-linux"
  elif sys == "Darwin":
    specific_ninja = "./tools/ninja/ninja-mac"
  else:
    print("No bundled ninja for this platform, please install ninja and add it to your path.")
    exit(1)
  specific_ninja = str(pathlib.Path(specific_ninja).absolute())

# Create a build folder in the current directory if it does not exist
pathlib.Path("build").mkdir(parents=True, exist_ok=True)

# Create a folder for the compiler
pathlib.Path("compiler").mkdir(parents=True, exist_ok=True)

# Check if MSVC420 is in the INCLUDE environment variable
set_compiler_paths = False
if not args.modern_compiler:
  if not pathlib.Path("compiler/MSVC420-master").exists():
    print("MSVC420 not found in compiler/...")
    url = "https://github.com/itsmattkc/MSVC420/archive/refs/heads/master.zip"
    print("Downloading MSVC420...")
    r = requests.get(url, stream=True)
    print("Unzipping to compiler/...")
    z = zipfile.ZipFile(io.BytesIO(r.content))
    z.extractall(path="compiler")
  set_compiler_paths = True

# Run cmake in the build folder
cmake_args = []
cmake_args += ["-G", "Ninja"]
cmake_args += ["-DCMAKE_BUILD_TYPE=RelWithDebInfo"]
if specific_ninja:
  cmake_args += ["-DCMAKE_MAKE_PROGRAM="+specific_ninja]
  print("Using specific ninja:", specific_ninja)
if set_compiler_paths:
  full_compiler_path = pathlib.Path.cwd() / "compiler" / "MSVC420-master/"
  cmake_args += ["-DCMAKE_CXX_COMPILER=" + (full_compiler_path / "bin" / "CL.EXE").as_posix()]
  cmake_args += ["-DCMAKE_C_COMPILER=" + (full_compiler_path / "bin" / "CL.EXE").as_posix()]
  cmake_args += ["-DCMAKE_LINKER=" + (full_compiler_path / "bin" / "LINK.EXE").as_posix()]
  cmake_args += ["-DCMAKE_RC_COMPILER=" + (full_compiler_path / "bin" / "RC.EXE").as_posix()]
  os.environ["INCLUDE"] = (full_compiler_path / "include").as_posix()
  os.environ["LIB"] = (full_compiler_path / "lib").as_posix()
cmake_args += [".."]
subprocess.run(["cmake"] + cmake_args, cwd="build")

# Create a folder for the original binaries
if not pathlib.Path("original/LEGO1.DLL").exists():
  pathlib.Path("original").mkdir(parents=True, exist_ok=True)
  print("Please obtain a copy of the original game and place its "
       "ISLE.EXE and LEGO1.DLL into the `original` folder if you plan "
     "on contributing so that the assembly diff tools can compare against them.")
