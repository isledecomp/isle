#!/usr/bin/python3
import argparse
import os
import subprocess

parser = argparse.ArgumentParser(
    allow_abbrev=False, description="Verify Exports: Compare the exports of two DLLs."
)
parser.add_argument(
    "cppfile", metavar="cppfile", help="Path to the C++ File to preprocess."
)
parser.add_argument(
    "--debug",
    action="store_true",
    help="Print debug information by showing the output from the preprocessor. THIS WILL TAKE A LONG TIME AS YOUR TERMINAL TRIES TO LOAD OVER 100K LINES OF TEXT. Use this if your context contains an error or is empty.",
)

args = parser.parse_args()
if not os.path.isfile(args.cppfile):
    parser.error("Specified C++ file does not exist.")

output = subprocess.run(
    "cl.exe /EP " + args.cppfile, capture_output=not args.debug, text=True
)

f = open("ctx.h", "w")
f.write(output.stdout)

print("Preprocessed file to ctx.h")
