#!/usr/bin/python3
import argparse
import os

parser = argparse.ArgumentParser(allow_abbrev=False,
  description='Verify Exports: Compare the exports of two DLLs.')
parser.add_argument('cppfile', metavar='cppfile', help='Path to the C++ File to preprocess.')

args = parser.parse_args()
if not os.path.isfile(args.cppfile):
  parser.error('Specified C++ file does not exist.')

os.system('cl.exe /EP /P ' + args.cppfile)

print('Preprocessed file. It will be in the directory you executed in this command as "(filename).i".')