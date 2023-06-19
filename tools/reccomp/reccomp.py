#!/usr/bin/env python3

from capstone import *
import difflib
import struct
import subprocess
import os
import sys

def print_usage():
  print('Usage: %s [options] <original-binary> <recompiled-binary> <recompiled-pdb> <decomp-dir>\n' % sys.argv[0])
  print('\t-v, --verbose <offset>\t\t\tPrint assembly diff for specific function (original file\'s offset)')
  sys.exit(1)

positional_args = []
verbose = None
skip = False

for i, arg in enumerate(sys.argv):
  if skip:
    skip = False
    continue

  if arg.startswith('-'):
    # A flag rather than a positional arg
    flag = arg[1:]

    if flag == 'v' or flag == '-verbose':
      verbose = int(sys.argv[i + 1], 16)
      skip = True
    else:
      print('Unknown flag: %s' % arg)
      print_usage()
  else:
    positional_args.append(arg)

if len(positional_args) != 5:
  print_usage()

original = positional_args[1]
if not os.path.isfile(original):
  print('Invalid input: Original binary does not exist')
  sys.exit(1)

recomp = positional_args[2]
if not os.path.isfile(recomp):
  print('Invalid input: Recompiled binary does not exist')
  sys.exit(1)

syms = positional_args[3]
if not os.path.isfile(syms):
  print('Invalid input: Symbols PDB does not exist')
  sys.exit(1)

source = positional_args[4]
if not os.path.isdir(source):
  print('Invalid input: Source directory does not exist')
  sys.exit(1)

# Declare a class that can automatically convert virtual executable addresses
# to file addresses
class Bin:
  def __init__(self, filename):
    self.file = open(filename, 'rb')

    #HACK: Strictly, we should be parsing the header, but we know where
    #      everything is in these two files so we just jump straight there

    # Read ImageBase
    self.file.seek(0xB4)
    self.imagebase = struct.unpack('i', self.file.read(4))[0]

    # Read .text VirtualAddress
    self.file.seek(0x184)
    self.textvirt = struct.unpack('i', self.file.read(4))[0]

    # Read .text PointerToRawData
    self.file.seek(0x18C)
    self.textraw = struct.unpack('i', self.file.read(4))[0]

  def __del__(self):
    if self.file:
      self.file.close()

  def get_addr(self, virt):
    return virt - self.imagebase - self.textvirt + self.textraw

  def read(self, offset, size):
    self.file.seek(self.get_addr(offset))
    return self.file.read(size)

line_dump = None
sym_dump = None

origfile = Bin(original)
recompfile = Bin(recomp)

class RecompiledInfo:
  addr = None
  size = None
  name = None

print()

def get_recompiled_address(filename, line):
  global line_dump, sym_dump

  def get_wine_path(fn):
    return subprocess.check_output(['winepath', '-w', fn]).decode('utf-8').strip()

  # Load source lines from PDB
  if not line_dump:
    call = ['cvdump', '-l', '-s']

    if os.name != 'nt':
      # Run cvdump through wine and convert path to Windows-friendly wine path
      call.insert(0, 'wine')
      call.append(get_wine_path(syms))
    else:
      call.append(syms)

    line_dump = subprocess.check_output(call, cwd=os.path.dirname(os.path.abspath(sys.argv[0]))).decode('utf-8').split('\r\n')

  # Find requested filename/line in PDB
  if os.name != 'nt':
    # Convert filename to Wine path
    filename = get_wine_path(filename)

  #print('Looking for ' + filename + ' line ' + str(line))

  addr = None

  for i, s in enumerate(line_dump):
    if s.startswith('  ' + filename):
      lines = line_dump[i + 2].split()
      if line == int(lines[0]):
        # Found address
        addr = int(lines[1], 16)
        break

  if addr:
    # Find size of function
    for i, s in enumerate(line_dump):
      if 'S_GPROC32' in s:
        if int(s[26:34], 16) == addr:

          obj = RecompiledInfo()
          obj.addr = addr + recompfile.imagebase + recompfile.textvirt
          obj.size = int(s[41:49], 16)
          obj.name = s[77:]

          return obj

md = Cs(CS_ARCH_X86, CS_MODE_32)

def parse_asm(file, addr, size):
  asm = []
  data = file.read(addr, size)
  for i in md.disasm(data, 0):
    if i.mnemonic == 'call':
      # Filter out "calls" because the offsets we're not currently trying to
      # match offsets. As long as there's a call in the right place, it's
      # probably accurate.
      asm.append(i.mnemonic)
    else:
      asm.append("%s %s" % (i.mnemonic, i.op_str))
  return asm

function_count = 0
total_accuracy = 0

for subdir, dirs, files in os.walk(source):
  for file in files:
    srcfilename = os.path.join(subdir, file)
    srcfile = open(srcfilename, 'r')
    line_no = 0

    while True:
      try:
        line = srcfile.readline()
        line_no += 1

        if not line:
          break

        if line.startswith('// OFFSET:'):
          par = line[10:].strip().split()
          module = par[0]
          addr = int(par[1], 16)

          find_open_bracket = line
          while '{' not in find_open_bracket:
            find_open_bracket = srcfile.readline()
            line_no += 1

          recinfo = get_recompiled_address(srcfilename, line_no)
          if not recinfo:
            print('Failed to find recompiled address of ' + hex(addr))
            continue

          origasm = parse_asm(origfile, addr, recinfo.size)
          recompasm = parse_asm(recompfile, recinfo.addr, recinfo.size)

          diff = difflib.SequenceMatcher(None, origasm, recompasm)
          ratio = diff.ratio()
          print('%s (%s) is %.2f%% similar to the original' % (recinfo.name, hex(addr), ratio * 100))

          function_count += 1
          total_accuracy += ratio

          if verbose == addr:
            udiff = difflib.unified_diff(origasm, recompasm)
            for line in udiff:
              print(line)
            print()
            print()

      except UnicodeDecodeError:
        break

print('\nTotal accuracy %.2f%% across %i functions' % (total_accuracy / function_count * 100, function_count))
