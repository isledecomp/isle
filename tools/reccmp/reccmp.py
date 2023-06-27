#!/usr/bin/env python3

import argparse
import base64
from capstone import *
import difflib
import struct
import subprocess
import os
import sys
import colorama

parser = argparse.ArgumentParser(allow_abbrev=False,
  description='Recompilation Compare: compare an original EXE with a recompiled EXE + PDB.')
parser.add_argument('original', metavar='original-binary', help='The original binary')
parser.add_argument('recompiled', metavar='recompiled-binary', help='The recompiled binary')
parser.add_argument('pdb', metavar='recompiled-pdb', help='The PDB of the recompiled binary')
parser.add_argument('decomp_dir', metavar='decomp-dir', help='The decompiled source tree')
parser.add_argument('--total', '-T', metavar='total-func-count', help='Total number of expected functions (improves total accuracy statistic)')
parser.add_argument('--verbose', '-v', metavar='offset', help='Print assembly diff for specific function (original file\'s offset)')
parser.add_argument('--html', '-H', metavar='output-file', help='Generate searchable HTML summary of status and diffs')
parser.add_argument('--no-color', '-n', action='store_true', help='Do not color the output')
parser.add_argument('--svg', '-S', metavar='output-svg', help='Generate SVG graphic of progress')
parser.add_argument('--svg-icon', metavar='svg-icon', help='Icon to use in SVG (PNG)')

args = parser.parse_args()

colorama.init()

verbose = None
found_verbose_target = False
if args.verbose:
  try:
    verbose = int(args.verbose, 16)
  except ValueError:
    parser.error('invalid verbose argument')
html = args.html

plain = args.no_color

original = args.original
if not os.path.isfile(original):
  parser.error('Original binary does not exist')

recomp = args.recompiled
if not os.path.isfile(recomp):
  parser.error('Recompiled binary does not exist')

syms = args.pdb
if not os.path.isfile(syms):
  parser.error('Symbols PDB does not exist')

source = args.decomp_dir
if not os.path.isdir(source):
  parser.error('Source directory does not exist')

svg = args.svg

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

class RecompiledInfo:
  addr = None
  size = None
  name = None
  start = None

def get_wine_path(fn):
  return subprocess.check_output(['winepath', '-w', fn]).decode('utf-8').strip()

def get_unix_path(fn):
  return subprocess.check_output(['winepath', fn]).decode('utf-8').strip()

def get_file_in_script_dir(fn):
  return os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), fn)

# Declare a class that parses the output of cvdump for fast access later
class SymInfo:
  funcs = {}
  lines = {}

  def __init__(self, pdb, file):
    call = [get_file_in_script_dir('cvdump.exe'), '-l', '-s']

    if os.name != 'nt':
      # Run cvdump through wine and convert path to Windows-friendly wine path
      call.insert(0, 'wine')
      call.append(get_wine_path(pdb))
    else:
      call.append(pdb)

    print('Parsing %s...' % pdb)

    line_dump = subprocess.check_output(call).decode('utf-8').split('\r\n')

    current_section = None

    for i, line in enumerate(line_dump):
      if line.startswith('***'):
        current_section = line[4:]

      if current_section == 'SYMBOLS' and 'S_GPROC32' in line:
        addr = int(line[26:34], 16)



        info = RecompiledInfo()
        info.addr = addr + recompfile.imagebase + recompfile.textvirt

        use_dbg_offs = False
        if use_dbg_offs:
          debug_offs = line_dump[i + 2]
          debug_start = int(debug_offs[22:30], 16)
          debug_end = int(debug_offs[43:], 16)

          info.start = debug_start
          info.size = debug_end - debug_start
        else:
          info.start = 0
          info.size = int(line[41:49], 16)

        info.name = line[77:]

        self.funcs[addr] = info
      elif current_section == 'LINES' and line.startswith('  ') and not line.startswith('   '):
        sourcepath = line.split()[0]

        if os.name != 'nt':
          # Convert filename to Unix path for file compare
          sourcepath = get_unix_path(sourcepath)

        if sourcepath not in self.lines:
          self.lines[sourcepath] = {}

        j = i + 2
        while True:
          ll = line_dump[j].split()
          if len(ll) == 0:
            break

          k = 0
          while k < len(ll):
            linenum = int(ll[k + 0])
            address = int(ll[k + 1], 16)
            if linenum not in self.lines[sourcepath]:
              self.lines[sourcepath][linenum] = address
            k += 2

          j += 1

  def get_recompiled_address(self, filename, line):
    addr = None
    found = False

    #print('Looking for ' + filename + ' line ' + str(line))

    for fn in self.lines:
      # Sometimes a PDB is compiled with a relative path while we always have
      # an absolute path. Therefore we must
      if os.path.samefile(fn, filename):
        filename = fn
        break

    if filename in self.lines and line in self.lines[fn]:
      addr = self.lines[fn][line]

      if addr in self.funcs:
        return self.funcs[addr]
      else:
        print('Failed to find function symbol with address: %s' % hex(addr))
    else:
      print('Failed to find function symbol with filename and line: %s:%s' % (filename, str(line)))

origfile = Bin(original)
recompfile = Bin(recomp)
syminfo = SymInfo(syms, recompfile)

print()

md = Cs(CS_ARCH_X86, CS_MODE_32)

def sanitize(file, mnemonic, op_str):
  offsetplaceholder = '<OFFSET>'

  op_str_is_number = False
  try:
    int(op_str, 16)
    op_str_is_number = True
  except ValueError:
    pass

  if (mnemonic == 'call' or mnemonic == 'jmp') and op_str_is_number:
    # Filter out "calls" because the offsets we're not currently trying to
    # match offsets. As long as there's a call in the right place, it's
    # probably accurate.
    op_str = offsetplaceholder
  else:
    def filter_out_ptr(ptype, op_str):
      try:
        ptrstr = ptype + ' ptr ['
        start = op_str.index(ptrstr) + len(ptrstr)
        end = op_str.index(']', start)

        # This will throw ValueError if not hex
        inttest = int(op_str[start:end], 16)

        return op_str[0:start] + offsetplaceholder + op_str[end:]
      except ValueError:
        return op_str

    # Filter out dword ptrs where the pointer is to an offset
    op_str = filter_out_ptr('dword', op_str)
    op_str = filter_out_ptr('word', op_str)
    op_str = filter_out_ptr('byte', op_str)

    # Use heuristics to filter out any args that look like offsets
    words = op_str.split(' ')
    for i, word in enumerate(words):
      try:
        inttest = int(word, 16)
        if inttest >= file.imagebase + file.textvirt:
          words[i] = offsetplaceholder
      except ValueError:
        pass
    op_str = ' '.join(words)

  return mnemonic, op_str

def parse_asm(file, addr, size):
  asm = []
  data = file.read(addr, size)
  for i in md.disasm(data, 0):
    # Use heuristics to disregard some differences that aren't representative
    # of the accuracy of a function (e.g. global offsets)
    mnemonic, op_str = sanitize(file, i.mnemonic, i.op_str)
    if op_str is None:
      asm.append(mnemonic)
    else:
      asm.append("%s %s" % (mnemonic, op_str))
  return asm

function_count = 0
total_accuracy = 0
htmlinsert = []

# Generate basename of original file, used in locating OFFSET lines
basename = os.path.basename(os.path.splitext(original)[0])
pattern = '// OFFSET:'

for subdir, dirs, files in os.walk(source):
  for file in files:
    srcfilename = os.path.join(os.path.abspath(subdir), file)
    srcfile = open(srcfilename, 'r')
    line_no = 0

    while True:
      try:
        line = srcfile.readline()
        line_no += 1

        if not line:
          break

        line = line.strip()

        if line.startswith(pattern):
          par = line[len(pattern):].strip().split()
          module = par[0]
          if module != basename:
            continue

          addr = int(par[1], 16)

          # Verbose flag handling
          if verbose:
            if addr == verbose:
              found_verbose_target = True
            else:
              continue

          find_open_bracket = line
          while '{' not in find_open_bracket:
            find_open_bracket = srcfile.readline()
            line_no += 1

          recinfo = syminfo.get_recompiled_address(srcfilename, line_no)
          if not recinfo:
            continue

          if recinfo.size:
            origasm = parse_asm(origfile, addr + recinfo.start, recinfo.size)
            recompasm = parse_asm(recompfile, recinfo.addr + recinfo.start, recinfo.size)

            diff = difflib.SequenceMatcher(None, origasm, recompasm)
            ratio = diff.ratio()
          else:
            ratio = 0

          percenttext = "%.2f%%" % (ratio * 100)
          if not plain:
            if ratio == 1.0:
              percenttext = colorama.Fore.GREEN + percenttext + colorama.Style.RESET_ALL
            elif ratio > 0.8:
              percenttext = colorama.Fore.YELLOW + percenttext + colorama.Style.RESET_ALL
            else:
              percenttext = colorama.Fore.RED + percenttext + colorama.Style.RESET_ALL

          if not verbose:
            print('  %s (%s / %s) is %s similar to the original' % (recinfo.name, hex(addr), hex(recinfo.addr), percenttext))

          function_count += 1
          total_accuracy += ratio

          if recinfo.size:
            udiff = difflib.unified_diff(origasm, recompasm, n=10)

            # If verbose, print the diff for that funciton to the output
            if verbose:
              if ratio == 1.0:
                print("%s: %s 100%% match.\n\nOK!" % (hex(addr), recinfo.name))
              else:
                for line in udiff:
                  if line.startswith("++") or line.startswith("@@") or line.startswith("--"):
                    # Skip unneeded parts of the diff for the brief view
                    pass
                  elif line.startswith("+"):
                    if plain:
                      print(line)
                    else:
                      print(colorama.Fore.GREEN + line)
                  elif line.startswith("-"):
                    if plain:
                      print(line)
                    else:
                      print(colorama.Fore.RED + line)
                  else:
                    print(line)
                  if not plain:
                    print(colorama.Style.RESET_ALL, end='')

                print("\n%s is only %s similar to the original, diff above" % (recinfo.name, percenttext))

            # If html, record the diffs to an HTML file
            if html:
              escaped = '\\n'.join(udiff).replace('"', '\\"').replace('\n', '\\n').replace('<', '&lt;').replace('>', '&gt;')
              htmlinsert.append('{address: "%s", name: "%s", matching: %s, diff: "%s"}' % (hex(addr), recinfo.name, str(ratio), escaped))

      except UnicodeDecodeError:
        break

def gen_html(html, data):
  templatefile = open(get_file_in_script_dir('template.html'), 'r')
  if not templatefile:
    print('Failed to find HTML template file, can\'t generate HTML summary')
    return

  templatedata = templatefile.read()
  templatefile.close()

  templatedata = templatedata.replace('/* INSERT DATA HERE */', ','.join(data), 1)

  htmlfile = open(html, 'w')
  if not htmlfile:
    print('Failed to write to HTML file %s' % html)
    return

  htmlfile.write(templatedata)
  htmlfile.close()

def gen_svg(svg, name, icon, implemented_funcs, total_funcs, raw_accuracy):
  templatefile = open(get_file_in_script_dir('template.svg'), 'r')
  if not templatefile:
    print('Failed to find SVG template file, can\'t generate SVG summary')
    return

  templatedata = templatefile.read()
  templatefile.close()

  # Replace icon
  if args.svg_icon:
    iconfile = open(args.svg_icon, 'rb')
    templatedata = templatedata.replace('{icon}', base64.b64encode(iconfile.read()).decode('utf-8'), 1)
    iconfile.close()

  # Replace name
  templatedata = templatedata.replace('{name}', name, 1)

  # Replace implemented statistic
  templatedata = templatedata.replace('{implemented}', '%.2f%% (%i/%i)' % (implemented_funcs / total_funcs * 100, implemented_funcs, total_funcs), 1)

  # Replace accuracy statistic
  templatedata = templatedata.replace('{accuracy}', '%.2f%%' % (raw_accuracy / implemented_funcs * 100), 1)

  # Generate progress bar width
  total_statistic = raw_accuracy / total_funcs
  percenttemplate = '{progbar'
  percentstart = templatedata.index(percenttemplate)
  percentend = templatedata.index('}', percentstart)
  progwidth = float(templatedata[percentstart + len(percenttemplate) + 1:percentend]) * total_statistic
  templatedata = templatedata[0:percentstart] + str(progwidth) + templatedata[percentend + 1:]

  # Replace percentage statistic
  templatedata = templatedata.replace('{percent}', '%.2f%%' % (total_statistic * 100), 1)

  svgfile = open(svg, 'w')
  if not svgfile:
    print('Failed to write to SVG file %s' % svg)
    return

  svgfile.write(templatedata)
  svgfile.close()

if html:
  gen_html(html, htmlinsert)

if verbose:
  if not found_verbose_target:
    print('Failed to find the function with address %s' % hex(verbose))
else:
  implemented_funcs = function_count

  if args.total:
    function_count = int(args.total)

  if function_count > 0:
    print('\nTotal accuracy %.2f%% across %i functions' % (total_accuracy / function_count * 100, function_count))

    if svg:
      gen_svg(svg, os.path.basename(original), args.svg_icon, implemented_funcs, function_count, total_accuracy)
