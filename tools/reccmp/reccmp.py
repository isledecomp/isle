#!/usr/bin/env python3

import argparse
import base64
from capstone import *
import difflib
import struct
import subprocess
import logging
import os
import sys
import colorama
import re

parser = argparse.ArgumentParser(allow_abbrev=False,
  description='Recompilation Compare: compare an original EXE with a recompiled EXE + PDB.')
parser.add_argument('original', metavar='original-binary', help='The original binary')
parser.add_argument('recompiled', metavar='recompiled-binary', help='The recompiled binary')
parser.add_argument('pdb', metavar='recompiled-pdb', help='The PDB of the recompiled binary')
parser.add_argument('decomp_dir', metavar='decomp-dir', help='The decompiled source tree')
parser.add_argument('--total', '-T', metavar='<count>', help='Total number of expected functions (improves total accuracy statistic)')
parser.add_argument('--verbose', '-v', metavar='<offset>', help='Print assembly diff for specific function (original file\'s offset)')
parser.add_argument('--html', '-H', metavar='<file>', help='Generate searchable HTML summary of status and diffs')
parser.add_argument('--no-color', '-n', action='store_true', help='Do not color the output')
parser.add_argument('--svg', '-S', metavar='<file>', help='Generate SVG graphic of progress')
parser.add_argument('--svg-icon', metavar='icon', help='Icon to use in SVG (PNG)')
parser.add_argument('--print-rec-addr', action='store_true', help='Print addresses of recompiled functions too')

parser.set_defaults(loglevel=logging.INFO)
parser.add_argument('--debug', action='store_const', const=logging.DEBUG, dest='loglevel', help='Print script debug information')

args = parser.parse_args()

logging.basicConfig(level=args.loglevel, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

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
    logger.debug('Parsing headers of "%s"... ', filename)
    self.file = open(filename, 'rb')

    #HACK: Strictly, we should be parsing the header, but we know where
    #      everything is in these two files so we just jump straight there

    # Read ImageBase
    self.file.seek(0xB4)
    self.imagebase, = struct.unpack('<i', self.file.read(4))

    # Read .text VirtualAddress
    self.file.seek(0x184)
    self.textvirt, = struct.unpack('<i', self.file.read(4))

    # Read .text PointerToRawData
    self.file.seek(0x18C)
    self.textraw, = struct.unpack('<i', self.file.read(4))
    logger.debug('... Parsing finished')

  def __del__(self):
    if self.file:
      self.file.close()

  def get_addr(self, virt):
    return virt - self.imagebase - self.textvirt + self.textraw

  def read(self, offset, size):
    self.file.seek(self.get_addr(offset))
    return self.file.read(size)

class RecompiledInfo:
  def __init__(self):
    self.addr = None
    self.size = None
    self.name = None
    self.start = None

class WinePathConverter:
  def __init__(self, unix_cwd):
    self.unix_cwd = unix_cwd
    self.win_cwd = self._call_winepath_unix2win(self.unix_cwd)

  def get_wine_path(self, unix_fn: str) -> str:
    if unix_fn.startswith('./'):
      return self.win_cmd + '\\' + unix_fn[2:].replace('/', '\\')
    if unix_fn.startswith(self.unix_cwd):
      return self.win_cwd + '\\' + unix_fn.removeprefix(self.unix_cwd).replace('/', '\\').lstrip('\\')
    return self._call_winepath_unix2win(unix_fn)

  def get_unix_path(self, win_fn: str) -> str:
    if win_fn.startswith('.\\') or win_fn.startswith('./'):
      return self.unix_cwd + '/' + win_fn[2:].replace('\\', '/')
    if win_fn.startswith(self.win_cwd):
      return self.unix_cwd + '/' + win_fn.removeprefix(self.win_cwd).replace('\\', '/')
    return self._call_winepath_win2unix(win_fn)

  @staticmethod
  def _call_winepath_unix2win(fn: str) -> str:
    return subprocess.check_output(['winepath', '-w', fn], text=True).strip()

  @staticmethod
  def _call_winepath_win2unix(fn: str) -> str:
    return subprocess.check_output(['winepath', fn], text=True).strip()

def get_file_in_script_dir(fn):
  return os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), fn)

# Declare a class that parses the output of cvdump for fast access later
class SymInfo:
  funcs = {}
  lines = {}

  def __init__(self, pdb, file, wine_path_converter):
    call = [get_file_in_script_dir('cvdump.exe'), '-l', '-s']

    if wine_path_converter:
      # Run cvdump through wine and convert path to Windows-friendly wine path
      call.insert(0, 'wine')
      call.append(wine_path_converter.get_wine_path(pdb))
    else:
      call.append(pdb)

    logger.info('Parsing %s ...', pdb)
    logger.debug('Command = %r', call)
    line_dump = subprocess.check_output(call).decode('utf-8').split('\r\n')

    current_section = None

    logger.debug('Parsing output of cvdump.exe ...')

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

        if wine_path_converter:
          # Convert filename to Unix path for file compare
          sourcepath = wine_path_converter.get_unix_path(sourcepath)

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

    logger.debug('... Parsing output of cvdump.exe finished')

  def get_recompiled_address(self, filename, line):
    addr = None
    found = False

    logger.debug('Looking for %s:%d', filename, line)

    for fn in self.lines:
      # Sometimes a PDB is compiled with a relative path while we always have
      # an absolute path. Therefore we must
      try:
        if os.path.samefile(fn, filename):
          filename = fn
          break
      except FileNotFoundError as e:
        continue

    if filename in self.lines and line in self.lines[fn]:
      addr = self.lines[fn][line]

      if addr in self.funcs:
        return self.funcs[addr]
      else:
        logger.error('Failed to find function symbol with address: 0x%x', addr)
    else:
      logger.error('Failed to find function symbol with filename and line: %s:%d', filename, line)

wine_path_converter = None
if os.name != 'nt':
  wine_path_converter = WinePathConverter(source)
origfile = Bin(original)
recompfile = Bin(recomp)
syminfo = SymInfo(syms, recompfile, wine_path_converter)

print()

md = Cs(CS_ARCH_X86, CS_MODE_32)

class OffsetPlaceholderGenerator:
  def __init__(self):
    self.counter = 0
    self.replacements = {}

  def get(self, addr):
    if addr in self.replacements:
      return self.replacements[addr]
    else:
      self.counter += 1
      replacement = '<OFFSET%d>' % self.counter
      self.replacements[addr] = replacement
      return replacement

def sanitize(file, placeholderGenerator, mnemonic, op_str):
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
    op_str = placeholderGenerator.get(int(op_str, 16))
  else:
    def filter_out_ptr(ptype, op_str):
      try:
        ptrstr = ptype + ' ptr ['
        start = op_str.index(ptrstr) + len(ptrstr)
        end = op_str.index(']', start)

        # This will throw ValueError if not hex
        inttest = int(op_str[start:end], 16)

        return op_str[0:start] + placeholderGenerator.get(inttest) + op_str[end:]
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
          words[i] = placeholderGenerator.get(inttest)
      except ValueError:
        pass
    op_str = ' '.join(words)

  return mnemonic, op_str

def parse_asm(file, addr, size):
  asm = []
  data = file.read(addr, size)
  placeholderGenerator = OffsetPlaceholderGenerator()
  for i in md.disasm(data, 0):
    # Use heuristics to disregard some differences that aren't representative
    # of the accuracy of a function (e.g. global offsets)
    mnemonic, op_str = sanitize(file, placeholderGenerator, i.mnemonic, i.op_str)
    if op_str is None:
      asm.append(mnemonic)
    else:
      asm.append("%s %s" % (mnemonic, op_str))
  return asm

REGISTER_LIST = set([
  'eax', 'ebx', 'ecx', 'edx', 'edi', 'esi', 'ebp', 'esp',
  'ax', 'bx', 'cx', 'dx', 'di', 'si', 'bp', 'sp',
])
WORDS = re.compile(r'\w+')

def get_registers(line: str):
  to_replace = []
  # use words regex to find all matching positions:
  for match in WORDS.finditer(line):
    reg = match.group(0)
    if reg in REGISTER_LIST:
      to_replace.append((reg, match.start()))
  return to_replace

def replace_register(lines: list[str], start_line: int, reg: str, replacement: str):
  for i in range(start_line, len(lines)):
    lines[i] = lines[i].replace(reg, replacement)

# Is it possible to make new_asm the same as original_asm by swapping registers?
def can_resolve_register_differences(original_asm, new_asm):
  # Swapping ain't gonna help if the lengths are different
  if len(original_asm) != len(new_asm):
    return False

  # Make copies so we don't modify the original
  original_asm = original_asm.copy()
  new_asm = new_asm.copy()

  # Look for the mismatching lines
  for i in range(len(original_asm)):
    new_line = new_asm[i]
    original_line = original_asm[i]
    if new_line != original_line:
      # Find all the registers to replace
      to_replace = get_registers(original_line)

      for j in range(len(to_replace)):
        (reg, reg_index) = to_replace[j]
        replacing_reg = new_line[reg_index:reg_index + len(reg)]
        if replacing_reg in REGISTER_LIST:
          if replacing_reg != reg:
            # Do a three-way swap replacing in all the subsequent lines
            temp_reg = "&" * len(reg)
            replace_register(new_asm, i, replacing_reg, temp_reg)
            replace_register(new_asm, i, reg, replacing_reg)
            replace_register(new_asm, i, temp_reg, reg)
        else:
          # No replacement to do, different code, bail out
          return False
  # Check if the lines are now the same
  for i in range(len(original_asm)):
    if new_asm[i] != original_asm[i]:
      return False
  return True

function_count = 0
total_accuracy = 0
total_effective_accuracy = 0
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

        if line.startswith(pattern) and not line.endswith("STUB"):
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

          # The effective_ratio is the ratio when ignoring differing register 
          # allocation vs the ratio is the true ratio.
          ratio = 0.0
          effective_ratio = 0.0
          if recinfo.size:
            origasm = parse_asm(origfile, addr + recinfo.start, recinfo.size)
            recompasm = parse_asm(recompfile, recinfo.addr + recinfo.start, recinfo.size)

            diff = difflib.SequenceMatcher(None, origasm, recompasm)
            ratio = diff.ratio()
            effective_ratio = ratio

            if ratio != 1.0:
              # Check whether we can resolve register swaps which are actually
              # perfect matches modulo compiler entropy.
              if can_resolve_register_differences(origasm, recompasm):
                effective_ratio = 1.0
          else:
            ratio = 0

          percenttext = "%.2f%%" % (effective_ratio * 100)
          if not plain:
            if effective_ratio == 1.0:
              percenttext = colorama.Fore.GREEN + percenttext + colorama.Style.RESET_ALL
            elif effective_ratio > 0.8:
              percenttext = colorama.Fore.YELLOW + percenttext + colorama.Style.RESET_ALL
            else:
              percenttext = colorama.Fore.RED + percenttext + colorama.Style.RESET_ALL

          if effective_ratio == 1.0 and ratio != 1.0:
            if plain:
              percenttext += "*"
            else:
              percenttext += colorama.Fore.RED + "*" + colorama.Style.RESET_ALL

          if not verbose:
            if args.print_rec_addr:
              addrs = '%s / %s' % (hex(addr), hex(recinfo.addr))
            else:
              addrs = hex(addr)
            print('  %s (%s) is %s similar to the original' % (recinfo.name, addrs, percenttext))

          function_count += 1
          total_accuracy += ratio
          total_effective_accuracy += effective_ratio

          if recinfo.size:
            udiff = difflib.unified_diff(origasm, recompasm, n=10)

            # If verbose, print the diff for that funciton to the output
            if verbose:
              if effective_ratio == 1.0:
                ok_text = "OK!" if plain else (colorama.Fore.GREEN + "✨ OK! ✨" + colorama.Style.RESET_ALL)
                if ratio == 1.0:
                  print("%s: %s 100%% match.\n\n%s\n\n" %
                        (hex(addr), recinfo.name, ok_text))
                else:
                  print("%s: %s Effective 100%% match. (Differs in register allocation only)\n\n%s (still differs in register allocation)\n\n" %
                        (hex(addr), recinfo.name, ok_text))
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
              htmlinsert.append('{address: "%s", name: "%s", matching: %s, diff: "%s"}' % (hex(addr), recinfo.name, str(effective_ratio), escaped))

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
  templatedata = templatedata.replace('{percent}', '%.2f%%' % (total_statistic * 100), 2)

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
    print('\nTotal effective accuracy %.2f%% across %i functions (%.2f%% actual accuracy)' %
          (total_effective_accuracy / function_count * 100, function_count, total_accuracy / function_count * 100))

    if svg:
      gen_svg(svg, os.path.basename(original), args.svg_icon, implemented_funcs, function_count, total_effective_accuracy)
