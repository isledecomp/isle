from modules.logger import logger
import modules.util as util
import subprocess
import os

fieldlists = dict()
classes = dict()

class VTableEntry:
  def __init__(self):
    self.name = None
    self.offset = -1

class Class:
  def __init__(self):
    self.name = None
    self.id = None
    self.field_list = None
    self.size = None

class FieldList:
  def __init__(self):
    self.id = None
    self.baseclass = None
    self.vtable = []
    self.members = []

class RecompiledInfo:
  def __init__(self):
    self.addr = None
    self.size = None
    self.name = None
    self.start = None

def remove_quotes(l):
  while l[0] == '\'':
    l = l[1:]

  while l[len(l)-1] == '\'':
    l = l[0:len(l)-1]

  return l

# Declare a class that parses the output of cvdump for fast access later
class SymInfo:
  funcs = {}
  lines = {}
  names = {}

  def __init__(self, pdb, file, wine_path_converter):
    call = [util.get_file_in_script_dir('cvdump.exe'), '-l', '-s', '-t']

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
        info.addr = addr + file.imagebase + file.textvirt

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

        self.names[info.name] = info
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
      elif 'LF_CLASS' in line or 'LF_STRUCTURE' in line:
        c = Class()

        c.id = int(line.split()[0], 16)

        flt_str = 'field list type '
        nextline = line_dump[i+1]
        flt_start = nextline.index(flt_str)+len(flt_str)
        flt_end = nextline.index(',', flt_start)
        c.field_list = int(nextline[flt_start:flt_end], 16)

        info = line_dump[i+3].split(',')
        for i in info:
          kv = i.split('=')
          if len(kv) == 2:
            k = kv[0].strip()
            v = kv[1].strip()
            if k == 'Size':
              c.size = int(v)
            elif k == 'class name':
              c.name = v

        classes[c.id] = c

      elif 'LF_FIELDLIST' in line:
        def parse_line(lines, index):
          def space_count(s):
            spaces = 0
            for c in s:
              if c == '\t':
                spaces += 1
            return spaces

          l = lines[index].rstrip()
          spaces = space_count(l)

          while True:
            index += 1
            nextline = lines[index]
            nextspaces = space_count(nextline)
            if nextspaces > spaces:
              l += nextline[nextspaces:].rstrip()
            else:
              break

          l = l.strip()

          return l

        def get_vtable_func_info(l):
          info = VTableEntry()
          csv = l.split(',')
          for c in csv:
            kv = c.split('=')
            if len(kv) == 2:
              k = kv[0].strip()
              v = kv[1].strip()
              if k == 'name':
                info.name = remove_quotes(v)
              elif k == 'vfptr offset':
                info.offset = int(v)

          return info

        fl = FieldList()

        fl.id = int(line_dump[i].split()[0], 16)

        while True:
          i += 1
          if not line_dump[i].strip():
            break

          if 'BCLASS' in line_dump[i]:
            dp = line_dump[i].split(',')
            for d in dp:
              kv = d.split('=')
              if len(kv) == 2:
                k = kv[0].strip()
                v = kv[1].strip()
                if k == 'type':
                  fl.baseclass = int(v, 16)
          elif 'VIRTUAL' in line_dump[i]:
            info = get_vtable_func_info(parse_line(line_dump, i))
            fl.vtable.append(info)
          elif 'LF_MEMBER' in line_dump[i]:
            member = VTableEntry()
            l = line_dump[i]
            offset_str = 'offset = '
            member.offset = int(l[l.index(offset_str) + len(offset_str):])
            member.name = remove_quotes(line_dump[i+1][16:].rstrip())
            fl.members.append(member)

        fieldlists[fl.id] = fl

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

  def get_recompiled_address_from_name(self, name):
    logger.debug('Looking for %s', name)

    if name in self.names:
        return self.names[name]
    else:
        logger.error('Failed to find function symbol with name: %s', name)
