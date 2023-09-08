#!/usr/bin/python3
# Tool to make simple context, currently the basic Mx* structures.
import os
import shutil

ctxfile = open('ctx.h', 'w')

# These are the only files we can include, hopefully soon decomp.me can deal with DirectX files. There is no need to bundle all the thousands of lines DX5 headers have, its not like all of it is probably going to be used.
ctxfile.write('#include <string.h>\n')
ctxfile.write('#include <windows.h>\n')

# The order is important!
# In the future, *all* the files can be done - but there will always be some headers that need to be placed in before others.
# Later, when this initial list is complete, and DirectX header files are available on decomp.me, then we can bundle in everything that is not order-dependent (that isn't already in the list.)
# This will periodically need updating depending on what classes include stuff from others - for now, these are the most likely basics.
# This context should be enough to match basic functions, once manually adding in context for the intended class.
# This pastebin shows class inheritance. This can help us a lot: https://pastebin.com/AQAiurwC
headerfiles = [
  # Basic definitions/types/base classes
  'LEGO1/compat.h',
  'LEGO1/mxtypes.h',

  'LEGO1/mxcore.h',
  'LEGO1/mxstring.h',
  'LEGO1/mxhashtable.h',
  'LEGO1/mxvariable.h',
  'LEGO1/mxvariabletable.h',

  'LEGO1/mxcriticalsection.h',
  'LEGO1/mxomni.h',

  'LEGO1/legostate.h',

  'LEGO1/mxentity.h',
  'LEGO1/legoentity.h',
]

for i in headerfiles:
  ctxfile.write('\n// Start of ' + i + '\n')
  for line in open(i):
    if not line.startswith('#include'):
      ctxfile.write(line)
  ctxfile.write('\n// End of ' + i + '\n')