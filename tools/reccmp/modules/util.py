import os
import sys

def get_file_in_script_dir(fn):
  return os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), fn)
