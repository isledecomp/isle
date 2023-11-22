import os
import sys
import colorama


def print_diff(udiff, plain):
    has_diff = False
    for line in udiff:
        has_diff = True
        color = ""
        if line.startswith("++") or line.startswith("@@") or line.startswith("--"):
            # Skip unneeded parts of the diff for the brief view
            continue
        # Work out color if we are printing color
        if not plain:
            if line.startswith("+"):
                color = colorama.Fore.GREEN
            elif line.startswith("-"):
                color = colorama.Fore.RED
        print(color + line)
        # Reset color if we're printing in color
        if not plain:
            print(colorama.Style.RESET_ALL, end="")
    return has_diff


def get_file_in_script_dir(fn):
    return os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), fn)


class OffsetPlaceholderGenerator:
    def __init__(self):
        self.counter = 0
        self.replacements = {}

    def get(self, replace_addr):
        if replace_addr in self.replacements:
            return self.replacements[replace_addr]
        self.counter += 1
        replacement = f"<OFFSET{self.counter}>"
        self.replacements[replace_addr] = replacement
        return replacement
