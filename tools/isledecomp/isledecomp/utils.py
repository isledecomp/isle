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