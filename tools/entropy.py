"""Render deterministic, non-emitting C++ declaration shapes."""


def _shape_suffix(number: int, width: int) -> str:
    """Return the fixed-width base-26 suffix used by declaration shapes."""
    characters = []
    for _ in range(width):
        characters.append(chr(ord("a") + number % 26))
        number //= 26
    return "".join(reversed(characters))


def generate_forward_run(prefix: str, count: int, width: int) -> str:
    """Return a deterministic run of bare forward declarations.

    A forward declaration allocates one compiler name record and nothing
    else: no code, data, strings, vtables, or linker directives can be
    emitted from it.  The run is the stem-inert carrier form (`class X;`)
    with fixed-width decimal suffixes so a given (prefix, count, width)
    always renders identical bytes.
    """
    if not (prefix and prefix[0].isalpha() and prefix.isalnum()):
        raise ValueError("forward run prefix must be an identifier stem")
    if not 1 <= count <= 999:
        raise ValueError("forward run count must be in [1, 999]")
    if not 1 <= width <= 3 or count > 10 ** width:
        raise ValueError("forward run width cannot represent the count")
    return "".join(
        f"class {prefix}{number:0{width}d};\n" for number in range(count)
    )


def generate_extern_run(prefix: str, count: int, width: int) -> str:
    """Return a deterministic run of extern int object declarations.

    An extern declaration of a never-defined, never-referenced object
    allocates a compiler symbol record and emits nothing: no code, data,
    strings, vtables, or linker directives.  This is the historical
    seat-unit carrier form (`extern int g_p<i>;`).
    """
    if not (prefix and prefix[0].isalpha()
            and all(c.isalnum() or c == "_" for c in prefix)):
        raise ValueError("extern run prefix must be an identifier stem")
    if not 1 <= count <= 999:
        raise ValueError("extern run count must be in [1, 999]")
    if not 1 <= width <= 3 or count > 10 ** width:
        raise ValueError("extern run width cannot represent the count")
    return "".join(
        f"extern int {prefix}{number:0{width}d};\n"
        for number in range(count)
    )


def generate_shape(classes: int, functions: int) -> str:
    """Return a deterministic, declaration-only compiler-state shape.

    The shape intentionally has no objects with storage duration and no used
    inline members.  It can affect compiler allocation/order decisions, but it
    cannot contribute code, data, strings, vtables, or linker directives.
    """
    if not 1 <= classes <= 10:
        raise ValueError("declaration shape classes must be in [1, 10]")
    if not classes <= functions <= 10 * classes:
        raise ValueError("declaration shape functions must be in [classes, 10*classes]")

    counts = [1] * classes
    for index in range(functions - classes):
        counts[index % classes] += 1

    lines = [
        "// Generated declaration-only entropy shape. Emits no code or data.",
        f"// Shape: classes={classes} functions={functions}",
        "",
    ]
    function_number = 0
    for class_number, count in enumerate(counts):
        class_name = "Class" + chr(ord("A") + class_number) + "aaaaa"
        lines.extend([f"class {class_name} {{", "public:"])
        for _ in range(count):
            function_name = (
                "Function"
                + chr(ord("A") + function_number % 26)
                + _shape_suffix(function_number // 26, 7)
            )
            lines.append(f"\tinline void {function_name}() {{}}")
            function_number += 1
        lines.extend(["};", ""])
    return "\n".join(lines) + "\n"
