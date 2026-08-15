"""Render deterministic, non-emitting C++ declaration shapes."""


def _shape_suffix(number: int, width: int) -> str:
    """Return the fixed-width base-26 suffix used by declaration shapes."""
    characters = []
    for _ in range(width):
        characters.append(chr(ord("a") + number % 26))
        number //= 26
    return "".join(reversed(characters))


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
