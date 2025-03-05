import random
import string
import sys

# Parameters for tweaking:
MAX_CLASSES = 10
MAX_FUNC_PER_CLASS = 10

# Only the unique suffix, not counting "Class" or "Function"
CLASS_NAME_LEN = 6
FUNC_NAME_LEN = 8


def random_camel_case(length: int) -> str:
    """Return a random string with first letter capitalized."""
    return "".join(
        [
            random.choice(string.ascii_uppercase),
            *random.choices(string.ascii_lowercase, k=length - 1),
        ]
    )


# If the first parameter is an integer, use it as the seed.
try:
    seed = int(sys.argv[1])
except (IndexError, ValueError):
    seed = random.randint(0, 10000)

random.seed(seed)

print(f"// Seed: {seed}\n")

num_classes = random.randint(1, MAX_CLASSES)
for i in range(num_classes):
    class_name = "Class" + random_camel_case(CLASS_NAME_LEN)
    print(f"class {class_name} {{")
    num_functions = random.randint(1, MAX_FUNC_PER_CLASS)
    for j in range(num_functions):
        function_name = "Function" + random_camel_case(FUNC_NAME_LEN)
        print(f"\tinline void {function_name}() {{}}")

    print(f"}};\n")

print()
