#!/bin/bash

# Output file
OUTPUT_FILE="entropy.h"

# Function to generate a CamelCase string of given length
generate_name() {
  local seed="$1"
  local length="$2"
  local char_count=0
  local random_bytes=""

  while [ "$char_count" -lt "$length" ]; do
    random_bytes+=$(od -vAn -N4 -tu4 < /dev/urandom | tr -d '[:space:]')
    char_count=$((char_count + 1))
  done

  # Use the provided seed for the random number generation.  Crucially, re-seed bash's
  # RANDOM for each name.
  RANDOM="$seed"

  local result=""
  for ((i=0; i<length; i++)); do
    # Get a pseudo-random number between 0 and 25 (inclusive)
    local rand_index=$((RANDOM % 26))
    # Convert to lowercase ASCII character (a=97)
    local char_code=$((97 + rand_index))
    # Append to the result string
    result+=$(printf "\\$(printf '%o' "$char_code")")
  done
  echo "$result" | sed -E 's/(^|_)([a-z])/\U\2/g'
}

# Parse command-line arguments
if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <seed_number>"
  exit 1
fi

SEED="$1"
# Initialize the random number generator with the seed
RANDOM="$SEED"

# Generate a random number of classes (between 1 and 10)
NUM_CLASSES=$((RANDOM % 10 + 1))

> "$OUTPUT_FILE"  # Clear or create the output file

echo "// Seed: $SEED" > "$OUTPUT_FILE"
echo >> "$OUTPUT_FILE"

for ((i=0; i<NUM_CLASSES; i++)); do
    CLASS_NAME="Class$(generate_name "$((SEED + i * 100))" 6)"
    echo "class $CLASS_NAME {" >> "$OUTPUT_FILE"

    # Generate a random number of methods (between 1 and 10)
    NUM_METHODS=$((RANDOM % 10 + 1))
    for ((j=0; j<NUM_METHODS; j++)); do
        METHOD_NAME="Function$(generate_name "$((SEED + i * 100 + j))" 8)"
        echo -e "\tinline void $METHOD_NAME() {}" >> "$OUTPUT_FILE"
    done

    echo "};" >> "$OUTPUT_FILE"
    echo >> "$OUTPUT_FILE"
done

echo "Generated $NUM_CLASSES classes in $OUTPUT_FILE"
