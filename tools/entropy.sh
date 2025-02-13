#!/bin/bash

# Output file
OUTPUT_FILE="entropy.h"

# Function to generate a random CamelCase string of given length
generate_name() {
    cat /dev/urandom | tr -dc 'a-z' | fold -w "$1" | head -n 1 | sed -E 's/(^|_)([a-z])/\U\2/g'
}

# Generate a random number of classes (between 1 and 10)
NUM_CLASSES=$((RANDOM % 10 + 1))

> "$OUTPUT_FILE"  # Clear or create the output file

for ((i=0; i<NUM_CLASSES; i++)); do
    CLASS_NAME="Class$(generate_name 6)"
    echo "class $CLASS_NAME {" >> "$OUTPUT_FILE"
    
    # Generate a random number of methods (between 1 and 10)
    NUM_METHODS=$((RANDOM % 10 + 1))
    for ((j=0; j<NUM_METHODS; j++)); do
        METHOD_NAME="Function$(generate_name 8)"
        echo "inline void $METHOD_NAME() {}" >> "$OUTPUT_FILE"
    done
    
    echo "};" >> "$OUTPUT_FILE"
    echo >> "$OUTPUT_FILE"  # Add an empty line for readability
done

echo "Generated $NUM_CLASSES classes in $OUTPUT_FILE"
