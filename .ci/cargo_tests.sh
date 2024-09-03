#!/bin/bash

export HEADER_FILE="/dev/null"
export CBINDGEN_CONFIG="../../cbindgen.toml"

CRATES_DIR="../crates"

for dir in "$CRATES_DIR"/*; do
  if [ -d "$dir" ]; then
    echo "Entering directory: $dir"
    cd "$dir" || exit

    cargo test

    if [ $? -ne 0 ]; then
      echo "Error: cargo test failed in $dir"
      exit 1
    fi

    cd - || exit
  fi
done

echo "All tests completed successfully."
