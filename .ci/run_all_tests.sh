#!/bin/bash

scripts=("build_test.sh" "check_files.py" "cargo_tests.sh")

error_found=0

for script in "${scripts[@]}"; do
  echo "Running $script..."

  if [[ "$script" == *.py ]]; then
    python3 "$script"
  elif [[ "$script" == *.sh ]]; then
    bash "$script"
  else
    echo "Unknown file type for script: $script"
    error_found=1
    continue
  fi

  if [ $? -ne 0 ]; then
    echo "Error: $script failed."
    error_found=1
  else
    echo "Success: $script completed successfully."
  fi
done

if [ $error_found -ne 0 ]; then
  echo "One or more scripts failed."
  exit 1
else
  echo "All scripts ran successfully."
  exit 0
fi
