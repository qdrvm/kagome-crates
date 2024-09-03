#!/bin/bash

cd ../

run_build() {
  build_type=$1
  build_dir=$2

  echo "Building with BUILD_TYPE=$build_type..."
  
  make -B build BUILD_TYPE="$build_type" BUILD_DIR="$build_dir"
  
  if [ $? -ne 0 ]; then
    echo "Error: Build failed for BUILD_TYPE=$build_type."
    exit 1
  else
    echo "Success: Build completed successfully for BUILD_TYPE=$build_type."
  fi
}

run_build Debug build-debug 
run_build Release build

echo "All build tests completed successfully."
exit 0
