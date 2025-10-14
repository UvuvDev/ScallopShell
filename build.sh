
#!/usr/bin/env bash
set -euo pipefail

# where to build
BUILD_DIR="${1:-build}"
TYPE="${CMAKE_BUILD_TYPE:-Debug}"

# wipe only the out-of-source build dir; keep source tree clean
rm -rf "$BUILD_DIR"

# ensure no stale in-source cache exists
rm -f CMakeCache.txt
rm -rf CMakeFiles

# configure + build
cmake -S . -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE="$TYPE"
cmake --build "$BUILD_DIR" -j"$(nproc)"

ln -sf build/compile_commands.json compile_commands.json

echo "Binary: $BUILD_DIR/scallop"
