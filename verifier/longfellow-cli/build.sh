#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"

echo "=== Installing build dependencies (requires sudo) ==="
sudo apt-get install -y libssl-dev libzstd-dev

echo "=== Configuring ==="
export PATH="$HOME/.local/lib/python3.12/site-packages/cmake/data/bin:$PATH"
mkdir -p "$BUILD_DIR"
cmake -S "$SCRIPT_DIR" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release

echo "=== Building ==="
cmake --build "$BUILD_DIR" --parallel $(nproc)

echo ""
echo "=== Done ==="
echo "Binary: $BUILD_DIR/longfellow-cli"
echo ""
echo "Usage:"
echo "  $BUILD_DIR/longfellow-cli circuit 0 circuit.json"
echo "  $BUILD_DIR/longfellow-cli prove circuit.json mdoc.json proof.json"
echo "  $BUILD_DIR/longfellow-cli verify circuit.json proof.json"
