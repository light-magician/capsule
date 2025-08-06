#!/bin/bash
set -e

echo "Building eBPF Hello World Project..."

# Build eBPF kernel program first (needs nightly + special flags)
echo "1. Building eBPF kernel program..."
cd hello-ebpf-kern
cargo +nightly build --target bpfel-unknown-none -Z build-std=core
cd ..

# Build userspace loader program
echo "2. Building userspace loader..."
cd hello-ebpf
cargo build
cd ..

echo "✅ Build complete!"
echo ""
echo "To run: ./target/debug/hello-eBPF"
echo "Binary locations:"
echo "  - eBPF kernel:    target/bpfel-unknown-none/debug/hello-kern"
echo "  - Userspace:      target/debug/hello-eBPF"