.PHONY: build clean run help stop

help:
	@echo "eBPF Hello World Project"
	@echo ""
	@echo "Commands:"
	@echo "  make build  - Build both eBPF kernel program and userspace loader"
	@echo "  make run    - Build and run the eBPF program"
	@echo "  make stop   - Kill all running eBPF programs"
	@echo "  make clean  - Clean build artifacts"
	@echo "  make help   - Show this help"

build:
	@echo "Building eBPF Hello World Project..."
	@echo "1. Building eBPF kernel program..."
	@cd src/hello-ebpf-kernelspace && cargo +nightly build --target bpfel-unknown-none -Z build-std=core
	@echo "2. Building userspace loader..."
	@cd src/hello-ebpf-userspace && cargo build
	@echo "✅ Build complete!"
	@echo ""
	@echo "To run: ./target/debug/hello-eBPF"

run: build
	@echo "Running eBPF program..."
	./target/debug/hello-eBPF

stop:
	@echo "Stopping all eBPF programs..."
	@pkill hello-eBPF || echo "No programs running"
	@echo "✅ All eBPF programs stopped!"

clean: stop
	@echo "Cleaning build artifacts..."
	@cd src/hello-ebpf-kernelspace && cargo clean
	@cd src/hello-ebpf-userspace && cargo clean
	@echo "✅ Clean complete!"