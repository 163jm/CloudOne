.PHONY: all build frontend backend clean run build-linux-amd64 build-linux-arm64 dev-frontend

all: build

frontend:
	@echo ">>> 构建前端..."
	cd frontend && npm install && npm run build
	@echo ">>> 前端构建完成"

backend: frontend
	@echo ">>> 构建 Rust 后端..."
	cargo build --release
	cp target/release/cloudone ./cloudone
	@echo ">>> 后端构建完成: ./cloudone"

build: backend

build-linux-amd64: frontend
	@echo ">>> 构建 Rust 后端 linux/amd64..."
	cargo build --release --target x86_64-unknown-linux-gnu
	cp target/x86_64-unknown-linux-gnu/release/cloudone ./cloudone-linux-amd64

build-linux-arm64: frontend
	@echo ">>> 构建 Rust 后端 linux/arm64..."
	cargo build --release --target aarch64-unknown-linux-gnu
	cp target/aarch64-unknown-linux-gnu/release/cloudone ./cloudone-linux-arm64

clean:
	rm -f cloudone cloudone-linux-amd64 cloudone-linux-arm64
	rm -rf target frontend/dist
	@echo ">>> 清理完成"

run: build
	./cloudone

dev-frontend:
	cd frontend && npm run dev
