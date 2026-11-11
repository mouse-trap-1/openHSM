# OpenHSM prototype: common tasks.
.PHONY: build test lint audit pentest report demo check clean

build:
	cargo build --release

test:
	cargo test --release

lint:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets --release -- -D warnings

audit:
	cargo audit

pentest: build
	python3 pentest/run.py
	python3 pentest/report.py

demo: build
	scripts/demo.sh

# Everything CI runs.
check: lint test audit pentest

clean:
	cargo clean
