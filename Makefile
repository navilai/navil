# Navil development commands
# Run `make check` before pushing to avoid CI failures

.PHONY: check lint format typecheck test test-all install-hooks

# Run all checks (same as CI) — run this before every push
check: lint format typecheck test
	@echo ""
	@echo "  All checks passed. Safe to push."
	@echo ""

# Lint with ruff
lint:
	@echo "=== Ruff lint ==="
	ruff check . --fix
	@echo "  OK"

# Format with ruff
format:
	@echo "=== Ruff format ==="
	ruff format .
	@echo "  OK"

# Type check with mypy
typecheck:
	@echo "=== Mypy ==="
	mypy navil/ --ignore-missing-imports
	@echo "  OK"

# Run core tests only (fast, ~45s)
test:
	@echo "=== Tests ==="
	python3 -m pytest tests/ -x -q --timeout=30

# Run ALL tests including ML and LLM (slow, needs extras)
test-all:
	@echo "=== All tests (core + ML + LLM) ==="
	python3 -m pytest tests/ -x -q --timeout=60

# Install pre-commit hooks (one-time setup)
install-hooks:
	pip install pre-commit
	pre-commit install
	@echo ""
	@echo "  Pre-commit hooks installed. Lint/format/typecheck"
	@echo "  will run automatically on every git commit."
	@echo ""

# Rust checks (for navil-proxy changes)
rust-check:
	@echo "=== Rust ==="
	cd navil-proxy && cargo fmt --check && cargo clippy -- -D warnings && cargo test
	@echo "  OK"
