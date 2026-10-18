# HoneyLens sensor 1.0 — the most common operations in one place.
# The same thing CI runs (ci/security.sh), so there is no divergence.

PY ?= python3.12
VENV := .venv
BIN := $(VENV)/bin

.PHONY: help venv dev lint type test security sbom lock all clean

help:
	@echo "  make dev       — venv on $(PY) + development dependencies + pre-commit"
	@echo "  make lint      — ruff (lint + format --check)"
	@echo "  make type      — mypy"
	@echo "  make test      — pytest"
	@echo "  make security  — SCA + SAST + secrets + SBOM (the same as CI)"
	@echo "  make lock      — requirements.in -> requirements.txt on 3.12 in a Rocky 9 container + pip-audit"
	@echo "  make all       — lint, type, test, security"

$(VENV):
	$(PY) -m venv $(VENV)
	$(BIN)/pip install -q --upgrade pip

# The interpreter is checked explicitly. A venv accidentally built on 3.9 looks the same,
# and this whole line exists in order not to be on 3.9.
dev: $(VENV)
	@v=$$($(BIN)/python -c 'import sys;print("%d.%d"%sys.version_info[:2])'); \
	 if [ "$$v" != "3.12" ]; then \
	   echo "ERROR: venv is on Python $$v, expected 3.12"; \
	   exit 1; fi
	$(BIN)/pip install -q -e '.[dev]'
	$(BIN)/pre-commit install --install-hooks
	@echo "done — interpreter $$($(BIN)/python -V)"

lint: $(VENV)
	$(BIN)/ruff check src tests scripts
	$(BIN)/ruff format --check src tests scripts

type: $(VENV)
	$(BIN)/mypy

test: $(VENV)
	$(BIN)/pytest

security:
	PATH="$(CURDIR)/$(BIN):$$PATH" ./ci/security.sh

sbom: $(VENV)
	$(BIN)/cyclonedx-py requirements requirements.txt -o out/honeylens-sbom.cdx.json

# Phase 1 of the plan. The lock is compiled ON THE TARGET (Rocky 9, Python 3.12 from AppStream), not on macOS —
# pinning done against a different interpreter and OS answers a different question.
# Requires podman locally (or running ci/lock.sh directly on a Rocky 9 host).
CONTAINER ?= podman
lock:
	$(CONTAINER) build -q -f ci/lock.Containerfile -t honeylens-lock .
	$(CONTAINER) run --rm -v "$(CURDIR)":/work:Z honeylens-lock

all: lint type test security

clean:
	rm -rf $(VENV) out .mypy_cache .pytest_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
