SHELL := /bin/bash
PY := python3
VENV := .venv
BIN := $(VENV)/bin

.PHONY: help setup install test lint run-api run-frontend demo sandbox-build clean

help:
	@echo "AIRLOCK targets:"
	@echo "  make setup          Create venv and install dependencies"
	@echo "  make install        Install Python dependencies"
	@echo "  make test           Run the test suite (pytest)"
	@echo "  make run-api        Start the FastAPI gateway"
	@echo "  make run-frontend   Start the frontend dev server"
	@echo "  make sandbox-build  Build the Docker sandbox image"
	@echo "  make demo           Admit the legitimate demo package"
	@echo "  make clean          Remove caches and venv"

setup: install

install:
	$(PY) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -r requirements.txt

test:
	$(BIN)/pytest -q

run-api:
	$(BIN)/uvicorn apps.gateway.main:app --reload --host 0.0.0.0 --port 8000

run-frontend:
	cd frontend && npm install && npm run dev

sandbox-build:
	docker build -t airlock-sandbox:latest -f apps/sandbox/Dockerfile .

demo:
	$(BIN)/python -m apps.cli.airlock admit demo/legitimate-package/package.tgz

clean:
	rm -rf $(VENV) .pytest_cache .mypy_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} \;
	find frontend -name node_modules -type d -prune -exec rm -rf {} \;
	find frontend -name .next -type d -prune -exec rm -rf {} \;
