.PHONY: help install dev test lint type-check format clean build run-tests all

help:
	@echo "Available commands:"
	@echo "  make install       Install dependencies"
	@echo "  make dev          Install with dev dependencies"
	@echo "  make test         Run all tests"
	@echo "  make lint         Run linting (ruff)"
	@echo "  make type-check   Run type checking (mypy)"
	@echo "  make format       Format code (black)"
	@echo "  make clean        Clean build artifacts"
	@echo "  make build        Build package"
	@echo "  make all          Run format, lint, type-check, and test"

install:
	pip install -r requirements.txt
	pip install -e .

dev:
	pip install -r requirements.txt
	pip install -e ".[dev]"

test:
	pytest elijahctl/tests -v --cov=elijahctl --cov-report=term-missing

lint:
	ruff check elijahctl/

type-check:
	mypy elijahctl/

format:
	black elijahctl/
	ruff check --fix elijahctl/

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf .pytest_cache
	rm -rf .mypy_cache
	rm -rf .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

build: clean
	python -m build

run-tests:
	pytest elijahctl/tests/unit -v
	pytest elijahctl/tests/integration -v

all: format lint type-check test