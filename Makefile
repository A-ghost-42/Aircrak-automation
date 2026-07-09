SHELL := /bin/bash
PYTHON := python3
PIP := pip3
VENV_DIR := .venv

.PHONY: all venv install dev-install lint typecheck test clean dist docker-build docker-run

all: install

venv:
	$(PYTHON) -m venv $(VENV_DIR)
	@echo "Virtual env created. Activate with: source $(VENV_DIR)/bin/activate"

install:
	$(PIP) install -r requirements.txt

dev-install:
	$(PIP) install -r requirements.txt
	$(PIP) install pytest pytest-cov mypy ruff

lint:
	ruff check .

typecheck:
	mypy main.py core/ intelligence/ engines/ orchestration/ tools/

test:
	python3 -m pytest tests/ -v --tb=short

test-cov:
	python3 -m pytest tests/ --cov=. --cov-report=term-missing

clean:
	find . -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache 2>/dev/null || true
	rm -rf *.egg-info dist build 2>/dev/null || true
	rm -f .coverage
	rm -rf htmlcov 2>/dev/null || true
	find . -name '*.pyc' -delete 2>/dev/null || true
	find . -name '*.pyo' -delete 2>/dev/null || true

dist:
	$(PYTHON) -m build

docker-build:
	docker build -t pegasus-nexus .

docker-run:
	docker run --rm --network=host --privileged pegasus-nexus --help
