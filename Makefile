.PHONY: install dev-install test lint typecheck check clean build docs format

install:
	pip install .

dev-install:
	pip install -e ".[all]"

test:
	python -m pytest tests/ -v --tb=short

test-cov:
	python -m pytest tests/ --tb=short --cov=src/agentforensics --cov-report=term-missing

lint:
	ruff check src/ tests/

format:
	ruff check --fix src/ tests/
	ruff format src/ tests/

typecheck:
	mypy src/agentforensics/

check: lint typecheck test

build:
	python -m build

docs:
	cd docs && sphinx-build -b html source build

clean:
	rm -rf build/ dist/ *.egg-info/ .pytest_cache/ .mypy_cache/ .ruff_cache/ docs/build/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete
	rm -f .coverage forensics.db
