.PHONY: all install test clean lint coverage examples docs format type-check

# Python parameters
PYTHON=python3
PIP=pip3
PYTEST=python -m pytest
BLACK=python -m black
FLAKE8=python -m flake8
MYPY=python -m mypy
PACKAGE_NAME=gauth

all: test build

# Development setup
install:
	@echo "Installing GAuth Python package and dependencies..."
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	$(PIP) install -r requirements-dev.txt
	$(PIP) install -e .
	@echo "✅ Installation completed successfully"

install-dev: install
	@echo "Setting up development environment..."
	pre-commit install
	@echo "✅ Development environment setup completed"

# Building (for Python, this mainly means installing)
build: install
	@echo "Building GAuth Python package..."
	$(PYTHON) setup.py build
	@echo "✅ Build completed successfully"

# Testing
test:
	@echo "Running tests..."
	$(PYTEST) tests/ -v
	@echo "✅ Tests completed successfully"

test-coverage:
	@echo "Running tests with coverage..."
	$(PYTEST) tests/ -v --cov=$(PACKAGE_NAME) --cov-report=html --cov-report=term
	@echo "✅ Coverage tests completed successfully"

test-verbose:
	$(PYTEST) tests/ -v -s

test-specific:
	$(PYTEST) tests/test_gauth_basic.py -v

# Code quality
lint:
	@echo "Running linting..."
	$(FLAKE8) $(PACKAGE_NAME)/ --max-line-length=100
	$(FLAKE8) tests/ --max-line-length=100
	@echo "✅ Linting completed successfully"

format:
	@echo "Formatting code..."
	$(BLACK) $(PACKAGE_NAME)/ tests/ examples/
	@echo "✅ Code formatting completed successfully"

format-check:
	$(BLACK) --check $(PACKAGE_NAME)/ tests/ examples/

type-check:
	@echo "Running type checking..."
	$(MYPY) $(PACKAGE_NAME)/
	@echo "✅ Type checking completed successfully"

# Comprehensive verification
verify: format-check lint type-check test
	@echo "✅ All verification steps completed successfully"

# Examples
examples:
	@echo "Running examples..."
	$(PYTHON) examples/basic_usage.py
	@echo "---"
	$(PYTHON) examples/advanced_features.py
	@echo "✅ Examples completed successfully"

demo:
	@echo "Running GAuth demo..."
	$(PYTHON) -m $(PACKAGE_NAME).demo.main
	@echo "✅ Demo completed successfully"

# Documentation
docs:
	@echo "Generating documentation..."
	sphinx-build -b html docs/ docs/_build/html/
	@echo "✅ Documentation generated successfully"

docs-serve:
	@echo "Serving documentation locally..."
	$(PYTHON) -m http.server 8000 --directory docs/_build/html/

# Cleanup
clean:
	@echo "Cleaning up..."
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	find . -type f -name ".coverage" -delete
	rm -rf htmlcov/
	rm -rf dist/
	rm -rf build/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -f audit.log
	rm -f audit_advanced.log
	@echo "✅ Cleanup completed successfully"

# Distribution
dist:
	@echo "Building distribution packages..."
	$(PYTHON) setup.py sdist bdist_wheel
	@echo "✅ Distribution packages built successfully"

upload-test:
	@echo "Uploading to PyPI test..."
	twine upload --repository testpypi dist/*

upload:
	@echo "Uploading to PyPI..."
	twine upload dist/*

# Docker operations
docker-build:
	@echo "Building Docker image..."
	docker build -t gauth-py .
	@echo "✅ Docker image built successfully"

docker-run:
	@echo "Running Docker container..."
	docker run --rm -it gauth-py

docker-test:
	@echo "Running tests in Docker..."
	docker-compose run --rm gauth-py-test

docker-examples:
	@echo "Running examples in Docker..."
	docker-compose run --rm gauth-py-examples

# Docker Compose operations
up:
	docker-compose up -d

down:
	docker-compose down

logs:
	docker-compose logs -f

# Development helpers
install-hooks:
	pre-commit install

run-hooks:
	pre-commit run --all-files

# Version management
version-patch:
	bump2version patch

version-minor:
	bump2version minor

version-major:
	bump2version major

# Security checks
security-check:
	bandit -r $(PACKAGE_NAME)/

# Dependency management
deps-update:
	pip-compile requirements.in
	pip-compile requirements-dev.in

deps-sync:
	pip-sync requirements.txt requirements-dev.txt

# Help
help:
	@echo "Available targets:"
	@echo "  install       - Install package and dependencies"
	@echo "  install-dev   - Setup development environment"
	@echo "  build         - Build the package"
	@echo "  test          - Run tests"
	@echo "  test-coverage - Run tests with coverage"
	@echo "  lint          - Run linting"
	@echo "  format        - Format code"
	@echo "  type-check    - Run type checking"
	@echo "  verify        - Run all quality checks"
	@echo "  examples      - Run examples"
	@echo "  demo          - Run demo application"
	@echo "  docs          - Generate documentation"
	@echo "  clean         - Clean up build artifacts"
	@echo "  dist          - Build distribution packages"
	@echo "  docker-build  - Build Docker image"
	@echo "  docker-run    - Run in Docker container"
	@echo "  up            - Start Docker Compose services"
	@echo "  down          - Stop Docker Compose services"
	@echo "  help          - Show this help message"