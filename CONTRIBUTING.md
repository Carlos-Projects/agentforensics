# Contributing to AgentForensics

Thank you for your interest in contributing to AgentForensics! This document provides guidelines and instructions for contributing.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/Carlos-Projects/agentforensics
cd agentforensics

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install with dev dependencies
pip install -e ".[dev]"
```

## Code Style

- **Linting**: `ruff check src/ tests/`
- **Type hints**: Required on all public functions and methods
- **Line length**: 120 characters (configured in pyproject.toml)
- **Python version**: 3.11+

## Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ -v --cov=agentforensics
```

We aim for **60+ tests** and **>80% coverage**.

## Pull Request Process

1. Create a feature branch (`git checkout -b feature/your-feature`)
2. Make your changes with appropriate type hints
3. Run `ruff check src/ tests/` — must pass with no errors
4. Run `python -m pytest tests/ -v` — all tests must pass
5. Commit with a descriptive message
6. Open a Pull Request against `main`

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Include Python version, OS, and steps to reproduce for bugs
- Tag issues appropriately (bug, enhancement, documentation)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
