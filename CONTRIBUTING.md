# Contributing to AgentForensics

👋 **Hello and welcome to AgentForensics!**

Thank you for considering contributing to our post-incident forensics system for AI agents. Whether you're an experienced developer or just starting your journey in AI security, your contributions help make agent behavior analysis more robust and accessible.

## First Time Contributor?

Here's how to dive in:

- Look for issues labeled `good first issue`
- Try running the existing test suite and improving coverage
- Add a new visualization to the dashboard
- Improve documentation or write a tutorial
- Report bugs or suggest features — your feedback matters!

We welcome contributors of all skill levels. Don't be shy — jump in!

## Need Help?

Questions or concerns?

- Open a [GitHub Issue](https://github.com/Carlos-Projects/agentforensics/issues)
- Search existing issues first
- Tag appropriately (bug, enhancement, documentation)
- Include Python version, OS, and steps to reproduce for bugs

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

---

💡 This project is governed by a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold its principles.
