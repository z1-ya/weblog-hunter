# Contributing to weblog-hunter

We welcome contributions! This guide will help you get started.

## Development Setup

```bash
# Clone repository
git clone https://github.com/z1-ya/weblog-hunter.git
cd weblog-hunter

# Install with development dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/
```

## Code Style

We use:
- **black** for code formatting
- **ruff** for linting
- **mypy** for type checking

```bash
# Format code
black weblog_hunter/

# Lint
ruff check weblog_hunter/

# Type check
mypy weblog_hunter/
```

## Testing

All new features must include tests:

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest --cov=weblog_hunter tests/

# Run specific test
pytest tests/test_parser.py::TestLogParser::test_parse_sqli_detection -v
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Format and lint your code
7. Commit your changes (`git commit -m 'Add amazing feature'`)
8. Push to your fork (`git push origin feature/amazing-feature`)
9. Open a Pull Request

## Code of Conduct

Be respectful, professional, and inclusive.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
