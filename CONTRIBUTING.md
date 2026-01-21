# Contributing to weblog-hunter

Thank you for your interest in contributing to weblog-hunter! We welcome contributions from the community.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct:

- **Be Respectful**: Treat all contributors with respect
- **Be Professional**: Keep discussions focused and constructive
- **Be Inclusive**: Welcome newcomers and help them get started
- **Be Collaborative**: Work together to improve the project

## Ways to Contribute

There are many ways to contribute to weblog-hunter:

- 🐛 Report bugs
- 💡 Suggest new features
- 📝 Improve documentation
- 🔧 Fix issues
- ✨ Add new features
- 🧪 Write tests
- 📖 Write tutorials or blog posts

## Getting Started

### Development Setup

1. **Fork and Clone**
   ```bash
   # Fork the repository on GitHub, then clone your fork
   git clone https://github.com/YOUR-USERNAME/weblog-hunter.git
   cd weblog-hunter
   ```

2. **Create a Virtual Environment** (Recommended)
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Development Dependencies**
   ```bash
   pip install -e ".[dev]"
   ```

4. **Set Up Pre-commit Hooks** (Optional but Recommended)
   ```bash
   pip install pre-commit
   pre-commit install
   ```

5. **Verify Installation**
   ```bash
   weblog-hunter --version
   pytest tests/
   ```

## Development Workflow

### 1. Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix
```

**Branch Naming Conventions:**
- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation changes
- `refactor/` - Code refactoring
- `test/` - Test additions or fixes

### 2. Make Your Changes

- Write clear, readable code
- Follow existing code style and conventions
- Add docstrings to functions and classes
- Include type hints where appropriate

### 3. Write Tests

All new features and bug fixes must include tests:

```bash
# Run all tests
pytest tests/

# Run specific test file
pytest tests/test_parser.py -v

# Run with coverage
pytest --cov=weblog_hunter --cov-report=term tests/
```

**Test Guidelines:**
- Place tests in the `tests/` directory
- Name test files `test_*.py`
- Name test functions `test_*`
- Use descriptive test names
- Include both positive and negative test cases
- Aim for high code coverage

### 4. Run Code Quality Checks

Before committing, ensure your code passes all quality checks:

```bash
# Format code with black
black weblog_hunter/ tests/

# Lint with ruff
ruff check weblog_hunter/ tests/

# Type check with mypy
mypy weblog_hunter/

# Run all checks together
black weblog_hunter/ tests/ && \
ruff check weblog_hunter/ tests/ && \
mypy weblog_hunter/ && \
pytest tests/
```

If you set up pre-commit hooks, these checks run automatically on commit.

### 5. Commit Your Changes

**Commit Message Convention:**

```
<type>: <subject>

<body (optional)>

<footer (optional)>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Test additions or changes
- `chore`: Build process or auxiliary tool changes

**Examples:**
```bash
git commit -m "feat: add support for custom log formats"
git commit -m "fix: handle malformed timestamp in nginx logs"
git commit -m "docs: update installation instructions"
```

### 6. Push to Your Fork

```bash
git push origin feature/your-feature-name
```

### 7. Create a Pull Request

1. Go to the [weblog-hunter repository](https://github.com/shalbuzov/weblog-hunter)
2. Click "New Pull Request"
3. Select your fork and branch
4. Fill out the pull request template
5. Submit the pull request

## Pull Request Guidelines

### Before Submitting

- ✅ All tests pass
- ✅ Code is formatted with black
- ✅ No linting errors from ruff
- ✅ Type checking passes (mypy)
- ✅ New features include tests
- ✅ Documentation is updated
- ✅ CHANGELOG.md is updated (for significant changes)

### PR Description

Your pull request should include:

- **Description**: Clear explanation of what the PR does
- **Motivation**: Why is this change needed?
- **Related Issues**: Link to any related issues (e.g., "Closes #123")
- **Type of Change**: Bug fix, new feature, documentation, etc.
- **Testing**: How was this tested?
- **Screenshots**: If applicable (especially for HTML report changes)

## Code Style Guidelines

### Python Code Style

We follow [PEP 8](https://pep8.org/) with these tools:

- **black**: Code formatter (line length: 100)
- **ruff**: Fast Python linter
- **mypy**: Static type checker

### Type Hints

Use type hints for function signatures:

```python
def parse_log_line(line: str) -> Optional[LogEntry]:
    """Parse a single log line."""
    ...
```

### Docstrings

Use Google-style docstrings:

```python
def analyze_threats(entries: List[LogEntry]) -> ThreatReport:
    """Analyze log entries for security threats.
    
    Args:
        entries: List of parsed log entries to analyze
        
    Returns:
        ThreatReport containing analysis results
        
    Raises:
        ValueError: If entries list is empty
    """
    ...
```

### Naming Conventions

- **Functions/Variables**: `snake_case`
- **Classes**: `PascalCase`
- **Constants**: `UPPER_SNAKE_CASE`
- **Private Methods**: `_leading_underscore`

## Testing Guidelines

### Test Structure

```python
def test_feature_description():
    """Test that feature works correctly."""
    # Arrange
    input_data = "test data"
    
    # Act
    result = function_under_test(input_data)
    
    # Assert
    assert result == expected_output
```

### Running Tests

```bash
# All tests
pytest tests/

# Specific test file
pytest tests/test_parser.py

# Specific test
pytest tests/test_parser.py::test_parse_apache_log

# With coverage
pytest --cov=weblog_hunter tests/

# Verbose output
pytest -v tests/

# Stop on first failure
pytest -x tests/
```

## Documentation

### Updating Documentation

If you change functionality:

1. Update relevant docstrings
2. Update `README.md` if user-facing
3. Update files in `docs/` directory
4. Update `CHANGELOG.md` for significant changes

### Documentation Files

- `README.md` - Main project documentation
- `docs/usage.md` - Detailed usage guide
- `docs/api.md` - API documentation
- `docs/contributing.md` - Contributing guide (legacy, prefer root CONTRIBUTING.md)
- `CHANGELOG.md` - Version history

## Reporting Issues

### Bug Reports

When reporting a bug, include:

- **Description**: Clear description of the bug
- **Steps to Reproduce**: Exact steps to reproduce the issue
- **Expected Behavior**: What you expected to happen
- **Actual Behavior**: What actually happened
- **Environment**: OS, Python version, weblog-hunter version
- **Log Samples**: Sample log entries that trigger the bug (sanitized)
- **Error Messages**: Full error messages and stack traces

### Feature Requests

When requesting a feature, include:

- **Description**: Clear description of the feature
- **Use Case**: Why is this feature needed?
- **Proposed Solution**: How should it work?
- **Alternatives**: Other approaches you've considered

## Review Process

After you submit a pull request:

1. **Automated Checks**: CI will run tests and quality checks
2. **Code Review**: Maintainers will review your code
3. **Feedback**: You may receive feedback or change requests
4. **Iteration**: Make requested changes and push updates
5. **Approval**: Once approved, your PR will be merged

## Release Process

(For Maintainers)

1. Update `CHANGELOG.md` with release notes
2. Update version in `pyproject.toml`
3. Create a git tag: `git tag -a v2.1.0 -m "Release v2.1.0"`
4. Push tag: `git push origin v2.1.0`
5. Create GitHub Release
6. CI will automatically publish to PyPI

## Getting Help

If you need help:

- 📖 Check the [documentation](docs/)
- 🐛 Search [existing issues](https://github.com/shalbuzov/weblog-hunter/issues)
- 💬 Ask in a new issue with the "question" label
- 📧 Contact maintainers (for security issues only)

## Recognition

Contributors will be recognized:

- In release notes
- In the project README (for significant contributions)
- In git history

## License

By contributing to weblog-hunter, you agree that your contributions will be licensed under the [MIT License](LICENSE).

---

Thank you for contributing to weblog-hunter! Your efforts help make web server log analysis more accessible and effective for everyone. 🎯
