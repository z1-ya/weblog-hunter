# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive CI/CD workflow with test, lint, format, and type checking jobs
- Code coverage reporting with Codecov integration
- Pre-commit hooks configuration for automated code quality checks
- GitHub issue templates for bugs and feature requests
- Pull request template with checklist
- PyPI publishing workflow for automated releases
- Repository documentation including SECURITY.md and enhanced CONTRIBUTING.md
- EditorConfig and .gitattributes for consistent development environment

### Changed
- Repository URLs updated from z1-ya to shalbuzov organization
- README badges updated to reflect actual CI status and coverage
- Split lint and format checks into separate CI jobs for better visibility

## [2.0.0] - 2024-01-XX

### Added
- Modular architecture with separated concerns (parser, analyzer, reporters)
- Type hints throughout the codebase for better code quality
- Multiple report formats: Markdown, JSON, and HTML
- Progress bars for long-running operations (via tqdm)
- Docker support with Dockerfile and docker-compose.yml
- Comprehensive test suite with 55+ tests
- Configuration file support (YAML)
- CLI with rich command-line options
- Attack tool fingerprinting (sqlmap, nikto, curl, etc.)
- Behavioral analysis (brute force, scraping detection)
- Vulnerability endpoint ranking

### Changed
- Complete refactoring from monolithic script to modular package structure
- Improved parsing with automatic format detection
- Enhanced threat detection with more attack signatures
- Better error handling and logging
- Cleaner, more maintainable code structure

### Fixed
- Various parsing edge cases
- Performance improvements for large log files

## [1.0.0] - Initial Release

### Added
- Basic web log parsing for Apache/Nginx logs
- Threat detection for common attack patterns (SQLi, XSS, LFI, etc.)
- Report generation in Markdown format
- Command-line interface

---

**Note**: Version 2.0.0 represents the modular refactor merged from PR #1. This changelog will be maintained going forward for all future releases.
