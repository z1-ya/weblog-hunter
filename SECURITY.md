# Security Policy

## Supported Versions

We release patches for security vulnerabilities in the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| < 2.0   | :x:                |

## Reporting a Vulnerability

We take the security of weblog-hunter seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### Please DO NOT:

- Open a public GitHub issue for security vulnerabilities
- Publicly disclose the vulnerability before it has been addressed

### Please DO:

1. **Report via GitHub Security Advisories** (Preferred)
   - Go to https://github.com/shalbuzov/weblog-hunter/security/advisories
   - Click "Report a vulnerability"
   - Fill in the details of the vulnerability

2. **Report via Email** (Alternative)
   - Email: z1-ya@users.noreply.github.com
   - Subject: [SECURITY] Brief description of the issue
   - Include detailed information about the vulnerability

### What to Include in Your Report

Please provide as much information as possible to help us understand and address the issue:

- Type of vulnerability (e.g., injection, XSS, command execution)
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code (tag/branch/commit)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

## Response Timeline

- **Initial Response**: Within 48 hours of receiving your report
- **Status Update**: Within 7 days, we'll provide a detailed response indicating next steps
- **Fix Timeline**: We aim to release a fix within 30-90 days, depending on complexity
- **Public Disclosure**: After a fix is released, we'll coordinate the disclosure timeline with you

## Scope

### In Scope

The following are considered in scope for security reports:

- **Command Injection**: Vulnerabilities in log parsing or report generation
- **Path Traversal**: Issues with file handling
- **Denial of Service**: Performance issues that could be exploited
- **Information Disclosure**: Unintended exposure of sensitive data
- **Code Execution**: Any vulnerability allowing arbitrary code execution
- **Dependency Vulnerabilities**: Critical vulnerabilities in project dependencies

### Out of Scope

The following are generally NOT considered security vulnerabilities:

- Issues in third-party dependencies (report to the dependency maintainers)
- Denial of Service through resource exhaustion with legitimate use
- Issues requiring physical access to the system
- Social engineering attacks
- Issues affecting unsupported versions

## Security Best Practices for Users

When using weblog-hunter:

1. **Run with Least Privilege**: Don't run weblog-hunter with elevated privileges unless necessary
2. **Validate Input**: Only analyze logs from trusted sources
3. **Sanitize Reports**: Review generated reports before sharing, as they may contain sensitive information
4. **Keep Updated**: Always use the latest version to benefit from security fixes
5. **Secure Dependencies**: Regularly update dependencies with `pip install --upgrade`
6. **Review Configurations**: Use configuration files carefully and don't expose sensitive data
7. **Container Security**: When using Docker, follow container security best practices

## Security Features

weblog-hunter is designed with security in mind:

- **No Network Access**: The tool operates entirely offline (except for optional threat intel features)
- **Read-Only Operations**: Log files are read but never modified
- **Type Safety**: Extensive use of type hints to prevent type-related bugs
- **Input Validation**: Regex patterns and parsing are designed to handle malformed input safely
- **Dependency Management**: We regularly review and update dependencies for security issues

## Known Security Considerations

### Log Files as Input

- weblog-hunter processes untrusted data (web server logs)
- All parsing is done defensively with proper error handling
- No execution of code from log files is possible
- Regular expressions are anchored and bounded to prevent ReDoS attacks

### Report Generation

- HTML reports use Jinja2 templating with autoescaping enabled
- No user-provided content is executed as code
- Reports may contain sensitive information about your infrastructure

## Disclosure Policy

When we receive a security report:

1. We'll confirm receipt within 48 hours
2. We'll investigate and validate the issue
3. We'll develop and test a fix
4. We'll prepare a security advisory
5. We'll release the fix and publish the advisory
6. We'll credit the reporter (unless they prefer to remain anonymous)

## Hall of Fame

We appreciate security researchers who help keep weblog-hunter secure. Contributors who responsibly disclose vulnerabilities will be acknowledged here (with their permission):

- *No security reports yet - be the first!*

## Contact

For security-related questions or concerns:
- Security Advisories: https://github.com/shalbuzov/weblog-hunter/security/advisories
- Email: z1-ya@users.noreply.github.com (for security issues only)

For non-security issues, please use the regular [issue tracker](https://github.com/shalbuzov/weblog-hunter/issues).

---

Thank you for helping keep weblog-hunter and its users safe!
