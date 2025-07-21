# Security Policy

## Supported Versions

We actively support the following versions with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please follow these steps:

### 1. **Do Not** Create a Public Issue
Please do not report security vulnerabilities through public GitHub issues, discussions, or pull requests.

### 2. Report Privately
Send details to: **[pypi-security@parker.im]**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (if you have them)

### 3. Response Timeline
- **Initial Response**: Within 7 days
- **Status Update**: Within 2 weeks
- **Resolution**: Depends on severity and complexity

## Security Features

This library includes several security features:

- **Schema Allowlist**: Interactive allowlist management for external schemas
- **SSRF Protection**: Blocks private networks and dangerous URLs
- **Input Validation**: Sanitizes templates and variables for malicious content
- **AST Evaluation**: Does not evaluate code directly, instead uses ASTs with restricted nodes allowed
- **Expression Sanitization**: Validates conditional expressions against code injection
- **Rate Limiting**: Prevents abuse of schema fetching and compilation

## Security Configuration

For production deployments:

```python
from its_compiler.security import SecurityConfig

# Use production security settings
config = SecurityConfig.from_environment()
compiler = ITSCompiler(security_config=config)
```

Environment variables for production:
- `ITS_DISABLE_ALLOWLIST=false`
- `ITS_INTERACTIVE_ALLOWLIST=false`
- `ITS_BLOCK_PRIVATE_NETWORKS=true`
- `ITS_BLOCK_LOCALHOST=true`

## Known Security Considerations

1. **External Schema Loading**: Only load schemas from trusted sources
2. **Variable Content**: Validate user-provided variables before processing
3. **Network Access**: Schema fetching and unit test execution requires network access - ensure proper firewall rules
4. **Template Sources**: Only process templates from trusted sources

## Security Updates

Security updates will be:
- Released as patch versions (e.g., 1.0.1)
- Announced in [GitHub Security Advisories](https://github.com/AlexanderParker/its-compiler-python/security/advisories)

## Acknowledgments

We appreciate security researchers who responsibly disclose vulnerabilities. Contributors will be acknowledged in our security advisories (unless they prefer to remain anonymous).
