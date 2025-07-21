# Security Policy

## Supported Versions

We actively support the following versions with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please follow these steps:

### 1. Do Not Create a Public Issue

Please do not report security vulnerabilities through public GitHub issues, discussions, or pull requests.

### 2. Report Privately

Send details to: **pypi-security@parker.im**

Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (if you have them)

### 3. Response Timeline

- **Initial Response**: Within 7 days
- **Status Update**: Within 2 weeks
- **Resolution**: Depends on severity and complexity

## Security Approach

This library processes user-provided templates and data. While we implement various validation and safety measures, **you should treat all template content and variables as potentially untrusted input**.

### What We Do

- **Input Validation**: Basic sanitisation of template content and variables
- **Expression Evaluation**: Use AST parsing with restricted node types for conditional expressions
- **Schema Validation**: Validate templates against JSON schemas
- **Network Controls**: Configurable restrictions on external schema fetching
- **Allowlist Management**: User-controlled allowlist for external schemas

### What We Don't Do

- **Complete Sandboxing**: Template processing is not fully sandboxed
- **Content Filtering**: We cannot catch all forms of malicious content
- **Network Security**: SSRF protection is basic and may not cover all edge cases
- **Guarantee Safety**: No security system is perfect

## Security Configuration

For production use:

```python
from its_compiler.security import SecurityConfig

# Recommended production settings
config = SecurityConfig.from_environment()
config.allowlist.interactive_mode = False
config.network.allow_http = False
config.network.block_localhost = True

compiler = ITSCompiler(security_config=config)
```

Environment variables for production:

- `ITS_INTERACTIVE_ALLOWLIST=false`
- `ITS_ALLOW_HTTP=false`
- `ITS_BLOCK_LOCALHOST=true`
- `ITS_REQUEST_TIMEOUT=30`

## Security Considerations

### Template Sources

- Only process templates from trusted sources
- Review templates before use in production
- External schemas should come from trusted domains

### Variable Content

- Validate user-provided variables before processing
- Consider variable values as potentially untrusted input
- Be cautious with variables containing user-generated content

### Network Access

- Schema fetching requires network access
- Configure firewall rules appropriately for your environment
- Monitor network requests in sensitive environments

### Expression Evaluation

- Conditional expressions use AST parsing with restricted nodes
- Complex expressions may have edge cases we haven't considered
- Avoid processing expressions from untrusted sources when possible

## Known Limitations

- **No Perfect Security**: This library cannot guarantee complete security
- **Evolving Threats**: New attack vectors may be discovered
- **Configuration Dependent**: Security depends on proper configuration
- **Input Dependent**: Safety depends on the content being processed

## Dependencies

This library has dependencies that may have their own security considerations:

- **Standard Library**: Uses Python's AST module for expression evaluation
- **Third-party Libraries**: See requirements.txt for current dependencies
- **Network Libraries**: For schema fetching (urllib, requests)

## Security Updates

Security updates will be:

- Released as patch versions (e.g., 1.0.1)
- Announced in [GitHub Security Advisories](https://github.com/alexanderparker/its-compiler-python/security/advisories)
- Documented in release notes with [SECURITY] tags

## Best Practices

1. **Keep Updated**: Always use the latest version
2. **Review Templates**: Audit templates from external sources
3. **Validate Variables**: Sanitise user-provided variables
4. **Configure Properly**: Use appropriate security settings for your environment
5. **Monitor Usage**: Log and monitor template processing in production
6. **Defense in Depth**: Don't rely solely on this library for security

## Acknowledgments

We appreciate security researchers who responsibly disclose vulnerabilities. Contributors will be acknowledged in our security advisories (unless they prefer to remain anonymous).

---

**Remember**: No security system is perfect. Use this library as part of a broader security strategy, not as your only line of defense.
