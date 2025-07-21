# ITS Compiler Python

[![PyPI version](https://img.shields.io/pypi/v/its-compiler.svg)](https://pypi.org/project/its-compiler/)
[![Python](https://img.shields.io/pypi/pyversions/its-compiler.svg)](https://pypi.org/project/its-compiler/)
[![License](https://img.shields.io/github/license/AlexanderParker/its-compiler-python.svg)](LICENSE)

Reference Python compiler for the [Instruction Template Specification (ITS)](https://alexanderparker.github.io/instruction-template-specification/) that converts content templates with placeholders into structured AI prompts.

> **New to ITS?** See the [specification documentation](https://alexanderparker.github.io/instruction-template-specification/) for complete details on the template format and concepts.

## Quick Example

**Input Template (`blog-post.json`):**

```json
{
  "$schema": "https://alexanderparker.github.io/instruction-template-specification/schema/v1.0/its-base-schema-v1.json",
  "version": "1.0.0",
  "extends": ["https://alexanderparker.github.io/instruction-template-specification/schema/v1.0/its-standard-types-v1.json"],
  "variables": {
    "topic": "sustainable technology",
    "includeExamples": true
  },
  "content": [
    {
      "type": "text",
      "text": "# "
    },
    {
      "type": "placeholder",
      "instructionType": "title",
      "config": {
        "description": "Create an engaging blog post title about ${topic}",
        "style": "catchy",
        "length": "short"
      }
    },
    {
      "type": "text",
      "text": "\n\n## Introduction\n\n"
    },
    {
      "type": "placeholder",
      "instructionType": "paragraph",
      "config": {
        "description": "Write an engaging introduction about ${topic}",
        "tone": "professional",
        "length": "medium"
      }
    },
    {
      "type": "conditional",
      "condition": "includeExamples == true",
      "content": [
        {
          "type": "text",
          "text": "\n\n## Examples\n\n"
        },
        {
          "type": "placeholder",
          "instructionType": "list",
          "config": {
            "description": "List 4 examples of ${topic}",
            "format": "bullet_points",
            "itemCount": 4
          }
        }
      ]
    }
  ]
}
```

**Using the Python Library:**

```python
from its_compiler import ITSCompiler

compiler = ITSCompiler()
result = compiler.compile_file('blog-post.json')
print(result.prompt)
```

**Output:**

```
INTRODUCTION

You are an AI assistant that fills in content templates. Follow the instructions exactly and replace each placeholder with appropriate content based on the user prompts provided. Respond only with the transformed content.

INSTRUCTIONS

1. Replace each placeholder marked with << >> with generated content
2. The user's content request is wrapped in ([{< >}]) to distinguish it from instructions
3. Follow the format requirements specified after each user prompt
4. Maintain the existing structure and formatting of the template
5. Only replace the placeholders - do not modify any other text
6. Generate content that matches the tone and style requested
7. Respond only with the transformed content - do not include any explanations or additional text

TEMPLATE

# <<Replace this placeholder with a title using this user prompt: ([{<Create an engaging blog post title about sustainable technology>}]). Format requirements: Create a catchy title that is short in length.>>

## Introduction

<<Replace this placeholder with text using this user prompt: ([{<Write an engaging introduction about sustainable technology>}]). Format requirements: Use professional tone and medium length (2-4 sentences).>>

## Examples

<<Replace this placeholder with a list using this user prompt: ([{<List 4 examples of sustainable technology>}]). Format requirements: Use bullet_points formatting with each item on a new line. Create exactly 4 items.>>
```

## Installation

### For Library Users

```bash
pip install its-compiler
```

### For Developers

```bash
# Clone and setup
git clone https://github.com/AlexanderParker/its-compiler-python.git
cd its-compiler-python

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Run tests
python test_runner.py
```

## Command Line Interface

For command-line usage, install the separate CLI package:

```bash
pip install its-compiler-cli
```

See the [ITS Compiler CLI repository](https://github.com/AlexanderParker/its-compiler-cli-python) for command-line documentation and usage examples.

## Python Library Usage

### Basic Usage

```python
from its_compiler import ITSCompiler

# Initialize compiler
compiler = ITSCompiler()

# Compile a template file
result = compiler.compile_file('template.json')
print(result.prompt)

# Compile with custom variables
variables = {"productType": "gaming headset", "featureCount": 5}
result = compiler.compile(template_dict, variables=variables)

# Handle compilation errors
try:
    result = compiler.compile_file('template.json')
except ITSValidationError as e:
    print(f"Validation error: {e}")
except ITSCompilationError as e:
    print(f"Compilation error: {e}")
```

### Configuration

```python
from its_compiler import ITSCompiler, ITSConfig
from its_compiler.security import SecurityConfig

# Custom configuration
config = ITSConfig(
    cache_enabled=False,
    strict_mode=True,
    max_retries=5
)

# Security configuration
security_config = SecurityConfig.for_development()
security_config.allowlist.interactive_mode = False

compiler = ITSCompiler(config=config, security_config=security_config)
```

## Features

### Complete ITS v1.0 Support

- All standard instruction types (list, paragraph, table, etc.)
- Variables with `${variable}` syntax, including object properties and arrays
- Conditional content with Python-like expressions
- Schema extension mechanism with override precedence
- Custom instruction types

### Security Features

The compiler includes security features to help protect against common attack vectors. **Users are responsible for validating their own inputs** and ensuring templates meet their security requirements.

- **Schema Allowlist** - Control which schema URLs are permitted
- **Expression Validation** - Validate conditional expressions
- **Input Validation** - Scan content for problematic patterns
- **SSRF Protection** - Block private networks and validate URLs

### Variables and Conditionals

```json
{
  "variables": {
    "product": { "name": "SmartWatch Pro", "price": 299 },
    "features": ["heart rate", "GPS", "waterproof"],
    "showSpecs": true
  },
  "content": [
    { "type": "text", "text": "# ${product.name}\nPrice: ${product.price}\n" },
    {
      "type": "conditional",
      "condition": "showSpecs == true and product.price > 200",
      "content": [{ "type": "text", "text": "Premium features included" }]
    }
  ]
}
```

**Variable support:**

- Simple values: `${productName}`
- Object properties: `${product.name}`, `${product.price}`
- Array elements: `${features[0]}`, array length: `${features.length}`
- Arrays as lists: `${features}` becomes "heart rate, GPS, waterproof"

**Conditional operators:**

- Comparison: `==`, `!=`, `<`, `<=`, `>`, `>=`
- Boolean: `and`, `or`, `not`
- Membership: `in`, `not in`

## Configuration

### Environment Variables

**Network Security:**

- `ITS_ALLOW_HTTP` - Allow HTTP URLs (default: false)
- `ITS_BLOCK_LOCALHOST` - Block localhost access (default: true)
- `ITS_REQUEST_TIMEOUT` - Network timeout in seconds (default: 10)
- `ITS_DOMAIN_ALLOWLIST` - Comma-separated allowed domains

**Schema Allowlist:**

- `ITS_INTERACTIVE_ALLOWLIST` - Enable interactive prompts (default: true)
- `ITS_ALLOWLIST_FILE` - Custom allowlist file location

**Processing Limits:**

- `ITS_MAX_TEMPLATE_SIZE` - Max template size in bytes (default: 1MB)
- `ITS_MAX_CONTENT_ELEMENTS` - Max content elements (default: 1000)

**Feature Toggles:**

- `ITS_DISABLE_ALLOWLIST` - Disable schema allowlist
- `ITS_DISABLE_INPUT_VALIDATION` - Disable input validation

### Allowlist Management

When `ITS_INTERACTIVE_ALLOWLIST` is enabled, you'll be prompted for unknown schemas:

```
SCHEMA ALLOWLIST DECISION REQUIRED
URL: https://example.com/schema.json

1. Allow permanently (saved to allowlist)
2. Allow for this session only
3. Deny (compilation will fail)
```

### Configuration File

Create `.its-config.json`:

```json
{
  "security": {
    "allowHttp": false,
    "domainAllowlist": ["alexanderparker.github.io"],
    "maxSchemaSize": "10MB"
  },
  "compiler": {
    "strictMode": true,
    "reportOverrides": true
  }
}
```

## Error Handling

The compiler provides detailed error messages:

### Schema Validation Errors

```
ITSValidationError: Template validation failed at content[2].config:
  - Missing required property 'description'
  - Invalid instruction type 'unknown_type'
```

### Variable Resolution Errors

```
ITSVariableError: Undefined variable reference at content[1].config.description:
  - Variable '${productName}' is not defined
  - Available variables: productType, featureCount
```

## Testing

```bash
# Run all tests
python test_runner.py

# Run specific categories
python test_runner.py --category security
python test_runner.py --category integration

# Run with verbose output
python test_runner.py --verbose

# Run linting and security checks
python test_runner.py --lint
python test_runner.py --security-scan
```

## API Reference

### Required Imports

```python
from typing import Optional
from its_compiler import ITSCompiler, ITSConfig
from its_compiler.security import SecurityConfig
from its_compiler.core.exceptions import ITSValidationError, ITSCompilationError
```

### ITSCompiler Class

```python
class ITSCompiler:
    def __init__(self, config: Optional[ITSConfig] = None,
                 security_config: Optional[SecurityConfig] = None)

    def compile(self, template: dict, variables: Optional[dict] = None,
                base_url: Optional[str] = None) -> CompilationResult

    def compile_file(self, template_path: str, variables: Optional[dict] = None) -> CompilationResult

    def validate(self, template: dict, base_url: Optional[str] = None) -> ValidationResult

    def validate_file(self, template_path: str) -> ValidationResult

    def get_security_status(self) -> dict
```

### CompilationResult Class

```python
class CompilationResult:
    prompt: str                           # The compiled prompt
    template: dict                        # The original template
    variables: dict                       # Resolved variables
    overrides: List[TypeOverride]         # Type overrides that occurred
    warnings: List[str]                   # Compilation warnings
    security_metrics: SecurityMetrics     # Security operation metrics
    compilation_time: Optional[float]     # Time taken to compile
    security_events: List[str]            # Security events that occurred

    # Properties
    @property
    def has_overrides(self) -> bool       # Check if any type overrides occurred

    @property
    def has_warnings(self) -> bool        # Check if any warnings were generated

    @property
    def has_security_events(self) -> bool # Check if any security events occurred

    @property
    def prompt_size(self) -> int          # Get prompt size in bytes

    # Methods
    def get_summary(self) -> dict         # Get compilation summary with metrics
```

### ValidationResult Class

```python
class ValidationResult:
    is_valid: bool                        # Whether validation passed
    errors: List[str]                     # Validation errors found
    warnings: List[str]                   # Validation warnings
    security_issues: List[str]            # Security issues found
    validation_time: Optional[float]      # Time taken to validate

    # Properties
    @property
    def has_security_issues(self) -> bool # Check if security issues were found

    @property
    def total_issues(self) -> int         # Get total count of all issues

    def __bool__(self) -> bool            # Allows `if validation_result:` usage
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`; other branch prefixes could be used i.e. `bugfix`, `devops`, `test`, etc, depending on use-case)
3. Make your changes and add / update tests, precommit configs, and github workflows as appropriate
4. Ensure all tests pass (`python test_runner.py --all`)
5. Commit your changes
6. Push to the branch and ensure all github workflows pass
7. Open a Pull Request

### Development Setup

```bash
# Clone and setup
git clone https://github.com/AlexanderParker/its-compiler-python.git
cd its-compiler-python

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Run tests
python test_runner.py
```

### For Maintainers

**Publishing to PyPI:**

This package is published to PyPI as `its-compiler`. Releases are currently managed manually:

```bash
# Build the package
python -m build

# Test upload to TestPyPI first (recommended)
python -m twine upload --repository testpypi dist/*

# Upload to production PyPI (requires appropriate credentials)
python -m twine upload dist/*
```

**TestPyPI Testing:**
```bash
# Install from TestPyPI to verify the package
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ its-compiler
```

## Related Projects

- **[ITS Compiler CLI](https://github.com/AlexanderParker/its-compiler-cli-python)** - Command-line interface for the ITS Compiler
- **[Instruction Template Specification](https://alexanderparker.github.io/instruction-template-specification/)** - The official ITS specification and schema
- **[ITS Example Templates](https://github.com/AlexanderParker/its-example-templates)** - Test templates and examples for the ITS compiler

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
