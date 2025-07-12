# ITS Compiler Python

[![PyPI version](https://badge.fury.io/py/its-compiler-python.svg)](https://badge.fury.io/py/its-compiler-python)
[![Python](https://img.shields.io/pypi/pyversions/its-compiler-python.svg)](https://pypi.org/project/its-compiler-python/)
[![License](https://img.shields.io/github/license/AlexanderParker/its-compiler-python.svg)](LICENSE)

Reference Python compiler for the [Instruction Template Specification (ITS)](https://alexanderparker.github.io/instruction-template-specification/) that converts content templates with placeholders into structured AI prompts.

> **New to ITS?** See the [specification documentation](https://alexanderparker.github.io/instruction-template-specification/) for complete details on the template format and concepts.

## Quick Example

**Input Template (`blog-post.json`):**

```json
{
  "$schema": "https://alexanderparker.github.io/instruction-template-specification/schema/v1.0/its-base-schema-v1.json",
  "version": "1.0.0",
  "extends": [
    "https://alexanderparker.github.io/instruction-template-specification/schema/v1.0/its-base-schema-v1.json"
  ],
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

**Compilation:**

```bash
its-compile blog-post.json --output blog-prompt.txt
```

**Output (`blog-prompt.txt`):**

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

### For Users

```bash
pip install its-compiler-python
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

# Verify installation
its-compile --help
```

## Quick Start

### Command Line

```bash
# Basic compilation
its-compile template.json

# Output to file
its-compile template.json --output prompt.txt

# Use custom variables
its-compile template.json --variables vars.json

# Watch mode for development
its-compile template.json --watch

# Validate template without compiling
its-compile template.json --validate-only

# Strict validation
its-compile template.json --strict
```

### Python Library

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

## Features

### Complete ITS v1.0 Support

- All standard instruction types (list, paragraph, table, etc.)
- Variables with `${variable}` syntax, including object properties and arrays
- Conditional content with Python-like expressions
- Schema extension mechanism with override precedence
- Custom instruction types

### Developer Tools

- Error messages with line numbers
- Override reporting shows which types are being replaced
- Watch mode for rapid development iteration
- Validation with detailed feedback

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

## CLI Reference

```
its-compile [OPTIONS] TEMPLATE_FILE

Options:
  -o, --output FILE          Output file (default: stdout)
  -v, --variables FILE       JSON file with variable values
  -w, --watch               Watch template file for changes
  --validate-only           Validate template without compiling
  --verbose                 Show detailed output
  --strict                  Enable strict validation mode
  --allowlist-status        Show schema allowlist status
  --help                    Show this message and exit
```

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

**Management commands:**

- `its-compile --allowlist-status` - View allowlist status
- `its-compile --add-trusted-schema URL` - Add trusted schema
- `its-compile --export-allowlist FILE` - Export allowlist

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

The test suite automatically downloads test templates from the [ITS Example Templates repository](https://github.com/AlexanderParker/its-example-templates) when you run tests.

Run the test suite:

```bash
# Run all tests (automatically downloads test templates from GitHub)
python test_runner.py

# Run specific categories
python test_runner.py --category security
python test_runner.py --category integration

# Run with verbose output
python test_runner.py --verbose

# Generate JUnit XML for CI
python test_runner.py --junit-xml test-results.xml

# Run specific test by name
python test_runner.py --test "Simple Variables"

# List available test categories
python test_runner.py --list-categories

# Run only security tests
python test_runner.py --security-only

# Use specific test version
python test_runner.py --test-version v1.0
```

**Test Coverage:**

- **24 integration tests** - All ITS features and error cases
- **8 security tests** - Malicious content detection and blocking
- **9 error handling tests** - Invalid templates and edge cases

The test runner will:
1. Download test templates directly from GitHub (no git required)
2. Use temporary files for each test run
3. Automatically clean up after completion
4. Work offline after initial downloads (browser cache)

**Requirements:**
- Internet connection for downloading test templates
- No git installation required
- Works in any environment with Python and urllib

## API Reference

### ITSCompiler Class

```python
class ITSCompiler:
    def __init__(self, config: Optional[ITSConfig] = None,
                 security_config: Optional[SecurityConfig] = None)

    def compile(self, template: dict, variables: Optional[dict] = None) -> CompilationResult
    def compile_file(self, template_path: str, variables: Optional[dict] = None) -> CompilationResult
    def validate(self, template: dict) -> ValidationResult
    def validate_file(self, template_path: str) -> ValidationResult
```

### CompilationResult Class

```python
class CompilationResult:
    prompt: str                    # The compiled prompt
    template: dict                 # The original template
    variables: dict                # Resolved variables
    overrides: List[TypeOverride]  # Type overrides that occurred
    warnings: List[str]            # Compilation warnings
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes and add tests
4. Ensure all tests pass (`python test_runner.py`)
5. Run linting (`black . && flake8`)
6. Commit your changes
7. Push to the branch and open a Pull Request

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

## Related Projects

- **[Instruction Template Specification](https://alexanderparker.github.io/instruction-template-specification/)** - The official ITS specification and schema
- **[ITS Example Templates](https://github.com/AlexanderParker/its-example-templates)** - Test templates and examples for the ITS compiler

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
