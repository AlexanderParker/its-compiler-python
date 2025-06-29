# ITS Compiler Python

[![PyPI version](https://badge.fury.io/py/its-compiler-python.svg)](https://badge.fury.io/py/its-compiler-python)
[![Python](https://img.shields.io/python/required-version-toml?tomlFilePath=https%3A%2F%2Fraw.githubusercontent.com%2Falexanderparker%2Fits-compiler-python%2Fmain%2Fpyproject.toml)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Reference Python compiler for the [Instruction Template Specification (ITS)](https://github.com/alexanderparker/instruction-template-specification) that converts content templates with placeholders into structured AI prompts for content generation.

## What is ITS?

ITS enables content creators to build templates using natural language and visual placeholders, which then compile into prompts that instruct AI systems to generate specific types of content.

**Traditional Templating vs ITS:**

```
Traditional: Template + Data → Content
ITS:         Template → AI Prompt → AI-Generated Content
```

## Installation

### For Users

```bash
pip install its-compiler-python
```

### For Development

Using a virtual environment is recommended to avoid dependency conflicts:

```bash
# Clone the repository
git clone https://github.com/alexanderparker/its-compiler-python.git
cd its-compiler-python

# Create and activate virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install in development mode with all dev tools
pip install -e ".[dev]"

# Verify installation
its-compile --help
```

**When you're done working:**

```bash
# Deactivate the virtual environment
deactivate
```

**To work on the project later:**

```bash
cd its-compiler-python
# Reactivate the virtual environment
venv\Scripts\activate  # Windows
source venv/bin/activate  # macOS/Linux
```

## Quick Start

### Command Line Usage

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

# Verbose output with override reporting
its-compile template.json --verbose
```

### Python Library Usage

```python
from its_compiler import ITSCompiler

# Initialize compiler
compiler = ITSCompiler()

# Compile a template file
result = compiler.compile_file('template.json')
print(result.prompt)

# Compile from dictionary
template_dict = {
    "$schema": "https://alexanderparker.github.io/instruction-template-specification/schema/v1.0/its-base-schema-v1.json",
    "version": "1.0.0",
    "content": [
        {"type": "text", "text": "Here are some fruits:\n"},
        {
            "type": "placeholder",
            "instructionType": "list",
            "config": {
                "description": "list 5 different citrus fruits",
                "format": "bullet_points"
            }
        }
    ]
}

result = compiler.compile(template_dict)
print(result.prompt)

# Compile with custom variables
variables = {"productType": "gaming headset", "featureCount": 5}
result = compiler.compile(template_dict, variables=variables)

# Handle compilation errors
try:
    result = compiler.compile_file('invalid-template.json')
except ITSValidationError as e:
    print(f"Validation error: {e}")
except ITSCompilationError as e:
    print(f"Compilation error: {e}")
```

## Features

### ✅ Complete ITS v1.0 Support

- All standard instruction types (list, paragraph, table, etc.)
- Variables with `${variable}` syntax, including object properties and arrays
- Conditional content with Python-like expressions
- Schema extension mechanism with override precedence
- Custom instruction types

### 🛠️ Developer-Friendly

- Comprehensive error messages with line numbers
- Override reporting shows which types are being replaced
- Watch mode for rapid development iteration
- Verbose logging for debugging

### 🔍 Validation

- Full JSON Schema validation for templates
- Type extension schema validation
- Variable reference validation (including undefined variables)
- Circular dependency detection
- Semantic validation during template parsing

### ⚡ Performance

- Efficient schema caching
- Lazy loading of remote schemas
- Optimised variable resolution
- Minimal memory footprint

## Variables and Conditionals

### Variable Support

The compiler supports comprehensive variable substitution:

```json
{
  "variables": {
    "product": {
      "name": "SmartWatch Pro",
      "price": 299
    },
    "features": ["heart rate", "GPS", "waterproof"],
    "showSpecs": true
  },
  "content": [
    { "type": "text", "text": "# ${product.name}\n\n" },
    { "type": "text", "text": "Price: $${product.price}\n\n" },
    { "type": "text", "text": "Features: ${features}\n\n" },
    { "type": "text", "text": "Feature count: ${features.length}\n\n" }
  ]
}
```

**Supported variable types:**

- Simple values: `${productName}`
- Object properties: `${product.name}`, `${product.price}`
- Array elements: `${features[0]}`, `${features[1]}`
- Array as comma-separated list: `${features}`
- Array length: `${features.length}`

### Conditional Logic

Support for Python-style conditional expressions:

```json
{
  "type": "conditional",
  "condition": "audience == \"technical\" and showAdvanced == True",
  "content": [{ "type": "text", "text": "Technical content here" }],
  "else": [{ "type": "text", "text": "General audience content" }]
}
```

**Supported operators:**

- Comparison: `==`, `!=`, `<`, `<=`, `>`, `>=`
- Boolean: `and`, `or`, `not`
- Membership: `in`, `not in`
- String literals: `"quoted strings"`
- Boolean literals: `True`, `False`
- Numeric comparisons: `price > 100`

## Example

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
      "condition": "includeExamples == True",
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

## Testing

The compiler includes a comprehensive test suite covering both success and error cases:

### Running Tests

```bash
# Run all tests
python test_runner.py

# Run specific test categories
python test_runner.py --test "Variables"
python test_runner.py --test "Conditionals"
python test_runner.py --test "Invalid"

# Run with verbose output
python test_runner.py --verbose

# Stop on first failure
python test_runner.py --stop-on-failure

# Generate JUnit XML for CI
python test_runner.py --junit-xml test-results.xml
```

### Test Coverage

**✅ Happy Path Tests (15 tests):**

- Basic templates (text-only, single/multiple placeholders)
- Variable substitution (default and custom variables)
- Complex variables (objects, arrays, properties)
- Conditional logic (simple and complex scenarios)
- Custom instruction types
- Array usage and `.length` properties
- Template validation

**✅ Error Path Tests (9 tests):**

- Invalid JSON syntax
- Missing required fields
- Undefined variable references
- Unknown instruction types
- Invalid conditional expressions
- Missing placeholder configuration
- Empty content arrays

All 24 tests pass, ensuring robust error handling and comprehensive feature coverage.

### Example Test Commands

```bash
# Test variable substitution
its-compile test/templates/04-simple-variables.json
its-compile test/templates/04-simple-variables.json --variables test/variables/custom-variables.json

# Test conditional logic
its-compile test/templates/06-simple-conditionals.json
its-compile test/templates/06-simple-conditionals.json --variables test/variables/conditional-test-variables.json

# Test error handling
its-compile test/templates/invalid/03-undefined-variables.json --validate-only
```

## Configuration

### Environment Variables

```bash
# Schema caching
export ITS_CACHE_DIR="~/.cache/its-compiler"
export ITS_CACHE_TTL=3600

# Network settings
export ITS_REQUEST_TIMEOUT=30
export ITS_MAX_RETRIES=3

# Security settings
export ITS_ALLOW_HTTP=false
export ITS_DOMAIN_ALLOWLIST="alexanderparker.github.io,your-domain.com"
```

### Configuration File

Create `.its-config.json` in your project root:

```json
{
  "schemaCache": {
    "enabled": true,
    "directory": "~/.cache/its-compiler",
    "ttl": 3600
  },
  "security": {
    "allowHttp": false,
    "domainAllowlist": ["alexanderparker.github.io"],
    "maxSchemaSize": "10MB"
  },
  "compiler": {
    "strictMode": true,
    "reportOverrides": true,
    "validateVariables": true
  }
}
```

## CLI Reference

```
its-compile [OPTIONS] TEMPLATE_FILE

Options:
  -o, --output FILE          Output file (default: stdout)
  -v, --variables FILE       JSON file with variable values
  -w, --watch               Watch template file for changes
  --validate-only           Validate template without compiling
  --verbose                 Show detailed output including overrides
  --strict                  Enable strict validation mode
  --no-cache               Disable schema caching
  --timeout INTEGER        Network timeout in seconds (default: 30)
  --help                   Show this message and exit
```

## API Reference

### ITSCompiler Class

```python
class ITSCompiler:
    def __init__(self, config: Optional[ITSConfig] = None)

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

## Error Handling

The compiler provides detailed error messages for common issues:

### Schema Validation Errors

```
ITSValidationError: Template validation failed at content[2].config:
  - Missing required property 'description'
  - Invalid instruction type 'unknown_type' (available: list, paragraph, table, ...)
```

### Variable Resolution Errors

```
ITSVariableError: Undefined variable reference at content[1].config.description:
  - Variable '${productName}' is not defined
  - Available variables: productType, featureCount, includeSpecs
```

### Schema Loading Errors

```
ITSSchemaError: Failed to load schema 'https://example.com/types.json':
  - HTTP 404: Schema not found
  - Consider checking the URL or network connectivity
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`python test_runner.py`)
6. Run linting (`black . && flake8`)
7. Commit your changes (`git commit -m 'Add amazing feature'`)
8. Push to the branch (`git push origin feature/amazing-feature`)
9. Open a Pull Request

### Development Setup

```bash
# Clone and setup
git clone https://github.com/alexanderparker/its-compiler-python.git
cd its-compiler-python

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install

# Run tests
python test_runner.py
```

## Related Projects

- **[Instruction Template Specification](https://github.com/alexanderparker/instruction-template-specification)** - The official ITS specification and schema
- **[ITS Documentation](https://alexanderparker.github.io/instruction-template-specification/)** - Complete specification documentation and examples

## Project Structure

This project uses modern Python packaging standards:

- **`pyproject.toml`** - Project configuration, dependencies, and tool settings
- **`its-compile`** - Command-line tool (automatically available after installation)
- **Development mode** - Use `pip install -e ".[dev]"` to install with live code changes
- **Virtual environment** - Recommended to isolate project dependencies

### Quick Setup for Contributors

```bash
# Clone and setup
git clone https://github.com/alexanderparker/its-compiler-python.git
cd its-compiler-python

# Create and activate virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # macOS/Linux

# Install in development mode with all dev tools
pip install -e ".[dev]"

# Verify installation
its-compile --help
```

**The `-e` flag** installs in "editable" mode, meaning changes to the source code are immediately available without reinstalling.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and release notes.

---

Built with ❤️ for the AI content generation community
