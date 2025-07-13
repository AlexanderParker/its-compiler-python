#!/usr/bin/env python3
"""
Integration test runner for ITS Compiler with security test support.
Runs a suite of test templates to validate compiler functionality and security.
"""

import argparse
import html
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class TestCase:
    """Represents a single test case."""

    name: str
    file_url: str
    description: str
    should_pass: bool = True
    expected_errors: Optional[List[str]] = None
    test_validation_only: bool = False
    variables_url: Optional[str] = None
    test_category: str = "integration"
    extra_args: Optional[List[str]] = None


@dataclass
class TestResult:
    """Represents the result of running a test case."""

    test_case: TestCase
    passed: bool
    output: str
    error_output: str
    execution_time: float
    exit_code: int


class TestRunner:
    """Runs integration and security tests for the ITS compiler."""

    def __init__(self, compiler_command: str = "its-compile", verbose: bool = False):
        self.compiler_command = compiler_command
        self.verbose = verbose
        self.results: List[TestResult] = []
        self.temp_dir = Path(tempfile.mkdtemp(prefix="its_tests_"))
        self.base_url = self._get_test_base_url()

    def _strip_ansi_codes(self, text: str) -> str:
        """Remove ANSI escape sequences from text."""
        ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
        return ansi_escape.sub("", text)

    def _get_test_base_url(self) -> str:
        """Get the base URL for test templates based on compiler's supported schema version."""
        schema_version = self.get_compiler_schema_version()
        if not schema_version:
            print(f"❌ Error: Could not determine supported schema version from compiler '{self.compiler_command}'")
            print("This could mean:")
            print("  - The compiler doesn't support --supported-schema-version flag")
            print("  - The compiler is too old")
            print("  - The compiler command is incorrect")
            print("\n💡 Try:")
            print("  - Update to latest compiler version: pip install --upgrade its-compiler-python")
            print("  - Check compiler command: --compiler /path/to/its-compile")
            raise SystemExit(1)

        # Schema versions are always two digits like "1.0", "1.1", etc.
        # Just prefix with 'v' for the URL path
        return f"https://raw.githubusercontent.com/AlexanderParker/its-example-templates/main/v{schema_version}"

    def check_compiler_available(self) -> bool:
        """Check if the compiler command is available."""
        try:
            result = subprocess.run([self.compiler_command, "--help"], capture_output=True, timeout=10, check=False)
            return result.returncode == 0
        except FileNotFoundError:
            return False
        except subprocess.TimeoutExpired:
            # If it times out but responds, it's probably available
            return True
        except Exception:
            return False

    def get_compiler_schema_version(self) -> Optional[str]:
        """Get the supported schema version from the compiler."""
        try:
            result = subprocess.run(
                [self.compiler_command, "--supported-schema-version"],
                capture_output=True,
                timeout=10,
                text=True,
                check=False,
            )
            if result.returncode == 0:
                # Strip ANSI codes first, then parse output to extract version
                clean_output = self._strip_ansi_codes(result.stdout.strip())
                lines = clean_output.split("\n")
                for line in lines:
                    if "Supported ITS Specification Version:" in line:
                        version = line.split(":")[-1].strip()
                        # Additional cleanup to ensure we only get the version number
                        version = re.sub(r"[^\d\.]", "", version)
                        return version
            return None
        except Exception:
            return None

    def download_file(self, url: str, description: str = "file") -> Optional[Path]:
        """Download a file from URL to temporary directory."""
        try:
            if self.verbose:
                print(f"Downloading {description} from {url}")

            response = urllib.request.urlopen(url, timeout=30)
            content = response.read()

            # Create a filename from the URL
            filename = url.split("/")[-1]
            file_path = self.temp_dir / filename

            # Ensure directory exists
            file_path.parent.mkdir(parents=True, exist_ok=True)

            with open(file_path, "wb") as f:
                f.write(content)

            if self.verbose:
                print(f"Downloaded {description} to {file_path}")

            return file_path

        except urllib.error.HTTPError as e:
            print(f"HTTP error downloading {description}: {e.code} {e.reason}")
            return None
        except urllib.error.URLError as e:
            print(f"URL error downloading {description}: {e.reason}")
            return None
        except Exception as e:
            print(f"Error downloading {description}: {e}")
            return None

    def get_test_cases(self) -> List[TestCase]:
        """Define all test cases including security tests."""
        base = self.base_url

        return [
            # Integration Tests
            TestCase(
                name="Text Only",
                file_url=f"{base}/templates/01-text-only.json",
                description="Basic template with no placeholders",
                test_category="integration",
            ),
            TestCase(
                name="Single Placeholder",
                file_url=f"{base}/templates/02-single-placeholder.json",
                description="Single placeholder with schema loading",
                test_category="integration",
            ),
            TestCase(
                name="Multiple Placeholders",
                file_url=f"{base}/templates/03-multiple-placeholders.json",
                description="Multiple instruction types",
                test_category="integration",
            ),
            TestCase(
                name="Simple Variables (Default)",
                file_url=f"{base}/templates/04-simple-variables.json",
                description="Variable substitution using template defaults",
                test_category="integration",
            ),
            TestCase(
                name="Simple Variables (Custom)",
                file_url=f"{base}/templates/04-simple-variables.json",
                description="Variable substitution with custom variables file",
                variables_url=f"{base}/variables/custom-variables.json",
                test_category="integration",
            ),
            TestCase(
                name="Complex Variables (Default)",
                file_url=f"{base}/templates/05-complex-variables.json",
                description="Object properties and array access with defaults",
                test_category="integration",
            ),
            TestCase(
                name="Complex Variables (Custom)",
                file_url=f"{base}/templates/05-complex-variables.json",
                description="Object properties and array access with custom variables",
                variables_url=f"{base}/variables/custom-variables.json",
                test_category="integration",
            ),
            TestCase(
                name="Simple Conditionals (Default)",
                file_url=f"{base}/templates/06-simple-conditionals.json",
                description="Basic conditional logic with default variables",
                test_category="integration",
            ),
            TestCase(
                name="Simple Conditionals (Inverted)",
                file_url=f"{base}/templates/06-simple-conditionals.json",
                description="Conditional logic with opposite boolean values",
                variables_url=f"{base}/variables/conditional-test-variables.json",
                test_category="integration",
            ),
            TestCase(
                name="Simple Conditionals (All False)",
                file_url=f"{base}/templates/06-simple-conditionals.json",
                description="Conditional logic with all conditions false",
                variables_url=f"{base}/variables/conditional-minimal-variables.json",
                test_category="integration",
            ),
            TestCase(
                name="Complex Conditionals (Default)",
                file_url=f"{base}/templates/07-complex-conditionals.json",
                description="Complex conditional expressions with default variables",
                test_category="integration",
            ),
            TestCase(
                name="Complex Conditionals (Beginner)",
                file_url=f"{base}/templates/07-complex-conditionals.json",
                description="Complex conditionals for beginner audience with lower price",
                variables_url=f"{base}/variables/complex-conditional-variables.json",
                test_category="integration",
            ),
            TestCase(
                name="Comprehensive Conditional Operators",
                file_url=f"{base}/templates/10-comprehensive-conditionals.json",
                description="Test all conditional operators: unary, binary, in/not in, chained comparisons",
                test_category="integration",
            ),
            TestCase(
                name="Custom Types",
                file_url=f"{base}/templates/08-custom-types.json",
                description="Custom instruction type definitions",
                test_category="integration",
            ),
            TestCase(
                name="Array Usage (Default)",
                file_url=f"{base}/templates/09-array-usage.json",
                description="Using full arrays and array properties in templates",
                test_category="integration",
            ),
            TestCase(
                name="Array Usage (Custom)",
                file_url=f"{base}/templates/09-array-usage.json",
                description="Using full arrays with custom variable values",
                variables_url=f"{base}/variables/custom-variables.json",
                test_category="integration",
            ),
            # Validation-only tests
            TestCase(
                name="Validate Text Only",
                file_url=f"{base}/templates/01-text-only.json",
                description="Validation of basic template",
                test_validation_only=True,
                test_category="validation",
            ),
            TestCase(
                name="Validate Custom Types",
                file_url=f"{base}/templates/08-custom-types.json",
                description="Validation of custom instruction types",
                test_validation_only=True,
                test_category="validation",
            ),
            # Error case tests - these should fail
            TestCase(
                name="Invalid JSON",
                file_url=f"{base}/templates/invalid/01-invalid-json.json",
                description="Template with invalid JSON syntax",
                should_pass=False,
                expected_errors=["Invalid JSON"],
                test_category="error-handling",
            ),
            TestCase(
                name="Missing Required Fields",
                file_url=f"{base}/templates/invalid/02-missing-required-fields.json",
                description="Template missing required version and content fields",
                should_pass=False,
                expected_errors=["Missing required field"],
                test_validation_only=True,
                test_category="error-handling",
            ),
            TestCase(
                name="Undefined Variables",
                file_url=f"{base}/templates/invalid/03-undefined-variables.json",
                description="Template with undefined variable references",
                should_pass=False,
                expected_errors=["Undefined variable reference"],
                test_validation_only=True,
                test_category="error-handling",
            ),
            TestCase(
                name="Unknown Instruction Type",
                file_url=f"{base}/templates/invalid/04-unknown-instruction-type.json",
                description="Template with non-existent instruction type",
                should_pass=False,
                expected_errors=["Unknown instruction type"],
                test_category="error-handling",
            ),
            TestCase(
                name="Invalid Conditional Syntax",
                file_url=f"{base}/templates/invalid/05-invalid-conditional.json",
                description="Template with invalid conditional expression",
                should_pass=False,
                expected_errors=["Security validation failed", "Syntax error"],
                test_category="error-handling",
            ),
            TestCase(
                name="Missing Placeholder Config",
                file_url=f"{base}/templates/invalid/06-missing-placeholder-config.json",
                description="Placeholder missing required description config",
                should_pass=False,
                expected_errors=["missing required field", "description"],
                test_validation_only=True,
                test_category="error-handling",
            ),
            TestCase(
                name="Empty Content Array",
                file_url=f"{base}/templates/invalid/07-empty-content.json",
                description="Template with empty content array",
                should_pass=False,
                expected_errors=["Content array cannot be empty"],
                test_validation_only=True,
                test_category="error-handling",
            ),
            # Security Tests - Malicious content that should be blocked
            TestCase(
                name="Security: Malicious Injection Attempts",
                file_url=f"{base}/templates/security/malicious_injection.json",
                description="Template with various XSS and injection attempts",
                should_pass=False,
                expected_errors=[
                    "Security",
                    "validation failed",
                    "Malicious content",
                    "Input validation",
                ],
                test_validation_only=True,
                test_category="security",
                extra_args=["--strict"],
            ),
            TestCase(
                name="Security: Dangerous Expression Injection",
                file_url=f"{base}/templates/security/malicious_expressions.json",
                description="Conditional expressions with code injection attempts",
                should_pass=False,
                expected_errors=["Malicious content detected", "condition", "Security"],
                test_category="security",
                extra_args=["--strict"],
            ),
            TestCase(
                name="Security: Malicious Variable Content",
                file_url=f"{base}/templates/security/malicious_variables.json",
                description="Variables with prototype pollution and XSS attempts",
                should_pass=False,
                expected_errors=["Security", "Variable", "validation", "Malicious"],
                test_category="security",
                extra_args=["--strict"],
            ),
            TestCase(
                name="Security: SSRF Schema Attempts",
                file_url=f"{base}/templates/security/malicious_schema.json",
                description="Schema URLs attempting SSRF and file access",
                should_pass=False,
                expected_errors=[
                    "Too many extensions",
                    "Input validation failed",
                    "Security",
                ],
                test_validation_only=True,
                test_category="security",
                extra_args=["--strict"],
            ),
            # Security Tests with Different Settings
            TestCase(
                name="Security: Basic Template with Strict Mode",
                file_url=f"{base}/templates/01-text-only.json",
                description="Basic template should pass even with strict validation",
                should_pass=True,
                test_category="security",
                extra_args=["--strict"],
            ),
            TestCase(
                name="Security: HTTP Blocking Test",
                file_url=f"{base}/templates/01-text-only.json",
                description="Basic template should pass with HTTP blocking enabled",
                should_pass=True,
                test_category="security",
                extra_args=["--no-interactive-allowlist"],
            ),
        ]

    def _safe_text_for_xml(self, text: str) -> str:
        """Safely escape text for XML, handling Unicode and control characters."""
        if not text:
            return ""

        # Remove control characters that are not allowed in XML
        # XML 1.0 allows: #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]
        import re

        # Remove control characters except tab, newline, and carriage return
        text = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", text)

        # Escape HTML/XML entities
        text = html.escape(text, quote=True)

        # Truncate very long text to prevent XML bloat
        if len(text) > 10000:
            text = text[:10000] + "... [TRUNCATED]"

        return text

    def run_test(self, test_case: TestCase) -> TestResult:
        """Run a single test case."""
        print(f"\n{'='*60}")
        print(f"Running: {test_case.name}")
        print(f"Category: {test_case.test_category}")
        print(f"Template URL: {test_case.file_url}")
        print(f"Description: {test_case.description}")
        if test_case.variables_url:
            print(f"Variables URL: {test_case.variables_url}")
        if test_case.extra_args:
            print(f"Extra Args: {' '.join(test_case.extra_args)}")
        print(f"{'='*60}")

        # Download template file
        template_file = self.download_file(test_case.file_url, "template")
        if not template_file:
            return TestResult(
                test_case=test_case,
                passed=False,
                output="",
                error_output=f"Failed to download template from: {test_case.file_url}",
                execution_time=0.0,
                exit_code=-1,
            )

        # Download variables file if specified
        variables_file = None
        if test_case.variables_url:
            variables_file = self.download_file(test_case.variables_url, "variables")
            if not variables_file:
                return TestResult(
                    test_case=test_case,
                    passed=False,
                    output="",
                    error_output=f"Failed to download variables from: {test_case.variables_url}",
                    execution_time=0.0,
                    exit_code=-1,
                )

        # Build command
        cmd = [self.compiler_command, str(template_file)]
        if test_case.test_validation_only:
            cmd.append("--validate-only")
        if variables_file:
            cmd.extend(["--variables", str(variables_file)])
        if test_case.extra_args:
            cmd.extend(test_case.extra_args)
        if self.verbose:
            cmd.append("--verbose")

        if self.verbose:
            print(f"Running command: {' '.join(cmd)}")

        # Run the command
        start_time = time.time()
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                encoding="utf-8",
                errors="replace",
            )
            execution_time = time.time() - start_time

            # Determine if test passed
            passed = result.returncode == 0 if test_case.should_pass else result.returncode != 0

            # Check for expected errors if specified
            if test_case.expected_errors and not test_case.should_pass:
                output_text = (result.stderr + result.stdout).lower()
                # For tests with multiple expected errors, we only need to find ONE of them
                found_expected_error = any(
                    expected_error.lower() in output_text for expected_error in test_case.expected_errors
                )
                if not found_expected_error:
                    print(f"Expected errors not found. Looking for any of: {test_case.expected_errors}")
                    print(f"Got output: {result.stderr + result.stdout}")
                passed = passed and found_expected_error

            print(f"Exit code: {result.returncode}")
            print(f"Execution time: {execution_time:.2f}s")
            print(f"Status: {'✅ PASS' if passed else '❌ FAIL'}")

            if self.verbose or not passed:
                if result.stdout:
                    print(f"\nSTDOUT:\n{result.stdout}")
                if result.stderr:
                    print(f"\nSTDERR:\n{result.stderr}")

            return TestResult(
                test_case=test_case,
                passed=passed,
                output=result.stdout,
                error_output=result.stderr,
                execution_time=execution_time,
                exit_code=result.returncode,
            )

        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            print("❌ FAIL - Test timed out after 30 seconds")
            return TestResult(
                test_case=test_case,
                passed=False,
                output="",
                error_output="Test timed out after 30 seconds",
                execution_time=execution_time,
                exit_code=-2,
            )
        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = f"❌ FAIL - Exception: {e}"
            print(error_msg)

            # Add more helpful error info
            if "cannot find the file specified" in str(e).lower() or "no such file" in str(e).lower():
                print(f"💡 Hint: Command '{self.compiler_command}' not found. Try:")
                print("  - Install: pip install its-compiler-python")
                print("  - Use full path: --compiler /path/to/its-compile")
                print("  - Use python module: --compiler 'python -m its_compiler.cli'")

            return TestResult(
                test_case=test_case,
                passed=False,
                output="",
                error_output=f"Exception: {e}",
                execution_time=execution_time,
                exit_code=-3,
            )

    def run_tests_by_category(self, category: str, stop_on_failure: bool = False) -> bool:
        """Run tests filtered by category."""
        test_cases = [tc for tc in self.get_test_cases() if tc.test_category == category]

        if not test_cases:
            print(f"No tests found for category: {category}")
            return True

        print(f"Running {len(test_cases)} tests in category: {category}")

        for test_case in test_cases:
            result = self.run_test(test_case)
            self.results.append(result)

            if not result.passed and stop_on_failure:
                print(f"\n🛑 Stopping on first failure: {test_case.name}")
                break

        return all(r.passed for r in self.results if r.test_case.test_category == category)

    def run_all_tests(self, stop_on_failure: bool = False, category_filter: Optional[str] = None) -> bool:
        """Run all test cases or filter by category."""
        # Check if compiler is available first
        if not self.check_compiler_available():
            print(f"❌ Compiler '{self.compiler_command}' is not available or not working properly.")
            print("\n💡 Try one of these solutions:")
            print("  1. Install the compiler: pip install its-compiler-python")
            print("  2. Use full path: --compiler /path/to/its-compile")
            print("  3. Use Python module: --compiler 'python -m its_compiler.cli'")
            print("  4. Check your PATH environment variable")
            return False

        # Get and display compiler schema version
        schema_version = self.get_compiler_schema_version()
        if schema_version:
            print(f"✅ Compiler '{self.compiler_command}' supports ITS schema version: {schema_version}")
        else:
            print("⚠️ Warning: Could not determine compiler schema version")

        test_cases = self.get_test_cases()

        if category_filter:
            test_cases = [tc for tc in test_cases if tc.test_category == category_filter]
            if not test_cases:
                print(f"No tests found for category: {category_filter}")
                return True

        print(f"✅ Compiler '{self.compiler_command}' is available")
        print(f"Running {len(test_cases)} tests...")
        if category_filter:
            print(f"Category filter: {category_filter}")
        print(f"Compiler command: {self.compiler_command}")
        print(f"Test repository: {self.base_url}")
        if schema_version:
            print(f"Using test templates for schema version: {schema_version}")

        for test_case in test_cases:
            result = self.run_test(test_case)
            self.results.append(result)

            if not result.passed and stop_on_failure:
                print(f"\n🛑 Stopping on first failure: {test_case.name}")
                break

        return self.print_summary(category_filter)

    def print_summary(self, category_filter: Optional[str] = None) -> bool:
        """Print test summary and return overall success."""
        print(f"\n{'='*60}")
        print("TEST SUMMARY")
        print(f"{'='*60}")

        # Filter results if category specified
        results = self.results
        if category_filter:
            results = [r for r in self.results if r.test_case.test_category == category_filter]

        passed_tests = [r for r in results if r.passed]
        failed_tests = [r for r in results if not r.passed]

        print(f"Total tests: {len(results)}")
        print(f"Passed: {len(passed_tests)}")
        print(f"Failed: {len(failed_tests)}")

        # Group by category for detailed breakdown
        categories = {}
        for result in results:
            cat = result.test_case.test_category
            if cat not in categories:
                categories[cat] = {"passed": 0, "failed": 0, "total": 0}
            categories[cat]["total"] += 1
            if result.passed:
                categories[cat]["passed"] += 1
            else:
                categories[cat]["failed"] += 1

        if len(categories) > 1:
            print("\nBreakdown by category:")
            for cat, stats in categories.items():
                print(f"  {cat}: {stats['passed']}/{stats['total']} passed")

        if failed_tests:
            print("\n❌ FAILED TESTS:")
            for result in failed_tests:
                print(f"  - {result.test_case.name} ({result.test_case.test_category}): {result.error_output[:100]}...")

        if passed_tests:
            print("\n✅ PASSED TESTS:")
            for result in passed_tests:
                print(f"  - {result.test_case.name} ({result.test_case.test_category}) ({result.execution_time:.2f}s)")

        total_time = sum(r.execution_time for r in results)
        print(f"\nTotal execution time: {total_time:.2f}s")

        success = len(failed_tests) == 0
        print(f"\nOverall result: {'✅ SUCCESS' if success else '❌ FAILURE'}")

        return success

    def generate_junit_xml(self, output_file: str) -> None:
        """Generate JUnit XML for CI systems with proper escaping."""
        try:
            from xml.etree.ElementTree import Element, ElementTree, SubElement
        except ImportError:
            print("Warning: Cannot generate JUnit XML (xml module not available)")
            return

        testsuites = Element("testsuites")

        # Group by category
        categories: Dict[str, List[TestResult]] = {}
        for result in self.results:
            cat = result.test_case.test_category
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(result)

        for category, results in categories.items():
            testsuite = SubElement(testsuites, "testsuite")
            testsuite.set("name", f"ITS Compiler {category.title()} Tests")
            testsuite.set("tests", str(len(results)))
            testsuite.set("failures", str(len([r for r in results if not r.passed])))
            testsuite.set("time", str(sum(r.execution_time for r in results)))

            for result in results:
                testcase = SubElement(testsuite, "testcase")
                # Use safe text for all XML content
                testcase.set("name", self._safe_text_for_xml(result.test_case.name))
                testcase.set("classname", f"ITSCompiler{category.title()}Tests")
                testcase.set("time", str(result.execution_time))

                if not result.passed:
                    failure = SubElement(testcase, "failure")
                    failure.set("message", "Test failed")
                    failure.text = self._safe_text_for_xml(result.error_output)

                if result.output:
                    stdout = SubElement(testcase, "system-out")
                    stdout.text = self._safe_text_for_xml(result.output)

                if result.error_output:
                    stderr = SubElement(testcase, "system-err")
                    stderr.text = self._safe_text_for_xml(result.error_output)

        # Write the XML file
        tree = ElementTree(testsuites)
        tree.write(output_file, encoding="utf-8", xml_declaration=True)
        print(f"JUnit XML report written to: {output_file}")

    def list_categories(self) -> None:
        """List available test categories."""
        test_cases = self.get_test_cases()
        categories = {}

        for tc in test_cases:
            cat = tc.test_category
            if cat not in categories:
                categories[cat] = 0
            categories[cat] += 1

        print("Available test categories:")
        for cat, count in sorted(categories.items()):
            print(f"  {cat}: {count} tests")

    def cleanup(self) -> None:
        """Clean up temporary files."""
        try:
            import shutil

            if self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
                if self.verbose:
                    print(f"Cleaned up temporary directory: {self.temp_dir}")
        except Exception as e:
            if self.verbose:
                print(f"Warning: Failed to clean up temporary directory: {e}")


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Run ITS Compiler integration and security tests")
    parser.add_argument(
        "--compiler",
        default="its-compile",
        help="Compiler command to test (default: its-compile)",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--stop-on-failure", action="store_true", help="Stop on first test failure")
    parser.add_argument("--junit-xml", help="Generate JUnit XML report to specified file")
    parser.add_argument("--test", help="Run specific test by name")
    parser.add_argument(
        "--category",
        choices=[
            "integration",
            "security",
            "validation",
            "error-handling",
            "performance",
        ],
        help="Run tests from specific category",
    )
    parser.add_argument("--list-categories", action="store_true", help="List available test categories")
    parser.add_argument("--security-only", action="store_true", help="Run only security tests")

    args = parser.parse_args()

    runner = TestRunner(compiler_command=args.compiler, verbose=args.verbose)

    try:
        if args.list_categories:
            runner.list_categories()
            return 0

        if args.security_only:
            args.category = "security"

        if args.test:
            # Check compiler for specific tests too
            if not runner.check_compiler_available():
                print(f"❌ Compiler '{args.compiler}' is not available or not working properly.")
                print("\n💡 Try one of these solutions:")
                print("  1. Install the compiler: pip install its-compiler-python")
                print("  2. Use full path: --compiler /path/to/its-compile")
                print("  3. Use Python module: --compiler 'python -m its_compiler.cli'")
                return 1

            # Run specific test
            test_cases = runner.get_test_cases()
            matching_tests = [tc for tc in test_cases if args.test.lower() in tc.name.lower()]

            if not matching_tests:
                print(f"No tests found matching: {args.test}")
                print("Available tests:")
                for tc in test_cases:
                    print(f"  - {tc.name} ({tc.test_category})")
                return 1

            print(f"✅ Compiler '{args.compiler}' is available")
            for test_case in matching_tests:
                result = runner.run_test(test_case)
                runner.results.append(result)

            success = runner.print_summary()
        elif args.category:
            # Run tests from specific category
            success = runner.run_all_tests(stop_on_failure=args.stop_on_failure, category_filter=args.category)
        else:
            # Run all tests
            success = runner.run_all_tests(stop_on_failure=args.stop_on_failure)

        if args.junit_xml:
            runner.generate_junit_xml(args.junit_xml)

        return 0 if success else 1

    finally:
        # Always clean up temporary files
        runner.cleanup()


if __name__ == "__main__":
    exit(main())
