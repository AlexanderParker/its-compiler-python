#!/usr/bin/env python3
"""
Integration test runner for ITS Compiler.
Runs a suite of test templates to validate compiler functionality.
"""

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
import argparse


@dataclass
class TestCase:
    """Represents a single test case."""

    name: str
    file_path: str
    description: str
    should_pass: bool = True
    expected_errors: Optional[List[str]] = None
    test_validation_only: bool = False


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
    """Runs integration tests for the ITS compiler."""

    def __init__(self, compiler_command: str = "its-compile", verbose: bool = False):
        self.compiler_command = compiler_command
        self.verbose = verbose
        self.results: List[TestResult] = []

    def get_test_cases(self) -> List[TestCase]:
        """Define all test cases."""
        return [
            TestCase(
                name="Text Only",
                file_path="test/templates/01-text-only.json",
                description="Basic template with no placeholders",
            ),
            TestCase(
                name="Single Placeholder",
                file_path="test/templates/02-single-placeholder.json",
                description="Single placeholder with schema loading",
            ),
            TestCase(
                name="Multiple Placeholders",
                file_path="test/templates/03-multiple-placeholders.json",
                description="Multiple instruction types",
            ),
            TestCase(
                name="Simple Variables",
                file_path="test/templates/04-simple-variables.json",
                description="Variable substitution with ${variable} syntax",
            ),
            TestCase(
                name="Complex Variables",
                file_path="test/templates/05-complex-variables.json",
                description="Object properties and array access",
            ),
            TestCase(
                name="Simple Conditionals",
                file_path="test/templates/06-simple-conditionals.json",
                description="Basic conditional logic",
            ),
            TestCase(
                name="Complex Conditionals",
                file_path="test/templates/07-complex-conditionals.json",
                description="Complex conditional expressions",
            ),
            TestCase(
                name="Custom Types",
                file_path="test/templates/08-custom-types.json",
                description="Custom instruction type definitions",
            ),
            # Validation-only tests
            TestCase(
                name="Validate Text Only",
                file_path="test/templates/01-text-only.json",
                description="Validation of basic template",
                test_validation_only=True,
            ),
            TestCase(
                name="Validate Custom Types",
                file_path="test/templates/08-custom-types.json",
                description="Validation of custom instruction types",
                test_validation_only=True,
            ),
        ]

    def run_test(self, test_case: TestCase) -> TestResult:
        """Run a single test case."""
        print(f"\n{'='*60}")
        print(f"Running: {test_case.name}")
        print(f"File: {test_case.file_path}")
        print(f"Description: {test_case.description}")
        print(f"{'='*60}")

        # Check if file exists
        if not Path(test_case.file_path).exists():
            return TestResult(
                test_case=test_case,
                passed=False,
                output="",
                error_output=f"Test file not found: {test_case.file_path}",
                execution_time=0.0,
                exit_code=-1,
            )

        # Build command
        cmd = [self.compiler_command, test_case.file_path]
        if test_case.test_validation_only:
            cmd.append("--validate-only")
        if self.verbose:
            cmd.append("--verbose")

        # Run the command
        start_time = time.time()
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30  # 30 second timeout
            )
            execution_time = time.time() - start_time

            # Determine if test passed
            passed = (
                result.returncode == 0
                if test_case.should_pass
                else result.returncode != 0
            )

            # Check for expected errors if specified
            if test_case.expected_errors and not test_case.should_pass:
                found_expected_error = any(
                    error in result.stderr for error in test_case.expected_errors
                )
                passed = passed and found_expected_error

            print(f"Exit code: {result.returncode}")
            print(f"Execution time: {execution_time:.2f}s")
            print(f"Status: {'✓ PASS' if passed else '✗ FAIL'}")

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
            print(f"✗ FAIL - Test timed out after 30 seconds")
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
            print(f"✗ FAIL - Exception: {e}")
            return TestResult(
                test_case=test_case,
                passed=False,
                output="",
                error_output=f"Exception: {e}",
                execution_time=execution_time,
                exit_code=-3,
            )

    def run_all_tests(self, stop_on_failure: bool = False) -> bool:
        """Run all test cases."""
        test_cases = self.get_test_cases()

        print(f"Running {len(test_cases)} integration tests...")
        print(f"Compiler command: {self.compiler_command}")

        for test_case in test_cases:
            result = self.run_test(test_case)
            self.results.append(result)

            if not result.passed and stop_on_failure:
                print(f"\n💥 Stopping on first failure: {test_case.name}")
                break

        return self.print_summary()

    def print_summary(self) -> bool:
        """Print test summary and return overall success."""
        print(f"\n{'='*60}")
        print("TEST SUMMARY")
        print(f"{'='*60}")

        passed_tests = [r for r in self.results if r.passed]
        failed_tests = [r for r in self.results if not r.passed]

        print(f"Total tests: {len(self.results)}")
        print(f"Passed: {len(passed_tests)}")
        print(f"Failed: {len(failed_tests)}")

        if failed_tests:
            print(f"\n❌ FAILED TESTS:")
            for result in failed_tests:
                print(f"  - {result.test_case.name}: {result.error_output[:100]}...")

        if passed_tests:
            print(f"\n✅ PASSED TESTS:")
            for result in passed_tests:
                print(f"  - {result.test_case.name} ({result.execution_time:.2f}s)")

        total_time = sum(r.execution_time for r in self.results)
        print(f"\nTotal execution time: {total_time:.2f}s")

        success = len(failed_tests) == 0
        print(f"\nOverall result: {'✅ SUCCESS' if success else '❌ FAILURE'}")

        return success

    def generate_junit_xml(self, output_file: str):
        """Generate JUnit XML for CI systems."""
        try:
            from xml.etree.ElementTree import Element, SubElement, tostring
            from xml.dom import minidom
        except ImportError:
            print("Warning: Cannot generate JUnit XML (xml module not available)")
            return

        testsuites = Element("testsuites")
        testsuite = SubElement(testsuites, "testsuite")
        testsuite.set("name", "ITS Compiler Integration Tests")
        testsuite.set("tests", str(len(self.results)))
        testsuite.set("failures", str(len([r for r in self.results if not r.passed])))
        testsuite.set("time", str(sum(r.execution_time for r in self.results)))

        for result in self.results:
            testcase = SubElement(testsuite, "testcase")
            testcase.set("name", result.test_case.name)
            testcase.set("classname", "ITSCompilerTests")
            testcase.set("time", str(result.execution_time))

            if not result.passed:
                failure = SubElement(testcase, "failure")
                failure.set("message", "Test failed")
                failure.text = result.error_output

            if result.output:
                stdout = SubElement(testcase, "system-out")
                stdout.text = result.output

            if result.error_output:
                stderr = SubElement(testcase, "system-err")
                stderr.text = result.error_output

        # Pretty print XML
        rough_string = tostring(testsuites, "unicode")
        reparsed = minidom.parseString(rough_string)
        pretty_xml = reparsed.toprettyxml(indent="  ")

        with open(output_file, "w") as f:
            f.write(pretty_xml)

        print(f"JUnit XML report written to: {output_file}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Run ITS Compiler integration tests")
    parser.add_argument(
        "--compiler",
        default="its-compile",
        help="Compiler command to test (default: its-compile)",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument(
        "--stop-on-failure", action="store_true", help="Stop on first test failure"
    )
    parser.add_argument(
        "--junit-xml", help="Generate JUnit XML report to specified file"
    )
    parser.add_argument("--test", help="Run specific test by name")

    args = parser.parse_args()

    runner = TestRunner(compiler_command=args.compiler, verbose=args.verbose)

    if args.test:
        # Run specific test
        test_cases = runner.get_test_cases()
        matching_tests = [
            tc for tc in test_cases if args.test.lower() in tc.name.lower()
        ]

        if not matching_tests:
            print(f"No tests found matching: {args.test}")
            print("Available tests:")
            for tc in test_cases:
                print(f"  - {tc.name}")
            return 1

        for test_case in matching_tests:
            result = runner.run_test(test_case)
            runner.results.append(result)

        success = runner.print_summary()
    else:
        # Run all tests
        success = runner.run_all_tests(stop_on_failure=args.stop_on_failure)

    if args.junit_xml:
        runner.generate_junit_xml(args.junit_xml)

    return 0 if success else 1


if __name__ == "__main__":
    exit(main())
