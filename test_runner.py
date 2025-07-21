#!/usr/bin/env python3
"""
Core library test runner for ITS Compiler.
Runs unit tests and security tests for the core library components.
"""

import argparse
import subprocess
import sys
from typing import Optional


def run_core_tests(verbose: bool = False, category: Optional[str] = None) -> bool:
    """Run core library tests using pytest."""

    # Construct pytest command
    cmd = ["pytest"]

    if verbose:
        cmd.append("-v")

    if category and category != "all":
        if category == "security":
            cmd.append("test/security/")
        elif category == "unit":
            cmd.extend(["test/", "-k", "not security"])
        else:
            print(f"Unknown test category: {category}")
            return False
    else:
        cmd.append("test/")

    # Add coverage reporting
    cmd.extend(["--cov=its_compiler", "--cov-report=term-missing", "--cov-report=html", "--cov-report=xml"])

    print(f"Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, check=False)
        return result.returncode == 0
    except FileNotFoundError:
        print("Error: pytest not found. Install with: pip install pytest pytest-cov")
        return False
    except Exception as e:
        print(f"Error running tests: {e}")
        return False


def run_security_tests_only(verbose: bool = False) -> bool:
    """Run only security tests."""
    return run_core_tests(verbose=verbose, category="security")


def run_linting() -> bool:
    """Run code quality checks."""
    checks = [
        (["black", "--check", "."], "Black formatting"),
        (["flake8", "its_compiler/", "test/"], "Flake8 linting"),
        (["mypy", "its_compiler/", "--ignore-missing-imports"], "MyPy type checking"),
        (["isort", "--check-only", "--profile", "black", "."], "Import sorting"),
    ]

    all_passed = True

    for cmd, description in checks:
        print(f"\nRunning {description}...")
        try:
            result = subprocess.run(cmd, check=False, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"✓ {description} passed")
            else:
                print(f"✗ {description} failed")
                if result.stdout:
                    print(result.stdout)
                if result.stderr:
                    print(result.stderr)
                all_passed = False
        except FileNotFoundError:
            print(f"✗ {description} - tool not found")
            all_passed = False

    return all_passed


def run_security_scan() -> bool:
    """Run security scanning with bandit and pip-audit."""
    import os
    import shutil

    all_passed = True

    # Run bandit for code security scanning
    print("Running code security scan with bandit...")
    bandit_cmd = shutil.which("bandit")
    if bandit_cmd:
        try:
            cmd = [bandit_cmd, "-r", "its_compiler/", "-f", "txt"]
            result = subprocess.run(cmd, check=False)
            if result.returncode == 0:
                print("✓ Bandit scan passed")
            else:
                print("✗ Bandit scan found issues")
                all_passed = False
        except Exception as e:
            print(f"Error running bandit: {e}")
            all_passed = False
    else:
        # Try running as a module
        try:
            cmd = [sys.executable, "-m", "bandit", "-r", "its_compiler/", "-f", "txt"]
            result = subprocess.run(cmd, check=False)
            if result.returncode == 0:
                print("✓ Bandit scan passed")
            else:
                print("✗ Bandit scan found issues")
                all_passed = False
        except Exception as e:
            print(f"Warning: bandit not found. Error: {e}")
            print("Install with: pip install bandit")

    # Run pip-audit for dependency vulnerability scanning
    print("\nRunning dependency security scan with pip-audit...")

    # Set up environment to use the current Python interpreter
    env = os.environ.copy()
    env["PIPAPI_PYTHON_LOCATION"] = sys.executable
    print(f"Using Python interpreter: {sys.executable}")

    pip_audit_cmd = shutil.which("pip-audit")
    if pip_audit_cmd:
        try:
            cmd = [pip_audit_cmd]
            result = subprocess.run(cmd, check=False, env=env)
            if result.returncode == 0:
                print("✓ pip-audit scan passed")
            else:
                print("✗ pip-audit scan found vulnerabilities")
                all_passed = False
        except Exception as e:
            print(f"Error running pip-audit: {e}")
            all_passed = False
    else:
        # Try running as a module
        try:
            cmd = [sys.executable, "-m", "pip_audit"]
            result = subprocess.run(cmd, check=False, env=env)
            if result.returncode == 0:
                print("✓ pip-audit scan passed")
            else:
                print("✗ pip-audit scan found vulnerabilities")
                all_passed = False
        except Exception as e:
            print(f"Warning: pip-audit not found. Error: {e}")
            print("Add pip-audit to your dev dependencies in pyproject.toml")

    return all_passed


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Run ITS Compiler core library tests")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--category", choices=["security", "unit", "all"], default="all", help="Test category to run")
    parser.add_argument("--security-only", action="store_true", help="Run only security tests")
    parser.add_argument("--lint", action="store_true", help="Run linting checks")
    parser.add_argument("--security-scan", action="store_true", help="Run security scan")
    parser.add_argument("--all", action="store_true", help="Run all tests and checks")

    args = parser.parse_args()

    success = True

    if args.all:
        print("Running all tests and checks...")
        success &= run_core_tests(verbose=args.verbose)
        success &= run_linting()
        success &= run_security_scan()
    elif args.security_only:
        success = run_security_tests_only(verbose=args.verbose)
    elif args.lint:
        success = run_linting()
    elif args.security_scan:
        success = run_security_scan()
    else:
        success = run_core_tests(verbose=args.verbose, category=args.category)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
