"""
Command-line interface for ITS Compiler with comprehensive security enhancements.
Fixed for cross-platform Unicode compatibility.
"""

import json
import platform
import sys
import time
from pathlib import Path as PathType
from typing import Any, Dict, Optional, Tuple

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from . import __supported_schema_version__, __version__
from .compiler import ITSCompiler
from .exceptions import ITSCompilationError, ITSError, ITSSecurityError, ITSValidationError
from .models import ITSConfig
from .security import AllowlistManager, SecurityConfig, TrustLevel


def setup_safe_console() -> Tuple[Console, bool]:
    """Setup console with Windows compatibility."""
    is_windows = platform.system() == "Windows"
    console = Console(
        force_terminal=True,
        legacy_windows=is_windows,
        safe_box=is_windows,
        color_system="auto",
    )
    return console, not is_windows


def safe_print(message: Any, style: Optional[str] = None, highlight: Optional[bool] = None) -> None:
    """Print message safely, handling Unicode encoding errors."""
    try:
        console.print(message, style=style, highlight=highlight)
    except Exception:
        # Fallback to plain print with safe message
        safe_message = str(message)
        for old, new in [
            ("✓", "[OK]"),
            ("✗", "[FAIL]"),
            ("⚠", "[WARN]"),
            ("ℹ", "[INFO]"),
            ("•", "*"),
        ]:
            safe_message = safe_message.replace(old, new)
        print(safe_message)


def create_safe_progress_context(description: str, disable_on_windows: bool = True) -> Any:
    """Create a progress context that's safe for Windows."""
    if platform.system() == "Windows" and disable_on_windows:
        # On Windows, use a simple context manager that just prints status
        class SimpleProgress:
            def __init__(self, description: str):
                self.description = description
                self.started = False

            def __enter__(self) -> "SimpleProgress":
                safe_print(f"[blue]{self.description}[/blue]")
                self.started = True
                return self

            def __exit__(self, *args: Any) -> None:
                if self.started:
                    safe_print("[green]Complete[/green]")

            def add_task(self, description: str, total: Optional[int] = None) -> int:
                return 0  # Dummy task ID

            def update(self, task_id: int, **kwargs: Any) -> None:
                pass  # No-op

        return SimpleProgress(description)
    else:
        # On non-Windows or when Unicode is supported, use Rich Progress
        try:
            return Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                disable=False,
            )
        except Exception:
            # Fallback to simple progress if Rich fails
            return create_safe_progress_context(description, disable_on_windows=True)


# Initialize console
try:
    console, CAN_USE_UNICODE = setup_safe_console()
except Exception:
    # Emergency fallback
    console = Console(force_terminal=True, legacy_windows=True)
    CAN_USE_UNICODE = False


def get_symbols() -> Dict[str, str]:
    """Get safe symbols for status messages."""
    symbols = {
        "ok": ("✓", "[OK]"),
        "fail": ("✗", "[FAIL]"),
        "warn": ("⚠", "[WARN]"),
        "info": ("ℹ", "[INFO]"),
        "bullet": ("•", "*"),
    }
    return {k: v[0] if CAN_USE_UNICODE else v[1] for k, v in symbols.items()}


SYMBOLS = get_symbols()


class TemplateChangeHandler(FileSystemEventHandler):
    """Handler for template file changes in watch mode."""

    def __init__(
        self,
        template_path: str,
        output_path: Optional[str],
        variables_path: Optional[str],
        verbose: bool,
        security_config: SecurityConfig,
    ):
        self.template_path = PathType(template_path)
        self.output_path = output_path
        self.variables_path = variables_path
        self.verbose = verbose
        self.security_config = security_config

    def on_modified(self, event: Any) -> None:
        if event.is_directory:
            return

        changed_path = PathType(event.src_path)
        if changed_path.name == self.template_path.name:
            safe_print(f"[yellow]File changed: {changed_path}[/yellow]")
            try:
                success = compile_template(
                    str(self.template_path),
                    self.output_path,
                    self.variables_path,
                    False,  # validate_only
                    self.verbose,
                    False,  # watch
                    False,  # no_cache
                    self.security_config,
                    None,  # security_report
                    watch_mode=True,  # Pass watch_mode=True
                )

                if success:
                    safe_print(f"[green]{SYMBOLS['ok']} Watch compilation successful[/green]")
                else:
                    safe_print(f"[blue]{SYMBOLS['info']} Waiting for fixes... (Ctrl+C to stop)[/blue]")
            except (
                ITSSecurityError,
                ITSValidationError,
                ITSCompilationError,
                ITSError,
            ) as e:
                # Handle ITS-specific errors gracefully in watch mode
                safe_print(f"[red]{SYMBOLS['fail']} Compilation failed: {e}[/red]")
                if self.verbose:
                    if hasattr(e, "details") and e.details:
                        safe_print(f"[red]Details: {e.details}[/red]")
                    if hasattr(e, "path") and e.path:
                        safe_print(f"[red]Path: {e.path}[/red]")
                safe_print(f"[blue]{SYMBOLS['info']} Continuing to watch for changes...[/blue]")
            except Exception as e:
                # Handle any other unexpected errors
                safe_print(f"[red]{SYMBOLS['fail']} Unexpected error: {e}[/red]")
                if self.verbose:
                    import traceback

                    safe_print("[red]Error details:[/red]")
                    for line in traceback.format_exc().splitlines():
                        safe_print(f"[red]  {line}[/red]")
                safe_print(f"[blue]{SYMBOLS['info']} Continuing to watch for changes...[/blue]")


def load_variables(variables_path: str) -> Dict[str, Any]:
    """Load variables from JSON file with security validation."""
    try:
        variables_file = PathType(variables_path)

        # Basic security checks on variables file
        if variables_file.stat().st_size > 10 * 1024 * 1024:  # 10MB limit
            safe_print(f"[red]Variables file too large: {variables_path}[/red]")
            sys.exit(1)

        with open(variables_path, "r", encoding="utf-8") as f:
            variables = json.load(f)

        if not isinstance(variables, dict):
            safe_print("[red]Variables file must contain a JSON object[/red]")
            sys.exit(1)

        return variables

    except FileNotFoundError:
        raise click.ClickException(f"Variables file not found: {variables_path}")
    except json.JSONDecodeError as e:
        raise click.ClickException(f"Invalid JSON in variables file: {e}")
    except PermissionError:
        raise click.ClickException(f"Permission denied accessing variables file: {variables_path}")


def create_security_config(
    allow_http: bool,
    interactive_allowlist: Optional[bool],
    strict_mode: bool,
) -> SecurityConfig:
    """Create security configuration from CLI options."""

    # Start with environment-based config
    config = SecurityConfig.from_environment()

    # Override with CLI options
    if allow_http:
        config.network.allowed_protocols.add("http")
        config.network.allow_http = True

    if interactive_allowlist is not None:
        config.allowlist.interactive_mode = interactive_allowlist

    if strict_mode:
        config.processing.max_template_size = 512 * 1024  # 512KB
        config.network.max_response_size = 5 * 1024 * 1024  # 5MB
        config.processing.max_content_elements = 500
        config.processing.max_nesting_depth = 8

    return config


def handle_allowlist_commands(
    security_config: SecurityConfig,
    add_trusted_schema: Optional[str],
    remove_schema: Optional[str],
    export_allowlist: Optional[PathType],
    import_allowlist: Optional[PathType],
    merge_allowlist: bool,
    cleanup_allowlist: bool,
    older_than: int,
    allowlist_status: bool,
) -> bool:
    """Handle allowlist management commands. Returns True if a command was executed."""

    if not any(
        [
            add_trusted_schema,
            remove_schema,
            export_allowlist,
            import_allowlist,
            cleanup_allowlist,
            allowlist_status,
        ]
    ):
        return False

    try:
        allowlist_manager = AllowlistManager(security_config)

        if allowlist_status:
            stats = allowlist_manager.get_stats()

            # Use safe table creation
            try:
                table = Table(title="Schema Allowlist Status", show_header=True)
                table.add_column("Metric", style="cyan")
                table.add_column("Value", style="green")

                for key, value in stats.items():
                    if key != "most_used":
                        table.add_row(key.replace("_", " ").title(), str(value))

                console.print(table)
            except Exception:
                safe_print("Schema Allowlist Status:")
                for key, value in stats.items():
                    if key != "most_used":
                        safe_print(f"  {key.replace('_', ' ').title()}: {value}")

            if stats.get("most_used"):
                safe_print("\nMost Used Schemas:")
                for schema in stats["most_used"]:
                    safe_print(f"  {SYMBOLS['bullet']} {schema['url']} (used {schema['use_count']} times)")

        if add_trusted_schema:
            allowlist_manager.add_trusted_url(add_trusted_schema, TrustLevel.PERMANENT, "Added via CLI")
            safe_print(f"[green]{SYMBOLS['ok']} Added trusted schema: {add_trusted_schema}[/green]")

        if remove_schema:
            if allowlist_manager.remove_url(remove_schema):
                safe_print(f"[green]{SYMBOLS['ok']} Removed schema: {remove_schema}[/green]")
            else:
                safe_print(f"[yellow]Schema not found in allowlist: {remove_schema}[/yellow]")

        if export_allowlist:
            allowlist_manager.export_allowlist(export_allowlist)
            safe_print(f"[green]{SYMBOLS['ok']} Exported allowlist to: {export_allowlist}[/green]")

        if import_allowlist:
            imported_count = allowlist_manager.import_allowlist(import_allowlist, merge=merge_allowlist)
            mode = "merged" if merge_allowlist else "imported"
            safe_print(
                f"[green]{SYMBOLS['ok']} {mode.title()} {imported_count} entries from: {import_allowlist}[/green]"
            )

        if cleanup_allowlist:
            removed_count = allowlist_manager.cleanup_old_entries(days=older_than)
            safe_print(
                f"[green]{SYMBOLS['ok']} Cleaned up {removed_count} old entries (older than {older_than} days)[/green]"
            )

        return True

    except Exception as e:
        safe_print(f"[red]Error managing allowlist: {e}[/red]")
        sys.exit(1)


def compile_template(
    template_path: str,
    output_path: Optional[str],
    variables_path: Optional[str],
    validate_only: bool,
    verbose: bool,
    watch: bool,
    no_cache: bool,
    security_config: SecurityConfig,
    security_report_path: Optional[str],
    watch_mode: bool = False,
) -> bool:
    """Compile a template file with security controls."""

    # Load variables if provided
    variables: Dict[str, Any] = {}
    if variables_path:
        try:
            variables = load_variables(variables_path)
            if verbose:
                safe_print(f"[blue]Loaded {len(variables)} variables from {variables_path}[/blue]")
        except Exception as e:
            error_msg = f"Failed to load variables: {e}"
            safe_print(f"[red]{error_msg}[/red]")
            if not watch_mode:
                sys.exit(1)
            return False

    # Configure compiler
    config = ITSConfig(cache_enabled=not no_cache, report_overrides=verbose)

    try:
        compiler = ITSCompiler(config, security_config)

        # Show security status if verbose
        if verbose:
            security_status = compiler.get_security_status()
            safe_print("[blue]Security Configuration:[/blue]")
            safe_print(f"  HTTP allowed: {security_config.network.allow_http}")
            safe_print(f"  Interactive allowlist: {security_config.allowlist.interactive_mode}")
            safe_print(f"  Block localhost: {security_config.network.block_localhost}")

            enabled_features = [k for k, v in security_status["features"].items() if v]
            if enabled_features:
                safe_print(f"[blue]Security Features: {', '.join(enabled_features)}[/blue]")

        start_time = time.time()

        if validate_only:
            # Validation only
            with create_safe_progress_context("Validating template...") as progress:
                task = progress.add_task("Validating template...", total=None)
                validation_result = compiler.validate_file(template_path)
                progress.update(task, completed=True)

            if validation_result.is_valid:
                safe_print(f"[green]{SYMBOLS['ok']} Template is valid[/green]")
                if validation_result.warnings and verbose:
                    for warning in validation_result.warnings:
                        safe_print(f"[yellow]{SYMBOLS['warn']} Warning: {warning}[/yellow]")
                if validation_result.security_issues and verbose:
                    for issue in validation_result.security_issues:
                        safe_print(f"[orange]{SYMBOLS['warn']} Security: {issue}[/orange]")
                return True
            else:
                safe_print(f"[red]{SYMBOLS['fail']} Template validation failed[/red]")
                for error in validation_result.errors:
                    safe_print(f"[red]Error: {error}[/red]")
                for issue in validation_result.security_issues:
                    safe_print(f"[red]Security: {issue}[/red]")
                if not watch_mode:
                    sys.exit(1)
                return False
        else:
            # Full compilation
            with create_safe_progress_context("Compiling template...") as progress:
                task = progress.add_task("Compiling template...", total=None)
                compilation_result = compiler.compile_file(template_path, variables)
                progress.update(task, completed=True)

            # Show compilation success
            compilation_time = time.time() - start_time
            safe_print(f"[green]{SYMBOLS['ok']} Template compiled successfully ({compilation_time:.2f}s)[/green]")

            # Show security metrics, overrides, warnings, etc.
            if verbose:
                if compilation_result.overrides:
                    safe_print("[yellow]Type Overrides:[/yellow]")
                    for type_override in compilation_result.overrides:
                        safe_print(
                            (
                                f"  {type_override.type_name}: "
                                f"{type_override.override_source} -> "
                                f"{type_override.overridden_source}"
                            )
                        )

                if compilation_result.warnings:
                    safe_print("[yellow]Warnings:[/yellow]")
                    for warning in compilation_result.warnings:
                        safe_print(f"  {warning}")

            # Output result
            if output_path:
                output_file = PathType(output_path)

                # Security check on output path
                if not _is_safe_output_path(output_file):
                    error_msg = f"Unsafe output path: {output_path}"
                    safe_print(f"[red]{error_msg}[/red]")
                    if not watch_mode:
                        sys.exit(1)
                    return False

                try:
                    output_file.parent.mkdir(parents=True, exist_ok=True)
                    with open(output_file, "w", encoding="utf-8") as f:
                        f.write(compilation_result.prompt)
                    safe_print(f"[blue]Output written to: {output_path}[/blue]")
                except PermissionError:
                    error_msg = f"Permission denied writing to: {output_path}"
                    safe_print(f"[red]{error_msg}[/red]")
                    if not watch_mode:
                        sys.exit(1)
                    return False
            else:
                safe_print("\n" + "=" * 80)
                safe_print(compilation_result.prompt)
                safe_print("=" * 80)

        # Generate security report if requested
        if security_report_path and hasattr(compiler, "generate_security_report"):
            try:
                report = compiler.generate_security_report(template_path)
                with open(security_report_path, "w", encoding="utf-8") as f:
                    json.dump(report.to_dict(), f, indent=2)
                safe_print(f"[blue]Security report written to: {security_report_path}[/blue]")
            except Exception as e:
                safe_print(f"[yellow]Failed to generate security report: {e}[/yellow]")

        return True

    except ITSSecurityError as e:
        safe_print(f"[red]Security Error: {e.get_user_message()}[/red]")
        if verbose and e.threat_type:
            safe_print(f"[red]Threat Type: {e.threat_type}[/red]")
        if not watch_mode:
            sys.exit(1)
        return False

    except ITSValidationError as e:
        safe_print(f"[red]Validation Error: {e.message}[/red]")
        if e.path:
            safe_print(f"[red]Path: {e.path}[/red]")
        for error in e.validation_errors:
            safe_print(f"[red]  {SYMBOLS['bullet']} {error}[/red]")
        for issue in e.security_issues:
            safe_print(f"[red]  {SYMBOLS['bullet']} Security: {issue}[/red]")
        if not watch_mode:
            sys.exit(1)
        return False

    except ITSCompilationError as e:
        safe_print(f"[red]Compilation Error: {e.get_context_message()}[/red]")
        if not watch_mode:
            sys.exit(1)
        return False

    except ITSError as e:
        safe_print(f"[red]ITS Error: {e.get_user_message()}[/red]")
        if verbose:
            safe_print(f"[red]Details: {e.details}[/red]")
        if not watch_mode:
            sys.exit(1)
        return False

    except Exception as e:
        safe_print(f"[red]Unexpected error: {e}[/red]")
        if verbose:
            import traceback

            traceback.print_exc()
        if not watch_mode:
            sys.exit(1)
        return False


def _is_safe_output_path(output_path: PathType) -> bool:
    """Check if output path is safe to write to."""
    try:
        # Resolve to absolute path
        resolved = output_path.resolve()

        # Check for dangerous patterns
        dangerous_patterns = ["..", "%", "<", ">", "|", ":", '"', "?", "*"]
        if any(pattern in str(resolved) for pattern in dangerous_patterns):
            return False

        # Check if trying to write to system directories
        system_dirs = {
            "/etc",
            "/bin",
            "/sbin",
            "/usr/bin",
            "/usr/sbin",
            "C:\\Windows",
            "C:\\System32",
        }
        for sys_dir in system_dirs:
            if str(resolved).startswith(sys_dir):
                return False

        return True
    except Exception:
        return False


@click.command()
@click.argument("template_file", type=click.Path(exists=True), required=False)
@click.option(
    "-o",
    "--output",
    type=click.Path(),
    help="Output file (default: stdout)",
)
@click.option(
    "-v",
    "--variables",
    type=click.Path(exists=True),
    help="JSON file with variable values",
)
@click.option("-w", "--watch", is_flag=True, help="Watch template file for changes")
@click.option("--validate-only", is_flag=True, help="Validate template without compiling")
@click.option("--verbose", is_flag=True, help="Show detailed output including security metrics")
@click.option("--strict", is_flag=True, help="Enable strict validation mode")
@click.option("--no-cache", is_flag=True, help="Disable schema caching")
@click.option("--timeout", type=int, default=30, help="Network timeout in seconds")
@click.option(
    "--allow-http",
    is_flag=True,
    help="Allow HTTP URLs (not recommended for production)",
)
@click.option(
    "--interactive-allowlist/--no-interactive-allowlist",
    default=None,
    help="Enable/disable interactive schema allowlist prompts",
)
@click.option(
    "--security-report",
    type=click.Path(),
    help="Generate security analysis report to specified file",
)
@click.option(
    "--supported-schema-version",
    is_flag=True,
    help="Show the supported ITS specification version and exit",
)
# Allowlist management options
@click.option("--allowlist-status", is_flag=True, help="Show allowlist status and exit")
@click.option(
    "--add-trusted-schema",
    type=str,
    help="Add a schema URL to the permanent allowlist and exit",
)
@click.option("--remove-schema", type=str, help="Remove a schema URL from the allowlist and exit")
@click.option(
    "--export-allowlist",
    type=click.Path(),
    help="Export allowlist to specified file and exit",
)
@click.option(
    "--import-allowlist",
    type=click.Path(exists=True),
    help="Import allowlist from specified file and exit",
)
@click.option(
    "--merge-allowlist",
    is_flag=True,
    help="Merge imported allowlist with existing (use with --import-allowlist)",
)
@click.option(
    "--cleanup-allowlist",
    is_flag=True,
    help="Remove old unused allowlist entries and exit",
)
@click.option(
    "--older-than",
    type=int,
    default=90,
    help="Days threshold for cleanup (default: 90)",
)
@click.version_option(version=__version__)
def main(
    template_file: Optional[PathType],
    output: Optional[PathType],
    variables: Optional[PathType],
    watch: bool,
    validate_only: bool,
    verbose: bool,
    strict: bool,
    no_cache: bool,
    timeout: int,
    allow_http: bool,
    interactive_allowlist: Optional[bool],
    security_report: Optional[PathType],
    supported_schema_version: bool,
    allowlist_status: bool,
    add_trusted_schema: Optional[str],
    remove_schema: Optional[str],
    export_allowlist: Optional[PathType],
    import_allowlist: Optional[PathType],
    merge_allowlist: bool,
    cleanup_allowlist: bool,
    older_than: int,
) -> None:
    """
    ITS Compiler Python - Convert ITS templates to AI prompts with security controls.

    TEMPLATE_FILE: Path to the ITS template JSON file to compile (required for compilation).
    """

    # Handle --supported-schema-version flag
    if supported_schema_version:
        safe_print(f"ITS Compiler Python v{__version__}")
        safe_print(f"Supported ITS Specification Version: {__supported_schema_version__}")
        return

    # Create security configuration
    security_config = create_security_config(allow_http, interactive_allowlist, strict)

    # Validate security configuration
    config_warnings = security_config.validate()
    if config_warnings and verbose:
        for warning in config_warnings:
            safe_print(f"[yellow]{SYMBOLS['warn']} Config Warning: {warning}[/yellow]")

    # Handle allowlist management commands
    if handle_allowlist_commands(
        security_config,
        add_trusted_schema,
        remove_schema,
        export_allowlist,
        import_allowlist,
        merge_allowlist,
        cleanup_allowlist,
        older_than,
        allowlist_status,
    ):
        return  # Exit after handling allowlist commands

    # Template file is required for compilation/validation
    if not template_file:
        safe_print("[red]Error: Template file is required for compilation[/red]")
        safe_print("Use --help for available commands or provide a template file.")
        sys.exit(1)

    if watch and validate_only:
        raise click.ClickException("Cannot use --watch with --validate-only")

    # Initial compilation
    compile_template(
        str(template_file),
        str(output) if output else None,
        str(variables) if variables else None,
        validate_only,
        verbose,
        watch,
        no_cache,
        security_config,
        str(security_report) if security_report else None,
    )

    # Watch mode
    if watch:
        safe_print(f"\n[blue]Watching {template_file} for changes... (Press Ctrl+C to stop)[/blue]")

        event_handler = TemplateChangeHandler(
            str(template_file),
            str(output) if output else None,
            str(variables) if variables else None,
            verbose,
            security_config,
        )

        observer = Observer()
        observer.schedule(event_handler, str(template_file.parent), recursive=False)
        observer.start()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            safe_print(f"\n[yellow]{SYMBOLS['warn']} Stopping watch mode...[/yellow]")
            observer.stop()
        observer.join()


@click.command()
@click.option(
    "--export-config",
    type=click.Path(),
    help="Export security configuration to file",
)
def validate_security_config(
    export_config: Optional[PathType],
) -> None:
    """Validate security configuration and settings."""

    try:
        security_config = SecurityConfig.from_environment()

        # Validate configuration
        warnings = security_config.validate()

        if warnings:
            safe_print(f"[yellow]{SYMBOLS['warn']} Configuration Warnings:[/yellow]")
            for warning in warnings:
                safe_print(f"  {SYMBOLS['bullet']} {warning}")
        else:
            safe_print(f"[green]{SYMBOLS['ok']} Security configuration is valid[/green]")

        # Show configuration summary
        try:
            table = Table(title="Security Configuration", show_header=True)
            table.add_column("Setting", style="cyan")
            table.add_column("Value", style="green")

            table.add_row("HTTP Allowed", str(security_config.network.allow_http))
            table.add_row("Allowlist Enabled", str(security_config.enable_allowlist))
            table.add_row("Input Validation", str(security_config.enable_input_validation))
            table.add_row(
                "Expression Sanitisation",
                str(security_config.enable_expression_sanitisation),
            )
            table.add_row("Interactive Allowlist", str(security_config.allowlist.interactive_mode))
            table.add_row("Block Localhost", str(security_config.network.block_localhost))
            table.add_row(
                "Max Template Size",
                f"{security_config.processing.max_template_size // 1024} KB",
            )
            table.add_row("Request Timeout", f"{security_config.network.request_timeout}s")

            console.print(table)
        except Exception:
            safe_print("Security Configuration:")
            safe_print(f"  HTTP Allowed: {security_config.network.allow_http}")
            safe_print(f"  Allowlist Enabled: {security_config.enable_allowlist}")
            safe_print(f"  Input Validation: {security_config.enable_input_validation}")
            safe_print(f"  Expression Sanitisation: {security_config.enable_expression_sanitisation}")
            safe_print(f"  Interactive Allowlist: {security_config.allowlist.interactive_mode}")
            safe_print(f"  Block Localhost: {security_config.network.block_localhost}")
            safe_print(f"  Max Template Size: {security_config.processing.max_template_size // 1024} KB")
            safe_print(f"  Request Timeout: {security_config.network.request_timeout}s")

        # Export configuration if requested
        if export_config:
            config_dict = {
                "features": {
                    "allowlist": security_config.enable_allowlist,
                    "input_validation": security_config.enable_input_validation,
                    "expression_sanitisation": security_config.enable_expression_sanitisation,
                },
                "network": {
                    "allow_http": security_config.network.allow_http,
                    "request_timeout": security_config.network.request_timeout,
                    "max_response_size": security_config.network.max_response_size,
                },
                "processing": {
                    "max_template_size": security_config.processing.max_template_size,
                    "max_expression_length": security_config.processing.max_expression_length,
                    "max_nesting_depth": security_config.processing.max_nesting_depth,
                },
            }

            with open(export_config, "w") as f:
                json.dump(config_dict, f, indent=2)

            safe_print(f"[green]{SYMBOLS['ok']} Configuration exported to: {export_config}[/green]")

    except Exception as e:
        safe_print(f"[red]Error validating security configuration: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
