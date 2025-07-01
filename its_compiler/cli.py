"""
Command-line interface for ITS Compiler with comprehensive security enhancements.
Fixed for cross-platform Unicode compatibility.
"""

import json
import sys
import time
import uuid
import os
import platform
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from .compiler import ITSCompiler
from .models import ITSConfig
from .exceptions import (
    ITSError,
    ITSValidationError,
    ITSCompilationError,
    ITSSecurityError,
)
from .security import SecurityConfig, AllowlistManager, TrustLevel


def setup_safe_console():
    """Setup console that handles Windows encoding issues gracefully."""

    # Always use legacy mode on Windows to avoid Unicode issues
    if platform.system() == "Windows":
        # Force legacy mode and safe settings for Windows
        console = Console(
            force_terminal=True,
            legacy_windows=True,
            width=None,
            color_system="auto",
            safe_box=True,
            file=sys.stdout,
        )
        use_unicode = False
    else:
        # Non-Windows systems usually handle Unicode fine
        console = Console(
            force_terminal=True, legacy_windows=False, width=None, color_system="auto"
        )
        use_unicode = True

    return console, use_unicode


def safe_print(message, style=None, highlight=None):
    """Print message safely, handling Unicode encoding errors."""
    try:
        if style:
            console.print(message, style=style, highlight=highlight)
        else:
            console.print(message, highlight=highlight)
    except UnicodeEncodeError:
        # Remove Unicode characters and try again
        safe_message = str(message)
        safe_message = safe_message.replace("✓", "[OK]").replace("❌", "[FAIL]")
        safe_message = safe_message.replace("✗", "[FAIL]").replace("⚠", "[WARN]")
        safe_message = safe_message.replace("ℹ", "[INFO]").replace("•", "*")
        safe_message = safe_message.replace("→", "->").replace("▶", ">")

        try:
            if style:
                console.print(safe_message, style=style, highlight=highlight)
            else:
                console.print(safe_message, highlight=highlight)
        except:
            # Ultimate fallback
            print(safe_message)
    except Exception:
        # Final fallback for any other errors
        print(str(message))


def create_safe_progress_context(description: str, disable_on_windows: bool = True):
    """Create a progress context that's safe for Windows."""
    if platform.system() == "Windows" and disable_on_windows:
        # On Windows, use a simple context manager that just prints status
        class SimpleProgress:
            def __init__(self, description):
                self.description = description
                self.started = False

            def __enter__(self):
                safe_print(f"[blue]{self.description}[/blue]")
                self.started = True
                return self

            def __exit__(self, *args):
                if self.started:
                    safe_print("[green]Complete[/green]")

            def add_task(self, description, total=None):
                return 0  # Dummy task ID

            def update(self, task_id, **kwargs):
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


def get_symbols():
    """Get safe symbols for status messages."""
    if CAN_USE_UNICODE:
        return {"ok": "✓", "fail": "✗", "warn": "⚠", "info": "ℹ", "bullet": "•"}
    else:
        return {
            "ok": "[OK]",
            "fail": "[FAIL]",
            "warn": "[WARN]",
            "info": "[INFO]",
            "bullet": "*",
        }


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
        self.template_path = Path(template_path)
        self.output_path = output_path
        self.variables_path = variables_path
        self.verbose = verbose
        self.security_config = security_config

    def on_modified(self, event):
        if event.is_directory:
            return

        changed_path = Path(event.src_path)
        if changed_path.name == self.template_path.name:
            safe_print(f"[yellow]File changed: {changed_path}[/yellow]")
            compile_template(
                str(self.template_path),
                self.output_path,
                self.variables_path,
                False,  # validate_only
                self.verbose,
                False,  # watch
                False,  # no_cache
                self.security_config,
                None,  # security_report
            )


def load_variables(variables_path: str) -> dict:
    """Load variables from JSON file with security validation."""
    try:
        variables_file = Path(variables_path)

        # Basic security checks on variables file
        if variables_file.stat().st_size > 10 * 1024 * 1024:  # 10MB limit
            safe_print(f"[red]Variables file too large: {variables_path}[/red]")
            sys.exit(1)

        with open(variables_path, "r", encoding="utf-8") as f:
            variables = json.load(f)

        if not isinstance(variables, dict):
            safe_print(f"[red]Variables file must contain a JSON object[/red]")
            sys.exit(1)

        return variables

    except FileNotFoundError:
        raise click.ClickException(f"Variables file not found: {variables_path}")
    except json.JSONDecodeError as e:
        raise click.ClickException(f"Invalid JSON in variables file: {e}")
    except PermissionError:
        raise click.ClickException(
            f"Permission denied accessing variables file: {variables_path}"
        )


def create_security_config(
    allow_http: bool,
    interactive_allowlist: bool,
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
    export_allowlist: Optional[Path],
    import_allowlist: Optional[Path],
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
            except (UnicodeEncodeError, Exception):
                safe_print("Schema Allowlist Status:")
                for key, value in stats.items():
                    if key != "most_used":
                        safe_print(f"  {key.replace('_', ' ').title()}: {value}")

            if stats.get("most_used"):
                safe_print("\nMost Used Schemas:")
                for schema in stats["most_used"]:
                    safe_print(
                        f"  {SYMBOLS['bullet']} {schema['url']} (used {schema['use_count']} times)"
                    )

        if add_trusted_schema:
            allowlist_manager.add_trusted_url(
                add_trusted_schema, TrustLevel.PERMANENT, "Added via CLI"
            )
            safe_print(
                f"[green]{SYMBOLS['ok']} Added trusted schema: {add_trusted_schema}[/green]"
            )

        if remove_schema:
            if allowlist_manager.remove_url(remove_schema):
                safe_print(
                    f"[green]{SYMBOLS['ok']} Removed schema: {remove_schema}[/green]"
                )
            else:
                safe_print(
                    f"[yellow]Schema not found in allowlist: {remove_schema}[/yellow]"
                )

        if export_allowlist:
            allowlist_manager.export_allowlist(export_allowlist)
            safe_print(
                f"[green]{SYMBOLS['ok']} Exported allowlist to: {export_allowlist}[/green]"
            )

        if import_allowlist:
            imported_count = allowlist_manager.import_allowlist(
                import_allowlist, merge=merge_allowlist
            )
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
) -> None:
    """Compile a template file with security controls."""

    # Generate unique operation ID for tracking
    operation_id = str(uuid.uuid4())[:8]

    # Load variables if provided
    variables = {}
    if variables_path:
        variables = load_variables(variables_path)
        if verbose:
            safe_print(
                f"[blue]Loaded {len(variables)} variables from {variables_path}[/blue]"
            )

    # Configure compiler
    config = ITSConfig(cache_enabled=not no_cache, report_overrides=verbose)

    try:
        compiler = ITSCompiler(config, security_config)

        # Show security status if verbose
        if verbose:
            security_status = compiler.get_security_status()
            safe_print(f"[blue]Security Configuration:[/blue]")
            safe_print(f"  HTTP allowed: {security_config.network.allow_http}")
            safe_print(
                f"  Interactive allowlist: {security_config.allowlist.interactive_mode}"
            )
            safe_print(f"  Block localhost: {security_config.network.block_localhost}")

            enabled_features = [k for k, v in security_status["features"].items() if v]
            if enabled_features:
                safe_print(
                    f"[blue]Security Features: {', '.join(enabled_features)}[/blue]"
                )

        start_time = time.time()

        if validate_only:
            # Validation only
            with create_safe_progress_context("Validating template...") as progress:
                task = progress.add_task("Validating template...", total=None)
                result = compiler.validate_file(template_path)
                progress.update(task, completed=True)

            if result.is_valid:
                safe_print(f"[green]{SYMBOLS['ok']} Template is valid[/green]")
                if result.warnings and verbose:
                    for warning in result.warnings:
                        safe_print(
                            f"[yellow]{SYMBOLS['warn']} Warning: {warning}[/yellow]"
                        )
                if result.security_issues and verbose:
                    for issue in result.security_issues:
                        safe_print(
                            f"[orange]{SYMBOLS['warn']} Security: {issue}[/orange]"
                        )
            else:
                safe_print(f"[red]{SYMBOLS['fail']} Template validation failed[/red]")
                for error in result.errors:
                    safe_print(f"[red]Error: {error}[/red]")
                for issue in result.security_issues:
                    safe_print(f"[red]Security: {issue}[/red]")
                sys.exit(1)
        else:
            # Full compilation
            with create_safe_progress_context("Compiling template...") as progress:
                task = progress.add_task("Compiling template...", total=None)
                result = compiler.compile_file(template_path, variables)
                progress.update(task, completed=True)

            # Show compilation success
            compilation_time = time.time() - start_time
            safe_print(
                f"[green]{SYMBOLS['ok']} Template compiled successfully ({compilation_time:.2f}s)[/green]"
            )

            # Show security metrics if verbose
            if verbose and hasattr(result, "security_metrics"):
                metrics = result.security_metrics
                if any(metrics.to_dict().values()):
                    try:
                        table = Table(title="Security Metrics", show_header=True)
                        table.add_column("Metric", style="cyan")
                        table.add_column("Count", style="green")

                        for key, value in metrics.to_dict().items():
                            if value > 0:
                                table.add_row(key.replace("_", " ").title(), str(value))

                        if table.rows:
                            console.print(table)
                    except (UnicodeEncodeError, Exception):
                        safe_print("Security Metrics:")
                        for key, value in metrics.to_dict().items():
                            if value > 0:
                                safe_print(
                                    f"  {key.replace('_', ' ').title()}: {value}"
                                )

            # Show overrides if verbose
            if verbose and result.has_overrides:
                try:
                    table = Table(title="Type Overrides", show_header=True)
                    table.add_column("Type", style="cyan")
                    table.add_column("Overridden By", style="green")
                    table.add_column("Previously From", style="yellow")

                    for override in result.overrides:
                        table.add_row(
                            override.type_name,
                            override.override_source,
                            override.overridden_source,
                        )
                    console.print(table)
                except (UnicodeEncodeError, Exception):
                    safe_print("Type Overrides:")
                    for override in result.overrides:
                        safe_print(
                            f"  {override.type_name}: {override.override_source} -> {override.overridden_source}"
                        )

            # Show warnings
            if result.has_warnings:
                for warning in result.warnings:
                    safe_print(f"[yellow]{SYMBOLS['warn']} Warning: {warning}[/yellow]")

            # Show security events
            if result.has_security_events and verbose:
                for event in result.security_events:
                    safe_print(f"[blue]{SYMBOLS['info']} Security: {event}[/blue]")

            # Output result
            if output_path:
                output_file = Path(output_path)

                # Security check on output path
                if not _is_safe_output_path(output_file):
                    safe_print(f"[red]Unsafe output path: {output_path}[/red]")
                    sys.exit(1)

                try:
                    output_file.parent.mkdir(parents=True, exist_ok=True)
                    with open(output_file, "w", encoding="utf-8") as f:
                        f.write(result.prompt)
                    safe_print(f"[blue]Output written to: {output_path}[/blue]")
                except PermissionError:
                    safe_print(
                        f"[red]Permission denied writing to: {output_path}[/red]"
                    )
                    sys.exit(1)
            else:
                safe_print("\n" + "=" * 80)
                safe_print(result.prompt)
                safe_print("=" * 80)

        # Generate security report if requested
        if security_report_path and hasattr(compiler, "generate_security_report"):
            try:
                report = compiler.generate_security_report(template_path)
                with open(security_report_path, "w", encoding="utf-8") as f:
                    json.dump(report.to_dict(), f, indent=2)
                safe_print(
                    f"[blue]Security report written to: {security_report_path}[/blue]"
                )
            except Exception as e:
                safe_print(f"[yellow]Failed to generate security report: {e}[/yellow]")

    except ITSSecurityError as e:
        safe_print(f"[red]Security Error: {e.get_user_message()}[/red]")
        if verbose and e.threat_type:
            safe_print(f"[red]Threat Type: {e.threat_type}[/red]")
        sys.exit(1)

    except ITSValidationError as e:
        safe_print(f"[red]Validation Error: {e.message}[/red]")
        if e.path:
            safe_print(f"[red]Path: {e.path}[/red]")
        for error in e.validation_errors:
            safe_print(f"[red]  {SYMBOLS['bullet']} {error}[/red]")
        for issue in e.security_issues:
            safe_print(f"[red]  {SYMBOLS['bullet']} Security: {issue}[/red]")
        sys.exit(1)

    except ITSCompilationError as e:
        safe_print(f"[red]Compilation Error: {e.get_context_message()}[/red]")
        sys.exit(1)

    except ITSError as e:
        safe_print(f"[red]ITS Error: {e.get_user_message()}[/red]")
        if verbose:
            safe_print(f"[red]Details: {e.details}[/red]")
        sys.exit(1)

    except Exception as e:
        safe_print(f"[red]Unexpected error: {e}[/red]")
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


def _is_safe_output_path(output_path: Path) -> bool:
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
@click.argument(
    "template_file", type=click.Path(exists=True, path_type=Path), required=False
)
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path),
    help="Output file (default: stdout)",
)
@click.option(
    "-v",
    "--variables",
    type=click.Path(exists=True, path_type=Path),
    help="JSON file with variable values",
)
@click.option("-w", "--watch", is_flag=True, help="Watch template file for changes")
@click.option(
    "--validate-only", is_flag=True, help="Validate template without compiling"
)
@click.option(
    "--verbose", is_flag=True, help="Show detailed output including security metrics"
)
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
    type=click.Path(path_type=Path),
    help="Generate security analysis report to specified file",
)
# Allowlist management options
@click.option("--allowlist-status", is_flag=True, help="Show allowlist status and exit")
@click.option(
    "--add-trusted-schema",
    type=str,
    help="Add a schema URL to the permanent allowlist and exit",
)
@click.option(
    "--remove-schema", type=str, help="Remove a schema URL from the allowlist and exit"
)
@click.option(
    "--export-allowlist",
    type=click.Path(path_type=Path),
    help="Export allowlist to specified file and exit",
)
@click.option(
    "--import-allowlist",
    type=click.Path(exists=True, path_type=Path),
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
@click.version_option()
def main(
    template_file: Optional[Path],
    output: Optional[Path],
    variables: Optional[Path],
    watch: bool,
    validate_only: bool,
    verbose: bool,
    strict: bool,
    no_cache: bool,
    timeout: int,
    allow_http: bool,
    interactive_allowlist: Optional[bool],
    security_report: Optional[Path],
    allowlist_status: bool,
    add_trusted_schema: Optional[str],
    remove_schema: Optional[str],
    export_allowlist: Optional[Path],
    import_allowlist: Optional[Path],
    merge_allowlist: bool,
    cleanup_allowlist: bool,
    older_than: int,
) -> None:
    """
    ITS Compiler Python - Convert ITS templates to AI prompts with security controls.

    TEMPLATE_FILE: Path to the ITS template JSON file to compile (required for compilation).
    """

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
        safe_print(
            f"\n[blue]Watching {template_file} for changes... (Press Ctrl+C to stop)[/blue]"
        )

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
    type=click.Path(path_type=Path),
    help="Export security configuration to file",
)
def validate_security_config(
    export_config: Optional[Path],
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
            safe_print(
                f"[green]{SYMBOLS['ok']} Security configuration is valid[/green]"
            )

        # Show configuration summary
        try:
            table = Table(title="Security Configuration", show_header=True)
            table.add_column("Setting", style="cyan")
            table.add_column("Value", style="green")

            table.add_row("HTTP Allowed", str(security_config.network.allow_http))
            table.add_row("Allowlist Enabled", str(security_config.enable_allowlist))
            table.add_row(
                "Input Validation", str(security_config.enable_input_validation)
            )
            table.add_row(
                "Expression Sanitisation",
                str(security_config.enable_expression_sanitisation),
            )
            table.add_row(
                "Interactive Allowlist", str(security_config.allowlist.interactive_mode)
            )
            table.add_row(
                "Block Localhost", str(security_config.network.block_localhost)
            )
            table.add_row(
                "Max Template Size",
                f"{security_config.processing.max_template_size // 1024} KB",
            )
            table.add_row(
                "Request Timeout", f"{security_config.network.request_timeout}s"
            )

            console.print(table)
        except (UnicodeEncodeError, Exception):
            safe_print("Security Configuration:")
            safe_print(f"  HTTP Allowed: {security_config.network.allow_http}")
            safe_print(f"  Allowlist Enabled: {security_config.enable_allowlist}")
            safe_print(f"  Input Validation: {security_config.enable_input_validation}")
            safe_print(
                f"  Expression Sanitisation: {security_config.enable_expression_sanitisation}"
            )
            safe_print(
                f"  Interactive Allowlist: {security_config.allowlist.interactive_mode}"
            )
            safe_print(f"  Block Localhost: {security_config.network.block_localhost}")
            safe_print(
                f"  Max Template Size: {security_config.processing.max_template_size // 1024} KB"
            )
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

            safe_print(
                f"[green]{SYMBOLS['ok']} Configuration exported to: {export_config}[/green]"
            )

    except Exception as e:
        safe_print(f"[red]Error validating security configuration: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
