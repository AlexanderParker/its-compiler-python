"""
Command-line interface for ITS Compiler.
"""

import json
import sys
import time
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from .compiler import ITSCompiler
from .models import ITSConfig
from .exceptions import ITSError, ITSValidationError, ITSCompilationError

# Configure console with safe encoding for Windows
console = Console(force_terminal=True, legacy_windows=False)


class TemplateChangeHandler(FileSystemEventHandler):
    """Handler for template file changes in watch mode."""

    def __init__(
        self,
        template_path: str,
        output_path: Optional[str],
        variables_path: Optional[str],
        verbose: bool,
    ):
        self.template_path = Path(template_path)
        self.output_path = output_path
        self.variables_path = variables_path
        self.verbose = verbose

    def on_modified(self, event):
        if event.is_directory:
            return

        changed_path = Path(event.src_path)
        if changed_path.name == self.template_path.name:
            console.print(f"\n[yellow]File changed: {changed_path}[/yellow]")
            compile_template(
                str(self.template_path),
                self.output_path,
                self.variables_path,
                False,  # validate_only
                self.verbose,
                False,  # watch
                False,  # no_cache
            )


def load_variables(variables_path: str) -> dict:
    """Load variables from JSON file."""
    try:
        with open(variables_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise click.ClickException(f"Variables file not found: {variables_path}")
    except json.JSONDecodeError as e:
        raise click.ClickException(f"Invalid JSON in variables file: {e}")


def compile_template(
    template_path: str,
    output_path: Optional[str],
    variables_path: Optional[str],
    validate_only: bool,
    verbose: bool,
    watch: bool,
    no_cache: bool,
) -> None:
    """Compile a template file."""

    # Load variables if provided
    variables = {}
    if variables_path:
        variables = load_variables(variables_path)
        if verbose:
            console.print(
                f"[blue]Loaded {len(variables)} variables from {variables_path}[/blue]"
            )

    # Configure compiler
    config = ITSConfig(cache_enabled=not no_cache, report_overrides=verbose)
    compiler = ITSCompiler(config)

    try:
        if validate_only:
            # Validation only
            result = compiler.validate_file(template_path)

            if result.is_valid:
                # Use simple text instead of Unicode checkmark
                console.print(
                    "[green]PASS - Template is valid[/green]", highlight=False
                )
                if result.warnings and verbose:
                    for warning in result.warnings:
                        console.print(
                            f"[yellow]Warning: {warning}[/yellow]", highlight=False
                        )
            else:
                console.print(
                    "[red]FAIL - Template validation failed[/red]", highlight=False
                )
                for error in result.errors:
                    console.print(f"[red]Error: {error}[/red]", highlight=False)
                sys.exit(1)
        else:
            # Full compilation
            result = compiler.compile_file(template_path, variables)

            # Show compilation success
            console.print(
                "[green]Template compiled successfully[/green]", highlight=False
            )

            # Show overrides if verbose
            if verbose and result.has_overrides:
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

            # Show warnings
            if result.has_warnings:
                for warning in result.warnings:
                    console.print(f"[yellow]Warning: {warning}[/yellow]")

            # Output result
            if output_path:
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(result.prompt)
                console.print(f"[blue]Output written to: {output_path}[/blue]")
            else:
                console.print("\n" + "=" * 80)
                console.print(result.prompt)
                console.print("=" * 80)

    except ITSValidationError as e:
        console.print(f"[red]Validation Error: {e.message}[/red]")
        if e.path:
            console.print(f"[red]Path: {e.path}[/red]")
        for error in e.validation_errors:
            console.print(f"[red]  • {error}[/red]")
        sys.exit(1)

    except ITSCompilationError as e:
        console.print(f"[red]Compilation Error: {e.message}[/red]")
        if e.element_id:
            console.print(f"[red]Element ID: {e.element_id}[/red]")
        sys.exit(1)

    except ITSError as e:
        console.print(f"[red]ITS Error: {e.message}[/red]")
        sys.exit(1)

    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


@click.command()
@click.argument("template_file", type=click.Path(exists=True, path_type=Path))
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
    "--verbose", is_flag=True, help="Show detailed output including overrides"
)
@click.option("--strict", is_flag=True, help="Enable strict validation mode")
@click.option("--no-cache", is_flag=True, help="Disable schema caching")
@click.option("--timeout", type=int, default=30, help="Network timeout in seconds")
@click.version_option()
def main(
    template_file: Path,
    output: Optional[Path],
    variables: Optional[Path],
    watch: bool,
    validate_only: bool,
    verbose: bool,
    strict: bool,
    no_cache: bool,
    timeout: int,
) -> None:
    """
    ITS Compiler Python - Convert ITS templates to AI prompts.

    TEMPLATE_FILE: Path to the ITS template JSON file to compile.
    """

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
    )

    # Watch mode
    if watch:
        console.print(
            f"\n[blue]Watching {template_file} for changes... (Press Ctrl+C to stop)[/blue]"
        )

        event_handler = TemplateChangeHandler(
            str(template_file),
            str(output) if output else None,
            str(variables) if variables else None,
            verbose,
        )

        observer = Observer()
        observer.schedule(event_handler, str(template_file.parent), recursive=False)
        observer.start()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            console.print("\n[yellow]Stopping watch mode...[/yellow]")
            observer.stop()
        observer.join()


if __name__ == "__main__":
    main()
