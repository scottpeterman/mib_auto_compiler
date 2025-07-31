#!/usr/bin/env python3
"""
Command-line interface for MIB Auto Compiler
"""

import sys
import json
from pathlib import Path
from typing import Optional, List, Dict, Any
import logging

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.text import Text
from rich.logging import RichHandler

from .core import MibAutoCompiler
from .config import CompilerConfig
from .exceptions import MibAutoCompilerError
from .__version__ import __version__

# Setup rich console
console = Console()


# Setup logging with rich
def setup_logging(verbose: bool = False, quiet: bool = False) -> None:
    """Configure logging with rich formatting"""
    if quiet:
        level = logging.WARNING
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True)]
    )


@click.group(context_settings={'help_option_names': ['-h', '--help']})
@click.version_option(version=__version__, prog_name='mib-auto-compiler')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.option('--quiet', '-q', is_flag=True, help='Suppress info messages')
@click.pass_context
def cli(ctx: click.Context, verbose: bool, quiet: bool) -> None:
    """
    MIB Auto Compiler - Automatic SNMP MIB dependency resolution and compilation

    This tool automatically downloads standard MIB dependencies and compiles
    vendor-specific MIBs into Python modules for use with PySNMP applications.
    """
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose
    ctx.obj['quiet'] = quiet
    setup_logging(verbose, quiet)


@cli.command()
@click.argument('vendor_mib_directory', type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option('--output', '-o', type=click.Path(path_type=Path),
              help='Output directory for compiled MIBs (default: auto-generated)')
@click.option('--config', '-c', type=click.Path(exists=True, path_type=Path),
              help='Configuration file path')
@click.option('--mibs', '-m', multiple=True,
              help='Specific MIBs to compile (default: all found)')
@click.option('--retries', '-r', default=3, type=int,
              help='Maximum retry attempts for compilation')
@click.option('--timeout', '-t', default=10, type=int,
              help='Download timeout in seconds')
@click.option('--no-http-fallback', is_flag=True,
              help='Disable HTTP MIB source fallback')
@click.option('--preserve-downloads/--no-preserve-downloads', default=True,
              help='Keep downloaded standard MIBs for reuse')
@click.option('--report-format', type=click.Choice(['text', 'json', 'html']), default='text',
              help='Output report format')
@click.option('--report-file', type=click.Path(path_type=Path),
              help='Save report to file instead of stdout')
@click.pass_context
def compile(ctx: click.Context,
            vendor_mib_directory: Path,
            output: Optional[Path],
            config: Optional[Path],
            mibs: tuple,
            retries: int,
            timeout: int,
            no_http_fallback: bool,
            preserve_downloads: bool,
            report_format: str,
            report_file: Optional[Path]) -> None:
    """
    Compile vendor MIBs with automatic dependency resolution.

    VENDOR_MIB_DIRECTORY: Directory containing vendor MIB files (.mib, .txt)

    Examples:

        # Compile all MIBs in directory
        mib-compile /path/to/vendor/mibs

        # Compile specific MIBs with custom output
        mib-compile /path/to/vendor/mibs -o /path/to/output -m MIB1 -m MIB2

        # Use configuration file
        mib-compile /path/to/vendor/mibs --config config.yaml
    """
    verbose = ctx.obj['verbose']

    try:
        # Load configuration
        compiler_config = CompilerConfig()
        if config:
            compiler_config.load_from_file(config)

        # Override config with CLI options
        if output:
            compiler_config.output_directory = str(output)
        if retries != 3:
            compiler_config.max_retries = retries
        if timeout != 10:
            compiler_config.download_timeout = timeout
        if no_http_fallback:
            compiler_config.enable_http_fallback = False
        if not preserve_downloads:
            compiler_config.preserve_downloads = False

        # Create compiler instance
        with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True
        ) as progress:

            init_task = progress.add_task("Initializing compiler...", total=None)

            compiler = MibAutoCompiler(
                vendor_mib_directory=str(vendor_mib_directory),
                config=compiler_config,
                verbose=verbose
            )

            progress.update(init_task, description="✓ Compiler initialized")
            progress.remove_task(init_task)

            # Convert mibs tuple to list if specified
            mib_list = list(mibs) if mibs else None

            # Run compilation
            download_task = progress.add_task("Downloading dependencies...", total=None)
            results = compiler.run_auto_compilation(mib_list)
            progress.update(download_task, description="✓ Compilation completed")

        # Generate and display report
        _display_results(results, compiler.get_compilation_stats(), report_format, report_file)

        # Exit with appropriate code
        success_count = sum(1 for r in results.values() if r['success'])
        if success_count == 0:
            console.print("[bold red]❌ No MIBs compiled successfully[/bold red]")
            sys.exit(1)
        elif success_count < len(results):
            console.print(
                f"[bold yellow]⚠️  Partial success: {success_count}/{len(results)} MIBs compiled[/bold yellow]")
            sys.exit(2)
        else:
            console.print(f"[bold green]🎉 All {success_count} MIBs compiled successfully![/bold green]")

    except MibAutoCompilerError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        if verbose and e.details:
            console.print(f"[dim]Details: {e.details}[/dim]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Unexpected error:[/bold red] {e}")
        if verbose:
            console.print_exception()
        sys.exit(1)


@cli.command()
@click.argument('mib_directory', type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option('--format', 'output_format', type=click.Choice(['text', 'json', 'yaml']), default='text',
              help='Output format')
@click.option('--output', '-o', type=click.Path(path_type=Path),
              help='Output file (default: stdout)')
@click.option('--include-dependencies', is_flag=True,
              help='Show dependency analysis')
@click.option('--include-objects', is_flag=True,
              help='Include object type details')
def analyze(mib_directory: Path,
            output_format: str,
            output: Optional[Path],
            include_dependencies: bool,
            include_objects: bool) -> None:
    """
    Analyze MIB files without compilation.

    MIB_DIRECTORY: Directory containing MIB files to analyze

    Examples:

        # Basic analysis
        mib-compile analyze /path/to/mibs

        # Full analysis with dependencies
        mib-compile analyze /path/to/mibs --include-dependencies --include-objects

        # Export analysis to JSON
        mib-compile analyze /path/to/mibs --format json -o analysis.json
    """
    try:
        from .utils import analyze_mib_directory

        with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True
        ) as progress:
            task = progress.add_task("Analyzing MIB files...", total=None)

            analysis = analyze_mib_directory(
                mib_directory,
                include_dependencies=include_dependencies,
                include_objects=include_objects
            )

            progress.update(task, description="✓ Analysis completed")

        _output_analysis(analysis, output_format, output)

    except Exception as e:
        console.print(f"[bold red]Analysis failed:[/bold red] {e}")
        sys.exit(1)


@cli.command()
@click.option('--template', type=click.Choice(['basic', 'advanced', 'enterprise']), default='basic',
              help='Configuration template type')
@click.option('--output', '-o', type=click.Path(path_type=Path), default='mib-compiler.yaml',
              help='Output configuration file path')
def init_config(template: str, output: Path) -> None:
    """
    Generate a configuration file template.

    Examples:

        # Generate basic configuration
        mib-compile init-config

        # Generate advanced configuration
        mib-compile init-config --template advanced -o my-config.yaml
    """
    try:
        config = CompilerConfig.create_template(template)
        config.save_to_file(output)

        console.print(f"[bold green]✓[/bold green] Configuration template saved to {output}")
        console.print(f"[dim]Template type: {template}[/dim]")

    except Exception as e:
        console.print(f"[bold red]Failed to create configuration:[/bold red] {e}")
        sys.exit(1)


@cli.command()
@click.argument('compiled_directory', type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option('--format', 'output_format', type=click.Choice(['text', 'json']), default='text',
              help='Output format')
@click.option('--filter', 'filter_patterns', multiple=True,
              help='OID name filter patterns (regex)')
def extract_oids(compiled_directory: Path,
                 output_format: str,
                 filter_patterns: tuple) -> None:
    """
    Extract discovery OIDs from compiled MIB files.

    COMPILED_DIRECTORY: Directory containing compiled Python MIB modules

    Examples:

        # Extract all discovery OIDs
        mib-compile extract-oids /path/to/compiled

        # Filter by patterns
        mib-compile extract-oids /path/to/compiled --filter ".*[Ss]ys.*" --filter ".*[Mm]odel.*"
    """
    try:
        from .utils import extract_discovery_oids_from_directory

        with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True
        ) as progress:
            task = progress.add_task("Extracting OIDs...", total=None)

            patterns = list(filter_patterns) if filter_patterns else None
            oids = extract_discovery_oids_from_directory(compiled_directory, patterns)

            progress.update(task, description="✓ OID extraction completed")

        _output_oids(oids, output_format)

    except Exception as e:
        console.print(f"[bold red]OID extraction failed:[/bold red] {e}")
        sys.exit(1)


def _display_results(results: Dict[str, Dict],
                     stats: Dict[str, Any],
                     report_format: str,
                     report_file: Optional[Path]) -> None:
    """Display compilation results in specified format"""

    if report_format == 'json':
        report_data = {
            'results': results,
            'stats': stats,
            'summary': {
                'total': len(results),
                'successful': sum(1 for r in results.values() if r['success']),
                'failed': sum(1 for r in results.values() if not r['success'])
            }
        }

        if report_file:
            with open(report_file, 'w') as f:
                json.dump(report_data, f, indent=2)
            console.print(f"[dim]Report saved to {report_file}[/dim]")
        else:
            console.print_json(data=report_data)

    elif report_format == 'html':
        # Generate HTML report (implement if needed)
        console.print("[yellow]HTML format not yet implemented[/yellow]")

    else:  # text format
        _display_text_results(results, stats, report_file)


def _display_text_results(results: Dict[str, Dict],
                          stats: Dict[str, Any],
                          report_file: Optional[Path]) -> None:
    """Display results in rich text format"""

    # Summary panel
    successful = sum(1 for r in results.values() if r['success'])
    total = len(results)
    success_rate = (successful / total * 100) if total > 0 else 0

    summary_text = Text()
    summary_text.append(f"Total MIBs: {total}\n")
    summary_text.append(f"Successful: {successful}\n", style="bold green")
    summary_text.append(f"Failed: {total - successful}\n", style="bold red")
    summary_text.append(f"Success Rate: {success_rate:.1f}%", style="bold")

    console.print(Panel(summary_text, title="Compilation Summary", border_style="blue"))

    # Results table
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("MIB Name", style="cyan", width=25)
    table.add_column("Status", width=10)
    table.add_column("Message", style="dim")

    for mib_name, result in sorted(results.items()):
        status = "✓ PASS" if result['success'] else "✗ FAIL"
        status_style = "bold green" if result['success'] else "bold red"

        table.add_row(
            mib_name,
            Text(status, style=status_style),
            result['message']
        )

    console.print(table)

    # Statistics
    if stats:
        stats_text = Text()
        for key, value in stats.items():
            if isinstance(value, (int, float)):
                stats_text.append(f"{key.replace('_', ' ').title()}: {value:,}\n")
            else:
                stats_text.append(f"{key.replace('_', ' ').title()}: {value}\n")

        console.print(Panel(stats_text, title="Statistics", border_style="green"))


def _output_analysis(analysis: Dict[str, Any],
                     output_format: str,
                     output_file: Optional[Path]) -> None:
    """Output analysis results"""

    if output_format == 'json':
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(analysis, f, indent=2, default=str)
            console.print(f"[dim]Analysis saved to {output_file}[/dim]")
        else:
            console.print_json(data=analysis)

    elif output_format == 'yaml':
        try:
            import yaml
            if output_file:
                with open(output_file, 'w') as f:
                    yaml.dump(analysis, f, default_flow_style=False)
                console.print(f"[dim]Analysis saved to {output_file}[/dim]")
            else:
                console.print(yaml.dump(analysis, default_flow_style=False))
        except ImportError:
            console.print("[red]PyYAML not installed. Install with: pip install PyYAML[/red]")

    else:  # text format
        _display_text_analysis(analysis, output_file)


def _display_text_analysis(analysis: Dict[str, Any], output_file: Optional[Path]) -> None:
    """Display analysis in text format"""

    content = []

    # Summary
    summary = analysis.get('summary', {})
    content.append("=== MIB ANALYSIS REPORT ===\n")
    content.append(f"Total MIB Files: {summary.get('total_files', 0)}")
    content.append(f"Total Size: {summary.get('total_size', 0):,} bytes")
    content.append(f"Unique Dependencies: {summary.get('unique_dependencies', 0)}")
    content.append("")

    # Individual MIBs
    mibs = analysis.get('mibs', [])
    if mibs:
        content.append("=== INDIVIDUAL MIB DETAILS ===")
        for mib in mibs:
            content.append(f"\n{mib.get('name', 'Unknown')}:")
            content.append(f"  File: {mib.get('file', 'Unknown')}")
            content.append(f"  Size: {mib.get('size', 0):,} bytes")
            content.append(f"  Objects: {len(mib.get('object_types', []))}")
            content.append(f"  Dependencies: {len(mib.get('dependencies', []))}")

            if mib.get('dependencies'):
                deps = ', '.join(sorted(mib['dependencies']))
                content.append(f"  Imports from: {deps}")

    output_text = '\n'.join(content)

    if output_file:
        with open(output_file, 'w') as f:
            f.write(output_text)
        console.print(f"[dim]Analysis saved to {output_file}[/dim]")
    else:
        console.print(output_text)


def _output_oids(oids: Dict[str, List[str]], output_format: str) -> None:
    """Output extracted OIDs"""

    if output_format == 'json':
        console.print_json(data=oids)
    else:
        # Text format
        for mib_name, oid_list in sorted(oids.items()):
            console.print(f"[bold cyan]{mib_name}[/bold cyan]")
            for oid in sorted(oid_list):
                console.print(f"  {oid}")
            console.print()


def main() -> None:
    """Main CLI entry point"""
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[bold red]Unexpected error:[/bold red] {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()