"""Command line interface that wraps the enhanced binary analyzer."""

from __future__ import annotations

import json
from pathlib import Path

import click

from build_system import AutomatedBuilder, CodeValidator, CompilerDetector
from enhanced_disassembler import run_analysis


def _echo_progress(message: str) -> None:
    """Helper used to forward progress messages to Click."""

    click.echo(message)


@click.group()
def cli() -> None:
    """Binary analysis toolkit with build helpers."""


@cli.command()
@click.argument("binary_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--output", "output_dir", default="output", show_default=True,
              type=click.Path(file_okay=False, dir_okay=True, path_type=Path),
              help="Directory where analysis artefacts will be written.")
@click.option("--report/--no-report", default=False, show_default=True,
              help="Generate the detailed analysis report text file.")
@click.option("--strings/--no-strings", default=False, show_default=True,
              help="Extract and analyse printable strings from the binary.")
@click.option("--build-files/--no-build-files", default=False, show_default=True,
              help="Emit Makefile and CMakeLists.txt build helpers.")
@click.option("--detailed/--no-detailed", default=False, show_default=True,
              help="Reserved flag for future extended analysis.")
@click.option("--complete/--no-complete", default=False, show_default=True,
              help="Reserved flag for deeper disassembly workflows.")
@click.option("--max-functions", default=100, show_default=True,
              help="Limit the number of automatically discovered functions to inspect.")
def analyze(
    binary_path: Path,
    output_dir: Path,
    report: bool,
    strings: bool,
    build_files: bool,
    detailed: bool,
    complete: bool,
    max_functions: int,
) -> None:
    """Analyse *BINARY_PATH* and regenerate C/C++ artefacts."""

    click.echo("Enhanced Binary Analysis Tool")
    click.echo(f"Analyzing: {binary_path}")
    click.echo(f"Output: {output_dir}")
    click.echo("-" * 50)

    try:
        result = run_analysis(
            str(binary_path),
            str(output_dir),
            report=report,
            strings=strings,
            build_files=build_files,
            detailed=detailed,
            complete=complete,
            max_functions=max_functions,
            progress_callback=_echo_progress,
        )
    except (FileNotFoundError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from exc

    click.echo("-" * 50)
    click.echo("Generated files:")
    for label, filepath in result["generated_files"].items():
        pretty_label = label.replace("_", " ").title()
        click.echo(f"- {pretty_label}: {filepath}")

    click.echo("")
    click.echo("Key statistics:")
    stats = result["summary"]["analysis_stats"]
    click.echo(f"- Sections: {stats['sections']}")
    click.echo(f"- Imports: {stats['imports']}")
    click.echo(f"- Exports: {stats['exports']}")
    click.echo(f"- Functions analysed: {stats['functions_analyzed']}")
    click.echo(f"- Strings found: {stats['strings_found']}")

    click.echo("")
    click.echo("Analysis complete! 🎉")
    click.echo(f"Summary saved to: {result['generated_files']['summary']}")


def _build_compiler_detector() -> CompilerDetector:
    detector = CompilerDetector()
    available = detector.get_available_compilers()
    if not available:
        raise click.ClickException("No supported C/C++ compiler was detected on this system.")
    return detector


@cli.command()
@click.argument("project_dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--system",
    "build_system",
    type=click.Choice(["auto", "cmake", "make", "msvc", "simple"], case_sensitive=False),
    default="auto",
    show_default=True,
    help="Build system to use for compiling generated artefacts.",
)
def build(project_dir: Path, build_system: str) -> None:
    """Compile the generated code located in *PROJECT_DIR*."""

    detector = _build_compiler_detector()
    builder = AutomatedBuilder(detector)
    click.echo(f"Building project in {project_dir} using '{build_system}' mode...")

    result = builder.build_project(project_dir, build_system=build_system.lower())

    if not result.get("success", False):
        stderr = result.get("stderr") or result.get("error")
        raise click.ClickException(stderr or "Build failed")

    click.echo("Build succeeded!")
    if result.get("output_dir"):
        click.echo(f"Build artefacts are available in: {result['output_dir']}")


@cli.command()
@click.argument("project_dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
def validate(project_dir: Path) -> None:
    """Run a syntax check over all C/C++ files in *PROJECT_DIR*."""

    detector = _build_compiler_detector()

    validator = CodeValidator(detector)
    click.echo(f"Validating source files in {project_dir}...")
    result = validator.validate_project(project_dir)

    if not result.get("project_valid", False):
        error = result.get("error", "Project validation failed")
        raise click.ClickException(error)

    file_results = result.get("file_results", {})
    for filename, file_result in file_results.items():
        status = "passed" if file_result.get("success") else "failed"
        click.echo(f"- {filename}: {status}")
        for warning in file_result.get("warnings", []):
            click.echo(f"  ⚠️  {warning}")
        for error in file_result.get("errors", []):
            click.echo(f"  ❌ {error}")

    summary = {
        "files_validated": result.get("files_validated", 0),
        "errors": result.get("summary", {}).get("total_errors", 0),
        "warnings": result.get("summary", {}).get("total_warnings", 0),
    }

    click.echo("")
    click.echo("Validation summary:")
    click.echo(json.dumps(summary, indent=2))


if __name__ == "__main__":
    cli()
