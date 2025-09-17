#!/usr/bin/env python3
"""Simple demonstration harness for :mod:`enhanced_disassembler`.

The original project attempted to generate full C/C++ reconstructions of a PE
binary.  That goal required a significant amount of functionality that was not
present in the repository, making the "demo" script unusable.  The new version
keeps the spirit of a one-stop demonstration while embracing the strengths of
our refactored analyser: structured data, robust string extraction and
human-friendly summaries.

Running the script performs an analysis with strings enabled, prints a report to
stdout and writes the JSON payload + plain text summary to the output directory.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Optional, Sequence

from enhanced_disassembler import EnhancedBinaryAnalyzer, format_summary


def demonstrate_complete_disassembly(binary_path: Path, output_dir: Path) -> None:
    """Analyse ``binary_path`` and persist the results into ``output_dir``."""

    analyzer = EnhancedBinaryAnalyzer(binary_path)
    analyzer.load_binary()
    result = analyzer.analyze(include_strings=True)

    summary = format_summary(result, include_strings=True, max_strings=25)
    print(summary)

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "analysis.txt").write_text(summary)
    (output_dir / "analysis.json").write_text(json.dumps(result.to_dict(), indent=2))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Demonstrate the enhanced disassembler on a PE file")
    parser.add_argument("binary", type=Path, help="Path to the PE binary to analyse")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("complete_demo_output"),
        help="Directory that will receive the generated files",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.binary.exists():
        parser.error(f"Binary not found: {args.binary}")

    demonstrate_complete_disassembly(args.binary, args.output_dir)
    return 0


if __name__ == "__main__":  # pragma: no cover - manual execution only
    raise SystemExit(main())
