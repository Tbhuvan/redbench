"""
run_benchmark.py — CLI for running the redbench vulnerability benchmark.

Evaluates a detection tool (bandit, semgrep, or stub) against all 17
vulnerability classes in the redbench dataset, prints a summary table, and
saves full results to results/benchmark_results.json.

Usage::

    # Stub baseline (always predicts "vulnerable"):
    python run_benchmark.py --tool stub

    # Bandit static analyser:
    python run_benchmark.py --tool bandit

    # Semgrep static analyser:
    python run_benchmark.py --tool semgrep

    # Load from v3 files when canonical files are absent:
    python run_benchmark.py --tool stub --source-files samples.jsonl samples_generated_v3.jsonl

    # Only evaluate a subset of classes:
    python run_benchmark.py --tool stub --classes idor sqli ssrf

    # Custom output file:
    python run_benchmark.py --tool stub --output results/my_run.json
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import os
from pathlib import Path
from typing import Any

# Allow running from repo root without installing the package
sys.path.insert(0, str(Path(__file__).resolve().parent))

from redbench.evaluator import BenchmarkEvaluator
from redbench.loader import VULN_CLASSES
from redbench.reporter import BenchmarkReporter


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


def stub_tool(code: str) -> dict[str, Any]:
    """
    Baseline stub: always predicts "vulnerable".

    This gives 100% recall (catches every real vulnerability) at the cost of
    50% precision on a balanced dataset (flags all safe samples too).

    Args:
        code: Source code snippet to analyse.

    Returns:
        Dict with label always set to "vulnerable".
    """
    return {"label": "vulnerable", "tool": "stub", "note": "always-vulnerable baseline"}


def _run_bandit(code: str) -> dict[str, Any]:
    """
    Run Bandit on a code snippet and return a prediction dict.

    Bandit is invoked on a temporary file.  Any finding of medium or higher
    confidence/severity is treated as a "vulnerable" prediction.

    Args:
        code: Python source code to analyse.

    Returns:
        Dict containing "label" ("vulnerable" | "safe") and raw Bandit output.

    Raises:
        RuntimeError: If bandit is not installed or fails unexpectedly.
    """
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(code)
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            ["bandit", "-q", "-f", "json", tmp_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        # Bandit exits with 1 when issues are found, 0 when clean.
        # Any other exit code indicates an unexpected error.
        if result.returncode not in (0, 1):
            return {
                "label": "safe",
                "error": f"bandit exited with code {result.returncode}: {result.stderr.strip()}",
            }

        try:
            output = json.loads(result.stdout)
        except json.JSONDecodeError:
            return {"label": "safe", "error": "bandit returned non-JSON output"}

        results_list = output.get("results", [])
        # Predict vulnerable if at least one medium+ severity or medium+ confidence issue
        is_vulnerable = any(
            r.get("issue_severity", "").upper() in ("MEDIUM", "HIGH")
            or r.get("issue_confidence", "").upper() in ("MEDIUM", "HIGH")
            for r in results_list
        )
        return {
            "label": "vulnerable" if is_vulnerable else "safe",
            "n_issues": len(results_list),
            "bandit_output": output,
        }
    finally:
        os.unlink(tmp_path)


def _run_semgrep(code: str) -> dict[str, Any]:
    """
    Run Semgrep on a code snippet using the ``p/python`` ruleset and return a
    prediction dict.

    Semgrep is invoked on a temporary file with the ``--config p/python`` rule
    set.  Any finding is treated as a "vulnerable" prediction.

    Args:
        code: Python source code to analyse.

    Returns:
        Dict containing "label" ("vulnerable" | "safe") and raw Semgrep output.

    Raises:
        RuntimeError: If semgrep is not installed or fails unexpectedly.
    """
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(code)
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            [
                "semgrep",
                "--config", "p/python",
                "--json",
                "--quiet",
                tmp_path,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        # Semgrep exits 0 (no findings) or 1 (findings found).
        if result.returncode not in (0, 1):
            return {
                "label": "safe",
                "error": f"semgrep exited with code {result.returncode}: {result.stderr.strip()[:200]}",
            }

        try:
            output = json.loads(result.stdout)
        except json.JSONDecodeError:
            return {"label": "safe", "error": "semgrep returned non-JSON output"}

        findings = output.get("results", [])
        return {
            "label": "vulnerable" if findings else "safe",
            "n_findings": len(findings),
            "semgrep_output": output,
        }
    finally:
        os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------

TOOLS: dict[str, Any] = {
    "stub": stub_tool,
    "bandit": _run_bandit,
    "semgrep": _run_semgrep,
}


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def _print_summary_table(results: dict[str, Any], tool_name: str) -> None:
    """
    Print a formatted summary table to stdout.

    Args:
        results: Return value from BenchmarkEvaluator.evaluate().
        tool_name: Display name of the evaluated tool.
    """
    overall = results["overall"]
    per_class = results["per_class"]

    col_w = 22  # class column width
    header = (
        f"{'Class':<{col_w}}  {'Prec':>6}  {'Rec':>6}  {'F1':>6}  "
        f"{'FPR':>6}  {'Acc':>6}  {'N':>4}"
    )
    sep = "-" * len(header)

    print()
    print(f"  redbench Results — {tool_name}")
    print(f"  Samples: {results['n_samples']}   Correct: {results['n_correct']}")
    print()
    print(header)
    print(sep)

    for vc in sorted(per_class.keys()):
        m = per_class[vc]
        n = m["tp"] + m["fp"] + m["tn"] + m["fn"]
        print(
            f"  {vc:<{col_w - 2}}  "
            f"{m['precision']:>6.3f}  {m['recall']:>6.3f}  {m['f1']:>6.3f}  "
            f"{m['fpr']:>6.3f}  {m['accuracy']:>6.3f}  {n:>4}"
        )

    print(sep)
    n_total = overall["tp"] + overall["fp"] + overall["tn"] + overall["fn"]
    print(
        f"  {'OVERALL':<{col_w - 2}}  "
        f"{overall['precision']:>6.3f}  {overall['recall']:>6.3f}  "
        f"{overall['f1']:>6.3f}  {overall['fpr']:>6.3f}  "
        f"{overall['accuracy']:>6.3f}  {n_total:>4}"
    )
    print()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """
    Main entry point for the run_benchmark CLI.

    Args:
        argv: Command-line arguments. Defaults to sys.argv[1:].

    Returns:
        Exit code: 0 on success, non-zero on error.
    """
    parser = argparse.ArgumentParser(
        prog="run_benchmark",
        description="Run the redbench vulnerability detection benchmark.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--tool",
        choices=list(TOOLS.keys()),
        required=True,
        help=(
            "Detection tool to benchmark. "
            "'stub' is a always-predict-vulnerable baseline. "
            "'bandit' and 'semgrep' require the respective tools to be installed."
        ),
    )
    parser.add_argument(
        "--classes",
        nargs="+",
        default=None,
        metavar="CLASS",
        help=(
            "Vulnerability classes to evaluate (space-separated). "
            f"Defaults to all 17 classes. Known classes: {' '.join(sorted(VULN_CLASSES))}"
        ),
    )
    parser.add_argument(
        "--source-files",
        nargs="+",
        default=["samples.jsonl"],
        dest="source_files",
        metavar="FILE",
        help=(
            "JSONL filename(s) to load from each class directory (tried in order). "
            "Default: samples.jsonl. "
            "Example: --source-files samples.jsonl samples_generated_v3.jsonl"
        ),
    )
    parser.add_argument(
        "--output",
        default="results/benchmark_results.json",
        metavar="PATH",
        help="Path to write the JSON results file. Default: results/benchmark_results.json",
    )
    parser.add_argument(
        "--dataset-dir",
        default=None,
        dest="dataset_dir",
        metavar="DIR",
        help="Path to the datasets/ directory. Defaults to datasets/ in the repo root.",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        dest="no_save",
        help="Skip saving results to disk; only print the summary.",
    )

    args = parser.parse_args(argv)

    # Validate class names early
    if args.classes is not None:
        invalid = set(args.classes) - set(VULN_CLASSES)
        if invalid:
            parser.error(
                f"Unknown vulnerability classes: {sorted(invalid)}. "
                f"Valid classes: {sorted(VULN_CLASSES)}"
            )

    tool_fn = TOOLS[args.tool]
    tool_display_name = args.tool

    print(f"Running redbench with tool={tool_display_name!r} ...")
    print(f"  source_files : {args.source_files}")
    print(f"  classes      : {args.classes or 'all 17'}")

    evaluator = BenchmarkEvaluator(
        dataset_dir=args.dataset_dir,
        source_files=args.source_files,
    )

    try:
        results = evaluator.evaluate(tool_fn, vuln_classes=args.classes)
    except Exception as exc:
        print(f"ERROR: Evaluation failed: {exc}", file=sys.stderr)
        return 1

    if results["n_samples"] == 0:
        print("WARNING: No samples loaded. Check --source-files and --classes.", file=sys.stderr)
        return 1

    _print_summary_table(results, tool_display_name)

    if not args.no_save:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        reporter = BenchmarkReporter(tool_name=tool_display_name)
        payload: dict[str, Any] = {
            "tool": tool_display_name,
            "source_files": args.source_files,
            "classes_evaluated": args.classes or list(VULN_CLASSES),
            **json.loads(reporter.to_json(results)),
        }
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)

        print(f"Results saved to: {output_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
