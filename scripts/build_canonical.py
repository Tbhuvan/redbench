"""
Build canonical samples.jsonl files for the 12 new vulnerability classes.

Reads ``samples_generated_v3.jsonl`` from each new class directory, cleans
and normalises the data, then writes a balanced ``samples.jsonl`` containing
up to 20 samples (10 vulnerable + 10 safe where possible).

Existing canonical files for the original five classes are left untouched.

Usage::

    python scripts/build_canonical.py [--dry-run] [--classes cls1 cls2 ...]

Flags:
    --dry-run   Print what would be written without touching any files.
    --classes   Space-separated list of class names to process. Defaults to
                all 12 new classes.
    --top-n     Maximum samples per class to write (default: 20).
    --per-label Maximum samples per label (default: 10 when --top-n is even,
                else top_n // 2).
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Canonical 5 classes already have samples.jsonl — skip them by default.
EXISTING_CLASSES: frozenset[str] = frozenset(
    {"idor", "sqli", "ssrf", "auth_bypass", "path_traversal"}
)

NEW_CLASSES: tuple[str, ...] = (
    "command_injection",
    "xss",
    "deserialization",
    "weak_crypto",
    "cleartext_secrets",
    "tls_validation",
    "unsafe_yaml",
    "mass_assignment",
    "redos",
    "race_condition",
    "open_redirect",
    "xxe",
)

# Fields to include in canonical output (ordered for readability)
CANONICAL_FIELDS: tuple[str, ...] = (
    "id",
    "cwe",
    "severity",
    "label",
    "language",
    "code",
    "description",
    "fix",
    "attack_scenario",
)

REQUIRED_FIELDS: frozenset[str] = frozenset(
    {"id", "cwe", "severity", "label", "language", "code", "description", "fix"}
)

VALID_LABELS: frozenset[str] = frozenset({"vulnerable", "safe"})
VALID_SEVERITIES: frozenset[str] = frozenset({"critical", "high", "medium", "low"})

# The v3 generator wrote severity="none" for all safe-labelled samples.
# We normalise this to "low" because safe code has no inherent severity, and
# "none" is not a valid canonical value.
_SEVERITY_REMAP: dict[str, str] = {"none": "low"}

# Regex to strip markdown code fences (```python\n...\n``` or just ```\n...\n```)
_CODE_FENCE_RE: re.Pattern[str] = re.compile(
    r"^```[^\n]*\n(.*?)(?:```\s*)?$",
    re.DOTALL,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    format="%(levelname)s  %(message)s",
    level=logging.INFO,
    stream=sys.stdout,
)
log = logging.getLogger("build_canonical")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clean_code(code: str) -> str:
    """
    Strip markdown code fences from a code string.

    Args:
        code: Raw code string, possibly wrapped in ```lang\\n...\\n```.

    Returns:
        Inner code content with surrounding whitespace trimmed.
    """
    stripped = code.strip()
    match = _CODE_FENCE_RE.match(stripped)
    if match:
        return match.group(1).rstrip()
    return stripped


def _normalise_severity(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Return a copy of *raw* with severity normalised.

    The v3 generator wrote ``severity: "none"`` for safe-labelled samples.
    We remap that to ``"low"`` so the record passes canonical validation.
    A shallow copy is returned; the original dict is not mutated.

    Args:
        raw: Parsed JSON dict from a v3 JSONL file.

    Returns:
        Dict with severity remapped if necessary.
    """
    severity = raw.get("severity", "")
    remapped = _SEVERITY_REMAP.get(severity)
    if remapped is not None:
        raw = dict(raw)  # shallow copy — do not mutate caller's dict
        raw["severity"] = remapped
    return raw


def _validate_raw(
    raw: dict[str, Any],
    source_file: str,
    lineno: int,
) -> list[str]:
    """
    Check a raw sample dict for required fields and valid enum values.

    Call *after* ``_normalise_severity`` so remapped values are accepted.

    Args:
        raw: Parsed (and normalised) JSON dict.
        source_file: Path string used in warning messages.
        lineno: 1-based line number used in warning messages.

    Returns:
        List of warning strings; empty list means the sample is valid.
    """
    warnings: list[str] = []

    missing = REQUIRED_FIELDS - set(raw.keys())
    if missing:
        warnings.append(
            f"{source_file}:{lineno}: missing required fields {sorted(missing)}"
        )
        return warnings  # Cannot perform further checks without required fields

    if raw["label"] not in VALID_LABELS:
        warnings.append(
            f"{source_file}:{lineno}: invalid label {raw['label']!r} "
            f"(must be one of {sorted(VALID_LABELS)})"
        )

    if raw["severity"] not in VALID_SEVERITIES:
        warnings.append(
            f"{source_file}:{lineno}: invalid severity {raw['severity']!r} "
            f"(must be one of {sorted(VALID_SEVERITIES)})"
        )

    cleaned_code = _clean_code(raw.get("code", ""))
    if not cleaned_code:
        warnings.append(f"{source_file}:{lineno}: empty code field after fence stripping")

    cwe = raw.get("cwe", "")
    if not isinstance(cwe, str) or not cwe.upper().startswith("CWE-"):
        warnings.append(
            f"{source_file}:{lineno}: CWE must start with 'CWE-', got {cwe!r}"
        )

    return warnings


def _to_canonical(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Convert a v3 raw sample to canonical format.

    - Strips markdown fences from ``code`` and ``fix`` fields.
    - Defaults ``attack_scenario`` to empty string when absent.
    - Drops ``vuln_class`` and ``source`` (extra fields not in canonical schema).

    Args:
        raw: Parsed JSON dict from a v3 JSONL file.

    Returns:
        Clean dict containing only canonical fields in canonical order.
    """
    return {
        "id": raw["id"],
        "cwe": raw["cwe"],
        "severity": raw["severity"],
        "label": raw["label"],
        "language": raw["language"],
        "code": _clean_code(raw["code"]),
        "description": raw["description"],
        "fix": _clean_code(raw.get("fix", "") or ""),
        "attack_scenario": raw.get("attack_scenario", ""),
    }


def _select_balanced(
    samples: list[dict[str, Any]],
    per_label: int,
) -> list[dict[str, Any]]:
    """
    Select up to ``per_label`` vulnerable and ``per_label`` safe samples.

    Maintains original order within each label group.  If one label has fewer
    than ``per_label`` samples, all of its samples are included and the
    remaining budget is *not* redistributed to the other label (balanced
    benchmark is preferred over larger but skewed).

    Args:
        samples: List of canonical sample dicts.
        per_label: Maximum number of samples per label.

    Returns:
        Selected samples: vulnerable first, then safe.
    """
    vulnerable = [s for s in samples if s["label"] == "vulnerable"]
    safe = [s for s in samples if s["label"] == "safe"]
    return vulnerable[:per_label] + safe[:per_label]


def _load_v3_samples(
    v3_path: Path,
) -> tuple[list[dict[str, Any]], int]:
    """
    Parse and validate all samples from a v3 JSONL file.

    Args:
        v3_path: Path to the ``samples_generated_v3.jsonl`` file.

    Returns:
        Tuple of (valid_canonical_samples, skipped_count).
    """
    valid: list[dict[str, Any]] = []
    skipped = 0

    with open(v3_path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                raw: dict[str, Any] = json.loads(line)
            except json.JSONDecodeError as exc:
                log.warning("  JSON parse error at %s:%d: %s — skipping", v3_path.name, lineno, exc)
                skipped += 1
                continue

            # Normalise severity="none" -> "low" for safe samples before validation
            raw = _normalise_severity(raw)

            warnings = _validate_raw(raw, v3_path.name, lineno)
            if warnings:
                for w in warnings:
                    log.warning("  %s", w)
                skipped += 1
                continue

            valid.append(_to_canonical(raw))

    return valid, skipped


# ---------------------------------------------------------------------------
# Main build logic
# ---------------------------------------------------------------------------


def build_class(
    class_name: str,
    datasets_dir: Path,
    per_label: int,
    dry_run: bool,
) -> bool:
    """
    Build the canonical ``samples.jsonl`` for one vulnerability class.

    Args:
        class_name: Name of the vulnerability class directory.
        datasets_dir: Root datasets directory.
        per_label: Maximum samples per label to write.
        dry_run: If True, skip writing and only log what would happen.

    Returns:
        True if the file was written (or would be in dry_run), False on error.
    """
    class_dir = datasets_dir / class_name
    v3_path = class_dir / "samples_generated_v3.jsonl"
    out_path = class_dir / "samples.jsonl"

    if not v3_path.exists():
        log.error("[%s] source file not found: %s", class_name, v3_path)
        return False

    log.info("[%s] reading %s", class_name, v3_path.name)
    valid_samples, skipped = _load_v3_samples(v3_path)

    if not valid_samples:
        log.error("[%s] no valid samples found — skipping", class_name)
        return False

    selected = _select_balanced(valid_samples, per_label)

    label_counts = {
        "vulnerable": sum(1 for s in selected if s["label"] == "vulnerable"),
        "safe": sum(1 for s in selected if s["label"] == "safe"),
    }

    log.info(
        "[%s] %d valid / %d skipped -> selected %d (vuln=%d safe=%d)",
        class_name,
        len(valid_samples),
        skipped,
        len(selected),
        label_counts["vulnerable"],
        label_counts["safe"],
    )

    if dry_run:
        log.info("[%s] DRY RUN — would write %d lines to %s", class_name, len(selected), out_path)
        return True

    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        for sample in selected:
            fh.write(json.dumps(sample, ensure_ascii=False) + "\n")

    log.info("[%s] wrote %s (%d samples)", class_name, out_path, len(selected))
    return True


def main(argv: list[str] | None = None) -> int:
    """
    Entry point for the build_canonical script.

    Args:
        argv: Command-line arguments. Defaults to sys.argv[1:].

    Returns:
        Exit code: 0 on success, 1 if any class failed.
    """
    parser = argparse.ArgumentParser(
        description="Build canonical samples.jsonl files for new redbench classes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be written without creating any files.",
    )
    parser.add_argument(
        "--classes",
        nargs="+",
        default=list(NEW_CLASSES),
        metavar="CLASS",
        help=(
            "Vulnerability class names to process. "
            f"Defaults to all 12 new classes: {' '.join(NEW_CLASSES)}"
        ),
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=20,
        dest="top_n",
        help="Maximum total samples per class (default: 20).",
    )
    args = parser.parse_args(argv)

    per_label: int = args.top_n // 2

    # Locate datasets/ relative to this script (scripts/ -> repo_root/datasets/)
    scripts_dir = Path(__file__).resolve().parent
    datasets_dir = scripts_dir.parent / "datasets"

    if not datasets_dir.exists():
        log.error("datasets/ directory not found at %s", datasets_dir)
        return 1

    log.info(
        "Building canonical files: classes=%s top_n=%d per_label=%d dry_run=%s",
        args.classes,
        args.top_n,
        per_label,
        args.dry_run,
    )

    results: dict[str, bool] = {}
    for class_name in args.classes:
        if class_name in EXISTING_CLASSES:
            log.info("[%s] skipping — already has canonical samples.jsonl", class_name)
            results[class_name] = True
            continue
        results[class_name] = build_class(class_name, datasets_dir, per_label, args.dry_run)

    failed = [cls for cls, ok in results.items() if not ok]
    if failed:
        log.error("Failed classes: %s", failed)
        return 1

    log.info(
        "Done. %d/%d classes processed successfully.",
        len(results) - len(failed),
        len(results),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
