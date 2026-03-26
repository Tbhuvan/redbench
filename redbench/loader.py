"""
Dataset loading and validation for the redbench benchmark suite.

Loads JSONL vulnerability samples from the datasets/ directory, validates
schema, and provides filtered access by vulnerability class, severity,
and CWE.
"""

from __future__ import annotations

import json
import re
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator


# ---------------------------------------------------------------------------
# Schema definition
# ---------------------------------------------------------------------------

# attack_scenario is intentionally excluded — it is optional in v3 files.
REQUIRED_FIELDS: frozenset[str] = frozenset(
    {
        "id",
        "cwe",
        "severity",
        "label",
        "language",
        "code",
        "description",
        "fix",
    }
)

# Fields that are allowed as extras (not treated as unknown)
OPTIONAL_KNOWN_FIELDS: frozenset[str] = frozenset(
    {"attack_scenario", "vuln_class", "source"}
)

VALID_LABELS: frozenset[str] = frozenset({"vulnerable", "safe"})
VALID_SEVERITIES: frozenset[str] = frozenset({"critical", "high", "medium", "low"})
VALID_LANGUAGES: frozenset[str] = frozenset({"python", "javascript", "java", "go", "rust"})

VULN_CLASSES: tuple[str, ...] = (
    "idor",
    "sqli",
    "ssrf",
    "auth_bypass",
    "path_traversal",
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

# Regex to strip markdown code fences such as ```python\n...\n``` or ```\n...\n```
_CODE_FENCE_RE: re.Pattern[str] = re.compile(
    r"^```[^\n]*\n(.*?)(?:```\s*)?$",
    re.DOTALL,
)


# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------


@dataclass
class BenchmarkSample:
    """
    A single vulnerability sample from the redbench dataset.

    Attributes:
        id: Unique sample identifier (e.g. "idor-001").
        cwe: CWE identifier (e.g. "CWE-639").
        severity: "critical" | "high" | "medium" | "low".
        label: Ground truth: "vulnerable" | "safe".
        language: Programming language of the code snippet.
        code: The code snippet to be analysed.
        description: Explanation of why the code is vulnerable.
        fix: The corrected code snippet.
        attack_scenario: Concrete exploitation scenario (empty string if absent).
        vuln_class: Derived from the containing dataset directory.
        extra: Additional fields not in the core schema.
    """

    id: str
    cwe: str
    severity: str
    label: str
    language: str
    code: str
    description: str
    fix: str
    attack_scenario: str
    vuln_class: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dictionary."""
        return {
            "id": self.id,
            "cwe": self.cwe,
            "severity": self.severity,
            "label": self.label,
            "language": self.language,
            "code": self.code,
            "description": self.description,
            "fix": self.fix,
            "attack_scenario": self.attack_scenario,
            "vuln_class": self.vuln_class,
            **self.extra,
        }

    def __repr__(self) -> str:
        return (
            f"BenchmarkSample(id={self.id!r}, cwe={self.cwe!r}, "
            f"severity={self.severity!r}, label={self.label!r})"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clean_code(code: str) -> str:
    """
    Strip markdown code fences from a code string.

    Handles patterns like::

        ```python
        import os
        ```

    or plain ````` ``` ````` without a language tag. Returns the inner code
    with any trailing whitespace trimmed.

    Args:
        code: Raw code string, potentially wrapped in markdown fences.

    Returns:
        Cleaned code string without fence markers.
    """
    stripped = code.strip()
    match = _CODE_FENCE_RE.match(stripped)
    if match:
        return match.group(1).rstrip()
    return stripped


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


class ValidationError(Exception):
    """Raised when a JSONL sample fails schema validation."""


class BenchmarkLoader:
    """
    Loads and validates the redbench benchmark dataset.

    By default reads from the datasets/ directory adjacent to this package.
    Can be pointed at a custom dataset directory.

    The ``source_files`` parameter controls which JSONL filenames are searched
    in each class directory (in order).  If the first name does not exist the
    loader tries the next, allowing transparent fallback from canonical
    ``samples.jsonl`` to ``samples_generated_v3.jsonl``.

    Example:
        >>> loader = BenchmarkLoader()
        >>> all_samples = loader.load_all()
        >>> idor_samples = loader.load_class("idor")
        >>> critical = loader.filter(severity="critical")

        # Load v3 generated data for classes that lack canonical files:
        >>> loader = BenchmarkLoader(
        ...     source_files=["samples.jsonl", "samples_generated_v3.jsonl"]
        ... )
    """

    def __init__(
        self,
        dataset_dir: str | None = None,
        source_files: list[str] | None = None,
    ) -> None:
        """
        Initialise the loader.

        Args:
            dataset_dir: Path to the directory containing vuln class
                         subdirectories. Defaults to the datasets/ directory
                         in the repository root (two levels up from this file).
            source_files: Ordered list of JSONL filenames to try when loading
                          each class. The first file that exists is used.
                          Defaults to ``["samples.jsonl"]``.

        Raises:
            TypeError: If dataset_dir is provided but is not a string.
            TypeError: If source_files is provided but is not a list of strings.
        """
        if dataset_dir is not None and not isinstance(dataset_dir, str):
            raise TypeError(f"dataset_dir must be str or None, got {type(dataset_dir).__name__}")
        if dataset_dir is not None:
            self.dataset_dir = Path(dataset_dir)
        else:
            # Default: <repo_root>/datasets/
            self.dataset_dir = Path(__file__).resolve().parent.parent / "datasets"

        if source_files is None:
            self.source_files: list[str] = ["samples.jsonl"]
        else:
            if not isinstance(source_files, list) or not all(
                isinstance(f, str) for f in source_files
            ):
                raise TypeError("source_files must be a list of strings or None")
            if not source_files:
                raise ValueError("source_files must contain at least one filename")
            self.source_files = source_files

        self._cache: dict[str, list[BenchmarkSample]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_all(self, validate: bool = True) -> list[BenchmarkSample]:
        """
        Load all samples from all vulnerability classes.

        Args:
            validate: Whether to validate each sample's schema.

        Returns:
            Combined list of all BenchmarkSample objects.

        Raises:
            ValidationError: If validate=True and a sample is malformed.
            FileNotFoundError: If the dataset directory does not exist.
        """
        self._ensure_dataset_dir_exists()
        all_samples: list[BenchmarkSample] = []
        for vuln_class in VULN_CLASSES:
            if self._resolve_class_path(vuln_class) is not None:
                all_samples.extend(self.load_class(vuln_class, validate=validate))
        return all_samples

    def load_class(self, vuln_class: str, validate: bool = True) -> list[BenchmarkSample]:
        """
        Load all samples for a specific vulnerability class.

        Args:
            vuln_class: One of the 17 known vulnerability class names.
            validate: Whether to validate each sample's schema.

        Returns:
            List of BenchmarkSample for the requested class.

        Raises:
            ValueError: If vuln_class is not recognised.
            FileNotFoundError: If no source file exists for this class.
            ValidationError: If validate=True and a sample is malformed.
        """
        if vuln_class not in VULN_CLASSES:
            raise ValueError(
                f"Unknown vulnerability class {vuln_class!r}. "
                f"Valid classes: {sorted(VULN_CLASSES)}"
            )

        # Return cached result if available
        cache_key = f"{vuln_class}::{':'.join(self.source_files)}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        jsonl_path = self._resolve_class_path(vuln_class)
        if jsonl_path is None:
            tried = [str(self.dataset_dir / vuln_class / f) for f in self.source_files]
            raise FileNotFoundError(
                f"No dataset file found for class {vuln_class!r}. "
                f"Tried: {tried}"
            )

        samples: list[BenchmarkSample] = []
        with open(jsonl_path, encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    raw: dict[str, Any] = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValidationError(
                        f"JSON parse error in {jsonl_path}:{lineno}: {exc}"
                    ) from exc
                if validate:
                    self._validate_sample(raw, jsonl_path, lineno)
                sample = self._deserialise(raw, vuln_class)
                samples.append(sample)

        self._cache[cache_key] = samples
        return samples

    def filter(
        self,
        vuln_class: str | None = None,
        severity: str | None = None,
        label: str | None = None,
        cwe: str | None = None,
        language: str | None = None,
    ) -> list[BenchmarkSample]:
        """
        Filter the loaded dataset by one or more criteria.

        Args:
            vuln_class: Filter by vulnerability class.
            severity: Filter by severity level.
            label: Filter by ground truth label ("vulnerable" | "safe").
            cwe: Filter by CWE identifier (e.g. "CWE-89").
            language: Filter by programming language.

        Returns:
            Filtered list of BenchmarkSample objects.
        """
        samples = self.load_all()
        if vuln_class is not None:
            samples = [s for s in samples if s.vuln_class == vuln_class]
        if severity is not None:
            samples = [s for s in samples if s.severity == severity]
        if label is not None:
            samples = [s for s in samples if s.label == label]
        if cwe is not None:
            samples = [s for s in samples if s.cwe == cwe]
        if language is not None:
            samples = [s for s in samples if s.language == language]
        return samples

    def iter_all(self) -> Iterator[BenchmarkSample]:
        """Iterate over all samples without loading everything into memory."""
        self._ensure_dataset_dir_exists()
        for vuln_class in VULN_CLASSES:
            jsonl_path = self._resolve_class_path(vuln_class)
            if jsonl_path is None:
                continue
            with open(jsonl_path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        raw = json.loads(line)
                        yield self._deserialise(raw, vuln_class)

    def stats(self) -> dict[str, Any]:
        """
        Return summary statistics about the loaded dataset.

        Returns:
            Dict with keys: total_samples, by_class, by_severity, by_cwe, by_label.
        """
        all_samples = self.load_all()
        by_class: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        by_cwe: dict[str, int] = {}
        by_label: dict[str, int] = {}

        for s in all_samples:
            by_class[s.vuln_class] = by_class.get(s.vuln_class, 0) + 1
            by_severity[s.severity] = by_severity.get(s.severity, 0) + 1
            by_cwe[s.cwe] = by_cwe.get(s.cwe, 0) + 1
            by_label[s.label] = by_label.get(s.label, 0) + 1

        return {
            "total_samples": len(all_samples),
            "by_class": by_class,
            "by_severity": by_severity,
            "by_cwe": by_cwe,
            "by_label": by_label,
        }

    def clear_cache(self) -> None:
        """Clear the in-memory sample cache."""
        self._cache.clear()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _resolve_class_path(self, vuln_class: str) -> Path | None:
        """
        Return the first existing source file path for a class, or None.

        Iterates ``self.source_files`` in order and returns the first Path
        that exists on disk.

        Args:
            vuln_class: Name of the vulnerability class directory.

        Returns:
            Resolved Path if a file exists, else None.
        """
        for fname in self.source_files:
            candidate = self.dataset_dir / vuln_class / fname
            if candidate.exists():
                return candidate
        return None

    def _ensure_dataset_dir_exists(self) -> None:
        if not self.dataset_dir.exists():
            raise FileNotFoundError(
                f"Dataset directory not found: {self.dataset_dir}. "
                "Clone the repository to access the bundled datasets."
            )

    def _validate_sample(
        self, raw: dict[str, Any], path: Path, lineno: int
    ) -> None:
        """Validate that a raw dict has all required fields and valid values."""
        missing = REQUIRED_FIELDS - set(raw.keys())
        if missing:
            raise ValidationError(
                f"Missing required fields {sorted(missing)} in {path}:{lineno}"
            )
        if raw["label"] not in VALID_LABELS:
            raise ValidationError(
                f"Invalid label {raw['label']!r} in {path}:{lineno}. "
                f"Must be one of {sorted(VALID_LABELS)}"
            )
        if raw["severity"] not in VALID_SEVERITIES:
            raise ValidationError(
                f"Invalid severity {raw['severity']!r} in {path}:{lineno}. "
                f"Must be one of {sorted(VALID_SEVERITIES)}"
            )
        # Clean code before checking emptiness so fenced code is not falsely rejected
        cleaned = _clean_code(raw.get("code", ""))
        if not cleaned:
            raise ValidationError(f"Empty code field in {path}:{lineno}")
        if not raw.get("cwe", "").upper().startswith("CWE-"):
            raise ValidationError(
                f"CWE must start with 'CWE-' in {path}:{lineno}, "
                f"got {raw.get('cwe')!r}"
            )

    def _deserialise(self, raw: dict[str, Any], vuln_class: str) -> BenchmarkSample:
        """Convert a raw dict to a BenchmarkSample, placing unknown fields in extra."""
        known = REQUIRED_FIELDS | OPTIONAL_KNOWN_FIELDS | {"vuln_class"}
        extra = {k: v for k, v in raw.items() if k not in known}
        return BenchmarkSample(
            id=raw["id"],
            cwe=raw["cwe"],
            severity=raw["severity"],
            label=raw["label"],
            language=raw["language"],
            code=_clean_code(raw["code"]),
            description=raw["description"],
            fix=_clean_code(raw.get("fix", "") or ""),
            attack_scenario=raw.get("attack_scenario", ""),
            vuln_class=vuln_class,
            extra=extra,
        )
