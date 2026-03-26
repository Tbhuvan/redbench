"""
Tests for redbench.loader — BenchmarkLoader, BenchmarkSample, ValidationError.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from redbench.loader import (
    BenchmarkLoader,
    BenchmarkSample,
    ValidationError,
    VULN_CLASSES,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SAMPLE_VALID = {
    "id": "idor-001",
    "cwe": "CWE-639",
    "severity": "critical",
    "label": "vulnerable",
    "language": "python",
    "code": "User.objects.get(id=user_id)",
    "description": "Direct object reference without ownership check",
    "fix": "User.objects.get(id=user_id, owner=request.user)",
    "attack_scenario": "Enumerate user IDs to read other users' data",
}


def write_samples(directory: Path, vuln_class: str, samples: list[dict]) -> Path:
    """Write a list of samples as JSONL to a temp dataset directory."""
    class_dir = directory / vuln_class
    class_dir.mkdir(parents=True)
    jsonl_path = class_dir / "samples.jsonl"
    with open(jsonl_path, "w") as f:
        for s in samples:
            f.write(json.dumps(s) + "\n")
    return jsonl_path


@pytest.fixture()
def temp_dataset(tmp_path: Path) -> Path:
    """Create a minimal temporary dataset directory with one IDOR sample."""
    write_samples(tmp_path, "idor", [SAMPLE_VALID])
    return tmp_path


@pytest.fixture()
def full_dataset() -> Path:
    """Return the actual redbench dataset path."""
    return Path(__file__).resolve().parent.parent / "datasets"


# ---------------------------------------------------------------------------
# BenchmarkLoader construction
# ---------------------------------------------------------------------------


class TestBenchmarkLoaderConstruction:
    def test_default_dataset_dir(self) -> None:
        loader = BenchmarkLoader()
        assert "datasets" in str(loader.dataset_dir)

    def test_custom_dataset_dir(self, temp_dataset: Path) -> None:
        loader = BenchmarkLoader(dataset_dir=str(temp_dataset))
        assert loader.dataset_dir == temp_dataset

    def test_type_error_on_non_string(self) -> None:
        with pytest.raises(TypeError):
            BenchmarkLoader(dataset_dir=42)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# load_class
# ---------------------------------------------------------------------------


class TestLoadClass:
    def test_loads_idor_samples(self, temp_dataset: Path) -> None:
        loader = BenchmarkLoader(dataset_dir=str(temp_dataset))
        samples = loader.load_class("idor")
        assert len(samples) == 1
        assert isinstance(samples[0], BenchmarkSample)

    def test_sample_fields(self, temp_dataset: Path) -> None:
        loader = BenchmarkLoader(dataset_dir=str(temp_dataset))
        s = loader.load_class("idor")[0]
        assert s.id == "idor-001"
        assert s.cwe == "CWE-639"
        assert s.severity == "critical"
        assert s.label == "vulnerable"
        assert s.vuln_class == "idor"

    def test_invalid_class_raises_value_error(self, temp_dataset: Path) -> None:
        loader = BenchmarkLoader(dataset_dir=str(temp_dataset))
        with pytest.raises(ValueError, match="Unknown vulnerability class"):
            loader.load_class("not_a_real_class")

    def test_missing_file_raises_file_not_found(self, tmp_path: Path) -> None:
        loader = BenchmarkLoader(dataset_dir=str(tmp_path))
        with pytest.raises(FileNotFoundError):
            loader.load_class("idor")

    def test_caching(self, temp_dataset: Path) -> None:
        loader = BenchmarkLoader(dataset_dir=str(temp_dataset))
        first = loader.load_class("idor")
        second = loader.load_class("idor")
        assert first is second  # same list object from cache

    def test_clear_cache(self, temp_dataset: Path) -> None:
        loader = BenchmarkLoader(dataset_dir=str(temp_dataset))
        loader.load_class("idor")
        loader.clear_cache()
        # After clearing, no entries should remain
        assert len(loader._cache) == 0


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


class TestValidation:
    def test_missing_field_raises_validation_error(self, tmp_path: Path) -> None:
        bad_sample = {k: v for k, v in SAMPLE_VALID.items() if k != "code"}
        write_samples(tmp_path, "idor", [bad_sample])
        loader = BenchmarkLoader(dataset_dir=str(tmp_path))
        with pytest.raises(ValidationError, match="Missing required fields"):
            loader.load_class("idor")

    def test_invalid_label_raises_validation_error(self, tmp_path: Path) -> None:
        bad = {**SAMPLE_VALID, "label": "VULNERABLE"}  # wrong case
        write_samples(tmp_path, "idor", [bad])
        loader = BenchmarkLoader(dataset_dir=str(tmp_path))
        with pytest.raises(ValidationError, match="Invalid label"):
            loader.load_class("idor")

    def test_invalid_severity_raises(self, tmp_path: Path) -> None:
        bad = {**SAMPLE_VALID, "severity": "ultra-critical"}
        write_samples(tmp_path, "idor", [bad])
        loader = BenchmarkLoader(dataset_dir=str(tmp_path))
        with pytest.raises(ValidationError, match="Invalid severity"):
            loader.load_class("idor")

    def test_invalid_cwe_format_raises(self, tmp_path: Path) -> None:
        bad = {**SAMPLE_VALID, "cwe": "639"}  # missing CWE- prefix
        write_samples(tmp_path, "idor", [bad])
        loader = BenchmarkLoader(dataset_dir=str(tmp_path))
        with pytest.raises(ValidationError, match="CWE must start with"):
            loader.load_class("idor")

    def test_empty_code_raises(self, tmp_path: Path) -> None:
        bad = {**SAMPLE_VALID, "code": "   "}
        write_samples(tmp_path, "idor", [bad])
        loader = BenchmarkLoader(dataset_dir=str(tmp_path))
        with pytest.raises(ValidationError, match="Empty code"):
            loader.load_class("idor")

    def test_invalid_json_raises(self, tmp_path: Path) -> None:
        class_dir = tmp_path / "idor"
        class_dir.mkdir()
        (class_dir / "samples.jsonl").write_text("{bad json\n")
        loader = BenchmarkLoader(dataset_dir=str(tmp_path))
        with pytest.raises(ValidationError, match="JSON parse error"):
            loader.load_class("idor")

    def test_skips_blank_lines(self, tmp_path: Path) -> None:
        class_dir = tmp_path / "idor"
        class_dir.mkdir()
        (class_dir / "samples.jsonl").write_text(
            "\n" + json.dumps(SAMPLE_VALID) + "\n\n"
        )
        loader = BenchmarkLoader(dataset_dir=str(tmp_path))
        samples = loader.load_class("idor")
        assert len(samples) == 1

    def test_validation_disabled(self, tmp_path: Path) -> None:
        bad = {**SAMPLE_VALID, "label": "WRONG"}
        write_samples(tmp_path, "idor", [bad])
        loader = BenchmarkLoader(dataset_dir=str(tmp_path))
        # Should not raise when validate=False
        samples = loader.load_class("idor", validate=False)
        assert len(samples) == 1


# ---------------------------------------------------------------------------
# load_all
# ---------------------------------------------------------------------------


class TestLoadAll:
    def test_loads_all_classes(self, tmp_path: Path) -> None:
        for vc in VULN_CLASSES:
            sample = {**SAMPLE_VALID, "id": f"{vc}-001"}
            write_samples(tmp_path, vc, [sample])
        loader = BenchmarkLoader(dataset_dir=str(tmp_path))
        all_samples = loader.load_all()
        assert len(all_samples) == len(VULN_CLASSES)

    def test_skips_missing_class_directory(self, temp_dataset: Path) -> None:
        # Only idor is present; other classes are absent — should not raise
        loader = BenchmarkLoader(dataset_dir=str(temp_dataset))
        samples = loader.load_all()
        assert len(samples) >= 1

    def test_missing_dataset_dir_raises(self, tmp_path: Path) -> None:
        loader = BenchmarkLoader(dataset_dir=str(tmp_path / "nonexistent"))
        with pytest.raises(FileNotFoundError):
            loader.load_all()


# ---------------------------------------------------------------------------
# filter
# ---------------------------------------------------------------------------


class TestFilter:
    def test_filter_by_vuln_class(self, tmp_path: Path) -> None:
        for vc in ("idor", "sqli"):
            sample = {**SAMPLE_VALID, "id": f"{vc}-001"}
            write_samples(tmp_path, vc, [sample])
        loader = BenchmarkLoader(dataset_dir=str(tmp_path))
        filtered = loader.filter(vuln_class="idor")
        assert all(s.vuln_class == "idor" for s in filtered)

    def test_filter_by_severity(self, tmp_path: Path) -> None:
        write_samples(tmp_path, "idor", [SAMPLE_VALID])
        loader = BenchmarkLoader(dataset_dir=str(tmp_path))
        critical = loader.filter(severity="critical")
        high = loader.filter(severity="high")
        assert len(critical) == 1
        assert len(high) == 0

    def test_filter_by_label(self, tmp_path: Path) -> None:
        write_samples(tmp_path, "idor", [SAMPLE_VALID])
        loader = BenchmarkLoader(dataset_dir=str(tmp_path))
        vuln = loader.filter(label="vulnerable")
        safe = loader.filter(label="safe")
        assert len(vuln) == 1
        assert len(safe) == 0


# ---------------------------------------------------------------------------
# BenchmarkSample
# ---------------------------------------------------------------------------


class TestBenchmarkSample:
    def test_to_dict(self) -> None:
        s = BenchmarkSample(**{**SAMPLE_VALID, "vuln_class": "idor"})
        d = s.to_dict()
        assert d["id"] == "idor-001"
        assert d["vuln_class"] == "idor"

    def test_repr(self) -> None:
        s = BenchmarkSample(**{**SAMPLE_VALID, "vuln_class": "idor"})
        r = repr(s)
        assert "idor-001" in r
        assert "CWE-639" in r


# ---------------------------------------------------------------------------
# Integration: load real dataset files
# ---------------------------------------------------------------------------


class TestRealDataset:
    @pytest.mark.skipif(
        not (Path(__file__).resolve().parent.parent / "datasets" / "idor" / "samples.jsonl").exists(),
        reason="Real dataset files not present",
    )
    def test_loads_real_idor_samples(self, full_dataset: Path) -> None:
        loader = BenchmarkLoader(dataset_dir=str(full_dataset))
        samples = loader.load_class("idor")
        assert len(samples) == 10
        for s in samples:
            assert s.cwe == "CWE-639"
            assert s.label == "vulnerable"
            assert s.language == "python"

    @pytest.mark.skipif(
        not (Path(__file__).resolve().parent.parent / "datasets" / "sqli" / "samples.jsonl").exists(),
        reason="Real dataset files not present",
    )
    def test_loads_real_sqli_samples(self, full_dataset: Path) -> None:
        loader = BenchmarkLoader(dataset_dir=str(full_dataset))
        samples = loader.load_class("sqli")
        assert len(samples) == 10
        assert all(s.cwe == "CWE-89" for s in samples)

    @pytest.mark.skipif(
        not (Path(__file__).resolve().parent.parent / "datasets").exists(),
        reason="Real dataset files not present",
    )
    def test_total_sample_count(self, full_dataset: Path) -> None:
        # 5 original classes × 10 samples + 12 new classes × 20 samples = 290
        loader = BenchmarkLoader(dataset_dir=str(full_dataset))
        all_samples = loader.load_all()
        assert len(all_samples) == 290  # 17 classes: 5×10 + 12×20

    @pytest.mark.skipif(
        not (Path(__file__).resolve().parent.parent / "datasets").exists(),
        reason="Real dataset files not present",
    )
    def test_stats(self, full_dataset: Path) -> None:
        loader = BenchmarkLoader(dataset_dir=str(full_dataset))
        stats = loader.stats()
        assert stats["total_samples"] == 290
        assert "idor" in stats["by_class"]
        assert stats["by_class"]["idor"] == 10
        # New classes should be present
        assert "command_injection" in stats["by_class"]
        assert stats["by_class"]["command_injection"] == 20
