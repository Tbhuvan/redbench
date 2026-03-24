"""
Tests for redbench.evaluator — BenchmarkEvaluator
and redbench.reporter — BenchmarkReporter.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from redbench.evaluator import BenchmarkEvaluator, EvaluationError
from redbench.reporter import BenchmarkReporter


# ---------------------------------------------------------------------------
# Helpers: build a minimal temp dataset
# ---------------------------------------------------------------------------

SAMPLE_VULN = {
    "id": "idor-001",
    "cwe": "CWE-639",
    "severity": "critical",
    "label": "vulnerable",
    "language": "python",
    "code": "User.objects.get(id=user_id)",
    "description": "IDOR",
    "fix": "User.objects.get(id=user_id, owner=request.user)",
    "attack_scenario": "Enumerate IDs",
}

SAMPLE_SAFE = {
    "id": "idor-002",
    "cwe": "CWE-639",
    "severity": "critical",
    "label": "safe",
    "language": "python",
    "code": "User.objects.get(id=user_id, owner=request.user)",
    "description": "Safe IDOR",
    "fix": "Already safe",
    "attack_scenario": "None",
}


def write_samples(directory: Path, vuln_class: str, samples: list[dict]) -> None:
    class_dir = directory / vuln_class
    class_dir.mkdir(parents=True, exist_ok=True)
    with open(class_dir / "samples.jsonl", "w") as f:
        for s in samples:
            f.write(json.dumps(s) + "\n")


@pytest.fixture()
def two_sample_dataset(tmp_path: Path) -> Path:
    write_samples(tmp_path, "idor", [SAMPLE_VULN, SAMPLE_SAFE])
    return tmp_path


@pytest.fixture()
def real_dataset_dir() -> Path | None:
    p = Path(__file__).resolve().parent.parent / "datasets"
    return p if p.exists() else None


# ---------------------------------------------------------------------------
# BenchmarkEvaluator — construction
# ---------------------------------------------------------------------------


class TestEvaluatorConstruction:
    def test_default_dataset_dir(self) -> None:
        ev = BenchmarkEvaluator()
        assert ev._loader is not None

    def test_custom_dataset_dir(self, two_sample_dataset: Path) -> None:
        ev = BenchmarkEvaluator(dataset_dir=str(two_sample_dataset))
        assert ev._loader.dataset_dir == two_sample_dataset


# ---------------------------------------------------------------------------
# BenchmarkEvaluator — evaluate
# ---------------------------------------------------------------------------


class TestEvaluatorEvaluate:
    def test_perfect_tool(self, two_sample_dataset: Path) -> None:
        """A tool that always returns the correct label gets F1=1."""
        def perfect_tool(code: str) -> dict:
            if "owner=request.user" in code:
                return {"label": "safe"}
            return {"label": "vulnerable"}

        ev = BenchmarkEvaluator(dataset_dir=str(two_sample_dataset))
        results = ev.evaluate(perfect_tool, vuln_classes=["idor"])
        assert results["overall"]["f1"] == 1.0
        assert results["overall"]["precision"] == 1.0
        assert results["overall"]["recall"] == 1.0
        assert results["overall"]["fpr"] == 0.0

    def test_always_vulnerable_tool(self, two_sample_dataset: Path) -> None:
        """A tool that always says vulnerable has recall=1 but fpr=1."""
        def always_vuln(code: str) -> dict:
            return {"label": "vulnerable"}

        ev = BenchmarkEvaluator(dataset_dir=str(two_sample_dataset))
        results = ev.evaluate(always_vuln, vuln_classes=["idor"])
        assert results["overall"]["recall"] == 1.0
        assert results["overall"]["fpr"] == 1.0
        assert results["overall"]["tn"] == 0

    def test_always_safe_tool(self, two_sample_dataset: Path) -> None:
        """A tool that always says safe misses everything."""
        def always_safe(code: str) -> dict:
            return {"label": "safe"}

        ev = BenchmarkEvaluator(dataset_dir=str(two_sample_dataset))
        results = ev.evaluate(always_safe, vuln_classes=["idor"])
        assert results["overall"]["recall"] == 0.0
        assert results["overall"]["fn"] == 1  # one vulnerable sample missed
        assert results["overall"]["tp"] == 0

    def test_type_error_on_non_callable(self, two_sample_dataset: Path) -> None:
        ev = BenchmarkEvaluator(dataset_dir=str(two_sample_dataset))
        with pytest.raises(TypeError, match="callable"):
            ev.evaluate("not_a_function")  # type: ignore[arg-type]

    def test_result_structure(self, two_sample_dataset: Path) -> None:
        ev = BenchmarkEvaluator(dataset_dir=str(two_sample_dataset))
        results = ev.evaluate(lambda c: {"label": "safe"}, vuln_classes=["idor"])
        assert "overall" in results
        assert "per_class" in results
        assert "n_samples" in results
        assert "n_correct" in results
        assert "predictions" in results

    def test_n_samples_matches(self, two_sample_dataset: Path) -> None:
        ev = BenchmarkEvaluator(dataset_dir=str(two_sample_dataset))
        results = ev.evaluate(lambda c: {"label": "safe"}, vuln_classes=["idor"])
        assert results["n_samples"] == 2

    def test_predictions_list_populated(self, two_sample_dataset: Path) -> None:
        ev = BenchmarkEvaluator(dataset_dir=str(two_sample_dataset))
        results = ev.evaluate(lambda c: {"label": "vulnerable"}, vuln_classes=["idor"])
        assert len(results["predictions"]) == 2
        for p in results["predictions"]:
            assert "sample_id" in p
            assert "true_label" in p
            assert "predicted_label" in p
            assert "correct" in p

    def test_tool_exception_treated_as_safe(self, two_sample_dataset: Path) -> None:
        """A tool that crashes should be treated as 'safe' (not crash the evaluator)."""
        def crashing_tool(code: str) -> dict:
            raise RuntimeError("tool crashed")

        ev = BenchmarkEvaluator(dataset_dir=str(two_sample_dataset))
        results = ev.evaluate(crashing_tool, vuln_classes=["idor"])
        # Should not raise; crashing tool treated as "safe"
        assert results["n_samples"] == 2

    def test_invalid_vuln_class_raises(self, two_sample_dataset: Path) -> None:
        ev = BenchmarkEvaluator(dataset_dir=str(two_sample_dataset))
        with pytest.raises(ValueError, match="Unknown vulnerability class"):
            ev.evaluate(lambda c: {"label": "safe"}, vuln_classes=["xss"])

    def test_invalid_vuln_classes_type(self, two_sample_dataset: Path) -> None:
        ev = BenchmarkEvaluator(dataset_dir=str(two_sample_dataset))
        with pytest.raises(TypeError):
            ev.evaluate(lambda c: {"label": "safe"}, vuln_classes="idor")  # type: ignore[arg-type]

    def test_tool_without_label_key_raises(self, two_sample_dataset: Path) -> None:
        def bad_tool(code: str) -> dict:
            return {"score": 0.9}  # missing 'label'

        ev = BenchmarkEvaluator(dataset_dir=str(two_sample_dataset))
        with pytest.raises(EvaluationError, match="label"):
            ev.evaluate(bad_tool, vuln_classes=["idor"])

    def test_tool_returning_non_dict_raises(self, two_sample_dataset: Path) -> None:
        def bad_tool(code: str) -> str:  # type: ignore[return]
            return "vulnerable"

        ev = BenchmarkEvaluator(dataset_dir=str(two_sample_dataset))
        with pytest.raises(EvaluationError, match="dict"):
            ev.evaluate(bad_tool, vuln_classes=["idor"])  # type: ignore[arg-type]

    def test_per_class_present(self, two_sample_dataset: Path) -> None:
        ev = BenchmarkEvaluator(dataset_dir=str(two_sample_dataset))
        results = ev.evaluate(lambda c: {"label": "vulnerable"}, vuln_classes=["idor"])
        assert "idor" in results["per_class"]

    def test_metrics_are_floats(self, two_sample_dataset: Path) -> None:
        ev = BenchmarkEvaluator(dataset_dir=str(two_sample_dataset))
        results = ev.evaluate(lambda c: {"label": "vulnerable"}, vuln_classes=["idor"])
        overall = results["overall"]
        for metric in ("precision", "recall", "f1", "fpr", "accuracy"):
            assert isinstance(overall[metric], float)


# ---------------------------------------------------------------------------
# BenchmarkEvaluator — compare_tools
# ---------------------------------------------------------------------------


class TestCompareTools:
    def test_compare_two_tools(self, two_sample_dataset: Path) -> None:
        ev = BenchmarkEvaluator(dataset_dir=str(two_sample_dataset))
        tools = {
            "always_safe": lambda c: {"label": "safe"},
            "always_vuln": lambda c: {"label": "vulnerable"},
        }
        comparison = ev.compare_tools(tools, vuln_classes=["idor"])
        assert "tools" in comparison
        assert "summary" in comparison
        assert "always_safe" in comparison["tools"]
        assert "always_vuln" in comparison["tools"]

    def test_summary_sorted_by_f1(self, two_sample_dataset: Path) -> None:
        ev = BenchmarkEvaluator(dataset_dir=str(two_sample_dataset))
        tools = {
            "tool_a": lambda c: {"label": "vulnerable"},
            "tool_b": lambda c: {"label": "safe"},
        }
        comparison = ev.compare_tools(tools, vuln_classes=["idor"])
        f1_values = [row["f1"] for row in comparison["summary"]]
        assert f1_values == sorted(f1_values, reverse=True)

    def test_empty_tools_raises(self, two_sample_dataset: Path) -> None:
        ev = BenchmarkEvaluator(dataset_dir=str(two_sample_dataset))
        with pytest.raises(ValueError):
            ev.compare_tools({}, vuln_classes=["idor"])

    def test_non_dict_tools_raises(self, two_sample_dataset: Path) -> None:
        ev = BenchmarkEvaluator(dataset_dir=str(two_sample_dataset))
        with pytest.raises(TypeError):
            ev.compare_tools("not a dict")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# BenchmarkEvaluator — LaTeX generation
# ---------------------------------------------------------------------------


class TestLatexGeneration:
    def test_generate_latex_table(self, two_sample_dataset: Path) -> None:
        ev = BenchmarkEvaluator(dataset_dir=str(two_sample_dataset))
        tools = {"MyTool": lambda c: {"label": "safe"}}
        comparison = ev.compare_tools(tools, vuln_classes=["idor"])
        latex = ev.generate_latex_table(comparison)
        assert r"\begin{table}" in latex
        assert r"\end{table}" in latex
        assert r"\toprule" in latex
        assert "MyTool" in latex

    def test_per_class_latex_table(self, two_sample_dataset: Path) -> None:
        ev = BenchmarkEvaluator(dataset_dir=str(two_sample_dataset))
        results = ev.evaluate(lambda c: {"label": "safe"}, vuln_classes=["idor"])
        latex = ev.per_class_latex_table(results, tool_name="TestTool")
        assert r"\begin{table}" in latex
        assert "idor" in latex
        assert "Overall" in latex

    def test_latex_table_invalid_input(self, two_sample_dataset: Path) -> None:
        ev = BenchmarkEvaluator(dataset_dir=str(two_sample_dataset))
        with pytest.raises(ValueError):
            ev.generate_latex_table({"no_summary_key": True})


# ---------------------------------------------------------------------------
# BenchmarkReporter
# ---------------------------------------------------------------------------


class TestBenchmarkReporter:
    @pytest.fixture()
    def sample_results(self, two_sample_dataset: Path) -> dict:
        ev = BenchmarkEvaluator(dataset_dir=str(two_sample_dataset))
        return ev.evaluate(
            lambda c: {"label": "vulnerable" if "objects.get" in c else "safe"},
            vuln_classes=["idor"],
        )

    def test_markdown_returns_string(self, sample_results: dict) -> None:
        reporter = BenchmarkReporter(tool_name="TestTool")
        md = reporter.markdown(sample_results)
        assert isinstance(md, str)
        assert "TestTool" in md
        assert "## Overall Metrics" in md

    def test_markdown_contains_per_class(self, sample_results: dict) -> None:
        reporter = BenchmarkReporter(tool_name="TestTool")
        md = reporter.markdown(sample_results)
        assert "## Per-Class Results" in md
        assert "idor" in md

    def test_console_summary(self, sample_results: dict) -> None:
        reporter = BenchmarkReporter(tool_name="TestTool")
        summary = reporter.console_summary(sample_results)
        assert isinstance(summary, str)
        assert "TestTool" in summary
        assert "F1" in summary

    def test_to_json_valid(self, sample_results: dict) -> None:
        reporter = BenchmarkReporter(tool_name="TestTool")
        json_str = reporter.to_json(sample_results)
        parsed = json.loads(json_str)
        assert "overall" in parsed
        assert parsed["tool"] == "TestTool"

    def test_save_json(self, sample_results: dict, tmp_path: Path) -> None:
        reporter = BenchmarkReporter()
        out = tmp_path / "results.json"
        reporter.save_json(sample_results, str(out))
        assert out.exists()
        json.loads(out.read_text())  # Should not raise

    def test_save_markdown(self, sample_results: dict, tmp_path: Path) -> None:
        reporter = BenchmarkReporter()
        out = tmp_path / "report.md"
        reporter.save_markdown(sample_results, str(out))
        assert out.exists()
        assert len(out.read_text()) > 100

    def test_invalid_results_raises(self) -> None:
        reporter = BenchmarkReporter()
        with pytest.raises(ValueError):
            reporter.markdown({"bad": True})

    def test_type_error_on_non_string_name(self) -> None:
        with pytest.raises(TypeError):
            BenchmarkReporter(tool_name=42)  # type: ignore[arg-type]

    def test_fn_samples_listed_in_report(self, two_sample_dataset: Path) -> None:
        """Missed vulnerabilities should appear in the Markdown report."""
        ev = BenchmarkEvaluator(dataset_dir=str(two_sample_dataset))
        results = ev.evaluate(lambda c: {"label": "safe"}, vuln_classes=["idor"])
        reporter = BenchmarkReporter(tool_name="WeakTool")
        md = reporter.markdown(results)
        assert "Missed Vulnerabilities" in md

    def test_fp_samples_listed_in_report(self, two_sample_dataset: Path) -> None:
        """False positives should appear in the Markdown report."""
        ev = BenchmarkEvaluator(dataset_dir=str(two_sample_dataset))
        results = ev.evaluate(lambda c: {"label": "vulnerable"}, vuln_classes=["idor"])
        reporter = BenchmarkReporter(tool_name="NoisyTool")
        md = reporter.markdown(results)
        assert "False Positives" in md


# ---------------------------------------------------------------------------
# Integration: real dataset + evaluate
# ---------------------------------------------------------------------------


class TestRealDatasetEvaluation:
    @pytest.mark.skipif(
        not (Path(__file__).resolve().parent.parent / "datasets" / "idor" / "samples.jsonl").exists(),
        reason="Real dataset not present",
    )
    def test_evaluate_on_real_idor(self) -> None:
        ev = BenchmarkEvaluator()
        # Simple regex-based tool
        def regex_tool(code: str) -> dict:
            import re
            if re.search(r"objects\.get\s*\(\s*id\s*=", code):
                return {"label": "vulnerable"}
            return {"label": "safe"}

        results = ev.evaluate(regex_tool, vuln_classes=["idor"])
        assert results["n_samples"] == 10
        assert results["overall"]["recall"] > 0.0

    @pytest.mark.skipif(
        not (Path(__file__).resolve().parent.parent / "datasets").exists(),
        reason="Real dataset not present",
    )
    def test_evaluate_on_all_classes(self) -> None:
        ev = BenchmarkEvaluator()
        results = ev.evaluate(lambda c: {"label": "vulnerable"})
        assert results["n_samples"] == 50
        assert results["overall"]["recall"] == 1.0  # catches all vulnerables
