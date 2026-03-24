"""
Benchmark evaluation framework for redbench.

Evaluates any vulnerability detection tool (a callable that takes code and
returns a prediction dict) against the redbench dataset. Computes per-class
and overall precision, recall, F1, FPR, and TPR.
"""

from __future__ import annotations

from typing import Any, Callable

from .loader import BenchmarkLoader, BenchmarkSample, VULN_CLASSES


# Type alias for a detection tool
DetectionTool = Callable[[str], dict[str, Any]]


class EvaluationError(Exception):
    """Raised when tool output does not conform to the expected schema."""


def _safe_divide(numerator: float, denominator: float, default: float = 0.0) -> float:
    """Safe division returning default when denominator is zero."""
    return numerator / denominator if denominator != 0 else default


class BenchmarkEvaluator:
    """
    Evaluates any vulnerability detection tool against the redbench dataset.

    Tool interface:
        The tool must be a callable with signature:
            tool(code: str) -> dict

        The returned dict must contain at minimum:
            {"label": "vulnerable" | "safe"}

        Any additional fields are ignored.

    Metrics computed:
        - Precision: TP / (TP + FP) — of flagged samples, how many are truly vulnerable?
        - Recall (TPR): TP / (TP + FN) — of truly vulnerable samples, how many were caught?
        - F1: harmonic mean of precision and recall.
        - FPR: FP / (FP + TN) — of truly safe samples, how many were falsely flagged?

    Example:
        >>> def my_tool(code: str) -> dict:
        ...     return {"label": "vulnerable" if "objects.get(id=" in code else "safe"}
        >>> evaluator = BenchmarkEvaluator()
        >>> results = evaluator.evaluate(my_tool)
        >>> print(results["overall"]["f1"])
    """

    def __init__(self, dataset_dir: str | None = None) -> None:
        """
        Initialise the evaluator.

        Args:
            dataset_dir: Path to the dataset directory. Defaults to the
                         bundled datasets/ directory.
        """
        self._loader = BenchmarkLoader(dataset_dir=dataset_dir)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(
        self,
        tool: DetectionTool,
        vuln_classes: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Evaluate a detection tool against the benchmark dataset.

        Args:
            tool: Callable that takes a code snippet (str) and returns a dict
                  with at least {"label": "vulnerable" | "safe"}.
            vuln_classes: Subset of vulnerability classes to evaluate against.
                          Defaults to all five classes.

        Returns:
            Dict with structure:
            {
                "overall": {
                    "precision": float, "recall": float, "f1": float,
                    "fpr": float, "accuracy": float,
                    "tp": int, "fp": int, "tn": int, "fn": int
                },
                "per_class": {
                    "idor": {"precision": ..., "recall": ..., "f1": ..., ...},
                    ...
                },
                "n_samples": int,
                "n_correct": int,
                "predictions": list[dict]   # per-sample results
            }

        Raises:
            TypeError: If tool is not callable.
            EvaluationError: If the tool returns a malformed prediction.
        """
        if not callable(tool):
            raise TypeError(f"tool must be callable, got {type(tool).__name__}")

        classes = self._validate_vuln_classes(vuln_classes)
        samples = []
        for vc in classes:
            try:
                samples.extend(self._loader.load_class(vc))
            except FileNotFoundError:
                pass  # Skip missing class files gracefully

        if not samples:
            return self._empty_result()

        predictions: list[dict[str, Any]] = []
        all_tp = all_fp = all_tn = all_fn = 0
        per_class_counts: dict[str, dict[str, int]] = {
            vc: {"tp": 0, "fp": 0, "tn": 0, "fn": 0} for vc in classes
        }

        for sample in samples:
            pred = self._run_tool(tool, sample)
            predictions.append(pred)

            predicted_label = pred["predicted_label"]
            true_label = sample.label
            vc = sample.vuln_class

            # Compute TP/FP/TN/FN
            # Positive = "vulnerable", Negative = "safe"
            if true_label == "vulnerable" and predicted_label == "vulnerable":
                all_tp += 1
                per_class_counts[vc]["tp"] += 1
            elif true_label == "safe" and predicted_label == "vulnerable":
                all_fp += 1
                per_class_counts[vc]["fp"] += 1
            elif true_label == "safe" and predicted_label == "safe":
                all_tn += 1
                per_class_counts[vc]["tn"] += 1
            elif true_label == "vulnerable" and predicted_label == "safe":
                all_fn += 1
                per_class_counts[vc]["fn"] += 1

        overall = self._compute_metrics(all_tp, all_fp, all_tn, all_fn)
        per_class = {}
        for vc, counts in per_class_counts.items():
            per_class[vc] = self._compute_metrics(
                counts["tp"], counts["fp"], counts["tn"], counts["fn"]
            )

        n_correct = sum(
            1 for p in predictions if p["predicted_label"] == p["true_label"]
        )

        return {
            "overall": overall,
            "per_class": per_class,
            "n_samples": len(samples),
            "n_correct": n_correct,
            "predictions": predictions,
        }

    def compare_tools(
        self,
        tools: dict[str, DetectionTool],
        vuln_classes: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Compare multiple detection tools side-by-side.

        Args:
            tools: Dict mapping tool names to callable tools.
            vuln_classes: Subset of vulnerability classes to evaluate.

        Returns:
            Dict mapping tool names to their evaluation results.

        Raises:
            TypeError: If tools is not a dict.
        """
        if not isinstance(tools, dict):
            raise TypeError(f"tools must be a dict, got {type(tools).__name__}")
        if not tools:
            raise ValueError("tools dict must not be empty")

        comparison: dict[str, Any] = {}
        for name, tool in tools.items():
            if not isinstance(name, str) or not name.strip():
                raise ValueError(f"Tool name must be a non-empty string, got {name!r}")
            comparison[name] = self.evaluate(tool, vuln_classes=vuln_classes)

        # Build a summary table
        summary_rows: list[dict[str, Any]] = []
        for name, result in comparison.items():
            overall = result["overall"]
            summary_rows.append(
                {
                    "tool": name,
                    "precision": overall["precision"],
                    "recall": overall["recall"],
                    "f1": overall["f1"],
                    "fpr": overall["fpr"],
                    "accuracy": overall["accuracy"],
                    "n_samples": result["n_samples"],
                }
            )
        summary_rows.sort(key=lambda r: r["f1"], reverse=True)

        return {"tools": comparison, "summary": summary_rows}

    def generate_latex_table(self, results: dict[str, Any]) -> str:
        """
        Generate a LaTeX table from compare_tools() results for paper submission.

        Args:
            results: Return value from compare_tools().

        Returns:
            LaTeX tabular environment string.

        Raises:
            ValueError: If results does not have the expected structure.
        """
        if "summary" not in results:
            raise ValueError("results must be the return value of compare_tools()")

        lines: list[str] = [
            r"\begin{table}[ht]",
            r"\centering",
            r"\caption{Comparison of vulnerability detection tools on redbench}",
            r"\label{tab:redbench-comparison}",
            r"\begin{tabular}{lrrrrr}",
            r"\toprule",
            r"Tool & Precision & Recall & F1 & FPR & Accuracy \\",
            r"\midrule",
        ]
        for row in results["summary"]:
            lines.append(
                f"  {self._latex_escape(row['tool'])} & "
                f"{row['precision']:.3f} & "
                f"{row['recall']:.3f} & "
                f"\\textbf{{{row['f1']:.3f}}} & "
                f"{row['fpr']:.3f} & "
                f"{row['accuracy']:.3f} \\\\"
            )
        lines += [
            r"\bottomrule",
            r"\end{tabular}",
            r"\end{table}",
        ]
        return "\n".join(lines)

    def per_class_latex_table(self, result: dict[str, Any], tool_name: str = "Tool") -> str:
        """
        Generate a per-class LaTeX table from a single evaluate() result.

        Args:
            result: Return value from evaluate().
            tool_name: Name of the tool for the caption.

        Returns:
            LaTeX tabular environment string.
        """
        if "per_class" not in result:
            raise ValueError("result must be the return value of evaluate()")

        lines: list[str] = [
            r"\begin{table}[ht]",
            r"\centering",
            f"\\caption{{Per-class results for {self._latex_escape(tool_name)} on redbench}}",
            r"\label{tab:per-class}",
            r"\begin{tabular}{lrrrr}",
            r"\toprule",
            r"Vulnerability Class & Precision & Recall & F1 & FPR \\",
            r"\midrule",
        ]
        for vc, metrics in sorted(result["per_class"].items()):
            vc_escaped = vc.replace("_", r"\_")
            lines.append(
                f"  {vc_escaped} & "
                f"{metrics['precision']:.3f} & "
                f"{metrics['recall']:.3f} & "
                f"\\textbf{{{metrics['f1']:.3f}}} & "
                f"{metrics['fpr']:.3f} \\\\"
            )
        overall = result["overall"]
        lines.append(r"\midrule")
        lines.append(
            f"  \\textbf{{Overall}} & "
            f"{overall['precision']:.3f} & "
            f"{overall['recall']:.3f} & "
            f"\\textbf{{{overall['f1']:.3f}}} & "
            f"{overall['fpr']:.3f} \\\\"
        )
        lines += [
            r"\bottomrule",
            r"\end{tabular}",
            r"\end{table}",
        ]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _run_tool(self, tool: DetectionTool, sample: BenchmarkSample) -> dict[str, Any]:
        """Run the tool on a single sample and return the prediction dict."""
        try:
            output = tool(sample.code)
        except Exception as exc:
            # Tool crashed — treat as missed detection
            output = {"label": "safe", "error": str(exc)}

        if not isinstance(output, dict):
            raise EvaluationError(
                f"Tool must return a dict, got {type(output).__name__} "
                f"for sample {sample.id!r}"
            )
        if "label" not in output:
            raise EvaluationError(
                f"Tool output must contain 'label' key for sample {sample.id!r}. "
                f"Got keys: {sorted(output.keys())}"
            )
        predicted_label = output["label"]
        if predicted_label not in ("vulnerable", "safe"):
            # Normalise unknown labels to "safe" (conservative)
            predicted_label = "safe"

        return {
            "sample_id": sample.id,
            "vuln_class": sample.vuln_class,
            "true_label": sample.label,
            "predicted_label": predicted_label,
            "correct": predicted_label == sample.label,
            "tool_output": output,
        }

    def _compute_metrics(
        self, tp: int, fp: int, tn: int, fn: int
    ) -> dict[str, Any]:
        """Compute precision, recall, F1, FPR, and accuracy from confusion matrix."""
        precision = _safe_divide(tp, tp + fp)
        recall = _safe_divide(tp, tp + fn)
        f1 = _safe_divide(2 * precision * recall, precision + recall)
        fpr = _safe_divide(fp, fp + tn)
        accuracy = _safe_divide(tp + tn, tp + fp + tn + fn)
        return {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "fpr": round(fpr, 4),
            "accuracy": round(accuracy, 4),
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
        }

    def _validate_vuln_classes(self, vuln_classes: list[str] | None) -> list[str]:
        """Validate and return the list of vulnerability classes to evaluate."""
        if vuln_classes is None:
            return list(VULN_CLASSES)
        if not isinstance(vuln_classes, list):
            raise TypeError(
                f"vuln_classes must be a list or None, got {type(vuln_classes).__name__}"
            )
        invalid = set(vuln_classes) - set(VULN_CLASSES)
        if invalid:
            raise ValueError(
                f"Unknown vulnerability classes: {sorted(invalid)}. "
                f"Valid: {sorted(VULN_CLASSES)}"
            )
        return vuln_classes

    def _empty_result(self) -> dict[str, Any]:
        """Return an empty result structure when no samples are loaded."""
        return {
            "overall": self._compute_metrics(0, 0, 0, 0),
            "per_class": {},
            "n_samples": 0,
            "n_correct": 0,
            "predictions": [],
        }

    @staticmethod
    def _latex_escape(text: str) -> str:
        """Escape special LaTeX characters in text."""
        replacements = {
            "&": r"\&",
            "%": r"\%",
            "$": r"\$",
            "#": r"\#",
            "_": r"\_",
            "{": r"\{",
            "}": r"\}",
            "~": r"\textasciitilde{}",
            "^": r"\^{}",
            "\\": r"\textbackslash{}",
        }
        for char, replacement in replacements.items():
            text = text.replace(char, replacement)
        return text
