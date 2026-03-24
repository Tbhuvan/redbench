"""
redbench — Adversarial benchmark suite for LLM code security tools.

Provides 50 real, accurately described vulnerability samples across five
classes (IDOR, SQLi, SSRF, auth_bypass, path_traversal) plus an evaluation
framework for measuring precision, recall, and F1 of any detection tool.

Quick start:
    from redbench import BenchmarkLoader, BenchmarkEvaluator

    loader = BenchmarkLoader()
    samples = loader.load_all()

    def my_tool(code: str) -> dict:
        # returns {"label": "vulnerable" | "safe", ...}
        ...

    evaluator = BenchmarkEvaluator()
    results = evaluator.evaluate(my_tool)
    print(results['overall'])
"""

from .loader import BenchmarkLoader, BenchmarkSample
from .evaluator import BenchmarkEvaluator
from .reporter import BenchmarkReporter

__all__ = [
    "BenchmarkLoader",
    "BenchmarkSample",
    "BenchmarkEvaluator",
    "BenchmarkReporter",
]

__version__ = "0.1.0"
__author__ = "Bhuvan Garg"
__description__ = "Adversarial benchmark suite for LLM code security tools"
