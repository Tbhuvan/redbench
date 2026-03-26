<div align="center">

# RedBench

**Adversarial benchmark suite for evaluating LLM code security tools**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-green.svg)](LICENSE)

</div>

---

## Overview

RedBench is a curated benchmark dataset and evaluation harness for measuring the detection accuracy of LLM code security tools. It provides **290 balanced vulnerable/safe code pairs across 17 CWE classes**, enabling rigorous precision/recall/F1 measurement with ground-truth labels and automated tool comparison.

Existing benchmarks for code vulnerability detection (e.g., Big-Vul, Devign) focus on historical CVEs in human-written code. RedBench targets a different distribution: **vulnerabilities characteristic of AI-generated code** — the patterns LLMs produce when given underspecified security prompts.

## Dataset

| Class | CWE | Pairs | Description |
|-------|-----|-------|-------------|
| SQL Injection | CWE-89 | 20 | String interpolation / unsanitised input in SQL |
| Command Injection | CWE-78 | 20 | Unsanitised input to shell commands |
| Path Traversal | CWE-22 | 20 | Unvalidated file path construction |
| XSS | CWE-79 | 20 | Unescaped user input in HTML output |
| SSRF | CWE-918 | 20 | Unrestricted outbound URL fetching |
| IDOR | CWE-639 | 20 | Missing authorisation / ownership checks |
| Auth Bypass | CWE-306 | 20 | Weak or missing authentication |
| Deserialization | CWE-502 | 20 | Unsafe pickle/YAML deserialisation |
| Open Redirect | CWE-601 | 20 | Unvalidated redirect targets |
| ReDoS | CWE-1333 | 20 | Catastrophic regex backtracking |
| Unsafe YAML | CWE-20 | 20 | yaml.load without SafeLoader |
| TLS Validation | CWE-295 | 20 | Disabled certificate verification |
| XXE | CWE-611 | 20 | XML external entity injection |
| Cleartext Secrets | CWE-312 | 20 | Hardcoded credentials / secrets in source |
| Weak Crypto | CWE-327 | 20 | MD5/SHA1/DES in security contexts |
| Mass Assignment | CWE-915 | 20 | Unfiltered model attribute assignment |
| Race Condition | CWE-362 | 20 | TOCTOU / unsynchronised shared state |

**Total: 290 balanced pairs** (vulnerable code + matched safe implementation)

Each sample contains: `code`, `fix`, `cwe`, `severity`, `description` (the prompt that produced the vulnerability), and `attack_scenario`.

## Evaluation Results

Tools evaluated on the **8-class static benchmark** (198 pairs, complete code fragments):

| Tool | Recall | Precision | F1 | Notes |
|------|--------|-----------|-----|-------|
| **ActivGuard** (activation probe) | **100%†** | **100%†** | **1.00** | In-sample; held-out AUC **0.835 ± 0.055** (5-fold CV) |
| Bandit ≥MEDIUM | 41.9% (83/198) | 60.6% | 0.53 | Strong on SQLi, SSRF, cmd-injection |
| Semgrep p/python | ~14%‡ | 51.0% | 0.22 | Taint-flow rules require full app context |

**On live streaming code** (44 prompts, field test):

| Tool | Recall | Notes |
|------|--------|-------|
| ActivGuard | 58.3% (21/36) | Intercepts during generation; 57.4% mean token savings |
| Semgrep | 19.4% (7/36) | Post-hoc scanning of partial fragments |
| Bandit | 0% | Cannot parse incomplete streaming code |

†*In-sample evaluation — same pairs used for probe training. Bandit threshold: MEDIUM (standard CI/CD setting; HIGH misses B608/SQLi entirely).*

‡*Semgrep recall measured in a separate static scan. Taint-flow rules require full application context — isolated snippets break the taint chain, which accounts for near-zero detection in the automated e2e benchmark.*

## Usage

```bash
pip install -e .

# Run stub baseline (always-vulnerable predictor) across all 17 classes
python run_benchmark.py --tool stub

# Run Bandit across all 17 classes
python run_benchmark.py --tool bandit --output results/bandit_results.json

# Run Semgrep
python run_benchmark.py --tool semgrep

# Evaluate a subset of classes
python run_benchmark.py --tool bandit --classes sqli command_injection path_traversal

# Include extended generated samples
python run_benchmark.py --tool stub --source-files samples.jsonl samples_generated_v3.jsonl
```

```python
from redbench import BenchmarkLoader, BenchmarkEvaluator

# Load all 17 classes (290 samples)
loader = BenchmarkLoader()
samples = loader.load_all()

# Evaluate a custom tool
def my_detector(code: str) -> str:
    return "vulnerable" if "execute(" in code else "safe"

evaluator = BenchmarkEvaluator()
result = evaluator.evaluate(my_detector, vuln_class="sqli")
print(f"Recall: {result.recall:.1%}  Precision: {result.precision:.1%}  F1: {result.f1:.3f}")

# Compare multiple tools and export LaTeX table
comparison = evaluator.compare_tools({"bandit": bandit_fn, "semgrep": semgrep_fn})
print(evaluator.generate_latex_table(comparison))
```

## Project Structure

```
redbench/
├── redbench/
│   ├── loader.py        # BenchmarkLoader — schema-validated JSONL loading, all 17 classes
│   ├── evaluator.py     # BenchmarkEvaluator — TP/FP/TN/FN, compare_tools(), LaTeX export
│   └── reporter.py      # BenchmarkReporter — Markdown + JSON report generation
├── datasets/            # 17 vulnerability class directories (samples.jsonl per class)
├── scripts/
│   └── build_canonical.py  # Promotes generated samples to canonical format
├── run_benchmark.py     # CLI entry point
├── tests/               # 64 tests
└── README.md
```

## Research Context

Part of the [ActivGuard](https://github.com/Tbhuvan/activguard) research programme. RedBench provides the adversarial evaluation surface that [AgentAudit](https://github.com/Tbhuvan/agentaudit) uses to close the attack-defence loop: successful bypasses are automatically promoted to new benchmark entries, improving detection with each adversarial iteration.

## License

Apache License 2.0
