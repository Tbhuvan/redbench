<div align="center">

# RedBench

**Adversarial benchmark suite for evaluating LLM code security tools**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-green.svg)](LICENSE)

</div>

---

## Overview

RedBench is a curated benchmark dataset for evaluating the detection accuracy of LLM code security tools. It provides balanced vulnerable/safe code pairs across 13 CWE classes, enabling rigorous precision/recall measurement with ground-truth labels.

Existing benchmarks for code vulnerability detection (e.g., Big-Vul, Devign) focus on historical CVEs in human-written code. RedBench targets a different distribution: **vulnerabilities characteristic of AI-generated code** — the patterns that LLMs produce when given underspecified security prompts.

## Dataset

| Class | CWE | Pairs | Description |
|-------|-----|-------|-------------|
| SQL Injection | CWE-89 | 15+ | String interpolation in SQL queries |
| Command Injection | CWE-78 | 15+ | Unsanitised input to shell commands |
| Path Traversal | CWE-22 | 15+ | Unvalidated file path construction |
| XSS | CWE-79 | 15+ | Unescaped user input in HTML output |
| SSRF | CWE-918 | 15+ | Unrestricted URL fetching |
| IDOR | CWE-639 | 10+ | Missing authorisation checks |
| Auth Bypass | CWE-306 | 15+ | Weak or missing authentication |
| Deserialization | CWE-502 | 10+ | Unsafe pickle/YAML deserialisation |
| Open Redirect | CWE-601 | 5+ | Unvalidated redirect targets |
| ReDoS | CWE-1333 | 5+ | Catastrophic regex backtracking |
| Unsafe YAML | CWE-20 | 5+ | yaml.load without SafeLoader |
| TLS Validation | CWE-295 | 5+ | Disabled certificate verification |
| XXE | CWE-611 | 5+ | XML external entity injection |

**Total: 198 balanced pairs** (vulnerable code + matched safe fix)

Each pair contains:
- `code`: The vulnerable implementation
- `fix`: The secure implementation (same function, safe patterns)
- `cwe`: CWE identifier
- `vuln_class`: Category label

## Usage

```python
from redbench import load_samples, evaluate_tool

# Load all samples
samples = load_samples()

# Evaluate a detection tool
results = evaluate_tool(my_detector, samples)
print(f"Recall: {results.recall:.1%}, Precision: {results.precision:.1%}")
```

## Evaluation Results

Tools evaluated on RedBench:

| Tool | Recall | False Positives | AUC | Notes |
|------|--------|-----------------|-----|-------|
| ActivGuard (activation probe) | **100%** | **0%** | **0.835** | Static benchmark only |
| Bandit (SAST) | 0% | 0% | — | Pattern-matching, no semantic understanding |
| Semgrep (SAST) | 0% | 0% | — | Pattern-matching, no semantic understanding |

*Static benchmark evaluation: probe scores pre-written code samples. Field test on real LLM-generated code shows 48.8% recall — identifying the optimal generation-time intervention point is ongoing research.*

## Project Structure

```
redbench/
├── redbench/        # Core: loader, evaluator, reporter
├── datasets/        # Vulnerability samples by class
│   ├── sqli/
│   ├── xss/
│   ├── ssrf/
│   └── ...          # 13 CWE classes
├── tests/           # Test suite
└── README.md
```

## Research Context

Part of the [ActivGuard](https://github.com/Tbhuvan/activguard) research programme on runtime security for AI-assisted software development. See also: [AgentWarden](https://github.com/Tbhuvan/agentwarden), [AgentAudit](https://github.com/Tbhuvan/agentaudit).

## License

Apache License 2.0
