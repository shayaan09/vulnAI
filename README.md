# vulnAI

[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![PyPI](https://img.shields.io/pypi/v/vulnai)](https://pypi.org/project/vulnai/)
[![Package](https://img.shields.io/badge/package-CLI-111827)](#installation)
[![Analysis](https://img.shields.io/badge/analysis-interprocedural%20taint-5B8DEF)](#how-it-works)
[![Benchmark](https://img.shields.io/badge/OWASP%20Benchmark%20Python-F1%200.85-22C55E)](#benchmark-results)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](#license)

vulnAI is a Python static application security testing tool built around
interprocedural taint analysis. It parses Python code, builds function-level
summaries, resolves calls across a code graph, and reports source-to-sink
vulnerability flows with CWE labels.

It is designed to answer a harder question than simple pattern matching:

> Did attacker-controlled data move across functions, returns, aliases, and
> callsites before reaching a dangerous sink?

![vulnAI analysis pipeline](https://raw.githubusercontent.com/shayaan09/vulnAI/main/docs/media/vulnai-pipeline.gif)

## Highlights

- Interprocedural taint propagation across function call boundaries.
- Custom codebase indexing, import resolution, call graph construction, CFG
  construction, use-def analysis, and fixed-point dataflow iteration.
- Per-callsite context isolation to avoid mixing taint from unrelated calls.
- Rule support for common Python web/security vulnerability classes.
- CLI workflow for scanning codebases and scoring OWASP Benchmark Python.
- Measured against OWASP Benchmark Python ground truth and compared with
  Bandit 1.9.4 on the same supported benchmark scope.

## Demo

### CLI Scan

![vulnAI CLI scan demo](https://raw.githubusercontent.com/shayaan09/vulnAI/main/docs/media/vulnai-cli-demo.gif)

```powershell
vulnai scan ./benchmarks/external/pygoat
```

Example output shape:

```text
[*] Starting vulnAI scan on: ./benchmarks/external/pygoat
[-] Building CodebaseIndex...
[-] Building CallGraph edges...
[-] Building function summaries...
[-] Running interprocedural taint analysis...
[+] Scan complete.

Vulnerabilities found: 65
```

### Cross-Function Taint Tracking

![vulnAI cross-function taint flow](https://raw.githubusercontent.com/shayaan09/vulnAI/main/docs/media/vulnai-taint-flow.gif)

vulnAI does not stop at the local function. If a value enters through a web
request, passes through helper functions, returns into another scope, and then
reaches a sink, the analyzer can preserve the flow through the call graph.

```python
def route(request):
    name = request.args.get("name")
    value = normalize(name)
    return render(value)

def normalize(x):
    return x.strip()

def render(html):
    return HttpResponse(html)
```

In this shape, the important fact is not just that `HttpResponse` exists. The
important fact is that attacker-controlled input reached it.

## Installation

Install the published CLI from PyPI:

```powershell
pip install vulnai
```

PyPI package: [vulnai](https://pypi.org/project/vulnai/)

From source:

```powershell
git clone https://github.com/shayaan09/vulnAI.git
cd vulnAI
python -m pip install -e .
```

Verify the CLI:

```powershell
vulnai --help
```

## Usage

Scan a Python project:

```powershell
vulnai scan ./path/to/python-project
```

Run OWASP Benchmark Python scoring:

```powershell
vulnai benchmark ./benchmarks/external/OWASPBenchmarkPython ./benchmarks/external/OWASPBenchmarkPython/expectedresults-0.1.csv
```

Run the local recall corpus:

```powershell
python ./tests/cwe_recall_check.py --strict
```

## Supported Vulnerability Classes

| CWE | Vulnerability class | Detection style |
|---|---|---|
| CWE-22 | Path traversal | Taint flow |
| CWE-78 | OS command injection | Taint flow |
| CWE-79 | Cross-site scripting | Taint flow |
| CWE-89 | SQL injection | Taint flow |
| CWE-327 / CWE-328 | Weak cryptography / weak hash | Pattern-based |
| CWE-330 / CWE-338 | Insecure randomness / weak PRNG | Pattern-based |
| CWE-502 | Insecure deserialization | Taint flow + sink rules |
| CWE-611 | XML external entity injection | Taint flow + parser rules |
| CWE-798 | Hardcoded credentials/secrets | Pattern-based |
| CWE-918 | Server-side request forgery | Taint flow |

The OWASP Benchmark Python score below uses the 8 currently supported OWASP
Benchmark categories: command injection, deserialization, hash, path traversal,
SQL injection, weak randomness, XSS, and XXE.

## Benchmark Results

Measured on OWASP Benchmark Python using the benchmark's expected-results CSV.
The table below reports the supported vulnAI categories only, covering 852
labeled test cases.

| Tool | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| vulnAI | 267 | 50 | 43 | 492 | 0.84 | 0.86 | 0.85 |
| Bandit 1.9.4 | 192 | 50 | 118 | 492 | 0.79 | 0.62 | 0.70 |

Interpretation:

- vulnAI detected 75 more true positives than Bandit at the same false-positive
  count on the supported OWASP Benchmark Python scope.
- Bandit remains strong on local risky APIs such as `hashlib.md5`,
  `random.getrandbits`, `pickle.loads`, `eval`, and `exec`.
- vulnAI's advantage comes from resolving source-to-sink dataflow across
  function boundaries rather than only matching local AST patterns.

Reproduce vulnAI's benchmark run:

```powershell
vulnai benchmark ./benchmarks/external/OWASPBenchmarkPython ./benchmarks/external/OWASPBenchmarkPython/expectedresults-0.1.csv
```

## How It Works

vulnAI runs the scan in phases:

1. Parse Python files into ASTs.
2. Build a codebase index of modules, imports, functions, classes, and nested
   definitions.
3. Build a code graph with containment, import, call, and external-call edges.
4. Build a CFG for each function.
5. Run reaching-definition and use-def analysis.
6. Build function summaries that describe parameter-to-return and
   parameter-to-sink behavior.
7. Run fixed-point interprocedural taint propagation over the call graph.
8. Replay local sink checks once new return taint is discovered.
9. Emit CWE-labeled findings with caller, callee, sink, line, and context data.

On OWASP Benchmark Python, the analyzer builds a graph with more than 5,400
nodes, 19,700 edges, and 3,700 indexed functions.

## Example Finding

```text
[1] Tainted Flow to Sink: SQL Injection
    CWE: CWE-89
    Caller: views.search
    Callee: database.run_query
    Via Parameter: query
    Sink Reached: cursor.execute(sql)
    Line: 42
    Context: views.search -> database.run_query
```

The goal is to make the report explain both the dangerous operation and how
tainted data reached it.

## Development

Install in editable mode:

```powershell
python -m pip install -e .
```

Run tests:

```powershell
python -m pytest
```

Run the positive-only CWE recall matrix:

```powershell
python ./tests/cwe_recall_check.py --strict
```

Build the package:

```powershell
python -m build
python -m twine check dist/*
```

## Project Status

vulnAI is a research/portfolio SAST engine. It is useful for exploring static
analysis architecture and catching many common Python vulnerability patterns,
but it is not a replacement for a professional security review.

Known limitations:

- Python 3 AST parsing only. Python 2 projects should be converted before
  scanning.
- Highly dynamic Python features can hide calls or dataflow from static
  analysis.
- Framework-specific source/sink modeling is rule-dependent and should be
  expanded over time.
- Benchmark metrics are reported for supported OWASP Benchmark Python
  categories only.

## Responsible Use

Only scan code you own or are authorized to test. Static analysis findings
should be reviewed before being treated as confirmed vulnerabilities.

## License

MIT
