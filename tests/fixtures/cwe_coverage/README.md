# CWE Coverage Corpus

This folder is a tiny intentionally vulnerable codebase for vulnAI itself.

It is not benchmark code and it is not meant to run. The files are parsed by the
static analyzer so each rule can be tested against small, obvious examples.

Each CWE fixture includes:

- at least one direct vulnerable flow
- at least one interprocedural flow
- at least one sanitizer or safe-looking negative example
- at least one alias or wrapper shape where useful

Run the manual coverage checker from the repo root:

```powershell
python .\tools\cwe_coverage_check.py
```

Use strict mode when you want the command to fail if any defined CWE is missing:

```powershell
python .\tools\cwe_coverage_check.py --strict
```

