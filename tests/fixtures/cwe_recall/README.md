# CWE Recall Matrix

This is a positive-only recall corpus for vulnAI.

Every case in this folder is intentionally vulnerable. The matching manifest
labels each case by CWE and by vulnerability shape, so the checker can answer:

- which CWE families are being detected
- which source/sink/propagation shapes are being missed
- where the analyzer needs new coverage work

Run from the repo root:

```powershell
python .\tests\cwe_recall_check.py
```

Strict mode exits non-zero when any expected vulnerable case is missed:

```powershell
python .\tests\cwe_recall_check.py --strict
```

