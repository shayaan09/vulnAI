from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
DEFAULT_CORPUS = REPO_ROOT / "tests" / "fixtures" / "cwe_coverage"
DEFAULT_EXPECTED = DEFAULT_CORPUS / "expected_cwes.json"


def load_expected(path: Path) -> dict[str, str]:
    with path.open("r", encoding="utf-8") as f:
        payload = json.load(f)

    expected = payload.get("expected_cwes", {})
    if not isinstance(expected, dict):
        raise ValueError("expected_cwes must be a JSON object mapping CWE id to rule name")

    return {str(cwe): str(name) for cwe, name in expected.items()}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan the internal CWE fixture corpus and report CWE coverage."
    )
    parser.add_argument(
        "--corpus",
        default=str(DEFAULT_CORPUS),
        help="Path to the fixture codebase to scan.",
    )
    parser.add_argument(
        "--expected",
        default=str(DEFAULT_EXPECTED),
        help="JSON file containing expected_cwes.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with code 1 if any expected CWE is missing.",
    )
    parser.add_argument(
        "--show-findings",
        action="store_true",
        help="Print every raw finding after the summary.",
    )
    args = parser.parse_args()

    sys.path.insert(0, str(SRC_ROOT))

    from vulnai.scanner import Scanner

    corpus_path = Path(args.corpus).resolve()
    expected_path = Path(args.expected).resolve()
    expected = load_expected(expected_path)

    result = Scanner().scan(str(corpus_path))

    findings_by_cwe: dict[str, list[dict]] = defaultdict(list)
    for finding in result.vulnerabilities:
        cwe = finding.get("cwe")
        if cwe:
            findings_by_cwe[str(cwe)].append(finding)

    expected_cwes = set(expected)
    observed_cwes = set(findings_by_cwe)
    missing_cwes = sorted(expected_cwes - observed_cwes)
    unexpected_cwes = sorted(observed_cwes - expected_cwes)

    print("\n==============================")
    print(" vulnAI CWE Coverage Corpus")
    print("==============================")
    print(f"Corpus: {corpus_path}")
    print(f"Expected CWEs: {len(expected_cwes)}")
    print(f"Observed CWEs: {len(observed_cwes)}")
    print(f"Raw findings: {len(result.vulnerabilities)}")

    print("\nPer CWE:")
    for cwe in sorted(expected):
        status = "PASS" if cwe in observed_cwes else "MISS"
        count = len(findings_by_cwe.get(cwe, []))
        print(f"  {status} {cwe} {expected[cwe]} findings={count}")

    if unexpected_cwes:
        print("\nUnexpected CWEs:")
        for cwe in unexpected_cwes:
            print(f"  {cwe} findings={len(findings_by_cwe[cwe])}")

    if args.show_findings:
        print("\nFindings:")
        for cwe in sorted(findings_by_cwe):
            for finding in findings_by_cwe[cwe]:
                location = finding.get("callee") or finding.get("caller") or "unknown"
                sink = finding.get("sinkReached") or finding.get("sink") or "unknown"
                line = finding.get("line", "unknown")
                print(f"  {cwe} {location} line={line} sink={sink}")

    if missing_cwes:
        print("\nMissing CWEs:")
        for cwe in missing_cwes:
            print(f"  {cwe} {expected[cwe]}")

    if args.strict and missing_cwes:
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

