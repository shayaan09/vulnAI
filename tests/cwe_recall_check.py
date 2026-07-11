from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
DEFAULT_CORPUS = REPO_ROOT / "tests" / "fixtures" / "cwe_recall"
DEFAULT_MANIFEST = DEFAULT_CORPUS / "expected_recall.json"


@dataclass(frozen=True)
class RecallCase:
    id: str
    cwe: str
    type: str
    description: str


def load_cases(path: Path) -> list[RecallCase]:
    with path.open("r", encoding="utf-8") as f:
        payload = json.load(f)

    cases = []
    for row in payload.get("cases", []):
        cases.append(
            RecallCase(
                id=str(row["id"]),
                cwe=str(row["cwe"]),
                type=str(row["type"]),
                description=str(row["description"]),
            )
        )

    return cases


def finding_text(finding: dict) -> str:
    fields = [
        finding.get("caller"),
        finding.get("callee"),
        finding.get("function"),
        finding.get("sinkReached"),
        finding.get("sink"),
        finding.get("expression"),
        finding.get("vulnerability"),
    ]
    return " ".join(str(field) for field in fields if field)


def group_findings_by_case(cases: list[RecallCase], findings: list[dict]) -> dict[str, list[dict]]:
    by_case: dict[str, list[dict]] = defaultdict(list)

    for finding in findings:
        cwe = finding.get("cwe")
        text = finding_text(finding)

        for case in cases:
            if cwe == case.cwe and case.id in text:
                by_case[case.id].append(finding)

    return by_case


def print_report(cases: list[RecallCase], by_case: dict[str, list[dict]], show_found: bool) -> list[RecallCase]:
    cases_by_cwe: dict[str, list[RecallCase]] = defaultdict(list)
    for case in cases:
        cases_by_cwe[case.cwe].append(case)

    missed: list[RecallCase] = []

    print("\n==============================")
    print(" vulnAI CWE Recall Matrix")
    print("==============================")
    print(f"Expected vulnerable cases: {len(cases)}")
    print(f"CWE families: {len(cases_by_cwe)}")

    for cwe in sorted(cases_by_cwe):
        cwe_cases = cases_by_cwe[cwe]
        caught = [case for case in cwe_cases if by_case.get(case.id)]
        cwe_missed = [case for case in cwe_cases if not by_case.get(case.id)]
        missed.extend(cwe_missed)

        recall = len(caught) / len(cwe_cases) if cwe_cases else 0.0
        print(f"\n{cwe}")
        print(f"  Expected: {len(cwe_cases)}")
        print(f"  Caught:   {len(caught)}")
        print(f"  Missed:   {len(cwe_missed)}")
        print(f"  Recall:   {recall:.2%}")

        if show_found and caught:
            print("  Caught Types:")
            for case in caught:
                print(f"    PASS {case.id} [{case.type}] findings={len(by_case[case.id])}")

        if cwe_missed:
            print("  Missed Types:")
            for case in cwe_missed:
                print(f"    MISS {case.id} [{case.type}] {case.description}")

    print("\nOverall")
    caught_total = len([case for case in cases if by_case.get(case.id)])
    missed_total = len(missed)
    recall_total = caught_total / len(cases) if cases else 0.0
    print(f"  Caught: {caught_total}")
    print(f"  Missed: {missed_total}")
    print(f"  Recall: {recall_total:.2%}")

    return missed


def print_unmatched_findings(cases: list[RecallCase], findings: list[dict]) -> None:
    case_ids = {case.id for case in cases}
    unmatched = []

    for finding in findings:
        text = finding_text(finding)
        if not any(case_id in text for case_id in case_ids):
            unmatched.append(finding)

    if not unmatched:
        return

    print("\nUnmatched Findings:")
    for finding in unmatched:
        print(
            "  "
            f"{finding.get('cwe')} "
            f"caller={finding.get('caller')} "
            f"callee={finding.get('callee')} "
            f"sink={finding.get('sinkReached')}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run vulnAI against positive-only CWE recall fixtures."
    )
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--show-found", action="store_true")
    parser.add_argument("--show-unmatched", action="store_true")
    args = parser.parse_args()

    sys.path.insert(0, str(SRC_ROOT))

    from vulnai.scanner import Scanner

    corpus_path = Path(args.corpus).resolve()
    manifest_path = Path(args.manifest).resolve()
    cases = load_cases(manifest_path)

    result = Scanner().scan(str(corpus_path))
    by_case = group_findings_by_case(cases, result.vulnerabilities)

    missed = print_report(cases, by_case, show_found=args.show_found)

    if args.show_unmatched:
        print_unmatched_findings(cases, result.vulnerabilities)

    if args.strict and missed:
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

