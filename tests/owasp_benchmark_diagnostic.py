from __future__ import annotations

import argparse
import csv
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
DEFAULT_TARGET = REPO_ROOT / "benchmarks" / "external" / "OWASPBenchmarkPython"
DEFAULT_EXPECTED = DEFAULT_TARGET / "expectedresults-0.1.csv"


SUPPORTED_CATEGORIES = {
    "cmdi",
    "deserialization",
    "hash",
    "pathtraver",
    "sqli",
    "weakrand",
    "xss",
    "xxe",
}


UNSUPPORTED_CATEGORIES = {
    "codeinj",
    "ldapi",
    "redirect",
    "securecookie",
    "trustbound",
    "xpathi",
}


OWASP_ALIAS_CWES = {
    # Normal vulnAI weak crypto rule is CWE-327, OWASP hash expects CWE-328.
    ("hash", "CWE-328"): {"CWE-328", "CWE-327"},

    # Normal vulnAI insecure random rule is CWE-338, OWASP weakrand expects CWE-330.
    ("weakrand", "CWE-330"): {"CWE-330", "CWE-338"},
}


@dataclass
class ExpectedCase:
    test_name: str
    category: str
    expected_vulnerable: bool
    cwe: str


@dataclass
class MetricBucket:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    def f1(self) -> float:
        p = self.precision()
        r = self.recall()
        return (2 * p * r / (p + r)) if (p + r) else 0.0


def load_expected(path: Path) -> dict[str, ExpectedCase]:
    expected = {}

    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            raise ValueError("Expected results file has no header row.")

        reader.fieldnames = [
            name.strip().lower()[1:].strip()
            if name.strip().lower().startswith("#")
            else name.strip().lower()
            for name in reader.fieldnames
        ]

        for row in reader:
            cleaned = {}
            for key, value in row.items():
                if key is None:
                    continue

                clean_key = key.strip().lower()
                if clean_key.startswith("#"):
                    clean_key = clean_key[1:].strip()

                cleaned[clean_key] = value

            test_name = cleaned["test name"].strip()
            category = cleaned["category"].strip().lower()
            real_vuln = cleaned["real vulnerability"].strip().lower() == "true"
            cwe = f"CWE-{cleaned['cwe'].strip()}"

            expected[test_name] = ExpectedCase(
                test_name=test_name,
                category=category,
                expected_vulnerable=real_vuln,
                cwe=cwe,
            )

    return expected


def extract_test_name(finding: dict) -> str | None:
    for key in ("callee", "caller", "function"):
        value = finding.get(key)
        if not value:
            continue

        for part in str(value).split("."):
            if part.startswith("BenchmarkTest"):
                return part.split("_", 1)[0]

    return None


def normalize_findings(vulnerabilities: list[dict]) -> dict[str, set[str]]:
    found = defaultdict(set)

    for finding in vulnerabilities:
        test_name = extract_test_name(finding)
        cwe = finding.get("cwe")

        if test_name and cwe:
            found[test_name].add(str(cwe))

    return found


def accepted_cwes(case: ExpectedCase) -> set[str]:
    return OWASP_ALIAS_CWES.get((case.category, case.cwe), {case.cwe})


def score_cases(
    expected: dict[str, ExpectedCase],
    found: dict[str, set[str]],
    categories: set[str],
) -> tuple[MetricBucket, dict[str, MetricBucket], dict[str, list[str]]]:
    overall = MetricBucket()
    by_category: dict[str, MetricBucket] = defaultdict(MetricBucket)
    missed_by_category: dict[str, list[str]] = defaultdict(list)

    for test_name, case in expected.items():
        if case.category not in categories:
            continue

        found_cwes = found.get(test_name, set())
        vulnai_found = bool(found_cwes)
        cwe_matched = bool(found_cwes & accepted_cwes(case))

        key = f"{case.category} {case.cwe}"
        bucket = by_category[key]

        if case.expected_vulnerable and cwe_matched:
            overall.tp += 1
            bucket.tp += 1
        elif not case.expected_vulnerable and vulnai_found:
            overall.fp += 1
            bucket.fp += 1
        elif case.expected_vulnerable and not cwe_matched:
            overall.fn += 1
            bucket.fn += 1
            missed_by_category[key].append(test_name)
        else:
            overall.tn += 1
            bucket.tn += 1

    return overall, by_category, missed_by_category


def print_bucket(name: str, bucket: MetricBucket) -> None:
    print(f"\n{name}")
    print(f"  TP: {bucket.tp}")
    print(f"  FP: {bucket.fp}")
    print(f"  FN: {bucket.fn}")
    print(f"  TN: {bucket.tn}")
    print(f"  Precision: {bucket.precision():.2f}")
    print(f"  Recall:    {bucket.recall():.2f}")
    print(f"  F1:        {bucket.f1():.2f}")


def print_report(
    title: str,
    overall: MetricBucket,
    by_category: dict[str, MetricBucket],
    missed_by_category: dict[str, list[str]],
    show_missed: bool,
) -> None:
    print("\n==============================")
    print(title)
    print("==============================")

    print_bucket("OVERALL", overall)

    print("\nPer Category:")
    for name in sorted(by_category):
        print_bucket(name, by_category[name])

        if show_missed and missed_by_category.get(name):
            first_misses = ", ".join(missed_by_category[name][:20])
            more = len(missed_by_category[name]) - 20
            suffix = f" ... and {more} more" if more > 0 else ""
            print(f"  Missed vulnerable tests: {first_misses}{suffix}")


def print_unsupported_pollution(expected: dict[str, ExpectedCase], found: dict[str, set[str]]) -> None:
    print("\n==============================")
    print("Unsupported Category Pollution")
    print("==============================")

    by_category = defaultdict(list)
    for test_name, case in expected.items():
        if case.category in UNSUPPORTED_CATEGORIES and test_name in found:
            by_category[case.category].append((test_name, sorted(found[test_name])))

    if not by_category:
        print("No findings landed on unsupported OWASP categories.")
        return

    for category in sorted(by_category):
        rows = by_category[category]
        print(f"\n{category}: {len(rows)} tests with findings")
        for test_name, cwes in rows[:20]:
            print(f"  {test_name}: {', '.join(cwes)}")

        if len(rows) > 20:
            print(f"  ... and {len(rows) - 20} more")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Alias-aware OWASP diagnostic report for vulnAI."
    )
    parser.add_argument("--target", default=str(DEFAULT_TARGET))
    parser.add_argument("--expected", default=str(DEFAULT_EXPECTED))
    parser.add_argument("--show-missed", action="store_true")
    args = parser.parse_args()

    sys.path.insert(0, str(SRC_ROOT))

    from vulnai.scanner import Scanner

    expected = load_expected(Path(args.expected).resolve())
    result = Scanner().scan(str(Path(args.target).resolve()))
    found = normalize_findings(result.vulnerabilities)

    supported_overall, supported_by_category, supported_missed = score_cases(
        expected,
        found,
        SUPPORTED_CATEGORIES,
    )

    print_report(
        "vulnAI OWASP Supported/Alias-Aware Metrics",
        supported_overall,
        supported_by_category,
        supported_missed,
        args.show_missed,
    )

    print_unsupported_pollution(expected, found)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

