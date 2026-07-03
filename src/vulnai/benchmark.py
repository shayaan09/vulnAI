import csv
from dataclasses import dataclass
from collections import defaultdict

from vulnai.scanner import Scanner


SUPPORTED_BENCHMARK_CATEGORIES = {
    "cmdi",
    "deserialization",
    "hash",
    "pathtraver",
    "sqli",
    "weakrand",
    "xss",
    "xxe",
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


class BenchmarkScorer:
    def __init__(self, target_path: str, expected_path: str):
        self.target_path = target_path
        self.expected_path = expected_path

    def load_expected(self) -> dict[str, ExpectedCase]:
        expected = {}

        with open(self.expected_path, "r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)

            if reader.fieldnames is None:
                raise ValueError("Expected results file has no header row.")

            clean_headers = []
            for name in reader.fieldnames:
                clean = name.strip().lower()

                if clean.startswith("#"):
                    clean = clean[1:].strip()

                clean_headers.append(clean)

            reader.fieldnames = clean_headers

            for row in reader:
                cleaned_row = {}

                for key, value in row.items():
                    if key is None:
                        continue

                    clean_key = key.strip().lower()

                    if clean_key.startswith("#"):
                        clean_key = clean_key[1:].strip()

                    cleaned_row[clean_key] = value

                test_name = cleaned_row["test name"].strip()
                category = cleaned_row["category"].strip().lower()
                real_vuln = cleaned_row["real vulnerability"].strip().lower() == "true"
                cwe = f"CWE-{cleaned_row['cwe'].strip()}"

                expected[test_name] = ExpectedCase(
                    test_name=test_name,
                    category=category,
                    expected_vulnerable=real_vuln,
                    cwe=cwe,
                )

        return expected

    def extract_test_name(self, finding: dict) -> str | None:
        candidates = [
            finding.get("callee"),
            finding.get("caller"),
            finding.get("function"),
        ]

        for value in candidates:
            if not value:
                continue

            for part in str(value).split("."):
                if part.startswith("BenchmarkTest"):
                    return part

        return None

    def normalize_findings(self, vulnerabilities: list[dict]) -> dict[str, set[str]]:
        found = defaultdict(set)

        for finding in vulnerabilities:
            test_name = self.extract_test_name(finding)
            cwe = finding.get("cwe")

            if test_name and cwe:
                found[test_name].add(cwe)

        return found

    def score(self) -> None:
        expected = self.load_expected()

        scanner = Scanner()
        result = scanner.scan(self.target_path)

        found = self.normalize_findings(result.vulnerabilities)

        overall_all = MetricBucket()
        overall_supported = MetricBucket()
        by_category: dict[str, MetricBucket] = defaultdict(MetricBucket)

        for test_name, case in expected.items():
            vulnai_found = test_name in found
            cwe_matched = case.cwe in found.get(test_name, set())

            category_key = f"{case.category} {case.cwe}"
            bucket = by_category[category_key]

            is_supported = case.category in SUPPORTED_BENCHMARK_CATEGORIES

            if case.expected_vulnerable and cwe_matched:
                overall_all.tp += 1
                bucket.tp += 1

                if is_supported:
                    overall_supported.tp += 1

            elif not case.expected_vulnerable and vulnai_found:
                overall_all.fp += 1
                bucket.fp += 1

                if is_supported:
                    overall_supported.fp += 1

            elif case.expected_vulnerable and not cwe_matched:
                overall_all.fn += 1
                bucket.fn += 1

                if is_supported:
                    overall_supported.fn += 1

            else:
                overall_all.tn += 1
                bucket.tn += 1

                if is_supported:
                    overall_supported.tn += 1

        self.print_report(
            overall_all=overall_all,
            overall_supported=overall_supported,
            by_category=by_category,
        )

    def print_report(
        self,
        overall_all: MetricBucket,
        overall_supported: MetricBucket,
        by_category: dict[str, MetricBucket],
    ) -> None:
        print("\n==============================")
        print(" vulnAI Benchmark Metrics")
        print("==============================")

        self.print_bucket("OVERALL - ALL BENCHMARK CATEGORIES", overall_all)

        self.print_bucket(
            "OVERALL - SUPPORTED VULNAI CATEGORIES ONLY",
            overall_supported,
        )

        print("\nPer Category:")
        for name in sorted(by_category.keys()):
            self.print_bucket(name, by_category[name])

    def print_bucket(self, name: str, bucket: MetricBucket) -> None:
        print(f"\n{name}")
        print(f"  TP: {bucket.tp}")
        print(f"  FP: {bucket.fp}")
        print(f"  FN: {bucket.fn}")
        print(f"  TN: {bucket.tn}")
        print(f"  Precision: {bucket.precision():.2f}")
        print(f"  Recall:    {bucket.recall():.2f}")
        print(f"  F1:        {bucket.f1():.2f}")