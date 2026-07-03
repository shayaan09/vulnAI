import argparse
import argparse
import os

from vulnai.scanner import Scanner, print_scan_result
from vulnai.benchmark import BenchmarkScorer


def main():
    parser= argparse.ArgumentParser(prog="vulnai")
    subparsers = parser.add_subparsers(dest="cmd", help="Subcommand Help")
    parser_scan = subparsers.add_parser("scan", aliases=["s"], help="Scans the codebase provided")
    parser_scan.add_argument("target", help="Path of the directory being scanned")

    benchmark_parser = subparsers.add_parser("benchmark", aliases=["b"], help="Run benchmark scoring")
    benchmark_parser.add_argument("target", help="Benchmark target directory")
    benchmark_parser.add_argument("expected", help="Expected results CSV file")

    args = parser.parse_args() #Checks if the args passed are valid or no.

    if args.cmd == "scan" or args.cmd == 's':
        scanner = Scanner()
        result = scanner.scan(args.target)
        print_scan_result(result)

    elif args.cmd in ["benchmark", "b"]:
        scorer = BenchmarkScorer(args.target, args.expected)
        scorer.score()

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
    