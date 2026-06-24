import argparse
import argparse
import os

from vulnai.scanner import Scanner, print_scan_result

def main():
    parser= argparse.ArgumentParser(prog="vulnai")
    subparsers = parser.add_subparsers(dest="cmd", help="Subcommand Help")
    parser_scan = subparsers.add_parser("scan", aliases=["s"], help="Scans the file provided")
    parser_scan.add_argument("target", help="Path of the directory being scanned")
    args = parser.parse_args() #Checks if the args passed are valid or no.

    if args.cmd == "scan" or args.cmd == 's':
        target_path = args.target

        if not os.path.exists(target_path):
            print(f"[!] Error: Target path does not exist: {target_path}")
            return

        if not os.path.isdir(target_path):
            print("[!] For now, vulnAI full scan expects a directory.")
            print("    Example:")
            print("    vulnai scan benchmarks/external/pygoat")
            return

        scanner = Scanner()
        result = scanner.scan(target_path)
        print_scan_result(result)
        return

    elif args.cmd is None:
        parser.print_help()
        return


if __name__ == "__main__":
    main()
    