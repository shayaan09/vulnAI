import argparse


def main():
    parser= argparse.ArgumentParser(prog="vulnai")
    subparsers = parser.add_subparsers(dest="cmd", help="Subcommand Help")
    parser_scan = subparsers.add_parser("scan", aliases=["s"], help="Scans the file provided")
    parser_scan.add_argument("file_name", help="Name of the file being scanned")
    args = parser.parse_args()

    #if args.cmd == "scan":
     #   someFunc()
