import argparse
import ast
from vulnai.parser.python_parser import fileToCode
from vulnai.parser.python_parser import treeWalk

def main():
    parser= argparse.ArgumentParser(prog="vulnai")
    subparsers = parser.add_subparsers(dest="cmd", help="Subcommand Help")
    parser_scan = subparsers.add_parser("scan", aliases=["s"], help="Scans the file provided")
    parser_scan.add_argument("target", help="Name of the file being scanned")
    args = parser.parse_args() #Checks if the args passed are valid or no.

    if args.cmd == "scan" or args.cmd == 's':
        print("Scanning: " + args.target)
        codeTree = fileToCode(args.target)
        walker = treeWalk()
        walker.visit(codeTree)
        print(ast.dump(codeTree , indent = 4))
    elif args.cmd is None:
        parser.print_help()
        return
    