"""Command-line interface.

    orgx-parcel make 1234567      -> prints a parcel ID with its check digit
    orgx-parcel check OX12345674  -> exit code 0 if valid, 1 otherwise
    orgx-parcel version
"""

import argparse
import sys

from . import __version__
from .ids import is_valid, make_id


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="orgx-parcel", description="OrgX parcel-ID toolkit")
    sub = parser.add_subparsers(dest="command", required=True)

    make_cmd = sub.add_parser("make", help="create a parcel ID from a serial number")
    make_cmd.add_argument("serial", type=int)

    check_cmd = sub.add_parser("check", help="validate a parcel ID")
    check_cmd.add_argument("parcel_id")

    sub.add_parser("version", help="print the version")

    args = parser.parse_args(argv)

    if args.command == "make":
        try:
            print(make_id(args.serial))
        except ValueError as error:
            print(f"error: {error}", file=sys.stderr)
            return 2
        return 0

    if args.command == "check":
        valid = is_valid(args.parcel_id)
        print("valid" if valid else "invalid")
        return 0 if valid else 1

    print(__version__)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
