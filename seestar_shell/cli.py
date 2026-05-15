import argparse
from seestar_shell import deploy, inventory, pack, upload


def main():
    parser = argparse.ArgumentParser(
        prog="seestar-shell",
        description="Security research toolkit for the ZWO Seestar telescope",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND", required=True)

    inventory.add_subparser(sub)
    pack.add_subparser(sub)
    upload.add_subparser(sub)
    deploy.add_subparser(sub)

    args = parser.parse_args()
    args.func(args)
