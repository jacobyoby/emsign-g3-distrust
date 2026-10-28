"""Unified CLI for emsign-g3 distrust tooling."""
from __future__ import annotations

import argparse

from emsign_g3.distrust import run_distrust
from emsign_g3.export import run_export
from emsign_g3.paths import default_certs_dir, indicators_csv_path
from emsign_g3.scan import run_scan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="emsign-g3",
        description="Detect and deny compromised eMudhra/emSign G3 intermediates (Bug 2083449).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="inventory trust stores (read-only)")
    scan_p.add_argument("--json", action="store_true", help="machine-readable output")

    dist_p = sub.add_parser("distrust", help="plan or apply intermediate blocklist")
    dist_p.add_argument("--apply", action="store_true", help="execute (default: dry run)")
    dist_p.add_argument("--undo", action="store_true", help="roll back instead of distrust")
    dist_p.add_argument(
        "--certs-dir",
        default=None,
        help=f"directory with eight verified PEMs (default: {default_certs_dir()})",
    )

    exp_p = sub.add_parser("export-indicators", help="SIEM/SOAR indicator bundle")
    exp_p.add_argument("--csv", default=None, help="path to indicators.csv")
    exp_p.add_argument(
        "--format",
        choices=("json", "ndjson", "sigma"),
        default="json",
        help="output format (default: json)",
    )
    exp_p.add_argument(
        "--ndjson",
        action="store_true",
        help="shorthand for --format ndjson (deprecated)",
    )
    exp_p.add_argument("--verify", action="store_true", help="verify PEMs match CSV")
    exp_p.add_argument("--certs-dir", default=None, help="PEM directory for --verify")
    exp_p.add_argument(
        "--output-dir",
        default=None,
        help="write --format sigma YAML files to this directory",
    )

    args = parser.parse_args(argv)

    if args.command == "scan":
        return run_scan(as_json=args.json)
    if args.command == "distrust":
        return run_distrust(apply=args.apply, undo=args.undo, certs_dir=args.certs_dir)
    if args.command == "export-indicators":
        return run_export(
            csv_path=args.csv or indicators_csv_path(),
            fmt=args.format,
            ndjson=args.ndjson,
            verify=args.verify,
            certs_dir=args.certs_dir,
            output_dir=args.output_dir,
        )

    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
