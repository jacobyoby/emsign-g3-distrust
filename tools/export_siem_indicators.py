#!/usr/bin/env python3
"""Export SIEM indicators (shim — prefer: emsign-g3 export-indicators)."""
import sys

import _ensure_src_path  # noqa: F401

from emsign_g3.cli import main

if __name__ == "__main__":
    raise SystemExit(main(["export-indicators", *sys.argv[1:]]))
