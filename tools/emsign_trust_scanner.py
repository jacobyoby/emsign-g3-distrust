#!/usr/bin/env python3
"""Scan trust stores for compromised eMudhra/emSign G3 anchors (shim — prefer: emsign-g3 scan)."""
import sys

import _ensure_src_path  # noqa: F401

from emsign_g3.scan import run_scan

if __name__ == "__main__":
    raise SystemExit(run_scan(as_json="--json" in sys.argv))
