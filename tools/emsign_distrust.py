#!/usr/bin/env python3
"""Distrust the eight compromised intermediates (shim — prefer: emsign-g3 distrust)."""
import sys

import _ensure_src_path  # noqa: F401

from emsign_g3.cli import main

if __name__ == "__main__":
    raise SystemExit(main(["distrust", *sys.argv[1:]]))
