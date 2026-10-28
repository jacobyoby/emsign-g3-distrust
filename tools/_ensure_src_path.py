"""Prepend src/ to sys.path so tools/*.py shims work without pip install."""
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if _SRC.is_dir():
    root = str(_SRC)
    if root not in sys.path:
        sys.path.insert(0, root)
