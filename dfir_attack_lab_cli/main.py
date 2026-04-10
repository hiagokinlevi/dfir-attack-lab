"""Console-script wrapper for the k1n DFIR Attack Lab CLI."""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) in sys.path:
    sys.path.remove(str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT))

from cli.main import cli


def main() -> None:
    """Run the Click CLI."""
    cli()


__all__ = ["cli", "main"]
