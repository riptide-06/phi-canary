#!/usr/bin/env python3
"""PHI-canary demo (thin wrapper). See src/demo_run.py.

    python3 demo.py          # OFFLINE cached replay — 0 API calls (default)
    python3 demo.py --live   # re-run the cell live against the model
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent / "src"))
from demo_run import run_demo

if __name__ == "__main__":
    sys.exit(run_demo(live="--live" in sys.argv))
