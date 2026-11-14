#!/usr/bin/env python3
"""Compile a VulGate policy candidate into local bundle artifacts."""

from __future__ import annotations

import argparse
from pathlib import Path

try:
    from .compiler import compile_file
except ImportError:
    from compiler import compile_file


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--frontier-report", type=Path,
                        help="separately supplied source report; replayed before candidate IDs are bound")
    args = parser.parse_args()

    bundle = compile_file(args.input, args.output_dir, frontier_report_path=args.frontier_report)
    print(f"wrote {bundle.manifest_path}")
    print(f"wrote {bundle.ir_path}")
    print(f"wrote {bundle.program_path}")
    print(f"wrote {bundle.review_c_path}")
    print(f"wrote {bundle.verify_report_path}")
    return 0 if bundle.verify_report["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
