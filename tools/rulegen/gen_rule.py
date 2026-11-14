#!/usr/bin/env python3
"""Generate a tiny autoshield shadow rule for the prototype demo.

The first prototype keeps the LLM step reviewable: a prompt or human-readable
description selects a simple read-only predicate, and this script emits both the
review C file and the bytecode consumed by the runtime VM.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

try:
    from . import ebpf_asm, verifier
except ImportError:
    import ebpf_asm
    import verifier


def build_arg_gt_program(arg_index: int, threshold: int) -> bytes:
    template = (Path(__file__).with_name("rules") / "user_oob.asm.in").read_text(encoding="utf-8")
    return ebpf_asm.assemble_text(
        template.format(
            arg_index=arg_index,
            threshold=threshold,
        )
    )


def render_shadow_c(template: str, arg_index: int, threshold: int) -> str:
    body = (
        f"unsigned long value = shadow_get_arg({arg_index});\n"
        f"    if (value > {threshold}) {{\n"
        "        return SHADOW_BLOCK;\n"
        "    }\n"
        "    return SHADOW_PASS;"
    )
    return template.replace("/* AUTOSHIELD_RULE_BODY */", body)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--demo", choices=["user_oob"], default="user_oob")
    parser.add_argument("--arg-index", type=int, default=1)
    parser.add_argument("--max-len", type=int, default=16)
    parser.add_argument("--output-dir", type=Path, default=Path("build/workloads/basic"))
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    template = Path(__file__).with_name("template.c").read_text(encoding="utf-8")
    shadow_c = render_shadow_c(template, args.arg_index, args.max_len)
    shadow_bin = build_arg_gt_program(args.arg_index, args.max_len)

    c_path = args.output_dir / "shadow.c"
    bin_path = args.output_dir / "shadow.bin"
    manifest_path = args.output_dir / "manifest.json"
    report_path = args.output_dir / "verify_report.json"

    c_path.write_text(shadow_c, encoding="utf-8")
    bin_path.write_bytes(shadow_bin)

    manifest = {
        "project": "autoshield",
        "demo": args.demo,
        "rule": "arg_gt",
        "arg_index": args.arg_index,
        "threshold": args.max_len,
        "program": str(bin_path),
        "generated_at": int(time.time()),
        "note": "prototype rule: block when function argument exceeds safe length",
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    report = verifier.verify_file(bin_path)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"wrote {c_path}")
    print(f"wrote {bin_path}")
    print(f"wrote {manifest_path}")
    print(f"wrote {report_path}")
    if args.verify and not report["accepted"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
