#!/usr/bin/env python3
"""Minimal verifier for autoshield shadow bytecode.

The prototype uses Linux eBPF's 8-byte instruction layout and intentionally
supports only the tiny read-only subset needed by the paper demo.
"""

from __future__ import annotations

import argparse
import json
import struct
from dataclasses import dataclass
from pathlib import Path


BPF_CLASS_MASK = 0x07
BPF_LD = 0x00
BPF_LDX = 0x01
BPF_ST = 0x02
BPF_STX = 0x03
BPF_ALU = 0x04
BPF_JMP = 0x05
BPF_JMP32 = 0x06
BPF_ALU64 = 0x07

BPF_CALL = 0x85
BPF_EXIT = 0x95

ALLOWED_HELPERS = {1: "get_arg", 2: "safe_read_u8", 3: "get_reg"}
ALLOWED_OPCODES = {
    0x04, 0x07, 0x0C, 0x0F,  # add
    0x14, 0x17, 0x1C, 0x1F,  # sub
    0x54, 0x57, 0x5C, 0x5F,  # and
    0x44, 0x47, 0x4C, 0x4F,  # or
    0xB4, 0xB7, 0xBC, 0xBF,  # mov
    0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D, 0x55, 0x5D,
    BPF_CALL,
    BPF_EXIT,
}


@dataclass(frozen=True)
class Insn:
    code: int
    regs: int
    off: int
    imm: int

    @property
    def dst(self) -> int:
        return self.regs & 0x0F

    @property
    def src(self) -> int:
        return self.regs >> 4


def parse_program(path: Path) -> list[Insn]:
    data = path.read_bytes()
    if len(data) == 0:
        raise ValueError("empty program")
    if len(data) % 8 != 0:
        raise ValueError(f"program size {len(data)} is not a multiple of 8")
    return [
        Insn(*struct.unpack_from("<BBhi", data, offset))
        for offset in range(0, len(data), 8)
    ]


def verify_program(insns: list[Insn], *, max_insns: int = 4096) -> dict:
    errors: list[str] = []
    helpers: list[int] = []
    branches = 0
    exits = 0

    if len(insns) > max_insns:
        errors.append(f"program has {len(insns)} instructions, max is {max_insns}")

    for pc, insn in enumerate(insns):
        cls = insn.code & BPF_CLASS_MASK

        if cls in {BPF_ST, BPF_STX}:
            errors.append(f"pc {pc}: write/store instruction 0x{insn.code:02x} is forbidden")

        if cls == BPF_LDX:
            errors.append(f"pc {pc}: raw memory load 0x{insn.code:02x} is forbidden; use safe_read helper")

        if insn.code not in ALLOWED_OPCODES:
            errors.append(f"pc {pc}: opcode 0x{insn.code:02x} is outside the prototype subset")

        if insn.code == BPF_CALL:
            helpers.append(insn.imm)
            if insn.imm not in ALLOWED_HELPERS:
                errors.append(f"pc {pc}: helper {insn.imm} is not whitelisted")

        if insn.code == BPF_EXIT:
            exits += 1

        if cls in {BPF_JMP, BPF_JMP32} and insn.code not in {BPF_CALL, BPF_EXIT}:
            branches += 1
            target = pc + 1 + insn.off
            if insn.off < 0:
                errors.append(f"pc {pc}: backward jump to pc {target} is forbidden")
            if target < 0 or target >= len(insns):
                errors.append(f"pc {pc}: jump target pc {target} is outside the program")

    if exits == 0:
        errors.append("program has no exit instruction")
    elif insns[-1].code != BPF_EXIT:
        errors.append("last instruction must be exit in this prototype")

    return {
        "accepted": not errors,
        "instruction_count": len(insns),
        "branch_count": branches,
        "helper_ids": helpers,
        "helper_names": [ALLOWED_HELPERS.get(helper, "unknown") for helper in helpers],
        "errors": errors,
    }


def verify_file(path: Path, *, max_insns: int = 4096) -> dict:
    try:
        return verify_program(parse_program(path), max_insns=max_insns)
    except ValueError as exc:
        return {
            "accepted": False,
            "instruction_count": 0,
            "branch_count": 0,
            "helper_ids": [],
            "helper_names": [],
            "errors": [str(exc)],
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("program", type=Path)
    parser.add_argument("--max-insns", type=int, default=4096)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    report = verify_file(args.program, max_insns=args.max_insns)
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if report["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
