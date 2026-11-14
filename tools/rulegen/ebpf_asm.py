#!/usr/bin/env python3
"""Tiny text assembler for the prototype eBPF subset.

The syntax is intentionally small and mirrors the verifier/runtime subset:

    mov64 r1, 1
    call get_arg
    jgt r0, 16, +2
    exit

Unsupported instructions used by negative tests can still be written as
semantic mnemonics, for example ``stxdw [r0+0], r0``.
"""

from __future__ import annotations

import argparse
import re
import struct
from dataclasses import dataclass
from pathlib import Path


BPF_CALL = 0x85
BPF_EXIT = 0x95

OPCODES = {
    "add64": 0x07,
    "sub64": 0x17,
    "and64": 0x57,
    "or64": 0x47,
    "mov64": 0xB7,
    "mov64x": 0xBF,
    "jeq": 0x15,
    "jgt": 0x25,
    "jge": 0x35,
    "jne": 0x55,
    "stxdw": 0x7B,
    "ldxdw": 0x79,
}

HELPERS = {
    "get_arg": 1,
    "safe_read_u8": 2,
    "get_reg": 3,
}

CONSTANTS = {
    "pass": 0,
    "block": 1,
    "unknown": 2,
    "vm_error": 3,
}

REG_RE = re.compile(r"^r(10|[0-9])$")
MEM_RE = re.compile(r"^\[\s*r(10|[0-9])\s*([+-]\s*(?:0x[0-9a-fA-F]+|\d+))?\s*\]$")


@dataclass(frozen=True)
class AsmInsn:
    code: int
    dst: int = 0
    src: int = 0
    off: int = 0
    imm: int = 0

    def to_bytes(self) -> bytes:
        return struct.pack("<BBhi", self.code, (self.src << 4) | self.dst, self.off, self.imm)


def _strip_comment(line: str) -> str:
    return line.split("#", 1)[0].split(";", 1)[0].strip()


def _parts(line: str) -> list[str]:
    return [part.strip() for part in line.split(",")]


def _parse_int(token: str) -> int:
    token = token.strip().replace(" ", "")
    lowered = token.lower()
    if lowered in CONSTANTS:
        return CONSTANTS[lowered]
    if lowered in HELPERS:
        return HELPERS[lowered]
    return int(token, 0)


def _parse_reg(token: str) -> int:
    match = REG_RE.match(token.strip().lower())
    if not match:
        raise ValueError(f"expected register, got {token!r}")
    return int(match.group(1))


def _parse_mem(token: str) -> tuple[int, int]:
    match = MEM_RE.match(token.strip().lower())
    if not match:
        raise ValueError(f"expected memory operand like [r1+0], got {token!r}")
    base = int(match.group(1))
    off = _parse_int(match.group(2) or "0")
    return base, off


def assemble_line(line: str, line_no: int) -> AsmInsn | None:
    line = _strip_comment(line)
    if not line:
        return None

    mnemonic, _, rest = line.partition(" ")
    mnemonic = mnemonic.lower()
    operands = _parts(rest) if rest else []

    try:
        if mnemonic == "exit":
            if operands:
                raise ValueError("exit takes no operands")
            return AsmInsn(BPF_EXIT)

        if mnemonic == "call":
            if len(operands) != 1:
                raise ValueError("call takes one helper operand")
            return AsmInsn(BPF_CALL, imm=_parse_int(operands[0]))

        if mnemonic == "raw":
            if len(operands) != 4:
                raise ValueError("raw takes: code, regs, off, imm")
            code, regs, off, imm = (_parse_int(operand) for operand in operands)
            return AsmInsn(code, dst=regs & 0x0F, src=regs >> 4, off=off, imm=imm)

        if mnemonic in {"mov64", "add64", "sub64", "and64", "or64"}:
            if len(operands) != 2:
                raise ValueError(f"{mnemonic} takes: dst, imm")
            return AsmInsn(OPCODES[mnemonic], dst=_parse_reg(operands[0]), imm=_parse_int(operands[1]))

        if mnemonic == "mov64x":
            if len(operands) != 2:
                raise ValueError("mov64x takes: dst, src")
            return AsmInsn(OPCODES[mnemonic], dst=_parse_reg(operands[0]), src=_parse_reg(operands[1]))

        if mnemonic in {"jeq", "jgt", "jge", "jne"}:
            if len(operands) != 3:
                raise ValueError(f"{mnemonic} takes: dst, imm, off")
            return AsmInsn(
                OPCODES[mnemonic],
                dst=_parse_reg(operands[0]),
                off=_parse_int(operands[2]),
                imm=_parse_int(operands[1]),
            )

        if mnemonic == "stxdw":
            if len(operands) != 2:
                raise ValueError("stxdw takes: [dst+off], src")
            dst, off = _parse_mem(operands[0])
            return AsmInsn(OPCODES[mnemonic], dst=dst, src=_parse_reg(operands[1]), off=off)

        if mnemonic == "ldxdw":
            if len(operands) != 2:
                raise ValueError("ldxdw takes: dst, [src+off]")
            src, off = _parse_mem(operands[1])
            return AsmInsn(OPCODES[mnemonic], dst=_parse_reg(operands[0]), src=src, off=off)
    except ValueError as exc:
        raise ValueError(f"line {line_no}: {exc}") from exc

    raise ValueError(f"line {line_no}: unknown mnemonic {mnemonic!r}")


def assemble_text(text: str) -> bytes:
    insns = [
        insn
        for line_no, line in enumerate(text.splitlines(), start=1)
        if (insn := assemble_line(line, line_no)) is not None
    ]
    if not insns:
        raise ValueError("program has no instructions")
    return b"".join(insn.to_bytes() for insn in insns)


def assemble_file(path: Path) -> bytes:
    return assemble_text(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    args = parser.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(assemble_file(args.input))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
