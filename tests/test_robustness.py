from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from tools.rulegen import ebpf_asm, verifier


CASES_DIR = Path(__file__).with_name("ebpf_cases")


def _assemble_case(case_name: str, tmp_path: Path) -> Path:
    source = CASES_DIR / case_name
    output = tmp_path / source.with_suffix(".bin").name
    output.write_bytes(ebpf_asm.assemble_file(source))
    return output


def test_generated_shadow_rule_is_accepted(user_workload):
    report = verifier.verify_file(user_workload["rule"])

    assert report["accepted"], report["errors"]
    assert report["instruction_count"] == 7
    assert report["helper_names"] == ["get_arg"]


@pytest.mark.parametrize(
    ("case_name", "expected_error"),
    [
        ("reject_store.asm", "write/store instruction"),
        ("reject_backjump.asm", "backward jump"),
        ("reject_raw_load.asm", "raw memory load"),
        ("reject_unknown_helper.asm", "helper 99 is not whitelisted"),
    ],
)
def test_verifier_rejects_bad_programs(case_name, expected_error, tmp_path):
    program = _assemble_case(case_name, tmp_path)
    report = verifier.verify_file(program)

    assert not report["accepted"]
    assert any(expected_error in error for error in report["errors"]), json.dumps(report, indent=2)


def test_safe_read_invalid_pointer_fails_safely(safe_read_probe):
    result = subprocess.run(
        [str(safe_read_probe)],
        text=True,
        capture_output=True,
        check=True,
    )

    assert "safe_read_invalid rc=-1" in result.stdout
