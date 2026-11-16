from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from runtime.dsl import x86  # noqa: E402

FIXTURE = ROOT / 'tests' / 'workloads' / 'dsl' / 'callsite_fixture.c'


@pytest.mark.skipif(sys.platform != 'linux' or shutil.which('objdump') is None
                    or shutil.which('nm') is None or shutil.which('gcc') is None,
                    reason='callsite/line resolution needs Linux binutils + gcc')
def test_callsite_and_line_resolution(tmp_path: Path) -> None:
    binary = tmp_path / 'callsite_fixture'
    subprocess.run(['gcc', '-O0', '-g', '-no-pie', '-rdynamic', str(FIXTURE),
                    '-o', str(binary)], check=True)
    callsite = x86.resolve_callsite(binary, 'caller', 'callee')
    assert callsite > 0
    line = x86.resolve_line(binary, 'callsite_fixture.c', 18)
    assert abs(line - callsite) <= 64

