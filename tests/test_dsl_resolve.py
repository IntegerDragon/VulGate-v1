from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from runtime.dsl import parser, resolve  # noqa: E402


def _local_binary(tmp_path: Path) -> Path:
    source = tmp_path / 'local_target.c'
    source.write_text('''
static int local_target(int value) { return value + 1; }
int main(void) { return local_target(1); }
''', encoding='utf-8')
    binary = tmp_path / 'local_target'
    subprocess.run(['gcc', '-O0', '-g', str(source), '-o', str(binary)], check=True)
    return binary


@pytest.mark.skipif(sys.platform != 'linux' or shutil.which('nm') is None,
                    reason='offset resolution needs Linux nm')
def test_resolve_local_symbol_offset(tmp_path: Path) -> None:
    binary = _local_binary(tmp_path)
    patch = parser.parse('''
action REJECT:
{
    return_type: int
    return: -1
}

mount local:
{
    location: symbol="local_target", args=[int], return=int
    nature: intercept
    behavior: { if (true) { return block("REJECT"); } }
}
''')
    assert patch.mounts[0].offset is None
    resolve.resolve_patch(patch, executable=binary)
    assert patch.mounts[0].offset is not None
    assert patch.mounts[0].offset > 0


@pytest.mark.skipif(sys.platform != 'linux' or shutil.which('nm') is None,
                    reason='offset resolution needs Linux nm')
def test_resolve_keeps_explicit_offset(tmp_path: Path) -> None:
    binary = _local_binary(tmp_path)
    patch = parser.parse('''
action REJECT:
{
    return_type: int
    return: -1
}

mount local:
{
    location: symbol="local_target", offset=0x1234, args=[int], return=int
    nature: intercept
    behavior: { if (true) { return block("REJECT"); } }
}
''')
    resolve.resolve_patch(patch, executable=binary)
    assert patch.mounts[0].offset == 0x1234
