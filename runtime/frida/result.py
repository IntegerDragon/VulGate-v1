"""Stable exit codes and error classification for Frida bundle operations."""
from __future__ import annotations

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_BUNDLE = 3
EXIT_MOUNT = 4
EXIT_PRIVILEGE = 5
EXIT_TARGET = 6
EXIT_PARTIAL = 7
EXIT_ALREADY_INSTALLED = 8

_PRIVILEGE_HINTS = (
    'permission denied',
    'unable to access',
    'ptrace',
    'operation not permitted',
    'access denied',
)


def classify_probe(errors: list[dict] | None) -> int:
    """Map the agent probe error list to a CLI exit code."""
    codes = {error.get('code') for error in errors or [] if isinstance(error, dict)}
    if not codes:
        return EXIT_OK
    if 'E_ALREADY_INSTALLED' in codes:
        return EXIT_ALREADY_INSTALLED
    return EXIT_MOUNT


def classify_exception(error: BaseException) -> int:
    """Map a bundle/attach exception to a CLI exit code."""
    text = str(error).lower()
    if isinstance(error, FileNotFoundError) or 'no such file or directory' in text:
        return EXIT_BUNDLE
    if 'artifact pin mismatch' in text or 'target mismatch' in text:
        return EXIT_TARGET
    if 'unsupported bundle schema' in text or 'rule must contain' in text:
        return EXIT_BUNDLE
    for hint in _PRIVILEGE_HINTS:
        if hint in text:
            return EXIT_PRIVILEGE
    if 'not found' in text or 'processnotfound' in text or 'process not found' in text:
        return EXIT_TARGET
    return EXIT_MOUNT


def summarize_probe(results: list[dict]) -> dict:
    """Aggregate per-process probe results for the CLI summary line."""
    ok = [item for item in results if item.get('ok')]
    failed = [item for item in results if not item.get('ok')]
    return {
        'event': 'probe-summary',
        'checked': len(results),
        'ok': len(ok),
        'failed': len(failed),
        'errors': [{'pid': item['pid'], 'errors': item['errors']} for item in failed],
    }


def exit_code_for_summary(summary: dict) -> int:
    checked = int(summary.get('checked') or 0)
    failed = int(summary.get('failed') or 0)
    if checked == 0:
        return EXIT_TARGET
    if failed == 0:
        return EXIT_OK
    codes = {
        error.get('code')
        for item in summary.get('errors') or []
        for error in item.get('errors') or []
        if isinstance(error, dict)
    }
    if 'E_ALREADY_INSTALLED' in codes:
        return EXIT_ALREADY_INSTALLED
    if failed < checked:
        return EXIT_PARTIAL
    return EXIT_MOUNT
