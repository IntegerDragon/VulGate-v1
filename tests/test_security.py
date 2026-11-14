from __future__ import annotations


def test_normal_request_passes(user_workload, run_with_env):
    result = run_with_env([user_workload["app"], "normal"], user_workload["preload_env"])

    output = result.stdout + result.stderr
    assert "AUTOSHIELD target=vulnerable_copy decision=PASS" in output
    assert "RESULT OK value=65" in output


def test_poc_is_blocked_before_vulnerable_body(user_workload, run_with_env):
    result = run_with_env([user_workload["app"], "poc"], user_workload["preload_env"])

    output = result.stdout + result.stderr
    assert "AUTOSHIELD target=vulnerable_copy decision=BLOCK" in output
    assert "RESULT BLOCKED code=-13" in output
    assert "VULN_REACHED" not in output


def test_unprotected_poc_reaches_vulnerable_body(user_workload, run_with_env):
    result = run_with_env([user_workload["app"], "poc"])

    output = result.stdout + result.stderr
    assert "VULN_REACHED" in output
    assert "RESULT OVERFLOW_WRITE value=65" in output
