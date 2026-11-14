from __future__ import annotations

import json
from pathlib import Path

from tools.frontier import analyze_sources
from tools.frontier.__main__ import main


ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "tests" / "frontier_cases"


def _run(case: str, func: str) -> dict:
    return analyze_sources([CASES / case / "sample.c"], func, case)


def test_entry_return_when_caller_checks_errno():
    result = _run("entry_errno", "pedit_act")
    assert result["status"] == "found"
    assert result["intercept"] == "pedit_act"
    assert result["position"] == "entry"
    assert result["return_value"] == "-EINVAL"


def test_caller_frees_allocation_on_existing_errno():
    result = _run("caller_frees", "child")
    assert result["status"] == "found"
    assert result["intercept"] == "child"
    assert result["return_value"] == "-EINVAL"
    pairs = {(item["function"], item["return_value"]) for item in result["candidates"]}
    assert ("child", "-EINVAL") in pairs
    assert ("parent", "-ENOMEM") in pairs


def test_void_function_lifts_to_caller_entry():
    result = _run("lift_parent", "child_write")
    assert result["status"] == "found"
    assert result["intercept"] == "parent_handle"
    assert result["return_value"] == "-ENOMEM"


def test_void_skb_owner_has_no_safe_return():
    result = _run("void_skb", "rxrpc_input_data")
    assert result["status"] == "out_of_scope"
    assert result["intercept"] == ""


def test_generic_path_is_rejected():
    result = _run("generic_path", "vfs_write")
    assert result["status"] == "out_of_scope"


def test_cleanup_function_is_rejected():
    result = _run("cleanup_func", "ep_free")
    assert result["status"] == "out_of_scope"


def test_missing_caller_is_insufficient_input():
    result = _run("no_caller", "child")
    assert result["status"] == "insufficient_input"


def test_cli_manifest_prints_intercept(capsys):
    code = main([str(CASES / "entry_errno" / "case.json")])
    captured = capsys.readouterr()
    assert code == 0
    assert "拦截点：pedit_act 入口" in captured.out
    assert "候选返回值：-EINVAL" in captured.out


def test_ops_table_call_is_a_caller():
    result = _run("ops_table", "do_act")
    assert result["status"] == "found"
    assert result["intercept"] == "do_act"
    assert result["return_value"] == "-EPERM"


def test_syscall_macro_uses_assigned_errno():
    result = _run("syscall_macro", "fremovexattr")
    assert result["status"] == "found"
    assert result["intercept"] == "fremovexattr"
    values = {item["return_value"] for item in result["candidates"]}
    assert values == {"-EBADF", "-ERANGE"}


def test_enoioctlcmd_is_not_a_candidate():
    result = _run("enoioctl", "hci_ioctl")
    # No macro definitions establish whether the two names alias.
    assert result["status"] == "partial"
    assert result["candidates"][0]["caller_contract"] == "partial"
    values = {item["return_value"] for item in result["candidates"]}
    assert values == {"-EPERM"}


def test_creation_init_is_listed_when_enqueue_has_no_errno():
    result = _run("creation_ops", "hq_enqueue")
    assert result["intercept"] == "hq_init"
    assert result["return_value"] == "-EINVAL"
    assert result["candidates"][0]["relation"] == "creation"


def test_releases_attribute_is_an_entry_obligation():
    result = _run("macro_guard", "locked")
    assert "locked" not in {item["function"] for item in result["candidates"]}


def test_if0_keeps_the_else_branch():
    result = _run("macro_if0", "child")
    assert result["status"] == "found"
    assert {item["return_value"] for item in result["candidates"]} == {"-EPERM"}


def test_bpf_call_macro_is_the_helper_name():
    result = _run("macro_bpf", "bpf_chk")
    # The BPF macro's concrete return type/expansion is not supplied.
    assert result["status"] == "partial"
    assert result["return_value"] == "-EINVAL"


def test_compat_syscall_macro():
    result = _run("macro_compat", "fremovexattr")
    assert result["status"] == "found"
    assert result["return_value"] == "-EPERM"


def test_is_err_or_null_inside_unlikely():
    result = _run("macro_errptr", "make")
    assert result["status"] == "found"
    assert result["return_value"] == "ERR_PTR(-EINVAL)"
    assert result["return_kind"] == "err_ptr"


def test_chained_ops_pointer_reaches_ioctl():
    result = _run("chain_ops", "hci_ioctl")
    assert result["status"] == "partial"  # errno/sentinel values are not supplied
    values = {item["return_value"] for item in result["candidates"]}
    assert values == {"-EPERM"}


def test_call_inside_if_condition_accepts_negative():
    result = _run("call_in_if", "do_dump")
    assert result["status"] == "found"
    assert result["return_value"] == "-EMSGSIZE"


def test_same_function_lists_every_terminal_errno():
    result = _run("two_values", "fn")
    assert result["status"] == "found"
    values = [item["return_value"] for item in result["candidates"]]
    assert values == ["-EPERM", "-EINVAL"]


def test_while_not_err_accepts_negative():
    result = _run("loop_while", "child")
    # Loop exit propagates errno, but parent's return contract is not supplied.
    assert result["status"] == "partial"
    assert result["candidates"][0]["caller_evidence"][0]["return_flow"]["status"] == "propagated"
    assert result["intercept"] == "child"
    assert result["return_value"] == "-EROFS"


def test_return_not_err_accepts_negative():
    result = _run("return_not", "child")
    assert result["status"] == "partial"  # Boolean result has no supplied caller.
    # This source does not supply bool's typedef or its defining header.
    assert result["candidates"][0]["caller_evidence"][0]["return_flow"]["status"] == "unknown"
    assert result["return_value"] == "-EPERM"


def test_caller_checked_named_sentinel():
    result = _run("named_sentinel", "target")
    assert result["status"] == "found"
    assert result["return_value"] == "SENTINEL"
    assert result["return_kind"] == "named"


def test_ifdef_both_branches_keep_the_call():
    result = _run("ifdef_keep", "target")
    assert result["status"] == "found"
    assert result["return_value"] == "SENTINEL"


def test_goto_out_unlocks_before_return():
    result = _run("goto_unlock", "child")
    assert result["status"] == "found"
    assert result["intercept"] == "child"
    assert result["return_value"] == "-ENOTTY"


def test_unrelated_cleanup_callee_does_not_free_the_allocation():
    result = _run("callee_free", "parse")
    assert "parse" not in {item["function"] for item in result["candidates"]}


def test_function_macro_alias_is_the_real_body():
    result = _run("macro_alias", "expand_stack")
    assert result["status"] == "found"
    assert result["intercept"] == "expand_stack_locked"
    assert result["return_value"] == "-EINVAL"


def test_unlocked_ioctl_accepts_existing_errno():
    result = _run("ioctl_fops", "inner")
    assert result["status"] == "found"
    assert result["intercept"] == "inner"
    assert result["return_value"] == "-ENOTTY"


def test_read_once_ops_chain():
    result = _run("read_once_ops", "sco_sock_connect")
    assert result["status"] == "found"
    assert result["intercept"] == "sco_sock_connect"
    assert result["return_value"] == "-EBADFD"
    assert "connect" not in {item["function"] for item in result["candidates"]}


def test_null_fallthrough_after_spinlock():
    result = _run("null_fallthrough", "find")
    assert result["status"] == "found"
    assert result["intercept"] == "find"
    assert result["return_value"] == "NULL"
    assert result["return_kind"] == "null"


def test_fdput_after_call_is_released():
    result = _run("fd_put", "child")
    assert result["status"] == "found"
    assert result["intercept"] == "child"
    assert result["return_value"] == "-EINVAL"


def test_unconfirmed_caller_stays_uncovered():
    result = _run("partial_caller", "child")
    assert result["status"] == "partial"
    assert result["intercept"] == "child"
    assert result["return_value"] == "-EINVAL"
    assert result["uncovered"] == ["kernel_wrap"]


def test_cli_json(capsys):
    code = main(["--func", "ep_free", "--src", str(CASES / "cleanup_func" / "sample.c"), "--json"])
    captured = capsys.readouterr()
    assert code == 2
    payload = json.loads(captured.out)
    assert payload["status"] == "out_of_scope"
