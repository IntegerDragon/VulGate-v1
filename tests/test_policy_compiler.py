from __future__ import annotations

import json
import os
import shutil
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from tools.policy import PolicyCandidate, compile_candidate
from tools.policy.candidate import parse_candidate_file
from tools.policy.dsl import validate_dsl
from tools.rulegen import verifier
from tools.frontier import analyze_sources


ROOT = Path(__file__).resolve().parents[1]
POLICIES = ROOT / "tests" / "policies"


def _metadata(policy_id: str, target: str, unsafe: int, fallback: int) -> dict[str, object]:
    return {
        "policy_id": policy_id,
        "target_function": target,
        "protection_boundary": "function_entry",
        "abi": "int",
        "unsafe_action": {"value": unsafe},
        "unknown_action": {"value": fallback},
        "error_action": {"value": fallback, "disable_policy": True},
        "max_steps": 64,
        "max_call_depth": 2,
    }


SIMPLE_DSL = """
@monitor("vulnerable_copy", phase="enter")
def monitor(ctx, input, len):
    ctx.set(status="safe")
    if len > 16:
        ctx.set(status="unsafe")
    else:
        ctx.set(status="safe")

@intercept("vulnerable_copy")
def intercept(ctx, input, len):
    facts = ctx.get()
    if facts.status == "safe":
        return PASS
    return BLOCK(value=-13)
"""


def _constant_dsl(status: str) -> str:
    return f"""
@monitor("vulnerable_copy", phase="enter")
def monitor(ctx, input, len):
    ctx.set(status="{status}")

@intercept("vulnerable_copy")
def intercept(ctx, input, len):
    facts = ctx.get()
    return PASS
"""


@pytest.mark.parametrize(
    "policy_dir",
    ["cve_2022_0778", "cve_2020_25212"],
)
def test_cve_policy_candidate_compiles(policy_dir, tmp_path):
    bundle = compile_candidate(parse_candidate_file(POLICIES / policy_dir / "policy.md"), tmp_path / policy_dir)

    assert bundle.verify_report["accepted"], json.dumps(bundle.verify_report, indent=2)
    assert bundle.manifest_path.exists()
    assert bundle.ir_path.exists()
    assert bundle.program_path.exists()
    assert bundle.review_c_path.exists()

    report = verifier.verify_file(bundle.program_path)
    assert report["accepted"], json.dumps(report, indent=2)


def test_simple_comparison_policy_emits_legacy_compatible_bytecode(tmp_path):
    candidate = PolicyCandidate(metadata=_metadata("simple_arg_guard", "vulnerable_copy", -13, -13), dsl=SIMPLE_DSL)
    bundle = compile_candidate(candidate, tmp_path)

    assert bundle.verify_report["accepted"], json.dumps(bundle.verify_report, indent=2)
    assert bundle.verify_report["bytecode_model"] == "scalar_decision_tree"
    assert bundle.verify_report["instruction_count"] == 7
    assert bundle.verify_report["helper_names"] == ["get_arg"]


@pytest.fixture(scope="module")
def vm_probe(tmp_path_factory):
    compiler = shutil.which("cc") or shutil.which("gcc")
    if not compiler:
        pytest.skip("native compiler required for actual runtime decision validation")
    directory = tmp_path_factory.mktemp("policy_vm")
    source = directory / "probe.c"
    executable = directory / ("probe.exe" if os.name == "nt" else "probe")
    source.write_text('''
#include "autoshield.h"
#include <stdio.h>
#include <stdlib.h>
/* These scalar policies never read target memory. Refuse it if emitted. */
int safe_read(void *dst, const void *src, size_t len) { return -1; }
int main(int argc, char **argv) {
    shadow_program program;
    shadow_ctx ctx;
    shadow_policy policy;
    shadow_stats stats;
    shadow_ctx_init(&ctx);
    shadow_policy_init(&policy);
    if (argc < 2 || shadow_program_load(argv[1], &program) != 0) return 2;
    for (int i=2; i<argc && i-2<SHADOW_MAX_ARGS; i++)
        ctx.args[i-2]=strtoull(argv[i], NULL, 10);
    printf("%d\\n", run_ebpf_vm(&ctx, &program, &policy, &stats));
    shadow_program_free(&program);
    return 0;
}
''', encoding="utf-8")
    subprocess.run([compiler, "-std=c11", "-I", str(ROOT / "runtime"), str(source),
                    str(ROOT / "runtime/vm.c"), "-o", str(executable)],
                   check=True, capture_output=True, text=True)

    def run(bundle, *args):
        result = subprocess.run([str(executable), str(bundle.program_path), *map(str, args)],
                                check=True, capture_output=True, text=True, timeout=5)
        return int(result.stdout.strip())
    return run


@pytest.mark.parametrize("operator", [">", ">=", "<", "<=", "==", "!="])
def test_lowered_comparison_matches_runtime_decisions(operator, vm_probe, tmp_path):
    dsl = f'''@monitor("vulnerable_copy", phase="enter")
def guard(ctx, size, pointer):
    ctx.set(status="safe")
    if size {operator} 16:
        ctx.set(status="unsafe")
    else:
        ctx.set(status="safe")
'''
    bundle = compile_candidate(PolicyCandidate(_metadata("comparison", "vulnerable_copy", -13, -13), dsl), tmp_path)
    assert bundle.verify_report["monitor_lowering_complete"]
    for value in [0, 1, 15, 16, 17, 2**64 - 1]:
        # The expected result is independent of instruction layout/code generation.
        expected = {">": value > 16, ">=": value >= 16, "<": value < 16,
                    "<=": value <= 16, "==": value == 16, "!=": value != 16}[operator]
        assert vm_probe(bundle, value, 99) == int(expected)


def test_lowering_preserves_following_statements_and_early_return(vm_probe, tmp_path):
    dsl = '''@monitor("vulnerable_copy")
def guard(ctx, arg0):
    ctx.set(status="safe")
    if arg0 > 16:
        ctx.set(status="unsafe")
        return
    ctx.set(status="unknown")
'''
    bundle = compile_candidate(PolicyCandidate(_metadata("tail", "vulnerable_copy", -13, -13), dsl), tmp_path)
    assert vm_probe(bundle, 17) == 1
    assert vm_probe(bundle, 0) == 2


def test_unsupported_monitor_does_not_compile_only_its_safe_prefix(vm_probe, tmp_path):
    dsl = '''@monitor("vulnerable_copy")
def guard(ctx, arg0):
    ctx.set(status="safe")
    require(arg0.readable)
    if arg0 > 16:
        ctx.set(status="unsafe")
    else:
        ctx.set(status="safe")
'''
    bundle = compile_candidate(PolicyCandidate(_metadata("unsupported", "vulnerable_copy", -13, -13), dsl), tmp_path)
    assert not bundle.verify_report["monitor_lowering_complete"]
    assert bundle.verify_report["lowering_limitations"]
    assert vm_probe(bundle, 0) == 2
    assert vm_probe(bundle, 17) == 2


def test_compilation_does_not_invent_or_authorize_return_actions(tmp_path):
    metadata = {"target_function": "vulnerable_copy", "enforceable": True, "deployment_ready": True}
    bundle = compile_candidate(PolicyCandidate(metadata, _constant_dsl("safe")), tmp_path)
    manifest = json.loads(bundle.manifest_path.read_text())
    assert not manifest["enforceable"]
    assert not manifest["deployment_ready"]
    assert not manifest["policy_lowering_complete"]
    assert "value" not in manifest["unsafe_action"]
    assert bundle.verify_report["action_binding"]["status"] == "unbound"


def bound_fixture(tmp_path):
    source = tmp_path / "input.c"
    source.write_text("int vulnerable_copy(void) {return -13;}\nint caller(void) {int r=vulnerable_copy(); if(r<0) return r; return 0;}")
    catalog = analyze_sources([source], "vulnerable_copy")
    ident = catalog["candidates"][0]["candidate_id"]
    metadata = _metadata("bound", "vulnerable_copy", -13, -13)
    for name in ("unsafe_action", "unknown_action", "error_action"):
        metadata[name]["candidate_id"] = ident
    return source, catalog, PolicyCandidate(metadata, SIMPLE_DSL)


def test_binding_replays_sources_but_does_not_grant_deployment(tmp_path):
    _, catalog, candidate = bound_fixture(tmp_path)
    bundle = compile_candidate(candidate, tmp_path / "bundle", frontier_report=catalog)
    assert bundle.verify_report["accepted"]
    binding = bundle.verify_report["action_binding"]
    assert binding["status"] == "source_matched"
    assert binding["catalog_replayed"]
    assert binding["actions"]["unsafe_action"]["resolved_integer"] == -13
    assert not binding["authorized"]
    assert not bundle.verify_report["deployment_ready"]


@pytest.mark.parametrize("change", ["return_value", "candidate_id", "target", "boundary", "source", "forged_catalog"])
def test_binding_rejects_changed_or_forged_claims(tmp_path, change):
    source, catalog, candidate = bound_fixture(tmp_path)
    if change == "return_value":
        candidate.metadata["unsafe_action"]["value"] = -1
    elif change == "candidate_id":
        candidate.metadata["unsafe_action"]["candidate_id"] = "not-a-candidate"
    elif change == "target":
        candidate.metadata["target_function"] = "different"
    elif change == "boundary":
        candidate.metadata["protection_boundary"] = "mid_function"
    elif change == "source":
        source.write_text(source.read_text().replace("return -13", "return 0"))
    else:
        # A catalog's editable declarations do not override actual source replay.
        catalog = deepcopy(catalog)
        catalog["candidates"][0]["return_value"] = "-1"
        catalog["analysis"]["enforceable"] = True
        candidate.metadata["unsafe_action"]["value"] = -1
    bundle = compile_candidate(candidate, tmp_path / "bundle", frontier_report=catalog)
    assert not bundle.verify_report["accepted"]
    assert bundle.verify_report["errors"]
    assert not bundle.verify_report["enforceable"]
    assert bundle.program_path.read_bytes() == b""


def test_quoted_candidate_id_without_separate_catalog_is_not_authority(tmp_path):
    _, _, candidate = bound_fixture(tmp_path)
    bundle = compile_candidate(candidate, tmp_path / "bundle")
    assert not bundle.verify_report["accepted"]


def test_additional_error_state_is_not_authorized_by_return_candidate(tmp_path):
    _, catalog, candidate = bound_fixture(tmp_path)
    candidate.metadata["unsafe_action"]["error"] = "SET_PROCESS_ERROR_QUEUE"
    bundle = compile_candidate(candidate, tmp_path / "bundle", frontier_report=catalog)
    action = bundle.verify_report["action_binding"]["actions"]["unsafe_action"]
    assert any("error-state" in reason for reason in action["pending"])
    assert not action["authorized"]


def test_constant_status_policies_compile(tmp_path):
    for status in ["safe", "unsafe", "unknown", "error"]:
        candidate = PolicyCandidate(
            metadata=_metadata(f"constant_{status}", "vulnerable_copy", -13, -13),
            dsl=_constant_dsl(status),
        )
        bundle = compile_candidate(candidate, tmp_path / status)
        assert bundle.verify_report["accepted"]
        assert verifier.verify_file(bundle.program_path)["accepted"]


def test_invalid_dsl_rejects_import_and_direct_target_call():
    bad = """
import os

@monitor("decode_attr_security_label", phase="enter")
def monitor(ctx, xdr, bitmap, label):
    ctx.set(status="unsafe")
    decode_attr_security_label(xdr, bitmap, label)
"""
    result = validate_dsl(bad, "decode_attr_security_label")
    assert not result.accepted
    assert any("import" in error for error in result.errors)
    assert any("direct target function call" in error for error in result.errors)


def test_invalid_dsl_rejects_unbounded_loop():
    bad = """
@monitor("BN_mod_sqrt", phase="enter")
def monitor(ctx, a, p):
    ctx.set(status="safe")
    while p:
        ctx.set(status="unsafe")
"""
    result = validate_dsl(bad, "BN_mod_sqrt")
    assert not result.accepted
    assert any("while loops are forbidden" in error for error in result.errors)
