"""Compile VulGate policy candidates into local policy bundles."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from .candidate import PolicyCandidate, parse_candidate_file
    from .dsl import validate_dsl
    from .ir import build_ir
    from .lowering import compile_monitor
    from .actions import bind_actions
    from tools.rulegen import ebpf_asm
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from tools.policy.candidate import PolicyCandidate, parse_candidate_file
    from tools.policy.dsl import validate_dsl
    from tools.policy.ir import build_ir
    from tools.policy.lowering import compile_monitor
    from tools.policy.actions import bind_actions
    from tools.rulegen import ebpf_asm


@dataclass
class PolicyBundle:
    manifest_path: Path
    ir_path: Path
    program_path: Path
    review_c_path: Path
    verify_report_path: Path
    verify_report: dict[str, Any]


def compile_file(input_path: Path, output_dir: Path, *, frontier_report_path: Path | None = None) -> PolicyBundle:
    catalog = json.loads(frontier_report_path.read_text(encoding="utf-8")) if frontier_report_path else None
    return compile_candidate(parse_candidate_file(input_path), output_dir, frontier_report=catalog)


def compile_candidate(candidate: PolicyCandidate, output_dir: Path, *, frontier_report=None) -> PolicyBundle:
    metadata = _normalized_metadata(candidate.metadata)
    validation = validate_dsl(candidate.dsl, metadata["target_function"])
    report: dict[str, Any] = {
        "accepted": validation.accepted,
        "policy_id": metadata["policy_id"],
        "errors": validation.errors,
        "warnings": validation.warnings,
        "checks": [],
        "generated_at": int(time.time()),
        "enforceable": False,
        "deployment_ready": False,
        "monitor_lowering_complete": False,
        "policy_lowering_complete": False,
        "action_binding": {"status": "unbound"},
    }

    binding, binding_errors = bind_actions(metadata, frontier_report)
    report["action_binding"] = binding
    report["errors"].extend(binding_errors)
    report["accepted"] = validation.accepted and not binding_errors
    if not report["accepted"]:
        return _write_bundle(candidate, metadata, [], b"", report, output_dir)

    ir = build_ir(metadata, validation.functions)
    program_text, bytecode_model, limitations = compile_monitor(validation.functions)
    bytecode = ebpf_asm.assemble_text(program_text)
    report["bytecode_model"] = bytecode_model
    report["monitor_lowering_complete"] = bytecode_model != "legacy_unknown_stub"
    report["parameter_domain"] = "raw_unsigned_64"
    report["target_abi_binding"] = "not_verified"
    report["lowering_limitations"] = limitations
    report["instruction_count"] = len(bytecode) // 8
    report["helper_names"] = ["get_arg"] if "call get_arg" in program_text else []
    report["checks"] = [
        {"name": "dsl_allowed_subset", "accepted": True},
        {"name": "monitor_status_set", "accepted": any(function.kind == "monitor" for function in validation.functions)},
        {"name": "action_contracts_present", "accepted": _actions_present(metadata)},
        {"name": "shadow_resource_models", "accepted": False, "status": "not_verified"},
    ]
    report["warnings"].append("compilation does not authorize return actions or deployment; intercept/check remain review IR")
    if bytecode_model == "legacy_unknown_stub":
        report["warnings"].append(
            "complex DSL was serialized to high-level IR; compatibility bytecode returns UNKNOWN until adapter-backed runtime execution is enabled"
        )

    return _write_bundle(candidate, metadata, [ir.to_jsonable()], bytecode, report, output_dir)


def _write_bundle(
    candidate: PolicyCandidate,
    metadata: dict[str, Any],
    ir_items: list[dict[str, Any]],
    bytecode: bytes,
    report: dict[str, Any],
    output_dir: Path,
) -> PolicyBundle:
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = output_dir / "policy_manifest.json"
    ir_path = output_dir / "policy.ir.json"
    program_path = output_dir / "policy.bin"
    review_c_path = output_dir / "shadow.c"
    verify_report_path = output_dir / "verify_report.json"

    manifest = {
        "schema_version": "vulgate.policy.v0.2",
        **metadata,
        "enforceable": False,
        "deployment_ready": False,
        "monitor_lowering_complete": report["monitor_lowering_complete"],
        "policy_lowering_complete": False,
        "action_binding": report["action_binding"],
        "runtime": {
            "program": program_path.name,
            "decision_map": {
                "safe": "PASS",
                "unsafe": "BLOCK",
                "unknown": "UNKNOWN/REQUIRES_BOUND_ACTION",
                "error": "VM_ERROR/REQUIRES_BOUND_ACTION",
            },
        },
        "dsl": candidate.dsl,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    ir_path.write_text(json.dumps(ir_items, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    program_path.write_bytes(bytecode)
    review_c_path.write_text(_review_c(metadata, report), encoding="utf-8")
    verify_report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return PolicyBundle(
        manifest_path=manifest_path,
        ir_path=ir_path,
        program_path=program_path,
        review_c_path=review_c_path,
        verify_report_path=verify_report_path,
        verify_report=report,
    )


def _normalized_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(metadata)
    normalized.setdefault("policy_id", "unnamed_policy")
    normalized.setdefault("target_function", "")
    normalized.setdefault("protection_boundary", "function_entry")
    normalized.setdefault("abi", "int")
    for key in ("unsafe_action", "unknown_action", "error_action"):
        action = dict(normalized.get(key, {}) or {})
        action.setdefault("error", "")
        action.setdefault("disable_policy", key == "error_action")
        normalized[key] = action
    return normalized


def _actions_present(metadata: dict[str, Any]) -> bool:
    return all(
        isinstance(metadata.get(key), dict) and "value" in metadata[key]
        for key in ("unsafe_action", "unknown_action", "error_action")
    )


def _review_c(metadata: dict[str, Any], report: dict[str, Any]) -> str:
    return f"""// VulGate review C for {metadata.get('policy_id', 'unnamed_policy')}.
// Generated locally by tools/policy; verifier accepted: {report.get('accepted', False)}.

#define SHADOW_PASS 0
#define SHADOW_BLOCK 1
#define SHADOW_UNKNOWN 2
#define SHADOW_VM_ERROR 3

int shadow_main(void)
{{
    /*
     * Review artifact only.  The runtime-compatible bytecode is written to
     * policy.bin.  Complex DSL policies are preserved in policy.ir.json until
     * adapter-backed execution is enabled outside this local v0.2 release.
     */
    return SHADOW_UNKNOWN;
}}
"""
