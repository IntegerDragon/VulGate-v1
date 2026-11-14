"""Simple high-level IR for validated policy DSL."""

from __future__ import annotations

import ast
from dataclasses import asdict, dataclass
from typing import Any

try:
    from .dsl import DslFunction
except ImportError:
    from dsl import DslFunction


@dataclass
class PolicyIr:
    schema_version: str
    policy_id: str
    target_function: str
    protection_boundary: str
    actions: dict[str, Any]
    status_logic: dict[str, str]
    functions: list[dict[str, Any]]
    shadow_functions: list[dict[str, Any]]
    runtime_bytecode_model: str

    def to_jsonable(self) -> dict[str, Any]:
        return asdict(self)


def build_ir(metadata: dict[str, Any], functions: list[DslFunction]) -> PolicyIr:
    return PolicyIr(
        schema_version="vulgate.policy.v0.2",
        policy_id=str(metadata.get("policy_id", "unnamed_policy")),
        target_function=str(metadata.get("target_function", "")),
        protection_boundary=str(metadata.get("protection_boundary", "function_entry")),
        actions={
            "unsafe": metadata.get("unsafe_action", {}),
            "unknown": metadata.get("unknown_action", {}),
            "error": metadata.get("error_action", {}),
        },
        status_logic=_status_logic(metadata, functions),
        functions=[_function_ir(function) for function in functions],
        shadow_functions=_shadow_functions(metadata, functions),
        runtime_bytecode_model="legacy_ebpf_compatible_stub_or_simple_predicate",
    )


def _function_ir(function: DslFunction) -> dict[str, Any]:
    return {
        "kind": function.kind,
        "name": function.name,
        "target": function.target,
        "decorator_args": function.decorator_args,
        "parameters": function.parameters,
        "status_sets": function.status_sets,
        "requires": function.requires,
        "asserts": function.asserts,
        "shadow_calls": function.shadow_calls,
        "loops": function.loops,
        "sample_body": "\n".join(ast.unparse(stmt) for stmt in function.body[:12]),
    }


def _shadow_functions(metadata: dict[str, Any], functions: list[DslFunction]) -> list[dict[str, Any]]:
    declared = list(metadata.get("shadow_functions", []) or [])
    for function in functions:
        if function.kind == "shadow":
            declared.append(
                {
                    "name": function.target or function.name,
                    "declared_by": function.name,
                    **function.decorator_args,
                }
            )
    return declared


def _status_logic(metadata: dict[str, Any], functions: list[DslFunction]) -> dict[str, str]:
    declared = metadata.get("status_logic", {})
    if isinstance(declared, dict):
        return {str(key): str(value) for key, value in declared.items()}
    sets = [status for function in functions for status in function.status_sets]
    return {
        "safe": "set safe by monitor",
        "unsafe": "set unsafe by monitor" if "unsafe" in sets else "not declared",
        "unknown": "set unknown by monitor or runtime failure" if "unknown" in sets else "runtime failure",
        "error": "set error by monitor or VM/adapter invariant failure" if "error" in sets else "VM/adapter failure",
    }
