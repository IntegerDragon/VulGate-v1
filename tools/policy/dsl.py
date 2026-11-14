"""AST validation for the VulGate policy DSL subset."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any


STATUS_TO_DECISION = {
    "safe": 0,
    "unsafe": 1,
    "unknown": 2,
    "error": 3,
}

ALLOWED_HELPERS = {
    "assert_action",
    "assert_model",
    "bounded_range",
    "require",
    "shadow_call",
    "SWRR",
    "BLOCK",
    "FALLBACK",
    "PASS",
}

ALLOWED_ADAPTER_METHODS = {
    "bit_length",
    "can_read",
    "capacity_at_entry",
    "get",
    "label",
    "private_cursor",
    "read_be32",
    "readable",
    "set",
    "snapshot",
}

ALLOWED_MODEL_HELPERS = {
    "bn_is_one_ro",
    "bn_mod_mul_ro",
    "bn_mod_sqr_ro",
    "setup_tonelli_state_ro",
}


@dataclass
class DslFunction:
    kind: str
    name: str
    target: str | None
    decorator_args: dict[str, Any]
    body: list[ast.stmt]
    parameters: list[str] = field(default_factory=list)
    status_sets: list[str] = field(default_factory=list)
    requires: list[str] = field(default_factory=list)
    asserts: list[str] = field(default_factory=list)
    shadow_calls: list[str] = field(default_factory=list)
    loops: list[str] = field(default_factory=list)


@dataclass
class DslValidation:
    functions: list[DslFunction]
    errors: list[str]
    warnings: list[str]

    @property
    def accepted(self) -> bool:
        return not self.errors


def validate_dsl(dsl: str, target_function: str | None = None) -> DslValidation:
    errors: list[str] = []
    warnings: list[str] = []
    try:
        tree = ast.parse(dsl)
    except SyntaxError as exc:
        return DslValidation([], [f"syntax error: {exc}"], warnings)

    functions: list[DslFunction] = []
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            errors.append("import statements are forbidden")
            continue
        if isinstance(node, ast.Assign):
            if not _is_allowed_top_level_constant(node):
                errors.append("only simple constant assignments are allowed at top level")
                continue
            continue
        if not isinstance(node, ast.FunctionDef):
            errors.append(f"only function definitions are allowed at top level, got {type(node).__name__}")
            continue
        function, function_errors = _parse_function(node, target_function)
        functions.append(function)
        errors.extend(function_errors)

    if not any(function.kind == "monitor" for function in functions):
        errors.append("policy must define at least one @monitor")
    if not any(function.kind == "intercept" for function in functions):
        warnings.append("policy does not define @intercept; framework can generate generic intercept")
    if not any(function.kind == "check" for function in functions):
        warnings.append("policy does not define @check; framework can generate default audit")

    return DslValidation(functions=functions, errors=errors, warnings=warnings)


def _is_allowed_top_level_constant(node: ast.Assign) -> bool:
    if not all(isinstance(target, ast.Name) for target in node.targets):
        return False
    value = node.value
    if isinstance(value, ast.UnaryOp) and isinstance(value.op, (ast.UAdd, ast.USub)):
        value = value.operand
    return isinstance(value, ast.Constant) and isinstance(value.value, (int, str))


def _parse_function(node: ast.FunctionDef, target_function: str | None) -> tuple[DslFunction, list[str]]:
    errors: list[str] = []
    if not node.decorator_list:
        errors.append(f"function {node.name} must have a VulGate decorator")
        return DslFunction("unknown", node.name, None, {}, node.body), errors

    decorator = node.decorator_list[0]
    kind, args = _decorator_info(decorator)
    if kind not in {"monitor", "intercept", "check", "shadow"}:
        errors.append(f"function {node.name} uses unsupported decorator")
        return DslFunction(kind, node.name, None, {}, node.body), errors

    dsl_function = DslFunction(
        kind=kind,
        name=node.name,
        target=args.get("target") or args.get("name"),
        decorator_args=args,
        body=list(node.body),
        parameters=[arg.arg for arg in node.args.posonlyargs + node.args.args],
    )
    if node.args.vararg or node.args.kwarg or node.args.kwonlyargs or node.args.defaults:
        errors.append(f"function {node.name} must use fixed positional parameters without defaults")
    if kind in {"monitor", "intercept"} and target_function and dsl_function.target != target_function:
        errors.append(f"{kind} {node.name} target does not match policy target_function")
    for stmt in node.body:
        _walk_statement(stmt, dsl_function, errors, target_function)
    if not dsl_function.status_sets and kind == "monitor":
        errors.append(f"monitor {node.name} must set ctx status")
    return dsl_function, errors


def _decorator_info(decorator: ast.expr) -> tuple[str, dict[str, Any]]:
    if not isinstance(decorator, ast.Call):
        return "", {}
    name = _expr_name(decorator.func)
    args: dict[str, Any] = {}
    if decorator.args:
        first = decorator.args[0]
        if isinstance(first, ast.Constant):
            args["target"] = first.value
            args["name"] = first.value
    for keyword in decorator.keywords:
        if keyword.arg and isinstance(keyword.value, ast.Constant):
            args[keyword.arg] = keyword.value.value
    return name or "", args


def _walk_statement(stmt: ast.stmt, function: DslFunction, errors: list[str], target_function: str | None) -> None:
    for node in ast.walk(stmt):
        if isinstance(node, ast.While):
            errors.append(f"while loops are forbidden in {function.name}")
        elif isinstance(node, ast.For):
            if not _is_bounded_range(node.iter):
                errors.append(f"for loop in {function.name} must use bounded_range")
            else:
                function.loops.append(ast.unparse(node.iter))
        if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(node.ctx, (ast.Store, ast.Del)):
            errors.append(f"target field/subscript mutation is forbidden in {function.name}")
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            errors.append("import is forbidden inside DSL")
        elif isinstance(node, ast.Call):
            _validate_call(node, function, errors, target_function)


def _validate_call(call: ast.Call, function: DslFunction, errors: list[str], target_function: str | None) -> None:
    name = _expr_name(call.func)
    if name == "ctx.set":
        status = _status_argument(call)
        if status is None:
            errors.append(f"ctx.set in {function.name} must use status='safe|unsafe|unknown|error'")
        else:
            function.status_sets.append(status)
        return
    if name == "ctx.get":
        return
    if name == "require":
        function.requires.append(ast.unparse(call))
        return
    if name in {"assert_model", "assert_action"}:
        function.asserts.append(ast.unparse(call))
        return
    if name == "shadow_call":
        function.shadow_calls.append(ast.unparse(call))
        return
    if name in ALLOWED_HELPERS or name in ALLOWED_MODEL_HELPERS:
        return
    if name and "." in name:
        method = name.rsplit(".", 1)[1]
        if method in ALLOWED_ADAPTER_METHODS:
            return
    if name == target_function:
        errors.append(f"direct target function call {name!r} is forbidden in {function.name}")
        return
    errors.append(f"unmodeled call {name!r} in {function.name}")


def _is_bounded_range(iter_expr: ast.expr) -> bool:
    return isinstance(iter_expr, ast.Call) and _expr_name(iter_expr.func) == "bounded_range"


def _status_argument(call: ast.Call) -> str | None:
    for keyword in call.keywords:
        if keyword.arg == "status" and isinstance(keyword.value, ast.Constant):
            value = keyword.value.value
            if value in STATUS_TO_DECISION:
                return value
    return None


def _expr_name(expr: ast.expr) -> str | None:
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        base = _expr_name(expr.value)
        return f"{base}.{expr.attr}" if base else expr.attr
    return None
