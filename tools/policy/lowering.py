"""Whole-monitor lowering for a deliberately small, typed scalar DSL subset.

Every admitted path ends in an explicit decision. Unsupported reachable syntax
rejects the whole lowering; it never disappears from a partially compiled check.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass

from .dsl import STATUS_TO_DECISION


@dataclass
class Branch:
    argument: int
    opcode: str
    bound: int
    yes: int | Branch
    no: int | Branch


class UnsupportedLowering(ValueError):
    pass


def compile_monitor(functions):
    monitors = [f for f in functions if f.kind == "monitor"]
    try:
        if len(monitors) != 1:
            raise UnsupportedLowering("exactly one monitor is required by the scalar backend")
        monitor = monitors[0]
        if monitor.decorator_args.get("phase", "enter") != "enter":
            raise UnsupportedLowering("only entry monitors have an argument context")
        if not monitor.parameters or monitor.parameters[0] != "ctx":
            raise UnsupportedLowering("first monitor parameter must be ctx")
        if len(monitor.parameters) > 7:
            raise UnsupportedLowering("runtime supports at most six raw arguments")
        tree = _lower(monitor.body, STATUS_TO_DECISION["unknown"], monitor.parameters[1:], [512])
        program = _emit(tree)
        if len(program) > 4096:
            raise UnsupportedLowering("lowered program exceeds the runtime instruction limit")
        model = "constant_status" if isinstance(tree, int) else "scalar_decision_tree"
        return "\n".join(program) + "\n", model, []
    except (UnsupportedLowering, RecursionError) as exc:
        return "mov64 r0, unknown\nexit\n", "legacy_unknown_stub", [str(exc) or "lowering depth exceeded"]


def _lower(statements, status, parameters, budget):
    for index, stmt in enumerate(statements):
        budget[0] -= 1
        if budget[0] < 0:
            raise UnsupportedLowering("scalar lowering path budget exceeded")
        if isinstance(stmt, ast.Pass):
            continue
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str):
            continue  # A docstring has no monitor effects.
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            call = stmt.value
            if (isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name)
                    and call.func.value.id == "ctx" and call.func.attr == "set"
                    and not call.args and len(call.keywords) == 1
                    and call.keywords[0].arg == "status"
                    and isinstance(call.keywords[0].value, ast.Constant)
                    and call.keywords[0].value.value in STATUS_TO_DECISION):
                status = STATUS_TO_DECISION[call.keywords[0].value.value]
                continue
        if isinstance(stmt, ast.Return) and stmt.value is None:
            return status
        if isinstance(stmt, ast.If):
            test = stmt.test
            if (not isinstance(test, ast.Compare) or len(test.ops) != 1 or len(test.comparators) != 1
                    or not isinstance(test.left, ast.Name) or test.left.id not in parameters
                    or not isinstance(test.comparators[0], ast.Constant)):
                raise UnsupportedLowering("condition must compare a raw argument with an integer literal")
            bound = test.comparators[0].value
            if type(bound) is not int or not 0 <= bound <= 2**31 - 1:
                raise UnsupportedLowering("comparison literal is outside the supported unsigned/immediate domain")
            opcode = {ast.Gt: "jgt", ast.GtE: "jge", ast.Eq: "jeq", ast.NotEq: "jne",
                      ast.Lt: "jge", ast.LtE: "jgt"}.get(type(test.ops[0]))
            if opcode is None:
                raise UnsupportedLowering("unsupported comparison operator")
            tail = statements[index + 1:]
            yes = _lower(stmt.body + tail, status, parameters, budget)
            no = _lower(stmt.orelse + tail, status, parameters, budget)
            if isinstance(test.ops[0], (ast.Lt, ast.LtE)):
                yes, no = no, yes
            return Branch(parameters.index(test.left.id), opcode, bound, yes, no)
        raise UnsupportedLowering(f"unsupported monitor statement: {type(stmt).__name__}")
    return status


def _emit(tree):
    if isinstance(tree, int):
        return [f"mov64 r0, {tree}", "exit"]
    no, yes = _emit(tree.no), _emit(tree.yes)
    return [f"mov64 r1, {tree.argument}", "call get_arg",
            f"{tree.opcode} r0, {tree.bound}, +{len(no)}", *no, *yes]
