"""Bounded path analysis of an injected return, using an explicit C CFG.

This checks return use, not complete ownership or concurrent program safety.
Unknown syntax and effects remain unknown; no CVE names occur in this layer.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field, replace
import re

from .syntax import ControlFlow, declarator_identifier, parse_flow
from .constants import integer_expression
from .ctypes import (CType, INT, UNKNOWN, MODELS, TypeContext, arithmetic_type, compatible, convert_integer, integer_info, integer_literal,
                     member, member_names, parameters as typed_parameters, type_context)


@dataclass(frozen=True)
class Value:
    atom: int | str | None = None
    kind: str = "scalar"
    sign: int | None = None
    origin: bool = False
    ctype: CType | None = None
    issue: str | None = None

    def truth(self) -> bool | None:
        if self.kind in {"reference", "error_pointer"}:
            return True
        if isinstance(self.atom, int):
            return bool(self.atom)
        if self.sign is not None:
            return self.sign != 0
        return None


def integer(number: int, origin=False, ctype=None) -> Value:
    return Value(number, sign=(number > 0) - (number < 0), origin=origin, ctype=ctype)


def candidate_value(expr: str, kind: str, constants=None) -> Value:
    if kind == "null":
        return Value(0, "null", 0, True)
    if kind == "err_ptr":
        inner = expr[expr.find("(") + 1:expr.rfind(")")].strip()
        resolved = integer_expression(inner, constants or {})
        return Value(inner if resolved is None else resolved, "error_pointer", -1, True)
    resolved = integer_expression(expr, constants or {})
    if resolved is not None:
        return integer(resolved, True)
    try:
        return integer(int(expr, 0), True)
    except ValueError:
        return Value(expr, sign=-1 if kind == "neg" else None, origin=True)


def convert_value(value, ctype, model, state):
    """C assignment conversion, shared by storage, parameters and returns."""
    if value.issue:
        state.unknown.add(value.issue)
    if ctype.kind == "pointer":
        if value.atom == 0:
            return replace(value, kind="null", ctype=ctype)
        if value.kind in {"reference", "null", "error_pointer", "string_pointer"}:
            if (value.kind == "reference" and value.ctype and value.ctype.kind == "pointer"
                    and not compatible(value.ctype.target or UNKNOWN, ctype.target or UNKNOWN)):
                state.unknown.add("pointer_pointee_type_unbound_or_incompatible")
            return replace(value, ctype=ctype)
        if value.atom is not None or value.sign is not None:
            state.unknown.add("unmodeled_pointer_conversion")
            return Value(origin=value.origin, ctype=ctype)
    elif ctype.kind == "integer":
        if ctype.name == "_Bool" and value.truth() is not None:
            return integer(int(value.truth()), value.origin, ctype)
        if isinstance(value.atom, int) and value.kind in {"scalar", "null"}:
            converted, reason = convert_integer(value.atom, ctype, model)
            if reason:
                state.unknown.add(reason)
                return Value(origin=value.origin, ctype=ctype)
            return integer(converted, value.origin, ctype)
        if value.kind != "scalar":
            state.unknown.add("unmodeled_integer_conversion")
            return Value(origin=value.origin, ctype=ctype)
        source = integer_info(value.ctype or INT, model)
        target = integer_info(ctype, model)
        if (value.atom is not None or value.sign is not None) and value.ctype != ctype:
            if not (source and target and source[0] == target[0] and target[3] >= source[3]):
                state.unknown.add("integer_conversion_range_unbound")
                return Value(origin=value.origin, ctype=ctype)
    elif ctype.kind == "unknown" and (value.atom is not None or value.sign is not None):
        state.unknown.add("unmodeled_declared_type:" + ctype.name)
        return Value(origin=value.origin, ctype=ctype)
    return replace(value, ctype=ctype)


def converted_candidate(value, ctype, model, types=TypeContext()):
    state = State(records=dict(types.records))
    result = convert_value(value, ctype, MODELS[model], state)
    return replace(result, issue=next(iter(sorted(state.unknown)), None))


@dataclass
class State:
    env: dict[str, Value] = field(default_factory=dict)
    seen: bool = False
    guards: frozenset[int] = frozenset()
    unsafe: set[str] = field(default_factory=set)
    unknown: set[str] = field(default_factory=set)
    trace: tuple[int, ...] = ()
    escaped: frozenset[str] = frozenset()
    types: dict[str, CType] = field(default_factory=dict)
    records: dict = field(default_factory=dict)

    def clone(self):
        return State(dict(self.env), self.seen, self.guards, set(self.unsafe), set(self.unknown), self.trace, self.escaped,
                     dict(self.types), self.records)

    def signature(self):
        return (tuple(sorted(self.env.items())), self.seen, self.guards,
                tuple(sorted(self.unsafe)), tuple(sorted(self.unknown)), self.escaped, tuple(sorted(self.types.items())))


@dataclass
class Outcome:
    value: Value
    state: State


@dataclass
class FlowResult:
    status: str
    outcomes: list[Outcome]
    reasons: list[str]
    explored_states: int
    composition: tuple[str, ...] = ()

    def evidence(self) -> dict:
        return {"status": self.status, "reasons": self.reasons,
                "explored_states": self.explored_states,
                "returns": sorted({str(o.value.atom) for o in self.outcomes}),
                "paths": [list(o.state.trace) for o in self.outcomes[:8]],
                "composed_functions": list(self.composition)}


@dataclass(frozen=True)
class CallPlan:
    """Source-derived continuation for a selected inner rejection, not an action."""
    function_id: str
    body: str
    parameters: str
    offset: int
    injected: Value
    constants: tuple[tuple[str, int], ...] = ()
    nested: CallPlan | None = None
    source_file: str = ""
    type_context: TypeContext = TypeContext()
    return_type: CType | None = None


@dataclass
class Budget:
    remaining: int
    explored: int = 0


class CallAlternatives(Exception):
    def __init__(self, outcomes):
        self.outcomes = outcomes


class Evaluator:
    def __init__(self, graph: ControlFlow, offset: int, injected: Value, constants=None, entry_injection=True,
                 *, call_plan=None, frame="", parameters=(), budget=None, depth=0, source_file="", globals_bound=False,
                 types=TypeContext(), integer_model="portable", return_type=None):
        self.graph = graph
        self.offset = len(graph.source[:graph.prefix_bytes]) + len(
            graph.source[graph.prefix_bytes:].decode("utf-8")[:offset].encode("utf-8"))
        self.injected = injected
        self.entry_injection = entry_injection
        self.call_plan = call_plan
        self.frame = frame
        self.parameters = {name: frame + name + "@parameter" for name, _ in parameters}
        self.budget = budget
        self.depth = depth
        self.call_override = None
        self.source_file = source_file
        self.globals_bound = globals_bound
        self.integer_model = MODELS[integer_model]
        self.return_type = return_type
        self.type_context = type_context(((source_file + "<flow>", graph.source.decode("utf-8")),), types, True)
        declaration_types = dict(self.type_context.declarations)
        self.cast_types = dict(self.type_context.casts)
        self.constants = {"NULL": 0, "false": 0, "true": 1, **(constants or {})}
        self.defined_constants = set(constants or {})
        self.types = {self.parameters[name]: kind for name, kind in parameters}
        pending = [graph.body]
        while pending:
            node = pending.pop()
            if node.type == "declaration":
                for declarator in node.children_by_field_name("declarator"):
                    ident = declarator_identifier(declarator)
                    if ident is None:
                        continue
                    ctype = declaration_types.get(len(graph.source[:ident.start_byte].decode("utf-8")), UNKNOWN)
                    key = self.variable(ident)
                    previous = self.types.get(key)
                    self.types[key] = ctype if previous in {None, ctype} else CType("unknown", "configuration-dependent type")
            pending.extend(node.named_children)

    def variable(self, node):
        key = self.graph.variable(node)
        return self.frame + key if "@" in key else self.parameters.get(key, key)

    def global_identity(self, key, text, state):
        if self.frame and not self.globals_bound and "@" not in key and text not in self.constants:
            state.unknown.add("unresolved_composed_global_identity")

    def composed_order(self, node, state):
        def constant(child):
            if child.type in {"number_literal", "null", "true", "false"}:
                return True
            if child.type == "identifier":
                return self.graph.text(child) in self.constants
            return child.type in {"parenthesized_expression", "unary_expression"} and all(
                constant(c) for c in child.named_children)

        arguments = node.child_by_field_name("arguments")
        if arguments is not None and len(arguments.named_children) > 1:
            pending = list(arguments.named_children)
            while pending:
                child = pending.pop()
                if child.type in {"call_expression", "assignment_expression", "update_expression"}:
                    state.unknown.add("unsequenced_composed_call_arguments")
                pending.extend(child.named_children)
        child, parent = node, node.parent
        while parent is not None and parent.type not in {"expression_statement", "declaration", "return_statement", "compound_statement"}:
            if parent.type == "binary_expression":
                operator = self.graph.text(parent.child_by_field_name("operator"))
                others = [c for c in parent.named_children if c != child]
                if operator not in {"&&", "||"} and not all(constant(c) for c in others):
                    state.unknown.add("unsequenced_composed_call_expression")
            elif parent.type == "assignment_expression":
                left = parent.child_by_field_name("left")
                if left is not None and left.type != "identifier":
                    state.unknown.add("unsequenced_composed_assignment")
            child, parent = parent, parent.parent

    def read(self, key: str | None, state: State) -> Value:
        if key is None:
            return Value()
        if key in state.env:
            value = state.env[key]
            if value.kind == "union_overlap":
                state.unknown.add("inactive_or_overlapping_union_member")
            ctype, _, reason = self.storage_type(key, state)
            if "." in key and reason:
                state.unknown.add(reason)
            return replace(value, ctype=ctype if ctype.kind != "unknown" else value.ctype)
        parent = key
        while "." in parent:
            parent = parent.rsplit(".", 1)[0]
            if parent + ".*" in state.env:
                value = state.env[parent + ".*"]
                if value.kind == "union_overlap":
                    state.unknown.add("inactive_or_overlapping_union_member")
                ctype, _, reason = self.storage_type(key, state)
                if reason:
                    state.unknown.add(reason)
                return replace(value, ctype=ctype if ctype.kind != "unknown" else None)
        return Value()

    def storage_type(self, key, state):
        if key is None:
            return UNKNOWN, (), "storage_identity_missing"
        if key in state.types:
            return state.types[key], (), None
        pieces = key.split(".")
        prefix, ctype = pieces[0], state.types.get(pieces[0], UNKNOWN)
        overlaps = []
        for name in pieces[1:]:
            if ctype.kind == "pointer":
                ctype = ctype.target or UNKNOWN
            ctype, siblings, reason = member(ctype, name, state.records)
            if reason:
                return ctype, tuple(overlaps), reason
            overlaps.extend(prefix + "." + sibling for sibling in siblings)
            prefix += "." + name
        return ctype, tuple(overlaps), None

    def convert(self, value, ctype, state):
        return convert_value(value, ctype, self.integer_model, state)

    def expression_type(self, node, state):
        """Resolve unevaluated operand types without executing their effects."""
        if node is None:
            return UNKNOWN
        kind = node.type
        if kind == "parenthesized_expression":
            return self.expression_type(node.named_children[0], state)
        if kind == "identifier":
            key = self.variable(node)
            return state.types.get(key, self.types.get(key, INT if self.graph.text(node) in self.constants else UNKNOWN))
        if kind == "number_literal":
            return integer_literal(self.graph.text(node), self.integer_model)[1]
        if kind in {"true", "false", "null"}:
            return INT
        if kind == "cast_expression":
            descriptor = node.child_by_field_name("type")
            return self.cast_types.get(len(self.graph.source[:descriptor.start_byte].decode("utf-8")), UNKNOWN)
        if kind in {"unary_expression", "pointer_expression", "update_expression"}:
            argument = self.expression_type(node.child_by_field_name("argument"), state)
            operator = self.graph.text(node.child_by_field_name("operator"))
            if operator == "!":
                return INT
            if operator == "&":
                return CType("pointer", target=argument)
            if operator == "*":
                return argument.target or UNKNOWN if argument.kind == "pointer" else UNKNOWN
            return argument if kind == "update_expression" else arithmetic_type(argument, INT, self.integer_model) or UNKNOWN
        if kind == "field_expression":
            base = self.expression_type(node.child_by_field_name("argument"), state)
            if self.graph.text(node.child_by_field_name("operator")) == "->":
                base = base.target or UNKNOWN if base.kind == "pointer" else UNKNOWN
            return member(base, self.graph.text(node.child_by_field_name("field")), state.records)[0]
        if kind == "assignment_expression":
            return self.expression_type(node.child_by_field_name("left"), state)
        if kind == "comma_expression":
            return self.expression_type(node.named_children[-1], state)
        if kind in {"binary_expression", "conditional_expression"}:
            if kind == "binary_expression":
                operator = self.graph.text(node.child_by_field_name("operator"))
                if operator in {"==", "!=", "<", "<=", ">", ">=", "&&", "||"}:
                    return INT
                left, right = (node.child_by_field_name(n) for n in ("left", "right"))
            else:
                left, right = (node.child_by_field_name(n) for n in ("consequence", "alternative"))
            a, b = self.expression_type(left, state), self.expression_type(right, state)
            if a.kind == b.kind == "integer":
                return arithmetic_type(a, b, self.integer_model) or UNKNOWN
            return a if a == b else UNKNOWN
        if kind == "call_expression":
            function = node.child_by_field_name("function")
            if function is not None and node.start_byte <= self.offset < function.end_byte:
                return (self.call_plan.return_type if self.call_plan else self.injected.ctype) or INT
            return dict(self.type_context.returns).get(self.graph.text(function), UNKNOWN)
        return UNKNOWN

    def binary(self, operator, left, right, state):
        if left.kind in {"reference", "null", "error_pointer", "string_pointer"} or right.kind in {"reference", "null", "error_pointer", "string_pointer"}:
            return binary(operator, left, right)
        common = arithmetic_type(left.ctype or INT, right.ctype or INT, self.integer_model)
        if common is None:
            state.unknown.add("usual_arithmetic_conversion_unbound")
            return Value(origin=left.origin or right.origin)
        left, right = self.convert(left, common, state), self.convert(right, common, state)
        if operator not in {"==", "!=", "<", "<=", ">", ">=", "+", "-", "*", "&", "|", "^"}:
            state.unknown.add("unsupported_integer_operator:" + operator)
            return Value(origin=left.origin or right.origin)
        result = binary(operator, left, right)
        if operator in {"==", "!=", "<", "<=", ">", ">="}:
            return replace(result, ctype=INT)
        if operator in {"&", "|", "^"} and not self.integer_model.widths and (left.sign == -1 or right.sign == -1):
            state.unknown.add("signed_integer_representation_unbound")
            return Value(origin=left.origin or right.origin, ctype=common)
        return self.convert(result, common, state)

    def configuration(self, node, state):
        condition = node.child_by_field_name("condition")
        name = node.child_by_field_name("name")
        if condition is not None:
            value = integer_expression(self.graph.text(condition), self.constants)
            if value is not None:
                return integer(value)
        elif name is not None and self.graph.text(name) in self.defined_constants:
            negated = re.match(r"\s*#\s*(?:ifndef|elifndef)\b", self.graph.text(node)) is not None
            return integer(not negated)
        state.unknown.add("unresolved_configuration")
        return Value()

    def write(self, key, value, state):
        if key is None:
            state.unknown.add("unresolved_write")
            return Value(origin=value.origin)
        else:
            ctype, overlaps, reason = self.storage_type(key, state)
            if "." in key and reason:
                state.unknown.add(reason)
            for prefix in overlaps:
                for old in list(state.env):
                    if old == prefix or old.startswith(prefix + "."):
                        del state.env[old]
                state.env[prefix] = Value(kind="union_overlap")
                state.env[prefix + ".*"] = Value(kind="union_overlap")
                if key.startswith(prefix + "."):
                    del state.env[prefix]
            if key in state.types or "." in key:
                value = self.convert(value, ctype, state)
            if key in overlaps and ctype.kind in {"integer", "pointer"}:
                # Same typed scalar union members have the same representation.
                # Other views remain unknown; no byte layout is guessed.
                for sibling in overlaps:
                    other, _, error = self.storage_type(sibling, state)
                    if error is None and other == ctype:
                        state.env[sibling] = value
                        state.env.pop(sibling + ".*", None)
            # Replacing an aggregate cannot leave stale initialized fields.
            for child in list(state.env):
                if child.startswith(key + "."):
                    del state.env[child]
            state.env[key] = value
            if "@" not in key and value.kind == "reference" and isinstance(value.atom, str):
                state.escaped = state.escaped | {value.atom}
            return value

    def lvalue(self, node, state):
        if node is None:
            return None
        if node.type == "identifier":
            key = self.variable(node)
            self.global_identity(key, self.graph.text(node), state)
            return key
        if node.type == "parenthesized_expression":
            return self.lvalue(node.named_children[0], state)
        if node.type == "field_expression":
            argument = node.child_by_field_name("argument")
            field_name = self.graph.text(node.child_by_field_name("field"))
            base = self.eval(argument, state)
            operator = self.graph.text(node.child_by_field_name("operator"))
            if operator == "->" and base.origin and (base.kind in {"null", "error_pointer"} or base.atom == 0):
                state.unsafe.add("invalid_pointer_dereference")
            if operator == "->" and self.frame and base.kind != "reference":
                state.unknown.add("unresolved_composed_pointer_alias")
            key = base.atom if base.kind == "reference" else self.lvalue(argument, state)
            return f"{key}.{field_name}" if key else None
        if node.type == "pointer_expression" and self.graph.text(node.child_by_field_name("operator")) == "*":
            pointer = self.eval(node.child_by_field_name("argument"), state)
            if pointer.origin and (pointer.kind in {"null", "error_pointer"} or pointer.atom == 0):
                state.unsafe.add("invalid_pointer_dereference")
            if self.frame and pointer.kind != "reference":
                state.unknown.add("unresolved_composed_pointer_alias")
            return pointer.atom if pointer.kind == "reference" else None
        if node.type == "subscript_expression":
            pointer = self.eval(node.child_by_field_name("argument"), state)
            index = self.eval(node.child_by_field_name("index"), state)
            if pointer.origin and (pointer.kind in {"null", "error_pointer"} or pointer.atom == 0):
                state.unsafe.add("invalid_pointer_dereference")
            if index.origin and index.sign == -1:
                state.unsafe.add("negative_error_used_as_index")
            return None
        return None

    def eval(self, node, state: State) -> Value:
        if node is None:
            return Value()
        kind = node.type
        text = self.graph.text(node)
        if node.is_error or node.is_missing:
            state.unknown.add("parse_error")
        if kind in {"parenthesized_expression", "expression_statement"}:
            return self.eval(node.named_children[0], state) if node.named_children else Value()
        if kind == "null":
            return Value(0, "null", 0)
        if kind in {"true", "false"}:
            return integer(kind == "true")
        if kind == "identifier":
            key = self.variable(node)
            self.global_identity(key, text, state)
            if key in state.env:
                return state.env[key]
            if text in self.constants:
                return integer(self.constants[text])
            if text.isupper():
                return Value(text)
            return self.read(key, state)
        if kind == "number_literal":
            number, ctype, reason = integer_literal(text, self.integer_model)
            if reason:
                state.unknown.add(reason)
            return Value() if number is None else integer(number, ctype=ctype)
        if kind in {"field_expression", "subscript_expression"}:
            return self.read(self.lvalue(node, state), state)
        if kind == "cast_expression":
            value = self.eval(node.child_by_field_name("value"), state)
            node_type = node.child_by_field_name("type")
            ctype = self.cast_types.get(len(self.graph.source[:node_type.start_byte].decode("utf-8")), UNKNOWN)
            if ctype.kind == "unknown":
                state.unknown.add("unmodeled_cast")
                return Value(origin=value.origin)
            return self.convert(value, ctype, state)
        if kind == "sizeof_expression":
            return Value(sign=1)
        if kind == "type_definition":
            pending = list(node.named_children)
            while pending:
                child = pending.pop()
                if child.type in {"array_declarator", "typeof_specifier"}:
                    state.unknown.add("typedef_variably_modified_type_unmodeled")
                pending.extend(child.named_children)
            return Value()
        if kind in {"unary_expression", "pointer_expression"}:
            operator = self.graph.text(node.child_by_field_name("operator"))
            argument = node.child_by_field_name("argument")
            if operator == "&":
                key = self.lvalue(argument, state)
                ctype, _, _ = self.storage_type(key, state)
                return Value(key, "reference", 1, ctype=CType("pointer", target=ctype))
            if operator == "*":
                return self.read(self.lvalue(node, state), state)
            value = self.eval(argument, state)
            if operator == "!":
                truth = value.truth()
                return Value(origin=value.origin) if truth is None else integer(not truth, value.origin)
            if operator == "-":
                if isinstance(value.atom, str) and value.ctype is None:
                    return Value("-" + value.atom, sign=-value.sign if value.sign is not None else None,
                                 origin=value.origin)
                return self.binary("-", integer(0), value, state)
            if operator == "+":
                promoted = arithmetic_type(value.ctype or INT, INT, self.integer_model)
                return self.convert(value, promoted or UNKNOWN, state)
            state.unknown.add("unsupported_unary")
            return Value(origin=value.origin)
        if kind == "binary_expression":
            operator = self.graph.text(node.child_by_field_name("operator"))
            left = self.eval(node.child_by_field_name("left"), state)
            if operator in {"&&", "||"}:
                truth = left.truth()
                if (operator == "&&" and truth is False) or (operator == "||" and truth is True):
                    return integer(truth, left.origin)
                before = state.seen
                right = self.eval(node.child_by_field_name("right"), state)
                # Only paths evaluating the selected call belong to this query.
                if truth is None and state.seen and not before:
                    rt = right.truth()
                    return Value(origin=True) if rt is None else integer(rt, True)
                if truth is None:
                    # Evaluate for evidence, but never certify the merged state:
                    # on the short-circuited path RHS writes/calls did not occur.
                    state.unknown.add("conditional_short_circuit_effects")
                    return Value(origin=left.origin or right.origin)
                rt = right.truth()
                return Value(origin=left.origin or right.origin) if rt is None else integer(rt, left.origin or right.origin)
            right = self.eval(node.child_by_field_name("right"), state)
            return self.binary(operator, left, right, state)
        if kind == "assignment_expression":
            left = node.child_by_field_name("left")
            key = self.lvalue(left, state)
            value = self.eval(node.child_by_field_name("right"), state)
            operator = self.graph.text(node.child_by_field_name("operator"))
            if operator != "=":
                value = self.binary(operator[:-1], self.read(key, state), value, state)
            return self.write(key, value, state)
        if kind == "update_expression":
            argument = node.child_by_field_name("argument")
            key = self.lvalue(argument, state)
            old = self.read(key, state)
            operator = self.graph.text(node.child_by_field_name("operator"))
            new = self.binary("+" if operator == "++" else "-", old, integer(1), state)
            new = self.write(key, new, state)
            return new if text.startswith(operator) else old
        if kind == "declaration":
            type_name = self.graph.text(node.child_by_field_name("type"))
            if any(c.type == "storage_class_specifier" and self.graph.text(c) in {"static", "extern", "thread_local", "_Thread_local"}
                   for c in node.named_children):
                state.unknown.add("unmodeled_storage_duration_or_linkage")
            for declaration in node.children_by_field_name("declarator"):
                ident = declarator_identifier(declaration)
                if ident is None:
                    state.unknown.add("unsupported_declaration")
                    continue
                key = self.variable(ident)
                state.types[key] = self.types.get(key, UNKNOWN)
                value = declaration.child_by_field_name("value")
                if value is not None and value.type == "initializer_list":
                    self.initialize(key, value, state)
                else:
                    self.write(key, self.eval(value, state), state)
            return Value()
        if kind == "call_expression":
            function = node.child_by_field_name("function")
            arguments = node.child_by_field_name("arguments")
            values = [self.eval(arg, state) for arg in arguments.named_children] if arguments else []
            if function is not None and node.start_byte <= self.offset < function.end_byte:
                if self.call_plan is not None or self.frame:
                    self.composed_order(node, state)
                if self.call_plan is not None:
                    if self.call_override is None:
                        raise CallAlternatives(_compose_call(self, values, state))
                    outcome = self.call_override
                    state.env = dict(outcome.state.env)
                    state.types = dict(outcome.state.types)
                    state.records = outcome.state.records
                    state.seen = True
                    state.unsafe.update(outcome.state.unsafe)
                    state.unknown.update(outcome.state.unknown)
                    state.escaped = outcome.state.escaped
                    state.trace = (*state.trace[-23:], self.graph.offset(node))
                    return outcome.value
                state.seen = True
                if self.injected.issue:
                    state.unknown.add(self.injected.issue)
                state.trace = (*state.trace[-23:], self.graph.offset(node))
                if not self.entry_injection:
                    # A wrapper returning the injected value has executed its
                    # own body, including potential global writes even when no
                    # explicit output address was passed. Scalar local return
                    # propagation need not fail when no tracked memory can be
                    # affected; this does not assert that the wrapper is pure.
                    if (any(v.kind == "reference" for v in values) or state.escaped
                            or any("@" not in key for key in state.env)):
                        state.unknown.add("propagated_callee_effects_unmodeled")
                    self.havoc(values, state)
                return self.injected
            name = self.graph.text(function)
            if name in {"IS_ERR", "IS_ERR_OR_NULL", "PTR_ERR", "ERR_PTR", "PTR_ERR_OR_ZERO"} and len(values) == 1:
                value = values[0]
                if name == "ERR_PTR":
                    return replace(value, kind="error_pointer")
                if name == "PTR_ERR" and value.kind == "error_pointer":
                    return Value(value.atom, sign=-1, origin=value.origin)
                if name == "PTR_ERR_OR_ZERO" and value.kind == "error_pointer":
                    return Value(value.atom, sign=-1, origin=value.origin)
                if name == "PTR_ERR_OR_ZERO" and (value.kind in {"null", "reference"} or value.atom == 0):
                    return integer(0, value.origin)
                if name == "PTR_ERR":
                    return integer(0, value.origin) if value.atom == 0 else Value(origin=value.origin)
                if value.kind in {"null", "error_pointer", "reference"} or value.atom == 0:
                    error = value.kind == "error_pointer"
                    return integer(error or (name == "IS_ERR_OR_NULL" and not value.truth()), value.origin)
                return Value(origin=value.origin)
            if any(value.origin for value in values):
                state.unknown.add("injected_value_passed_to_unmodeled_call")
            self.havoc(values, state)
            return Value(origin=any(value.origin for value in values))
        if kind == "conditional_expression":
            condition = self.eval(node.child_by_field_name("condition"), state)
            truth = condition.truth()
            if truth is not None:
                value = self.eval(node.child_by_field_name("consequence" if truth else "alternative"), state)
                ctype = self.expression_type(node, state)
                if ctype.kind == "unknown":
                    state.unknown.add("conditional_expression_type_unbound")
                return self.convert(value, ctype, state)
            state.unknown.add("unknown_conditional_expression")
            return Value(origin=condition.origin)
        if kind == "comma_expression":
            value = Value()
            for child in node.named_children:
                value = self.eval(child, state)
            return value
        if kind in {"string_literal", "concatenated_string"}:
            # Array-to-pointer conversion preserves non-nullness, but does not
            # invent a modeled writable storage object for the literal.
            return Value(kind="string_pointer", sign=1)
        state.unknown.add("unsupported_expression:" + kind)
        # Still find a selected call inside unsupported syntax, so it is not
        # silently omitted from the analyzed paths.
        value = Value()
        for child in node.named_children:
            value = self.eval(child, state)
        return Value(origin=value.origin)

    def havoc(self, values, state):
        # An unknown callee can recover the containing object from a subobject
        # pointer, follow stored pointers, and access unscoped/global storage.
        # Field-sized invalidation requires a closed effect summary.
        def root(key):
            return key.split(".", 1)[0]

        reachable = {root(key) for key in state.escaped}
        for value in values:
            if value.kind == "reference" and isinstance(value.atom, str):
                reachable.add(root(value.atom))
        reachable.update(root(key) for key in state.env if "@" not in key)
        pending = list(reachable)
        while pending:
            prefix = pending.pop()
            for key, value in state.env.items():
                if (key == prefix or key.startswith(prefix + ".")) and value.kind == "reference" and isinstance(value.atom, str):
                    target = root(value.atom)
                    if target not in reachable:
                        reachable.add(target)
                        pending.append(target)
        state.escaped = state.escaped | reachable
        for prefix in reachable:
            for key in list(state.env):
                if key == prefix or key.startswith(prefix + "."):
                    del state.env[key]
            state.env[prefix] = Value()
            state.env[prefix + ".*"] = Value()

    def initialize(self, key, node, state):
        for old in list(state.env):
            if old == key or old.startswith(key + "."):
                del state.env[old]
        ctype, _, _ = self.storage_type(key, state)
        if ctype.kind in {"integer", "pointer"}:
            if len(node.named_children) > 1:
                state.unknown.add("scalar_initializer_list")
            self.write(key, self.eval(node.named_children[0], state) if node.named_children else integer(0), state)
            return
        self.zero_initialize(key, ctype, state)
        if len(node.named_children) == 1 and self.graph.text(node.named_children[0]) == "0":
            return
        for pair in node.named_children:
            if pair.type != "initializer_pair":
                state.unknown.add("positional_aggregate_initializer")
                continue
            designators = pair.children_by_field_name("designator")
            if any(d.type != "field_designator" for d in designators):
                state.unknown.add("array_designator")
                continue
            target = key + "." + ".".join(self.graph.text(d).lstrip(".") for d in designators)
            value = pair.child_by_field_name("value")
            if value.type == "initializer_list":
                self.initialize(target, value, state)
            else:
                self.write(target, self.eval(value, state), state)

    def zero_initialize(self, key, ctype, state, depth=0):
        if depth > 12:
            state.unknown.add("aggregate_initialization_depth")
            return
        if ctype.kind == "record":
            state.env.pop(key, None)
            state.env.pop(key + ".*", None)
            record = state.records.get(ctype.name)
            if record is None or not record.complete:
                state.unknown.add("record_layout_incomplete")
                state.env[key + ".*"] = Value()
                return
            if record.kind == "union":
                for name in member_names(ctype, state.records):
                    state.env[key + "." + name] = Value(kind="union_overlap")
                    state.env[key + "." + name + ".*"] = Value(kind="union_overlap")
            fields = record.fields[:1] if record.kind == "union" else record.fields
            for name, nested in fields:
                target = key + "." + name if name else key
                if record.kind == "union" and nested.kind in {"integer", "pointer"}:
                    self.write(target, integer(0), state)
                else:
                    self.zero_initialize(target, nested, state, depth + 1)
        elif ctype.kind in {"integer", "pointer"}:
            state.env[key] = self.convert(integer(0), ctype, state)
        elif ctype.kind == "array":
            state.env[key + ".*"] = integer(0)
        else:
            # Missing type is not evidence that an aggregate is a struct with
            # independently zeroed fields rather than overlapping union arms.
            state.env[key] = Value()
            state.env[key + ".*"] = Value()


def binary(operator: str, left: Value, right: Value) -> Value:
    origin = left.origin or right.origin
    if operator in {"==", "!="}:
        answer = None
        if isinstance(left.atom, int) and isinstance(right.atom, int):
            answer = left.atom == right.atom
        elif left.atom is not None and left.atom == right.atom and left.kind == right.kind:
            answer = True
        elif left.sign is not None and right.sign == 0:
            answer = left.sign == 0
        elif right.sign is not None and left.sign == 0:
            answer = right.sign == 0
        if answer is not None:
            return integer(answer if operator == "==" else not answer, origin)
    if operator in {"<", "<=", ">", ">="}:
        a, b = left.atom, right.atom
        if not (isinstance(a, int) and isinstance(b, int)):
            if left.sign is not None and right.sign == 0:
                a, b = left.sign, 0
            elif right.sign is not None and left.sign == 0:
                a, b = 0, right.sign
            elif a is not None and a == b:
                a = b = 0
            else:
                return Value(origin=origin)
        return integer({"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[operator], origin)
    if isinstance(left.atom, int) and isinstance(right.atom, int):
        a, b = left.atom, right.atom
        operations = {"+": lambda: a + b, "-": lambda: a - b, "*": lambda: a * b,
                      "&": lambda: a & b, "|": lambda: a | b, "^": lambda: a ^ b}
        if operator in operations:
            return integer(operations[operator](), origin)
    return Value(origin=origin)


def _compose_call(caller, arguments, state):
    plan = caller.call_plan
    parameters = typed_parameters(plan.parameters, plan.type_context)
    if parameters is None or len(parameters) != len(arguments) or caller.depth >= 6:
        failed = state.clone()
        failed.seen = True
        failed.unknown.add("composed_call_signature_or_depth_unmodeled")
        caller.havoc(arguments, failed)
        return [Outcome(Value(origin=True), failed)]
    frame = f"frame{caller.depth + 1}|"
    graph = parse_flow(plan.body)
    evaluator = Evaluator(graph, plan.offset, plan.injected, dict(plan.constants),
                          call_plan=plan.nested, frame=frame, parameters=parameters,
                          budget=caller.budget, depth=caller.depth + 1, source_file=plan.source_file,
                          globals_bound=bool(plan.source_file and plan.source_file == caller.source_file),
                          types=plan.type_context, integer_model=caller.integer_model.name, return_type=plan.return_type)
    initial = state.clone()
    initial.seen = False
    initial.guards = frozenset()
    initial.trace = ()
    initial.records = {**initial.records, **dict(evaluator.type_context.records)}
    for (name, ctype), argument in zip(parameters, arguments):
        initial.types[evaluator.parameters[name]] = ctype
        evaluator.write(evaluator.parameters[name], argument, initial)
    outcomes = _execute(evaluator, initial)
    if not outcomes:
        # An absent inner call may reflect unsupported syntax/configuration;
        # it is not proof that this caller can safely use the desired return.
        initial.unknown.add("composed_selected_call_not_reached")
        outcomes = [Outcome(Value(origin=True), initial)]
    result = []
    for outcome in outcomes:
        returned = replace(outcome.value, origin=outcome.value.origin or bool(outcome.state.guards))
        post = outcome.state.clone()
        post.env = {key: value for key, value in post.env.items() if not key.startswith(frame)}
        post.types = {key: value for key, value in post.types.items() if not key.startswith(frame)}
        escaped_local = any(key.startswith(frame) for key in post.escaped)
        escaped_local |= any(value.kind == "reference" and isinstance(value.atom, str) and value.atom.startswith(frame)
                             for value in [returned, *post.env.values()])
        if escaped_local:
            post.unknown.add("composed_local_address_escaped")
        post.escaped = frozenset(key for key in post.escaped if not key.startswith(frame))
        post.seen = True
        post.guards = state.guards
        post.trace = state.trace
        result.append(Outcome(returned, post))
    return result


def _execute(evaluator, initial):
    graph, budget = evaluator.graph, evaluator.budget
    pending = deque([(graph.entry, initial, frozenset(), None)])
    if graph.body.has_error:
        pending[0][1].unknown.add("parse_error")
    outcomes = []
    while pending and budget.remaining > 0:
        pc, state, history, override = pending.popleft()
        state.guards = frozenset(g for g in state.guards
                                if pc not in {graph.instructions[g].join, graph.instructions[g].lexical_end})
        signature = (pc, state.signature())
        if signature in history:
            if state.seen:
                state.unknown.add("nonterminating_path")
                outcomes.append(Outcome(Value(), state))
            continue
        before_history = history
        history = history | {signature}
        budget.remaining -= 1
        budget.explored += 1
        instruction = graph.instructions[pc]
        kind = instruction.kind
        original = state.clone()
        evaluator.call_override = override
        try:
            if kind == "unknown":
                state.unknown.add("unsupported_statement")
            if kind == "configuration":
                evaluated = evaluator.configuration(instruction.node, state)
            elif kind == "branch" and instruction.node is None:
                evaluated = integer(1)
            elif kind in {"return", "exit", "branch", "switch", "eval", "unknown"}:
                evaluated = evaluator.eval(instruction.node, state)
            else:
                evaluated = Value()
        except CallAlternatives as alternatives:
            # Replay only this abstract instruction from its pre-state, with
            # one complete callee outcome. Prefix effects occur once per path;
            # return and memory from different callee paths are never merged.
            for outcome in alternatives.outcomes:
                pending.append((pc, original.clone(), before_history, outcome))
            continue
        if kind in {"return", "exit"}:
            if state.seen:
                if kind == "return" and evaluator.return_type is not None:
                    evaluated = evaluator.convert(evaluated, evaluator.return_type, state)
                outcomes.append(Outcome(evaluated, state))
            continue
        if kind in {"branch", "configuration"}:
            condition = evaluated
            truth = condition.truth()
            options = (0, 1) if truth is None else (0 if truth else 1,)
            for choice in options:
                branch = state.clone()
                if condition.origin and truth is not None:
                    branch.guards = branch.guards | {pc}
                    branch.trace = (*branch.trace[-23:], graph.offset(instruction.node))
                pending.append((instruction.successors[choice], branch, history, None))
            continue
        if kind == "switch":
            selected = evaluated
            matches = []
            default = None
            uncertain = False
            for target, case in zip(instruction.successors, instruction.cases):
                if case is None:
                    default = target
                    continue
                compared = evaluator.binary("==", selected, evaluator.eval(case, state), state).truth()
                if compared is not False:
                    matches.append(target)
                uncertain |= compared is None
            if not matches or uncertain:
                if default is not None:
                    matches.append(default)
            for target in set(matches):
                branch = state.clone()
                if selected.origin and not uncertain:
                    branch.guards = branch.guards | {pc}
                pending.append((target, branch, history, None))
            continue
        for target in instruction.successors:
            pending.append((target, state.clone(), history, None))
    if pending:
        for _, state, _, _ in pending:
            state.unknown.add("state_budget_exhausted")
            outcomes.append(Outcome(Value(), state))
    return outcomes


def analyze_return_flow(body: str, offset: int, value: Value, *, constants=None, max_states=512,
                        entry_injection=True, call_plan: CallPlan | None = None, source_file="",
                        types=TypeContext(), integer_model="portable", parameters="", return_type=None) -> FlowResult:
    graph = parse_flow(body)
    budget = Budget(max_states)
    signature = typed_parameters(parameters, types)
    evaluator = Evaluator(graph, offset, value, constants, entry_injection, call_plan=call_plan,
                          budget=budget, source_file=source_file, types=types, integer_model=integer_model,
                          parameters=signature or (), return_type=return_type)
    initial = State(types=dict(evaluator.type_context.globals), records=dict(evaluator.type_context.records))
    if signature is None:
        initial.unknown.add("function_parameter_signature_unmodeled")
    for key in evaluator.parameters.values():
        initial.types[key] = evaluator.types[key]
        initial.env[key] = Value(ctype=evaluator.types[key])
    outcomes = _execute(evaluator, initial)
    composition = []
    plan = call_plan
    while plan is not None:
        composition.append(plan.function_id)
        plan = plan.nested
    reasons = sorted({issue for outcome in outcomes for issue in outcome.state.unsafe | outcome.state.unknown})
    if not outcomes:
        return FlowResult("unknown", [], ["selected_call_not_reached"], budget.explored, tuple(composition))
    if any(o.state.unsafe for o in outcomes):
        status = "unsafe"
    elif any(o.state.unknown for o in outcomes):
        status = "unknown"
    elif any(o.value.atom is None and not o.state.guards for o in outcomes):
        status = "unknown"
        reasons.append("unknown_return_value")
    elif any(not o.value.origin and not o.state.guards for o in outcomes):
        status = "ignored"
    elif any(o.state.guards for o in outcomes):
        # Control dependence is evidence of a check, not proof of an error
        # contract or of safe ownership/output state after the injected call.
        status = "checked"
    elif any((o.value.atom, o.value.kind, o.value.sign, o.value.origin) !=
             (value.atom, value.kind, value.sign, value.origin) for o in outcomes):
        status = "transformed"
    else:
        status = "propagated"
    return FlowResult(status, outcomes, reasons, budget.explored, tuple(composition))
