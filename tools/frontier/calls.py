from __future__ import annotations

import re
from dataclasses import dataclass, field

from .parse import KEYWORDS, Function, _match_brace
from .resources import calls, identity


@dataclass
class Edge:
    caller: str
    offset: int
    indirect: bool


@dataclass
class OpsInit:
    type_name: str
    var: str
    file: str
    fields: dict[str, str] = field(default_factory=dict)


def index_names(functions: dict[str, Function]) -> dict[str, list[Function]]:
    by_name: dict[str, list[Function]] = {}
    for func in functions.values():
        by_name.setdefault(func.name, []).append(func)
    return by_name


def resolve_name(functions: dict[str, Function], by_name: dict[str, list[Function]], file: str, name: str) -> Function | None:
    found = by_name.get(name, [])
    if not found:
        return None
    same = [func for func in found if func.file == file]
    if len(same) == 1:
        return same[0]
    globals_ = [func for func in found if not func.is_static]
    if len(globals_) == 1:
        return globals_[0]
    return None


def scan_ops(file: str, text: str, functions: dict[str, Function], by_name: dict[str, list[Function]]) -> list[OpsInit]:
    inits: list[OpsInit] = []
    for match in re.finditer(r"\bstruct\s+(\w+)\s+(\w+)(?:\s+__\w+)*\s*=\s*\{", text):
        open_at = match.end() - 1
        close_at = _match_brace(text, open_at)
        body = text[open_at + 1:close_at - 1]
        ops = OpsInit(match.group(1), match.group(2), file)
        depth = 0
        cursor = 0
        while cursor < len(body):
            char = body[cursor]
            if char == "{":
                depth += 1
                cursor += 1
                continue
            if char == "}":
                depth -= 1
                cursor += 1
                continue
            if depth == 0 and char == ".":
                field_match = re.match(r"\.(\w+)\s*=\s*&?(\w+)", body[cursor:])
                if field_match:
                    target = field_match.group(2)
                    func = resolve_name(functions, by_name, file, target)
                    if func is not None:
                        ops.fields[field_match.group(1)] = func.uid
                    else:
                        ops.fields[field_match.group(1)] = f"@{target}"
                    cursor += field_match.end()
                    continue
            cursor += 1
        inits.append(ops)
    return inits


def field_targets(inits: list[OpsInit]) -> dict[tuple[str, str], set[str]]:
    targets: dict[tuple[str, str], set[str]] = {}
    for ops in inits:
        for field_name, target in ops.fields.items():
            if target.startswith("@"):
                continue
            targets.setdefault((ops.type_name, field_name), set()).add(target)
    return targets


def creation_of(inits: list[OpsInit]) -> dict[str, list[str]]:
    by_var = {(ops.file, ops.var): ops for ops in inits}
    parents: dict[tuple[str, str], list[OpsInit]] = {}
    for ops in inits:
        for target in ops.fields.values():
            if not target.startswith("@"):
                continue
            key = (ops.file, target[1:])
            parents.setdefault(key, []).append(ops)
    created: dict[str, list[str]] = {}
    for ops in inits:
        owners = [ops, *parents.get((ops.file, ops.var), [])]
        init_ids = []
        for owner in owners:
            init_target = owner.fields.get("init")
            if init_target and not init_target.startswith("@"):
                init_ids.append(init_target)
        for target in ops.fields.values():
            if target.startswith("@"):
                continue
            bucket = created.setdefault(target, [])
            for init_id in init_ids:
                if init_id != target and init_id not in bucket:
                    bucket.append(init_id)
    return created


def _local_types(func: Function) -> dict[str, str]:
    types: dict[str, str] = {}
    for match in re.finditer(r"\bstruct\s+(\w+)\s*\*+\s*(\w+)", func.params + "\n" + func.body):
        types[match.group(2)] = match.group(1)
    return types


def scan_structs(text: str) -> dict[tuple[str, str], str]:
    layouts: dict[tuple[str, str], str] = {}
    for match in re.finditer(r"\bstruct\s+(\w+)\s*\{", text):
        name = match.group(1)
        open_at = match.end() - 1
        close_at = _match_brace(text, open_at)
        body = text[open_at + 1:close_at - 1]
        flat = []
        depth = 0
        for char in body:
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            elif depth == 0:
                flat.append(char)
        visible = "".join(flat)
        for field in re.finditer(r"\bstruct\s+(\w+)\s*\*+\s*(\w+)\s*;", visible):
            layouts[(name, field.group(2))] = field.group(1)
        for field in re.finditer(r"\(\s*\*+\s*(\w+)\s*\)", visible):
            layouts[(name, field.group(1))] = "fn"
    return layouts


def _method_targets(root_type: str | None, fields: list[str], targets: dict[tuple[str, str], set[str]], layouts: dict[tuple[str, str], str]) -> set[str]:
    method = fields[-1]
    current = root_type
    for field_name in fields[:-1]:
        nxt = layouts.get((current, field_name)) if current else None
        if not nxt or nxt == "fn":
            current = None
            break
        current = nxt
    if current:
        return set(targets.get((current, method), ()))
    if root_type:
        # Missing struct layout is not evidence that a same-named field in a
        # different ops type is the target (e.g. Qdisc_ops vs Qdisc_class_ops).
        return set()
    owners = []
    for type_name, field_name in targets:
        if field_name == method and type_name not in owners:
            owners.append(type_name)
    if len(owners) == 1:
        return set(targets[(owners[0], method)])
    return set()


def _apply_copies(functions: dict[str, Function], targets: dict[tuple[str, str], set[str]]) -> None:
    copies: list[tuple[tuple[str, str], tuple[str, str]]] = []
    pattern = re.compile(r"(\w+)\s*->\s*(\w+)\s*=\s*(\w+)\s*->\s*(\w+)\s*;")
    for func in functions.values():
        types = _local_types(func)
        for match in pattern.finditer(func.body):
            dst = types.get(match.group(1))
            src = types.get(match.group(3))
            if dst and src:
                copies.append(((dst, match.group(2)), (src, match.group(4))))
    changed = True
    guard = 0
    while changed and guard < 8:
        changed = False
        guard += 1
        for dst, src in copies:
            src_set = targets.get(src)
            if not src_set:
                continue
            bucket = targets.setdefault(dst, set())
            before = len(bucket)
            bucket.update(src_set)
            changed = changed or len(bucket) != before


def build_incoming(functions: dict[str, Function], sources: list[tuple[str, str]]) -> tuple[dict[str, list[Edge]], dict[str, list[str]]]:
    by_name = index_names(functions)
    inits: list[OpsInit] = []
    layouts: dict[tuple[str, str], str] = {}
    for file, text in sources:
        inits.extend(scan_ops(file, text, functions, by_name))
        layouts.update(scan_structs(text))
    targets = field_targets(inits)
    _mark_constructor_obligations(functions, inits)
    _apply_copies(functions, targets)
    incoming: dict[str, list[Edge]] = {uid: [] for uid in functions}
    call_re = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
    chain_re = re.compile(
        r"(?:\(\s*)?\b(\w+)((?:\s*->\s*\w+)+)\s*\)?\s*((?:\s*->\s*\w+)*)\s*\("
    )
    for func in functions.values():
        types = _local_types(func)
        for match in call_re.finditer(func.body):
            name = match.group(1)
            if name in KEYWORDS or name == func.name:
                continue
            if match.start(1) > 0 and func.body[match.start(1) - 1] in ">.":
                continue
            callee = resolve_name(functions, by_name, func.file, name)
            if callee is None or callee.uid == func.uid:
                continue
            incoming[callee.uid].append(Edge(func.uid, match.start(1), False))
        for match in chain_re.finditer(func.body):
            fields = re.findall(r"->\s*(\w+)", match.group(2) + match.group(3))
            if not fields:
                continue
            callees = _method_targets(types.get(match.group(1)), fields, targets, layouts)
            for callee_uid in callees:
                if callee_uid == func.uid or callee_uid not in functions:
                    continue
                incoming[callee_uid].append(Edge(func.uid, match.start(1), True))
    return incoming, creation_of(inits)


def _mark_constructor_obligations(functions, inits) -> None:
    # Paired callbacks can run destroy even after init fails. A return after
    # shared-state initialization is not evidence for returning before it.
    pairs = {"qdisc_watchdog_init": "qdisc_watchdog_cancel",
             "hrtimer_init": "hrtimer_cancel", "timer_setup": "del_timer_sync",
             "INIT_WORK": "cancel_work_sync", "mutex_init": "mutex_destroy"}
    for ops in inits:
        init = functions.get(ops.fields.get("init"))
        destroy = functions.get(ops.fields.get("destroy"))
        if init is None or destroy is None:
            continue
        failures = [site.offset for site in init.returns if site.kind in {"neg", "null", "err_ptr"}]
        if not failures:
            continue
        prefix = init.body[:min(failures)]
        cleanup = {(name, identity(args[0])) for name, args, _ in calls(destroy.body)}
        for name, args, _ in calls(prefix):
            if name in pairs and (pairs[name], identity(args[0])) in cleanup:
                init.entry_effects.append(f"{ops.var}: {name}({args[0]}) 在已有失败返回之前；{destroy.name} 调用 {pairs[name]}")
