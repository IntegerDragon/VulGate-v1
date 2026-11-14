from __future__ import annotations

import re
import hashlib
from dataclasses import asdict, replace
from pathlib import Path
from functools import lru_cache

from .calls import Edge, build_incoming
from .macros import call_alias, normalize_macros, plain_condition, unresolved_conditionals
from .parse import Function, mask_noise, parse_files
from . import resources
from .returnflow import CallPlan, analyze_return_flow, candidate_value, converted_candidate
from .constants import source_macro_contexts
from .ctypes import CType, UNKNOWN, MODELS, TypeContext, source_type_contexts


DENY = {
    "vfs_read",
    "vfs_write",
    "vfs_iter_read",
    "vfs_iter_write",
    "kernel_read",
    "kernel_write",
    "path_openat",
    "do_filp_open",
    "filename_lookup",
    "iterate_dir",
    "svc_process",
    "svc_process_common",
    "run_posix_cpu_timers",
    "__mark_inode_dirty",
    "ngx_http_finalize_request",
    "ngx_http_complex_value",
    "ngx_http_script_run",
    "do_syscall_64",
    "entry_SYSCALL_64",
}

CLEANUP = re.compile(
    r"(^|_)(free|destroy|cleanup|remove|put|unlink|release|gc|deinit)(_|$)"
)

ALLOC = ("kmalloc", "kzalloc", "kcalloc", "kvmalloc", "vmalloc", "kmem_cache_alloc")
ALLOC_RELEASE = ("kfree", "kvfree", "vfree", "kmem_cache_free")
LOCK = ("mutex_lock", "mutex_lock_interruptible", "spin_lock", "spin_lock_bh")
LOCK_RELEASE = ("mutex_unlock", "spin_unlock", "spin_unlock_bh")
FD = ("fdget",)
FD_RELEASE = ("fdput",)
PAGE = ("get_page", "alloc_page")
PAGE_RELEASE = ("put_page",)
FAMILIES = (
    (ALLOC, ALLOC_RELEASE),
    (LOCK, LOCK_RELEASE),
    (FD, FD_RELEASE),
    (PAGE, PAGE_RELEASE),
)

RELATION_RANK = {"self": 0, "caller": 1, "creation": 2}


def analyze_sources(sources: list[Path], dangerous: str, ident: str = "", *, integer_model="portable") -> dict:
    if integer_model not in MODELS:
        raise ValueError("unknown integer analysis model: " + str(integer_model))
    requested = dangerous
    blobs = []
    masked = []
    for path in sources:
        text = path.read_text(encoding="utf-8")
        blobs.append((str(path), text))
        masked.append((str(path), normalize_macros(mask_noise(text))))
    try:
        functions = parse_files(blobs)
    except ValueError as exc:
        return _result(ident, dangerous, "insufficient_input", reason=str(exc))
    hits = [func for func in functions.values() if func.name == dangerous]
    if not hits:
        for _file, text in masked:
            alias = call_alias(text, dangerous)
            if not alias:
                continue
            hits = [func for func in functions.values() if func.name == alias]
            if hits:
                dangerous = alias
                break
    if not hits:
        return _result(ident, dangerous, "insufficient_input", reason=f"源码里没有函数 {dangerous}")
    if len({func.file for func in hits}) > 1:
        return _result(ident, dangerous, "insufficient_input", reason=f"函数 {dangerous} 有多份定义，需要指定文件")
    _add_syscall_callers(functions)
    _add_ioctl_callers(functions, masked)
    incoming, creation = build_incoming(functions, masked)
    constants = source_macro_contexts(blobs)
    type_contexts = source_type_contexts(blobs)
    for function in functions.values():
        function.type_context = type_contexts.get(function.file, TypeContext())
        bindings = dict(function.type_context.function_bindings).get(function.name)
        if bindings is not None:
            function.type_context = replace(function.type_context, bindings=bindings, function_bindings=())
        function.integer_model = integer_model
        function.return_ctype = (CType("integer", "long") if function.is_syscall or function.uid.startswith("abi::")
                                 else dict(function.type_context.returns).get(function.name, UNKNOWN))
    result = analyze_functions(functions, incoming, creation, hits[0].uid, dangerous, ident, constants)
    result["analysis"]["integer_model"] = integer_model
    result["analysis"]["integer_model_verified_against_build"] = False
    result["analysis"]["integer_macros"] = {file: dict(values) for file, values in constants.items()}
    result["requested_function"] = requested
    result["input_files"] = [{"file": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for path in sources]
    digests = {item["file"]: item["sha256"] for item in result["input_files"]}
    for candidate in result["candidates"]:
        key = ":".join([digests[candidate["location"]["file"]], candidate["function"],
                        str(candidate["location"]["line"]), candidate["return_value"], candidate["relation"]])
        if integer_model != "portable":
            key += ":integer-model:" + integer_model
        candidate["candidate_id"] = hashlib.sha256(key.encode()).hexdigest()[:20]
        candidate["uncovered_runtime_callers"] = _uncovered(functions, incoming, hits[0].uid, [candidate])
        candidate["covers_all_modeled_runtime_paths"] = not candidate["uncovered_runtime_callers"]
    result["rejected"].extend(f"{func.name}: {effect}" for func in functions.values() for effect in func.entry_effects)
    result["analysis"]["unresolved_conditionals"] = [
        {"file": file, "directives": directives}
        for file, source in blobs if (directives := unresolved_conditionals(mask_noise(source)))
    ]
    return result


def analyze_functions(functions, incoming, creation, dangerous_uid: str, dangerous: str, ident: str, constants=()) -> dict:
    func = functions[dangerous_uid]
    if func.name in DENY:
        return _result(ident, dangerous, "out_of_scope", reason="危险函数在通用路径上。拦住它之后，正常的读写或系统调用也会停")
    if CLEANUP.search(func.name):
        return _result(ident, dangerous, "out_of_scope", reason="危险函数负责释放或拆除。从入口返回会把对象留在原来的结构上")
    candidates = _candidates(functions, incoming, creation, dangerous_uid, constants)
    uncovered = _uncovered(functions, incoming, dangerous_uid, candidates)
    if candidates:
        ordered = sorted(candidates, key=_candidate_key)
        full = not uncovered
        reason = f"找到 {len(ordered)} 个返回候选；结论限于输入源码和已建模的调用方式"
        if not full:
            reason += "。还有调用路径没有自己的安全返回"
        if any(item["relation"] == "creation" for item in ordered):
            reason += "。创建期候选需验证 init 是对象启用的必经路径；验证后可用于仅保护安装后新建对象的场景"
        return _found(ident, dangerous, ordered, uncovered, reason)
    notes = _reject_notes(functions, incoming, dangerous_uid)
    missing_caller = not incoming.get(dangerous_uid) and func.return_kind != "void" and not func.is_syscall
    status = "insufficient_input" if missing_caller else "out_of_scope"
    reason = "；".join(notes) if notes else "没有找到调用方会处理、并且不会漏掉已拿到资源的失败返回"
    return _result(ident, dangerous, status, reason=reason, rejected=notes)


def _add_syscall_callers(functions: dict[str, Function]) -> None:
    for func in list(functions.values()):
        if not func.is_syscall:
            continue
        name = f"__syscall_{func.name}"
        uid = f"abi::{func.name}"
        body = f"long ret = {func.name}();\nif (ret < 0)\nreturn ret;\nreturn ret;\n"
        functions[uid] = Function(
            name=name,
            return_kind="int",
            params="",
            body=body,
            returns=[],
            file=func.file,
            uid=uid,
            is_static=True,
        )


def _add_ioctl_callers(functions: dict[str, Function], masked: list[tuple[str, str]]) -> None:
    names: set[str] = set()
    for _file, text in masked:
        for match in re.finditer(r"\.(?:unlocked_ioctl|compat_ioctl)\s*=\s*(\w+)", text):
            names.add(match.group(1))
    present = {func.name for func in functions.values()}
    for func in list(functions.values()):
        if func.name not in names or func.name.startswith("__syscall_"):
            continue
        wrapper = f"__syscall_{func.name}"
        if wrapper in present:
            continue
        uid = f"abi::ioctl::{func.name}"
        body = (
            f"long ret = {func.name}();\n"
            "if (ret < 0)\n"
            "return ret;\n"
            "return ret;\n"
        )
        functions[uid] = Function(
            name=wrapper,
            return_kind="int",
            params="",
            body=body,
            returns=[],
            file=func.file,
            uid=uid,
            is_static=True,
        )
        present.add(wrapper)


def _candidates(functions, incoming, creation, dangerous_uid: str, constants=()) -> list[dict]:
    found: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    visited: set[str] = set()

    def walk(uid: str, depth: int, relation: str) -> None:
        if uid in visited or depth > 4:
            return
        visited.add(uid)
        func = functions[uid]
        if not func.name.startswith("__syscall_") and relation != "dispatcher":
            for item in _values(functions, incoming, uid, relation, depth, constants):
                key = (item["function_id"], item["return_value"], item["relation"])
                if key in seen:
                    continue
                seen.add(key)
                found.append(item)
        if relation == "dispatcher":
            return
        for edge in incoming.get(uid, []):
            caller = functions[edge.caller]
            if caller.name.startswith("__syscall_"):
                continue
            if edge.indirect:
                continue
            walk(edge.caller, depth + 1, "caller")

    walk(dangerous_uid, 0, "self")
    init_ids = list(creation.get(dangerous_uid, []))
    for edge in incoming.get(dangerous_uid, []):
        for init_uid in creation.get(edge.caller, []):
            if init_uid not in init_ids:
                init_ids.append(init_uid)
    for init_uid in init_ids:
        for item in _values(functions, incoming, init_uid, "creation", 1, constants):
            key = (item["function_id"], item["return_value"], item["relation"])
            if key in seen:
                continue
            seen.add(key)
            found.append(item)
    return found


def _values(functions, incoming, uid: str, relation: str, depth: int, constants=()) -> list[dict]:
    func = functions[uid]
    if func.return_kind == "void" or _owns_skb(func) or func.entry_effects:
        return []
    if func.name in DENY or CLEANUP.search(func.name) or func.name.startswith("__syscall_"):
        return []
    first = _first_acquire(func.body)
    items = []
    used: set[str] = set()
    for site in func.returns:
        if site.kind in {"success", "retry", "other", "nonterminal"} or site.expr in used:
            continue
        status, evidence = _value_acceptance(functions, incoming, uid, site.expr, site.kind, [], constants)
        if status not in {"ok", "partial"}:
            continue
        used.add(site.expr)
        value = candidate_value(site.expr, site.kind, dict((constants or {}).get(func.file, ())))
        converted = converted_candidate(value, func.return_ctype or UNKNOWN, func.integer_model,
                                        func.type_context or TypeContext())
        items.append({
            "function": func.name,
            "function_id": uid,
            "location": {"file": func.file, "line": _location(func, site.offset)["definition_line"]},
            "return_location": _location(func, site.offset),
            "caller_contract": "confirmed_in_model" if status == "ok" else "partial",
            "caller_evidence": evidence,
            "coverage_condition": "init_must_gate_object_activation" if relation == "creation" else "runtime_call_paths",
            "position": "entry",
            "return_value": site.expr,
            "return_kind": site.kind,
            "return_semantics": {"type": asdict(func.return_ctype or UNKNOWN),
                                 "converted_integer": converted.atom if type(converted.atom) is int and converted.kind in {"scalar", "null"} else None,
                                 "conversion_issue": converted.issue,
                                 "integer_model": func.integer_model, "abi_encoding_verified": False},
            "relation": relation,
            "depth": depth,
            "before_acquire": first < 0 or site.offset < first,
            "offset": site.offset,
            "via": "ops" if relation == "creation" else relation,
        })
    return items


@lru_cache(maxsize=2048)
def _return_flow(body, offset, injected, entry_injection, constants, call_plan=None, source_file="",
                 types=TypeContext(), integer_model="portable", parameters="", return_type=None):
    macros = dict(constants)
    return analyze_return_flow(body, offset, injected, constants=macros,
                               entry_injection=entry_injection, call_plan=call_plan, source_file=source_file,
                               types=types, integer_model=integer_model, parameters=parameters, return_type=return_type)


def _accepts_value(kinds, excluded, expr, kind):
    return expr not in excluded and (
        kind in kinds or (kind == "neg" and "nonzero" in kinds)
        or f"named:{expr}" in kinds or f"value:{expr}" in kinds)


def _value_acceptance(functions, incoming, uid, expr, kind, stack, constants=(), injected=None, call_plan=None):
    """A concrete value must survive every known edge, including AST vetoes.

    Legacy evidence can preserve an explicitly partial discovery when syntax or
    effects are missing. It never upgrades an unknown path to confirmed.
    """
    if uid in stack or len(stack) > 6:
        return "unconfirmed", []
    contexts = constants or {}
    if injected is None:
        injected = candidate_value(expr, kind, dict(contexts.get(functions[uid].file, ())))
        function = functions[uid]
        if function.return_ctype is not None:
            injected = converted_candidate(injected, function.return_ctype, function.integer_model,
                                           function.type_context or TypeContext())
    evidence = []
    for edge in incoming.get(uid, []):
        caller = functions[edge.caller]
        semantic_body, call_offset, body_base = caller.flow_body(edge.offset)
        # Synthetic ABI edges model only the consumed return value. They have
        # no actual arguments or caller memory in which to execute a callee.
        abi_return_only = caller.uid.startswith("abi::")
        flow = _return_flow(semantic_body, call_offset, injected, not stack, contexts.get(caller.file, ()),
                            None if abi_return_only else call_plan, caller.file,
                            caller.type_context or TypeContext(), caller.integer_model,
                            "" if abi_return_only else caller.flow_parameters(edge.offset), caller.return_ctype)
        kinds, excluded, legacy = _edge_acceptance(functions, incoming, edge, stack + [uid])
        nested_evidence = None
        optional_null = kind == "null" and flow.status == "ignored" and "null" in kinds
        if legacy == "reject" or flow.status == "unsafe" or (flow.status == "ignored" and not optional_null):
            status = "reject"
        elif expr in excluded:
            status = "reject"
        elif flow.status == "checked" or optional_null:
            status = "ok"
        elif flow.status == "propagated":
            continuation = CallPlan(caller.uid, semantic_body, caller.flow_parameters(edge.offset), call_offset,
                                    injected, contexts.get(caller.file, ()), call_plan, caller.file,
                                    caller.type_context or TypeContext(), caller.return_ctype)
            status, nested_evidence = _value_acceptance(functions, incoming, edge.caller, expr, kind,
                                                      stack + [uid], constants, injected, continuation)
        else:
            status = "unconfirmed"
        if status == "unconfirmed" and legacy in {"ok", "partial"} and _accepts_value(kinds, excluded, expr, kind):
            status = "partial"
        flow_evidence = flow.evidence()
        flow_evidence["body_offset_base"] = body_base
        if abi_return_only:
            flow_evidence["scope"] = "modeled_abi_return_only"
        if nested_evidence is not None:
            flow_evidence["continuation_evidence"] = nested_evidence
        evidence.append({"function": caller.name, "function_id": caller.uid,
                         "location": _location(caller, edge.offset), "indirect": edge.indirect,
                         "status": status, "accepted_kinds": sorted(kinds),
                         "excluded_values": sorted(excluded), "return_flow": flow_evidence})
    statuses = [item["status"] for item in evidence]
    if "reject" in statuses:
        return "reject", evidence
    if statuses and all(s == "ok" for s in statuses):
        return "ok", evidence
    if any(s in {"ok", "partial"} for s in statuses):
        return "partial", evidence
    return "unconfirmed", evidence


def _acceptance(functions, incoming, uid: str, stack: list[str]) -> tuple[set[str], set[str], str]:
    if uid in stack or len(stack) > 6:
        return set(), set(), "unconfirmed"
    edges = incoming.get(uid, [])
    if not edges:
        return set(), set(), "unconfirmed"
    decisions = [_edge_acceptance(functions, incoming, edge, stack + [uid]) for edge in edges]
    if any(status == "reject" for _kinds, _excluded, status in decisions):
        return set(), set(), "reject"
    confirmed = [(kinds, edge_excluded) for kinds, edge_excluded, status in decisions if status in {"ok", "partial"}]
    if not confirmed:
        return set(), set(), "unconfirmed"
    kinds_acc: set[str] | None = None
    excluded: set[str] = set()
    for kinds, edge_excluded in confirmed:
        kinds_acc = kinds if kinds_acc is None else kinds_acc & kinds
        excluded |= edge_excluded
    if not kinds_acc:
        return set(), set(), "unconfirmed"
    status = "ok" if all(status == "ok" for _, _, status in decisions) else "partial"
    return kinds_acc, excluded, status


def _location(func: Function, offset: int) -> dict:
    start, line, definition = max((s for s in func.segments if s[0] <= offset), default=(0, func.body_line, func.line))
    return {"file": func.file, "line": line + func.body.count("\n", start, offset), "definition_line": definition,
            "synthetic": func.uid.startswith("abi::")}


def _edge_acceptance(functions, incoming, edge: Edge, stack: list[str]) -> tuple[set[str], set[str], str]:
    caller = functions[edge.caller]
    if _held(caller.body, edge.offset) and not _releases(caller.body, edge.offset, functions, caller.file):
        return set(), set(), "reject"
    kinds, excluded = _kinds_at(caller.body, edge.offset)
    if kinds:
        return kinds, excluded, "ok"
    if _propagates(caller.body, edge.offset):
        return _acceptance(functions, incoming, edge.caller, stack)
    return set(), set(), "unconfirmed"


def _uncovered(functions, incoming, dangerous_uid: str, candidates: list[dict]) -> list[str]:
    self_covered = any(item["relation"] == "self" for item in candidates)
    names = {item["function_id"] for item in candidates if item["relation"] == "caller"
             and item["caller_contract"] == "confirmed_in_model"}
    gaps = []
    if not incoming.get(dangerous_uid) and not self_covered:
        return [functions[dangerous_uid].name]
    for edge in incoming.get(dangerous_uid, []):
        caller = functions[edge.caller]
        covered = _ancestor_named(functions, incoming, edge.caller, names, 0)
        supported = any(item["relation"] == "self" and any(
            e["function_id"] == edge.caller and e["location"] == _location(caller, edge.offset)
            and e["status"] == "ok" for e in item["caller_evidence"]) for item in candidates)
        if supported or covered:
            continue
        gaps.append(caller.name)
    return sorted(set(gaps))


def _ancestor_named(functions, incoming, uid: str, names: set[str], depth: int, seen=frozenset()) -> bool:
    if depth > 4 or uid in seen:
        return False
    if uid in names:
        return True
    edges = incoming.get(uid, [])
    return bool(edges) and all(
        not edge.indirect and not functions[edge.caller].name.startswith("__syscall_")
        and _ancestor_named(functions, incoming, edge.caller, names, depth + 1, seen | {uid})
        for edge in edges
    )


def _reject_notes(functions, incoming, dangerous_uid: str) -> list[str]:
    func = functions[dangerous_uid]
    notes = []
    if func.return_kind == "void" and "sk_buff" in func.params:
        notes.append(f"{func.name} 接管 sk_buff，入口返回既不入队也不释放")
    edges = incoming.get(dangerous_uid, [])
    if not edges:
        notes.append(f"{func.name} 在给定源码里没有调用方")
        return notes
    for edge in edges:
        caller = functions[edge.caller]
        if caller.name.startswith("__syscall_"):
            continue
        if caller.name in DENY or CLEANUP.search(caller.name):
            notes.append(f"{caller.name} 是通用路径或释放函数，不能作为拦截点")
            continue
        kinds, _excluded, status = _edge_acceptance(functions, incoming, edge, [dangerous_uid])
        if status != "ok":
            notes.append(f"{caller.name} 没有可用的失败返回")
    return notes


def _candidate_key(item: dict) -> tuple:
    bare = 1 if re.fullmatch(r"-\d+", item["return_value"]) else 0
    return (
        RELATION_RANK[item["relation"]],
        item["depth"],
        0 if item["before_acquire"] else 1,
        bare,
        item["offset"],
        item["return_value"],
    )


def _owns_skb(func: Function) -> bool:
    return "sk_buff" in func.params and func.return_kind == "void"


def _kinds_at(body: str, offset: int) -> tuple[set[str], set[str]]:
    body = resources.reachable_siblings(body, offset)
    var = _assigned_var(body, offset)
    rest = body[offset:]
    kinds: set[str] = set()
    excluded: set[str] = set()
    cond_end = _enclosing_if_end(body, offset)
    if cond_end is not None:
        window = body[offset:cond_end]
        if re.search(r"<\s*0", window):
            kinds.add("neg")
        if re.search(r"!=\s*0", window):
            kinds.add("nonzero")
        call_paren = body.find("(", offset)
        if 0 <= call_paren < cond_end:
            tail = body[_paren_end(body, call_paren):cond_end]
            if re.match(r"\s*(?:&&|\|\||\))", tail):
                kinds.add("nonzero")
    if not var:
        return kinds, excluded
    semi = body.find(";", offset)
    after_call = body[semi + 1:] if semi >= 0 else ""
    # A check of a different reaching definition is not a check of this call.
    overwritten = re.search(rf"\b{re.escape(var)}\s*(?:=(?!=)|\+=|-=|\+\+|--)", after_call)
    if overwritten:
        after_call = after_call[:overwritten.start()]
    checked_body = body[:semi + 1] + after_call if semi >= 0 else body
    for cond, terminal in _if_conditions(checked_body, offset):
        if not terminal:
            if plain_condition(cond) == var:
                kinds.add("null")
            elif re.fullmatch(rf"{re.escape(var)}\s*==\s*0|!\s*{re.escape(var)}", plain_condition(cond)):
                if re.search(rf"\breturn\s+{re.escape(var)}\s*;", after_call):
                    kinds.add("nonzero")
            continue
        _apply_cond(plain_condition(cond), var, rest, kinds, excluded)
    loop = _enclosing_loop_condition(body, offset)
    if loop:
        _apply_cond(plain_condition(loop), var, rest, kinds, excluded)
        if re.fullmatch(rf"!\s*{re.escape(var)}|{re.escape(var)}\s*==\s*0", plain_condition(loop)):
            kinds.add("nonzero")
    if re.search(rf"\breturn\s+!\s*{re.escape(var)}\s*;", rest):
        kinds.add("nonzero")
    return kinds, excluded


def _apply_cond(plain: str, var: str, rest: str, kinds: set[str], excluded: set[str]) -> None:
    if "&&" in plain or "||" in plain:
        return
    if re.search(rf"\b{var}\s*<\s*0\b", plain):
        kinds.add("neg")
    if re.search(rf"\b{var}\s*!=\s*0\b", plain):
        kinds.add("nonzero")
    if plain == var:
        kinds.add("nonzero")
        kinds.add("null")
    if re.search(rf"!\s*{var}\b", plain) or re.search(rf"\b{var}\s*==\s*NULL\b", plain):
        kinds.add("null")
    if re.search(rf"\bIS_ERR\s*\(\s*{var}\s*\)", plain):
        kinds.add("err_ptr")
    if re.search(rf"\bIS_ERR_OR_NULL\s*\(\s*{var}\s*\)", plain):
        kinds.add("err_ptr")
        kinds.add("null")
    if re.search(rf"\b{var}\s*!=\s*NGX_OK\b", plain):
        kinds.add("neg")
    if re.search(rf"\b{var}\s*==\s*TC_ACT_SHOT\b", plain):
        kinds.add("shot")
    named = re.search(rf"\b{var}\s*(?:==|!=|>=|<=)\s*([A-Z][A-Z0-9_]+)", plain)
    if named:
        kinds.add(f"named:{named.group(1)}")
    special = re.search(rf"\b{var}\s*!=\s*(-E[A-Z0-9_]+)", plain)
    if special:
        excluded.add(special.group(1))
        kinds.add("neg")
    same = re.search(rf"\b{var}\s*==\s*(-E[A-Z0-9_]+)", plain)
    if same:
        kinds.add(f"value:{same.group(1)}")


def _if_conditions(body: str, start: int) -> list[tuple[str, bool]]:
    found: list[tuple[str, bool]] = []
    cursor = start
    while cursor < len(body):
        match = re.search(r"\bif\b", body[cursor:])
        if match is None:
            break
        paren_at = cursor + match.end()
        while paren_at < len(body) and body[paren_at] in " \t\r\n":
            paren_at += 1
        if paren_at >= len(body) or body[paren_at] != "(":
            cursor = paren_at
            continue
        end = _paren_end(body, paren_at)
        branch_end = resources._statement_end(body, end)
        branch = body[end:branch_end]
        terminal = bool(re.search(r"\b(?:return|goto|break|continue)\b", branch))
        condition = body[paren_at + 1:end - 1]
        plain = plain_condition(condition)
        success_guard = re.fullmatch(r"(\w+)\s*==\s*0|!\s*(\w+)", plain)
        if terminal or success_guard or (re.fullmatch(r"\w+", plain) and not re.search(rf"\b{plain}\b", body[branch_end:])):
            found.append((condition, terminal))
        cursor = end
    return found


def _enclosing_if_end(body: str, offset: int) -> int | None:
    cursor = max(0, offset - 600)
    found = None
    while cursor < offset:
        match = re.search(r"\bif\b", body[cursor:offset])
        if match is None:
            break
        paren_at = cursor + match.end()
        while paren_at < len(body) and body[paren_at] in " \t\r\n":
            paren_at += 1
        if paren_at >= len(body) or body[paren_at] != "(":
            cursor = paren_at
            continue
        end = _paren_end(body, paren_at)
        if end > offset:
            found = end
        cursor = end
    return found


def _assigned_var(body: str, offset: int) -> str | None:
    line_start = max(body.rfind("\n", 0, offset), body.rfind(";", 0, offset), body.rfind("{", 0, offset)) + 1
    line = body[line_start:offset]
    match = re.search(r"(\w+)\s*=\s*[^=]*$", line)
    if match:
        return match.group(1)
    if "=" in line:
        return None
    previous = body.rfind("\n", 0, max(line_start - 1, 0)) + 1
    prev = body[previous:line_start]
    if re.search(r"=\s*$", prev) is None:
        return None
    match = re.search(r"(\w+)\s*=\s*$", prev)
    if match:
        return match.group(1)
    return None


def _propagates(body: str, offset: int) -> bool:
    body = resources.reachable_siblings(body, offset)
    line_start = max(body.rfind("\n", 0, offset), body.rfind(";", 0, offset), body.rfind("{", 0, offset)) + 1
    line_end = body.find(";", offset)
    if line_end < 0:
        line_end = len(body)
    statement = body[line_start:line_end]
    if statement.strip().startswith("return"):
        return True
    match = re.search(r"(\w+)\s*=", statement)
    if not match:
        return False
    after = body[line_end + 1:]
    label_name = _cleanup_label(body, offset)
    if label_name:
        label = re.search(rf"\b{re.escape(label_name)}\s*:", body)
        if label:
            after = body[label.end():]
    if re.search(rf"\b{match.group(1)}\s*=(?!=)", after):
        return False
    if _kinds_at(body, offset)[0]:
        return False
    return re.search(rf"\breturn\s+{match.group(1)}\s*;", body[offset:]) is not None


def _held(body: str, offset: int) -> bool:
    return bool(resources.obligations(body[:offset], FAMILIES))


def _first_acquire(body: str) -> int:
    best = -1
    for names, _releases in FAMILIES:
        for name in names:
            match = re.search(rf"\b{name}\s*\(", body)
            if match and (best < 0 or match.start() < best):
                best = match.start()
    return best


def _releases(body: str, offset: int, functions: dict[str, Function], file: str = "") -> bool:
    region = _error_region(body, offset)
    if region is None:
        region = ""
    region += _truthy_fallthrough(body, offset)
    region += _straight_suffix(body, offset)
    if not region and not _propagates(body, offset):
        return False
    aliases = resources.owned_aliases(body[:offset])
    held = [(family, aliases.get(obj, obj)) for family, obj in resources.obligations(body[:offset], FAMILIES)]
    return resources.covers(held,
                            resources.releases(region, functions, FAMILIES, file))


def _error_region(body: str, offset: int) -> str | None:
    body = resources.reachable_siblings(body, offset)
    label_name = _cleanup_label(body, offset)
    if label_name:
        label = re.search(rf"\b{re.escape(label_name)}\s*:", body)
        if label:
            return body[label.end():]
    var = _assigned_var(body, offset)
    region: str | None = None
    if var is None:
        if _propagates(body, offset):
            region = ""
    else:
        cursor = _if_body_at(body, offset, var)
        if cursor is None:
            if _propagates(body, offset):
                region = ""
        elif cursor < len(body) and body[cursor] == "{":
            end = _brace_end(body, cursor)
            region = body[cursor:end]
        else:
            end = body.find(";", cursor)
            region = body[cursor:len(body) if end < 0 else end + 1]
        if region:
            goto = re.search(r"\bgoto\s+(\w+)\s*;", region)
            if goto:
                label = re.search(rf"\b{goto.group(1)}\s*:", body)
                if label:
                    region = region[:goto.start()] + body[label.end():]
    label_name = _cleanup_label(body, offset)
    if label_name:
        label = re.search(rf"\b{label_name}\s*:", body)
        if label:
            region = (region or "") + body[label.end():]
    return region


def _cleanup_label(body: str, offset: int) -> str | None:
    semi = body.find(";", offset)
    if semi < 0:
        return None
    i = semi + 1
    depth = 0
    while i < len(body):
        char = body[i]
        if char == "{":
            depth += 1
            i += 1
            continue
        if char == "}":
            if depth == 0:
                return None
            depth -= 1
            i += 1
            continue
        if depth == 0 and not char.isspace():
            match = re.match(r"goto\s+(\w+)\s*;", body[i:])
            if match:
                return match.group(1)
            if re.match(r"(?:if|return|switch|for|while|do)\b", body[i:]):
                return None
            nxt = body.find(";", i)
            if nxt < 0:
                return None
            i = nxt + 1
            continue
        i += 1
    return None


def _straight_suffix(body: str, offset: int) -> str:
    semi = body.find(";", offset)
    if semi < 0:
        return ""
    i = semi + 1
    out: list[str] = []
    while i < len(body):
        while i < len(body) and body[i] in " \t\r\n":
            out.append(body[i])
            i += 1
        if i >= len(body) or body[i] in "};":
            break
        if re.match(r"(?:if|for|while|switch|return|goto|do)\b", body[i:]):
            break
        nxt = body.find(";", i)
        if nxt < 0:
            break
        out.append(body[i:nxt + 1])
        i = nxt + 1
    return "".join(out)


def _truthy_fallthrough(body: str, offset: int) -> str:
    var = _assigned_var(body, offset)
    if not var:
        return ""
    start = offset
    while start < len(body):
        match = re.search(r"\bif\b", body[start:])
        if match is None:
            return ""
        paren_at = start + match.end()
        while paren_at < len(body) and body[paren_at] in " \t\r\n":
            paren_at += 1
        if paren_at >= len(body) or body[paren_at] != "(":
            start = paren_at
            continue
        end = _paren_end(body, paren_at)
        plain = plain_condition(body[paren_at + 1:end - 1])
        if not re.search(rf"\b{re.escape(var)}\b", plain):
            start = end
            continue
        if re.search(rf"<\s*0|!\s*{re.escape(var)}\b", plain):
            return ""
        if plain != var and not re.search(rf"\b{re.escape(var)}\s*!=\s*NULL\b", plain):
            return ""
        brace = end
        while brace < len(body) and body[brace] in " \t\r\n":
            brace += 1
        if brace < len(body) and body[brace] == "{":
            close = _brace_end(body, brace)
            inner = body[brace:close]
            after = close
        else:
            semi = body.find(";", brace)
            inner = body[brace:len(body) if semi < 0 else semi + 1]
            after = len(body) if semi < 0 else semi + 1
        if re.search(r"\b(?:return|goto)\b", inner):
            return ""
        return _until_depth0_return(body, after)
    return ""


def _until_depth0_return(body: str, start: int) -> str:
    i = start
    depth = 0
    out: list[str] = []
    while i < len(body):
        char = body[i]
        if char == "{":
            depth += 1
        elif char == "}":
            if depth == 0:
                break
            depth -= 1
        elif depth == 0 and re.match(r"return\b", body[i:]):
            break
        if depth == 0:
            out.append(char)
        i += 1
    return "".join(out)


def _enclosing_loop_condition(body: str, offset: int) -> str | None:
    cursor = 0
    found = None
    while cursor < offset:
        match = re.search(r"\b(?:while|for)\b", body[cursor:offset])
        if match is None:
            break
        paren_at = cursor + match.end()
        while paren_at < len(body) and body[paren_at] in " \t\r\n":
            paren_at += 1
        if paren_at >= len(body) or body[paren_at] != "(":
            cursor = paren_at
            continue
        end = _paren_end(body, paren_at)
        brace = end
        while brace < len(body) and body[brace] in " \t\r\n":
            brace += 1
        if brace < len(body) and body[brace] == "{":
            close = _brace_end(body, brace)
            if brace < offset < close:
                found = body[paren_at + 1:end - 1]
            cursor = close
        else:
            cursor = end
    return found


def _if_body_at(body: str, offset: int, var: str) -> int | None:
    start = offset
    while True:
        match = re.search(r"\bif\b", body[start:])
        if match is None:
            return None
        cursor = start + match.end()
        while cursor < len(body) and body[cursor] in " \t\r\n":
            cursor += 1
        if cursor >= len(body) or body[cursor] != "(":
            start = cursor
            continue
        end = _paren_end(body, cursor)
        condition = body[cursor:end]
        if re.search(rf"\b{re.escape(var)}\b", condition):
            while end < len(body) and body[end] in " \t\r\n":
                end += 1
            return end
        start = end


def _paren_end(body: str, open_at: int) -> int:
    depth = 0
    i = open_at
    while i < len(body):
        if body[i] == "(":
            depth += 1
        elif body[i] == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(body)


def _brace_end(body: str, open_at: int) -> int:
    depth = 0
    i = open_at
    while i < len(body):
        if body[i] == "{":
            depth += 1
        elif body[i] == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(body)


def _found(ident: str, dangerous: str, sites: list[dict], uncovered: list[str], reason: str) -> dict:
    primary = sites[0]
    return _result(
        ident,
        dangerous,
        "found" if not uncovered else "partial",
        intercept=primary["function"],
        position=primary["position"],
        return_value=primary["return_value"],
        return_kind=primary["return_kind"],
        sites=sites,
        candidates=sites,
        uncovered=uncovered,
        reason=reason,
    )


def _result(
    ident: str,
    dangerous: str,
    status: str,
    intercept: str = "",
    position: str = "",
    return_value: str = "",
    return_kind: str = "",
    sites: list | None = None,
    candidates: list | None = None,
    uncovered: list | None = None,
    reason: str = "",
    rejected: list | None = None,
) -> dict:
    return {
        "schema_version": 2,
        "analysis": {
            "backend": "source_discovery_with_c_cfg_returnflow",
            "enforceable": False,
            "coverage_scope": "supplied_sources_and_modeled_calls",
            "unresolved_conditionals": [],
            "limitations": ["C CFG 只对已支持语法进行有界返回值分析；不是完整别名或所有权证明", "未解析的函数指针和外部调用可能遗漏",
                            "命名存储跟踪已知记录重叠与整数转换；位布局、位域、条件类型和真实构建/ABI仍未完整绑定",
                            "ENFORCE 前仍需按实际内核配置验证 ABI、资源契约及故障注入"],
        },
        "id": ident,
        "status": status,
        "dangerous_function": dangerous,
        "intercept": intercept,
        "position": position,
        "return_value": return_value,
        "return_kind": return_kind,
        "sites": sites or [],
        "candidates": candidates if candidates is not None else (sites or []),
        "uncovered": uncovered or [],
        "reason": reason,
        "rejected": rejected or [],
    }
