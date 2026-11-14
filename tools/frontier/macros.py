from __future__ import annotations

import re


def _match_paren(text: str, open_at: int) -> int:
    depth = 0
    i = open_at
    while i < len(text):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(text)


UNWRAP = ("WARN_ON_ONCE", "unlikely", "likely", "READ_ONCE", "WARN_ON")
ERASE = (
    "__cond_acquires",
    "__cond_releases",
    "__must_hold",
    "__acquires",
    "__releases",
    "__attribute__",
    "__printf",
    "__scanf",
    "__section",
)
DEFINE_PREFIX = ("COMPAT_SYSCALL_DEFINE", "SYSCALL32_DEFINE", "SYSCALL_DEFINE", "BPF_CALL_")
SYSCALL_PREFIX = ("COMPAT_SYSCALL_DEFINE", "SYSCALL32_DEFINE", "SYSCALL_DEFINE")


def normalize_macros(src: str, *, preserve_conditionals=False) -> str:
    text = src if preserve_conditionals else _strip_if0(src)
    for name in ERASE:
        text = _rewrite_call(text, name, "erase")
    for _ in range(4):
        updated = text
        for name in UNWRAP:
            updated = _rewrite_call(updated, name, "unwrap")
        updated = _rewrite_call(updated, "__builtin_expect", "first")
        if updated == text:
            break
        text = updated
    return text


def plain_condition(cond: str) -> str:
    current = cond.strip()
    for _ in range(4):
        updated = current
        for name in UNWRAP:
            updated = _rewrite_call(updated, name, "unwrap")
        updated = updated.strip()
        if updated.startswith("(") and _match_paren(updated, 0) == len(updated):
            updated = updated[1:-1].strip()
        if updated == current:
            break
        current = updated
    return current


def is_define_macro(name: str) -> bool:
    return name.startswith(DEFINE_PREFIX)


def is_syscall_macro(name: str) -> bool:
    return name.startswith(SYSCALL_PREFIX)


def call_alias(text: str, name: str) -> str | None:
    match = re.search(rf"#define\s+{re.escape(name)}\s*\(([^)]*)\)\s*(\w+)\s*\(", text)
    if match is None:
        return None
    callee = match.group(2)
    if callee == name or callee in {"if", "while", "for", "return", "sizeof", "do"}:
        return None
    return callee


def _rewrite_call(text: str, name: str, mode: str) -> str:
    parts: list[str] = []
    i = 0
    while True:
        found = text.find(name, i)
        if found < 0:
            parts.append(text[i:])
            break
        if found > 0 and (text[found - 1].isalnum() or text[found - 1] == "_"):
            parts.append(text[i:found + len(name)])
            i = found + len(name)
            continue
        cursor = found + len(name)
        while cursor < len(text) and text[cursor] in " \t\r\n":
            cursor += 1
        if cursor >= len(text) or text[cursor] != "(":
            parts.append(text[i:found + len(name)])
            i = found + len(name)
            continue
        end = _match_paren(text, cursor)
        inner = text[cursor + 1:end - 1]
        parts.append(text[i:found])
        if mode == "erase":
            parts.append(_blank(text[found:end]))
        elif mode == "first":
            first = _first_arg(inner)
            parts.append(_blank(text[found:cursor]) + "(" + first + _blank(inner[len(first):]) + ")")
        else:
            parts.append(_blank(text[found:cursor]) + "(" + inner + ")")
        i = end
    return "".join(parts)


def _first_arg(inner: str) -> str:
    depth = 0
    for index, char in enumerate(inner):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "," and depth == 0:
            return inner[:index]
    return inner


def _blank(text: str) -> str:
    return re.sub(r"[^\n]", " ", text)


def unresolved_conditionals(src: str) -> list[str]:
    return [line.strip() for line in src.splitlines()
            if re.match(r"\s*#\s*(?:if|ifdef|ifndef|elif)\b", line)
            and _constant_condition(re.sub(r"^\s*#\s*", "", line)) is None]


def _constant_condition(head: str) -> bool | None:
    match = re.fullmatch(r"(?:if|elif)\s+\(?\s*([01])\s*\)?\s*", head)
    return bool(int(match.group(1))) if match else None


def _strip_if0(src: str) -> str:
    lines = src.split("\n")
    frames: list[dict] = []
    out: list[str] = []

    def dead() -> bool:
        return any(bool(frame["dead"]) for frame in frames)

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#"):
            head = stripped[1:].lstrip()
            directive = head.split(maxsplit=1)[0] if head else ""
            if directive in {"if", "ifdef", "ifndef"}:
                condition = _constant_condition(head)
                frames.append({"dead": dead() or condition is False, "taken": condition})
                out.append(_blank(line))
                continue
            if directive in {"else", "elif"}:
                if frames:
                    parent = any(bool(frame["dead"]) for frame in frames[:-1])
                    frame = frames[-1]
                    condition = True if directive == "else" else _constant_condition(head)
                    frame["dead"] = parent or frame["taken"] is True or condition is False
                    if condition is True:
                        frame["taken"] = True
                    elif condition is None and frame["taken"] is False:
                        frame["taken"] = None
                out.append(_blank(line))
                continue
            if directive == "endif":
                if frames:
                    frames.pop()
                out.append(_blank(line))
                continue
        out.append(_blank(line) if dead() else line)
    return "\n".join(out)


