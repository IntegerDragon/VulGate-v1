from __future__ import annotations

import re
from dataclasses import dataclass, field

from .macros import is_syscall_macro, is_define_macro, normalize_macros


KEYWORDS = {
    "if",
    "while",
    "for",
    "switch",
    "return",
    "sizeof",
    "else",
    "do",
    "case",
    "alignof",
    "__alignof__",
}


@dataclass
class ReturnSite:
    expr: str
    offset: int
    kind: str


@dataclass
class Function:
    name: str
    return_kind: str
    params: str
    body: str
    returns: list[ReturnSite] = field(default_factory=list)
    file: str = ""
    uid: str = ""
    is_static: bool = False
    is_syscall: bool = False
    line: int = 1
    body_line: int = 1
    segments: list[tuple[int, int, int]] = field(default_factory=list)
    entry_effects: list[str] = field(default_factory=list)
    semantic_body: str = ""
    parameter_segments: list[tuple[int, str]] = field(default_factory=list)
    type_context: object | None = None
    integer_model: str = "portable"
    return_ctype: object | None = None

    def flow_body(self, offset: int) -> tuple[str, int, int]:
        """Analyze one conditional definition, retaining original merged offsets."""
        starts = sorted({segment[0] for segment in self.segments})
        start = max((s for s in starts if s <= offset), default=0)
        end = min((s - 1 for s in starts if s > offset), default=len(self.body))
        return (self.semantic_body or self.body)[start:end], offset - start, start

    def flow_parameters(self, offset: int) -> str:
        text = max((s for s in self.parameter_segments if s[0] <= offset), default=(0, self.params))[1]
        if self.is_syscall:
            parts = text.split(",")
            if len(parts) % 2 == 1:
                return ", ".join(parts[i].strip() + " " + parts[i + 1].strip() for i in range(1, len(parts), 2)) or "void"
        return text


def mask_noise(src: str, *, literal_spans=None) -> str:
    out = list(src)
    i = 0
    n = len(src)
    while i < n:
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
            continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
            continue
        if src[i] in "\"'":
            start = i
            quote = src[i]
            out[i] = " "
            i += 1
            while i < n:
                if src[i] == "\\":
                    if i + 1 < n and out[i] != "\n":
                        out[i] = " "
                    if i + 1 < n and out[i + 1] != "\n":
                        out[i + 1] = " "
                    i += 2
                    continue
                if src[i] == quote:
                    out[i] = " "
                    i += 1
                    break
                if out[i] != "\n":
                    out[i] = " "
                i += 1
            if literal_spans is not None:
                literal_spans.append((start, min(i, n)))
            continue
        i += 1
    return "".join(out)


def source_views(src: str) -> tuple[str, str]:
    """Keep literal contents out of macro rewriting, without losing C syntax."""
    spans = []
    masked = mask_noise(src, literal_spans=spans)
    protected = list(masked)
    for start, end in spans:
        protected[start] = src[start]
        if end > start + 1 and src[end - 1] == src[start]:
            protected[end - 1] = src[end - 1]
    semantic = list(normalize_macros("".join(protected), preserve_conditionals=True))
    for start, end in spans:
        # Erased attributes/builtin arguments must not be resurrected by restoring
        # a literal that belonged to the erased region.
        if semantic[start] == src[start] and semantic[end - 1] == src[end - 1]:
            semantic[start:end] = src[start:end]
    return normalize_macros(masked), "".join(semantic)


def _skip_ws(src: str, i: int) -> int:
    n = len(src)
    while i < n and src[i] in " \t\r\n":
        i += 1
    return i


def _ident(src: str, i: int) -> tuple[str, int] | None:
    if i >= len(src) or not (src[i].isalpha() or src[i] == "_"):
        return None
    j = i + 1
    while j < len(src) and (src[j].isalnum() or src[j] == "_"):
        j += 1
    return src[i:j], j


def _match_paren(src: str, open_at: int) -> int:
    depth = 0
    i = open_at
    while i < len(src):
        if src[i] == "(":
            depth += 1
        elif src[i] == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(src)


def _match_brace(src: str, open_at: int) -> int:
    depth = 0
    i = open_at
    while i < len(src):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(src)


def _header_start(src: str, name_at: int) -> int:
    i = name_at
    while i > 0:
        if src[i - 1] in ";}":
            return i
        i -= 1
    return 0


def classify_return_kind(header: str) -> str:
    h = header
    for word in ("static", "inline", "noinline", "extern", "__init", "__exit", "__user"):
        h = h.replace(word, " ")
    if "*" in h:
        return "pointer"
    tokens = h.split()
    if tokens and tokens[-1] == "void":
        return "void"
    return "int"


def _return_sites(body: str, return_kind: str) -> list[ReturnSite]:
    assigned = _assigned_constants(body)
    sites: list[ReturnSite] = []
    i = 0
    n = len(body)
    while i < n:
        ident = _ident(body, i)
        if ident is None:
            i += 1
            continue
        name, j = ident
        if name != "return":
            i = j
            continue
        k = _skip_ws(body, j)
        expr_start = k
        paren = 0
        while k < n:
            if body[k] == "(":
                paren += 1
            elif body[k] == ")":
                paren -= 1
            elif body[k] == ";" and paren == 0:
                break
            k += 1
        expr = " ".join(body[expr_start:k].split())
        if expr in assigned:
            for value, offset in assigned[expr]:
                if offset >= expr_start:
                    continue
                # A later assignment kills this value on a straight-line path.
                # Across branches we retain a hypothesis, not a reaching-def proof.
                suffix = body[offset:expr_start]
                if re.search(rf"\b{re.escape(expr)}\s*=(?!=)", suffix) and not re.search(r"[{}]|\b(?:if|goto|switch)\b", suffix):
                    continue
                sites.append(ReturnSite(value, offset, _expr_kind(value, return_kind)))
        elif expr:
            sites.append(ReturnSite(expr, expr_start, _expr_kind(expr, return_kind)))
        i = k + 1
    return sites


def _expr_kind(expr: str, return_kind: str) -> str:
    retry = {
        "-EAGAIN",
        "-EWOULDBLOCK",
        "-EBUSY",
        "-EINPROGRESS",
        "-ERESTARTSYS",
        "-ERESTARTNOINTR",
        "-ERESTARTNOHAND",
        "NGX_AGAIN",
        "NGX_BUSY",
    }
    if expr in retry:
        return "retry"
    if expr in {"-ENOIOCTLCMD", "NGX_DECLINED", "NGX_DONE"}:
        return "nonterminal"
    if expr in {"0", "NGX_OK", "TC_ACT_OK", "TC_ACT_PIPE"}:
        return "success"
    if expr == "NULL":
        return "null" if return_kind == "pointer" else "other"
    error_pointer = re.fullmatch(r"ERR_PTR\(\s*(-E[A-Z0-9_]+|-\d+)\s*\)", expr)
    if error_pointer:
        kind = _expr_kind(error_pointer.group(1), "int")
        return "err_ptr" if kind == "neg" and return_kind == "pointer" else "other"
    if expr.startswith("-") and expr[1:].isdigit():
        return "neg"
    if expr.startswith("-E") and expr[2:].replace("_", "").isalnum():
        return "neg"
    if expr == "NGX_ERROR":
        return "neg"
    if expr == "TC_ACT_SHOT":
        return "shot"
    if expr in {"VM_FAULT_SIGBUS", "VM_FAULT_SIGSEGV", "VM_FAULT_OOM"}:
        return "named"
    if re.fullmatch(r"[A-Z][A-Z0-9_]+", expr):
        return "named"
    return "other"


def _assigned_constants(body: str) -> dict[str, list[tuple[str, int]]]:
    found: dict[str, list[tuple[str, int]]] = {}
    pattern = re.compile(r"(?<![=!<>])\b(\w+)\s*=\s*(NULL|-E[A-Z0-9_]+|-\d+)\s*[,;]")
    for match in pattern.finditer(body):
        found.setdefault(match.group(1), []).append((match.group(2), match.start(2)))
    return found


def _syscall_name(text: str, open_paren: int) -> str | None:
    cursor = _skip_ws(text, open_paren + 1)
    ident = _ident(text, cursor)
    if ident is None:
        return None
    return ident[0]


def parse_functions(src: str, file: str) -> dict[str, Function]:
    text, semantic = source_views(src)
    found: dict[str, Function] = {}
    i = 0
    n = len(text)
    while i < n:
        ident = _ident(text, i)
        if ident is None:
            i += 1
            continue
        name, j = ident
        k = _skip_ws(text, j)
        if k >= n or text[k] != "(" or name in KEYWORDS:
            i = j
            continue
        end_paren = _match_paren(text, k)
        m = _skip_ws(text, end_paren)
        if m >= n or text[m] != "{":
            i = j
            continue
        defined = is_define_macro(name)
        syscall = is_syscall_macro(name)
        if defined:
            real = _syscall_name(text, k)
            if real is None:
                i = j
                continue
        else:
            real = name
        body_end = _match_brace(text, m)
        header = text[_header_start(text, i):i]
        params = text[k + 1:end_paren - 1]
        body = text[m + 1:body_end - 1]
        return_kind = "int" if syscall else classify_return_kind(header)
        func = Function(
            name=real,
            return_kind=return_kind,
            params=params,
            body=body,
            semantic_body=semantic[m + 1:body_end - 1],
            returns=_return_sites(body, return_kind),
            file=file,
            uid=f"{file}::{real}",
            is_static=re.search(r"\bstatic\b", header) is not None and not syscall,
            is_syscall=syscall,
            line=text.count("\n", 0, i) + 1,
            body_line=text.count("\n", 0, m + 1) + 1,
            entry_effects=re.findall(r"\b__(?:releases|acquires)\s*\([^)]*\)", src[i:m]),
        )
        func.segments = [(0, func.body_line, func.line)]
        func.parameter_segments = [(0, params)]
        previous = found.get(func.uid)
        if previous is None:
            found[func.uid] = func
        else:
            shift = len(previous.body) + 1
            previous.body += "\n" + body
            previous.semantic_body += "\n" + func.semantic_body
            previous.parameter_segments.append((shift, params))
            previous.segments.extend((start + shift, line, definition) for start, line, definition in func.segments)
            previous.entry_effects.extend(func.entry_effects)
            previous.returns.extend(
                ReturnSite(site.expr, site.offset + shift, site.kind) for site in func.returns
            )
        i = body_end
    return found


def parse_files(paths: list[tuple[str, str]]) -> dict[str, Function]:
    merged: dict[str, Function] = {}
    globals_seen: dict[str, str] = {}
    for file, src in paths:
        for func in parse_functions(src, file).values():
            if not func.is_static:
                previous = globals_seen.get(func.name)
                if previous is not None and previous != func.file:
                    raise ValueError(f"函数 {func.name} 在多个文件里都有定义")
                globals_seen[func.name] = func.file
            merged[func.uid] = func
    return merged
