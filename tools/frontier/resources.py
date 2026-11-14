"""Small, conservative resource model. Unknown aliases are not cleanup evidence."""
from __future__ import annotations

import re

from .parse import _match_brace, _match_paren


def _statement_end(text: str, start: int) -> int:
    while start < len(text) and text[start].isspace():
        start += 1
    if start < len(text) and text[start] == "{":
        return _match_brace(text, start)
    nested = re.match(r"(?:if|for|while|switch)\s*\(", text[start:])
    if nested:
        end = _statement_end(text, _match_paren(text, start + nested.end() - 1))
        tail = re.match(r"\s*else\b", text[end:])
        if nested.group().startswith("if") and tail:
            end = _statement_end(text, end + tail.end())
        return end
    semi = text.find(";", start)
    return len(text) if semi < 0 else semi + 1


def unconditional_code(text: str, reaching_end: bool = False) -> str:
    """Keep straight-line statements; conditional cleanup cannot discharge a debt."""
    out = []
    cursor = 0
    while cursor < len(text):
        if text[cursor].isspace() or text[cursor] in "{}":
            cursor += 1
            continue
        label = re.match(r"\w+\s*:(?!:)", text[cursor:])
        if label:
            cursor += label.end()
            continue
        branch = re.match(r"(?:if|while|for|switch)\s*\(", text[cursor:])
        if branch:
            begin = _match_paren(text, cursor + branch.end() - 1)
            end = _statement_end(text, begin)
            other = re.match(r"\s*else\b", text[end:])
            if reaching_end and branch.group().startswith("if") and other:
                other_begin = end + other.end()
                other_end = _statement_end(text, other_begin)
                left = unconditional_code(text[begin:end], True)
                right = unconditional_code(text[other_begin:other_end], True)
                right_calls = {(n, tuple(map(identity, a))) for n, a, _ in calls(right)}
                # Only a release common to both arms can discharge a debt.
                for name, args, _ in calls(left):
                    if (name, tuple(map(identity, args))) in right_calls:
                        out.append(f"{name}({', '.join(args)});")
                cursor = other_end
                continue
            if not reaching_end and re.search(r"\b(?:return|goto|break|continue)\b", text[begin:end]):
                break
            cursor = end
            continue
        otherwise = re.match(r"(?:else|do)\b", text[cursor:])
        if otherwise:
            cursor = _statement_end(text, cursor + otherwise.end())
            continue
        if re.match(r"(?:return|goto|break|continue)\b", text[cursor:]):
            break
        end = _statement_end(text, cursor)
        out.append(text[cursor:end])
        cursor = end
    return "\n".join(out)


def calls(text: str):
    for match in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", text):
        end = _match_paren(text, match.end() - 1)
        yield match.group(1), split_args(text[match.end():end - 1]), match.start()


def split_args(text: str) -> list[str]:
    args, start, depth = [], 0, 0
    for i, char in enumerate(text):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            args.append(text[start:i].strip())
            start = i + 1
    args.append(text[start:].strip())
    return args


def identity(expr: str) -> str:
    return re.sub(r"\s+", "", expr)


def reachable_siblings(body: str, offset: int) -> str:
    """Mask else arms excluded by the branch containing this call."""
    stack = []
    for i, char in enumerate(body[:offset]):
        if char == "{":
            stack.append(i)
        elif char == "}" and stack:
            stack.pop()
    out = list(body)
    cursor = offset
    while cursor < len(body):
        if body[cursor] == "{":
            stack.append(cursor)
        elif body[cursor] == "}" and stack:
            opened = stack.pop()
            alternate = re.match(r"\s*else\b", body[cursor + 1:])
            if opened < offset and alternate:
                end = _statement_end(body, cursor + 1 + alternate.end())
                for j in range(cursor + 1, end):
                    if out[j] != "\n":
                        out[j] = " "
                cursor = end
                continue
        cursor += 1
    return "".join(out)


def assigned_object(text: str, offset: int) -> str | None:
    start = max(text.rfind(";", 0, offset), text.rfind("{", 0, offset), text.rfind("}", 0, offset)) + 1
    match = re.search(r"(\w+(?:(?:\s*->\s*|\s*\.\s*)\w+)*)\s*=\s*$", text[start:offset])
    return identity(match.group(1)) if match else None


def obligations(prefix: str, families) -> list[tuple[int, str]]:
    held = []
    for name, args, offset in calls(prefix):
        for family, (acquires, _) in enumerate(families):
            if name not in acquires:
                continue
            obj = identity(args[0]) if name in {"get_page", "mutex_lock", "mutex_lock_interruptible", "spin_lock", "spin_lock_bh"} else assigned_object(prefix, offset)
            held.append((family, obj or "<unresolved>"))
    # Only unconditional releases before the call remove obligations. Ignoring
    # conditional releases can cause false negatives, never a guessed pairing.
    for name, args, _ in calls(unconditional_code(prefix, True)):
        for family, (_, releases) in enumerate(families):
            if name in releases:
                obj = identity(args[-1] if name == "kmem_cache_free" else args[0])
                if (family, obj) in held:
                    held.remove((family, obj))
    return held


def releases(region: str, functions, families, file: str = "", seen=frozenset()) -> list[tuple[int, str]]:
    found = []
    for name, args, _ in calls(unconditional_code(region)):
        modeled = False
        for family, (_, release_names) in enumerate(families):
            if name in release_names:
                obj = args[-1] if name == "kmem_cache_free" else args[0]
                found.append((family, identity(obj)))
                modeled = True
        if modeled:
            continue
        targets = [func for func in functions.values() if func.name == name
                   and (not func.is_static or func.file == file)]
        local = [func for func in targets if func.file == file]
        targets = local or targets
        if len(targets) != 1 or targets[0].uid in seen or len(seen) >= 4:
            continue
        target = targets[0]
        params = [re.search(r"(\w+)\s*$", param) for param in split_args(target.params)]
        mapping = {param.group(1): arg for param, arg in zip(params, args) if param}
        for family, obj in releases(target.body, functions, families, target.file, seen | {target.uid}):
            root = re.match(r"\w+", obj)
            if root and root.group() in mapping:
                found.append((family, identity(mapping[root.group()]) + obj[root.end():]))
    return found


def covers(held, released) -> bool:
    remaining = list(released)
    for debt in held:
        if debt[1] == "<unresolved>" or debt not in remaining:
            return False
        remaining.remove(debt)
    return True


def owned_aliases(prefix: str) -> dict[str, str]:
    """Recognize a direct transfer to an owner field on the path to the call."""
    found = {}
    code = unconditional_code(prefix, True)
    for match in re.finditer(r"\b(\w+(?:\s*->\s*\w+)+)\s*=\s*(\w+)\s*;", code):
        field, local = identity(match.group(1)), match.group(2)
        suffix = identity(code[match.end():])
        if local not in found and not re.search(re.escape(field) + r"=(?!=)", suffix):
            found[local] = field
    return found
