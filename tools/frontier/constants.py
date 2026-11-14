"""Small integer macro environment; never evaluate source text as Python code."""
import ast
import re

from .macros import normalize_macros


def integer_expression(expression, constants):
    def visit(node):
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value
        if isinstance(node, ast.Name):
            return constants.get(node.id)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
            value = visit(node.operand)
            if value is not None:
                return -value if isinstance(node.op, ast.USub) else value
        return None

    try:
        value = visit(ast.parse(expression.strip(), mode="eval").body)
        return value if value is not None and -(2**31 - 1) <= value <= 2**31 - 1 else None
    except (SyntaxError, RecursionError, ValueError):
        return None


def _active_directives(source):
    """Yield reachable directives and certainty, never infer optional presence.

    A conventional whole-file include guard is a container, under the ordinary
    first-inclusion assumption. All other unknown branches remain conditional.
    This is intentionally not a replacement for a configured preprocessor.
    """
    lines = normalize_macros(source, preserve_conditionals=True).splitlines()
    nonempty = [i for i, line in enumerate(lines) if line.strip()]
    guard = None
    if len(nonempty) >= 3:
        opening = re.fullmatch(r"\s*#\s*ifndef\s+(\w+)\s*", lines[nonempty[0]])
        if opening and re.fullmatch(r"\s*#\s*define\s+" + re.escape(opening[1]) + r"\s*", lines[nonempty[1]]):
            depth = 0
            for index in nonempty:
                directive = re.match(r"\s*#\s*(\w+)", lines[index])
                word = directive[1] if directive else ""
                depth += word in {"if", "ifdef", "ifndef"}
                depth -= word == "endif"
                if depth == 1 and word in {"else", "elif", "elifdef", "elifndef"}:
                    break
                if depth == 0:
                    if index == nonempty[-1] and word == "endif":
                        guard = nonempty[0]
                    break
    # Each frame retains the parent activity and whether a prior arm was taken.
    # None means possible; False means unreachable in this source view.
    frames = []
    active = True
    for index, line in enumerate(lines):
        directive = re.match(r"\s*#\s*(\w+)\b(.*)", line)
        if not directive:
            continue
        word, expression = directive.groups()
        if word in {"if", "ifdef", "ifndef"}:
            value = integer_expression(expression, {}) if word == "if" else None
            condition = True if index == guard else None if value is None else bool(value)
            frames.append((active, condition))
            active = False if active is False or condition is False else (True if active is True and condition is True else None)
        elif word in {"else", "elif", "elifdef", "elifndef"} and frames:
            parent, taken = frames[-1]
            value = integer_expression(expression, {}) if word == "elif" else None
            condition = True if word == "else" else None if value is None else bool(value)
            active = False if parent is False or taken is True or condition is False else (True if parent is True and taken is False and condition is True else None)
            frames[-1] = (parent, True if taken is True or condition is True else None if taken is None or condition is None else False)
        elif word == "endif" and frames:
            active, _ = frames.pop()
        elif active is not False:
            yield index, word, expression, active is True


def integer_macros(sources):
    definitions = {}
    undefined = set()
    conditional = set()
    for source in sources:
        undefined.update(re.findall(r"^\s*#\s*undef\s+(\w+)", source, re.MULTILINE))
        for _, directive, expression, certain in _active_directives(source):
            match = re.fullmatch(r"[ \t]+([A-Za-z_]\w*)[ \t]+(.+)", expression)
            if directive != "define" or match is None:
                continue
            name, expression = match.groups()
            definitions.setdefault(name, set()).add(expression.strip())
            if not certain:
                conditional.add(name)
    # Alternative definitions are configuration-dependent even if the values
    # might simplify alike. Do not select one by traversal/file order.
    pending = {name: next(iter(values)) for name, values in definitions.items()
               if len(values) == 1 and name not in undefined | conditional}
    constants = {}
    for _ in range(len(pending)):
        found = {name: value for name, expr in pending.items()
                 if (value := integer_expression(expr, constants)) is not None}
        if not found:
            break
        constants.update(found)
        for name in found:
            del pending[name]
    return constants


def source_include_sets(blobs):
    """Respect file scope; only follow explicitly included supplied headers."""
    sources = dict(blobs)
    from .parse import mask_noise
    masked = {name: mask_noise(source) for name, source in blobs}
    result = {}
    for filename in sources:
        included = set()
        pending = [filename]
        while pending:
            current = pending.pop()
            if current in included:
                continue
            included.add(current)
            certain_includes = {line for line, word, _, certain in _active_directives(masked[current])
                                if word == "include" and certain}
            for match in re.finditer(r'^[ \t]*#\s*include\s*[<"]([^>"\n]+)[>"]', sources[current], re.MULTILINE):
                if sources[current].count("\n", 0, match.start()) not in certain_includes:
                    continue
                if not re.match(r"\s*#\s*include", masked[current][match.start():]):
                    continue
                include = match.group(1)
                matches = [path for path in sources if path.replace("\\", "/").endswith("/" + include)
                           or path.replace("\\", "/") == include]
                if len(matches) == 1:
                    pending.append(matches[0])
        result[filename] = tuple(sorted(included))
    return result


def source_macro_contexts(blobs):
    from .parse import mask_noise
    masked = {name: mask_noise(source) for name, source in blobs}
    return {filename: tuple(sorted(integer_macros([masked[p] for p in included]).items()))
            for filename, included in source_include_sets(blobs).items()}
