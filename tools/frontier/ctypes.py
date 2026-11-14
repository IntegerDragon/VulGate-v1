"""Source C types for named storage, without inventing a target ABI.

Records describe member identity/overlap, not byte offsets. Exact integer widths
are available only under an explicit analysis model, never from the host Python.
"""
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import re

from tree_sitter import Language, Parser
import tree_sitter_c

from .constants import integer_expression


@dataclass(frozen=True)
class CType:
    kind: str
    name: str = ""
    target: "CType | None" = None


UNKNOWN = CType("unknown")
INT = CType("integer", "int")


@dataclass(frozen=True)
class Record:
    uid: str
    kind: str
    fields: tuple[tuple[str, CType], ...]
    complete: bool = True


@dataclass(frozen=True)
class TypeContext:
    bindings: tuple[tuple[str, CType], ...] = ()
    records: tuple[tuple[str, Record], ...] = ()
    declarations: tuple[tuple[int, CType], ...] = ()
    globals: tuple[tuple[str, CType], ...] = ()
    returns: tuple[tuple[str, CType], ...] = ()
    casts: tuple[tuple[int, CType], ...] = ()
    function_bindings: tuple[tuple[str, tuple[tuple[str, CType], ...]], ...] = ()


@dataclass(frozen=True)
class IntegerModel:
    name: str = "portable"
    widths: tuple[int, ...] = ()  # char, short, int, long, long long


MODELS = {"portable": IntegerModel(), "ilp32": IntegerModel("ilp32", (8, 16, 32, 32, 64)),
          "lp64": IntegerModel("lp64", (8, 16, 32, 64, 64)),
          "llp64": IntegerModel("llp64", (8, 16, 32, 32, 64))}


def primitive(spelling):
    words = spelling.split()
    if spelling == "_Bool":
        return CType("integer", "_Bool")
    if spelling == "void":
        return CType("void", "void")
    if not words or any(w not in {"signed", "unsigned", "char", "short", "int", "long"} for w in words):
        return None
    base = "char" if "char" in words else "short" if "short" in words else "long long" if words.count("long") == 2 else "long" if "long" in words else "int"
    prefix = "unsigned " if "unsigned" in words else "signed " if base == "char" and "signed" in words else ""
    return CType("integer", prefix + base)


def integer_info(ctype, model):
    if ctype.kind != "integer":
        return None
    if ctype.name == "_Bool":
        return False, 1, 1, -1
    unsigned = ctype.name.startswith("unsigned ")
    base = ctype.name.removeprefix("unsigned ").removeprefix("signed ")
    if base not in {"char", "short", "int", "long", "long long"}:
        return None
    rank = ("char", "short", "int", "long", "long long").index(base)
    # Plain char signedness is not implied by LP64/LLP64.
    signed = None if ctype.name == "char" else not unsigned
    return signed, (8, 16, 16, 32, 64)[rank], model.widths[rank] if model.widths else None, rank


def convert_integer(number, ctype, model):
    info = integer_info(ctype, model)
    if info is None:
        return None, "unmodeled_integer_type"
    signed, minimum, bits, _ = info
    if ctype.name == "_Bool":
        return int(number != 0), None
    if signed is None:
        return (number, None) if 0 <= number < 128 else (None, "plain_char_signedness_unbound")
    width = bits or minimum
    low = -(2 ** (width - 1) - 1) if signed else 0
    high = 2 ** (width - int(signed)) - 1
    if bits and signed:
        low -= 1
    if low <= number <= high:
        return number, None
    if bits and not signed:
        return number % (2 ** bits), None
    return None, "signed_integer_conversion_out_of_range" if bits else "integer_width_unbound"


def arithmetic_type(left, right, model):
    def promote(ctype):
        info = integer_info(ctype, model)
        if info is None:
            return None
        signed, _, bits, rank = info
        if rank >= 2:
            return ctype
        if signed is True or ctype.name == "_Bool":
            return INT
        if bits is not None:
            return INT if bits < model.widths[2] else CType("integer", "unsigned int")
        return None

    a, b = promote(left), promote(right)
    if a is None or b is None:
        return None
    if a == b:
        return a
    sa, _, ba, ra = integer_info(a, model)
    sb, _, bb, rb = integer_info(b, model)
    if sa == sb:
        return a if ra >= rb else b
    signed, unsigned = (a, b) if sa else (b, a)
    _, _, signed_bits, signed_rank = integer_info(signed, model)
    _, _, unsigned_bits, unsigned_rank = integer_info(unsigned, model)
    if unsigned_rank >= signed_rank:
        return unsigned
    if signed_bits is None or unsigned_bits is None:
        return None
    return signed if signed_bits > unsigned_bits else CType("integer", "unsigned " + signed.name)


def integer_literal(text, model):
    match = re.fullmatch(r"(.*?)([uUlL]*)", text)
    raw, suffix = match.groups()
    if suffix.lower() not in {"", "u", "l", "ul", "lu", "ll", "ull", "llu"}:
        return None, UNKNOWN, "unsupported_integer_suffix"
    try:
        number = int(raw, 8 if re.fullmatch(r"0[0-7]+", raw) else 0)
    except ValueError:
        return None, UNKNOWN, "unsupported_number"
    unsigned, count = "u" in suffix.lower(), suffix.lower().count("l")
    bases = ["long long"] if count == 2 else ["long", "long long"] if count == 1 else ["int", "long", "long long"]
    types = [CType("integer", ("unsigned " if unsigned else "") + base) for base in bases]
    if not unsigned and raw.startswith(("0x", "0X", "0b", "0B")) or not unsigned and re.fullmatch(r"0[0-7]+", raw):
        types = [ctype for base in bases for ctype in (CType("integer", base), CType("integer", "unsigned " + base))]
    for ctype in types:
        info = integer_info(ctype, model)
        signed, minimum, bits, _ = info
        if number <= 2 ** ((bits or minimum) - int(signed)) - 1:
            return number, ctype, None
        if bits is None:
            break
    return number, UNKNOWN, "integer_literal_type_unbound"


def compatible(left, right):
    if left.kind == "unknown" or right.kind == "unknown":
        return False
    if left == right:
        return True
    if left.kind == "void" or right.kind == "void":
        return True
    if left.kind != right.kind:
        return False
    if left.kind in {"pointer", "array"}:
        return compatible(left.target or UNKNOWN, right.target or UNKNOWN)
    # Equal-looking records in different scopes are not thereby compatible C
    # types. Shared provided headers preserve the actual declaration identity.
    return False


def _parse(source):
    return Parser(Language(tree_sitter_c.language())).parse(source)


def _text(source, node):
    return "" if node is None else source[node.start_byte:node.end_byte].decode("utf-8")


def _scope_chain(node):
    result = []
    while node is not None:
        if node.type == "compound_statement":
            result.append(node.start_byte)
        node = node.parent
    return result + [0]


def _identifier(node):
    while node is not None and node.type not in {"identifier", "field_identifier", "type_identifier", "primitive_type"}:
        node = node.child_by_field_name("declarator")
    return node


def _presence(node, source, guard):
    uncertain = False
    child, parent = node, node.parent
    while parent is not None:
        if parent.type in {"preproc_if", "preproc_ifdef", "preproc_elif", "preproc_elifdef"} and parent != guard:
            condition = parent.child_by_field_name("condition")
            value = integer_expression(_text(source, condition), {}) if condition else None
            alternative = parent.child_by_field_name("alternative") == child
            if value is not None and bool(value) == alternative:
                return False
            uncertain |= value is None
        child, parent = parent, parent.parent
    return None if uncertain else True


@lru_cache(maxsize=64)
def type_context(sources: tuple[tuple[str, str], ...], base=TypeContext(), local=False):
    """Collect typed declarations, scoped typedefs, records and anonymous members."""
    from .parse import source_views
    entries, units, records, declaration_types, globals_, returns, casts = {}, [], dict(base.records), {}, dict(base.globals), dict(base.returns), {}
    function_bindings = {}
    inherited = dict(base.bindings)
    for filename, text in sources:
        source = source_views(text)[1].encode("utf-8")
        tree = _parse(source)
        root = tree.root_node
        identity = filename + ":" + hashlib.sha256(source).hexdigest()[:16]
        guard = None
        if len(root.named_children) == 1:
            first = root.named_children[0]
            name = first.child_by_field_name("name")
            definitions = [c for c in first.named_children if c.type == "preproc_def"]
            if (first.type == "preproc_ifdef" and re.match(r"#\s*ifndef\b", _text(source, first))
                    and definitions and _text(source, definitions[0].child_by_field_name("name")) == _text(source, name)
                    and first.child_by_field_name("alternative") is None):
                guard = first
        nodes = []
        pending = [root]
        while pending:
            node = pending.pop()
            if not local and node.type == "function_definition":
                nodes.append(node)
                continue
            if _presence(node, source, guard) is False:
                continue
            nodes.append(node)
            pending.extend(reversed(node.named_children))
            scope = _scope_chain(node)[0] if local else 0
            if node.type in {"struct_specifier", "union_specifier"}:
                tag = node.child_by_field_name("name")
                standalone = node.parent and node.parent.type == "declaration" and not node.parent.children_by_field_name("declarator")
                if tag is not None and (node.child_by_field_name("body") or standalone):
                    name = node.type.removesuffix("_specifier") + " " + _text(source, tag)
                    uid = identity + ":tag:" + str(scope) + ":" + name
                    entries.setdefault((scope, name), []).append((source, node, uid, guard))
            if node.type == "type_definition":
                for declarator in node.children_by_field_name("declarator"):
                    ident = _identifier(declarator)
                    if ident:
                        entries.setdefault((scope, _text(source, ident)), []).append((source, node, declarator, guard))
        units.append((source, nodes, identity, guard))

    resolving = set()

    def lookup(name, node, source):
        for scope in _scope_chain(node) if local else [0]:
            key = (scope, name)
            if key not in entries:
                continue
            # A later block typedef/tag must not shadow an earlier use. Across
            # supplied headers ordering is not reconstructed here; unresolved
            # duplicates remain unknown rather than choosing one by traversal.
            candidates = [entry for entry in entries[key]
                          if entry[0] is not source or entry[1].start_byte <= node.start_byte]
            if not candidates:
                continue
            same_tag = (all(isinstance(entry[2], str) for entry in candidates)
                        and len({entry[2] for entry in candidates}) == 1
                        and sum(entry[1].child_by_field_name("body") is not None for entry in candidates) <= 1)
            if (len(candidates) != 1 and not same_tag) or key in resolving:
                return CType("unknown", "conflicting_or_recursive_type:" + name)
            source, definition, item, guard = candidates[0]
            if _presence(definition, source, guard) is not True:
                return CType("unknown", "conditional_type:" + name)
            if isinstance(item, str):
                return CType("record", item)
            resolving.add(key)
            result = declaration_type(source, definition, item)
            resolving.remove(key)
            return result
        return inherited.get(name, CType("unknown", "missing_type:" + name))

    def node_type(source, node):
        if node is None:
            return UNKNOWN
        spelling = _text(source, node)
        basic = primitive(spelling)
        if basic:
            return basic
        if node.type in {"struct_specifier", "union_specifier"}:
            unit = next(u for u in units if u[0] is source)
            tag = node.child_by_field_name("name")
            scope = _scope_chain(node)[0] if local else 0
            name = node.type.removesuffix("_specifier") + " " + _text(source, tag)
            identity = unit[2] + ":tag:" + str(scope) + ":" + name
            if node.child_by_field_name("body"):
                return CType("record", identity if tag else unit[2] + ":" + str(node.start_byte))
            resolved = lookup(name, node, source)
            # A tagged incomplete declaration and its later definition denote
            # the same type; unlike typedef shadowing, completion is allowed.
            return CType("record", identity) if resolved.name == "missing_type:" + name else resolved
        return lookup(spelling, node, source) if node.type in {"type_identifier", "primitive_type"} else CType("unknown", "unsupported_type:" + node.type)

    def declaration_type(source, declaration, declarator):
        ctype = node_type(source, declaration.child_by_field_name("type"))
        if any(c.type in {"bitfield_clause", "attribute_specifier"} or (c.type == "type_qualifier" and _text(source, c) in {"volatile", "_Atomic"}) for c in declaration.named_children):
            return CType("unknown", "qualified_or_bitfield_type")
        layers = []
        while declarator is not None and declarator.type not in {"identifier", "field_identifier", "type_identifier", "primitive_type"}:
            if declarator.type == "init_declarator":
                declarator = declarator.child_by_field_name("declarator")
                continue
            if declarator.type not in {"pointer_declarator", "array_declarator", "abstract_pointer_declarator"}:
                return CType("unknown", "unsupported_declarator:" + declarator.type)
            if any(c.type == "type_qualifier" and _text(source, c) in {"volatile", "_Atomic"}
                   for c in declarator.named_children):
                return CType("unknown", "qualified_pointer_type")
            layers.append(declarator.type)
            declarator = declarator.child_by_field_name("declarator")
        for layer in layers:
            ctype = CType("pointer" if layer in {"pointer_declarator", "abstract_pointer_declarator"} else "array", target=ctype)
        return ctype

    for source, nodes, identity, guard in units:
        for node in nodes:
            if node.type == "type_descriptor":
                casts[len(source[:node.start_byte].decode("utf-8"))] = declaration_type(source, node, node.child_by_field_name("declarator"))
            if node.type == "function_definition" and not local:
                ctype = node_type(source, node.child_by_field_name("type"))
                declarator = node.child_by_field_name("declarator")
                while declarator is not None and declarator.type == "pointer_declarator":
                    ctype = CType("pointer", target=ctype)
                    declarator = declarator.child_by_field_name("declarator")
                ident = _identifier(declarator)
                if ident:
                    name = _text(source, ident)
                    returns[name] = ctype if name not in returns or returns[name] == ctype else UNKNOWN
                    visible = {key: lookup(key, node, source) for scope, key in entries if scope == 0}
                    if name in function_bindings:
                        prior = function_bindings[name]
                        visible = {key: kind if prior.get(key) == kind else UNKNOWN for key, kind in visible.items()}
                    function_bindings[name] = visible
            body = node.child_by_field_name("body") if node.type in {"struct_specifier", "union_specifier"} else None
            if body:
                fields, complete = [], not body.has_error and _presence(node, source, guard) is True
                for declaration in body.named_children:
                    if declaration.type != "field_declaration":
                        complete = False
                        continue
                    declarators = declaration.children_by_field_name("declarator")
                    if not declarators:
                        fields.append(("", declaration_type(source, declaration, None)))
                    for declarator in declarators:
                        ident = _identifier(declarator)
                        if ident is None:
                            complete = False
                            continue
                        fields.append((_text(source, ident), declaration_type(source, declaration, declarator)))
                uid = node_type(source, node).name
                names = [name for name, _ in fields if name]
                records[uid] = Record(uid, node.type.removesuffix("_specifier"), tuple(fields), complete and len(names) == len(set(names)))
            if node.type in {"declaration", "parameter_declaration"}:
                for declarator in node.children_by_field_name("declarator"):
                    ident = _identifier(declarator)
                    if ident is None:
                        continue
                    ctype = declaration_type(source, node, declarator)
                    declaration_types[len(source[:ident.start_byte].decode("utf-8"))] = ctype
                    if not local and node.type == "declaration":
                        globals_[_text(source, ident)] = ctype
    bindings = dict(inherited)
    for (scope, name), definitions in entries.items():
        if scope == 0:
            # Export the whole file binding only when definitions agree.
            bindings[name] = (lookup(name, definitions[-1][1], definitions[-1][0]) if len(definitions) == 1 or all(isinstance(d[2], str) for d in definitions)
                              else CType("unknown", "conflicting_type:" + name))
    return TypeContext(tuple(sorted(bindings.items())), tuple(sorted(records.items())),
                       tuple(sorted(declaration_types.items())), tuple(sorted(globals_.items())), tuple(sorted(returns.items())), tuple(sorted(casts.items())),
                       tuple(sorted((name, tuple(sorted(values.items()))) for name, values in function_bindings.items())))


def member(ctype, name, records, depth=0):
    if ctype.kind != "record" or depth > 12:
        return UNKNOWN, (), "record_layout_missing"
    record = records.get(ctype.name)
    if record is None or not record.complete:
        return UNKNOWN, (), "record_layout_incomplete"
    names = member_names(ctype, records)
    for field, nested in record.fields:
        overlaps = tuple(names) if record.kind == "union" else ()
        if field == name:
            return nested, overlaps, None
        if not field and nested.kind == "record":
            result, inner, reason = member(nested, name, records, depth + 1)
            if reason is None:
                return result, tuple(set(overlaps) | set(inner)), None
    return UNKNOWN, (), "record_member_missing"


def member_names(ctype, records, depth=0):
    record = records.get(ctype.name) if ctype.kind == "record" else None
    if record is None or depth > 12:
        return ()
    return tuple(name for field, nested in record.fields
                 for name in ((field,) if field else member_names(nested, records, depth + 1)))


def source_type_contexts(blobs):
    from .constants import source_include_sets
    sources = dict(blobs)
    return {filename: type_context(tuple((path, sources[path]) for path in included))
            for filename, included in source_include_sets(blobs).items()}


def parameters(text, context):
    source = ("void __frontier_typed_parameters(" + text + ") {}").encode("utf-8")
    tree = _parse(source)
    if tree.root_node.has_error:
        return None
    function = tree.root_node.named_children[0]
    nodes = function.child_by_field_name("declarator").child_by_field_name("parameters").named_children
    if len(nodes) == 1 and _text(source, nodes[0]).strip() == "void":
        return ()
    local_context = type_context((("<parameters>", source.decode()),), context, True)
    types = dict(local_context.declarations)
    result = []
    for node in nodes:
        ident = _identifier(node.child_by_field_name("declarator"))
        if node.type != "parameter_declaration" or ident is None:
            return None
        ctype = types.get(len(source[:ident.start_byte].decode("utf-8")), UNKNOWN)
        if ctype.kind == "array":
            return None
        result.append((_text(source, ident), ctype))
    return tuple(result)
