"""C syntax and explicit control-flow edges, independent of kernel/CVE names."""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache

from tree_sitter import Language, Node, Parser
import tree_sitter_c


@dataclass
class Instruction:
    kind: str
    node: Node | None = None
    successors: tuple[int, ...] = ()
    cases: tuple[Node | None, ...] = ()
    join: int | None = None
    lexical_end: int | None = None


@dataclass
class ControlFlow:
    source: bytes
    body: Node
    prefix_bytes: int
    instructions: list[Instruction] = field(default_factory=list)
    entry: int = 0
    labels: dict[str, int] = field(default_factory=dict)
    gotos: list[tuple[int, str]] = field(default_factory=list)

    def text(self, node: Node | None) -> str:
        return "" if node is None else self.source[node.start_byte:node.end_byte].decode("utf-8")

    def offset(self, node: Node) -> int:
        return len(self.source[self.prefix_bytes:node.start_byte].decode("utf-8"))

    def add(self, kind, node=None, successors=(), cases=()) -> int:
        index = len(self.instructions)
        self.instructions.append(Instruction(kind, node, tuple(successors), tuple(cases)))
        return index

    def lower(self, node: Node | None, after: int, break_to=None, continue_to=None) -> int:
        if node is None:
            return after
        kind = node.type
        if kind == "type_definition":
            return self.add("eval", node, (after,))
        if kind in {"compound_statement", "case_statement", "else_clause", "preproc_else"}:
            children = node.named_children
            if kind == "case_statement":
                value = node.child_by_field_name("value")
                children = [c for c in children if c != value]
            entry = after
            for child in reversed(children):
                entry = self.lower(child, entry, break_to, continue_to)
            return entry
        if kind in {"preproc_if", "preproc_ifdef", "preproc_elif", "preproc_elifdef"}:
            condition = node.child_by_field_name("condition") or node.child_by_field_name("name")
            alternative = node.child_by_field_name("alternative")
            yes = after
            for child in reversed([c for c in node.named_children if c not in {condition, alternative}]):
                yes = self.lower(child, yes, break_to, continue_to)
            no = self.lower(alternative, after, break_to, continue_to)
            index = self.add("configuration", node, (yes, no))
            self.instructions[index].lexical_end = after
            return index
        if kind == "if_statement":
            yes = self.lower(node.child_by_field_name("consequence"), after, break_to, continue_to)
            no = self.lower(node.child_by_field_name("alternative"), after, break_to, continue_to)
            index = self.add("branch", node.child_by_field_name("condition"), (yes, no))
            self.instructions[index].join = after
            self.instructions[index].lexical_end = after
            return index
        if kind in {"while_statement", "for_statement", "do_statement"}:
            branch = self.add("branch", node.child_by_field_name("condition"))
            update = node.child_by_field_name("update")
            back = self.add("eval", update, (branch,)) if update else branch
            body = self.lower(node.child_by_field_name("body"), back, after, back)
            self.instructions[branch].successors = (body, after)
            self.instructions[branch].join = after
            self.instructions[branch].lexical_end = after
            if kind == "for_statement":
                return self.lower(node.child_by_field_name("initializer"), branch, break_to, continue_to)
            return body if kind == "do_statement" else branch
        if kind == "switch_statement":
            body = node.child_by_field_name("body")
            if body is None:
                return self.add("unknown", node, (after,))
            targets, values = [], []
            fallthrough = after
            for case in reversed(body.named_children):
                if case.type != "case_statement":
                    # Declaration before the first case is not an executable
                    # predecessor of every case. Keep unsupported forms unknown.
                    return self.add("unknown", node, (after,))
                fallthrough = self.lower(case, fallthrough, after, continue_to)
                targets.insert(0, fallthrough)
                values.insert(0, case.child_by_field_name("value"))
            if None not in values:
                targets.append(after)
                values.append(None)
            index = self.add("switch", node.child_by_field_name("condition"), targets, values)
            self.instructions[index].join = after
            self.instructions[index].lexical_end = after
            return index
        if kind == "return_statement":
            return self.add("return", node.named_children[0] if node.named_children else None)
        if kind == "goto_statement":
            label = self.text(node.child_by_field_name("label"))
            index = self.add("goto", node)
            self.gotos.append((index, label))
            return index
        if kind == "labeled_statement":
            label = node.child_by_field_name("label")
            entry = after
            for child in reversed([c for c in node.named_children if c != label]):
                entry = self.lower(child, entry, break_to, continue_to)
            self.labels[self.text(label)] = entry
            return entry
        if kind in {"break_statement", "continue_statement"}:
            target = break_to if kind == "break_statement" else continue_to
            return self.add("goto", node, (target,)) if target is not None else self.add("unknown", node, (after,))
        if kind in {"comment", "struct_specifier"}:
            return after
        if kind in {"declaration", "expression_statement", "assignment_expression", "update_expression", "call_expression", "comma_expression"}:
            return self.add("eval", node, (after,))
        return self.add("unknown", node, (after,))

    def variable(self, node: Node, name: str | None = None) -> str:
        """Lexical identities keep a nested declaration from overwriting an outer one."""
        name = name or self.text(node)
        scope = node.parent
        while scope is not None:
            if scope.type in {"compound_statement", "for_statement"}:
                declarations = [child for child in scope.named_children if child.type == "declaration"
                                and child.start_byte <= node.start_byte]
                for declaration in reversed(declarations):
                    for child in declaration.children_by_field_name("declarator"):
                        ident = declarator_identifier(child)
                        if ident is not None and self.text(ident) == name:
                            return f"{name}@{ident.start_byte}"
            scope = scope.parent
        return name


def declarator_identifier(node: Node | None) -> Node | None:
    while node is not None:
        if node.type in {"identifier", "field_identifier"}:
            return node
        node = node.child_by_field_name("declarator")
    return None


@lru_cache(maxsize=128)
def parse_parameters(parameters: str) -> tuple[tuple[str, str], ...] | None:
    """Bind ordinary fixed C parameters; unsupported declarators stay unknown."""
    source = ("void __frontier_params(" + parameters + ") {}").encode("utf-8")
    tree = Parser(Language(tree_sitter_c.language())).parse(source)
    if tree.root_node.has_error:
        return None
    function = tree.root_node.named_children[0]
    declarator = function.child_by_field_name("declarator")
    nodes = declarator.child_by_field_name("parameters").named_children
    result = []
    for node in nodes:
        if node.type != "parameter_declaration":
            return None
        ctype = node.child_by_field_name("type")
        kind = source[ctype.start_byte:ctype.end_byte].decode("utf-8") if ctype else ""
        cursor = node.child_by_field_name("declarator")
        if cursor is None and kind == "void" and len(nodes) == 1:
            return ()
        while cursor is not None and cursor.type == "pointer_declarator":
            kind = "pointer"
            cursor = cursor.child_by_field_name("declarator")
        if cursor is None or cursor.type != "identifier":
            return None
        result.append((source[cursor.start_byte:cursor.end_byte].decode("utf-8"), kind))
    return tuple(result)


@lru_cache(maxsize=128)
def parse_flow(body: str) -> ControlFlow:
    prefix = b"void __frontier_flow(void) {\n"
    source = prefix + body.encode("utf-8") + b"\n}"
    parser = Parser(Language(tree_sitter_c.language()))
    tree = parser.parse(source)
    function = next((n for n in tree.root_node.named_children if n.type == "function_definition"), None)
    root = function.child_by_field_name("body") if function else None
    if root is None:
        raise ValueError("无法解析 C 函数体")
    graph = ControlFlow(source, root, len(prefix))
    exit_node = graph.add("exit")
    graph.entry = graph.lower(root, exit_node)
    for index, label in graph.gotos:
        if label in graph.labels:
            graph.instructions[index].successors = (graph.labels[label],)
        else:
            graph.instructions[index].kind = "unknown"
            graph.instructions[index].successors = (exit_node,)
    # Postdominators clear checks where branches actually reconverge, including
    # goto cleanup labels. All returns share a virtual exit for this calculation.
    end = len(graph.instructions)
    post = [set(range(end + 1)) for _ in range(end)] + [{end}]
    changed = True
    while changed:
        changed = False
        for index, instruction in enumerate(graph.instructions):
            successors = instruction.successors or (end,)
            updated = {index} | set.intersection(*(post[s] for s in successors))
            if updated != post[index]:
                post[index] = updated
                changed = True
    for index, instruction in enumerate(graph.instructions):
        if instruction.kind in {"branch", "switch"}:
            strict = post[index] - {index}
            nearest = max(strict, key=lambda s: len(post[s]), default=end)
            instruction.join = nearest if nearest != end else None
    return graph
