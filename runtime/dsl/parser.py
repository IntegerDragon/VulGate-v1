"""Parser for the VulGate patch DSL.

The DSL is intentionally small and text based:

    动作 NGX_ERROR_RETURN:
    {
        返回类型: int
        返回: -1
    }

    挂载点 CVE-2026-97205:
    {
        位置: module="nginx", symbol="ngx_http_copy_filter",
              参数=[pointer, pointer], 返回=int64
        性质: 拦截点
        行为:
        {
            value["counter"] = read_u32(arg0 + 1000);
            if ((value["counter"] & 255) >= 250) {
                return block("NGX_ERROR_RETURN");
            }
        }
    }

`性质` is `读取点` or `拦截点`.  A read point records values into the shared
`value[...]` map; an interception point evaluates the fall-through condition and
falls back to the original function (PASS) when the body does not `return block`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from pathlib import Path


@dataclass
class ActionSpec:
    id: str
    return_type: str = 'int'
    value: object = 0
    errno: int | None = None
    writes: list[dict] = field(default_factory=list)


@dataclass
class MountSpec:
    id: str
    module: str | None
    symbol: str
    args: list[str]
    return_type: str
    nature: str
    body: str


@dataclass
class PatchSpec:
    actions: dict[str, ActionSpec]
    mounts: list[MountSpec]


class DSLParseError(ValueError):
    pass


def _strip_comments(text: str) -> str:
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('#'):
            continue
        lines.append(line)
    return '\n'.join(lines)


def _find_block(text: str, start: int) -> tuple[str, int]:
    """Return the text inside the first balanced { ... } block at/after start."""
    begin = text.find('{', start)
    if begin < 0:
        raise DSLParseError('missing "{"')
    depth = 0
    in_string = None
    index = begin
    while index < len(text):
        char = text[index]
        if in_string:
            if char == '\\':
                index += 2
                continue
            if char == in_string:
                in_string = None
        elif char in ('"', "'"):
            in_string = char
        elif char == '{':
            depth += 1
        elif char == '}':
            depth -= 1
            if depth == 0:
                return text[begin + 1:index], index + 1
        index += 1
    raise DSLParseError('unbalanced braces')


def _split_fields(body: str) -> dict[str, str]:
    """Split a mount/action block into top-level `key: value` fields."""
    fields: dict[str, str] = {}
    depth = 0
    bracket = 0
    in_string = None
    current = []
    pieces: list[str] = []
    for char in body:
        if in_string:
            current.append(char)
            if char == in_string:
                in_string = None
            continue
        if char in ('"', "'"):
            in_string = char
            current.append(char)
        elif char in '([{':
            depth += 1
            current.append(char)
        elif char in ')]}':
            depth -= 1
            current.append(char)
        elif char == '\n' and depth == 0:
            line = ''.join(current).strip()
            if line:
                pieces.append(line)
            current = []
        else:
            current.append(char)
    line = ''.join(current).strip()
    if line:
        pieces.append(line)
    for piece in pieces:
        match = re.match(r'([^:：]+)[:：]\s*(.*)$', piece, re.S)
        if not match:
            continue
        key = match.group(1).strip()
        value = match.group(2).strip()
        fields[key] = value
    return fields


def _parse_location(text: str) -> tuple[str | None, str, list[str], str]:
    module = None
    symbol = None
    args: list[str] = []
    return_type = 'int'

    def split_commas(value: str) -> list[str]:
        pieces: list[str] = []
        current: list[str] = []
        depth = 0
        in_string = None
        for char in value:
            if in_string:
                current.append(char)
                if char == in_string:
                    in_string = None
            elif char in ('"', "'"):
                in_string = char
                current.append(char)
            elif char in '([':
                depth += 1
                current.append(char)
            elif char in ')]':
                depth -= 1
                current.append(char)
            elif char == ',' and depth == 0:
                pieces.append(''.join(current))
                current = []
            else:
                current.append(char)
        pieces.append(''.join(current))
        return [piece.strip() for piece in pieces if piece.strip()]

    for part in split_commas(text):
        if '=' not in part:
            continue
        key, value = part.split('=', 1)
        key = key.strip()
        value = value.strip()
        if key in ('module', '模块'):
            module = value.strip('"\'')
        elif key in ('symbol', 'symbol_name', '符号', '函数'):
            symbol = value.strip('"\'')
        elif key in ('参数', 'args', 'arg_types'):
            args = [item.strip().strip('"\'')
                    for item in value.strip('[]').split(',') if item.strip()]
        elif key in ('返回', 'return', 'return_type'):
            return_type = value.strip('"\'')
        else:
            raise DSLParseError('unknown location field: ' + key)
    if not symbol:
        raise DSLParseError('location needs symbol')
    return module, symbol, args, return_type


def _parse_action(identifier: str, body: str) -> ActionSpec:
    fields = _split_fields(body)
    return_type = fields.get('返回类型', fields.get('return_type', 'int')).strip()
    raw_value = fields.get('返回', fields.get('value', '0')).strip()
    if raw_value in ('null', 'NULL', 'nil'):
        value: object = None
    elif raw_value.startswith(('"', "'")):
        value = raw_value.strip('"\'')
    else:
        value = int(raw_value, 0)
    errno = fields.get('errno')
    spec = ActionSpec(identifier, return_type, value, int(errno, 0) if errno else None)
    return spec


def parse(text: str) -> PatchSpec:
    text = _strip_comments(text)
    actions: dict[str, ActionSpec] = {}
    mounts: list[MountSpec] = []
    cursor = 0
    pattern = re.compile(r'^(动作|挂载点)\s+([^\s:：]+)\s*[:：]\s*', re.M)
    while True:
        match = pattern.search(text, cursor)
        if not match:
            break
        kind, identifier = match.group(1), match.group(2)
        block, cursor = _find_block(text, match.end())
        if kind == '动作':
            actions[identifier] = _parse_action(identifier, block)
            continue
        fields = _split_fields(block)
        location = fields.get('位置')
        if not location:
            raise DSLParseError(f'mount {identifier} has no 位置')
        module, symbol, args, return_type = _parse_location(location)
        nature = fields.get('性质', '拦截点').strip()
        if nature not in ('拦截点', '读取点', 'intercept', 'read'):
            raise DSLParseError(f'mount {identifier} has invalid 性质: {nature}')
        nature = '读取点' if nature in ('读取点', 'read') else '拦截点'
        body = fields.get('行为')
        if body is None:
            # 行为 usually opens a nested block: split_fields sees "行为: {" ... "}"
            body = ''
        # The behavior block is nested inside fields parsing; extract it from
        # the raw block for robustness.
        behavior_match = re.search(r'行为\s*[:：]\s*', block)
        if not behavior_match:
            raise DSLParseError(f'mount {identifier} has no 行为')
        behavior, _ = _find_block(block, behavior_match.end())
        mounts.append(MountSpec(identifier, module, symbol, args, return_type, nature, behavior))
    if not mounts:
        raise DSLParseError('DSL has no 挂载点')
    return PatchSpec(actions, mounts)


def load(path: Path | str) -> PatchSpec:
    return parse(Path(path).read_text(encoding='utf-8'))
