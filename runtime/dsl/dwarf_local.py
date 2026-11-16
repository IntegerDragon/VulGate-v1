"""Resolve a caller local variable to an x86-64 runtime location via DWARF.

Supported for the current MVP:
- DW_AT_location exprloc (DW_FORM_exprloc)
- register, breg, fbreg, const, plus/plus_uconst, deref, stack_value

Location lists (DW_AT_location offsets / loclists) are detected but not yet
evaluated; the error is explicit.
"""
from __future__ import annotations

from pathlib import Path
import struct

from runtime.dsl.x86 import ResolveError


def _sleb(data: bytes, index: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        byte = data[index]
        index += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not (byte & 0x80):
            if shift < 64 and (byte & 0x40):
                result -= 1 << shift
            return result, index


def _uleb(data: bytes, index: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        byte = data[index]
        index += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not (byte & 0x80):
            return result, index


def _reg_name(index: int) -> str:
    names = ['rax', 'rdx', 'rcx', 'rbx', 'rsi', 'rdi', 'rbp', 'rsp',
             'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
    return names[index] if index < len(names) else 'r' + str(index)


def _parse_expr(data: bytes) -> dict:
    stack: list[dict] = []
    index = 0
    while index < len(data):
        opcode = data[index]
        index += 1
        if 0x50 <= opcode <= 0x6F:
            stack.append({'kind': 'register', 'reg': _reg_name(opcode - 0x50)})
        elif 0x70 <= opcode <= 0x8F:
            offset, index = _sleb(data, index)
            stack.append({'kind': 'memory', 'base': _reg_name(opcode - 0x70),
                          'offset': offset, 'deref': 0})
        elif opcode == 0x91:  # DW_OP_fbreg
            offset, index = _sleb(data, index)
            stack.append({'kind': 'memory', 'base': 'rbp', 'offset': offset, 'deref': 0})
        elif opcode == 0x06:  # DW_OP_deref
            if not stack:
                raise ResolveError('DWARF deref without value')
            stack[-1]['deref'] = stack[-1].get('deref', 0) + 1
        elif opcode == 0x08:
            stack.append({'kind': 'constant', 'value': data[index]}); index += 1
        elif opcode == 0x09:
            stack.append({'kind': 'constant', 'value': struct.unpack('b', data[index:index + 1])[0]}); index += 1
        elif opcode == 0x0A:
            stack.append({'kind': 'constant', 'value': struct.unpack('<H', data[index:index + 2])[0]}); index += 2
        elif opcode == 0x0B:
            stack.append({'kind': 'constant', 'value': struct.unpack('<h', data[index:index + 2])[0]}); index += 2
        elif opcode == 0x0C:
            stack.append({'kind': 'constant', 'value': struct.unpack('<I', data[index:index + 4])[0]}); index += 4
        elif opcode == 0x0D:
            stack.append({'kind': 'constant', 'value': struct.unpack('<i', data[index:index + 4])[0]}); index += 4
        elif opcode == 0x0E:
            stack.append({'kind': 'constant', 'value': struct.unpack('<Q', data[index:index + 8])[0]}); index += 8
        elif opcode == 0x0F:
            stack.append({'kind': 'constant', 'value': struct.unpack('<q', data[index:index + 8])[0]}); index += 8
        elif opcode == 0x10:
            value, index = _uleb(data, index)
            stack.append({'kind': 'constant', 'value': value})
        elif opcode == 0x11:
            value, index = _sleb(data, index)
            stack.append({'kind': 'constant', 'value': value})
        elif opcode == 0x22:  # plus
            right = stack.pop()
            left = stack.pop()
            if left['kind'] == 'memory' and right['kind'] == 'constant':
                left['offset'] += right['value']
                stack.append(left)
            elif right['kind'] == 'memory' and left['kind'] == 'constant':
                right['offset'] += left['value']
                stack.append(right)
            else:
                raise ResolveError('unsupported DWARF plus')
        elif opcode == 0x23:  # plus_uconst
            value, index = _uleb(data, index)
            top = stack.pop()
            if top['kind'] != 'memory':
                raise ResolveError('plus_uconst on non-memory')
            top['offset'] += value
            stack.append(top)
        elif opcode == 0x9F:  # stack_value
            if stack:
                stack[-1]['stack_value'] = True
        else:
            raise ResolveError('unsupported DWARF opcode: 0x%02x' % opcode)
    if not stack:
        raise ResolveError('empty DWARF location expression')
    recipe = stack[-1]
    if recipe['kind'] == 'memory':
        recipe['size'] = recipe.get('size', 8)
    return recipe


def _die_name(die) -> str | None:
    name = die.attributes.get('DW_AT_name')
    if name is None:
        return None
    return name.value.decode() if isinstance(name.value, bytes) else str(name.value)


def _type_size(dwarf, die, depth: int = 0) -> int:
    if depth > 8:
        return 8
    attr = die.attributes.get('DW_AT_type')
    if attr is None:
        return 8
    target = dwarf.get_DIE_from_refaddr(attr.value)
    if target is None:
        return 8
    if target.tag == 'DW_TAG_pointer_type':
        return 8
    size = target.attributes.get('DW_AT_byte_size')
    if size is not None:
        return int(size.value)
    if target.tag in ('DW_TAG_const_type', 'DW_TAG_volatile_type', 'DW_TAG_typedef'):
        return _type_size(dwarf, target, depth + 1)
    return 8


def resolve_local(binary: Path, caller: str, variable: str,
                  pc: int | None = None) -> dict:
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError as error:
        raise ResolveError('pyelftools missing') from error
    with Path(binary).open('rb') as stream:
        elf = ELFFile(stream)
        dwarf = elf.get_dwarf_info()
        for cu in dwarf.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag != 'DW_TAG_subprogram' or _die_name(die) != caller:
                    continue
                for child in die.iter_children():
                    if child.tag != 'DW_TAG_variable' or _die_name(child) != variable:
                        continue
                    location = child.attributes.get('DW_AT_location')
                    if location is None:
                        raise ResolveError('variable has no DWARF location: ' + variable)
                    if location.form != 'DW_FORM_exprloc':
                        raise ResolveError('unsupported DWARF location form: ' + location.form)
                    data = bytes(location.value)
                    recipe = _parse_expr(data)
                    recipe['size'] = _type_size(dwarf, child)
                    return recipe
    raise ResolveError('variable not found in DWARF: ' + caller + ':' + variable)
