"""Compile the patch DSL to a Frida agent (and expose metadata for installs).

The generated agent replaces each mount's target with a NativeCallback that
evaluates the DSL body.  BLOCK actions are applied in JS; falling off the body
calls the original function through Frida's SystemFunction (PASS).

Selector assignments (`value["x"] = <expr>;`) are wrapped with `vg_sel(name,
thunk)` so a validation harness can inject selector values without building a
full application image; in production the thunk reads real memory.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import re

from .parser import ActionSpec, MountSpec, PatchSpec, parse


SCALAR_JS = {
    'int': 'int', 'uint': 'uint', 'int64': 'int64', 'uint64': 'uint64',
    'pointer': 'pointer', 'void': 'void', 'float': 'float', 'double': 'double',
    'char': 'char', 'uchar': 'uchar', 'long': 'long', 'ulong': 'ulong',
    'size_t': 'ulong', 'ssize_t': 'long', 'bool': 'bool',
}


@dataclass
class CompiledMount:
    id: str
    module: str | None
    symbol: str
    args: list[str]
    return_type: str
    nature: str
    offset: int | None = None


@dataclass
class CompiledPatch:
    js: str
    mounts: list[CompiledMount]
    actions: dict[str, ActionSpec] = field(default_factory=dict)
    source: str = ''


def _js_action_table(actions: dict[str, ActionSpec]) -> str:
    table = {}
    for name, action in actions.items():
        table[name] = {
            'return_type': action.return_type,
            'value': action.value,
            'errno': action.errno,
        }
    return json.dumps(table, ensure_ascii=False)


def _transform_body(body: str) -> str:
    lines = []
    for raw in body.splitlines():
        line = raw
        # `value["name"] = expr;` -> selector thunk, unless it is a read of an
        # already recorded value (no assignment).
        match = re.match(r'^(\s*)value\["([^"]+)"\]\s*=\s*(.+?);\s*$', line)
        if match:
            indent, name, expr = match.groups()
            line = f'{indent}value["{name}"] = vg_sel("{name}", () => ({expr}));'
        line = re.sub(r'return\s+block\s*\(\s*"([^"]+)"\s*\)\s*;',
                      lambda m: f'return vg_block("{m.group(1)}");', line)
        line = re.sub(r'\bTrue\b', 'true', line)
        line = re.sub(r'\bFalse\b', 'false', line)
        line = re.sub(r'\b(?:u?int(?:8|16|32|64)_t|size_t|ssize_t|int|unsigned|uint|long|bool)\s+([A-Za-z_]\w*)\s*=',
                      r'let \1 =', line)
        line = re.sub(r'for\s*\(\s*(?:u?int(?:8|16|32|64)_t|size_t|ssize_t|int|unsigned|uint|long|bool)\s+([A-Za-z_]\w*)\s*=',
                      r'for (let \1 =', line)
        lines.append(line)
    return '\n'.join(lines)


def _callback_body(mount: MountSpec, actions: dict[str, ActionSpec]) -> str:
    body = _transform_body(mount.body)
    args = ', '.join(f'arg{index}' for index in range(len(mount.args)))
    call = f'original({args})' if args else 'original()'
    if mount.return_type == 'void':
        tail = f'    {call};\n    return;'
    else:
        tail = f'    return {call};'
    return body.rstrip() + '\n' + tail


def compile_patch(patch: PatchSpec | str, source: str = '') -> CompiledPatch:
    if isinstance(patch, str):
        source = patch
        patch = parse(patch)
    action_table = _js_action_table(patch.actions)
    mounts_js = []
    compiled_mounts: list[CompiledMount] = []
    for index, mount in enumerate(patch.mounts):
        args = [SCALAR_JS.get(kind, kind) for kind in mount.args]
        ret = SCALAR_JS.get(mount.return_type, mount.return_type)
        compiled_mounts.append(CompiledMount(mount.id, mount.module, mount.symbol,
                                             args, ret, mount.nature, mount.offset))
        body = _callback_body(mount, patch.actions)
        mounts_js.append({
            'id': mount.id,
            'module': mount.module,
            'symbol': mount.symbol,
            'args': args,
            'return_type': ret,
            'nature': mount.nature,
            'offset': mount.offset,
            'body': body,
        })
    # Build one install pass.  Each callback body is a JavaScript function body.
    entries = []
    for index, mount in enumerate(mounts_js):
        params = ', '.join(f'arg{position}' for position in range(len(mount['args'])))
        entries.append(f'''
    (function() {{
      const mount = {json.dumps(mount, ensure_ascii=False)};
      const target = vg_resolve(mount.module, mount.symbol, mount.offset);
      if (target === null) {{
        throw new Error('mount ' + mount.id + ': unresolved symbol ' + mount.symbol);
      }}
      const original = new SystemFunction(target, mount.return_type, mount.args);
      const callback = new NativeCallback(function({params}) {{
        VG_HITS[mount.id] = (VG_HITS[mount.id] || 0) + 1;
        const value = VG_VALUE;
{mount['body']}
      }}, mount.return_type, mount.args);
      Interceptor.replace(target, callback);
      VG_INSTALLED.push({{
        id: mount.id, symbol: mount.symbol, module: mount.module,
        target: target.toString(), guard: callback,
      }});
    }})();''')
    js = '''
'use strict';
const VG_INSTALLED = [];
const VG_TEST = {};
const VG_HITS = {};
const VG_VALUE = {};
const VG_ACTIONS = %s;

function vg_resolve(moduleName, symbol, offset) {
  if (offset !== null && offset !== undefined) {
    try {
      let module = null;
      if (moduleName) module = Process.findModuleByName(moduleName);
      if (module === null) module = Process.mainModule;
      if (module !== null) return module.base.add(offset);
    } catch (error) {}
  }
  try {
    if (moduleName) {
      const module = Process.findModuleByName(moduleName);
      if (module !== null) {
        const exported = module.getExportByName(symbol);
        if (exported !== null) {
          return exported;
        }
      }
    }
  } catch (error) {}
  try {
    const main = Process.mainModule;
    if (main !== null) {
      const exported = main.getExportByName(symbol);
      if (exported !== null) {
        return exported;
      }
    }
  } catch (error) {}
  for (const candidate of Process.enumerateModules()) {
    try {
      const exported = candidate.getExportByName(symbol);
      if (exported !== null) {
        return exported;
      }
    } catch (error) {}
  }
  try {
    return Module.getExportByName(null, symbol);
  } catch (error) {
    return null;
  }
}

function vg_sel(name, thunk) {
  if (Object.prototype.hasOwnProperty.call(VG_TEST, name)) {
    return VG_TEST[name];
  }
  return thunk();
}

function vg_global(name) {
  const address = Module.getExportByName(null, name);
  if (address === null) {
    throw new Error('global symbol not found: ' + name);
  }
  return address;
}

function vg_ptr(value) {
  if (value === null || value === undefined) return ptr(0);
  if (value instanceof NativePointer) return value;
  return ptr(value);
}

function vg_read_u8(address) { return Memory.readU8(vg_ptr(address)); }
function vg_read_s8(address) { return Memory.readS8(vg_ptr(address)); }
function vg_read_u16(address) { return Memory.readU16(vg_ptr(address)); }
function vg_read_s16(address) { return Memory.readS16(vg_ptr(address)); }
function vg_read_u32(address) { return Memory.readU32(vg_ptr(address)); }
function vg_read_s32(address) { return Memory.readS32(vg_ptr(address)); }
function vg_read_u64(address) { return Memory.readU64(vg_ptr(address)).toNumber(); }
function vg_read_s64(address) { return Memory.readS64(vg_ptr(address)).toNumber(); }
function vg_read_pointer(address) { return Memory.readPointer(vg_ptr(address)); }
function vg_map_get(name, key, slot) { return 0; }
function vg_map_present(name, key) { return 0; }

function vg_block(name) {
  const action = VG_ACTIONS[name];
  if (!action) {
    throw new Error('unknown block action: ' + name);
  }
  if (action.errno !== null && action.errno !== undefined) {
    try {
      const errnoLocation = new NativeFunction(Module.getExportByName(null, '__errno_location'), 'pointer', []);
      Memory.writeS32(errnoLocation(), action.errno);
    } catch (error) {}
  }
  if (action.return_type === 'void') {
    return undefined;
  }
  if (action.return_type === 'pointer' || action.value === null) {
    return null;
  }
  if (action.return_type === 'string') {
    return Memory.allocUtf8String(String(action.value));
  }
  return action.value;
}

function vg_install() {
  VG_INSTALLED.length = 0;
  %s

  Interceptor.flush();
}

function vg_status() {
  return {
    hits: VG_HITS,
    installed: VG_INSTALLED.map((entry) => ({
      id: entry.id, symbol: entry.symbol, module: entry.module,
      target: entry.target,
    })),
  };
}

rpc.exports = {
  install: () => { vg_install(); return vg_status(); },
  status: () => vg_status(),
  setTest: (values) => { Object.assign(VG_TEST, values); return Object.keys(VG_TEST).length; },
  clearTest: () => { for (const key of Object.keys(VG_TEST)) delete VG_TEST[key]; },
};
''' % (action_table, ''.join(entries))
    return CompiledPatch(js=js, mounts=compiled_mounts,
                         actions=dict(patch.actions), source=source)



