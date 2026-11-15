"""Install a DSL patch through the VulGate Shadow VM (runtime/vm.c) instead of JS guards."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime.dsl import parser as dsl_parser  # noqa: E402
from runtime.dsl import resolve as dsl_resolve  # noqa: E402
from runtime.dsl import vm as dsl_vm  # noqa: E402


def _bridge(output: Path) -> Path:
    bridge = output / 'vulgate_frida.so'
    if not bridge.is_file():
        subprocess.run([sys.executable, '-m', 'runtime.frida.build',
                        '--output', str(output)], check=True)
    return bridge


def _global_names(patch: dsl_parser.PatchSpec) -> list[str]:
    names = []
    for mount in patch.mounts:
        for name in re.findall(r'global\("([^"]+)"\)', mount.body):
            if name not in names:
                names.append(name)
    return names


def _target_address(pid: int | None, mount: dsl_parser.MountSpec,
                    executable: Path | None) -> tuple[int, str | None]:
    info = dsl_resolve.module_base(pid, mount.module, executable)
    if info is None:
        raise ValueError('cannot find module for mount ' + mount.id)
    module, base, path = info
    if mount.offset is None:
        offsets = dsl_resolve.frida_symbols.symbol_offsets(path, [mount.symbol])
        if mount.symbol not in offsets:
            raise ValueError('symbol not found in ' + str(path) + ': ' + mount.symbol)
        mount.offset = offsets[mount.symbol]
    return (base + mount.offset, module)


def _action_value(action: dsl_parser.ActionSpec) -> str:
    if action.return_type == 'void':
        return 'undefined'
    if action.return_type in ('pointer', 'string') or action.value is None:
        return 'null' if action.value is None else 'Memory.allocUtf8String(%s)' % json.dumps(str(action.value))
    return str(int(action.value))


def _script(patch: dsl_parser.PatchSpec, compiled: dsl_vm.VMPatch,
            targets: list[tuple[int, str | None]], bridge: Path) -> str:
    entries = []
    for mount, target, module in zip(compiled.mounts, targets, [m.module for m in patch.mounts]):
        action = patch.actions[mount.action_id]
        entries.append(
            '{id: %s, args: %s, return_type: %s, target: %s, code: %s, action: %s}' % (
                json.dumps(mount.id), json.dumps(mount.args),
                json.dumps(mount.return_type), json.dumps(hex(target[0])),
                json.dumps(list(mount.code)), _action_value(action)))
    mounts_literal = '[' + ', '.join(entries) + ']'
    return r'''
'use strict';
const bridge = Module.load(%s);
const create = new NativeFunction(bridge.getExportByName('vg_program_create'), 'pointer', ['pointer', 'uint']);
const destroy = new NativeFunction(bridge.getExportByName('vg_program_destroy'), 'void', ['pointer']);
const run = new NativeFunction(bridge.getExportByName('vg_run'), 'int', ['pointer', 'pointer', 'pointer', 'uint', 'pointer']);
const VG_MOUNTS = %s;
const VG_STATE = [];
const VG_HITS = {};

function vg_install() {
  for (const spec of VG_MOUNTS) {
    const code = Memory.alloc(spec.code.length);
    code.writeByteArray(spec.code);
    const handle = create(code, spec.code.length);
    if (handle.isNull()) throw new Error('vg_program_create failed: ' + spec.id);
    const args = Memory.alloc(6 * 8);
    const regs = Memory.alloc(16 * 8);
    const stats = Memory.alloc(64);
    const original = new SystemFunction(ptr(spec.target), spec.return_type, spec.args);
    const callback = new NativeCallback(function() {
      VG_HITS[spec.id] = (VG_HITS[spec.id] || 0) + 1;
      const values = Array.prototype.slice.call(arguments);
      for (let index = 0; index < values.length; index++) {
        const value = values[index];
        if (value instanceof NativePointer) args.add(index * 8).writePointer(value);
        else args.add(index * 8).writeU64(value);
      }
      const decision = run(handle, args, regs, 4096, stats);
      if (decision === 1) return spec.action;
      return original.apply(null, values);
    }, spec.return_type, spec.args);
    Interceptor.replace(ptr(spec.target), callback);
    VG_STATE.push({id: spec.id, target: String(spec.target), handle: handle,
                   callback: callback, program: code});
  }
  Interceptor.flush();
}

rpc.exports = {
  install: () => { vg_install(); return {installed: VG_STATE.map((s) => ({id: s.id, target: s.target})), hits: VG_HITS}; },
  status: () => ({installed: VG_STATE.map((s) => ({id: s.id, target: s.target})), hits: VG_HITS}),
};
''' % (json.dumps(str(bridge)), mounts_literal)


def install(patch_path: Path, pid: int | None, executable: Path | None,
            bridge_dir: Path, duration: float = 5.0, spawn=False) -> dict:
    patch = dsl_parser.load(patch_path)
    import frida
    device = frida.get_local_device()
    if spawn:
        pid = device.spawn([str(executable.resolve())])
    assert pid is not None
    dsl_resolve.resolve_patch(patch, pid=pid, executable=executable)
    globals_ = {}
    for name in _global_names(patch):
        module, address = dsl_resolve.resolve_global(
            name, pid, None, executable)
        globals_[name] = address
    compiled = dsl_vm.compile_patch(patch, globals_)
    targets = []
    for mount in patch.mounts:
        targets.append(_target_address(pid, mount, executable))
    bridge = _bridge(bridge_dir)
    session = None
    try:
        session = device.attach(pid)
        script = session.create_script(_script(patch, compiled, targets, bridge))
        script.load()
        result = script.exports_sync.install()
        if spawn:
            device.resume(pid)
        time.sleep(max(0.0, duration))
        result['final'] = script.exports_sync.status()
        return result
    finally:
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        if spawn:
            try:
                device.kill(pid)
            except Exception:
                pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dsl', type=Path, required=True)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('--pid', type=int)
    target.add_argument('--spawn', type=Path)
    parser.add_argument('--duration', type=float, default=5.0)
    parser.add_argument('--bridge-dir', type=Path, default=ROOT / 'build' / 'frida-vm')
    args = parser.parse_args()
    result = install(args.dsl, args.pid, args.spawn, args.bridge_dir,
                     args.duration, spawn=args.spawn is not None)
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
