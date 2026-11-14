"""Minimal validation: Frida hot attach + native CModule guard + own inline patch.

Builds a CModule from runtime/vm.c (stack-only state, since CModule data is
read-only), builds an x86-64 trampoline for the original prologue, patches the
target with a 14-byte absolute jump, and verifies PASS/BLOCK on 4 pthreads.

Run in WSL:
    PYTHONPATH=/tmp/vulgate-frida-deps-20261111 python3 experiments/native-frida/probe.py
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PKG = ROOT / 'build' / 'frida-linux'
FIXTURE = PKG / 'frida_fixture'


def _module_source(action: str) -> str:
    autoshield = (ROOT / 'runtime' / 'autoshield.h').read_text()
    vm = (ROOT / 'runtime' / 'vm.c').read_text()
    autoshield = autoshield.replace('#include <stddef.h>', '').replace('#include <stdint.h>', '')
    for line in ('#include "autoshield.h"', '#include <errno.h>', '#include <stdio.h>',
                 '#include <stdlib.h>', '#include <string.h>', '#include <linux/errno.h>',
                 '#include <linux/string.h>'):
        vm = vm.replace(line, '')
    start = vm.index('#ifndef __KERNEL__\nint shadow_program_load')
    end = vm.index('void shadow_program_free')
    end = vm.index('#endif', end) + len('#endif')
    vm = vm[:start] + vm[end:]
    prelude = r'''
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef signed char int8_t;
typedef short int16_t;
typedef int int32_t;
typedef long long int64_t;
typedef unsigned long size_t;
typedef long ssize_t;
typedef unsigned long uintptr_t;
typedef long intptr_t;
#ifndef NULL
#define NULL ((void *)0)
#endif
#define EPERM 1
#define EIO 5
#define ENOMEM 12
#define EINVAL 22
#define EOVERFLOW 75
static void *vg_memset(void *dst, int value, size_t len)
{
    unsigned char *bytes = (unsigned char *)dst;
    for (size_t index = 0; index < len; index++) bytes[index] = (unsigned char)value;
    return dst;
}
static void *vg_memcpy(void *dst, const void *src, size_t len)
{
    unsigned char *to = (unsigned char *)dst;
    const unsigned char *from = (const unsigned char *)src;
    for (size_t index = 0; index < len; index++) to[index] = from[index];
    return dst;
}
#define memset vg_memset
#define memcpy vg_memcpy
'''
    decision = '1' if action == 'block' else '0'
    code = f'''static const unsigned char code[] = {{
    0xb7, 0, 0, 0, {decision}, 0, 0, 0,
    0x95, 0, 0, 0, 0, 0, 0, 0
}};
'''
    wrapper = r'''
int safe_read(void *dst, const void *src, size_t len) { (void)dst; (void)src; (void)len; return -1; }
int c_guard(uint64_t a, uint64_t b)
{
    (void)a; (void)b;
    shadow_program program;
    if (shadow_program_init(code, sizeof(code), &program) != 0) return -1;
    shadow_ctx ctx; shadow_policy policy; shadow_stats stats;
    shadow_ctx_init(&ctx); shadow_policy_init(&policy); policy.step_limit = 4096;
    memset(&stats, 0, sizeof(stats));
    uint64_t args[6] = {a, b, 0, 0, 0, 0};
    memcpy(ctx.args, args, sizeof(ctx.args));
    int decision = run_ebpf_vm(&ctx, &program, &policy, &stats);
    if (decision == SHADOW_BLOCK) return -73;
    return ((int (*)(uint64_t, uint64_t))(__ORIG_ADDR__))(a, b);
}
'''
    return prelude + autoshield + vm + code + wrapper


def _agent_script(action: str) -> str:
    source = json.dumps(_module_source(action))
    return r'''
const target = Process.getModuleByName('frida_fixture').getExportByName('fixture_target');
const instructions = [];
let size = 0;
while (size < 14) {
    const insn = Instruction.parse(target.add(size));
    instructions.push({mnemonic: insn.mnemonic, opStr: insn.opStr,
                       base: insn.operands.map(o => o.value && o.value.base).filter(Boolean)});
    size += insn.size;
}
if (instructions.some(i => i.mnemonic.startsWith('j') || i.mnemonic === 'call' ||
                          i.base.includes('rip'))) {
    send({event: 'unsupported-prologue', instructions});
    throw new Error('prologue needs relocation');
}
const trampoline = Memory.alloc(64);
Memory.protect(trampoline, 64, 'rwx');
trampoline.writeByteArray(target.readByteArray(size));
const back = trampoline.add(size);
back.writeByteArray([0x48, 0xb8]);
back.add(2).writePointer(target.add(size));
back.add(10).writeByteArray([0xff, 0xe0]);
const cm = new CModule(%s.replace('__ORIG_ADDR__', trampoline.toString()));
globalThis.__vg = {cm, trampoline, target, size, original: target.readByteArray(size)};
Memory.patchCode(target, size, function (code) {
    code.writeByteArray([0x48, 0xb8]);
    code.add(2).writePointer(cm.c_guard);
    code.add(10).writeByteArray([0xff, 0xe0]);
});
send({event: 'patched', size, guard: cm.c_guard.toString(), trampoline: trampoline.toString()});
rpc.exports = {
    unpatch() {
        const state = globalThis.__vg;
        Memory.patchCode(state.target, state.size, function (code) {
            code.writeByteArray(state.original);
        });
        return true;
    },
};
''' % source


class Fixture:
    def __init__(self):
        self.proc = subprocess.Popen([str(FIXTURE)], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True, bufsize=1)
        assert json.loads(self.proc.stdout.readline()) == {'ready': True}

    def command(self, text: str) -> dict:
        self.proc.stdin.write(text + '\n')
        self.proc.stdin.flush()
        return json.loads(self.proc.stdout.readline())

    def timed_threads(self, threads: int, iterations: int) -> tuple[float, dict]:
        started = time.perf_counter()
        reply = self.command(f'threads {threads} {iterations}')
        return time.perf_counter() - started, reply

    def close(self):
        try:
            self.proc.stdin.write('exit\n')
            self.proc.stdin.flush()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def run_action(device, action: str, threads: int = 4, iterations: int = 50000) -> dict:
    fixture = Fixture()
    session = None
    try:
        baseline_ms, baseline = fixture.timed_threads(threads, iterations)
        session = device.attach(fixture.proc.pid)
        script = session.create_script(_agent_script(action))
        messages = []
        script.on('message', lambda message, data: messages.append(message))
        load_started = time.perf_counter()
        script.load()
        install_ms = (time.perf_counter() - load_started) * 1000
        patch = [m for m in messages if m.get('payload', {}).get('event') == 'patched']
        if not patch:
            raise RuntimeError('patch failed: ' + json.dumps(messages))
        patched_ms, patched = fixture.timed_threads(threads, iterations)
        single = fixture.command('call 1 5')
        script.exports_sync.unpatch()
        restored = fixture.command('call 1 5')
        return {
            'action': action,
            'threads': threads,
            'iterations': iterations,
            'install_ms': round(install_ms, 1),
            'baseline': baseline,
            'patched': patched,
            'baseline_ns_per_call': round(baseline_ms * 1e9 / (threads * iterations), 1),
            'patched_ns_per_call': round(patched_ms * 1e9 / (threads * iterations), 1),
            'single': single,
            'restored': restored,
        }
    finally:
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        fixture.close()


def main() -> int:
    if not FIXTURE.is_file():
        print('fixture missing; run: python -m runtime.frida.build --output build/frida-linux --with-fixture',
              file=sys.stderr)
        return 2
    import frida
    device = frida.get_local_device()
    results = [run_action(device, 'pass'), run_action(device, 'block')]
    print(json.dumps(results, indent=2))
    failures = []
    for result in results:
        expected = -73 if result['action'] == 'block' else 105
        expected_blocked = result['threads'] * result['iterations'] if result['action'] == 'block' else 0
        if result['single']['result'] != expected:
            failures.append(f"{result['action']}: single result {result['single']}")
        if result['patched'].get('blocked') != expected_blocked:
            failures.append(f"{result['action']}: blocked {result['patched'].get('blocked')} != {expected_blocked}")
        if result['restored']['result'] != 105:
            failures.append(f"{result['action']}: restore failed {result['restored']}")
    if failures:
        print('FAIL: ' + '; '.join(failures))
        return 1
    print('PASS: CModule native guard works on 4 pthreads for PASS/BLOCK and unpatches cleanly')
    return 0


if __name__ == '__main__':
    sys.exit(main())
