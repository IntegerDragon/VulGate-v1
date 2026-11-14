"""Boot a caller-selected kernel in a diskless QEMU guest with no network."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import shutil
import stat
import subprocess
import sys


def policy_markers(console, runtime_pin, probe_included):
    required = ['VULGATE_KERNEL_VM_SELFTEST:PASS', 'VULGATE_KERNEL_RUNTIME:' + runtime_pin]
    if probe_included:
        required.append('VULGATE_KERNEL_POLICY_PROBE:PASS')
    return (all(console.count(marker) == 1 for marker in required) and
            'VULGATE_KERNEL_VM_SELFTEST:FAIL' not in console and
            'VULGATE_KERNEL_POLICY_PROBE:FAIL' not in console), required


def newc(entries):
    image = bytearray()
    for number, (name, data, mode, major, minor) in enumerate([*entries, ('TRAILER!!!', b'', 0, 0, 0)], 1):
        name = name.encode() + b'\0'
        fields = [number, mode, 0, 0, 1, 0, len(data), 0, 0, major, minor, len(name), 0]
        image.extend(b'070701' + ''.join(f'{field:08x}' for field in fields).encode())
        image.extend(name)
        image.extend(b'\0' * (-len(image) % 4))
        image.extend(data)
        image.extend(b'\0' * (-len(image) % 4))
    return bytes(image)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--binding', type=Path, help='pinned kernel image binding manifest')
    parser.add_argument('--binding-sha256')
    args = parser.parse_args()
    build, output = args.build.resolve(), args.output.resolve()
    if bool(args.binding) != bool(args.binding_sha256):
        parser.error('--binding and --binding-sha256 must be supplied together')
    binding = None
    if args.binding:
        sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
        from tools.kernel_binding import check_kernel
        checked = check_kernel(args.binding, args.binding_sha256)
        if Path(checked['image']).resolve() != build / 'arch/x86/boot/bzImage':
            raise ValueError('guest image differs from the caller-pinned binding')
        if output.is_relative_to(args.binding.resolve().parent):
            raise ValueError('guest evidence must be outside the pinned kernel bundle')
        binding = json.loads(args.binding.read_text())
    output.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).with_name('init.c')
    init = output / 'init'
    compilation = ['gcc', '-static', '-O2', '-Wall', '-Wextra', '-Werror', str(source), '-o', str(init)]
    subprocess.run(compilation, check=True, capture_output=True, timeout=60)
    entries = [(name, b'', stat.S_IFDIR | 0o755, 0, 0) for name in ('dev', 'proc', 'sys')]
    entries += [('dev/console', b'', stat.S_IFCHR | 0o600, 5, 1),
                ('init', init.read_bytes(), stat.S_IFREG | 0o755, 0, 0)]
    initramfs = output / 'initramfs.cpio'
    initramfs.write_bytes(newc(entries))
    kernel = build / 'arch/x86/boot/bzImage'
    qemu = shutil.which('qemu-system-x86_64')
    if not qemu:
        raise RuntimeError('qemu-system-x86_64 is required')
    command = [qemu, '-accel', 'tcg', '-m', '256', '-smp', '1', '-nographic', '-no-reboot',
               '-nic', 'none', '-kernel', str(kernel), '-initrd', str(initramfs),
               '-append', 'console=ttyS0 panic=-1 rdinit=/init']
    timed_out = False
    with (output / 'console.log').open('wb') as log:
        try:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=90)
            returncode = result.returncode
        except subprocess.TimeoutExpired:
            timed_out, returncode = True, None
    console = (output / 'console.log').read_text(errors='replace')
    passed = (returncode == 0 and 'VULGATE_GUEST_BOOT_OK:' in console and
              'VULGATE_GUEST_FAILED:' not in console and 'Kernel panic' not in console)
    required = []
    if binding:
        markers_ok, required = policy_markers(console, binding['runtime_sha256'], binding['probe_included'])
        passed = passed and markers_ok
        check_kernel(args.binding, args.binding_sha256)
    record = {'status': 'PASSED' if passed else 'FAILED', 'qemu_returncode': returncode,
              'timed_out': timed_out,
              'commands': {'compile_init': compilation, 'qemu': command},
              'pins': {str(p): sha256(p.read_bytes()).hexdigest() for p in
                       (Path(__file__), source, init, kernel, build / '.config', initramfs, Path(qemu), output / 'console.log')},
              'binding_manifest_sha256': args.binding_sha256,
              'required_policy_markers': required,
              'scope': ('Isolated boot, actual VM self-test and supplied kernel API probe; symbolic proof scope remains the supplied root.'
                        if binding else 'Isolated kernel boot, procfs/sysfs operation and reboot. No policy/module qualification yet.')}
    (output / 'report.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))
    raise SystemExit(0 if passed else 1)


if __name__ == '__main__':
    main()
