"""Command-line helpers.

Frida hooks live inside the session that installed them, so a one-shot CLI
process cannot install persistently. The CLI therefore has two modes:

  check   --pid PID --manifest M --catalog C   resolve the bundle without hooks
  status  --socket PATH                        ask a running launcher
  metrics --socket PATH                        ask a running launcher
  uninstall --socket PATH [--pid PID ...]      ask a running launcher

Use run.py or multiproc.py (with --control-socket) when the bundle must stay
installed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

try:
    from .control import ControlClient
    from .run import load_bundle
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from control import ControlClient
    from run import load_bundle


def default_agent() -> Path:
    return Path(__file__).with_name('agent.js')


def check(pid: int, manifest: Path, catalog: Path, agent: Path | None = None) -> dict:
    import frida
    config, actions = load_bundle(Path(manifest), Path(catalog))
    session = frida.get_local_device().attach(pid)
    script = session.create_script(Path(agent or default_agent()).read_text(encoding='utf-8'))
    try:
        script.load()
        return dict(script.exports_sync.probe(config, actions))
    finally:
        try:
            script.unload()
        except Exception:
            pass
        try:
            session.detach()
        except Exception:
            pass


def request(socket_path: Path, payload: dict) -> dict:
    return ControlClient(socket_path).request(payload)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    check_parser = sub.add_parser('check')
    check_parser.add_argument('--pid', type=int, required=True)
    check_parser.add_argument('--manifest', type=Path, required=True)
    check_parser.add_argument('--catalog', type=Path, required=True)
    check_parser.add_argument('--agent', type=Path)
    for name in ('status', 'metrics'):
        command = sub.add_parser(name)
        command.add_argument('--socket', type=Path, required=True)
    uninstall_parser = sub.add_parser('uninstall')
    uninstall_parser.add_argument('--socket', type=Path, required=True)
    uninstall_parser.add_argument('--pid', type=int, action='append')
    args = parser.parse_args()
    if args.command == 'check':
        result = check(args.pid, args.manifest, args.catalog, args.agent)
    elif args.command == 'uninstall':
        payload = {'command': 'uninstall'}
        if args.pid:
            payload['pids'] = args.pid
        result = request(args.socket, payload)
    else:
        result = request(args.socket, {'command': args.command})
    print(json.dumps(result, ensure_ascii=False), flush=True)
    if args.command == 'check' and not result.get('ok'):
        sys.exit(4)


if __name__ == '__main__':
    main()
